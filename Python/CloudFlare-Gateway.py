import socket
import json
import argparse
from lib import requests_wrapper as requests ## Using custom lib to force IPv4 / IPv6 requests.


def dig(fqdn: str) -> dict:
    addrs = socket.getaddrinfo(fqdn, None)
    ipv4_addrs = [addr[4][0] for addr in addrs if addr[0] == socket.AF_INET]
    ipv6_addrs = [addr[4][0] for addr in addrs if addr[0] == socket.AF_INET6]
    return {'ipv4': ['ifconfig.io'], 'ipv6': ['ifconfig.io']}

def get_public_ip(mode: str = "ipv4", verify: bool = True) -> dict:
    ifconfig = dig('ifconfig.io')
    ipv4 = None
    ipv6 = None
    if mode in ["ipv4", "all"]:
        ip4 = requests.get('http://{}/ip'.format(ifconfig['ipv4'][0]), headers = {'Host' : 'ifconfig.io'}, verify = verify, family = socket.AF_INET)
        ipv4 = ip4.text.strip() if ip4.status_code == 200 else None
    if mode in ["ipv6", "all"]:
        ip6 = requests.get('http://{}/ip'.format(ifconfig['ipv6'][0]), headers = {'Host' : 'ifconfig.io'}, verify = verify, family = socket.AF_INET6)
        ipv6 = ip6.text.strip() if ip6.status_code == 200 else None
    return {'ipv4': ipv4, 'ipv6': ipv6}

def initiate_session(headers: dict) -> requests.Session:
    session = requests.Session()
    session.headers.update(headers)
    return session

def get_gateway_id(session: requests.Session, uri: str, gw_name: str, verify: bool = True):
  r = session.get(uri, verify=verify)
  if r.status_code != 200:
    print("Whoops... {}".format(session.text))
  js = r.json()
  for record in js['result']:
    if record['name'] == gw_name:
      return record['id'], record['networks']
  return False, False

def update_gateway(session: requests.Session, uri, gw_name: str, networks: list, verify: bool = True) -> bool|dict:
    data = {
        'name': gw_name,
        'networks': networks
    }
    r = session.put(uri, data = json.dumps(data), verify = verify)
    if r.status_code > 299:
        print("Error: {} - {}".format(r.status_code, r.text))
        return False
    return r.json()

def main(account_id: str, gateway_name: str, api_token:str, verify: bool = True) -> None:
    if len(account_id) <= 1 or len(gateway_name) <= 4 or len(api_token) <= 1:
        print("Missing required fields. Please check and try again")
        return

    session = initiate_session({"Authorization":"Bearer {}".format(api_token), "Content-Type": "application/json"})
    uri = "https://api.cloudflare.com/client/v4/accounts/{}/gateway/locations".format(account_id)
    gateway_id, gateway_networks = get_gateway_id(session, uri, gateway_name, verify)
    ips = get_public_ip('ipv4', verify)
    if gateway_id != False:
      match = False
      for entry in gateway_networks:
          if entry['network'].split('/')[0] == ips['ipv4']:
              match = True
              print("Gateway IP Unchanged")
              return
      if not match:
        gateway_networks = [
          {
            'network': '{}/32'.format(ips['ipv4'])
          }
        ]
        print("Updating Gateway")
        update_gateway(session, "{}/{}".format(uri, gateway_id), gateway_name, gateway_networks, verify)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog = "CloudFlare Dynamic Gateway Updater - CloudFlare-Gateway.py",
        description = "Dynamically updates CloudFlare via API calls with current recorded IP address",
        epilog = "Written by Phatkone/Ashikabi"
    )
    parser.add_argument('-a', '--accountid', type = str, help = 'CloudFlare DNS Account ID', required = True)
    parser.add_argument('-t', '--token', type = str, help = 'CloudFlare DNS API Token', required = True)
    parser.add_argument('-g', '--gateway', type = str, help = 'CloudFlare Gateway Name', required = True)
    parser.add_argument('-i', '--insecure', help = 'Ignore TLS/SSL Certificate', default = True, action = 'store_false')
    args = parser.parse_args()
    if not args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main(args.accountid, args.gateway, args.token, args.insecure)

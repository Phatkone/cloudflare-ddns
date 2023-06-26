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

def get_record_ids(session: requests.Session, uri: str, fqdn: str, verify: bool = True) -> dict:
    records = {'A': [],'AAAA': []}
    for t in ['A', 'AAAA']:
        r = session.get("{}?name={}&type={}".format(uri, fqdn,t), verify=verify)
        if r.status_code != 200:
            print("Whoops... {}".format(session.text))
        js = r.json()
        if js['result_info']['count'] < 1:
            records[t] = False
            continue
        for record in js['result']:
            if record['name'] == fqdn and record['type']:
                records[t].append({'type': t, 'id': record['id'], 'ip': record['content']})
    return records if len(records) > 0 else False

def create_dns_record(session: requests.Session, uri: str, fqdn:str, ip_address: str, proxied: bool, ttl: int, r_type: str = "A", verify: bool = True) -> bool|dict:
    data = {
        'content': ip_address,
        'name': fqdn,
        'type': r_type,
        'ttl': ttl,
        'proxied': proxied,
        'comment': "Created by Dynamic DNS"
    }
    r = session.post(uri, json = data, verify = verify)
    if r.status_code > 299:
        print("Error: {} - {}".format(r.status_code, r.text))
        return False
    return r.json()

def update_dns_record(session: requests.Session, uri: str, fqdn:str, ip_address: str, r_type: str = "A", verify: bool = True) -> bool|dict:
    data = {
        'content': ip_address,
        'name': fqdn,
        'type': r_type,
        'comment': "Updated by Dynamic DNS"
    }
    r = session.put(uri, data = json.dumps(data), verify = verify)
    if r.status_code > 299:
        print("Error: {} - {}".format(r.status_code, r.text))
        return False
    return r.json()

def delete_dns_record(session: requests.Session, uri: str, verify: bool = True) -> bool:
    r = session.delete(uri, verify = verify)
    print(uri)
    if r.status_code > 299:
        print("Error Deleting AAAA record: {} - {}".format(r.status_code, r.text))
        return False
    return True

def main(zone_id: str, fqdn: str, api_token:str, proxied: bool = True, ttl: int = 1, mode: str = "ipv4", verify: bool = True) -> None:
    if len(zone_id) <= 1 or len(fqdn) <= 4 or len(api_token) <= 1:
        print("Missing required fields. Please check adn try again")
        return

    session = initiate_session({"Authorization":"Bearer {}".format(api_token), "Content-Type": "application/json"})
    uri = "https://api.cloudflare.com/client/v4/zones/{}/dns_records".format(zone_id)
    record_ids = get_record_ids(session, uri, fqdn, verify)
    ips = get_public_ip(mode, verify)
    if record_ids['A'] == False:
        if mode in ["ipv4", "all"] and ips['ipv4'] is not None and len(ips['ipv4']) > 5:
            print("Unable to find A record. Creating new entry.")
            c = create_dns_record(session, uri, fqdn, ips['ipv4'], proxied, ttl, 'A', verify) 
            if type(c) == dict:
                print("Successfully created new A record with id: {}".format(c['result']['id']))
    else:
        for record in record_ids['A']:
            req_uri = "{}/{}".format(uri,record['id'])
            if mode in ["ipv4", "all"] and ips['ipv4'] is not None and len(ips['ipv4']) > 5 and record['type'] == "A":
                if ips['ipv4'] == record['ip']:
                    print("IPv4 Address Unchanged. Skipping...")
                else:
                    print("Updating {} DNS Record: {} with IP {}.".format(record['type'], record['name'], ips['ipv4']))
                    update_dns_record(session, req_uri, fqdn, ips['ipv4'], 'A', verify)
    if record_ids['AAAA'] == False:
        if mode in ["ipv6", "all"] and ips['ipv6'] is not None and len(ips['ipv6']) > 5:
            print("Unable to find AAAA record. Creating new entry.")
            c = create_dns_record(session, uri, fqdn, ips['ipv6'], proxied, ttl, 'AAAA', verify)
            if type(c) == dict:
                print("Successfully created new AAAA record with id: {}".format(c['result']['id']))
    else:
        for record in record_ids['AAAA']:
            if mode in ["ipv6", "all"] and ips['ipv6'] is not None and len(ips['ipv6']) > 5 and record['type'] == "AAAA":
                if ips['ipv6'] == record['ip']:
                    print("IPv6 Address Unchanged. Skipping...")
                else:
                    print("Updating {} DNS Record: {} with IP {}.".format(record['type'], record['name'], ips['ipv6']))
                    # Not feasible through CloudFlare API to update AAAA - need to delete and recreate at present. Leaving for if they add the capability later on.
                    #update_dns_record(session, uri, fqdn, ips['ipv6'], 'AAAA', verify) 
                    if delete_dns_record(session, req_uri, verify):
                        print("here")
                        create_dns_record(session, uri, fqdn, ips['ipv6'], proxied, ttl, 'AAAA', verify)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog = "CloudFlare Dynamic DNS Updater - CloudFlare-DDNS.py",
        description = "Dynamically updates CloudFlare via API calls with current recorded IP address",
        epilog = "Written by Phatkone/Ashikabi"
    )
    parser.add_argument('-z', '--zoneid', type = str, help = 'CloudFlare DNS Zone ID', required = True)
    parser.add_argument('-f', '--fqdn', type = str, help = 'FQDN / Hostname', required = True)
    parser.add_argument('-t', '--token', type = str, help = 'CloudFlare DNS API Token', required = True)
    parser.add_argument('-p', '--proxied', type = bool, help = 'Set record as proxied', action=argparse.BooleanOptionalAction, default = False)
    parser.add_argument('-m', '--mode', type = str, help = 'IPv4 / IPv6 / all', choices = ['IPv4', 'IPv6', 'all'], default = "IPv4")
    parser.add_argument('-l', '--ttl', type = int, help = 'DNS Record Time To Live (TTL) (1 for auto, or within 60-86400)', default = 1)
    parser.add_argument('-i', '--insecure', help = 'Ignore TLS/SSL Certificate', default = True, action = 'store_false')
    args = parser.parse_args()
    if not args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main(args.zoneid, args.fqdn, args.token, args.proxied, args.ttl, args.mode.lower(), args.insecure)
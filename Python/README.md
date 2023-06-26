# Python CloudFlare DDNS Script
## Usage
`python3 CloudFlare-DDNS.py -z|--zoneid <Zone ID> -f|--fqdn <FQDN> -t|--token <API Token> [-p|--proxied -m|--mode (IPv4|IPv6|all) -l|-ttl (1|60-86400) -i|--insecure]`  
 - Create an API Token in CloudFlare and retrieve your zone ID  
 - Create a Task Scheduler event to run this script on what ever interval you desire.  
 - Set the variables.  
 - Execute.  
  
Defaults to be proxied, IPv4 only with the TTL set to auto (1)

## License
GNU GPL 3.0 applies
  
## Author 
 [Phatkone](https://github.com/Phatkone)
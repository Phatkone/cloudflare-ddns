# Python CloudFlare DDNS Script
## Usage
`python3 CloudFlare-DDNS.py -z|--zoneid <Zone ID> -f|--fqdn <FQDN> -t|--token <API Token> [-p|--proxied -m|--mode (IPv4|IPv6|all) -l|-ttl (1|60-86400) -i|--insecure]`  
 - Create an API Token in CloudFlare and retrieve your zone ID  
 - Create a Task Scheduler event to run this script on what ever interval you desire.  
 - Set the variables.  
 - Execute.  
  
Defaults to be proxied, IPv4 only with the TTL set to auto (1)

# Python CloudFlare Dynamic Gateway Updater Script
## Usage
`python3 CloudFlare-Gateway.py -a|--accountid <Account ID> -g|--gateway <Gateway Name> -t|--token <API Token> [-i|--insecure]`  
 - Create an API Token in CloudFlare and retrieve your Account ID  
 - Create a Task Scheduler event to run this script on what ever interval you desire.  
 - Set the variables.  
 - Execute.  

## License
GNU GPL 3.0 applies
  
## Author 
 [Phatkone](https://github.com/Phatkone)

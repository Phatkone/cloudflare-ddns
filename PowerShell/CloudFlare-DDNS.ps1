#Input Variables
$zone_id = "";
$fqdn = "";
$api_token = "";
$proxied = $False; # Set to $True for proxied or $False for direct.
$ttl = 1800; # (Seconds) Set to 1 for automatic. or between 60 and 86400

#Main Script - No need to edit beyond here.
if ($zone_id.Length -le 1 -or $fqdn.Length -le 4 -or $api_token.Length -le 1) {
    write-host "Missing required fields. Please check and try again";
    exit;
}
$list_uri = "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records";
# Force IPv4 IP Address Lookup
$ifconfig = (Resolve-DnsName -Name "ifconfig.io" -Type A).IPAddress[0];
$ipv4 = (Invoke-WebRequest -Uri https://${ifconfig}/ip -Headers @{"Host"="ifconfig.io"}).content -replace "`n","" -replace "`r","";
# Set authorization and content type headers.
$headers = @{};
$headers.Add("Authorization", "Bearer ${api_token}");
$headers.Add("Content-Type", "application/json");

# Pull existing DNS records
$records_req = Invoke-WebRequest -Uri $list_uri -Headers $headers -Method Get -ErrorAction SilentlyContinue

if ($records_req.StatusCode -ne 200) {
    write-host "Invalid AuthZ Token";
    exit;
}
$records = $records_req.content | ConvertFrom-Json
$record_id = "";

# Loop results to find record ID.
foreach ($record in $records.result) {
    if ($record.name -eq $fqdn) {
        # Record Found
        $record_id = $record.id;
        break;
    }
}
# Set update URI.
$update_uri = "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}";
$method = "PUT";
if ($record_id.Length -le 1) {
    # ID not found, setting URI for creation.
    write-host "Unable to find existing DNS record. Creating Record";
    $update_uri = "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/";
    $method = "POST";
}

# Set and create Body content
$body = @{}
$body.Add("content","${ipv4}");
$body.Add("name", "${fqdn}");
$body.Add("type", "A");
$body.Add("ttl","${ttl}");
$body.Add("proxied",$proxied);
$body.Add("comment","Dynamically Updated DNS Record");

# Send PUT request to CloudFlare API to update DNS A Record
$update = Invoke-WebRequest -Uri $update_uri -Body ($body|ConvertTo-Json) -Headers $headers -Method $method -ContentType "application/json"
write-host $update
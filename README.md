# xcname

###Example usage

Scan a single subdomain record:
```
./xcname.py -g GANDI_API_KEY -d subdomain.example.com
```

Scan a list of subdomains for expired CNAME records:
```
./xcname.py -g GANDI_API_KEY -l domain_list.txt
```

Perform a zone transfer and if successful parse the results for expired CNAME records:
```
./xcname.py -g GANDI_API_KEY -z global-transfers-allowed.com
```

Perform zone tranfsers against a list of domains and parse the results for expired CNAME records:
```
./xcname.py -g GANDI_API_KEY -l domain_list.txt -z
```

Print nameservers for a specific domain
```
./xcname.py -g GANDI_API_KEY -d example.com -ns
```


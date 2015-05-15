# xcname

###Example usage

Scan a single subdomain record:
```
./xcname.py -g GANDI_API_KEY -d subdomain.example.com
```

Perform a zone transfer and if successful parse the results for expired CNAME records:
```
./xcname.py -g GANDI_API_KEY -z global-transfers-allowed.com
```

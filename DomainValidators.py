'''
These classes peform a variety of tests to see if a domain
has expired or is available for purchase.

@author: moloch
'''

import time
import requests
import xmlrpclib

from whois import whois
from whois.parser import PywhoisError


class DomainValidator(object):

    ''' Interface class '''

    version = ''

    def __init__(self, *args):
        pass

    def is_available(self):
        raise NotImplementedError()


class DomainComAPI(DomainValidator):

    '''
    This class uses the reverse-engineered Domain.com web API, if we ever
    feel like speeding this up, using non-blocking requests would cut down
    on search time significantly.
    '''

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64)',
    }

    URL = "https://secure.domain.com/register/pages/dom_lookup_json.cmp"
    ARGS = "?autoAdd=false&search_type=standard&dom_lookup="

    version = '0.1'

    def is_available(self, domain):
        resp = requests.get(self.URL + self.ARGS + domain,
                            headers=self.headers)
        for offer in resp.json():
            if offer['domain'] == domain:
                return offer['availability'] != 0
        return False


class GandiAPI(DomainValidator):

    '''
    This is simple wrapper object to abstract the Gandi API, it's
    rather ineffecient since everything blocks but we're not
    super concerned with performance anyways. It is a much more accurate
    test than using WHOIS.
    '''

    XMLRPC_URL = 'https://rpc.gandi.net/xmlrpc/'

    def __init__(self, api_key):
        self.api_key = api_key
        self.api = xmlrpclib.ServerProxy(self.XMLRPC_URL)

    @property
    def version(self):
        return self.api.version.info(self.api_key)

    def is_available(self, domain, count=0):
        domain = domain.lower()
        ''' This is a blocking call to see if the domain is available '''
        if 10 <= count:
            return False

        ''' Put try block here '''
        try:
            result = self.api.domain.available(self.api_key, [domain])
        except:
            return False
        if result[domain] == 'pending':
            time.sleep(0.25)
            return self.is_available(domain, count=count + 1)
        return result[domain].lower().strip() == 'available'


class WhoIs(DomainValidator):

    '''
    This class uses the WHOIS database to attempt to see if domains
    are expired/available. It is not as accurate as using the Gandi API,
    but it also doesn't require an account or API keys/etc
    '''

    version = '0.1'

    def is_available(self, domain):
        ''' Blindly grabbing PywhoisError isn't ideal but works '''
        try:
            whois(domain)
            return False
        except PywhoisError:
            return True


domain_validators = {
    'whois': WhoIs,
    'gandi': GandiAPI,
    'domaincom': DomainComAPI
}

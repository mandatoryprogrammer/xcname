#!/usr/bin/env python 
import dns.resolver
import dns.zone
import dns.query
import tldextract
import argparse
import random
import socket
import string
import signal
import json
import sys
import os

from contextlib import contextmanager
from DomainValidators import domain_validators, DomainComAPI

# http://stackoverflow.com/a/287944/1195812
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class xcname:
    def __init__( self, gandi_key, verbose = True ):
        self.verbose = verbose
        self.gandi_key = gandi_key
        self.domain_cache = {}
        self.RECORD_MAP = {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            6: 'SOA',
            11: 'WKS',
            12: 'PTR',
            15: 'MX',
            16: 'TXT',
            17: 'RP',
            18: 'AFSDB',
            33: 'SRV',
            38: 'A6'
        }

    def is_expired( self, domain ):
        '''
        Validate domain is expired
        '''
        self.statusmsg( 'Checking if ' + domain + ' is expired...' )
        if domain in self.domain_cache:
            return self.domain_cache[ domain ]
        else:
            validator = domain_validators.get( 'gandi' )
            domain_validator = validator( self.gandi_key )
            expired = domain_validator.is_available( domain )
            self.domain_cache[ domain ] = expired
            return expired

    def statusmsg( self, msg, mtype = 'status' ):
        '''
        Status messages
        '''
        if mtype == 'status':
            print '[ STATUS ] ' + msg
        elif mtype == 'warning':
            print bcolors.WARNING + '[ WARNING ] ' + msg + bcolors.ENDC
        elif mtype == 'error':
            print bcolors.FAIL + '[ ERROR ] ' + msg + bcolors.ENDC
        elif mtype == 'success':
            print bcolors.OKGREEN + '[ SUCCESS ] ' + msg + bcolors.ENDC

    def typenum_to_name( self, num ):
        ''' 
        Turn DNS type number into it's corresponding DNS record name
        e.g. 5 => CNAME, 1 => A
        '''
        if num in self.RECORD_MAP:
            return self.RECORD_MAP[ num ]
        else:
            # Some record type we don't recognize
            return "UNK"

    @contextmanager
    def time_limit( self, seconds ):
        '''
        Timeout handler to hack around a bug in dnspython with AXFR not obeying it's timeouts 
        '''
        def signal_handler(signum, frame):
            raise Exception("TIMEOUT")
        signal.signal(signal.SIGALRM, signal_handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)

    def get_zone_cnames( self, nameservers ):
        '''
        Attempts a zone transfer on all nameservers and returns a list of CNAME references if successful
        '''
        ret_dns_data = {}
        for nameserver in nameservers:
            self.statusmsg( 'Getting DNS data from ' + nameserver )
            try:
                with self.time_limit( 5 ):
                    zone = dns.zone.from_xfr( dns.query.xfr( nameserver, domain, timeout=5 ) )
                    self.statusmsg( 'Server responded to global transfer!' )
                    for name, node in zone.nodes.items():
                        rdataset = node.rdatasets[0]
                        if self.typenum_to_name( rdataset.rdtype ) == 'CNAME':
                            ret_dns_data[ str(name) ] = str( rdataset ).split( " " )[-1]
            except EOFError:
                self.statusmsg( "EOF Error", 'error' )
            except socket.error:
                self.statusmsg( "Socket error", 'error' )
            except dns.exception.FormError:
                self.statusmsg(  "Server denied our AXFR request", 'error' )
            except dns.zone.NoNS:
                self.statusmsg( "No nameservers", 'error' )
            except dns.exception.SyntaxError:
                self.statusmsg( "Syntax error?", 'error' )
            except Exception as inst:
                if len( inst.args ) != 0 and inst.args[0] == "TIMEOUT":
                    self.statusmsg( "dnspython took too long to AXFR", 'error' )
                else:
                    raise inst

        return ret_dns_data

    def non_relative_filter( self, dns_data, filter_localhost = True ):
        '''
        Filters the DNS record dict returns from get_zone_cnames() to non-relative records for expired domain checking
        '''
        ret_dict = {}
        for key, value in dns_data.iteritems():
            if value[-1] == ".":
                if filter_localhost:
                    if value != "localhost.":
                        ret_dict[ key ] = value
                else:
                    ret_dict[ key ] = value
        return ret_dict

    def get_cname( self, domain ):
        '''
        Check to see if CNAME is pointing to expired domain
        '''
        try:
            answer = dns.resolver.query( domain, "CNAME" )
            if len( answer ) > 0:
                return str( answer[0] )
        except dns.resolver.NoAnswer:
            self.statusmsg( 'No answer received from DNS server' )
        except dns.resolver.NXDOMAIN:
            self.statusmsg( 'NXDOMAIN, dead end' )
        return False

    def scan_cname( self, domain, initial = False ):
        '''
        Recursively crawl single CNAME record for expired domain pointer
        '''
        if initial:
            self.statusmsg( 'Checking ' + domain + ' for expired CNAME records...' )
        base_domain = self.parse_tld( domain )
        pointed_domain = self.get_cname( domain )

        if pointed_domain:
            self.statusmsg( domain + ' => ' + pointed_domain )
            # Check if the pointed domain is just the base domain, if so return False
            if pointed_domain[:-1] == base_domain:
                self.statusmsg( "Subdomain just points to base domain." )
                return False
            # Check if it's still a subdomain of the main domain. If so, we must go deeper!
            elif self.parse_tld( domain ) == self.parse_tld( pointed_domain ):
                return self.scan_cname( pointed_domain )
            elif self.is_expired( self.parse_tld( pointed_domain ) ):
                return pointed_domain
        return False

    def pprint( self, input_dict ):
        '''
        Prints dicts in a JSON pretty sort of way
        '''
        print json.dumps(input_dict, sort_keys=True, indent=4, separators=(',', ': '))

    def get_nameserver_list( self, domain ):
        '''
        Query the list of authoritative nameservers for a domain

        It is important to query all of these as it only takes one misconfigured server to give away the zone.
        '''
        try:
            answers = dns.resolver.query( domain, 'NS' )
        except dns.resolver.NXDOMAIN:
            self.statusmsg( "NXDOMAIN - domain name doesn't exist", 'error' )
            return []
        except dns.resolver.NoNameservers:
            self.statusmsg( "No nameservers returned!", 'error' )
            return []
        except dns.exception.Timeout:
            self.statusmsg( "Nameserver request timed out (wat)", 'error' )
            return []
        except dns.resolver.NoAnswer:
            self.statusmsg( "No answer", 'error' )
            return []
        nameservers = []
        for rdata in answers:
            nameservers.append( str( rdata ) )
        return nameservers

    def parse_tld( self, domain ):
        '''
        Parse DNS CNAME external pointer to get the base domain (stolen from moloch's source code, sorry buddy)
        '''
        url = 'http://' + str( domain ) # Hack to get parse_tld to work with us
        tld = tldextract.extract(url)
        if tld.suffix == '':
            return tld.domain
        else:
            return "%s.%s" % (tld.domain, tld.suffix)

if __name__ == "__main__":
    print unicode( """ 
`MM(   )P' 6MMMMb.`MM 6MMb   6MMMMb  `MM 6MMb  6MMb   6MMMMb  
 `MM` ,P  6M'   Mb MMM9 `Mb 8M'  `Mb  MM69 `MM69 `Mb 6M'  `Mb 
  `MM,P   MM    `' MM'   MM     ,oMM  MM'   MM'   MM MM    MM 
   `MM.   MM       MM    MM ,6MM9'MM  MM    MM    MM MMMMMMMM 
   d`MM.  MM       MM    MM MM'   MM  MM    MM    MM MM       
  d' `MM. YM.   d9 MM    MM MM.  ,MM  MM    MM    MM YM    d9 
_d_  _)MM_ YMMMM9 _MM_  _MM_`YMMM9'Yb_MM_  _MM_  _MM_ YMMMM9  
 
                                Connecting the expired dots.
    """ )
    parser = argparse.ArgumentParser(description='Scan for expired CNAME records')
    parser.add_argument('-d', '--domain', dest='domain', help='Scan single domain for expired CNAME record')
    parser.add_argument('-l', '--list', dest='domain_list', help='Input a list of subdomains/domain')
    parser.add_argument('-z', '--zone-enum', dest='zone_enum', action='store_true', help='Attempt a zone transfer against each domain and check the resulting data for expired CNAME records')
    parser.add_argument('-s', '--sanity', dest='sanity', action='store_true', help='Check to ensure the domain checking functionality is sane')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Show verbose output during run')
    parser.add_argument('-g', '--gandi', dest='gandi', help='Gandi API key for checking if domain is expired (required)' )
    parser.add_argument('-ns', '--nameservers', dest='nameservers', action='store_true', help='Print out list of authoritative name servers for domain' )
    args = parser.parse_args()

    bs_domain = ( ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(30)) + '.com' ).lower() # Generate non-existant domain
    if args.verbose:
        xcnamer = xcname( args.gandi )
    else:
        xcnamer = xcname( args.gandi, False )

    if args.domain_list:
        # Ensure the file exists
        if not os.path.exists( args.domain_list ):
            xcnamer.statusmsg( 'Error, domain list does not exist!', 'error' )
            exit()

        f = open( args.domain_list )
        domains = f.read().split( "\n" )
        domains = [ domain for domain in domains if domain.strip().lower() != "" ]
        f.close()


    # Check to see if we're sane
    if args.sanity:
        if not args.gandi:
            xcnamer.statusmsg( 'Cannot check expired domain without Gandi API key!', 'error' )
            exit();
        if xcnamer.is_expired( bs_domain ):
            xcnamer.statusmsg( "Domain name checker appears to be sane!" )
        else:
            xcnamer.statusmsg( "Domain namer checker failed sanity check - are you using the production API key?", 'error' )
            sys.exit()

    # Print out list of nameservers
    if args.domain and args.nameservers:
        xcnamer.pprint( xcnamer.get_nameserver_list( args.domain ) )
        exit()

    # Single domain specified
    if args.domain:
        if not args.gandi:
            xcnamer.statusmsg( 'Cannot check expired domain without Gandi API key!', 'error' )
            exit();
        result = xcnamer.scan_cname( args.domain, True )
        if result:
            xcnamer.statusmsg( 'Domain points to an expired domain: ' + result, 'success' )

    # Zone scan specified
    if args.zone_enum:
        results = {} # A dict with the key being the subdomain and the value being the external expired domain
        tdomains = []
        if args.domain:
            tdomains.append( args.domain )
        elif args.domain_list:
            for domain in domains:
                tdomains.append( domain )
        else:
            self.statusmsg( 'No domains specified!', 'error' )
            exit()

        try:
            for domain in tdomains:
                xcnamer.statusmsg( 'Performing zone transfer scan on ' + domain )
                nameservers = xcnamer.get_nameserver_list( domain )
                for nameserver in nameservers:
                    xcnamer.statusmsg( 'Nameserver ' + nameserver + ' enumerated.' )
                    if xcnamer.is_expired( xcnamer.parse_tld( nameserver ) ):
                        xcnamer.statusmsg( 'Nameserver ' + nameserver + ' is expired!', 'success' )

                cnames = xcnamer.get_zone_cnames( nameservers )
                external_domain_references = xcnamer.non_relative_filter( cnames )

                for subdomain, rdomain in external_domain_references.iteritems():
                    full_subdomain = subdomain + "." + domain
                    xcnamer.statusmsg( "Checking " + full_subdomain + " => " + rdomain + " for exired domain" )
                    cname_result = xcnamer.scan_cname( full_subdomain, True )
                    if cname_result:
                        xcnamer.statusmsg( "Expired domain CNAME found: " + full_subdomain + " points to expired " + rdomain )
                        results[ full_subdomain ] = rdomain
        except KeyboardInterrupt:
            xcnamer.statusmsg( 'User has canceled the scan, printing results...', 'error' )
        xcnamer.pprint( results )

    # Domain list specified
    if args.domain_list and not args.zone_enum:
        results = {} # A dict with the key being the subdomain and the value being the external expired domain

        for domain in domains:
            result = xcnamer.scan_cname( domain, True )
            if result:
                xcnamer.statusmsg( 'Domain points to an expired domain: ' + result, 'success' )
                results[ domain ] = result
        
        if results:
            xcnamer.pprint( results )
        else:
            xcnamer.statusmsg( 'No expired CNAME records found in list of subdomains!' )

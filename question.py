import string
import random
from termcolor import cprint

import dns.resolver
import dns.name
import socket

RANDOM_DOMAIN_SUFFIX = ".zealbino.com"


def get_authoritative_record(qrecord):
    """
    Takes a hostname, finds its authoritative name server and returns the initial
    TTL and ip addresses for the IN A or IN CNAME record.
    """

    domain = qrecord
    auth_ns = None

    default_resolver = dns.resolver.Resolver()
    default_resolver.nameservers = ['8.8.8.8']

    # Let's first find the most authoritative DNS for this hostname:
    while(domain):
        print("Whois SOA for %s?" % (domain))
        try:
            response = default_resolver.resolve(domain, rdtype=dns.rdatatype.SOA)
        except Exception as e:
            domain = '.'.join(domain.split('.')[1:])
            continue
        if len(response) > 0:
            # Check if this SOA response is really about this domain
            if domain.endswith(str(response.canonical_name).rstrip('.')):
                auth_ns = str(response[0].mname)
                print("%s is SOA for %s" % (auth_ns, domain))
                break
        domain = '.'.join(domain.split('.')[1:])
    if auth_ns:
        ns_addr = socket.gethostbyname(auth_ns)
        print("DNS Authoritative Query for qrecord: %s @%s/%s" % (qrecord, auth_ns, ns_addr))

        # First we try A record:
        response = None
        try:
            request = dns.message.make_query(qrecord, dns.rdatatype.A)
            response = dns.query.udp(request, ns_addr, timeout=5)
        except Exception as e:
            print('Exception while requesting authoritative A Record: %s' % (e))
            pass
        if response:
            for answer in response.answer:
                if answer.rdtype == dns.rdatatype.A:
                    ttl = answer.ttl
                    addresses = [str(x) for x in answer]
                    print("%s IN A %s TTL %s" % (qrecord, addresses, ttl))
                    return ttl, addresses, dns.rdatatype.A

        # Then we try CNAME:
        response = None
        try:
            request = dns.message.make_query(qrecord, dns.rdatatype.CNAME)
            response = dns.query.udp(request, ns_addr, timeout=5)
        except Exception as e:
            print('Exception while requesting authoritative CNAME Record: %s' % (e))
            pass
        if response:
            for answer in response.answer:
                if answer.rdtype == dns.rdatatype.CNAME:
                    ttl = answer.ttl
                    addresses = [str(x) for x in answer]
                    print("%s IN CNAME %s TTL %s" % (qrecord, addresses, ttl))
                    return ttl, addresses, dns.rdatatype.CNAME

            # Finally we look for NXDOMAIN in the response and use that response as well
            if response.rcode() == dns.rcode.NXDOMAIN:
                if len(response.authority) >= 1:
                    if response.authority[0].rdtype == dns.rdatatype.SOA:
                        return response.authority[0].ttl, [], dns.rcode.NXDOMAIN

    return None, None, None


class Answer:
    def __init__(self, nameserver):
        pass


class Question:
    def __init__(self, qname):
        if qname == 'random':
            self._qname = ''.join(random.choices(string.ascii_lowercase, k=12)) + RANDOM_DOMAIN_SUFFIX
            self.is_random = True
        else:
            self._qname = qname
            self.is_random = False
        initial_ttl, addresses, rdtype = get_authoritative_record(self.qname)
        if not initial_ttl:
            print(self.qname)
            raise ValueError('Invalid qname %s' % (self._qname))

        if rdtype == dns.rcode.NXDOMAIN:
            self.is_nxdomain = True
        else:
            self.is_nxdomain = False

        self.rdtype = rdtype
        self.initial_ttl = initial_ttl
        self.addresses = addresses
        self.positives = 0
        self.negatives = 0

        print("Question %s: Initial TTL: %s, Addresses: %s" %
              (qname, initial_ttl, addresses))

    @property
    def qname(self):
        if self.is_random:
            self._qname = ''.join(random.choices(string.ascii_lowercase, k=12)) + RANDOM_DOMAIN_SUFFIX
        return self._qname

    def add_negative(self, nameserver):
        cprint("%s is NOT cached at %s" % (self.qname, nameserver), 'white')
        self.negatives += 1

    def add_positive(self, nameserver, ttl):
        cprint("%s IS cached at %s with TTL %s" % (self.qname, nameserver, ttl), 'green')
        self.positives += 1

    def cache_presence_pct(self):
        return (self.positives / (self.positives + self.negatives)) * 100

    def is_poisoned(self, nameserver, addresses):
        for a in addresses:
            if a not in self.addresses:
                cprint("%s IS POISONED at %s with address %s" % (self.qname, nameserver, a), 'yellow')
                return True
        return False

#!/usr/bin/env python3

from threading import Thread
from scapy.all import conf, sniff, IP, UDP, DNS, DNSQR, get_if_addr
import re
import time
import random
import argparse
import dns.resolver
import dns.name

from custom_logger import get_logger
from termcolor import cprint

from resolvers import Resolvers
from question import Question, RANDOM_DOMAIN_SUFFIX

logger = get_logger()


# Gets called whenever a DNS response is received:
def process_dns_pkt(p):
    global stopped
    global questions

    if (stopped):
        return False

    if not p.haslayer(DNS) or p[DNS].qdcount == 0:
        return False

    qname = p[DNS].qd[0].qname.decode().rstrip('.')
    resolver_ip = str(p[IP].src)
    ancount = p[DNS].ancount
    rcode = p[DNS].rcode
    recursion_available = p[DNS].ra

    # if the answer does not come from one of the queried addresses, bail
    if resolver_ip not in myresolvers.resolvers.keys():
        return False

    # Update global response count for this resolver:
    myresolvers.resolvers[resolver_ip].rcount += 1

    for question in questions:
        if question.qname == qname or (question.is_random and qname.endswith(RANDOM_DOMAIN_SUFFIX)):
            # If recursion is not available, this is not a good candidate for cache snooping:
            if not recursion_available:
                myresolvers.resolvers[resolver_ip].misbehaved("Recursion is not available")
                continue

            # Regular requests:
            if (question.rdtype == dns.rdatatype.CNAME or question.rdtype == dns.rdatatype.A) and rcode == 0:
                if ancount == 0:
                    question.add_negative(resolver_ip)
                else:
                    ttl = int(p[DNS].an[0].ttl)
                    rdbit = bool(p[DNS].rd)
                    if rdbit:
                        myresolvers.resolvers[resolver_ip].misbehaved("Ignores (and sets) RD Bit")
                    else:
                        if p[DNS].an[0].type == dns.rdatatype.A:
                            addresses = [str(x.rdata) for x in (p[DNS].an)]
                        else:
                            addresses = [x.rdata.decode() for x in (p[DNS].an)]
                        if question.is_poisoned(resolver_ip, addresses):
                            justwarn = not args.checkpoison
                            if question.is_random:
                                # We will optionally ignore poisoned caches, but should never ignore
                                # poisoned caches while calibrating
                                justwarn = False
                            myresolvers.resolvers[resolver_ip].misbehaved("Poisoned Cache", justwarn=justwarn)
                            if not args.checkpoison and not question.is_random:
                                # If we are ignoring poisoned servers, we will also consider this a cache hit:
                                question.add_positive(resolver_ip, ttl)
                        else:
                            if question.is_random:
                                # While calibrating, the record should NEVER be cached. So we add this
                                # resolver to the list of misbehaving servers:
                                myresolvers.resolvers[resolver_ip].misbehaved("Ignores (and does NOT set) RD Bit")
                            else:
                                question.add_positive(resolver_ip, ttl)

            # NXDOMAIN requests:
            if (question.rdtype == dns.rcode.NXDOMAIN):
                if rcode == dns.rcode.NXDOMAIN:
                    rdbit = bool(p[DNS].rd)
                    nscount = p[DNS].nscount
                    if rdbit:
                        myresolvers.resolvers[resolver_ip].misbehaved("Ignores (and sets) RD Bit")
                    else:
                        if nscount > 0:
                            ttl = int(p[DNS].ns[0].ttl)
                            question.add_positive(resolver_ip, ttl)
                else:
                    question.add_negative(resolver_ip)



    return False


# Send Thread:
def sendqueries(resolver_list, question):
    local_list = resolver_list.copy()
    while (len(local_list) > 0):
        address = local_list.pop(0)
        send_query(address, question.qname, question.rdtype)

        # Update global query count for this resolver
        myresolvers.resolvers[address].qcount += 1

        if (stopped):
            logger.info("got stop signal")
            break
    logger.info("Ending send thread")


def send_query(nameserver, qname, qtype):
    s = conf.L3socket(iface=args.ifname)
    # recursion desired bit is zero:
    packet = IP(dst=nameserver)/UDP(dport=53)/DNS(
        rd=0, id=random.getrandbits(16), qd=DNSQR(qname=qname, qtype=qtype))
    s.send(packet)


# Receive Thread:
def recvqueries():
    ifname = args.ifname
    localip = get_if_addr(conf.iface)
    sniff(iface=ifname, prn=None, filter="udp src port 53 and src host not " + localip, store=0,
          stop_filter=process_dns_pkt)
    logger.info("Ending receive thread")


# Sweep domains:
# This is the main code of the DNS sweep function. It takes a list of hostnames (or a keyword),
# and interrogates the cache of the pool of resolvers to infer its presence in the cache.
# It will remove caches from the pool that are unresponsive or don't support non-recursive queries.
# 
# If the hostname is the keyword "calibrate", it will "self-calibrate" by querying a list of random hostnames
# And removing any caches that claim to have that record cached.
# The list will then be refilled with new caches from the list.


def main():
    # GLOBAL VARIABLES:
    global args
    global nthreads
    global myresolvers
    global stopped
    global questions

    # Parse command line arguments:
    parser = argparse.ArgumentParser(description="DNS cache health check")
    parser.add_argument("-i", metavar="eth0", default=None, dest="ifname", type=str,
                        help="network interface to use", required=False)
    parser.add_argument("-r", metavar="openresolvers.txt", dest="opresover_file", type=str,
                        help="file containing ip addresses of open resolvers", required=True)
    parser.add_argument("-m", metavar=1000, default=1000, dest="maxresolvers", type=int,
                        help="number of resolvers to query")
    parser.add_argument("-p", default=False, dest="checkpoison", type=bool,
                        help="verify if cache is poisoning records", required=False)

    args = parser.parse_args()

    if not args.ifname:
        args.ifname = conf.iface

    logger.info("Reading DNS resolvers pool...")
    myresolvers = Resolvers(max_resolvers=args.maxresolvers, file=args.opresover_file)

    stopped = False
    # start receiving thread
    recvthread = Thread(target=recvqueries)
    recvthread.start()

    # Do an initial calibration pass first
    do_calibration(50)

    while(1):
        inputline = input("enter dns records to query, separated by commas, or 'help': ")
        if inputline == "help":
            print("valid commands: 'help', 'stats', 'calibrate', 'write', 'write_extra' or a comma separated list of hostnames.")
            continue
        if inputline == "stats":
            myresolvers.show_resolver_stats()
            continue
        if inputline.startswith('write '):
            # Write the current resolver list (without the purged resolvers) into a new file
            outfile = inputline.split(' ')[1]
            if not outfile:
                logger.error('Error writing to file %s' % outfile)
                continue
            myresolvers.write_to_file(outfile)
            logger.info('Wrote tested resolvers to file %s' % outfile)
            continue
        if inputline.startswith('write_extra '):
            # Write the current resolver list (without the purged resolvers) into a new file,
            # plus the current untested resolvers
            outfile = inputline.split(' ')[1]
            if not outfile:
                logger.error('Error writing to file %s' % outfile)
                continue
            myresolvers.write_to_file(outfile, extra=True)
            logger.info('Wrote tested + other resolvers to file %s' % outfile)
            continue
        if inputline == "calibrate":
            do_calibration(50)
        else:
            do_dns_snooping(inputline)
            for question in questions:
                cprint("%s is %02f popular within the responding nameservers" %
                       (question.qname, question.cache_presence_pct()), 'white', attrs=['bold'])


def do_calibration(threshold):
    global myresolvers
    global stopped
    global questions

    myresolvers.start_snoop_test()

    random_question = Question('random')
    questions = list()
    questions.append(random_question)

    stopped = False

    # There will be one send thread for each hostname queried
    logger.info("Checking DNS Cache Snooping capabilities for our current pool")

    test_pass = 1
    while(len(myresolvers.untested_resolver_ips()) > threshold):
        logger.debug('Testing, pass %i, untested_resolvers: %i' % (test_pass, len(myresolvers.untested_resolver_ips())))
        untested_list = myresolvers.untested_resolver_ips()
        sendqueries(untested_list, random_question)
        time.sleep(2)
        myresolvers.mark_tested(untested_list)
        myresolvers.purge_misbehaving()
        myresolvers.purge_unresponsive(1)
        myresolvers.add_resolvers()
        test_pass += 1

    stopped = True


def do_dns_snooping(hosts_str):
    global myresolvers
    global stopped
    global questions

    send_threads = []

    qnames = re.split(',|\s', hosts_str)

    stopped = False

    questions = list()
    for qname in qnames:
        try:
            question = Question(qname)
        except ValueError:
            logger.error("unable to create %s" % (qname))
        else:
            questions.append(question)

    if not questions:
        return

    main_list = [x for x in myresolvers.resolvers.keys()]
    random.shuffle(main_list)

    # There will be one send thread for each hostname queried
    for question in questions:
        logger.info("DNS Snooping for %s" % (question.qname))
        t = Thread(target=sendqueries, args=(main_list, question))
        t.start()
        send_threads.append(t)

    # Wait for send threads to finish:
    for t in send_threads:
        t.join()

    time.sleep(2)
    stopped = True

    myresolvers.purge_misbehaving()
    myresolvers.purge_unresponsive(1)
    myresolvers.add_resolvers()


if __name__ == '__main__':
    main()

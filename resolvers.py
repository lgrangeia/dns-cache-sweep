from geolite2 import geolite2
import os
from custom_logger import get_logger


logger = get_logger()

geo = geolite2.reader()


def get_country(ip):
    try:
        x = geo.get(ip)
    except ValueError:
        return None
    try:
        return x['country']['names']['en'] if x else None
    except KeyError:
        return None


def get_continent(ip):
    try:
        x = geo.get(ip)
    except ValueError:
        return None
    try:
        return x['continent']['names']['en'] if x else None
    except KeyError:
        return None


class Resolver:
    def __init__(self, ip, country, continent):
        self.ip = ip
        self.country = country
        self.continent = continent
        self.misbehaving = False
        self.snoop_tested = False
        self.qcount = 0
        self.rcount = 0

    def misbehaved(self, reason, justwarn=False):
        if not justwarn:
            logger.warn("resolver %s misbehaved, will remove from pool: %s" % (self.ip, reason))
            self.misbehaving = True
        else:
            logger.info("resolver %s misbehaved (will not remove): %s" % (self.ip, reason))


class Resolvers:
    def __init__(self, max_resolvers=1000, file=None):
        self.resolvers = {}
        self.max_resolvers = max_resolvers
        self.rfile = open(file, "r")
        self.geo = geolite2.reader()

        self.add_resolvers()

    def purge_misbehaving(self):
        i = 0
        for resolver in list(self.resolvers.values()).copy():
            if resolver.misbehaving:
                self.resolvers.pop(resolver.ip)
                i += 1
        logger.info("Purged %s misbehaving resolvers" % (i))

    def purge_unresponsive(self, threshold):
        i = 0
        for resolver in list(self.resolvers.values()).copy():
            if resolver.qcount - resolver.rcount >= threshold:
                self.resolvers.pop(resolver.ip)
                i += 1
        logger.info("Purged %s unresponsive resolvers that failed to answer at least %s queries" %
                    (i, threshold))

    def add_resolvers(self):
        i = 0
        while line := self.rfile.readline().strip():
            res_ip = line
            if res_ip in self.resolvers.keys():
                continue
            res_country = get_country(res_ip)
            res_continent = get_continent(res_ip)
            print("ip: %s, country: %s, continent: %s" % (res_ip, res_country, res_continent))
            resolver = Resolver(res_ip, res_country, res_continent)
            self.resolvers[res_ip] = resolver
            i += 1

            if len(self.resolvers) >= self.max_resolvers:
                logger.info("Added %s more resolvers" % (i))
                return

    def start_snoop_test(self):
        for resolver in self.resolvers.values():
            resolver.snoop_tested = False

    def untested_resolver_ips(self):
        resolvers = list()
        for resolver in self.resolvers.values():
            if not resolver.snoop_tested:
                resolvers.append(resolver.ip)
        return resolvers

    def mark_tested(self, ip_list):
        for ip in ip_list:
            self.resolvers[ip].snoop_tested = True

    def show_resolver_stats(self):
        countries = {}
        continents = {}
        for resolver in self.resolvers.values():
            countries[resolver.country] = countries.get(resolver.country, 0) + 1
            continents[resolver.continent] = continents.get(resolver.continent, 0) + 1
        print("Currently %i DNS resolvers in the pool" % len(self.resolvers.keys()))
        for c in sorted(countries, key=countries.get, reverse=True):
            print("country: %s, resolvers: %s" % (c, countries[c]))
        for c in sorted(continents, key=continents.get, reverse=True):
            print("continent: %s, resolvers: %s" % (c, continents[c]))

    def write_to_file(self, outfile, extra=False):
        if os.path.isfile(outfile):
            print('File %s already exists, will not overwrite. Aborting.' % (outfile))
            return
        outfd = open(outfile, "w+")
        for resolver_ip in self.resolvers.keys():
            outfd.write(resolver_ip + '\n')
        if extra:
            current_pos = self.rfile.tell()
            while line := self.rfile.readline().strip():
                res_ip = line
                outfd.write(res_ip + '\n')
            self.rfile.seek(current_pos)
        outfd.close()

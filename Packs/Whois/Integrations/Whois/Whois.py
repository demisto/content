import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import re
import socket
import sys
import socks
import ipwhois
from typing import Dict, List, Optional, Type
import urllib
import whois
from whois.parser import PywhoisError
import dateparser.search

RATE_LIMIT_RETRY_COUNT_DEFAULT: int = 0
RATE_LIMIT_WAIT_SECONDS_DEFAULT: int = 120
RATE_LIMIT_ERRORS_SUPPRESSEDL_DEFAULT: bool = False

# flake8: noqa

"""
    This integration is built using the joepie91 "Whois" module. For more information regarding this package please see
    the following - https://github.com/joepie91/python-whois
"""

''' HELPER FUNCTIONS '''
# About the drop some mean regex right now disable-secrets-detection-start
tlds = {
    "_": {
        "schema": "2",
        "updated": "2018-10-05 11:43:46 UTC"
    },
    "aaa": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "aarp": {
        "_type": "newgtld",
        "host": "whois.nic.aarp"
    },
    "abarth": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "abb": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "abbott": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "abbvie": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "abc": {
        "_type": "newgtld",
        "host": "whois.nic.abc"
    },
    "able": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "abogado": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.abogado"
    },
    "abudhabi": {
        "_type": "newgtld",
        "host": "whois.nic.abudhabi"
    },
    "ac": {
        "host": "whois.nic.ac"
    },
    "academy": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.academy"
    },
    "accenture": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "accountant": {
        "_type": "newgtld",
        "host": "whois.nic.accountant"
    },
    "accountants": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.accountants"
    },
    "aco": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "active": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "actor": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.actor"
    },
    "ad": {
        "adapter": "none"
    },
    "adac": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "ads": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "adult": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "ae": {
        "host": "whois.aeda.net.ae"
    },
    "aeg": {
        "_type": "newgtld",
        "host": "whois.nic.aeg"
    },
    "aero": {
        "host": "whois.aero"
    },
    "aetna": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "af": {
        "host": "whois.nic.af"
    },
    "afamilycompany": {
        "_type": "newgtld",
        "host": "whois.nic.afamilycompany"
    },
    "afl": {
        "_type": "newgtld",
        "host": "whois.nic.afl"
    },
    "africa": {
        "_group": "zaregistry",
        "_type": "newgtld",
        "host": "africa-whois.registry.net.za"
    },
    "ag": {
        "host": "whois.nic.ag"
    },
    "agakhan": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "agency": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.agency"
    },
    "ai": {
        "host": "whois.nic.ai"
    },
    "aig": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "aigo": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "airbus": {
        "_type": "newgtld",
        "host": "whois.nic.airbus"
    },
    "airforce": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.airforce"
    },
    "airtel": {
        "_type": "newgtld",
        "host": "whois.nic.airtel"
    },
    "akdn": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "al": {
        "adapter": "none"
    },
    "alfaromeo": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "alibaba": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.alibaba"
    },
    "alipay": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.alipay"
    },
    "allfinanz": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "allstate": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "ally": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.ally"
    },
    "alsace": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois-alsace.nic.fr"
    },
    "alstom": {
        "_type": "newgtld",
        "host": "whois.nic.alstom"
    },
    "am": {
        "host": "whois.amnic.net"
    },
    "americanexpress": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "americanfamily": {
        "_type": "newgtld",
        "host": "whois.nic.americanfamily"
    },
    "amex": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "amfam": {
        "_type": "newgtld",
        "host": "whois.nic.amfam"
    },
    "amica": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "amsterdam": {
        "_type": "newgtld",
        "host": "whois.nic.amsterdam"
    },
    "analytics": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "android": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "anquan": {
        "_group": "teleinfo",
        "_type": "newgtld",
        "host": "whois.teleinfo.cn"
    },
    "anz": {
        "_type": "newgtld",
        "host": "whois.nic.anz"
    },
    "ao": {
        "adapter": "none"
    },
    "aol": {
        "_type": "newgtld",
        "host": "whois.nic.aol"
    },
    "apartments": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.apartments"
    },
    "app": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "apple": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "aq": {
        "adapter": "none"
    },
    "aquarelle": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois-aquarelle.nic.fr"
    },
    "ar": {
        "host": "whois.nic.ar"
    },
    "aramco": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "archi": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "army": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.army"
    },
    "arpa": {
        "host": "whois.iana.org"
    },
    "e164.arpa": {
        "host": "whois.ripe.net"
    },
    "in-addr.arpa": {
        "adapter": "arpa"
    },
    "art": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.art"
    },
    "arte": {
        "_type": "newgtld",
        "host": "whois.nic.arte"
    },
    "as": {
        "host": "whois.nic.as"
    },
    "asda": {
        "_type": "newgtld",
        "host": "whois.nic.asda"
    },
    "asia": {
        "host": "whois.nic.asia"
    },
    "associates": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.associates"
    },
    "at": {
        "host": "whois.nic.at"
    },
    "priv.at": {
        "host": "whois.nic.priv.at"
    },
    "athleta": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "attorney": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.attorney"
    },
    "au": {
        "host": "whois.auda.org.au"
    },
    "auction": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.auction"
    },
    "audi": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "audible": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "audio": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "auspost": {
        "_type": "newgtld",
        "host": "whois.nic.auspost"
    },
    "author": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "auto": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "autos": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "avianca": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "aw": {
        "host": "whois.nic.aw"
    },
    "aws": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none",
        "host": "whois.nic.aws"
    },
    "ax": {
        "host": "whois.ax"
    },
    "axa": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "az": {
        "adapter": "web",
        "url": "http://www.nic.az/"
    },
    "azure": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "ba": {
        "adapter": "web",
        "url": "http://nic.ba/lat/menu/view/13"
    },
    "baby": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "baidu": {
        "_group": "knet",
        "_type": "newgtld",
        "host": "whois.gtld.knet.cn"
    },
    "banamex": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "bananarepublic": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "band": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.band"
    },
    "bank": {
        "_type": "newgtld",
        "host": "whois.nic.bank"
    },
    "bar": {
        "_type": "newgtld",
        "host": "whois.nic.bar"
    },
    "barcelona": {
        "_type": "newgtld",
        "host": "whois.nic.barcelona"
    },
    "barclaycard": {
        "_type": "newgtld",
        "host": "whois.nic.barclaycard"
    },
    "barclays": {
        "_type": "newgtld",
        "host": "whois.nic.barclays"
    },
    "barefoot": {
        "_type": "newgtld",
        "host": "whois.nic.barefoot"
    },
    "bargains": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.bargains"
    },
    "baseball": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "basketball": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.basketball"
    },
    "bauhaus": {
        "_type": "newgtld",
        "host": "whois.nic.bauhaus"
    },
    "bayern": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.bayern"
    },
    "bb": {
        "adapter": "web",
        "url": "http://whois.telecoms.gov.bb/search_domain.php"
    },
    "bbc": {
        "_type": "newgtld",
        "host": "whois.nic.bbc"
    },
    "bbt": {
        "_type": "newgtld",
        "host": "whois.nic.bbt"
    },
    "bbva": {
        "_type": "newgtld",
        "host": "whois.nic.bbva"
    },
    "bcg": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.bcg"
    },
    "bcn": {
        "_type": "newgtld",
        "host": "whois.nic.bcn"
    },
    "bd": {
        "adapter": "web",
        "url": "http://whois.btcl.net.bd/"
    },
    "be": {
        "host": "whois.dns.be"
    },
    "beats": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "beauty": {
        "_type": "newgtld",
        "host": "whois.nic.beauty"
    },
    "beer": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.beer"
    },
    "bentley": {
        "_type": "newgtld",
        "host": "whois.nic.bentley"
    },
    "berlin": {
        "_type": "newgtld",
        "host": "whois.nic.berlin"
    },
    "best": {
        "_type": "newgtld",
        "host": "whois.nic.best"
    },
    "bestbuy": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.bestbuy"
    },
    "bet": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "bf": {
        "adapter": "none"
    },
    "bg": {
        "host": "whois.register.bg"
    },
    "bh": {
        "adapter": "none"
    },
    "bharti": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "bi": {
        "host": "whois1.nic.bi"
    },
    "bible": {
        "_type": "newgtld",
        "host": "whois.nic.bible"
    },
    "bid": {
        "_type": "newgtld",
        "host": "whois.nic.bid"
    },
    "bike": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.bike"
    },
    "bing": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "bingo": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.bingo"
    },
    "bio": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "biz": {
        "host": "whois.biz"
    },
    "bj": {
        "host": "whois.nic.bj"
    },
    "black": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "blackfriday": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "blanco": {
        "_type": "newgtld",
        "host": "whois.nic.blanco"
    },
    "blockbuster": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.blockbuster"
    },
    "blog": {
        "_type": "newgtld",
        "host": "whois.nic.blog"
    },
    "bloomberg": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "blue": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "bm": {
        "adapter": "web",
        "url": "http://www.bermudanic.bm/cgi-bin/lansaweb?procfun+BMWHO+BMWHO2+WHO"
    },
    "bms": {
        "_type": "newgtld",
        "host": "whois.nic.bms"
    },
    "bmw": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "bn": {
        "host": "whois.bnnic.bn"
    },
    "bnl": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.bnl"
    },
    "bnpparibas": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "bo": {
        "host": "whois.nic.bo"
    },
    "boats": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "boehringer": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "bofa": {
        "_type": "newgtld",
        "host": "whois.nic.bofa"
    },
    "bom": {
        "_group": "nicbr",
        "_type": "newgtld",
        "host": "whois.gtlds.nic.br"
    },
    "bond": {
        "_type": "newgtld",
        "host": "whois.nic.bond"
    },
    "boo": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "book": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "booking": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "bosch": {
        "_type": "newgtld",
        "host": "whois.nic.bosch"
    },
    "bostik": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois-bostik.nic.fr"
    },
    "boston": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.boston"
    },
    "bot": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "boutique": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.boutique"
    },
    "box": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.aridnrs.net.au"
    },
    "br": {
        "host": "whois.registro.br"
    },
    "bradesco": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.bradesco"
    },
    "bridgestone": {
        "_type": "newgtld",
        "host": "whois.nic.bridgestone"
    },
    "broadway": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.broadway"
    },
    "broker": {
        "_type": "newgtld",
        "host": "whois.nic.broker"
    },
    "brother": {
        "_type": "newgtld",
        "host": "whois.nic.brother"
    },
    "brussels": {
        "_type": "newgtld",
        "host": "whois.nic.brussels"
    },
    "bs": {
        "adapter": "web",
        "url": "http://www.nic.bs/cgi-bin/search.pl"
    },
    "bt": {
        "adapter": "web",
        "url": "http://www.nic.bt/"
    },
    "budapest": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois-dub.mm-registry.com"
    },
    "bugatti": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "build": {
        "_type": "newgtld",
        "host": "whois.nic.build"
    },
    "builders": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.builders"
    },
    "business": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.business"
    },
    "buy": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "buzz": {
        "_type": "newgtld",
        "host": "whois.nic.buzz"
    },
    "bv": {
        "adapter": "none"
    },
    "bw": {
        "host": "whois.nic.net.bw"
    },
    "by": {
        "host": "whois.cctld.by"
    },
    "bz": {
        "host": "whois.afilias-grs.info",
        "adapter": "afilias"
    },
    "za.bz": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "bzh": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois.nic.bzh"
    },
    "ca": {
        "host": "whois.cira.ca"
    },
    "co.ca": {
        "host": "whois.co.ca"
    },
    "cab": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.cab"
    },
    "cafe": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.cafe"
    },
    "cal": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "call": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "calvinklein": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "cam": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "camera": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.camera"
    },
    "camp": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.camp"
    },
    "cancerresearch": {
        "_type": "newgtld",
        "host": "whois.nic.cancerresearch"
    },
    "canon": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.canon"
    },
    "capetown": {
        "_group": "zaregistry",
        "_type": "newgtld",
        "host": "capetown-whois.registry.net.za"
    },
    "capital": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.capital"
    },
    "capitalone": {
        "_type": "newgtld",
        "host": "whois.nic.capitalone"
    },
    "car": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "caravan": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "cards": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.cards"
    },
    "care": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.care"
    },
    "career": {
        "_type": "newgtld",
        "host": "whois.nic.career"
    },
    "careers": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.careers"
    },
    "cars": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "cartier": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "casa": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.casa"
    },
    "case": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.case"
    },
    "caseih": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.caseih"
    },
    "cash": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.cash"
    },
    "casino": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.casino"
    },
    "cat": {
        "host": "whois.nic.cat",
        "adapter": "formatted",
        "format": "-C US-ASCII ace %s"
    },
    "catering": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.catering"
    },
    "catholic": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.aridnrs.net.au"
    },
    "cba": {
        "_type": "newgtld",
        "host": "whois.nic.cba"
    },
    "cbn": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "cbre": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "cbs": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "cc": {
        "host": "ccwhois.verisign-grs.com",
        "adapter": "verisign"
    },
    "cd": {
        "host": "whois.nic.cd"
    },
    "ceb": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "center": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.center"
    },
    "ceo": {
        "_type": "newgtld",
        "host": "whois.nic.ceo"
    },
    "cern": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "cf": {
        "host": "whois.dot.cf"
    },
    "cfa": {
        "_type": "newgtld",
        "host": "whois.nic.cfa"
    },
    "cfd": {
        "_type": "newgtld",
        "host": "whois.nic.cfd"
    },
    "cg": {
        "adapter": "none"
    },
    "ch": {
        "host": "whois.nic.ch"
    },
    "chanel": {
        "_type": "newgtld",
        "host": "whois.nic.chanel"
    },
    "channel": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "charity": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.charity"
    },
    "chase": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "chat": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.chat"
    },
    "cheap": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.cheap"
    },
    "chintai": {
        "_type": "newgtld",
        "host": "whois.nic.chintai"
    },
    "christmas": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "chrome": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "chrysler": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "church": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.church"
    },
    "ci": {
        "host": "whois.nic.ci"
    },
    "cipriani": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "circle": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "cisco": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "citadel": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "citi": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "citic": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "city": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.city"
    },
    "cityeats": {
        "_type": "newgtld",
        "host": "whois.nic.cityeats"
    },
    "ck": {
        "adapter": "none"
    },
    "cl": {
        "host": "whois.nic.cl"
    },
    "claims": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.claims"
    },
    "cleaning": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.cleaning"
    },
    "click": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "clinic": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.clinic"
    },
    "clinique": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.clinique"
    },
    "clothing": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.clothing"
    },
    "cloud": {
        "_type": "newgtld",
        "host": "whois.nic.cloud"
    },
    "club": {
        "_type": "newgtld",
        "host": "whois.nic.club"
    },
    "clubmed": {
        "_type": "newgtld",
        "host": "whois.nic.clubmed"
    },
    "cm": {
        "host": "whois.netcom.cm"
    },
    "cn": {
        "host": "whois.cnnic.cn"
    },
    "edu.cn": {
        "adapter": "none"
    },
    "co": {
        "host": "whois.nic.co"
    },
    "coach": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.coach"
    },
    "codes": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.codes"
    },
    "coffee": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.coffee"
    },
    "college": {
        "_type": "newgtld",
        "host": "whois.nic.college"
    },
    "cologne": {
        "_group": "knipp",
        "_type": "newgtld",
        "host": "whois.ryce-rsp.com"
    },
    "com": {
        "host": "whois.verisign-grs.com",
        "adapter": "verisign"
    },
    "africa.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "ar.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "br.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "cn.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "co.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.net"
    },
    "de.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "eu.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "gb.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "gr.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "hk.com": {
        "_group": "udrregistry",
        "_type": "private",
        "host": "whois.registry.hk.com"
    },
    "hu.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "jpn.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "kr.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "no.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "qc.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "ru.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "sa.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "se.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "uk.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "us.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "uy.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "za.com": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "comcast": {
        "_type": "newgtld",
        "host": "whois.nic.comcast"
    },
    "commbank": {
        "_type": "newgtld",
        "host": "whois.nic.commbank"
    },
    "community": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.community"
    },
    "company": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.company"
    },
    "compare": {
        "_type": "newgtld",
        "host": "whois.nic.compare"
    },
    "computer": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.computer"
    },
    "comsec": {
        "_type": "newgtld",
        "host": "whois.nic.comsec"
    },
    "condos": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.condos"
    },
    "construction": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.construction"
    },
    "consulting": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.consulting"
    },
    "contact": {
        "_type": "newgtld",
        "host": "whois.nic.contact"
    },
    "contractors": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.contractors"
    },
    "cooking": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.cooking"
    },
    "cookingchannel": {
        "_type": "newgtld",
        "host": "whois.nic.cookingchannel"
    },
    "cool": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.cool"
    },
    "coop": {
        "host": "whois.nic.coop"
    },
    "corsica": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois-corsica.nic.fr"
    },
    "country": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois-dub.mm-registry.com"
    },
    "coupon": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "coupons": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.coupons"
    },
    "courses": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.aridnrs.net.au"
    },
    "cr": {
        "host": "whois.nic.cr"
    },
    "credit": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.credit"
    },
    "creditcard": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.creditcard"
    },
    "creditunion": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "cricket": {
        "_type": "newgtld",
        "host": "whois.nic.cricket"
    },
    "crown": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "crs": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "cruise": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.cruise"
    },
    "cruises": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.cruises"
    },
    "csc": {
        "_type": "newgtld",
        "host": "whois.nic.csc"
    },
    "cu": {
        "adapter": "web",
        "url": "http://www.nic.cu/"
    },
    "cuisinella": {
        "_type": "newgtld",
        "host": "whois.nic.cuisinella"
    },
    "cv": {
        "adapter": "web",
        "url": "http://www.dns.cv/"
    },
    "cw": {
        "adapter": "none"
    },
    "cx": {
        "host": "whois.nic.cx"
    },
    "cy": {
        "adapter": "web",
        "url": "http://www.nic.cy/nslookup/online_database.php"
    },
    "cymru": {
        "_type": "newgtld",
        "host": "whois.nic.cymru"
    },
    "cyou": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.cyou"
    },
    "cz": {
        "host": "whois.nic.cz"
    },
    "dabur": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "dad": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "dance": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.dance"
    },
    "data": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.data"
    },
    "date": {
        "_type": "newgtld",
        "host": "whois.nic.date"
    },
    "dating": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.dating"
    },
    "datsun": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "day": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "dclk": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "dds": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.dds"
    },
    "de": {
        "host": "whois.denic.de",
        "adapter": "formatted",
        "format": "-T dn,ace %s"
    },
    "com.de": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "deal": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "dealer": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "deals": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.deals"
    },
    "degree": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.degree"
    },
    "delivery": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.delivery"
    },
    "dell": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "deloitte": {
        "_type": "newgtld",
        "host": "whois.nic.deloitte"
    },
    "delta": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.delta"
    },
    "democrat": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.democrat"
    },
    "dental": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.dental"
    },
    "dentist": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.dentist"
    },
    "desi": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "design": {
        "_type": "newgtld",
        "host": "whois.nic.design"
    },
    "dev": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "dhl": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "diamonds": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.diamonds"
    },
    "diet": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "digital": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.digital"
    },
    "direct": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.direct"
    },
    "directory": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.directory"
    },
    "discount": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.discount"
    },
    "discover": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "dish": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.dish"
    },
    "diy": {
        "_type": "newgtld",
        "host": "whois.nic.diy"
    },
    "dj": {
        "adapter": "web",
        "url": "http://www.nic.dj/whois.php"
    },
    "dk": {
        "host": "whois.dk-hostmaster.dk",
        "adapter": "formatted",
        "format": "--show-handles %s"
    },
    "dm": {
        "host": "whois.nic.dm"
    },
    "dnp": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "do": {
        "adapter": "web",
        "url": "http://www.nic.do/whois-h.php3"
    },
    "docs": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "doctor": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.doctor"
    },
    "dodge": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "dog": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.dog"
    },
    "doha": {
        "_type": "newgtld",
        "host": "whois.nic.doha"
    },
    "domains": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.domains"
    },
    "doosan": {
        "host": "whois.nic.xn--cg4bki"
    },
    "dot": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.dot"
    },
    "download": {
        "_type": "newgtld",
        "host": "whois.nic.download"
    },
    "drive": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "dtv": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.dtv"
    },
    "dubai": {
        "_type": "newgtld",
        "host": "whois.nic.dubai"
    },
    "duck": {
        "_type": "newgtld",
        "host": "whois.nic.duck"
    },
    "dunlop": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.dunlop"
    },
    "duns": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "dupont": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "durban": {
        "_group": "zaregistry",
        "_type": "newgtld",
        "host": "durban-whois.registry.net.za"
    },
    "dvag": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "dvr": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "dz": {
        "host": "whois.nic.dz"
    },
    "earth": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "eat": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "ec": {
        "host": "whois.nic.ec"
    },
    "eco": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "edeka": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "edu": {
        "host": "whois.educause.edu"
    },
    "education": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.education"
    },
    "ee": {
        "host": "whois.tld.ee"
    },
    "eg": {
        "adapter": "web",
        "url": "http://lookup.egregistry.eg/english.aspx"
    },
    "email": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.email"
    },
    "emerck": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "energy": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.energy"
    },
    "engineer": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.engineer"
    },
    "engineering": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.engineering"
    },
    "enterprises": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.enterprises"
    },
    "epost": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "epson": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.aridnrs.net.au"
    },
    "equipment": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.equipment"
    },
    "er": {
        "adapter": "none"
    },
    "ericsson": {
        "_type": "newgtld",
        "host": "whois.nic.ericsson"
    },
    "erni": {
        "_type": "newgtld",
        "host": "whois.nic.erni"
    },
    "es": {
        "host": "whois.nic.es"
    },
    "esq": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "estate": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.estate"
    },
    "esurance": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "et": {
        "adapter": "none"
    },
    "etisalat": {
        "_group": "centralnic",
        "host": "whois.centralnic.com"
    },
    "eu": {
        "host": "whois.eu"
    },
    "eurovision": {
        "_type": "newgtld",
        "host": "whois.nic.eurovision"
    },
    "eus": {
        "_group": "coreregistry",
        "_type": "newgtld",
        "host": "whois.nic.eus"
    },
    "events": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.events"
    },
    "everbank": {
        "_type": "newgtld",
        "host": "whois.nic.everbank"
    },
    "exchange": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.exchange"
    },
    "expert": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.expert"
    },
    "exposed": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.exposed"
    },
    "express": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.express"
    },
    "extraspace": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "fage": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "fail": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.fail"
    },
    "fairwinds": {
        "_type": "newgtld",
        "host": "whois.nic.fairwinds"
    },
    "faith": {
        "_type": "newgtld",
        "host": "whois.nic.faith"
    },
    "family": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.family"
    },
    "fan": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.fan"
    },
    "fans": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.fans"
    },
    "farm": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.farm"
    },
    "farmers": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "fashion": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.fashion"
    },
    "fast": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "fedex": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.fedex"
    },
    "feedback": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.feedback"
    },
    "ferrari": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.ferrari"
    },
    "ferrero": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "fi": {
        "host": "whois.fi"
    },
    "fiat": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "fidelity": {
        "_type": "newgtld",
        "host": "whois.nic.fidelity"
    },
    "fido": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "film": {
        "_type": "newgtld",
        "host": "whois.nic.film"
    },
    "final": {
        "_group": "nicbr",
        "_type": "newgtld",
        "host": "whois.gtlds.nic.br"
    },
    "finance": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.finance"
    },
    "financial": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.financial"
    },
    "fire": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "firestone": {
        "_type": "newgtld",
        "host": "whois.nic.firestone"
    },
    "firmdale": {
        "_type": "newgtld",
        "host": "whois.nic.firmdale"
    },
    "fish": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.fish"
    },
    "fishing": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.fishing"
    },
    "fit": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.fit"
    },
    "fitness": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.fitness"
    },
    "fj": {
        "host": "whois.usp.ac.fj"
    },
    "fk": {
        "adapter": "none"
    },
    "flickr": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "flights": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.flights"
    },
    "flir": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "florist": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.florist"
    },
    "flowers": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "fly": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "fm": {
        "host": "whois.nic.fm"
    },
    "fo": {
        "host": "whois.nic.fo"
    },
    "foo": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "food": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "foodnetwork": {
        "_type": "newgtld",
        "host": "whois.nic.foodnetwork"
    },
    "football": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.football"
    },
    "ford": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "forex": {
        "_type": "newgtld",
        "host": "whois.nic.forex"
    },
    "forsale": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.forsale"
    },
    "forum": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.forum"
    },
    "foundation": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.foundation"
    },
    "fox": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "fr": {
        "host": "whois.nic.fr"
    },
    "aeroport.fr": {
        "_group": "smallregistry",
        "_type": "private",
        "host": "whois.smallregistry.net"
    },
    "avocat.fr": {
        "_group": "smallregistry",
        "_type": "private",
        "host": "whois.smallregistry.net"
    },
    "chambagri.fr": {
        "_group": "smallregistry",
        "_type": "private",
        "host": "whois.smallregistry.net"
    },
    "chirurgiens-dentistes.fr": {
        "_group": "smallregistry",
        "_type": "private",
        "host": "whois.smallregistry.net"
    },
    "experts-comptables.fr": {
        "_group": "smallregistry",
        "_type": "private",
        "host": "whois.smallregistry.net"
    },
    "geometre-expert.fr": {
        "_group": "smallregistry",
        "_type": "private",
        "host": "whois.smallregistry.net"
    },
    "medecin.fr": {
        "_group": "smallregistry",
        "_type": "private",
        "host": "whois.smallregistry.net"
    },
    "notaires.fr": {
        "_group": "smallregistry",
        "_type": "private",
        "host": "whois.smallregistry.net"
    },
    "pharmacien.fr": {
        "_group": "smallregistry",
        "_type": "private",
        "host": "whois.smallregistry.net"
    },
    "port.fr": {
        "_group": "smallregistry",
        "_type": "private",
        "host": "whois.smallregistry.net"
    },
    "veterinaire.fr": {
        "_group": "smallregistry",
        "_type": "private",
        "host": "whois.smallregistry.net"
    },
    "free": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "fresenius": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "frl": {
        "_type": "newgtld",
        "host": "whois.nic.frl"
    },
    "frogans": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois.nic.frogans"
    },
    "frontdoor": {
        "_type": "newgtld",
        "host": "whois.nic.frontdoor"
    },
    "frontier": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "ftr": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "fujitsu": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "fujixerox": {
        "_type": "newgtld",
        "host": "whois.nic.fujixerox"
    },
    "fun": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.fun"
    },
    "fund": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.fund"
    },
    "furniture": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.furniture"
    },
    "futbol": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.futbol"
    },
    "fyi": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.fyi"
    },
    "ga": {
        "host": "whois.dot.ga"
    },
    "gal": {
        "_group": "coreregistry",
        "_type": "newgtld",
        "host": "whois.nic.gal"
    },
    "gallery": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.gallery"
    },
    "gallo": {
        "_type": "newgtld",
        "host": "whois.nic.gallo"
    },
    "gallup": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.gallup"
    },
    "game": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "games": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.games"
    },
    "gap": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "garden": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.garden"
    },
    "gb": {
        "adapter": "none"
    },
    "gbiz": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "gd": {
        "host": "whois.nic.gd"
    },
    "gdn": {
        "_type": "newgtld",
        "host": "whois.nic.gdn"
    },
    "ge": {
        "host": "whois.registration.ge"
    },
    "gea": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "gent": {
        "_type": "newgtld",
        "host": "whois.nic.gent"
    },
    "genting": {
        "_type": "newgtld",
        "host": "whois.nic.genting"
    },
    "george": {
        "_type": "newgtld",
        "host": "whois.nic.george"
    },
    "gf": {
        "host": "whois.mediaserv.net"
    },
    "gg": {
        "host": "whois.gg"
    },
    "ggee": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.ggee"
    },
    "gh": {
        "adapter": "web",
        "url": "http://www.nic.gh/customer/search_c.htm"
    },
    "gi": {
        "host": "whois.afilias-grs.info",
        "adapter": "afilias"
    },
    "gift": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "gifts": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.gifts"
    },
    "gives": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.gives"
    },
    "giving": {
        "_type": "newgtld",
        "host": "whois.nic.giving"
    },
    "gl": {
        "host": "whois.nic.gl"
    },
    "glade": {
        "_type": "newgtld",
        "host": "whois.nic.glade"
    },
    "glass": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.glass"
    },
    "gle": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "global": {
        "_type": "newgtld",
        "host": "whois.nic.global"
    },
    "globo": {
        "_group": "nicbr",
        "_type": "newgtld",
        "host": "whois.gtlds.nic.br"
    },
    "gm": {
        "adapter": "web",
        "url": "http://www.nic.gm/htmlpages/whois.htm"
    },
    "gmail": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "gmbh": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.gmbh"
    },
    "gmoregistry": {
        "_group": "gmo",
        "adapter": "none"
    },
    "gmx": {
        "_group": "knipp",
        "_type": "newgtld",
        "host": "whois-fe1.gmx.tango.knipp.de"
    },
    "gn": {
        "adapter": "none"
    },
    "godaddy": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "gold": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.gold"
    },
    "goldpoint": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.goldpoint"
    },
    "golf": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.golf"
    },
    "goo": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "goodyear": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.goodyear"
    },
    "goog": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "google": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "gop": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.gop"
    },
    "got": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "gov": {
        "host": "whois.dotgov.gov"
    },
    "gp": {
        "adapter": "web",
        "url": "https://www.dom-enic.com/whois.html"
    },
    "gq": {
        "host": "whois.dominio.gq"
    },
    "gr": {
        "adapter": "web",
        "url": "https://grweb.ics.forth.gr/Whois?lang=en"
    },
    "grainger": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "graphics": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.graphics"
    },
    "gratis": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.gratis"
    },
    "green": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "gripe": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.gripe"
    },
    "grocery": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "group": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.group"
    },
    "gs": {
        "host": "whois.nic.gs"
    },
    "gt": {
        "adapter": "web",
        "url": "http://www.gt/"
    },
    "gu": {
        "adapter": "web",
        "url": "http://gadao.gov.gu/domainsearch.htm"
    },
    "guardian": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "gucci": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "guge": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "guide": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.guide"
    },
    "guitars": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "guru": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.guru"
    },
    "gw": {
        "adapter": "web",
        "url": "http://nic.gw/en/whois/"
    },
    "gy": {
        "host": "whois.registry.gy"
    },
    "hair": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "hamburg": {
        "_type": "newgtld",
        "host": "whois.nic.hamburg"
    },
    "hangout": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "haus": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.haus"
    },
    "hbo": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "hdfc": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.hdfc"
    },
    "hdfcbank": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.hdfcbank"
    },
    "health": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "healthcare": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.healthcare"
    },
    "help": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "helsinki": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.helsinki"
    },
    "here": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "hermes": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "hgtv": {
        "_type": "newgtld",
        "host": "whois.nic.hgtv"
    },
    "hiphop": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "hisamitsu": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "hitachi": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "hiv": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "hk": {
        "host": "whois.hkirc.hk"
    },
    "inc.hk": {
        "_group": "udrregistry",
        "_type": "private",
        "host": "whois.registry.hk.com"
    },
    "ltd.hk": {
        "_group": "udrregistry",
        "_type": "private",
        "host": "whois.registry.hk.com"
    },
    "hkt": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.hkt"
    },
    "hm": {
        "host": "whois.registry.hm"
    },
    "hn": {
        "host": "whois.nic.hn"
    },
    "hockey": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.hockey"
    },
    "holdings": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.holdings"
    },
    "holiday": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.holiday"
    },
    "homedepot": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.homedepot"
    },
    "homegoods": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "homes": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "homesense": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "honda": {
        "_type": "newgtld",
        "host": "whois.nic.honda"
    },
    "honeywell": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "horse": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.horse"
    },
    "hospital": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.hospital"
    },
    "host": {
        "_type": "newgtld",
        "host": "whois.nic.host"
    },
    "hosting": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "hot": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "hoteles": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "hotels": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "hotmail": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "house": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.house"
    },
    "how": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "hr": {
        "host": "whois.dns.hr"
    },
    "hsbc": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "ht": {
        "host": "whois.nic.ht"
    },
    "hu": {
        "host": "whois.nic.hu"
    },
    "hughes": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.hughes"
    },
    "hyatt": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "hyundai": {
        "_type": "newgtld",
        "host": "whois.nic.hyundai"
    },
    "ibm": {
        "_type": "newgtld",
        "host": "whois.nic.ibm"
    },
    "icbc": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.icbc"
    },
    "ice": {
        "_type": "newgtld",
        "host": "whois.nic.ice"
    },
    "icu": {
        "_type": "newgtld",
        "host": "whois.nic.icu"
    },
    "id": {
        "host": "whois.id"
    },
    "ie": {
        "host": "whois.iedr.ie"
    },
    "ieee": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "ifm": {
        "_type": "newgtld",
        "host": "whois.nic.ifm"
    },
    "ikano": {
        "_type": "newgtld",
        "host": "whois.ikano.tld-box.at"
    },
    "il": {
        "host": "whois.isoc.org.il"
    },
    "co.il": {
        "host": "whois.isoc.org.il"
    },
    "im": {
        "host": "whois.nic.im"
    },
    "imamat": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "imdb": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "immo": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.immo"
    },
    "immobilien": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.immobilien"
    },
    "in": {
        "host": "in.whois-servers.net"
    },
    "inc": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.nic.inc"
    },
    "industries": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.industries"
    },
    "infiniti": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "info": {
        "host": "whois.afilias.net"
    },
    "ing": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "ink": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.ink"
    },
    "institute": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.institute"
    },
    "insurance": {
        "_type": "newgtld",
        "host": "whois.nic.insurance"
    },
    "insure": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.insure"
    },
    "int": {
        "host": "whois.iana.org"
    },
    "intel": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "international": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.international"
    },
    "intuit": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "investments": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.investments"
    },
    "io": {
        "host": "whois.nic.io"
    },
    "ipiranga": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "iq": {
        "host": "whois.cmc.iq"
    },
    "ir": {
        "host": "whois.nic.ir"
    },
    "irish": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.irish"
    },
    "is": {
        "host": "whois.isnic.is"
    },
    "iselect": {
        "_type": "newgtld",
        "host": "whois.nic.iselect"
    },
    "ismaili": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "ist": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "istanbul": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "it": {
        "host": "whois.nic.it"
    },
    "itau": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "itv": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "iveco": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.iveco"
    },
    "jaguar": {
        "_type": "newgtld",
        "host": "whois.nic.jaguar"
    },
    "java": {
        "_type": "newgtld",
        "host": "whois.nic.java"
    },
    "jcb": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "jcp": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "je": {
        "host": "whois.je"
    },
    "jeep": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "jetzt": {
        "_group": "donuts",
        "_type": "newgtld",
        "adapter": "none",
        "host": "whois.nic.jetzt"
    },
    "jewelry": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.jewelry"
    },
    "jio": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.jio"
    },
    "jll": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "jm": {
        "adapter": "none"
    },
    "jmp": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "jnj": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "jo": {
        "adapter": "web",
        "url": "http://www.dns.jo/Whois.aspx"
    },
    "jobs": {
        "host": "whois.nic.jobs",
        "adapter": "verisign"
    },
    "joburg": {
        "_group": "zaregistry",
        "_type": "newgtld",
        "host": "joburg-whois.registry.net.za"
    },
    "jot": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "joy": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "jp": {
        "host": "whois.jprs.jp",
        "adapter": "formatted",
        "format": "%s/e"
    },
    "jpmorgan": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "jprs": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "juegos": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "juniper": {
        "_type": "newgtld",
        "host": "whois.nic.juniper"
    },
    "kaufen": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.kaufen"
    },
    "kddi": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.kddi"
    },
    "ke": {
        "host": "whois.kenic.or.ke"
    },
    "kerryhotels": {
        "_type": "newgtld",
        "host": "whois.nic.kerryhotels"
    },
    "kerrylogistics": {
        "_type": "newgtld",
        "host": "whois.nic.kerrylogistics"
    },
    "kerryproperties": {
        "_type": "newgtld",
        "host": "whois.nic.kerryproperties"
    },
    "kfh": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.kfh"
    },
    "kg": {
        "host": "whois.kg"
    },
    "kh": {
        "adapter": "none"
    },
    "ki": {
        "host": "whois.nic.ki"
    },
    "kia": {
        "_type": "newgtld",
        "host": "whois.nic.kia"
    },
    "kim": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "kinder": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "kindle": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "kitchen": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.kitchen"
    },
    "kiwi": {
        "_type": "newgtld",
        "host": "whois.nic.kiwi"
    },
    "km": {
        "adapter": "none"
    },
    "kn": {
        "host": "whois.nic.kn"
    },
    "koeln": {
        "_group": "knipp",
        "_type": "newgtld",
        "host": "whois.ryce-rsp.com"
    },
    "komatsu": {
        "_type": "newgtld",
        "host": "whois.nic.komatsu"
    },
    "kosher": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.kosher"
    },
    "kp": {
        "adapter": "none"
    },
    "kpmg": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "kpn": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "kr": {
        "host": "whois.kr"
    },
    "krd": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.aridnrs.net.au"
    },
    "kred": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "kuokgroup": {
        "_type": "newgtld",
        "host": "whois.nic.kuokgroup"
    },
    "kw": {
        "adapter": "web",
        "url": "http://www.kw/"
    },
    "ky": {
        "host": "whois.kyregistry.ky"
    },
    "kyoto": {
        "_type": "newgtld",
        "host": "whois.nic.kyoto"
    },
    "kz": {
        "host": "whois.nic.kz"
    },
    "la": {
        "host": "whois.nic.la"
    },
    "lacaixa": {
        "_type": "newgtld",
        "host": "whois.nic.lacaixa"
    },
    "ladbrokes": {
        "_type": "newgtld",
        "host": "whois.nic.ladbrokes"
    },
    "lamborghini": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "lamer": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.lamer"
    },
    "lancaster": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois-lancaster.nic.fr"
    },
    "lancia": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "lancome": {
        "_type": "newgtld",
        "host": "whois.nic.lancome"
    },
    "land": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.land"
    },
    "landrover": {
        "_type": "newgtld",
        "host": "whois.nic.landrover"
    },
    "lanxess": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "lasalle": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "lat": {
        "_type": "newgtld",
        "host": "whois.nic.lat"
    },
    "latino": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.latino"
    },
    "latrobe": {
        "_type": "newgtld",
        "host": "whois.nic.latrobe"
    },
    "law": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.law"
    },
    "lawyer": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.lawyer"
    },
    "lb": {
        "adapter": "web",
        "url": "http://www.aub.edu.lb/lbdr/"
    },
    "lc": {
        "host": "whois.afilias-grs.info",
        "adapter": "afilias"
    },
    "lds": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.lds"
    },
    "lease": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.lease"
    },
    "leclerc": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois-leclerc.nic.fr"
    },
    "lefrak": {
        "_type": "newgtld",
        "host": "whois.nic.lefrak"
    },
    "legal": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.legal"
    },
    "lego": {
        "_type": "newgtld",
        "host": "whois.nic.lego"
    },
    "lexus": {
        "_type": "newgtld",
        "host": "whois.nic.lexus"
    },
    "lgbt": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "li": {
        "host": "whois.nic.li"
    },
    "liaison": {
        "_type": "newgtld",
        "host": "whois.nic.liaison"
    },
    "lidl": {
        "_type": "newgtld",
        "host": "whois.nic.lidl"
    },
    "life": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.life"
    },
    "lifeinsurance": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "lifestyle": {
        "_type": "newgtld",
        "host": "whois.nic.lifestyle"
    },
    "lighting": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.lighting"
    },
    "like": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "lilly": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "limited": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.limited"
    },
    "limo": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.limo"
    },
    "lincoln": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "linde": {
        "_type": "newgtld",
        "host": "whois.nic.linde"
    },
    "link": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "lipsy": {
        "_type": "newgtld",
        "host": "whois.nic.lipsy"
    },
    "live": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.live"
    },
    "living": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "lixil": {
        "_type": "newgtld",
        "host": "whois.nic.lixil"
    },
    "lk": {
        "host": "whois.nic.lk"
    },
    "llc": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "loan": {
        "_type": "newgtld",
        "host": "whois.nic.loan"
    },
    "loans": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.loans"
    },
    "locker": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.locker"
    },
    "locus": {
        "_type": "newgtld",
        "host": "whois.nic.locus"
    },
    "loft": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "lol": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "london": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.london"
    },
    "lotte": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.lotte"
    },
    "lotto": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "love": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.love"
    },
    "lpl": {
        "_type": "newgtld",
        "host": "whois.nic.lpl"
    },
    "lplfinancial": {
        "_type": "newgtld",
        "host": "whois.nic.lplfinancial"
    },
    "lr": {
        "adapter": "none"
    },
    "ls": {
        "adapter": "web",
        "url": "http://www.co.ls/co.asp"
    },
    "lt": {
        "host": "whois.domreg.lt"
    },
    "ltd": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.ltd"
    },
    "ltda": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "lu": {
        "host": "whois.dns.lu"
    },
    "lundbeck": {
        "_type": "newgtld",
        "host": "whois.nic.lundbeck"
    },
    "lupin": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "luxe": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.luxe"
    },
    "luxury": {
        "_type": "newgtld",
        "host": "whois.nic.luxury"
    },
    "lv": {
        "host": "whois.nic.lv"
    },
    "ly": {
        "host": "whois.nic.ly"
    },
    "ma": {
        "host": "whois.registre.ma"
    },
    "macys": {
        "_type": "newgtld",
        "host": "whois.nic.macys"
    },
    "madrid": {
        "_group": "corenic",
        "_type": "newgtld",
        "host": "whois.madrid.rs.corenic.net"
    },
    "maif": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "maison": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.maison"
    },
    "makeup": {
        "_type": "newgtld",
        "host": "whois.nic.makeup"
    },
    "man": {
        "_type": "newgtld",
        "host": "whois.nic.man"
    },
    "management": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.management"
    },
    "mango": {
        "_group": "coreregistry",
        "_type": "newgtld",
        "host": "whois.nic.mango"
    },
    "map": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "market": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.market"
    },
    "marketing": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.marketing"
    },
    "markets": {
        "_type": "newgtld",
        "host": "whois.nic.markets"
    },
    "marriott": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "marshalls": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "maserati": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.maserati"
    },
    "mattel": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "mba": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.mba"
    },
    "mc": {
        "adapter": "none"
    },
    "mckinsey": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.mckinsey"
    },
    "md": {
        "host": "whois.nic.md"
    },
    "me": {
        "host": "whois.nic.me"
    },
    "med": {
        "_type": "newgtld",
        "host": "whois.nic.med"
    },
    "media": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.media"
    },
    "meet": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "melbourne": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.aridnrs.net.au"
    },
    "meme": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "memorial": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.memorial"
    },
    "men": {
        "_type": "newgtld",
        "host": "whois.nic.men"
    },
    "menu": {
        "_type": "newgtld",
        "host": "whois.nic.menu"
    },
    "merckmsd": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "metlife": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.metlife"
    },
    "mg": {
        "host": "whois.nic.mg"
    },
    "mh": {
        "adapter": "none"
    },
    "miami": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.miami"
    },
    "microsoft": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "mil": {
        "adapter": "none"
    },
    "mini": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "mint": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "mit": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "mitsubishi": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "mk": {
        "host": "whois.marnet.mk"
    },
    "ml": {
        "host": "whois.dot.ml"
    },
    "mlb": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "mls": {
        "_type": "newgtld",
        "host": "whois.nic.mls"
    },
    "mm": {
        "adapter": "none"
    },
    "mma": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois-mma.nic.fr"
    },
    "mn": {
        "host": "whois.nic.mn"
    },
    "mo": {
        "host": "whois.monic.mo"
    },
    "mobi": {
        "_group": "afilias",
        "host": "whois.afilias.net"
    },
    "mobile": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.mobile"
    },
    "mobily": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "moda": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.moda"
    },
    "moe": {
        "_type": "newgtld",
        "host": "whois.nic.moe"
    },
    "moi": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "mom": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "monash": {
        "_type": "newgtld",
        "host": "whois.nic.monash"
    },
    "money": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.money"
    },
    "monster": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.monster"
    },
    "montblanc": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "mopar": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "mormon": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.mormon"
    },
    "mortgage": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.mortgage"
    },
    "moscow": {
        "_type": "newgtld",
        "host": "whois.nic.moscow"
    },
    "moto": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "motorcycles": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "mov": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "movie": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.movie"
    },
    "movistar": {
        "_group": "knipp",
        "_type": "newgtld",
        "host": "whois-fe.movistar.tango.knipp.de"
    },
    "mp": {
        "adapter": "none"
    },
    "mq": {
        "host": "whois.mediaserv.net"
    },
    "mr": {
        "adapter": "none",
        "host": "whois.nic.mr"
    },
    "ms": {
        "host": "whois.nic.ms"
    },
    "msd": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "mt": {
        "adapter": "web",
        "url": "https://www.nic.org.mt/dotmt/"
    },
    "mtn": {
        "_type": "newgtld",
        "host": "whois.nic.mtn"
    },
    "mtr": {
        "_type": "newgtld",
        "host": "whois.nic.mtr"
    },
    "mu": {
        "host": "whois.nic.mu"
    },
    "museum": {
        "host": "whois.nic.museum"
    },
    "mutual": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "mv": {
        "adapter": "none"
    },
    "mw": {
        "adapter": "web",
        "url": "http://www.registrar.mw/"
    },
    "mx": {
        "host": "whois.nic.mx"
    },
    "my": {
        "host": "whois.mynic.my"
    },
    "mz": {
        "host": "whois.nic.mz"
    },
    "na": {
        "host": "whois.na-nic.com.na"
    },
    "nab": {
        "_type": "newgtld",
        "host": "whois.nic.nab"
    },
    "nadex": {
        "_type": "newgtld",
        "host": "whois.nic.nadex"
    },
    "nagoya": {
        "_type": "newgtld",
        "host": "whois.nic.nagoya"
    },
    "name": {
        "host": "whois.nic.name",
        "adapter": "formatted",
        "format": "domain=%s"
    },
    "nationwide": {
        "_type": "newgtld",
        "host": "whois.nic.nationwide"
    },
    "natura": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "navy": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.navy"
    },
    "nba": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "nc": {
        "host": "whois.nc"
    },
    "ne": {
        "adapter": "none"
    },
    "nec": {
        "_type": "newgtld",
        "host": "whois.nic.nec"
    },
    "net": {
        "host": "whois.verisign-grs.com",
        "adapter": "verisign"
    },
    "gb.net": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "hu.net": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "in.net": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "jp.net": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "se.net": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "uk.net": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "za.net": {
        "host": "whois.za.net"
    },
    "netbank": {
        "_type": "newgtld",
        "host": "whois.nic.netbank"
    },
    "netflix": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "network": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.network"
    },
    "neustar": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "new": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "newholland": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.newholland"
    },
    "news": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.news"
    },
    "next": {
        "_type": "newgtld",
        "host": "whois.nic.next"
    },
    "nextdirect": {
        "_type": "newgtld",
        "host": "whois.nic.nextdirect"
    },
    "nexus": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "nf": {
        "host": "whois.nic.nf"
    },
    "nfl": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "ng": {
        "host": "whois.nic.net.ng"
    },
    "ngo": {
        "_group": "publicinterestregistry",
        "_type": "newgtld",
        "host": "whois.publicinterestregistry.net"
    },
    "nhk": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "ni": {
        "adapter": "web",
        "url": "http://www.nic.ni/"
    },
    "nico": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.nico"
    },
    "nike": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "nikon": {
        "_type": "newgtld",
        "host": "whois.nic.nikon"
    },
    "ninja": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.ninja"
    },
    "nissan": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "nissay": {
        "_type": "newgtld",
        "host": "whois.nic.nissay"
    },
    "nl": {
        "host": "whois.domain-registry.nl"
    },
    "no": {
        "host": "whois.norid.no"
    },
    "nokia": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "northwesternmutual": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "norton": {
        "_type": "newgtld",
        "host": "whois.nic.norton"
    },
    "now": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "nowruz": {
        "_group": "agitsys",
        "_type": "newgtld",
        "host": "whois.agitsys.net"
    },
    "nowtv": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.nowtv"
    },
    "np": {
        "adapter": "web",
        "url": "http://register.mos.com.np/np-whois-lookup"
    },
    "nr": {
        "adapter": "web",
        "url": "http://www.cenpac.net.nr/dns/whois.html"
    },
    "nra": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "nrw": {
        "_type": "newgtld",
        "host": "whois.nic.nrw"
    },
    "ntt": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "nu": {
        "host": "whois.iis.nu"
    },
    "nyc": {
        "_type": "newgtld",
        "host": "whois.nic.nyc"
    },
    "nz": {
        "host": "whois.srs.net.nz"
    },
    "obi": {
        "_type": "newgtld",
        "host": "whois.nic.obi"
    },
    "observer": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.observer"
    },
    "off": {
        "_type": "newgtld",
        "host": "whois.nic.off"
    },
    "office": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "okinawa": {
        "_type": "newgtld",
        "host": "whois.nic.okinawa"
    },
    "olayan": {
        "_type": "newgtld",
        "host": "whois.nic.olayan"
    },
    "olayangroup": {
        "_type": "newgtld",
        "host": "whois.nic.olayangroup"
    },
    "oldnavy": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "ollo": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.ollo"
    },
    "om": {
        "host": "whois.registry.om"
    },
    "omega": {
        "_type": "newgtld",
        "host": "whois.nic.omega"
    },
    "one": {
        "_type": "newgtld",
        "host": "whois.nic.one"
    },
    "ong": {
        "_group": "publicinterestregistry",
        "_type": "newgtld",
        "host": "whois.publicinterestregistry.net"
    },
    "onl": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "online": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.online"
    },
    "onyourside": {
        "_type": "newgtld",
        "host": "whois.nic.onyourside"
    },
    "ooo": {
        "_type": "newgtld",
        "host": "whois.nic.ooo"
    },
    "open": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "oracle": {
        "_type": "newgtld",
        "host": "whois.nic.oracle"
    },
    "orange": {
        "_type": "newgtld",
        "host": "whois.nic.orange"
    },
    "org": {
        "host": "whois.pir.org"
    },
    "ae.org": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "eu.org": {
        "host": "whois.eu.org"
    },
    "hk.org": {
        "_group": "udrregistry",
        "_type": "private",
        "host": "whois.registry.hk.com"
    },
    "us.org": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "za.org": {
        "host": "whois.za.org"
    },
    "organic": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "orientexpress": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "origin": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "origins": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.origins"
    },
    "osaka": {
        "_type": "newgtld",
        "host": "whois.nic.osaka"
    },
    "otsuka": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "ott": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.ott"
    },
    "ovh": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois-ovh.nic.fr"
    },
    "pa": {
        "adapter": "web",
        "url": "http://www.nic.pa/"
    },
    "page": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "panasonic": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "paris": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois-paris.nic.fr"
    },
    "pars": {
        "_group": "agitsys",
        "_type": "newgtld",
        "host": "whois.agitsys.net"
    },
    "partners": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.partners"
    },
    "parts": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.parts"
    },
    "party": {
        "_type": "newgtld",
        "host": "whois.nic.party"
    },
    "passagens": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "pay": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "pccw": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.pccw"
    },
    "pe": {
        "host": "kero.yachay.pe"
    },
    "pet": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "pf": {
        "host": "whois.registry.pf"
    },
    "pfizer": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "pg": {
        "adapter": "none"
    },
    "ph": {
        "adapter": "web",
        "url": "http://www.dot.ph/whois",
        "host": "whois.iana.org"
    },
    "pharmacy": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "phd": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "philips": {
        "_type": "newgtld",
        "host": "whois.nic.philips"
    },
    "phone": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.phone"
    },
    "photo": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "photography": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.photography"
    },
    "photos": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.photos"
    },
    "physio": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.nic.physio"
    },
    "piaget": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "pics": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "pictet": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "pictures": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.pictures"
    },
    "pid": {
        "_type": "newgtld",
        "host": "whois.nic.pid"
    },
    "pin": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "ping": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "pink": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "pioneer": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "pizza": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.pizza"
    },
    "pk": {
        "adapter": "web",
        "url": "http://www.pknic.net.pk/"
    },
    "pl": {
        "host": "whois.dns.pl"
    },
    "co.pl": {
        "host": "whois.co.pl"
    },
    "place": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.place"
    },
    "play": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "playstation": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.playstation"
    },
    "plumbing": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.plumbing"
    },
    "plus": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.plus"
    },
    "pm": {
        "host": "whois.nic.pm"
    },
    "pn": {
        "adapter": "web",
        "url": "http://www.pitcairn.pn/PnRegistry/"
    },
    "pnc": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.pnc"
    },
    "pohl": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "poker": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "politie": {
        "_type": "newgtld",
        "host": "whois.nicpolitie"
    },
    "porn": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "post": {
        "host": "whois.dotpostregistry.net"
    },
    "pr": {
        "_group": "afiliassrs",
        "host": "whois.afilias-srs.net"
    },
    "pramerica": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "praxi": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "press": {
        "_type": "newgtld",
        "host": "whois.nic.press"
    },
    "prime": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "pro": {
        "host": "whois.afilias.net"
    },
    "prod": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "productions": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.productions"
    },
    "prof": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "progressive": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "promo": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "properties": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.properties"
    },
    "property": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "protection": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.centralnic.com"
    },
    "pru": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "prudential": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "ps": {
        "host": "whois.pnina.ps"
    },
    "pt": {
        "host": "whois.dns.pt"
    },
    "pub": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.pub"
    },
    "pw": {
        "host": "whois.nic.pw"
    },
    "pwc": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "py": {
        "adapter": "web",
        "url": "http://www.nic.py/consulta-datos.php"
    },
    "qa": {
        "host": "whois.registry.qa"
    },
    "qpon": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "quebec": {
        "_type": "newgtld",
        "host": "whois.nic.quebec"
    },
    "quest": {
        "_type": "newgtld",
        "host": "whois.nic.quest"
    },
    "qvc": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "racing": {
        "_type": "newgtld",
        "host": "whois.nic.racing"
    },
    "radio": {
        "_type": "newgtld",
        "host": "whois.nic.radio"
    },
    "raid": {
        "_type": "newgtld",
        "host": "whois.nic.raid"
    },
    "re": {
        "host": "whois.nic.re"
    },
    "read": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "realestate": {
        "_type": "newgtld",
        "host": "whois.nic.realestate"
    },
    "realtor": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "realty": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.realty"
    },
    "recipes": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.recipes"
    },
    "red": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "redstone": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.redstone"
    },
    "redumbrella": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "rehab": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.rehab"
    },
    "reise": {
        "_type": "newgtld",
        "host": "whois.nic.reise"
    },
    "reisen": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.reisen"
    },
    "reit": {
        "_type": "newgtld",
        "host": "whois.nic.reit"
    },
    "reliance": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.reliance"
    },
    "ren": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "rent": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.rent"
    },
    "rentals": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.rentals"
    },
    "repair": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.repair"
    },
    "report": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.report"
    },
    "republican": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.republican"
    },
    "rest": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.rest"
    },
    "restaurant": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.restaurant"
    },
    "review": {
        "_type": "newgtld",
        "host": "whois.nic.review"
    },
    "reviews": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.reviews"
    },
    "rexroth": {
        "_type": "newgtld",
        "host": "whois.nic.rexroth"
    },
    "rich": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "richardli": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.richardli"
    },
    "ricoh": {
        "_type": "newgtld",
        "host": "whois.nic.ricoh"
    },
    "rightathome": {
        "_type": "newgtld",
        "host": "whois.nic.rightathome"
    },
    "ril": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.ril"
    },
    "rio": {
        "_group": "nicbr",
        "_type": "newgtld",
        "host": "whois.gtlds.nic.br"
    },
    "rip": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.rip"
    },
    "rmit": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.aridnrs.net.au"
    },
    "ro": {
        "host": "whois.rotld.ro"
    },
    "rocher": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "rocks": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.rocks"
    },
    "rodeo": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.rodeo"
    },
    "rogers": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "room": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "rs": {
        "host": "whois.rnids.rs"
    },
    "rsvp": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "ru": {
        "host": "whois.tcinet.ru"
    },
    "edu.ru": {
        "host": "whois.informika.ru"
    },
    "rugby": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.centralnic.com"
    },
    "ruhr": {
        "_type": "newgtld",
        "host": "whois.nic.ruhr"
    },
    "run": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.run"
    },
    "rw": {
        "host": "whois.ricta.org.rw"
    },
    "rwe": {
        "_type": "newgtld",
        "host": "whois.nic.rwe"
    },
    "ryukyu": {
        "_type": "newgtld",
        "host": "whois.nic.ryukyu"
    },
    "sa": {
        "host": "whois.nic.net.sa"
    },
    "saarland": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "safe": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "safety": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "sakura": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "sale": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.sale"
    },
    "salon": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.salon"
    },
    "samsclub": {
        "_type": "newgtld",
        "host": "whois.nic.samsclub"
    },
    "samsung": {
        "_type": "newgtld",
        "host": "whois.nic.xn--cg4bki"
    },
    "sandvik": {
        "_type": "newgtld",
        "host": "whois.nic.sandvik"
    },
    "sandvikcoromant": {
        "_type": "newgtld",
        "host": "whois.nic.sandvikcoromant"
    },
    "sanofi": {
        "_type": "newgtld",
        "host": "whois.nic.sanofi"
    },
    "sap": {
        "_type": "newgtld",
        "host": "whois.nic.sap"
    },
    "sarl": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.sarl"
    },
    "sas": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "save": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "saxo": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.aridnrs.net.au"
    },
    "sb": {
        "host": "whois.nic.net.sb"
    },
    "sbi": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.sbi"
    },
    "sbs": {
        "_type": "newgtld",
        "host": "whois.nic.sbs"
    },
    "sc": {
        "host": "whois.afilias-grs.info",
        "adapter": "afilias"
    },
    "sca": {
        "_type": "newgtld",
        "host": "whois.nic.sca"
    },
    "scb": {
        "_type": "newgtld",
        "host": "whois.nic.scb"
    },
    "schaeffler": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "schmidt": {
        "_type": "newgtld",
        "host": "whois.nic.schmidt"
    },
    "scholarships": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.scholarships"
    },
    "school": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.school"
    },
    "schule": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.schule"
    },
    "schwarz": {
        "_type": "newgtld",
        "host": "whois.nic.schwarz"
    },
    "science": {
        "_type": "newgtld",
        "host": "whois.nic.science"
    },
    "scjohnson": {
        "_type": "newgtld",
        "host": "whois.nic.scjohnson"
    },
    "scor": {
        "_type": "newgtld",
        "host": "whois.nic.scor"
    },
    "scot": {
        "_group": "coreregistry",
        "_type": "newgtld",
        "host": "whois.nic.scot"
    },
    "sd": {
        "adapter": "none"
    },
    "se": {
        "host": "whois.iis.se"
    },
    "com.se": {
        "_group": "centralnic",
        "_type": "private",
        "host": "whois.centralnic.com"
    },
    "search": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "seat": {
        "_type": "newgtld",
        "host": "whois.nic.seat"
    },
    "secure": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "security": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.security"
    },
    "seek": {
        "_type": "newgtld",
        "host": "whois.nic.seek"
    },
    "select": {
        "_type": "newgtld",
        "host": "whois.nic.select"
    },
    "sener": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "services": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.services"
    },
    "ses": {
        "_type": "newgtld",
        "host": "whois.nic.ses"
    },
    "seven": {
        "_type": "newgtld",
        "host": "whois.nic.seven"
    },
    "sew": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "sex": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "sexy": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "sfr": {
        "_type": "newgtld",
        "host": "whois.nic.sfr"
    },
    "sg": {
        "host": "whois.sgnic.sg"
    },
    "sh": {
        "host": "whois.nic.sh"
    },
    "shangrila": {
        "_type": "newgtld",
        "host": "whois.nic.shangrila"
    },
    "sharp": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "shaw": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "shell": {
        "_type": "newgtld",
        "host": "whois.nic.shell"
    },
    "shia": {
        "_group": "agitsys",
        "_type": "newgtld",
        "host": "whois.agitsys.net"
    },
    "shiksha": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "shoes": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.shoes"
    },
    "shop": {
        "_type": "newgtld",
        "host": "whois.nic.shop"
    },
    "shopping": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.shopping"
    },
    "shouji": {
        "_group": "teleinfo",
        "_type": "newgtld",
        "host": "whois.teleinfo.cn"
    },
    "show": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.show"
    },
    "showtime": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "shriram": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "si": {
        "host": "whois.register.si"
    },
    "silk": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "sina": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.sina"
    },
    "singles": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.singles"
    },
    "site": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.site"
    },
    "sj": {
        "adapter": "none"
    },
    "sk": {
        "host": "whois.sk-nic.sk"
    },
    "ski": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "skin": {
        "_type": "newgtld",
        "host": "whois.nic.skin"
    },
    "sky": {
        "_type": "newgtld",
        "host": "whois.nic.sky"
    },
    "skype": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "sl": {
        "host": "whois.nic.sl"
    },
    "sling": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.sling"
    },
    "sm": {
        "host": "whois.nic.sm"
    },
    "smart": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.smart"
    },
    "smile": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "sn": {
        "host": "whois.nic.sn"
    },
    "sncf": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois-sncf.nic.fr"
    },
    "so": {
        "host": "whois.nic.so"
    },
    "soccer": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.soccer"
    },
    "social": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.social"
    },
    "softbank": {
        "_type": "newgtld",
        "host": "whois.nic.softbank"
    },
    "software": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.software"
    },
    "sohu": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "solar": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.solar"
    },
    "solutions": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.solutions"
    },
    "song": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "sony": {
        "_type": "newgtld",
        "host": "whois.nic.sony"
    },
    "soy": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "space": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.space"
    },
    "spiegel": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "sport": {
        "_type": "newgtld",
        "host": "whois.nic.sport"
    },
    "spot": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "spreadbetting": {
        "_type": "newgtld",
        "host": "whois.nic.spreadbetting"
    },
    "sr": {
        "adapter": "none"
    },
    "srl": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "srt": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "st": {
        "host": "whois.nic.st"
    },
    "stada": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "staples": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "star": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.star"
    },
    "starhub": {
        "_type": "newgtld",
        "host": "whois.nic.starhub"
    },
    "statebank": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.statebank"
    },
    "statefarm": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "stc": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.stc"
    },
    "stcgroup": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.stcgroup"
    },
    "stockholm": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "storage": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.storage"
    },
    "store": {
        "_type": "newgtld",
        "host": "whois.nic.store"
    },
    "stream": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "studio": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.studio"
    },
    "study": {
        "_type": "newgtld",
        "host": "whois.nic.study"
    },
    "style": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.style"
    },
    "su": {
        "host": "whois.tcinet.ru"
    },
    "sucks": {
        "_type": "newgtld",
        "host": "whois.nic.sucks"
    },
    "supplies": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.supplies"
    },
    "supply": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.supply"
    },
    "support": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.support"
    },
    "surf": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.surf"
    },
    "surgery": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.surgery"
    },
    "suzuki": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "sv": {
        "adapter": "web",
        "url": "http://www.svnet.org.sv/"
    },
    "swatch": {
        "_type": "newgtld",
        "host": "whois.nic.swatch"
    },
    "swiftcover": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "swiss": {
        "_type": "newgtld",
        "host": "whois.nic.swiss"
    },
    "sx": {
        "host": "whois.sx"
    },
    "sy": {
        "host": "whois.tld.sy"
    },
    "sydney": {
        "_type": "newgtld",
        "host": "whois.nic.sydney"
    },
    "symantec": {
        "_type": "newgtld",
        "host": "whois.nic.symantec"
    },
    "systems": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.systems"
    },
    "sz": {
        "adapter": "none"
    },
    "tab": {
        "_type": "newgtld",
        "host": "whois.nic.tab"
    },
    "taipei": {
        "_type": "newgtld",
        "host": "whois.nic.taipei"
    },
    "talk": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "taobao": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "target": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "tatamotors": {
        "_type": "newgtld",
        "host": "whois.nic.tatamotors"
    },
    "tatar": {
        "_type": "newgtld",
        "host": "whois.nic.tatar"
    },
    "tattoo": {
        "_group": "uniregistry",
        "_type": "newgtld",
        "host": "whois.uniregistry.net"
    },
    "tax": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.tax"
    },
    "taxi": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.taxi"
    },
    "tc": {
        "host": "whois.nic.tc"
    },
    "tci": {
        "_group": "agitsys",
        "_type": "newgtld",
        "host": "whois.agitsys.net"
    },
    "td": {
        "adapter": "web",
        "url": "http://www.nic.td/"
    },
    "tdk": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "team": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.team"
    },
    "tech": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.tech"
    },
    "technology": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.technology"
    },
    "tel": {
        "host": "whois.nic.tel"
    },
    "telefonica": {
        "_group": "knipp",
        "_type": "newgtld",
        "host": "whois-fe.telefonica.tango.knipp.de"
    },
    "temasek": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "tennis": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.tennis"
    },
    "teva": {
        "_type": "newgtld",
        "host": "whois.nic.teva"
    },
    "tf": {
        "host": "whois.nic.fr"
    },
    "tg": {
        "host": "whois.nic.tg"
    },
    "th": {
        "host": "whois.thnic.co.th"
    },
    "thd": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.thd"
    },
    "theater": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.theater"
    },
    "theatre": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.theatre"
    },
    "tiaa": {
        "_type": "newgtld",
        "host": "whois.nic.tiaa"
    },
    "tickets": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.tickets"
    },
    "tienda": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.tienda"
    },
    "tiffany": {
        "_type": "newgtld",
        "host": "whois.nic.tiffany"
    },
    "tiia": {
        "host": "whois.nic.tiia"
    },
    "tips": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.tips"
    },
    "tires": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.tires"
    },
    "tirol": {
        "_type": "newgtld",
        "host": "whois.nic.tirol"
    },
    "tj": {
        "adapter": "web",
        "url": "http://www.nic.tj/whois.html"
    },
    "tjmaxx": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "tjx": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "tk": {
        "host": "whois.dot.tk"
    },
    "tkmaxx": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "tl": {
        "host": "whois.nic.tl"
    },
    "tm": {
        "host": "whois.nic.tm"
    },
    "tmall": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "tn": {
        "host": "whois.ati.tn"
    },
    "to": {
        "host": "whois.tonic.to"
    },
    "today": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.today"
    },
    "tokyo": {
        "_type": "newgtld",
        "host": "whois.nic.tokyo"
    },
    "tools": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.tools"
    },
    "top": {
        "_type": "newgtld",
        "host": "whois.nic.top"
    },
    "toray": {
        "_type": "newgtld",
        "host": "whois.nic.toray"
    },
    "toshiba": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.toshiba"
    },
    "total": {
        "_group": "nicfr",
        "_type": "newgtld",
        "host": "whois-total.nic.fr"
    },
    "tours": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.tours"
    },
    "town": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.town"
    },
    "toyota": {
        "_type": "newgtld",
        "host": "whois.nic.toyota"
    },
    "toys": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.toys"
    },
    "tr": {
        "host": "whois.nic.tr"
    },
    "trade": {
        "_type": "newgtld",
        "host": "whois.nic.trade"
    },
    "trading": {
        "_type": "newgtld",
        "host": "whois.nic.trading"
    },
    "training": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.training"
    },
    "travel": {
        "host": "whois.nic.travel"
    },
    "travelchannel": {
        "_type": "newgtld",
        "host": "whois.nic.travelchannel"
    },
    "travelers": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "travelersinsurance": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "trust": {
        "_type": "newgtld",
        "host": "whois.nic.trust"
    },
    "trv": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "tt": {
        "adapter": "web",
        "url": "http://www.nic.tt/cgi-bin/search.pl"
    },
    "tube": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "tui": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "tunes": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "tushu": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "tv": {
        "host": "tvwhois.verisign-grs.com",
        "adapter": "verisign"
    },
    "tvs": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.tvs"
    },
    "tw": {
        "host": "whois.twnic.net.tw"
    },
    "tz": {
        "host": "whois.tznic.or.tz"
    },
    "ua": {
        "host": "whois.ua"
    },
    "in.ua": {
        "host": "whois.in.ua"
    },
    "ubank": {
        "_type": "newgtld",
        "host": "whois.nic.ubank"
    },
    "ubs": {
        "_type": "newgtld",
        "host": "whois.nic.ubs"
    },
    "uconnect": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "ug": {
        "host": "whois.co.ug"
    },
    "uk": {
        "host": "whois.nic.uk"
    },
    "ac.uk": {
        "host": "whois.ja.net"
    },
    "bl.uk": {
        "adapter": "none"
    },
    "british-library.uk": {
        "adapter": "none"
    },
    "gov.uk": {
        "host": "whois.ja.net"
    },
    "icnet.uk": {
        "adapter": "none"
    },
    "jet.uk": {
        "adapter": "none"
    },
    "mod.uk": {
        "adapter": "none"
    },
    "nhs.uk": {
        "adapter": "none"
    },
    "nls.uk": {
        "adapter": "none"
    },
    "parliament.uk": {
        "adapter": "none"
    },
    "police.uk": {
        "adapter": "none"
    },
    "unicom": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "university": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.university"
    },
    "uno": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "uol": {
        "_group": "nicbr",
        "_type": "newgtld",
        "host": "whois.gtlds.nic.br"
    },
    "ups": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.ups"
    },
    "us": {
        "host": "whois.nic.us"
    },
    "uy": {
        "host": "whois.nic.org.uy"
    },
    "com.uy": {
        "adapter": "web",
        "url": "https://nic.anteldata.com.uy/dns/consultaWhois/whois.action"
    },
    "uz": {
        "host": "whois.cctld.uz"
    },
    "va": {
        "adapter": "none"
    },
    "vacations": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.vacations"
    },
    "vana": {
        "_type": "newgtld",
        "host": "whois.nic.vana"
    },
    "vanguard": {
        "_type": "newgtld",
        "host": "whois.nic.vanguard"
    },
    "vc": {
        "host": "whois.afilias-grs.info",
        "adapter": "afilias"
    },
    "ve": {
        "host": "whois.nic.ve"
    },
    "vegas": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "ventures": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.ventures"
    },
    "verisign": {
        "_type": "newgtld",
        "host": "whois.nic.verisign"
    },
    "versicherung": {
        "_type": "newgtld",
        "host": "whois.nic.versicherung"
    },
    "vet": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.vet"
    },
    "vg": {
        "host": "whois.nic.vg"
    },
    "vi": {
        "adapter": "web",
        "url": "https://secure.nic.vi/whois-lookup/"
    },
    "viajes": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.viajes"
    },
    "video": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.video"
    },
    "vig": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "viking": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "villas": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.villas"
    },
    "vin": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.vin"
    },
    "vip": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.vip"
    },
    "virgin": {
        "_type": "newgtld",
        "host": "whois.nic.virgin"
    },
    "visa": {
        "_type": "newgtld",
        "host": "whois.nic.visa"
    },
    "vision": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.vision"
    },
    "vistaprint": {
        "_type": "newgtld",
        "host": "whois.nic.vistaprint"
    },
    "viva": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.viva"
    },
    "vivo": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "vlaanderen": {
        "_type": "newgtld",
        "host": "whois.nic.vlaanderen"
    },
    "vn": {
        "adapter": "web",
        "url": "http://www.vnnic.vn/en/domain"
    },
    "vodka": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.vodka"
    },
    "volkswagen": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "volvo": {
        "_type": "newgtld",
        "host": "whois.nic.volvo"
    },
    "vote": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "voting": {
        "_type": "newgtld",
        "host": "whois.voting.tld-box.at"
    },
    "voto": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "voyage": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.voyage"
    },
    "vu": {
        "host": "vunic.vu"
    },
    "vuelos": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "wales": {
        "_type": "newgtld",
        "host": "whois.nic.wales"
    },
    "walmart": {
        "_type": "newgtld",
        "host": "whois.nic.walmart"
    },
    "walter": {
        "_type": "newgtld",
        "host": "whois.nic.walter"
    },
    "wang": {
        "_group": "knet",
        "_type": "newgtld",
        "host": "whois.gtld.knet.cn"
    },
    "wanggou": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "warman": {
        "_type": "newgtld",
        "host": "whois.nic.warman"
    },
    "watch": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.watch"
    },
    "watches": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "weather": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "weatherchannel": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "webcam": {
        "_type": "newgtld",
        "host": "whois.nic.webcam"
    },
    "weber": {
        "_type": "newgtld",
        "host": "whois.nic.weber"
    },
    "website": {
        "_type": "newgtld",
        "host": "whois.nic.website"
    },
    "wed": {
        "_type": "newgtld",
        "host": "whois.nic.wed"
    },
    "wedding": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.wedding"
    },
    "weibo": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.weibo"
    },
    "weir": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "wf": {
        "host": "whois.nic.wf"
    },
    "whoswho": {
        "_type": "newgtld",
        "host": "whois.nic.whoswho"
    },
    "wien": {
        "_type": "newgtld",
        "host": "whois.nic.wien"
    },
    "wiki": {
        "_type": "newgtld",
        "host": "whois.nic.wiki"
    },
    "williamhill": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "win": {
        "_type": "newgtld",
        "host": "whois.nic.win"
    },
    "windows": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "wine": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.wine"
    },
    "winners": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "wme": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.wme"
    },
    "wolterskluwer": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.wolterskluwer"
    },
    "woodside": {
        "_type": "newgtld",
        "host": "whois.nic.woodside"
    },
    "work": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.work"
    },
    "works": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.works"
    },
    "world": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.world"
    },
    "wow": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "ws": {
        "host": "whois.website.ws"
    },
    "wtc": {
        "_type": "newgtld",
        "host": "whois.nic.wtc"
    },
    "wtf": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.wtf"
    },
    "xbox": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xerox": {
        "_type": "newgtld",
        "host": "whois.nic.xerox"
    },
    "xfinity": {
        "_type": "newgtld",
        "host": "whois.nic.xfinity"
    },
    "xihuan": {
        "_group": "teleinfo",
        "_type": "newgtld",
        "host": "whois.teleinfo.cn"
    },
    "xin": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.xin"
    },
    "xn--11b4c3d": {
        "_type": "newgtld",
        "host": "whois.nic.xn--11b4c3d"
    },
    "xn--1ck2e1b": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--1qqw23a": {
        "_group": "ngtld",
        "_type": "newgtld",
        "host": "whois.ngtld.cn"
    },
    "xn--2scrj9c": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--30rr7y": {
        "_group": "knet",
        "_type": "newgtld",
        "host": "whois.gtld.knet.cn"
    },
    "xn--3bst00m": {
        "_group": "knet",
        "_type": "newgtld",
        "host": "whois.gtld.knet.cn"
    },
    "xn--3ds443g": {
        "_group": "teleinfo",
        "_type": "newgtld",
        "host": "whois.teleinfo.cn"
    },
    "xn--3e0b707e": {
        "host": "whois.kr"
    },
    "xn--3oq18vl8pn36a": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.xn--3oq18vl8pn36a"
    },
    "xn--3pxu8k": {
        "_type": "newgtld",
        "host": "whois.nic.xn--3pxu8k"
    },
    "xn--42c2d9a": {
        "_type": "newgtld",
        "host": "whois.nic.xn--42c2d9a"
    },
    "xn--45br5cyl": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--45brj9c": {
        "host": "whois.inregistry.net"
    },
    "xn--45q11c": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--4gbrim": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "xn--54b7fta0cc": {
        "adapter": "none"
    },
    "xn--55qw42g": {
        "_type": "newgtld",
        "host": "whois.conac.cn"
    },
    "xn--55qx5d": {
        "_group": "ngtld",
        "_type": "newgtld",
        "host": "whois.ngtld.cn"
    },
    "xn--5su34j936bgsg": {
        "_type": "newgtld",
        "host": "whois.nic.xn--5su34j936bgsg"
    },
    "xn--5tzm5g": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "adapter": "none",
        "host": "whois.nic.xn--5tzm5g"
    },
    "xn--6frz82g": {
        "_group": "afilias",
        "_type": "newgtld",
        "host": "whois.afilias.net"
    },
    "xn--6qq986b3xl": {
        "_group": "knet",
        "_type": "newgtld",
        "host": "whois.gtld.knet.cn"
    },
    "xn--80adxhks": {
        "_type": "newgtld",
        "host": "whois.nic.xn--80adxhks"
    },
    "xn--80ao21a": {
        "host": "whois.nic.kz"
    },
    "xn--80aqecdr1a": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.aridnrs.net.au"
    },
    "xn--80asehdb": {
        "_group": "corenic",
        "_type": "newgtld",
        "host": "whois.online.rs.corenic.net"
    },
    "xn--80aswg": {
        "_group": "corenic",
        "_type": "newgtld",
        "host": "whois.online.rs.corenic.net"
    },
    "xn--8y0a063a": {
        "_type": "newgtld",
        "host": "whois.imena.bg"
    },
    "xn--90a3ac": {
        "host": "whois.rnids.rs"
    },
    "xn--90ae": {
        "adapter": "none"
    },
    "xn--90ais": {
        "host": "whois.cctld.by"
    },
    "xn--9dbq2a": {
        "_type": "newgtld",
        "host": "whois.nic.xn--9dbq2a"
    },
    "xn--9et52u": {
        "_group": "knet",
        "_type": "newgtld",
        "host": "whois.gtld.knet.cn"
    },
    "xn--9krt00a": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.xn--9krt00a"
    },
    "xn--b4w605ferd": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "xn--bck1b9a5dre4c": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--c1avg": {
        "_group": "publicinterestregistry",
        "_type": "newgtld",
        "host": "whois.publicinterestregistry.net"
    },
    "xn--c2br7g": {
        "_type": "newgtld",
        "host": "whois.nic.xn--c2br7g"
    },
    "xn--cck2b3b": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--cg4bki": {
        "_type": "newgtld",
        "host": "whois.kr"
    },
    "xn--clchc0ea0b2g2a9gcd": {
        "host": "whois.sgnic.sg"
    },
    "xn--czrs0t": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.xn--czrs0t"
    },
    "xn--czru2d": {
        "_group": "knet",
        "_type": "newgtld",
        "host": "whois.gtld.knet.cn"
    },
    "xn--d1acj3b": {
        "_type": "newgtld",
        "host": "whois.nic.xn--d1acj3b"
    },
    "xn--d1alf": {
        "host": "whois.marnet.mk"
    },
    "xn--e1a4c": {
        "host": "whois.eu"
    },
    "xn--eckvdtc9d": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--efvy88h": {
        "_type": "newgtld",
        "host": "whois.nic.xn--efvy88h"
    },
    "xn--estv75g": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.xn--estv75g"
    },
    "xn--fct429k": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--fhbei": {
        "_type": "newgtld",
        "host": "whois.nic.xn--fhbei"
    },
    "xn--fiq228c5hs": {
        "_group": "teleinfo",
        "_type": "newgtld",
        "host": "whois.teleinfo.cn"
    },
    "xn--fiq64b": {
        "_type": "newgtld",
        "host": "whois.gtld.knet.cn"
    },
    "xn--fiqs8s": {
        "host": "cwhois.cnnic.cn"
    },
    "xn--fiqz9s": {
        "host": "cwhois.cnnic.cn"
    },
    "xn--fjq720a": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.xn--fjq720a"
    },
    "xn--flw351e": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "xn--fpcrj9c3d": {
        "host": "whois.inregistry.net"
    },
    "xn--fzc2c9e2c": {
        "host": "whois.nic.lk"
    },
    "xn--fzys8d69uvgm": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.xn--fzys8d69uvgm"
    },
    "xn--g2xx48c": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "xn--gckr3f0f": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--gecrj9c": {
        "host": "whois.inregistry.net"
    },
    "xn--gk3at1e": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--h2breg3eve": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--h2brj9c": {
        "host": "whois.inregistry.net"
    },
    "xn--h2brj9c8c": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--hxt814e": {
        "_type": "newgtld",
        "host": "whois.nic.xn--hxt814e"
    },
    "xn--i1b6b1a6a2e": {
        "_group": "publicinterestregistry",
        "_type": "newgtld",
        "host": "whois.publicinterestregistry.net"
    },
    "xn--imr513n": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--io0a7i": {
        "_group": "ngtld",
        "_type": "newgtld",
        "host": "whois.ngtld.cn"
    },
    "xn--j1aef": {
        "_type": "newgtld",
        "host": "whois.nic.xn--j1aef"
    },
    "xn--j1amh": {
        "host": "whois.dotukr.com"
    },
    "xn--j6w193g": {
        "host": "whois.hkirc.hk"
    },
    "xn--jlq61u9w7b": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.xn--jlq61u9w7b"
    },
    "xn--jvr189m": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--kcrx77d1x4a": {
        "_type": "newgtld",
        "host": "whois.nic.xn--kcrx77d1x4a"
    },
    "xn--kprw13d": {
        "host": "whois.twnic.net.tw"
    },
    "xn--kpry57d": {
        "host": "whois.twnic.net.tw"
    },
    "xn--kpu716f": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--kput3i": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.nic.xn--kput3i"
    },
    "xn--l1acc": {
        "adapter": "none"
    },
    "xn--lgbbat1ad8j": {
        "host": "whois.nic.dz"
    },
    "xn--mgb9awbf": {
        "host": "whois.registry.om"
    },
    "xn--mgba3a3ejt": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--mgba3a4f16a": {
        "host": "whois.nic.ir"
    },
    "xn--mgba7c0bbn0a": {
        "_type": "newgtld",
        "host": "whois.nic.xn--mgba7c0bbn0a"
    },
    "xn--mgbaakc7dvf": {
        "_group": "centralnic",
        "host": "whois.centralnic.com"
    },
    "xn--mgbaam7a8h": {
        "host": "whois.aeda.net.ae"
    },
    "xn--mgbab2bd": {
        "_group": "coreregistry",
        "_type": "newgtld",
        "host": "whois.bazaar.coreregistry.net"
    },
    "xn--mgbai9azgqp6j": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--mgbayh7gpa": {
        "adapter": "web",
        "url": "http://idn.jo/whois_a.aspx"
    },
    "xn--mgbb9fbpob": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--mgbbh1a": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--mgbbh1a71e": {
        "host": "whois.inregistry.net"
    },
    "xn--mgbc0a9azcg": {
        "adapter": "none"
    },
    "xn--mgbca7dzdo": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "xn--mgberp4a5d4ar": {
        "host": "whois.nic.net.sa"
    },
    "xn--mgbgu82a": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--mgbi4ecexp": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.aridnrs.net.au"
    },
    "xn--mgbpl2fh": {
        "adapter": "none"
    },
    "xn--mgbt3dhd": {
        "_group": "agitsys",
        "_type": "newgtld",
        "host": "whois.agitsys.net"
    },
    "xn--mgbtx2b": {
        "host": "whois.cmc.iq"
    },
    "xn--mgbx4cd0ab": {
        "host": "whois.mynic.my"
    },
    "xn--mix891f": {
        "host": "whois.monic.mo"
    },
    "xn--mk1bu44c": {
        "_type": "newgtld",
        "host": "whois.nic.xn--mk1bu44c"
    },
    "xn--mxtq1m": {
        "_type": "newgtld",
        "host": "whois.nic.xn--mxtq1m"
    },
    "xn--ngbc5azd": {
        "_type": "newgtld",
        "host": "whois.nic.xn--ngbc5azd"
    },
    "xn--ngbe9e0a": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.xn--ngbe9e0a"
    },
    "xn--node": {
        "host": "whois.itdc.ge"
    },
    "xn--nqv7f": {
        "_group": "publicinterestregistry",
        "_type": "newgtld",
        "host": "whois.publicinterestregistry.net"
    },
    "xn--nqv7fs00ema": {
        "_group": "publicinterestregistry",
        "_type": "newgtld",
        "host": "whois.nic.xn--nqv7fs00ema"
    },
    "xn--nyqy26a": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--o3cw4h": {
        "host": "whois.thnic.co.th"
    },
    "xn--ogbpf8fl": {
        "host": "whois.tld.sy"
    },
    "xn--otu796d": {
        "adapter": "none"
    },
    "xn--p1acf": {
        "_type": "newgtld",
        "host": "whois.nic.xn--p1acf"
    },
    "xn--p1ai": {
        "host": "whois.tcinet.ru"
    },
    "xn--pbt977c": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--pgbs0dh": {
        "adapter": "none"
    },
    "xn--pssy2u": {
        "_type": "newgtld",
        "host": "whois.nic.xn--pssy2u"
    },
    "xn--q9jyb4c": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "xn--qcka1pmc": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "xn--qxam": {
        "adapter": "web",
        "url": "https://grweb.ics.forth.gr/public/whois.jsp?lang=en"
    },
    "xn--rhqv96g": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--rovu88b": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--rvc1e0am3e": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "xn--s9brj9c": {
        "host": "whois.inregistry.net"
    },
    "xn--ses554g": {
        "_type": "newgtld",
        "host": "whois.registry.knet.cn"
    },
    "xn--t60b56a": {
        "_type": "newgtld",
        "host": "whois.nic.xn--t60b56a"
    },
    "xn--tckwe": {
        "_type": "newgtld",
        "host": "whois.nic.xn--tckwe"
    },
    "xn--tiq49xqyj": {
        "_group": "aridnrs",
        "_type": "newgtld",
        "host": "whois.aridnrs.net.au"
    },
    "xn--unup4y": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.xn--unup4y"
    },
    "xn--vermgensberater-ctb": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "xn--vermgensberatung-pwb": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "xn--vhquv": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.xn--vhquv"
    },
    "xn--vuq861b": {
        "_group": "ngtld",
        "_type": "newgtld",
        "host": "whois.teleinfo.cn"
    },
    "xn--w4r85el8fhu5dnra": {
        "_type": "newgtld",
        "host": "whois.nic.xn--w4r85el8fhu5dnra"
    },
    "xn--w4rs40l": {
        "_type": "newgtld",
        "host": "whois.nic.xn--w4rs40l"
    },
    "xn--wgbh1c": {
        "host": "whois.dotmasr.eg"
    },
    "xn--wgbl6a": {
        "host": "whois.registry.qa"
    },
    "xn--xhq521b": {
        "_group": "teleinfo",
        "_type": "newgtld",
        "host": "whois.teleinfo.cn"
    },
    "xn--xkc2al3hye2a": {
        "host": "whois.nic.lk"
    },
    "xn--xkc2dl3a5ee0h": {
        "host": "whois.inregistry.net"
    },
    "xn--y9a3aq": {
        "host": "whois.amnic.net"
    },
    "xn--yfro4i67o": {
        "host": "whois.sgnic.sg"
    },
    "xn--ygbi2ammx": {
        "host": "whois.pnina.ps"
    },
    "xn--zfr164b": {
        "_type": "newgtld",
        "host": "whois.conac.cn"
    },
    "xxx": {
        "host": "whois.nic.xxx"
    },
    "xyz": {
        "_group": "centralnic",
        "_type": "newgtld",
        "host": "whois.nic.xyz"
    },
    "yachts": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "yahoo": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "yamaxun": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "yandex": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "ye": {
        "adapter": "none"
    },
    "yodobashi": {
        "_group": "gmo",
        "_type": "newgtld",
        "host": "whois.nic.gmo"
    },
    "yoga": {
        "_group": "mmregistry",
        "_type": "newgtld",
        "host": "whois.nic.yoga"
    },
    "yokohama": {
        "_type": "newgtld",
        "host": "whois.nic.yokohama"
    },
    "you": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "youtube": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "yt": {
        "host": "whois.nic.yt"
    },
    "yun": {
        "_group": "teleinfo",
        "_type": "newgtld",
        "host": "whois.teleinfo.cn"
    },
    "za": {
        "adapter": "none"
    },
    "ac.za": {
        "host": "whois.ac.za"
    },
    "alt.za": {
        "host": "whois.alt.za"
    },
    "co.za": {
        "host": "coza-whois.registry.net.za"
    },
    "gov.za": {
        "host": "whois.gov.za"
    },
    "net.za": {
        "host": "net-whois.registry.net.za"
    },
    "org.za": {
        "host": "org-whois.registry.net.za"
    },
    "web.za": {
        "host": "web-whois.registry.net.za"
    },
    "zappos": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "zara": {
        "_group": "afiliassrs",
        "_type": "newgtld",
        "host": "whois.afilias-srs.net"
    },
    "zero": {
        "_group": "amazonregistry",
        "_type": "newgtld",
        "adapter": "none"
    },
    "zip": {
        "_group": "google",
        "_type": "newgtld",
        "host": "whois.nic.google"
    },
    "zippo": {
        "_type": "newgtld",
        "adapter": "none"
    },
    "zm": {
        "host": "whois.nic.zm"
    },
    "zone": {
        "_group": "donuts",
        "_type": "newgtld",
        "host": "whois.nic.zone"
    },
    "zuerich": {
        "_group": "ksregistry",
        "_type": "newgtld",
        "host": "whois.ksregistry.net"
    },
    "zw": {
        "adapter": "none"
    }
}

grammar = {
    "_data": {
        'id': ['Domain ID:[ ]*(?P<val>.+)'],
        'status': ['\[Status\]\s*(?P<val>.+)',
                   'Status\s*:\s?(?P<val>.+)',
                   '\[State\]\s*(?P<val>.+)',
                   '^state:\s*(?P<val>.+)'],
        'creation_date': ['\[Created on\]\s*(?P<val>.+)',
                          'Created on[.]*: [a-zA-Z]+, (?P<val>.+)',
                          'Creation Date:\s?(?P<val>.+)',
                          'Creation date\s*:\s?(?P<val>.+)',
                          'Registration Date:\s?(?P<val>.+)',
                          'Created Date:\s?(?P<val>.+)',
                          'Created on:\s?(?P<val>.+)',
                          'Created on\s?[.]*:\s?(?P<val>.+)\.',
                          'Date Registered\s?[.]*:\s?(?P<val>.+)',
                          'Domain Created\s?[.]*:\s?(?P<val>.+)',
                          'Domain registered\s?[.]*:\s?(?P<val>.+)',
                          'Domain record activated\s?[.]*:\s*?(?P<val>.+)',
                          'Record created on\s?[.]*:?\s*?(?P<val>.+)',
                          'Record created\s?[.]*:?\s*?(?P<val>.+)',
                          'Created\s?[.]*:?\s*?(?P<val>.+)',
                          'Registered on\s?[.]*:?\s*?(?P<val>.+)',
                          'Registered\s?[.]*:?\s*?(?P<val>.+)',
                          'Domain Create Date\s?[.]*:?\s*?(?P<val>.+)',
                          'Domain Registration Date\s?[.]*:?\s*?(?P<val>.+)',
                          'created:\s*(?P<val>.+)',
                          '\[Registered Date\]\s*(?P<val>.+)',
                          'created-date:\s*(?P<val>.+)',
                          'Domain Name Commencement Date: (?P<val>.+)',
                          'registered:\s*(?P<val>.+)',
                          'registration:\s*(?P<val>.+)'],
        'expiration_date': ['\[Expires on\]\s*(?P<val>.+)',
                            'Registrar Registration Expiration Date:[ ]*(?P<val>.+)-[0-9]{4}',
                            'Expires on[.]*: [a-zA-Z]+, (?P<val>.+)',
                            'Expiration Date:\s?(?P<val>.+)',
                            'Expiration date\s*:\s?(?P<val>.+)',
                            'Expires on:\s?(?P<val>.+)',
                            'Expires on\s?[.]*:\s?(?P<val>.+)\.',
                            'Exp(?:iry)? Date\s?[.]*:\s?(?P<val>.+)',
                            'Expiry\s*:\s?(?P<val>.+)',
                            'Domain Currently Expires\s?[.]*:\s?(?P<val>.+)',
                            'Record will expire on\s?[.]*:\s?(?P<val>.+)',
                            'Domain expires\s?[.]*:\s*?(?P<val>.+)',
                            'Record expires on\s?[.]*:?\s*?(?P<val>.+)',
                            'Record expires\s?[.]*:?\s*?(?P<val>.+)',
                            'Expires\s?[.]*:?\s*?(?P<val>.+)',
                            'Expire Date\s?[.]*:?\s*?(?P<val>.+)',
                            'Expired\s?[.]*:?\s*?(?P<val>.+)',
                            'Domain Expiration Date\s?[.]*:?\s*?(?P<val>.+)',
                            'paid-till:\s*(?P<val>.+)',
                            'expiration_date:\s*(?P<val>.+)',
                            'expire-date:\s*(?P<val>.+)',
                            'renewal:\s*(?P<val>.+)',
                            'expire:\s*(?P<val>.+)'],
        'updated_date': ['\[Last Updated\]\s*(?P<val>.+)',
                         'Record modified on[.]*: (?P<val>.+) [a-zA-Z]+',
                         'Record last updated on[.]*: [a-zA-Z]+, (?P<val>.+)',
                         'Updated Date:\s?(?P<val>.+)',
                         'Updated date\s*:\s?(?P<val>.+)',
                         # 'Database last updated on\s?[.]*:?\s*?(?P<val>.+)\s[a-z]+\.?',
                         'Record last updated on\s?[.]*:?\s?(?P<val>.+)\.',
                         'Domain record last updated\s?[.]*:\s*?(?P<val>.+)',
                         'Domain Last Updated\s?[.]*:\s*?(?P<val>.+)',
                         'Last updated on:\s?(?P<val>.+)',
                         'Date Modified\s?[.]*:\s?(?P<val>.+)',
                         'Last Modified\s?[.]*:\s?(?P<val>.+)',
                         'Domain Last Updated Date\s?[.]*:\s?(?P<val>.+)',
                         'Record last updated\s?[.]*:\s?(?P<val>.+)',
                         'Modified\s?[.]*:\s?(?P<val>.+)',
                         '(C|c)hanged:\s*(?P<val>.+)',
                         'last_update:\s*(?P<val>.+)',
                         'Last Update\s?[.]*:\s?(?P<val>.+)',
                         'Last updated on (?P<val>.+) [a-z]{3,4}',
                         'Last updated:\s*(?P<val>.+)',
                         'last-updated:\s*(?P<val>.+)',
                         '\[Last Update\]\s*(?P<val>.+) \([A-Z]+\)',
                         'Last update of whois database:\s?[a-z]{3}, (?P<val>.+) [a-z]{3,4}'],
        'registrar': ['registrar:\s*(?P<val>.+)',
                      'Registrar:\s*(?P<val>.+)',
                      'Sponsoring Registrar Organization:\s*(?P<val>.+)',
                      'Registered through:\s?(?P<val>.+)',
                      'Registrar Name[.]*:\s?(?P<val>.+)',
                      'Record maintained by:\s?(?P<val>.+)',
                      'Registration Service Provided By:\s?(?P<val>.+)',
                      'Registrar of Record:\s?(?P<val>.+)',
                      'Domain Registrar :\s?(?P<val>.+)',
                      'Registration Service Provider: (?P<val>.+)',
                      '\tName:\t\s(?P<val>.+)'],
        'whois_server': ['Whois Server:\s?(?P<val>.+)',
                         'Registrar Whois:\s?(?P<val>.+)'],
        'nameservers': ['Name Server:[ ]*(?P<val>[^ ]+)',
                        'Nameservers:[ ]*(?P<val>[^ ]+)',
                        '(?<=[ .]{2})(?P<val>([a-z0-9-]+\.)+[a-z0-9]+)(\s+([0-9]{1,3}\.){3}[0-9]{1,3})',
                        'nameserver:\s*(?P<val>.+)',
                        'nserver:\s*(?P<val>[^[\s]+)',
                        'Name Server[.]+ (?P<val>[^[\s]+)',
                        'Hostname:\s*(?P<val>[^\s]+)',
                        'DNS[0-9]+:\s*(?P<val>.+)',
                        '   DNS:\s*(?P<val>.+)',
                        'ns[0-9]+:\s*(?P<val>.+)',
                        'NS [0-9]+\s*:\s*(?P<val>.+)',
                        '\[Name Server\]\s*(?P<val>.+)',
                        '(?<=[ .]{2})(?P<val>[a-z0-9-]+\.d?ns[0-9]*\.([a-z0-9-]+\.)+[a-z0-9]+)',
                        '(?<=[ .]{2})(?P<val>([a-z0-9-]+\.)+[a-z0-9]+)(\s+([0-9]{1,3}\.){3}[0-9]{1,3})',
                        '(?<=[ .]{2})[^a-z0-9.-](?P<val>d?ns\.([a-z0-9-]+\.)+[a-z0-9]+)',
                        'Nserver:\s*(?P<val>.+)'],
        'emails': ['(?P<val>[\w.-]+@[\w.-]+\.[\w]{2,6})',  # Really need to fix this, much longer TLDs now exist...
                   '(?P<val>[\w.-]+\sAT\s[\w.-]+\sDOT\s[\w]{2,6})']
    },
    "_dateformats": (
        '(?P<day>[0-9]{1,2})[./ -](?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[./ -](?P<year>[0-9]{4}|[0-9]{2})'
        '(\s+(?P<hour>[0-9]{1,2})[:.](?P<minute>[0-9]{1,2})[:.](?P<second>[0-9]{1,2}))?',
        '[a-z]{3}\s(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[./ -](?P<day>[0-9]{1,2})(\s+(?P<hour>[0-9]{1,2})[:.](?P<minute>[0-9]{1,2})[:.](?P<second>[0-9]{1,2}))?\s[a-z]{3}\s(?P<year>[0-9]{4}|[0-9]{2})',
        '[a-zA-Z]+\s(?P<day>[0-9]{1,2})(?:st|nd|rd|th)\s(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December)\s(?P<year>[0-9]{4})',
        '(?P<year>[0-9]{4})[./-]?(?P<month>[0-9]{2})[./-]?(?P<day>[0-9]{2})(\s|T|/)((?P<hour>[0-9]{1,2})[:.-](?P<minute>[0-9]{1,2})[:.-](?P<second>[0-9]{1,2}))',
        '(?P<year>[0-9]{4})[./-](?P<month>[0-9]{1,2})[./-](?P<day>[0-9]{1,2})',
        '(?P<day>[0-9]{1,2})[./ -](?P<month>[0-9]{1,2})[./ -](?P<year>[0-9]{4}|[0-9]{2})',
        '(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?P<day>[0-9]{1,2}),? (?P<year>[0-9]{4})',
        '(?P<day>[0-9]{1,2})-(?P<month>January|February|March|April|May|June|July|August|September|October|November|December)-(?P<year>[0-9]{4})',
    ),
    "_months": {
        'jan': 1,
        'january': 1,
        'feb': 2,
        'february': 2,
        'mar': 3,
        'march': 3,
        'apr': 4,
        'april': 4,
        'may': 5,
        'jun': 6,
        'june': 6,
        'jul': 7,
        'july': 7,
        'aug': 8,
        'august': 8,
        'sep': 9,
        'sept': 9,
        'september': 9,
        'oct': 10,
        'october': 10,
        'nov': 11,
        'november': 11,
        'dec': 12,
        'december': 12
    }
}

dble_ext_str = "chirurgiens-dentistes.fr,in-addr.arpa,uk.net,za.org,mod.uk,org.za,za.com,de.com,us.com,hk.org,co.ca," \
               "avocat.fr,com.uy,gr.com,e164.arpa,hu.net,us.org,com.se,aeroport.fr,gov.uk,ru.com,alt.za,africa.com," \
               "geometre-expert.fr,in.net,co.com,kr.com,bl.uk,uk.com,port.fr,police.uk,gov.za,eu.com,eu.org,br.com," \
               "web.za,net.za,co.za,hk.com,ae.org,edu.ru,ar.com,jet.uk,icnet.uk,com.de,inc.hk,ltd.hk,parliament.uk," \
               "jp.net,gb.com,veterinaire.fr,edu.cn,qc.com,pharmacien.fr,ac.za,sa.com,medecin.fr,uy.com,se.net,co.pl," \
               "cn.com,hu.com,no.com,ac.uk,jpn.com,priv.at,za.net,nls.uk,nhs.uk,za.bz,experts-comptables.fr," \
               "chambagri.fr,gb.net,in.ua,notaires.fr,se.com,british-library.uk "
dble_ext = dble_ext_str.split(",")

# ipwhois exceptions to execution metrics attributes mapping
# https://ipwhois.readthedocs.io/en/latest/ipwhois.html
ipwhois_exception_mapping: Dict[Type, str] = {

    # General Errors
    ipwhois.exceptions.WhoisLookupError: "general_error",
    ipwhois.exceptions.ASNLookupError: "general_error",
    ipwhois.exceptions.ASNOriginLookupError: "general_error",
    ipwhois.exceptions.ASNRegistryError: "general_error",
    ipwhois.exceptions.ASNParseError: "general_error",
    ipwhois.exceptions.ASNRegistryError: "general_error",
    ipwhois.exceptions.BaseIpwhoisException: "general_error",
    urllib.error.HTTPError: "general_error",
    ValueError: "general_error",
    ipwhois.exceptions.IPDefinedError: "general_error",

    # Service Errors
    ipwhois.exceptions.BlacklistError: "service_error",
    ipwhois.exceptions.HTTPLookupError: "connection_error",

    # Connection Errors
    ipwhois.exceptions.NetError: "connection_error",

    # Rate Limit Errors
    ipwhois.exceptions.HTTPRateLimitError: "quota_error",
    ipwhois.exceptions.WhoisRateLimitError: "quota_error",
}


class WhoisInvalidDomain(Exception):
    pass


class WhoisEmptyResponse(Exception):
    pass


class WhoisException(Exception):
    pass


# whois domain exception to execution metrics attribute mapping
whois_exception_mapping: Dict[Type, str] = {
    socket.error: "connection_error",
    OSError: "connection_error",
    socket.timeout: "timeout_error",
    socket.herror: "connection_error",
    socket.gaierror: "connection_error",
    WhoisInvalidDomain: "general_error",
    WhoisEmptyResponse: "service_error",
    TypeError: "general_error",
    PywhoisError: "service_error"
}


def increment_metric(execution_metrics: ExecutionMetrics, mapping: Dict[type, str], caught_exception: Type) -> ExecutionMetrics:
    """
    Helper method to increment the API execution metric according to the caught exception

    Args:
        - `execution_metrics` (``ExecutionMetrics``): The instance of the API execution metrics.
        - `mapping` (``Dict[type, str]``): The exception type to execution metrics mapping.
        - `caught_exception` (``Exception``): The exception caught.
    """

    demisto.debug(
        f"Exception of type '{caught_exception}' caught. Trying to find the matching Execution Metric attribute to increment...")
    try:
        metric_attribute = mapping[caught_exception]
        execution_metrics.__setattr__(metric_attribute, execution_metrics.__getattribute__(metric_attribute) + 1)

    # Treat any other exception as a ErrorTypes.GENERAL_ERROR
    except Exception as e:
        demisto.debug(
            f"Exception attempting to find and update execution metric attribute: {str(e)}. Defaulting to GENERAL_ERROR...")
        execution_metrics.general_error += 1

    finally:
        demisto.debug(f"Returning updated execution_metrics")
        return execution_metrics


def get_whois_raw(domain, server="", previous=None, never_cut=False, with_server_list=False,
                  server_list=None, is_recursive=True):
    new_list = []
    previous = previous or []
    server_list = server_list or []
    # Sometimes IANA simply won't give us the right root WHOIS server
    exceptions = {
        ".ac.uk": "whois.ja.net",
        ".ps": "whois.pnina.ps",
        ".buzz": "whois.nic.buzz",
        ".moe": "whois.nic.moe",
        # The following is a bit hacky, but IANA won't return the right answer for example.com because it's a direct
        # registration.
        "example.com": "whois.verisign-grs.com"
    }

    if len(previous) == 0 and server == "":
        # Root query
        is_exception = False
        for exception, exc_serv in list(exceptions.items()):
            if domain.endswith(exception):
                is_exception = True
                target_server = exc_serv
                break
        if not is_exception:
            target_server = get_root_server(domain)
    else:
        target_server = server
    if target_server == "whois.jprs.jp":
        request_domain = "%s/e" % domain  # Suppress Japanese output
    elif domain.endswith(".de") and (target_server == "whois.denic.de" or target_server == "de.whois-servers.net"):
        request_domain = "-T dn,ace %s" % domain  # regional specific stuff
    elif target_server == "whois.verisign-grs.com":
        request_domain = "=%s" % domain  # Avoid partial matches
    else:
        request_domain = domain
    # The following loop handles errno 104 - "connection reset by peer" by retry whois_request with the same arguments.
    # If the request fails due to other cause - there will not be another try
    attempts = 3
    for attempt in range(attempts):
        demisto.debug(f"Attempt {attempt}/{attempts} to get response for whois '{domain}' from '{target_server}'...")
        response = whois_request_get_response(request_domain, target_server)
        response_size = len(response.encode('utf-8'))
        demisto.debug(f"Response of attempt {attempt}/{attempts} to get whois {domain=} from {target_server=}, {response_size=}")

        if response_size > 0:
            demisto.debug(f"Response received for domain '{domain}' after {attempt} attempt(s)")
            break

    if not response:
        raise WhoisEmptyResponse(
            f"Got an empty response for the requested domain '{request_domain}' from the server '{target_server}'.")

    if never_cut:
        # If the caller has requested to 'never cut' responses, he will get the original response from the server (
        # this is useful for callers that are only interested in the raw data). Otherwise, if the target is
        # verisign-grs, we will select the data relevant to the requested domain, and discard the rest, so that in a
        # multiple-option response the parsing code will only touch the information relevant to the requested domain.
        # The side-effect of this is that when `never_cut` is set to False, any verisign-grs responses in the raw data
        # will be missing header, footer, and alternative domain options (this is handled a few lines below,
        # after the verisign-grs processing).
        new_list = [response] + previous
    if target_server == "whois.verisign-grs.com":
        # VeriSign is a little... special. As it may return multiple full records and there's no way to do an exact query,
        # we need to actually find the correct record in the list.
        for record in response.split("\n\n"):
            if re.search("Domain Name: %s\n" % domain.upper(), record):
                response = record
                break
    if never_cut == False:
        new_list = [response] + previous
    server_list.append(target_server)
    if is_recursive:
        for line in [x.strip() for x in response.splitlines()]:
            match = re.match("(refer|whois server|referral url|registrar whois(?: server)?):\s*([^\s]+\.[^\s]+)", line,
                             re.IGNORECASE)
            if match is not None:
                referral_server = match.group(2)
                # We want to ignore anything non-WHOIS (eg. HTTP) for now.
                if referral_server != server and "://" not in referral_server:
                    # Referral to another WHOIS server...
                    return get_whois_raw(domain, referral_server, new_list, server_list=server_list,
                                         with_server_list=with_server_list)

    if with_server_list:
        return new_list, server_list
    else:
        return new_list


def get_root_server(domain):

    demisto.debug(f"Attempting to get root server from domain '{domain}'...")
    try:
        (_, tld) = domain.rsplit(".", 1)
        for dble in dble_ext:
            if domain.endswith(dble):
                tld = dble

        if tld in list(tlds.keys()):
            entry = tlds[tld]
            host = entry["host"]
            demisto.debug(f"Found host '{host}' from domain '{domain}'")
            return host
        else:
            raise WhoisInvalidDomain(f"Can't parse the root server from domain '{domain}'")

    except (KeyError, TypeError, ValueError) as e:
        demisto.error(f"Could not get root server from domain '{domain}': {e.__class__.__name__} {e}")
        raise WhoisInvalidDomain(f"Can't parse the root server from domain '{domain}'")


def whois_request_get_response(domain: str, server: str) -> str:
    """
    Helper function to create a socket connection to the Whois server and return the response.

    Arguments:
        - `domain` (``str``): The domain to do the lookup on.
        - `server` (``str``): The Whois server to use in the lookup.

    Returns:
        - `str` with the raw response.
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if is_time_sensitive():
            # Default short timeout
            sock.settimeout(10)
        sock.connect((server, 43))
        sock.send(("%s\r\n" % domain).encode("utf-8"))
        buff = b""
        while True:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            buff += data
        sock.close()
        try:
            d = buff.decode("utf-8")
        except UnicodeDecodeError:
            d = buff.decode("latin-1")

        return d


airports = {}  # type: dict
countries = {}  # type: dict
states_au = {}  # type: dict
states_us = {}  # type: dict
states_ca = {}  # type: dict


def precompile_regexes(source, flags=0):
    return [re.compile(regex, flags) for regex in source]


def preprocess_regex(regex):
    # Fix for #2; prevents a ridiculous amount of varying size permutations.
    regex = re.sub(r"\\s\*\(\?P<([^>]+)>\.\+\)", r"\\s*(?P<\1>\\S.*)", regex)
    # Experimental fix for #18; removes unnecessary variable-size whitespace
    # matching, since we're stripping results anyway.
    regex = re.sub(r"\[ \]\*\(\?P<([^>]+)>\.\*\)", r"(?P<\1>.*)", regex)
    return regex


registrant_regexes = [
    "   Registrant:[ ]*\n      (?P<organization>.*)\n      (?P<name>.*)\n      (?P<street>.*)\n      (?P<city>.*), (?P<state>.*) (?P<postalcode>.*)\n      (?P<country>.*)\n(?:      Phone: (?P<phone>.*)\n)?      Email: (?P<email>.*)\n",
    # Corporate Domains, Inc.
    "Registrant:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n",
    # OVH
    "(?:Registrant ID:(?P<handle>.+)\n)?Registrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Street1?:(?P<street1>.*)\n(?:Registrant Street2:(?P<street2>.*)\n)?(?:Registrant Street3:(?P<street3>.*)\n)?Registrant City:(?P<city>.*)\nRegistrant State/Province:(?P<state>.*)\nRegistrant Postal Code:(?P<postalcode>.*)\nRegistrant Country:(?P<country>.*)\nRegistrant Phone:(?P<phone>.*)\n(?:Registrant Phone Ext.:(?P<phone_ext>.*)\n)?(?:Registrant FAX:(?P<fax>.*)\n)?(?:Registrant FAX Ext.:(?P<fax_ext>.*)\n)?Registrant Email:(?P<email>.*)",
    # Public Interest Registry (.org), nic.pw, No-IP.com
    "Registrant ID:(?P<handle>.+)\nRegistrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Address1?:(?P<street1>.*)\n(?:Registrant Address2:(?P<street2>.*)\n)?(?:Registrant Address3:(?P<street3>.*)\n)?Registrant City:(?P<city>.*)\nRegistrant State/Province:(?P<state>.*)\nRegistrant Country/Economy:(?P<country>.*)\nRegistrant Postal Code:(?P<postalcode>.*)\nRegistrant Phone:(?P<phone>.*)\n(?:Registrant Phone Ext.:(?P<phone_ext>.*)\n)?(?:Registrant FAX:(?P<fax>.*)\n)?(?:Registrant FAX Ext.:(?P<fax_ext>.*)\n)?Registrant E-mail:(?P<email>.*)",
    # .ME, DotAsia
    "Registrant ID:\s*(?P<handle>.+)\nRegistrant Name:\s*(?P<name>.+)\nRegistrant Organization:\s*(?P<organization>.*)\nRegistrant Address1:\s*(?P<street1>.+)\nRegistrant Address2:\s*(?P<street2>.*)\nRegistrant City:\s*(?P<city>.+)\nRegistrant State/Province:\s*(?P<state>.+)\nRegistrant Postal Code:\s*(?P<postalcode>.+)\nRegistrant Country:\s*(?P<country>.+)\nRegistrant Country Code:\s*(?P<country_code>.+)\nRegistrant Phone Number:\s*(?P<phone>.+)\nRegistrant Email:\s*(?P<email>.+)\n",
    # .CO Internet
    "Registrant Contact: (?P<handle>.+)\nRegistrant Organization: (?P<organization>.+)\nRegistrant Name: (?P<name>.+)\nRegistrant Street: (?P<street>.+)\nRegistrant City: (?P<city>.+)\nRegistrant Postal Code: (?P<postalcode>.+)\nRegistrant State: (?P<state>.+)\nRegistrant Country: (?P<country>.+)\nRegistrant Phone: (?P<phone>.*)\nRegistrant Phone Ext: (?P<phone_ext>.*)\nRegistrant Fax: (?P<fax>.*)\nRegistrant Fax Ext: (?P<fax_ext>.*)\nRegistrant Email: (?P<email>.*)\n",
    # Key-Systems GmbH
    "(?:Registrant ID:[ ]*(?P<handle>.*)\n)?Registrant Name:[ ]*(?P<name>.*)\n(?:Registrant Organization:[ ]*(?P<organization>.*)\n)?Registrant Street:[ ]*(?P<street1>.+)\n(?:Registrant Street:[ ]*(?P<street2>.+)\n)?(?:Registrant Street:[ ]*(?P<street3>.+)\n)?Registrant City:[ ]*(?P<city>.+)\nRegistrant State(?:\/Province)?:[ ]*(?P<state>.*)\nRegistrant Postal Code:[ ]*(?P<postalcode>.+)\nRegistrant Country:[ ]*(?P<country>.+)\n(?:Registrant Phone:[ ]*(?P<phone>.*)\n)?(?:Registrant Phone Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Registrant Fax:[ ]*(?P<fax>.*)\n)?(?:Registrant Fax Ext:[ ]*(?P<fax_ext>.*)\n)?(?:Registrant Email:[ ]*(?P<email>.+)\n)?",
    # WildWestDomains, GoDaddy, Namecheap/eNom, Ascio, Musedoma (.museum), EuroDNS, nic.ps
    "Registrant\n(?:    (?P<organization>.+)\n)?    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n",
    # internet.bs
    " Registrant Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)",
    # Whois.com
    "owner-id:[ ]*(?P<handle>.*)\n(?:owner-organization:[ ]*(?P<organization>.*)\n)?owner-name:[ ]*(?P<name>.*)\nowner-street:[ ]*(?P<street>.*)\nowner-city:[ ]*(?P<city>.*)\nowner-zip:[ ]*(?P<postalcode>.*)\nowner-country:[ ]*(?P<country>.*)\n(?:owner-phone:[ ]*(?P<phone>.*)\n)?(?:owner-fax:[ ]*(?P<fax>.*)\n)?owner-email:[ ]*(?P<email>.*)",
    # InterNetworX
    "Registrant:\n registrant_org: (?P<organization>.*)\n registrant_name: (?P<name>.*)\n registrant_email: (?P<email>.*)\n registrant_address: (?P<address>.*)\n registrant_city: (?P<city>.*)\n registrant_state: (?P<state>.*)\n registrant_zip: (?P<postalcode>.*)\n registrant_country: (?P<country>.*)\n registrant_phone: (?P<phone>.*)",
    # Bellnames
    "Holder of domain name:\n(?P<name>[\S\s]+)\n(?P<street>.+)\n(?P<postalcode>[A-Z0-9-]+)\s+(?P<city>.+)\n(?P<country>.+)\nContractual Language",
    # nic.ch
    "\n\n(?:Owner)?\s+: (?P<name>.*)\n(?:\s+: (?P<organization>.*)\n)?\s+: (?P<street>.*)\n\s+: (?P<city>.*)\n\s+: (?P<state>.*)\n\s+: (?P<country>.*)\n",
    # nic.io
    "Contact Information:\n\[Name\]\s*(?P<name>.*)\n\[Email\]\s*(?P<email>.*)\n\[Web Page\]\s*(?P<url>.*)\n\[Postal code\]\s*(?P<postalcode>.*)\n\[Postal Address\]\s*(?P<street1>.*)\n(?:\s+(?P<street2>.*)\n)?(?:\s+(?P<street3>.*)\n)?\[Phone\]\s*(?P<phone>.*)\n\[Fax\]\s*(?P<fax>.*)\n",
    # jprs.jp
    "g\. \[Organization\]               (?P<organization>.+)\n",  # .co.jp registrations at jprs.jp
    "Registrant ID:(?P<handle>.*)\nRegistrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Address1:(?P<street1>.*)\n(?:Registrant Address2:(?P<street2>.*)\n)?(?:Registrant Address3:(?P<street3>.*)\n)?Registrant City:(?P<city>.*)\n(?:Registrant State/Province:(?P<state>.*)\n)?(?:Registrant Postal Code:(?P<postalcode>.*)\n)?Registrant Country:(?P<country>.*)\nRegistrant Country Code:.*\nRegistrant Phone Number:(?P<phone>.*)\n(?:Registrant Facsimile Number:(?P<facsimile>.*)\n)?Registrant Email:(?P<email>.*)",
    # .US, .biz (NeuStar), .buzz, .moe (Interlink Co. Ltd.)
    "Registrant\n  Name:             (?P<name>.+)\n(?:  Organization:     (?P<organization>.+)\n)?  ContactID:        (?P<handle>.+)\n(?:  Address:          (?P<street1>.+)\n(?:                    (?P<street2>.+)\n(?:                    (?P<street3>.+)\n)?)?                    (?P<city>.+)\n                    (?P<postalcode>.+)\n                    (?P<state>.+)\n                    (?P<country>.+)\n)?(?:  Created:          (?P<creationdate>.+)\n)?(?:  Last Update:      (?P<changedate>.+)\n)?",
    # nic.it
    "  Organisation Name[.]* (?P<name>.*)\n  Organisation Address[.]* (?P<street1>.*)\n  Organisation Address[.]* (?P<street2>.*)\n(?:  Organisation Address[.]* (?P<street3>.*)\n)?  Organisation Address[.]* (?P<city>.*)\n  Organisation Address[.]* (?P<postalcode>.*)\n  Organisation Address[.]* (?P<state>.*)\n  Organisation Address[.]* (?P<country>.*)",
    # Melbourne IT (what a horrid format...)
    "Registrant:[ ]*(?P<name>.+)\n[\s\S]*Eligibility Name:[ ]*(?P<organization>.+)\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n",
    # .au business
    "Eligibility Type:[ ]*Citizen\/Resident\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n[\s\S]*Registrant Contact Name:[ ]*(?P<name>.+)\n",
    # .au individual
    "Registrant:[ ]*(?P<organization>.+)\n[\s\S]*Eligibility Type:[ ]*(Higher Education Institution|Company|Incorporated Association|Other)\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n[\s\S]*Registrant Contact Name:[ ]*(?P<name>.+)\n",
    # .au educational, company, 'incorporated association' (non-profit?), other (spotted for linux.conf.au, unsure if also for others)
    "    Registrant:\n        (?P<name>.+)\n\n    Registrant type:\n        .*\n\n    Registrant's address:\n        The registrant .* opted to have",
    # Nominet (.uk) with hidden address
    "    Registrant:\n        (?P<name>.+)\n\n[\s\S]*    Registrant type:\n        .*\n\n    Registrant's address:\n        (?P<street1>.+)\n(?:        (?P<street2>.+)\n(?:        (?P<street3>.+)\n)??)??        (?P<city>[^0-9\n]+)\n(?:        (?P<state>.+)\n)?        (?P<postalcode>.+)\n        (?P<country>.+)\n\n",
    # Nominet (.uk) with visible address
    "Domain Owner:\n\t(?P<organization>.+)\n\n[\s\S]*?(?:Registrant Contact:\n\t(?P<name>.+))?\n\nRegistrant(?:'s)? (?:a|A)ddress:(?:\n\t(?P<street1>.+)\n(?:\t(?P<street2>.+)\n)?(?:\t(?P<street3>.+)\n)?\t(?P<city>.+)\n\t(?P<postalcode>.+))?\n\t(?P<country>.+)(?:\n\t(?P<phone>.+) \(Phone\)\n\t(?P<fax>.+) \(FAX\)\n\t(?P<email>.+))?\n\n",
    # .ac.uk - what a mess...
    "Registrant ID: (?P<handle>.+)\nRegistrant: (?P<name>.+)\nRegistrant Contact Email: (?P<email>.+)",  # .cn (CNNIC)
    "Registrant contact:\n  (?P<name>.+)\n  (?P<street>.*)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n\n",
    # Fabulous.com
    "registrant-name:\s*(?P<name>.+)\nregistrant-type:\s*(?P<type>.+)\nregistrant-address:\s*(?P<street>.+)\nregistrant-postcode:\s*(?P<postalcode>.+)\nregistrant-city:\s*(?P<city>.+)\nregistrant-country:\s*(?P<country>.+)\n(?:registrant-phone:\s*(?P<phone>.+)\n)?(?:registrant-email:\s*(?P<email>.+)\n)?",
    # Hetzner
    "Registrant Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n",
    # GAL Communication
    "Contact Information : For Customer # [0-9]+[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n",
    # GAL Communication alternative (private WHOIS) format?
    "Registrant:\n   Name:           (?P<name>.+)\n   City:           (?P<city>.+)\n   State:          (?P<state>.+)\n   Country:        (?P<country>.+)\n",
    # Akky (.com.mx)
    "   Registrant:\n      (?P<name>.+)\n      (?P<street>.+)\n      (?P<city>.+) (?P<state>\S+),[ ]+(?P<postalcode>.+)\n      (?P<country>.+)",
    # .am
    "Domain Holder: (?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?, (?P<city>[^.,]+), (?P<district>.+), (?P<state>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
    # .co.th, format 1
    "Domain Holder: (?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?, (?P<city>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
    # .co.th, format 2
    "Domain Holder: (?P<organization>.+)\n(?P<street1>.+)\n(?:(?P<street2>.+)\n)?(?:(?P<street3>.+)\n)?.+?, (?P<district>.+)\n(?P<city>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
    # .co.th, format 3
    "Domain Holder: (?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?\n(?P<city>.+),? (?P<state>[A-Z]{2,3})(?: [A-Z0-9]+)?\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
    # .co.th, format 4
    "   Registrant:\n      (?P<organization>.+)\n      (?P<name>.+)  (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)\n      (?P<street>.*)\n      (?P<city>.+), (?P<state>[^,\n]*)\n      (?P<country>.+)\n",
    # .com.tw (Western registrars)
    "Registrant:\n(?P<organization1>.+)\n(?P<organization2>.+)\n(?P<street1>.+?)(?:,+(?P<street2>.+?)(?:,+(?P<street3>.+?)(?:,+(?P<street4>.+?)(?:,+(?P<street5>.+?)(?:,+(?P<street6>.+?)(?:,+(?P<street7>.+?))?)?)?)?)?)?,(?P<city>.+),(?P<country>.+)\n\n   Contact:\n      (?P<name>.+)   (?P<email>.+)\n      TEL:  (?P<phone>.+?)(?:(?:#|ext.?)(?P<phone_ext>.+))?\n      FAX:  (?P<fax>.+)(?:(?:#|ext.?)(?P<fax_ext>.+))?\n",
    # .com.tw (TWNIC/SEEDNET, Taiwanese companies only?)
    "Registrant Contact Information:\n\nCompany English Name \(It should be the same as the registered/corporation name on your Business Register Certificate or relevant documents\):(?P<organization1>.+)\nCompany Chinese name:(?P<organization2>.+)\nAddress: (?P<street>.+)\nCountry: (?P<country>.+)\nEmail: (?P<email>.+)\n",
    # HKDNR (.hk)
    "Registrant ID:(?P<handle>.+)\nRegistrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Street1:(?P<street1>.+?)\n(?:Registrant Street2:(?P<street2>.+?)\n(?:Registrant Street3:(?P<street3>.+?)\n)?)?Registrant City:(?P<city>.+)\nRegistrant State:(?P<state>.*)\nRegistrant Postal Code:(?P<postalcode>.+)\nRegistrant Country:(?P<country>[A-Z]+)\nRegistrant Phone:(?P<phone>.*?)\nRegistrant Fax:(?P<fax>.*)\nRegistrant Email:(?P<email>.+)\n",
    # Realtime Register
    "owner:\s+(?P<name>.+)",  # .br
    "person:\s+(?P<name>.+)",  # nic.ru (person)
    "org:\s+(?P<organization>.+)",  # nic.ru (organization)
    "Registrant:\n\t(?P<organization>.+)\n\t(?P<organization2>.+)\n\t(?P<street>.*)\n\t(?P<city>.+), (?P<state>.*) (?P<postalcode>.+)\n\t(?P<country>.+)",
    # EDU domains
    "Registrant Organization: (?P<organization>.+)\nRegistrant State/Province: (?P<state>.*)\nRegistrant Country: (?P<country>[A-Z]+)",
    "Registrant:\n\t(?P<organization>.+)\n\t(?P<street>.*)\n\t(?P<city>.+), (?P<state>.*) (?P<postalcode>.+)\n\t(?P<country>.+)"
]

tech_contact_regexes = [
    "   Technical Contact:[ ]*\n      (?P<organization>.*)\n      (?P<name>.*)\n      (?P<street>.*)\n      (?P<city>.*), (?P<state>.*) (?P<postalcode>.*)\n      (?P<country>.*)\n(?:      Phone: (?P<phone>.*)\n)?      Email: (?P<email>.*)\n",
    # Corporate Domains, Inc.
    "Technical Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n",
    # OVH
    "(?:Tech ID:(?P<handle>.+)\n)?Tech Name:(?P<name>.*)\n(:?Tech Organization:(?P<organization>.*)\n)?Tech Street1?:(?P<street1>.*)\n(?:Tech Street2:(?P<street2>.*)\n)?(?:Tech Street3:(?P<street3>.*)\n)?Tech City:(?P<city>.*)\nTech State/Province:(?P<state>.*)\nTech Postal Code:(?P<postalcode>.*)\nTech Country:(?P<country>.*)\nTech Phone:(?P<phone>.*)\n(?:Tech Phone Ext.:(?P<phone_ext>.*)\n)?(?:Tech FAX:(?P<fax>.*)\n)?(?:Tech FAX Ext.:(?P<fax_ext>.*)\n)?Tech Email:(?P<email>.*)",
    # Public Interest Registry (.org), nic.pw, No-IP.com
    "Tech(?:nical)? ID:(?P<handle>.+)\nTech(?:nical)? Name:(?P<name>.*)\n(?:Tech(?:nical)? Organization:(?P<organization>.*)\n)?Tech(?:nical)? Address1?:(?P<street1>.*)\n(?:Tech(?:nical)? Address2:(?P<street2>.*)\n)?(?:Tech(?:nical)? Address3:(?P<street3>.*)\n)?Tech(?:nical)? City:(?P<city>.*)\nTech(?:nical)? State/Province:(?P<state>.*)\nTech(?:nical)? Country/Economy:(?P<country>.*)\nTech(?:nical)? Postal Code:(?P<postalcode>.*)\nTech(?:nical)? Phone:(?P<phone>.*)\n(?:Tech(?:nical)? Phone Ext.:(?P<phone_ext>.*)\n)?(?:Tech(?:nical)? FAX:(?P<fax>.*)\n)?(?:Tech(?:nical)? FAX Ext.:(?P<fax_ext>.*)\n)?Tech(?:nical)? E-mail:(?P<email>.*)",
    # .ME, DotAsia
    "Technical Contact ID:\s*(?P<handle>.+)\nTechnical Contact Name:\s*(?P<name>.+)\nTechnical Contact Organization:\s*(?P<organization>.*)\nTechnical Contact Address1:\s*(?P<street1>.+)\nTechnical Contact Address2:\s*(?P<street2>.*)\nTechnical Contact City:\s*(?P<city>.+)\nTechnical Contact State/Province:\s*(?P<state>.+)\nTechnical Contact Postal Code:\s*(?P<postalcode>.+)\nTechnical Contact Country:\s*(?P<country>.+)\nTechnical Contact Country Code:\s*(?P<country_code>.+)\nTechnical Contact Phone Number:\s*(?P<phone>.+)\nTechnical Contact Email:\s*(?P<email>.+)\n",
    # .CO Internet
    "Tech Contact: (?P<handle>.+)\nTech Organization: (?P<organization>.+)\nTech Name: (?P<name>.+)\nTech Street: (?P<street>.+)\nTech City: (?P<city>.+)\nTech Postal Code: (?P<postalcode>.+)\nTech State: (?P<state>.+)\nTech Country: (?P<country>.+)\nTech Phone: (?P<phone>.*)\nTech Phone Ext: (?P<phone_ext>.*)\nTech Fax: (?P<fax>.*)\nTech Fax Ext: (?P<fax_ext>.*)\nTech Email: (?P<email>.*)\n",
    # Key-Systems GmbH
    "(?:Tech ID:[ ]*(?P<handle>.*)\n)?Tech[ ]*Name:[ ]*(?P<name>.*)\n(?:Tech[ ]*Organization:[ ]*(?P<organization>.*)\n)?Tech[ ]*Street:[ ]*(?P<street1>.+)\n(?:Tech[ ]*Street:[ ]*(?P<street2>.+)\n)?(?:Tech[ ]*Street:[ ]*(?P<street3>.+)\n)?Tech[ ]*City:[ ]*(?P<city>.+)\nTech[ ]*State(?:\/Province)?:[ ]*(?P<state>.*)\nTech[ ]*Postal[ ]*Code:[ ]*(?P<postalcode>.+)\nTech[ ]*Country:[ ]*(?P<country>.+)\n(?:Tech[ ]*Phone:[ ]*(?P<phone>.*)\n)?(?:Tech[ ]*Phone[ ]*Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Tech[ ]*Fax:[ ]*(?P<fax>.*)\n)?(?:Tech[ ]*Fax[ ]*Ext:\s*?(?P<fax_ext>.*)\n)?(?:Tech[ ]*Email:[ ]*(?P<email>.+)\n)?",
    # WildWestDomains, GoDaddy, Namecheap/eNom, Ascio, Musedoma (.museum), EuroDNS, nic.ps
    "Technical Contact\n(?:    (?P<organization>.+)\n)?    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n",
    # internet.bs
    " Technical Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)",
    # Whois.com
    "tech-id:[ ]*(?P<handle>.*)\n(?:tech-organization:[ ]*(?P<organization>.*)\n)?tech-name:[ ]*(?P<name>.*)\ntech-street:[ ]*(?P<street>.*)\ntech-city:[ ]*(?P<city>.*)\ntech-zip:[ ]*(?P<postalcode>.*)\ntech-country:[ ]*(?P<country>.*)\n(?:tech-phone:[ ]*(?P<phone>.*)\n)?(?:tech-fax:[ ]*(?P<fax>.*)\n)?tech-email:[ ]*(?P<email>.*)",
    # InterNetworX
    "Technical Contact:\n tech_org: (?P<organization>.*)\n tech_name: (?P<name>.*)\n tech_email: (?P<email>.*)\n tech_address: (?P<address>.*)\n tech_city: (?P<city>.*)\n tech_state: (?P<state>.*)\n tech_zip: (?P<postalcode>.*)\n tech_country: (?P<country>.*)\n tech_phone: (?P<phone>.*)",
    # Bellnames
    "Technical contact:\n(?P<name>[\S\s]+)\n(?P<street>.+)\n(?P<postalcode>[A-Z0-9-]+)\s+(?P<city>.+)\n(?P<country>.+)\n\n",
    # nic.ch
    "Tech Contact ID:[ ]*(?P<handle>.+)\nTech Contact Name:[ ]*(?P<name>.+)",  # .au
    "Technical Contact ID:(?P<handle>.*)\nTechnical Contact Name:(?P<name>.*)\n(?:Technical Contact Organization:(?P<organization>.*)\n)?Technical Contact Address1:(?P<street1>.*)\n(?:Technical Contact Address2:(?P<street2>.*)\n)?(?:Technical Contact Address3:(?P<street3>.*)\n)?Technical Contact City:(?P<city>.*)\n(?:Technical Contact State/Province:(?P<state>.*)\n)?(?:Technical Contact Postal Code:(?P<postalcode>.*)\n)?Technical Contact Country:(?P<country>.*)\nTechnical Contact Country Code:.*\nTechnical Contact Phone Number:(?P<phone>.*)\n(?:Technical Contact Facsimile Number:(?P<facsimile>.*)\n)?Technical Contact Email:(?P<email>.*)",
    # .US, .biz (NeuStar), .buzz, .moe (Interlink Co. Ltd.)
    "Technical Contacts\n  Name:             (?P<name>.+)\n(?:  Organization:     (?P<organization>.+)\n)?  ContactID:        (?P<handle>.+)\n(?:  Address:          (?P<street1>.+)\n(?:                    (?P<street2>.+)\n(?:                    (?P<street3>.+)\n)?)?                    (?P<city>.+)\n                    (?P<postalcode>.+)\n                    (?P<state>.+)\n                    (?P<country>.+)\n)?(?:  Created:          (?P<creationdate>.+)\n)?(?:  Last Update:      (?P<changedate>.+)\n)?",
    # nic.it  //  NOTE: Why does this say 'Contacts'? Can it have multiple?
    "Tech Name[.]* (?P<name>.*)\n  Tech Address[.]* (?P<street1>.*)\n  Tech Address[.]* (?P<street2>.*)\n(?:  Tech Address[.]* (?P<street3>.*)\n)?  Tech Address[.]* (?P<city>.*)\n  Tech Address[.]* (?P<postalcode>.*)\n  Tech Address[.]* (?P<state>.*)\n  Tech Address[.]* (?P<country>.*)\n  Tech Email[.]* (?P<email>.*)\n  Tech Phone[.]* (?P<phone>.*)\n  Tech Fax[.]* (?P<fax>.*)",
    # Melbourne IT
    "Technical contact:\n(?:  (?P<organization>.+)\n)?  (?P<name>.+)\n  (?P<email>.+)\n  (?P<street>.+)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n  Phone: (?P<phone>.*)\n  Fax: (?P<fax>.*)\n",
    # Fabulous.com
    "tech-c-name:\s*(?P<name>.+)\ntech-c-type:\s*(?P<type>.+)\ntech-c-address:\s*(?P<street>.+)\ntech-c-postcode:\s*(?P<postalcode>.+)\ntech-c-city:\s*(?P<city>.+)\ntech-c-country:\s*(?P<country>.+)\n(?:tech-c-phone:\s*(?P<phone>.+)\n)?(?:tech-c-email:\s*(?P<email>.+)\n)?",
    # Hetzner
    "Admin Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n",
    # GAL Communication
    "   Technical contact:\n      (?P<name>.+)\n      (?P<organization>.*)\n      (?P<street>.+)\n      (?P<city>.+) (?P<state>\S+),[ ]+(?P<postalcode>.+)\n      (?P<country>.+)\n      (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)",
    # .am
    "Technical:\n\s*Name:\s*(?P<name>.*)\n\s*Organisation:\s*(?P<organization>.*)\n\s*Language:.*\n\s*Phone:\s*(?P<phone>.*)\n\s*Fax:\s*(?P<fax>.*)\n\s*Email:\s*(?P<email>.*)\n",
    # EURid
    "\[Zone-C\]\nType: (?P<type>.+)\nName: (?P<name>.+)\n(Organisation: (?P<organization>.+)\n){0,1}(Address: (?P<street1>.+)\n){1}(Address: (?P<street2>.+)\n){0,1}(Address: (?P<street3>.+)\n){0,1}(Address: (?P<street4>.+)\n){0,1}PostalCode: (?P<postalcode>.+)\nCity: (?P<city>.+)\nCountryCode: (?P<country>[A-Za-z]{2})\nPhone: (?P<phone>.+)\nFax: (?P<fax>.+)\nEmail: (?P<email>.+)\n(Remarks: (?P<remark>.+)\n){0,1}Changed: (?P<changed>.+)",
    # DeNIC
    "Technical Contact:\n   Name:           (?P<name>.+)\n   City:           (?P<city>.+)\n   State:          (?P<state>.+)\n   Country:        (?P<country>.+)\n",
    # Akky (.com.mx)
    "Tech Contact: (?P<handle>.+)\n(?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?\n(?P<city>.+),? (?P<state>[A-Z]{2,3})(?: [A-Z0-9]+)?\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
    # .co.th, format 1
    "Tech Contact: (?P<handle>.+)\n(?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?\n(?P<city>.+), (?P<state>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
    # .co.th, format 2
    "Tech Contact: (?P<handle>.+)\n(?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?, (?P<city>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
    # .co.th, format 3
    "Tech Contact: (?P<handle>.+)\n(?P<street1>.+) (?P<city>[^\s]+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
    # .co.th, format 4
    "Tech Contact: (?P<handle>.+)\n(?P<organization>.+)\n(?P<street1>.+)\n(?P<district>.+) (?P<city>[^\s]+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
    # .co.th, format 5
    "Tech Contact: (?P<handle>.+)\n(?P<organization>.+)\n(?P<street1>.+)\n(?P<street2>.+)\n(?:(?P<street3>.+)\n)?(?P<city>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
    # .co.th, format 6
    "   Technical Contact:\n      (?P<name>.+)  (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)\n",
    # .com.tw (Western registrars)
    "Technical Contact Information:\n\n(?:Given name: (?P<firstname>.+)\n)?(?:Family name: (?P<lastname>.+)\n)?(?:Company name: (?P<organization>.+)\n)?Address: (?P<street>.+)\nCountry: (?P<country>.+)\nPhone: (?P<phone>.*)\nFax: (?P<fax>.*)\nEmail: (?P<email>.+)\n(?:Account Name: (?P<handle>.+)\n)?",
    # HKDNR (.hk)
    "TECH ID:(?P<handle>.+)\nTECH Name:(?P<name>.*)\n(?:TECH Organization:(?P<organization>.*)\n)?TECH Street1:(?P<street1>.+?)\n(?:TECH Street2:(?P<street2>.+?)\n(?:TECH Street3:(?P<street3>.+?)\n)?)?TECH City:(?P<city>.+)\nTECH State:(?P<state>.*)\nTECH Postal Code:(?P<postalcode>.+)\nTECH Country:(?P<country>[A-Z]+)\nTECH Phone:(?P<phone>.*?)\nTECH Fax:(?P<fax>.*)\nTECH Email:(?P<email>.+)\n",
    # Realtime Register
    "Tech Organization: (?P<organization>.*)\nTech State/Province: (?P<state>.+)\nTech Country: (?P<country>.+)",
    # EDU registrar
    "Technical Contact:\n\t \n\t(?P<organization>.*)\n\t(?P<street>.+)\n\t(?P<city>.+), (?P<state>.+) (?P<postalcode>.+)\n\t(?P<country>.+)\n\t(?P<phone>.*)\n\t(?P<email>.+)"

]

admin_contact_regexes = [
    "   Administrative Contact:[ ]*\n      (?P<organization>.*)\n      (?P<name>.*)\n      (?P<street>.*)\n      (?P<city>.*), (?P<state>.*) (?P<postalcode>.*)\n      (?P<country>.*)\n(?:      Phone: (?P<phone>.*)\n)?      Email: (?P<email>.*)\n",
    # Corporate Domains, Inc.
    "Administrative Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n",
    # OVH
    "(?:Admin ID:(?P<handle>.+)\n)?Admin Name:(?P<name>.*)\n(?:Admin Organization:(?P<organization>.*)\n)?Admin Street1?:(?P<street1>.*)\n(?:Admin Street2:(?P<street2>.*)\n)?(?:Admin Street3:(?P<street3>.*)\n)?Admin City:(?P<city>.*)\nAdmin State/Province:(?P<state>.*)\nAdmin Postal Code:(?P<postalcode>.*)\nAdmin Country:(?P<country>.*)\nAdmin Phone:(?P<phone>.*)\n(?:Admin Phone Ext.:(?P<phone_ext>.*)\n)?(?:Admin FAX:(?P<fax>.*)\n)?(?:Admin FAX Ext.:(?P<fax_ext>.*)\n)?Admin Email:(?P<email>.*)",
    # Public Interest Registry (.org), nic.pw, No-IP.com
    "Admin(?:istrative)? ID:(?P<handle>.+)\nAdmin(?:istrative)? Name:(?P<name>.*)\n(?:Admin(?:istrative)? Organization:(?P<organization>.*)\n)?Admin(?:istrative)? Address1?:(?P<street1>.*)\n(?:Admin(?:istrative)? Address2:(?P<street2>.*)\n)?(?:Admin(?:istrative)? Address3:(?P<street3>.*)\n)?Admin(?:istrative)? City:(?P<city>.*)\nAdmin(?:istrative)? State/Province:(?P<state>.*)\nAdmin(?:istrative)? Country/Economy:(?P<country>.*)\nAdmin(?:istrative)? Postal Code:(?P<postalcode>.*)\nAdmin(?:istrative)? Phone:(?P<phone>.*)\n(?:Admin(?:istrative)? Phone Ext.:(?P<phone_ext>.*)\n)?(?:Admin(?:istrative)? FAX:(?P<fax>.*)\n)?(?:Admin(?:istrative)? FAX Ext.:(?P<fax_ext>.*)\n)?Admin(?:istrative)? E-mail:(?P<email>.*)",
    # .ME, DotAsia
    "Administrative Contact ID:\s*(?P<handle>.+)\nAdministrative Contact Name:\s*(?P<name>.+)\nAdministrative Contact Organization:\s*(?P<organization>.*)\nAdministrative Contact Address1:\s*(?P<street1>.+)\nAdministrative Contact Address2:\s*(?P<street2>.*)\nAdministrative Contact City:\s*(?P<city>.+)\nAdministrative Contact State/Province:\s*(?P<state>.+)\nAdministrative Contact Postal Code:\s*(?P<postalcode>.+)\nAdministrative Contact Country:\s*(?P<country>.+)\nAdministrative Contact Country Code:\s*(?P<country_code>.+)\nAdministrative Contact Phone Number:\s*(?P<phone>.+)\nAdministrative Contact Email:\s*(?P<email>.+)\n",
    # .CO Internet
    "Admin Contact: (?P<handle>.+)\nAdmin Organization: (?P<organization>.+)\nAdmin Name: (?P<name>.+)\nAdmin Street: (?P<street>.+)\nAdmin City: (?P<city>.+)\nAdmin State: (?P<state>.+)\nAdmin Postal Code: (?P<postalcode>.+)\nAdmin Country: (?P<country>.+)\nAdmin Phone: (?P<phone>.*)\nAdmin Phone Ext: (?P<phone_ext>.*)\nAdmin Fax: (?P<fax>.*)\nAdmin Fax Ext: (?P<fax_ext>.*)\nAdmin Email: (?P<email>.*)\n",
    # Key-Systems GmbH
    "(?:Admin ID:[ ]*(?P<handle>.*)\n)?Admin[ ]*Name:[ ]*(?P<name>.*)\n(?:Admin[ ]*Organization:[ ]*(?P<organization>.*)\n)?Admin[ ]*Street:[ ]*(?P<street1>.+)\n(?:Admin[ ]*Street:[ ]*(?P<street2>.+)\n)?(?:Admin[ ]*Street:[ ]*(?P<street3>.+)\n)?Admin[ ]*City:[ ]*(?P<city>.+)\nAdmin[ ]*State(?:\/Province)?:[ ]*(?P<state>.*)\nAdmin[ ]*Postal[ ]*Code:[ ]*(?P<postalcode>.+)\nAdmin[ ]*Country:[ ]*(?P<country>.+)\n(?:Admin[ ]*Phone:[ ]*(?P<phone>.*)\n)?(?:Admin[ ]*Phone[ ]*Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Admin[ ]*Fax:[ ]*(?P<fax>.*)\n)?(?:Admin[ ]*Fax[ ]*Ext:\s*?(?P<fax_ext>.*)\n)?(?:Admin[ ]*Email:[ ]*(?P<email>.+)\n)?",
    # WildWestDomains, GoDaddy, Namecheap/eNom, Ascio, Musedoma (.museum), EuroDNS, nic.ps
    "Administrative Contact\n(?:    (?P<organization>.+)\n)?    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n",
    # internet.bs
    " Administrative Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)",
    # Whois.com
    "admin-id:[ ]*(?P<handle>.*)\n(?:admin-organization:[ ]*(?P<organization>.*)\n)?admin-name:[ ]*(?P<name>.*)\nadmin-street:[ ]*(?P<street>.*)\nadmin-city:[ ]*(?P<city>.*)\nadmin-zip:[ ]*(?P<postalcode>.*)\nadmin-country:[ ]*(?P<country>.*)\n(?:admin-phone:[ ]*(?P<phone>.*)\n)?(?:admin-fax:[ ]*(?P<fax>.*)\n)?admin-email:[ ]*(?P<email>.*)",
    # InterNetworX
    "Administrative Contact:\n admin_org: (?P<organization>.*)\n admin_name: (?P<name>.*)\n admin_email: (?P<email>.*)\n admin_address: (?P<address>.*)\n admin_city: (?P<city>.*)\n admin_state: (?P<state>.*)\n admin_zip: (?P<postalcode>.*)\n admin_country: (?P<country>.*)\n admin_phone: (?P<phone>.*)",
    # Bellnames
    "Administrative Contact ID:(?P<handle>.*)\nAdministrative Contact Name:(?P<name>.*)\n(?:Administrative Contact Organization:(?P<organization>.*)\n)?Administrative Contact Address1:(?P<street1>.*)\n(?:Administrative Contact Address2:(?P<street2>.*)\n)?(?:Administrative Contact Address3:(?P<street3>.*)\n)?Administrative Contact City:(?P<city>.*)\n(?:Administrative Contact State/Province:(?P<state>.*)\n)?(?:Administrative Contact Postal Code:(?P<postalcode>.*)\n)?Administrative Contact Country:(?P<country>.*)\nAdministrative Contact Country Code:.*\nAdministrative Contact Phone Number:(?P<phone>.*)\n(?:Administrative Contact Facsimile Number:(?P<facsimile>.*)\n)?Administrative Contact Email:(?P<email>.*)",
    # .US, .biz (NeuStar), .buzz, .moe (Interlink Co. Ltd.)
    "Admin Contact\n  Name:             (?P<name>.+)\n(?:  Organization:     (?P<organization>.+)\n)?  ContactID:        (?P<handle>.+)\n(?:  Address:          (?P<street1>.+)\n(?:                    (?P<street2>.+)\n(?:                    (?P<street3>.+)\n)?)?                    (?P<city>.+)\n                    (?P<postalcode>.+)\n                    (?P<state>.+)\n                    (?P<country>.+)\n)?(?:  Created:          (?P<creationdate>.+)\n)?(?:  Last Update:      (?P<changedate>.+)\n)?",
    # nic.it
    "Admin Name[.]* (?P<name>.*)\n  Admin Address[.]* (?P<street1>.*)\n  Admin Address[.]* (?P<street2>.*)\n(?:  Admin Address[.]* (?P<street3>.*)\n)?  Admin Address[.]* (?P<city>.*)\n  Admin Address[.]* (?P<postalcode>.*)\n  Admin Address[.]* (?P<state>.*)\n  Admin Address[.]* (?P<country>.*)\n  Admin Email[.]* (?P<email>.*)\n  Admin Phone[.]* (?P<phone>.*)\n  Admin Fax[.]* (?P<fax>.*)",
    # Melbourne IT
    "Administrative contact:\n(?:  (?P<organization>.+)\n)?  (?P<name>.+)\n  (?P<email>.+)\n  (?P<street>.+)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n  Phone: (?P<phone>.*)\n  Fax: (?P<fax>.*)\n",
    # Fabulous.com
    "admin-c-name:\s*(?P<name>.+)\nadmin-c-type:\s*(?P<type>.+)\nadmin-c-address:\s*(?P<street>.+)\nadmin-c-postcode:\s*(?P<postalcode>.+)\nadmin-c-city:\s*(?P<city>.+)\nadmin-c-country:\s*(?P<country>.+)\n(?:admin-c-phone:\s*(?P<phone>.+)\n)?(?:admin-c-email:\s*(?P<email>.+)\n)?",
    # Hetzner
    "Tech Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n",
    # GAL Communication
    "   Administrative contact:\n      (?P<name>.+)\n      (?P<organization>.*)\n      (?P<street>.+)\n      (?P<city>.+) (?P<state>\S+),[ ]+(?P<postalcode>.+)\n      (?P<country>.+)\n      (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)",
    # .am
    "Administrative Contact:\n   Name:           (?P<name>.+)\n   City:           (?P<city>.+)\n   State:          (?P<state>.+)\n   Country:        (?P<country>.+)\n",
    # Akky (.com.mx)
    "\[Tech-C\]\nType: (?P<type>.+)\nName: (?P<name>.+)\n(Organisation: (?P<organization>.+)\n){0,1}(Address: (?P<street1>.+)\n){1}(Address: (?P<street2>.+)\n){0,1}(Address: (?P<street3>.+)\n){0,1}(Address: (?P<street4>.+)\n){0,1}PostalCode: (?P<postalcode>.+)\nCity: (?P<city>.+)\nCountryCode: (?P<country>[A-Za-z]{2})\nPhone: (?P<phone>.+)\nFax: (?P<fax>.+)\nEmail: (?P<email>.+)\n(Remarks: (?P<remark>.+)\n){0,1}Changed: (?P<changed>.+)",
    # DeNIC
    "   Administrative Contact:\n      (?P<name>.+)  (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)\n",
    # .com.tw (Western registrars)
    "Administrative Contact Information:\n\n(?:Given name: (?P<firstname>.+)\n)?(?:Family name: (?P<lastname>.+)\n)?(?:Company name: (?P<organization>.+)\n)?Address: (?P<street>.+)\nCountry: (?P<country>.+)\nPhone: (?P<phone>.*)\nFax: (?P<fax>.*)\nEmail: (?P<email>.+)\n(?:Account Name: (?P<handle>.+)\n)?",
    # HKDNR (.hk)
    "ADMIN ID:(?P<handle>.+)\nADMIN Name:(?P<name>.*)\n(?:ADMIN Organization:(?P<organization>.*)\n)?ADMIN Street1:(?P<street1>.+?)\n(?:ADMIN Street2:(?P<street2>.+?)\n(?:ADMIN Street3:(?P<street3>.+?)\n)?)?ADMIN City:(?P<city>.+)\nADMIN State:(?P<state>.*)\nADMIN Postal Code:(?P<postalcode>.+)\nADMIN Country:(?P<country>[A-Z]+)\nADMIN Phone:(?P<phone>.*?)\nADMIN Fax:(?P<fax>.*)\nADMIN Email:(?P<email>.+)\n",
    # Realtime Register
    "Admin Organization: (?P<name>.*)\nAdmin State/Province: (?P<state>.+)\nAdmin Country: (?P<country>.+)\n",
    # EDU registrar
    "Administrative Contact:\n\t(?P<name>.*)\n\t(?P<organization>.*)\n\t(?P<street>.+)\n\t(?P<city>.*), (?P<state>.+) (?P<postalcode>.+)\n\t(?P<country>.+)\n\t(?P<phone>.*)\n\t(?P<email>.+)"
]

billing_contact_regexes = [
    "(?:Billing ID:(?P<handle>.+)\n)?Billing Name:(?P<name>.*)\nBilling Organization:(?P<organization>.*)\nBilling Street1:(?P<street1>.*)\n(?:Billing Street2:(?P<street2>.*)\n)?(?:Billing Street3:(?P<street3>.*)\n)?Billing City:(?P<city>.*)\nBilling State/Province:(?P<state>.*)\nBilling Postal Code:(?P<postalcode>.*)\nBilling Country:(?P<country>.*)\nBilling Phone:(?P<phone>.*)\n(?:Billing Phone Ext.:(?P<phone_ext>.*)\n)?(?:Billing FAX:(?P<fax>.*)\n)?(?:Billing FAX Ext.:(?P<fax_ext>.*)\n)?Billing Email:(?P<email>.*)",
    # nic.pw, No-IP.com
    "Billing ID:(?P<handle>.+)\nBilling Name:(?P<name>.*)\n(?:Billing Organization:(?P<organization>.*)\n)?Billing Address1?:(?P<street1>.*)\n(?:Billing Address2:(?P<street2>.*)\n)?(?:Billing Address3:(?P<street3>.*)\n)?Billing City:(?P<city>.*)\nBilling State/Province:(?P<state>.*)\nBilling Country/Economy:(?P<country>.*)\nBilling Postal Code:(?P<postalcode>.*)\nBilling Phone:(?P<phone>.*)\n(?:Billing Phone Ext.:(?P<phone_ext>.*)\n)?(?:Billing FAX:(?P<fax>.*)\n)?(?:Billing FAX Ext.:(?P<fax_ext>.*)\n)?Billing E-mail:(?P<email>.*)",
    # DotAsia
    "Billing Contact ID:\s*(?P<handle>.+)\nBilling Contact Name:\s*(?P<name>.+)\nBilling Contact Organization:\s*(?P<organization>.*)\nBilling Contact Address1:\s*(?P<street1>.+)\nBilling Contact Address2:\s*(?P<street2>.*)\nBilling Contact City:\s*(?P<city>.+)\nBilling Contact State/Province:\s*(?P<state>.+)\nBilling Contact Postal Code:\s*(?P<postalcode>.+)\nBilling Contact Country:\s*(?P<country>.+)\nBilling Contact Country Code:\s*(?P<country_code>.+)\nBilling Contact Phone Number:\s*(?P<phone>.+)\nBilling Contact Email:\s*(?P<email>.+)\n",
    # .CO Internet
    "Billing Contact: (?P<handle>.+)\nBilling Organization: (?P<organization>.+)\nBilling Name: (?P<name>.+)\nBilling Street: (?P<street>.+)\nBilling City: (?P<city>.+)\nBilling Postal Code: (?P<postalcode>.+)\nBilling State: (?P<state>.+)\nBilling Country: (?P<country>.+)\nBilling Phone: (?P<phone>.*)\nBilling Phone Ext: (?P<phone_ext>.*)\nBilling Fax: (?P<fax>.*)\nBilling Fax Ext: (?P<fax_ext>.*)\nBilling Email: (?P<email>.*)\n",
    # Key-Systems GmbH
    "(?:Billing ID:[ ]*(?P<handle>.*)\n)?Billing[ ]*Name:[ ]*(?P<name>.*)\n(?:Billing[ ]*Organization:[ ]*(?P<organization>.*)\n)?Billing[ ]*Street:[ ]*(?P<street1>.+)\n(?:Billing[ ]*Street:[ ]*(?P<street2>.+)\n)?Billing[ ]*City:[ ]*(?P<city>.+)\nBilling[ ]*State\/Province:[ ]*(?P<state>.+)\nBilling[ ]*Postal[ ]*Code:[ ]*(?P<postalcode>.+)\nBilling[ ]*Country:[ ]*(?P<country>.+)\n(?:Billing[ ]*Phone:[ ]*(?P<phone>.*)\n)?(?:Billing[ ]*Phone[ ]*Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Billing[ ]*Fax:[ ]*(?P<fax>.*)\n)?(?:Billing[ ]*Fax[ ]*Ext:\s*?(?P<fax_ext>.*)\n)?(?:Billing[ ]*Email:[ ]*(?P<email>.+)\n)?",
    # Musedoma (.museum)
    "Billing Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n",
    # OVH
    " Billing Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)",
    # Whois.com
    "billing-id:[ ]*(?P<handle>.*)\n(?:billing-organization:[ ]*(?P<organization>.*)\n)?billing-name:[ ]*(?P<name>.*)\nbilling-street:[ ]*(?P<street>.*)\nbilling-city:[ ]*(?P<city>.*)\nbilling-zip:[ ]*(?P<postalcode>.*)\nbilling-country:[ ]*(?P<country>.*)\n(?:billing-phone:[ ]*(?P<phone>.*)\n)?(?:billing-fax:[ ]*(?P<fax>.*)\n)?billing-email:[ ]*(?P<email>.*)",
    # InterNetworX
    "Billing Contact:\n bill_org: (?P<organization>.*)\n bill_name: (?P<name>.*)\n bill_email: (?P<email>.*)\n bill_address: (?P<address>.*)\n bill_city: (?P<city>.*)\n bill_state: (?P<state>.*)\n bill_zip: (?P<postalcode>.*)\n bill_country: (?P<country>.*)\n bill_phone: (?P<phone>.*)",
    # Bellnames
    "Billing Contact ID:(?P<handle>.*)\nBilling Contact Name:(?P<name>.*)\n(?:Billing Contact Organization:(?P<organization>.*)\n)?Billing Contact Address1:(?P<street1>.*)\n(?:Billing Contact Address2:(?P<street2>.*)\n)?(?:Billing Contact Address3:(?P<street3>.*)\n)?Billing Contact City:(?P<city>.*)\n(?:Billing Contact State/Province:(?P<state>.*)\n)?(?:Billing Contact Postal Code:(?P<postalcode>.*)\n)?Billing Contact Country:(?P<country>.*)\nBilling Contact Country Code:.*\nBilling Contact Phone Number:(?P<phone>.*)\n(?:Billing Contact Facsimile Number:(?P<facsimile>.*)\n)?Billing Contact Email:(?P<email>.*)",
    # .US, .biz (NeuStar), .buzz, .moe (Interlink Co. Ltd.)
    "Billing contact:\n(?:  (?P<organization>.+)\n)?  (?P<name>.+)\n  (?P<email>.+)\n  (?P<street>.+)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n  Phone: (?P<phone>.*)\n  Fax: (?P<fax>.*)\n",
    # Fabulous.com
    "Billing Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n",
    # GAL Communication
    "Billing Contact:\n   Name:           (?P<name>.+)\n   City:           (?P<city>.+)\n   State:          (?P<state>.+)\n   Country:        (?P<country>.+)\n",
    # Akky (.com.mx)
    "BILLING ID:(?P<handle>.+)\nBILLING Name:(?P<name>.*)\n(?:BILLING Organization:(?P<organization>.*)\n)?BILLING Street1:(?P<street1>.+?)\n(?:BILLING Street2:(?P<street2>.+?)\n(?:BILLING Street3:(?P<street3>.+?)\n)?)?BILLING City:(?P<city>.+)\nBILLING State:(?P<state>.*)\nBILLING Postal Code:(?P<postalcode>.+)\nBILLING Country:(?P<country>[A-Z]+)\nBILLING Phone:(?P<phone>.*?)\nBILLING Fax:(?P<fax>.*)\nBILLING Email:(?P<email>.+)\n",
    # Realtime Register
]

# Some registries use NIC handle references instead of directly listing contacts...
nic_contact_references = {
    "registrant": [
        "registrant:\s*(?P<handle>.+)",  # nic.at
        "owner-contact:\s*(?P<handle>.+)",  # LCN.com
        "holder-c:\s*(?P<handle>.+)",  # AFNIC
        "holder:\s*(?P<handle>.+)",
        # iis.se (they apparently want to be difficult, and won't give you contact info for the handle over their WHOIS service)
    ],
    "tech": [
        "tech-c:\s*(?P<handle>.+)",  # nic.at, AFNIC, iis.se
        "technical-contact:\s*(?P<handle>.+)",  # LCN.com
        "n\. \[Technical Contact\]          (?P<handle>.+)\n",  # .co.jp
    ],
    "admin": [
        "admin-c:\s*(?P<handle>.+)",  # nic.at, AFNIC, iis.se
        "admin-contact:\s*(?P<handle>.+)",  # LCN.com
        "m\. \[Administrative Contact\]     (?P<handle>.+)\n",  # .co.jp
    ],
    "billing": [
        "billing-c:\s*(?P<handle>.+)",  # iis.se
        "billing-contact:\s*(?P<handle>.+)",  # LCN.com
    ]
}

# Why do the below? The below is meant to handle with an edge case (issue #2) where a partial match followed
# by a failure, for a regex containing the \s*.+ pattern, would send the regex module on a wild goose hunt for
# matching positions. The workaround is to use \S.* instead of .+, but in the interest of keeping the regexes
# consistent and compact, it's more practical to do this (predictable) conversion on runtime.
# FIXME: This breaks on NIC contact regex for nic.at. Why?
registrant_regexes = [preprocess_regex(regex) for regex in registrant_regexes]
tech_contact_regexes = [preprocess_regex(regex) for regex in tech_contact_regexes]
admin_contact_regexes = [preprocess_regex(regex) for regex in admin_contact_regexes]
billing_contact_regexes = [preprocess_regex(regex) for regex in billing_contact_regexes]

nic_contact_regexes = [
    "personname:\s*(?P<name>.+)\norganization:\s*(?P<organization>.+)\nstreet address:\s*(?P<street>.+)\npostal code:\s*(?P<postalcode>.+)\ncity:\s*(?P<city>.+)\ncountry:\s*(?P<country>.+)\n(?:phone:\s*(?P<phone>.+)\n)?(?:fax-no:\s*(?P<fax>.+)\n)?(?:e-mail:\s*(?P<email>.+)\n)?nic-hdl:\s*(?P<handle>.+)\nchanged:\s*(?P<changedate>.+)",
    # nic.at
    "contact-handle:[ ]*(?P<handle>.+)\ncontact:[ ]*(?P<name>.+)\n(?:organisation:[ ]*(?P<organization>.+)\n)?address:[ ]*(?P<street1>.+)\n(?:address:[ ]*(?P<street2>.+)\n)?(?:address:[ ]*(?P<street3>.+)\n)?(?:address:[ ]*(?P<street4>.+)\n)?address:[ ]*(?P<city>.+)\naddress:[ ]*(?P<state>.+)\naddress:[ ]*(?P<postalcode>.+)\naddress:[ ]*(?P<country>.+)\n(?:phone:[ ]*(?P<phone>.+)\n)?(?:fax:[ ]*(?P<fax>.+)\n)?(?:email:[ ]*(?P<email>.+)\n)?",
    # LCN.com
    "Contact Information:\na\. \[JPNIC Handle\]               (?P<handle>.+)\nc\. \[Last, First\]                (?P<lastname>.+), (?P<firstname>.+)\nd\. \[E-Mail\]                     (?P<email>.+)\ng\. \[Organization\]               (?P<organization>.+)\nl\. \[Division\]                   (?P<division>.+)\nn\. \[Title\]                      (?P<title>.+)\no\. \[TEL\]                        (?P<phone>.+)\np\. \[FAX\]                        (?P<fax>.+)\ny\. \[Reply Mail\]                 .*\n\[Last Update\]                   (?P<changedate>.+) \(JST\)\n",
    # JPRS .co.jp contact handle lookup
    "person:\s*(?P<name>.+)\nnic-hdl:\s*(?P<handle>.+)\n",  # .ie
    "nic-hdl:\s+(?P<handle>.+)\nperson:\s+(?P<name>.+)\n(?:e-mail:\s+(?P<email>.+)\n)?(?:address:\s+(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?, (?P<city>.+), (?P<state>.+), (?P<country>.+)\n)?(?:phone:\s+(?P<phone>.+)\n)?(?:fax-no:\s+(?P<fax>.+)\n)?",
    # nic.ir, individual  - this is a nasty one.
    "nic-hdl:\s+(?P<handle>.+)\norg:\s+(?P<organization>.+)\n(?:e-mail:\s+(?P<email>.+)\n)?(?:address:\s+(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?, (?P<city>.+), (?P<state>.+), (?P<country>.+)\n)?(?:phone:\s+(?P<phone>.+)\n)?(?:fax-no:\s+(?P<fax>.+)\n)?",
    # nic.ir, organization
    "nic-hdl:[ ]*(?P<handle>.*?)\ntype:[ ]*(?P<type>.*)\ncontact:[ ]*(?P<name>.*?)\n(?:.*\n)*?(?:(?:address:[ ]*(?P<street1>.*?)\n)(?:address:[ ]*(?P<street2>.*?)\n)?(?:address:[ ]*(?P<street3>.*)\n)?(?:address:[ ]*(?P<street4>.*)\n)?(?:country:[ ]*(?P<country>.*?)\n)?)(?:phone:[ ]*(?P<phone>.*?)\n)?(?:fax-no:[ ]*(?P<fax>.*?)\n)?(?:.*\n)*?(?:e-mail:[ ]*(?P<email>.*?)\n)?registrar:[ ]*(?P<registrar>.*?)\n(?:.*?\n)*?(?:changed:[ ]*(?P<changedate>.*?)\n)?"
]

organization_regexes = (
    r"\sltd\.?($|\s)",
    r"\sco\.?($|\s)",
    r"\scorp\.?($|\s)",
    r"\sinc\.?($|\s)",
    r"\ss\.?p\.?a\.?($|\s)",
    r"\ss\.?(c\.?)?r\.?l\.?($|\s)",
    r"\ss\.?a\.?s\.?($|\s)",
    r"\sa\.?g\.?($|\s)",
    r"\sn\.?v\.?($|\s)",
    r"\sb\.?v\.?($|\s)",
    r"\sp\.?t\.?y\.?($|\s)",
    r"\sp\.?l\.?c\.?($|\s)",
    r"\sv\.?o\.?f\.?($|\s)",
    r"\sb\.?v\.?b\.?a\.?($|\s)",
    r"\sg\.?m\.?b\.?h\.?($|\s)",
    r"\ss\.?a\.?r\.?l\.?($|\s)",
)

grammar["_data"]["id"] = precompile_regexes(grammar["_data"]["id"], re.IGNORECASE)  # type: ignore
grammar["_data"]["status"] = precompile_regexes(grammar["_data"]["status"], re.IGNORECASE)  # type: ignore
grammar["_data"]["creation_date"] = precompile_regexes(grammar["_data"]["creation_date"], re.IGNORECASE)  # type: ignore
grammar["_data"]["expiration_date"] = precompile_regexes(grammar["_data"]["expiration_date"],  # type: ignore
                                                         re.IGNORECASE)
grammar["_data"]["updated_date"] = precompile_regexes(grammar["_data"]["updated_date"], re.IGNORECASE)  # type: ignore
grammar["_data"]["registrar"] = precompile_regexes(grammar["_data"]["registrar"], re.IGNORECASE)  # type: ignore
grammar["_data"]["whois_server"] = precompile_regexes(grammar["_data"]["whois_server"], re.IGNORECASE)  # type: ignore
grammar["_data"]["nameservers"] = precompile_regexes(grammar["_data"]["nameservers"], re.IGNORECASE)  # type: ignore
grammar["_data"]["emails"] = precompile_regexes(grammar["_data"]["emails"], re.IGNORECASE)  # type: ignore

grammar["_dateformats"] = precompile_regexes(grammar["_dateformats"], re.IGNORECASE)

registrant_regexes = precompile_regexes(registrant_regexes)
tech_contact_regexes = precompile_regexes(tech_contact_regexes)
billing_contact_regexes = precompile_regexes(billing_contact_regexes)
admin_contact_regexes = precompile_regexes(admin_contact_regexes)
nic_contact_regexes = precompile_regexes(nic_contact_regexes)
organization_regexes = precompile_regexes(organization_regexes, re.IGNORECASE)

nic_contact_references["registrant"] = precompile_regexes(nic_contact_references["registrant"])
nic_contact_references["tech"] = precompile_regexes(nic_contact_references["tech"])
nic_contact_references["admin"] = precompile_regexes(nic_contact_references["admin"])
nic_contact_references["billing"] = precompile_regexes(nic_contact_references["billing"])

if sys.version_info < (3, 0):
    def is_string(data):
        """Test for string with support for python 2."""
        return isinstance(data, str)
else:
    def is_string(data):
        """Test for string with support for python 3."""
        return isinstance(data, str)


class InvalidDateHandler:
    """
        A class to represent an anparseble date by the datetime module.
        mainly for dates containing day, year, or month with an unvalid value of 0.
        """

    def __init__(self, year, month, day):
        self.year = year
        self.month = month
        self.day = day

    def strftime(self, *args):
        if self.year == 2000:
            return f'{self.day}-{self.month}-{0}'
        return f'{self.day}-{self.month}-{self.year}'


def parse_raw_whois(raw_data, normalized=None, never_query_handles=True, handle_server=""):
    normalized = normalized or []
    data = {}  # type: dict

    raw_data = [segment.replace("\r", "") for segment in raw_data]  # Carriage returns are the devil

    for segment in raw_data:
        for rule_key, rule_regexes in list(grammar['_data'].items()):  # type: ignore
            if (rule_key in data) == False:
                for line in segment.splitlines():
                    for regex in rule_regexes:
                        result = re.search(regex, line)

                        if result is not None:
                            val = result.group("val").strip()
                            if val != "":
                                try:
                                    data[rule_key].append(val)
                                except KeyError as e:
                                    data[rule_key] = [val]

        # Whois.com is a bit special... Fabulous.com also seems to use this format. As do some others.
        match = re.search("^\s?Name\s?[Ss]ervers:?\s*\n((?:\s*.+\n)+?\s?)\n", segment, re.MULTILINE)
        if match is not None:
            chunk = match.group(1)
            for match in re.findall("[ ]*(.+)\n", chunk):
                if match.strip() != "":  # type: ignore
                    if not re.match("^[a-zA-Z]+:", match):  # type: ignore
                        try:
                            data["nameservers"].append(match.strip())  # type: ignore
                        except KeyError as e:
                            data["nameservers"] = [match.strip()]  # type: ignore
        # Nominet also needs some special attention
        match = re.search("    Registrar:\n        (.+)\n", segment)
        if match is not None:
            data["registrar"] = [match.group(1).strip()]
        match = re.search("    Registration status:\n        (.+)\n", segment)
        if match is not None:
            data["status"] = [match.group(1).strip()]
        match = re.search("    Name servers:\n([\s\S]*?\n)\n", segment)
        if match is not None:
            chunk = match.group(1)
            for match in re.findall("        (.+)\n", chunk):
                match = match.split()[0]  # type: ignore
                try:
                    data["nameservers"].append(match.strip())  # type: ignore
                except KeyError as e:
                    data["nameservers"] = [match.strip()]  # type: ignore
        # janet (.ac.uk) is kinda like Nominet, but also kinda not
        match = re.search("Registered By:\n\t(.+)\n", segment)
        if match is not None:
            data["registrar"] = [match.group(1).strip()]
        match = re.search("Entry created:\n\t(.+)\n", segment)
        if match is not None:
            data["creation_date"] = [match.group(1).strip()]
        match = re.search("Renewal date:\n\t(.+)\n", segment)
        if match is not None:
            data["expiration_date"] = [match.group(1).strip()]
        match = re.search("Entry updated:\n\t(.+)\n", segment)
        if match is not None:
            data["updated_date"] = [match.group(1).strip()]
        match = re.search("Servers:([\s\S]*?\n)\n", segment)
        if match is not None:
            chunk = match.group(1)
            for match in re.findall("\t(.+)\n", chunk):
                match = match.split()[0]  # type: ignore
                try:
                    data["nameservers"].append(match.strip())  # type: ignore
                except KeyError as e:
                    data["nameservers"] = [match.strip()]  # type: ignore
        # .am plays the same game
        match = re.search("   DNS servers:([\s\S]*?\n)\n", segment)
        if match is not None:
            chunk = match.group(1)
            for match in re.findall("      (.+)\n", chunk):
                match = match.split()[0]  # type: ignore
                try:
                    data["nameservers"].append(match.strip())  # type: ignore
                except KeyError as e:
                    data["nameservers"] = [match.strip()]  # type: ignore
        # SIDN isn't very standard either. And EURid uses a similar format.
        match = re.search("Registrar:\n\s+(?:Name:\s*)?(\S.*)", segment)
        if match is not None:
            # Set default value -> https://docs.python.org/3/library/stdtypes.html#dict.setdefault
            data.setdefault("registrar", []).insert(0, match.group(1).strip())
        match = re.search("(?:Domain nameservers|Name servers):([\s\S]*?\n)\n", segment)
        if match is not None:
            chunk = match.group(1)
            for match in re.findall("\s+?(.+)\n", chunk):
                if match.strip():  # type: ignore
                    match = match.split()[0]  # type: ignore
                    # Prevent nameserver aliases from being picked up.
                    if not match.startswith("[") and not match.endswith("]"):  # type: ignore
                        try:
                            data["nameservers"].append(match.strip())  # type: ignore
                        except KeyError as e:
                            data["nameservers"] = [match.strip()]  # type: ignore
        # The .ie WHOIS server puts ambiguous status information in an unhelpful order
        match = re.search('ren-status:\s*(.+)', segment)
        if match is not None:
            data["status"].insert(0, match.group(1).strip())
        # nic.it gives us the registrar in a multi-line format...
        match = re.search('Registrar\n  Organization:     (.+)\n', segment)
        if match is not None:
            data["registrar"] = [match.group(1).strip()]
        # HKDNR (.hk) provides a weird nameserver format with too much whitespace
        match = re.search("Name Servers Information:\n\n([\s\S]*?\n)\n", segment)
        if match is not None:
            chunk = match.group(1)
            for match in re.findall("(.+)\n", chunk):
                match = match.split()[0]  # type: ignore
                try:
                    data["nameservers"].append(match.strip())  # type: ignore
                except KeyError as e:
                    data["nameservers"] = [match.strip()]  # type: ignore
        # ... and again for TWNIC.
        match = re.search("   Domain servers in listed order:\n([\s\S]*?\n)\n", segment)
        if match is not None:
            chunk = match.group(1)
            for match in re.findall("      (.+)\n", chunk):
                match = match.split()[0]  # type: ignore
                try:
                    data["nameservers"].append(match.strip())  # type: ignore
                except KeyError as e:
                    data["nameservers"] = [match.strip()]  # type: ignore

    data["contacts"] = parse_registrants(raw_data, never_query_handles, handle_server)

    # Parse dates
    try:
        data['expiration_date'] = remove_duplicates(data['expiration_date'])
        data['expiration_date'] = parse_dates(data['expiration_date'])
    except KeyError as e:
        pass  # Not present

    try:
        data['creation_date'] = remove_duplicates(data['creation_date'])
        data['creation_date'] = parse_dates(data['creation_date'])
    except KeyError as e:
        pass  # Not present

    try:
        data['updated_date'] = remove_duplicates(data['updated_date'])
        data['updated_date'] = parse_dates(data['updated_date'])
    except KeyError as e:
        pass  # Not present

    try:
        data['nameservers'] = remove_suffixes(data['nameservers'])
        data['nameservers'] = remove_duplicates([ns.rstrip(".") for ns in data['nameservers']])
    except KeyError as e:
        pass  # Not present

    try:
        data['emails'] = remove_duplicates(data['emails'])
    except KeyError as e:
        pass  # Not present

    try:
        data['registrar'] = remove_duplicates(data['registrar'])
    except KeyError as e:
        pass  # Not present

    # Remove e-mail addresses if they are already listed for any of the contacts
    known_emails = []
    for contact in ("registrant", "tech", "admin", "billing"):
        if data["contacts"][contact] is not None:  # type: ignore
            try:
                known_emails.append(data["contacts"][contact]["email"])  # type: ignore
            except KeyError as e:
                pass  # No e-mail recorded for this contact...
    try:
        data['emails'] = [email for email in data["emails"] if email not in known_emails]
    except KeyError as e:
        pass  # Not present

    for key in list(data.keys()):
        if data[key] is None or len(data[key]) == 0:
            del data[key]

    data["raw"] = raw_data

    if normalized:
        data = normalize_data(data, normalized)

    return data


def normalize_data(data, normalized):
    for key in ("nameservers", "emails", "whois_server"):
        if key in data and data[key] is not None and (normalized == True or key in normalized):
            if is_string(data[key]):
                data[key] = data[key].lower()
            else:
                data[key] = [item.lower() for item in data[key]]

    for key, threshold in (("registrar", 4), ("status", 3)):
        if key == "registrar":
            ignore_nic = True
        else:
            ignore_nic = False
        if key in data and data[key] is not None and (normalized == True or key in normalized):
            if is_string(data[key]):
                data[key] = normalize_name(data[key], abbreviation_threshold=threshold, length_threshold=1,
                                           ignore_nic=ignore_nic)
            else:
                data[key] = [
                    normalize_name(item, abbreviation_threshold=threshold, length_threshold=1, ignore_nic=ignore_nic)
                    for item in data[key]]

    for contact_type, contact in list(data['contacts'].items()):
        if contact is not None:
            if 'country' in contact and contact['country'] in countries:
                contact['country'] = countries[contact['country']]
            if 'city' in contact and contact['city'] in airports:
                contact['city'] = airports[contact['city']]
            if 'country' in contact and 'state' in contact:
                for country, source in (("united states", states_us), ("australia", states_au), ("canada", states_ca)):
                    if country in contact["country"].lower() and contact["state"] in source:
                        contact["state"] = source[contact["state"]]

            for key in ("email",):
                if key in contact and contact[key] is not None and (normalized == True or key in normalized):
                    if is_string(contact[key]):
                        contact[key] = contact[key].lower()
                    else:
                        contact[key] = [item.lower() for item in contact[key]]

            for key in ("name", "street"):
                if key in contact and contact[key] is not None and (normalized == True or key in normalized):
                    contact[key] = normalize_name(contact[key], abbreviation_threshold=3)

            for key in ("city", "organization", "state", "country"):
                if key in contact and contact[key] is not None and (normalized == True or key in normalized):
                    contact[key] = normalize_name(contact[key], abbreviation_threshold=3, length_threshold=3)

            if "name" in contact and "organization" not in contact:
                lines = [x.strip() for x in contact["name"].splitlines()]
                new_lines = []
                for i, line in enumerate(lines):
                    for regex in organization_regexes:
                        if re.search(regex, line):
                            new_lines.append(line)
                            del lines[i]
                            break
                if len(lines) > 0:
                    contact["name"] = "\n".join(lines)
                else:
                    del contact["name"]

                if len(new_lines) > 0:
                    contact["organization"] = "\n".join(new_lines)

            if "street" in contact and "organization" not in contact:
                lines = [x.strip() for x in contact["street"].splitlines()]
                if len(lines) > 1:
                    for regex in organization_regexes:
                        if re.search(regex, lines[0]):
                            contact["organization"] = lines[0]
                            contact["street"] = "\n".join(lines[1:])
                            break

            for key in list(contact.keys()):
                try:
                    contact[key] = contact[key].strip(", ")
                    if contact[key] == "-" or contact[key].lower() == "n/a":
                        del contact[key]
                except AttributeError as e:
                    pass  # Not a string
    return data


def normalize_name(value, abbreviation_threshold=4, length_threshold=8, lowercase_domains=True, ignore_nic=False):
    normalized_lines = []
    for line in value.split("\n"):
        line = line.strip(",")  # Get rid of useless comma's
        if (line.isupper() or line.islower()) and len(line) >= length_threshold:
            # This line is likely not capitalized properly
            if ignore_nic == True and "nic" in line.lower():
                # This is a registrar name containing 'NIC' - it should probably be all-uppercase.
                line = line.upper()
            else:
                words = line.split()
                normalized_words = []
                if len(words) >= 1:
                    # First word
                    if len(words[0]) >= abbreviation_threshold and "." not in words[0]:
                        normalized_words.append(words[0].capitalize())
                    elif lowercase_domains and "." in words[0] and not words[0].endswith(".") and not words[
                            0].startswith("."):
                        normalized_words.append(words[0].lower())
                    else:
                        # Probably an abbreviation or domain, leave it alone
                        normalized_words.append(words[0])
                if len(words) >= 3:
                    # Words between the first and last
                    for word in words[1:-1]:
                        if len(word) >= abbreviation_threshold and "." not in word:
                            normalized_words.append(word.capitalize())
                        elif lowercase_domains and "." in word and not word.endswith(".") and not word.startswith("."):
                            normalized_words.append(word.lower())
                        else:
                            # Probably an abbreviation or domain, leave it alone
                            normalized_words.append(word)
                if len(words) >= 2:
                    # Last word
                    if len(words[-1]) >= abbreviation_threshold and "." not in words[-1]:
                        normalized_words.append(words[-1].capitalize())
                    elif lowercase_domains and "." in words[-1] and not words[-1].endswith(".") and not words[
                            -1].startswith("."):
                        normalized_words.append(words[-1].lower())
                    else:
                        # Probably an abbreviation or domain, leave it alone
                        normalized_words.append(words[-1])
                line = " ".join(normalized_words)
        normalized_lines.append(line)
    return "\n".join(normalized_lines)


def parse_dates(dates):
    global grammar
    parsed_dates: List[datetime | InvalidDateHandler] = []

    for date in dates:
        for rule in grammar['_dateformats']:  # type: ignore
            result = re.match(rule, date)

            if result is not None:
                try:
                    # These are always numeric. If they fail, there is no valid date present.
                    year = int(result.group("year"))
                    day = int(result.group("day"))

                    # Detect and correct shorthand year notation
                    if year < 60:
                        year += 2000
                    elif year < 100:
                        year += 1900

                    # This will require some more guesswork - some WHOIS servers present the name of the month
                    try:
                        month = int(result.group("month"))
                    except ValueError as e:
                        # Apparently not a number. Look up the corresponding number.
                        try:
                            month = grammar['_months'][result.group("month").lower()]  # type: ignore
                        except KeyError as e:
                            # Unknown month name, default to 0
                            month = 0

                    try:
                        hour = int(result.group("hour"))
                    except IndexError as e:
                        hour = 0
                    except TypeError as e:
                        hour = 0

                    try:
                        minute = int(result.group("minute"))
                    except IndexError as e:
                        minute = 0
                    except TypeError as e:
                        minute = 0

                    try:
                        second = int(result.group("second"))
                    except IndexError as e:
                        second = 0
                    except TypeError as e:
                        second = 0

                    break
                except ValueError as e:
                    # Something went horribly wrong, maybe there is no valid date present?
                    year = 0
                    month = 0
                    day = 0
                    hour = 0
                    minute = 0
                    second = 0
                    demisto.debug(f'{e}')
        try:
            if year > 0:
                if month > 12:
                    # We might have gotten the day and month the wrong way around, let's try it the other way around.
                    month, day = day, month
                if 0 in [year, month, day]:
                    parsed_dates.append(InvalidDateHandler(year=year, month=month, day=day))
                else:
                    parsed_dates.append(datetime(year, month, day, hour, minute, second))
        except UnboundLocalError as e:
            pass

    if len(parsed_dates) > 0:
        return parsed_dates
    else:
        return None


def remove_duplicates(data):
    cleaned_list = []  # type: ignore

    for entry in data:
        if entry not in cleaned_list:
            cleaned_list.append(entry)

    return cleaned_list


def remove_suffixes(data):
    # Removes everything before and after the first non-whitespace continuous string.
    # Used to get rid of IP suffixes for nameservers.
    cleaned_list = []

    for entry in data:
        cleaned_list.append(re.search("([^\s]+)\s*[\s]*", entry).group(1).lstrip())  # type: ignore

    return cleaned_list


def parse_registrants(data, never_query_handles=True, handle_server=""):
    registrant = None
    tech_contact = None
    billing_contact = None
    admin_contact = None

    for segment in data:
        for regex in registrant_regexes:
            match = re.search(regex, segment)
            if match is not None:
                registrant = match.groupdict()
                break

    for segment in data:
        for regex in tech_contact_regexes:
            match = re.search(regex, segment)
            if match is not None:
                tech_contact = match.groupdict()
                break

    for segment in data:
        for regex in admin_contact_regexes:
            match = re.search(regex, segment)
            if match is not None:
                admin_contact = match.groupdict()
                break

    for segment in data:
        for regex in billing_contact_regexes:
            match = re.search(regex, segment)
            if match is not None:
                billing_contact = match.groupdict()
                break

    # Find NIC handle contact definitions
    handle_contacts = parse_nic_contact(data)

    # Find NIC handle references and process them
    for category in nic_contact_references:
        for regex in nic_contact_references[category]:
            for segment in data:
                match = re.search(regex, segment)
                if match is not None:
                    data_reference = match.groupdict()
                    if data_reference["handle"] == "-" or re.match("https?:\/\/", data_reference["handle"]) is not None:
                        pass  # Reference was either blank or a URL; the latter is to deal with false positives for nic.ru
                    else:
                        found = False
                        for contact in handle_contacts:
                            if contact["handle"] == data_reference["handle"]:
                                found = True
                                data_reference.update(contact)
                        if not found:
                            # The contact definition was not found in the supplied raw WHOIS data. If the
                            # method has been called with never_query_handles=False, we can use the supplied
                            # WHOIS server for looking up the handle information separately.
                            if not never_query_handles:
                                try:
                                    contact = fetch_nic_contact(data_reference["handle"], handle_server)
                                    data_reference.update(contact)
                                except WhoisException as e:
                                    pass  # No data found. TODO: Log error?
                            else:
                                pass  # TODO: Log warning?
                        if category == "registrant":
                            registrant = data_reference
                        elif category == "tech":
                            tech_contact = data_reference
                        elif category == "billing":
                            billing_contact = data_reference
                        elif category == "admin":
                            admin_contact = data_reference
                    break

    # Post-processing
    for obj in (registrant, tech_contact, billing_contact, admin_contact):
        if obj is not None:
            for key in list(obj.keys()):
                if obj[key] is None or obj[key].strip() == "":  # Just chomp all surrounding whitespace
                    del obj[key]
                else:
                    obj[key] = obj[key].strip()
            if "phone_ext" in obj:
                if "phone" in obj:
                    obj["phone"] += " ext. %s" % obj["phone_ext"]
                    del obj["phone_ext"]
            if "street1" in obj:
                street_items = []
                i = 1
                while True:
                    try:
                        street_items.append(obj["street%d" % i])
                        del obj["street%d" % i]
                    except KeyError as e:
                        break
                    i += 1
                obj["street"] = "\n".join(street_items)
            if "organization1" in obj:  # This is to deal with eg. HKDNR, who allow organization names in multiple languages.
                organization_items = []
                i = 1
                while True:
                    try:
                        if obj["organization%d" % i].strip() != "":
                            organization_items.append(obj["organization%d" % i])
                            del obj["organization%d" % i]
                    except KeyError as e:
                        break
                    i += 1
                obj["organization"] = "\n".join(organization_items)
            if 'changedate' in obj:
                obj['changedate'] = parse_dates([obj['changedate']])[0].strftime('%d-%m-%Y')
            if 'creationdate' in obj:
                obj['creationdate'] = parse_dates([obj['creationdate']])[0].strftime('%d-%m-%Y')
            if 'street' in obj and "\n" in obj["street"] and 'postalcode' not in obj:
                # Deal with certain mad WHOIS servers that don't properly delimit address data... (yes, AFNIC, looking at you)
                lines = [x.strip() for x in obj["street"].splitlines()]
                if " " in lines[-1]:
                    postal_code, city = lines[-1].split(" ", 1)
                    if "." not in lines[-1] and re.match("[0-9]", postal_code) and len(postal_code) >= 3:
                        obj["postalcode"] = postal_code
                        obj["city"] = city
                        obj["street"] = "\n".join(lines[:-1])
            if 'firstname' in obj or 'lastname' in obj:
                elements = []
                if 'firstname' in obj:
                    elements.append(obj["firstname"])
                if 'lastname' in obj:
                    elements.append(obj["lastname"])
                obj["name"] = " ".join(elements)
            if 'country' in obj and 'city' in obj and (re.match("^R\.?O\.?C\.?$", obj["country"], re.IGNORECASE) or obj[
                    "country"].lower() == "republic of china") and obj["city"].lower() == "taiwan":
                # There's an edge case where some registrants append ", Republic of China" after "Taiwan", and this is mis-parsed
                # as Taiwan being the city. This is meant to correct that.
                obj["country"] = "%s, %s" % (obj["city"], obj["country"])
                lines = [x.strip() for x in obj["street"].splitlines()]
                obj["city"] = lines[-1]
                obj["street"] = "\n".join(lines[:-1])

    return {
        "registrant": registrant,
        "tech": tech_contact,
        "admin": admin_contact,
        "billing": billing_contact,
    }


def fetch_nic_contact(handle, lookup_server):
    response = get_whois_raw(handle, lookup_server)
    response = [segment.replace("\r", "") for segment in response]
    results = parse_nic_contact(response)

    if len(results) > 0:
        return results[0]
    else:
        raise WhoisException("No contact data found in the response.")


def parse_nic_contact(data):
    handle_contacts = []
    for regex in nic_contact_regexes:
        for segment in data:
            matches = re.finditer(regex, segment)
            for match in matches:
                handle_contacts.append(match.groupdict())

    return handle_contacts


def get_whois(domain: str, is_recursive=True):

    raw_data, server_list = get_whois_raw(domain, with_server_list=True, is_recursive=is_recursive)
    return parse_raw_whois(raw_data, normalized=[], never_query_handles=False,
                           handle_server=server_list[-1])


# Drops the mic disable-secrets-detection-end

def get_domain_from_query(query: str):

    demisto.debug(f"Attempting to get domain from query '{query}'...")

    try:
        # remove everything after the first appearance of one of "/", "?" or "#"
        idx_to_split = min(
            i for i in [query.find("#"), query.find("?"), query.replace("://", ":$$").find("/"), len(query)]
            if i > -1
        )
        query = query[:idx_to_split]

        # checks for largest matching suffix inside tlds dictionary
        suffix_len = max([len(suffix) for suffix in tlds if query.endswith('.{}'.format(suffix))] or [0])
        # if suffix(TLD) was found increase the length by one in order to add the dot before it. --> .com instead of com
        if suffix_len != 0:
            suffix_len += 1
        suffixless_query = query[:-suffix_len]
        domain = query
        # checks if query includes subdomain
        if suffixless_query.count(".") > 0:
            domain = query[suffixless_query.rindex(".") + 1:]

        demisto.debug(f"Found domain '{domain}' from query")
        return domain
    except Exception:
        demisto.error(f"Error parsing domain from query '{query}'.")
        raise WhoisInvalidDomain(f"Can't parse domain from query '{query}'")


def is_good_query_result(raw_result):
    """ Good result is one where the raw_result does not contains `NOT FOUND` or `No match` """
    return 'NOT FOUND' not in raw_result and 'No match' not in raw_result


def create_outputs(whois_result, domain, reliability, query=None):
    md = {'Name': domain}
    ec = {'Name': domain,
          'QueryResult': is_good_query_result(str(whois_result.get('raw', 'NOT FOUND')))}
    standard_ec = {}  # type:dict
    standard_ec['WHOIS'] = {}
    if 'status' in whois_result:
        ec['DomainStatus'] = whois_result.get('status')
        standard_ec['DomainStatus'] = whois_result.get('status')
        standard_ec['WHOIS']['DomainStatus'] = whois_result.get('status')
        md['Domain Status'] = whois_result.get('status')
    if 'raw' in whois_result:
        ec['Raw'] = whois_result.get('raw')
    if 'nameservers' in whois_result:
        ec['NameServers'] = whois_result.get('nameservers')
        standard_ec['NameServers'] = whois_result.get('nameservers')
        standard_ec['WHOIS']['NameServers'] = whois_result.get('nameservers')
        md['NameServers'] = whois_result.get('nameservers')
    try:
        if 'creation_date' in whois_result:
            ec['CreationDate'] = whois_result.get('creation_date')[0].strftime('%d-%m-%Y')
            standard_ec['CreationDate'] = whois_result.get('creation_date')[0].strftime('%d-%m-%Y')
            standard_ec['WHOIS']['CreationDate'] = whois_result.get('creation_date')[0].strftime(
                '%d-%m-%Y')
            md['Creation Date'] = whois_result.get('creation_date')[0].strftime('%d-%m-%Y')
        if 'updated_date' in whois_result:
            ec['UpdatedDate'] = whois_result.get('updated_date')[0].strftime('%d-%m-%Y')
            standard_ec['UpdatedDate'] = whois_result.get('updated_date')[0].strftime('%d-%m-%Y')
            standard_ec['WHOIS']['UpdatedDate'] = whois_result.get('updated_date')[0].strftime(
                '%d-%m-%Y')
            md['Updated Date'] = whois_result.get('updated_date')[0].strftime('%d-%m-%Y')
        if 'expiration_date' in whois_result:
            ec['ExpirationDate'] = whois_result.get('expiration_date')[0].strftime('%d-%m-%Y')
            standard_ec['ExpirationDate'] = whois_result.get('expiration_date')[0].strftime(
                '%d-%m-%Y')
            standard_ec['WHOIS']['ExpirationDate'] = whois_result.get('expiration_date')[
                0].strftime(
                '%d-%m-%Y')
            md['Expiration Date'] = whois_result.get('expiration_date')[0].strftime('%d-%m-%Y')
    except ValueError as e:
        return_error('Date could not be parsed. Please check the date again.\n{}'.format(e))
    if 'registrar' in whois_result:
        ec.update({'Registrar': {'Name': whois_result.get('registrar')}})
        standard_ec['WHOIS']['Registrar'] = whois_result.get('registrar')
        md['Registrar'] = whois_result.get('registrar')
        standard_ec['Registrar'] = {'Name': whois_result.get('registrar')}
    if 'id' in whois_result:
        ec['ID'] = whois_result.get('id')
        md['ID'] = whois_result.get('id')
    if 'contacts' in whois_result:
        contacts = whois_result['contacts']
        if 'registrant' in contacts and contacts['registrant'] is not None:
            md['Registrant'] = contacts['registrant']
            standard_ec['Registrant'] = contacts['registrant'].copy()
            for key, val in list(contacts['registrant'].items()):
                standard_ec['Registrant'][key.capitalize()] = val
            ec['Registrant'] = contacts['registrant']
            if 'organization' in contacts['registrant']:
                standard_ec['Organization'] = contacts['registrant']['organization']
        if 'admin' in contacts and contacts['admin'] is not None:
            md['Administrator'] = contacts['admin']
            ec['Administrator'] = contacts['admin']
            standard_ec['Admin'] = contacts['admin'].copy()
            for key, val in list(contacts['admin'].items()):
                standard_ec['Admin'][key.capitalize()] = val
            standard_ec['WHOIS']['Admin'] = contacts['admin']
        if 'tech' in contacts and contacts['tech'] is not None:
            md['Tech Admin'] = contacts['tech']
            ec['TechAdmin'] = contacts['tech']
            standard_ec['Tech'] = {}
            if 'country' in contacts['tech']:
                standard_ec['Tech']['Country'] = contacts['tech']['country']
            if 'email' in contacts['tech']:
                standard_ec['Tech']['Email'] = contacts['tech']['email']
            if 'organization' in contacts['tech']:
                standard_ec['Tech']['Organization'] = contacts['tech']['organization']
        if 'billing' in contacts and contacts['billing'] is not None:
            md['Billing Admin'] = contacts['billing']
            ec['BillingAdmin'] = contacts['billing']
            standard_ec['Billing'] = contacts['billing']
    if 'emails' in whois_result:
        ec['Emails'] = whois_result.get('emails')
        md['Emails'] = whois_result.get('emails')
        standard_ec['FeedRelatedIndicators'] = [{'type': 'Email', 'value': email}
                                                for email in whois_result.get('emails')]
    ec['QueryStatus'] = 'Success'
    md['QueryStatus'] = 'Success'

    standard_ec['Name'] = domain
    standard_ec['Whois'] = ec
    standard_ec['Whois']['QueryValue'] = query

    dbot_score = Common.DBotScore(indicator=domain, indicator_type='domain', integration_name='Whois', score=0,
                                  reliability=reliability)

    return md, standard_ec, dbot_score.to_context()


def prepare_readable_ip_data(response):
    network_data = response.get('network', {})
    return {'query': response.get('query'),
            'asn': response.get('asn'),
            'asn_cidr': response.get('asn_cidr'),
            'asn_date': response.get('asn_date'),
            'country_code': response.get('asn_country_code'),
            'network_name': network_data.get('name')
            }


'''COMMANDS'''


def get_whois_ip(ip: str,
                 retry_count: int = RATE_LIMIT_RETRY_COUNT_DEFAULT,
                 rate_limit_timeout: int = RATE_LIMIT_WAIT_SECONDS_DEFAULT,
                 rate_limit_errors_suppressed: bool = RATE_LIMIT_ERRORS_SUPPRESSEDL_DEFAULT
                 ) -> Optional[Dict[str, Any]]:
    """
    Performs an Registration Data Access Protocol (RDAP) lookup for an IP.

    See https://ipwhois.readthedocs.io/en/latest/RDAP.html

    Arguments:
        - `ip` (``str``): The IP to perform the lookup for.
        - `retry_count` (``int``): The number of times to retry the lookup in case of rate limiting error.
        - `rate_limit_timeout` (``int``): How long in seconds to wait before retrying the lookup in case of rate limiting error.

    Returns:
        - `Dict[str, None]` with the result of the lookup.
    """

    from urllib.request import build_opener, ProxyHandler

    proxy_opener = None
    if demisto.params().get('proxy'):
        proxies = assign_params(http=handle_proxy().get('http'), https=handle_proxy().get('https'))
        handler = ProxyHandler(proxies)
        proxy_opener = build_opener(handler)
        ip_obj = ipwhois.IPWhois(ip, proxy_opener=proxy_opener)
    else:
        ip_obj = ipwhois.IPWhois(ip)

    try:
        rate_limit_timeout_actual = rate_limit_timeout
        if retry_count > 0:
            rate_limit_timeout_actual = 0
        ret_value = ip_obj.lookup_rdap(depth=1, retry_count=retry_count, rate_limit_timeout=rate_limit_timeout_actual)
        return ret_value
    except urllib.error.HTTPError as e:
        if rate_limit_errors_suppressed:
            demisto.debug(f'Suppressed HTTPError when trying to lookup rdap info. Error: {e}')
            return None

        demisto.error(f'HTTPError when trying to lookup rdap info. Error: {e}')
        raise e


def get_param_or_arg(param_key: str, arg_key: str):
    return demisto.params().get(param_key) or demisto.args().get(arg_key)


def ip_command(reliability: str, should_error: bool) -> List[CommandResults]:
    """
    Performs RDAP lookup for the IP(s) and returns a list of CommandResults.
    Sets API execution metrics functionality (if supported) and adds them to the list of CommandResults.

    Args:
        - `reliability` (``str``): RDAP lookup source reliability.
        - `should_error` (``bool``): Whether to return an error entry if the lookup fails.
    Returns:
        - `List[CommandResults]` with the command results and API execution metrics (if supported).
    """

    ips = demisto.args().get('ip', '1.1.1.1')
    rate_limit_retry_count: int = (
        RATE_LIMIT_RETRY_COUNT_DEFAULT
        if is_time_sensitive()
        else int(
            get_param_or_arg('rate_limit_retry_count', 'rate_limit_retry_count')
            or RATE_LIMIT_RETRY_COUNT_DEFAULT
        )
    )
    rate_limit_wait_seconds: int = int(get_param_or_arg('rate_limit_wait_seconds',
                                       'rate_limit_wait_seconds') or RATE_LIMIT_WAIT_SECONDS_DEFAULT)
    rate_limit_errors_suppressed: bool = bool(get_param_or_arg(
        'rate_limit_errors_suppressed', 'rate_limit_errors_suppressed') or RATE_LIMIT_ERRORS_SUPPRESSEDL_DEFAULT)

    execution = ExecutionMetrics()
    results: List[CommandResults] = []
    for ip in argToList(ips):

        try:
            response = get_whois_ip(ip, retry_count=rate_limit_retry_count, rate_limit_timeout=rate_limit_wait_seconds,
                                    rate_limit_errors_suppressed=rate_limit_errors_suppressed)
            if response:
                execution.success += 1
                dbot_score = Common.DBotScore(
                    indicator=ip,
                    indicator_type=DBotScoreType.IP,
                    integration_name='Whois',
                    score=Common.DBotScore.NONE,
                    reliability=reliability
                )
                related_feed = Common.FeedRelatedIndicators(
                    value=response.get('network', {}).get('cidr'),
                    indicator_type='CIDR'
                )
                network_data: Dict[str, Any] = response.get('network', {})
                ip_output = Common.IP(
                    ip=ip,
                    asn=response.get('asn'),
                    geo_country=network_data.get('country'),
                    organization_name=network_data.get('name'),
                    dbot_score=dbot_score,
                    feed_related_indicators=[related_feed]
                )
                readable_data = prepare_readable_ip_data(response)
                result = CommandResults(
                    outputs_prefix='Whois.IP',
                    outputs_key_field='query',
                    outputs=response,
                    readable_output=tableToMarkdown('Whois results:', readable_data),
                    raw_response=response,
                    indicator=ip_output
                )
            else:
                execution.general_error += 1

                if should_error:
                    result = CommandResults(readable_output=f"No results returned for IP {ip}", entry_type=EntryType.ERROR)
                else:
                    result = CommandResults(readable_output=f"No results returned for IP {ip}", entry_type=EntryType.WARNING)

            results.append(result)

        except Exception as e:
            demisto.error(f"Exception type {e.__class__.__name__} caught performing RDAP lookup for IP {ip}: {e}")

            output = {
                'query': ip,
                'raw': f"Query failed for {ip}: {e.__class__.__name__}, {e}"
            }

            execution = increment_metric(
                execution_metrics=execution,
                mapping=ipwhois_exception_mapping,
                caught_exception=type(e)
            )

            if should_error:
                results.append(
                    CommandResults(
                        outputs_prefix="Whois.IP",
                        outputs_key_field="query",
                        outputs=output,
                        entry_type=EntryType.ERROR,
                        readable_output=f"Error performing RDAP lookup for IP {ip}: {e.__class__.__name__} {e}"
                    ))
            else:
                results.append(
                    CommandResults(
                        outputs_prefix="Whois.IP",
                        outputs_key_field="query",
                        outputs=output,
                        entry_type=EntryType.WARNING,
                        readable_output=f"Error performing RDAP lookup for IP {ip}: {e.__class__.__name__} {e}"
                    ))

    return append_metrics(execution_metrics=execution, results=results)


def whois_command(reliability: str) -> List[CommandResults]:
    """
    Runs Whois domain query.

    Arguments:
        - `reliability` (``str``): The source reliability. Set in the integration instance settings.
    Returns:
        - `List[CommandResults]` with the command results and API execution metrics (if supported).
    """

    args = demisto.args()
    query = args.get("query", "paloaltonetworks.com")
    is_recursive = argToBoolean(args.get("recursive", 'false'))
    verbose = argToBoolean(args.get("verbose", "false"))
    should_error = argToBoolean(demisto.params().get('with_error', False))

    demisto.info(f"whois command is called with the query '{query}'")

    execution_metrics = ExecutionMetrics()
    results: List[CommandResults] = []
    for query in argToList(query):
        demisto.debug(f'Getting whois for a single {query=}')
        domain = get_domain_from_query(query)

        try:
            whois_result = get_whois(domain, is_recursive=is_recursive)
            demisto.debug(f'Got whois for a single {query=}')
            execution_metrics.success += 1
            md, standard_ec, dbot_score = create_outputs(whois_result, domain, reliability, query)
            context_res = {}
            context_res.update(dbot_score)
            context_res.update({Common.Domain.CONTEXT_PATH: standard_ec})

            if verbose:
                demisto.info('Verbose response')
                whois_result['query'] = query
                json_res = json.dumps(whois_result, indent=4, sort_keys=True, default=str)
                context_res.update({'Whois(val.query==obj.query)': json.loads(json_res)})

            result = CommandResults(
                outputs=context_res,
                entry_type=EntryType.NOTE,
                content_format=EntryFormat.MARKDOWN,
                readable_output=tableToMarkdown('Whois results for {}'.format(domain), md),
                raw_response=str(whois_result)
            )

            results.append(result)

        except PywhoisError as e:  # "DOMAIN NOT FOUND", "Invalid Domain Format", "Network Issues", "WHOIS Server Changes"
            demisto.debug(f"WHOIS lookup failed for {domain}: {e}")

            execution_metrics = increment_metric(
                execution_metrics=execution_metrics,
                mapping=whois_exception_mapping,
                caught_exception=type(e)
            )

            output = ({
                outputPaths['domain']: {
                    'Name': domain,
                    'Whois': {
                        'QueryStatus': f"Failed whois lookup: {e}"
                    }
                },
            })

            results.append(CommandResults(
                outputs=output,
                readable_output=f"Exception of type {e.__class__.__name__}"
                                f" was caught while performing whois lookup with the domain '{domain}': {e}",
                entry_type=EntryType.ERROR if should_error else EntryType.WARNING,
                raw_response=str(e)
            ))

    return append_metrics(execution_metrics=execution_metrics, results=results)


def domain_command(reliability: str) -> List[CommandResults]:
    """
    Runs Whois domain query.

    Arguments:
        - `reliability` (``str``): The source reliability. Set in the integration instance settings.
    Returns:
        - `List[CommandResults]` with the command results and API execution metrics (if supported).
    """

    args = demisto.args()
    domains = args.get("domain", [])
    is_recursive = argToBoolean(args.get("recursive", 'false'))
    should_error = argToBoolean(demisto.params().get('with_error', False))

    demisto.info(f"whois command is called with the query '{domains}'")

    execution_metrics = ExecutionMetrics()
    results: List[CommandResults] = []
    for domain in argToList(domains):
        demisto.debug(f'Getting domain for a single {domain=}')

        try:
            whois_result = get_whois(domain, is_recursive=is_recursive)
            demisto.debug(f'Got domain for a single {domain=}')
            execution_metrics.success += 1
            md, standard_ec, dbot_score = create_outputs(whois_result, domain, reliability)
            context_res = {}
            context_res.update(dbot_score)
            context_res.update({Common.Domain.CONTEXT_PATH: standard_ec})

            result = CommandResults(
                outputs=context_res,
                entry_type=EntryType.NOTE,
                content_format=EntryFormat.MARKDOWN,
                readable_output=tableToMarkdown('Whois results for {}'.format(domain), md),
                raw_response=str(whois_result)
            )

            results.append(result)

        except PywhoisError as e:  # "DOMAIN NOT FOUND", "Invalid Domain Format", "Network Issues", "WHOIS Server Changes"
            demisto.debug(f"WHOIS lookup failed for {domain}: {e}")

            execution_metrics = increment_metric(
                execution_metrics=execution_metrics,
                mapping=whois_exception_mapping,
                caught_exception=type(e)
            )

            output = ({
                outputPaths['domain']: {
                    'Name': domain,
                    'Whois': {
                        'QueryStatus': f"Failed domain lookup: {e}"
                    }
                },
            })

            results.append(CommandResults(
                outputs=output,
                readable_output=f"Exception of type {e.__class__.__name__}"
                                f" was caught while performing whois lookup with the domain '{domain}': {e}",
                entry_type=EntryType.ERROR if should_error else EntryType.WARNING,
                raw_response=str(e)
            ))

    return append_metrics(execution_metrics=execution_metrics, results=results)


def test_command():
    test_domain = 'google.co.uk'
    demisto.debug(f"Testing module using domain '{test_domain}'...")
    whois_result = get_whois(test_domain)

    try:
        if whois_result['nameservers'][0] == 'ns1.google.com':
            return 'ok'
    except Exception as e:
        raise WhoisException(f"Failed testing module using domain '{test_domain}': {e.__class__.__name__} {e}")


def setup_proxy():
    scheme_to_proxy_type = {
        'socks5': [socks.PROXY_TYPE_SOCKS5, False],
        'socks5h': [socks.PROXY_TYPE_SOCKS5, True],
        'socks4': [socks.PROXY_TYPE_SOCKS4, False],
        'socks4a': [socks.PROXY_TYPE_SOCKS4, True],
        'http': [socks.PROXY_TYPE_HTTP, True]
    }
    proxy_url = demisto.params().get('proxy_url')
    def_scheme = 'socks5h'
    if proxy_url == 'system_http' or not proxy_url and demisto.params().get('proxy'):
        system_proxy = handle_proxy('proxy')
        # use system proxy. Prefer https and fallback to http
        proxy_url = system_proxy.get('https') if system_proxy.get('https') else system_proxy.get('http')
        def_scheme = 'http'
    if not proxy_url and not demisto.params().get('proxy'):
        return
    scheme, host = (def_scheme, proxy_url) if '://' not in proxy_url else proxy_url.split('://')
    host, port = (host, None) if ':' not in host else host.split(':')
    if port:
        port = int(port)
    proxy_type = scheme_to_proxy_type.get(scheme)
    if not proxy_type:
        raise ValueError("Un supported proxy scheme: {}".format(scheme))
    socks.set_default_proxy(proxy_type[0], host, port, proxy_type[1])
    socket.socket = socks.socksocket  # type: ignore


def extract_hard_date(date: str) -> Optional[str]:
    """
    Extracts the first date from a given string.

    Args:
        date (str): A string containing a date.

    Returns:
        Optional[str]: The first extracted date as a string if found, otherwise None.
    """
    date_extracted = dateparser.search.search_dates(date)
    return date_extracted[0][0] if date_extracted else None


def extract_date(date) -> str:
    """
    Extracts and formats a date from raw data.

    Args:
        raw_data (dict): Dictionary containing date information.
        date_requested (str): Key for the requested date in raw_data.

    Returns:
        str: Formatted date string (DD-MM-YYYY) or original value if parsing fails.
    """
    if date:
        try:
            if isinstance(date, list):
                if isinstance(date[0], datetime):
                    return date[0].strftime("%d-%m-%Y")
                else:
                    parsed_date = dateparser.parse(date[0])
                    if parsed_date:
                        return parsed_date.strftime("%d-%m-%Y")
                    return extract_hard_date(date[0]) or str(date[0])
            elif isinstance(date, datetime):
                return date.strftime("%d-%m-%Y")
            else:
                parsed_date = dateparser.parse(date)  # type: ignore
                if parsed_date:
                    return parsed_date.strftime("%d-%m-%Y")
                return extract_hard_date(date) or str(date)
        except Exception as e:
            demisto.debug(f"Couldn't extract date from {date=}. Error: {e}")
            return str(date)
    return ""


def extract_name_servers(servers) -> list:
    """
    Extracts and normalizes name servers from input.

    Args:
        servers: String or iterable of name servers.

    Returns:
        list: Normalized list of unique name servers.
    """
    if not servers:
        return []
    if isinstance(servers, str):
        if "\n" in servers:
            return servers.split("\n")
        return [servers]
    return sorted(list(set(map(str.lower, servers))))


def get_info_by_prefix(domain_data: dict, prefix: str) -> dict:
    """
    Filters domain_data by prefix, removes prefix from keys, and capitalizes them.

    Args:
        domain_data (dict): Domain information.
        prefix (str): Prefix to filter by.

    Returns:
        dict: Filtered data with processed keys and non-None values.
    """

    def process_key(key: str):
        return (
            "Name"
            if key == "registrar"
            else (
                "Admin"
                if key == "admin"
                else key.removeprefix(prefix + "_").capitalize()
            )
        )

    return {
        camelize_string(process_key(key)): value
        for key, value in domain_data.items()
        if key.startswith(prefix) and value
    }


def rename_keys(d: dict, key_mapping: dict) -> dict:
    """
    Rename keys in a dictionary according to the provided mapping.

    Args:
        d (dict): The dictionary whose keys are to be renamed.
        key_mapping (dict): A dictionary where keys are existing keys in `d`
                            and values are new keys to replace them.

    Returns:
        dict: A new dictionary with keys renamed according to `key_mapping`.

    Example:
        >>> data = {'a': 1, 'b': 2, 'c': 3}
        >>> mapping = {'a': 'A', 'b': 'B'}
        >>> rename_keys(data, mapping)
        {'A': 1, 'B': 2, 'c': 3}
    """
    renamed_dict = d.copy()
    for old_key, new_key in key_mapping.items():
        if old_key in renamed_dict:
            renamed_dict[new_key] = renamed_dict.pop(old_key)
    return renamed_dict


def check_and_remove_abuse(domain_info: Dict[str, Any]):
    """
    Checks for keys or values containing the word 'abuse' in a domain information dictionary.
    Removes and collects these values, and returns them as a list. If only one value is found,
    it returns that value directly.

    Args:
        domain_info (Dict[str, Any]): The dictionary containing domain information.

    Returns:
        A single abuse-related value if only one is found, otherwise a list of abuse-related values.
    """
    abuse_values = []
    for key, value in list(domain_info.items()):
        if isinstance(value, str):
            if "abuse" in value.lower():
                abuse_values.append(domain_info.pop(key))
        elif isinstance(value, list):
            abuse_items = [
                item
                for item in value
                if isinstance(item, str) and "abuse" in item.lower()
            ]
            if abuse_items:
                abuse_values.extend(abuse_items)
                domain_info[key] = [item for item in value if item not in abuse_items]
    return abuse_values[0] if len(abuse_values) == 1 else abuse_values


def arrange_raw_whois_data_to_context(raw_data: dict, domain: str) -> dict:
    """
    Converts raw WHOIS data into a structured context dictionary.

    Args:
        raw_data (dict): Raw WHOIS data to be structured.
        domain (str): The domain name for which the WHOIS data is provided.

    Returns:
        dict: A dictionary containing structured WHOIS context data.
    """
    context_data: dict[str, Any] = {
        "Raw": {f"{key}": f"{value}" for key, value in raw_data.items()},
        "Name": domain,
        "NameServers": extract_name_servers(raw_data.pop("name_servers", [])),
    }
    raw_data.pop("name", None)
    for key in ["creation_date", "expiration_date", "updated_date"]:
        context_data[camelize_string(key)] = extract_date(raw_data.pop(key, None))

    for prefix in ("admin", "registrant", "registrar", "tech"):
        context_data[prefix.capitalize()] = get_info_by_prefix(raw_data, prefix)

    if abuse_emails := check_and_remove_abuse(raw_data):
        context_data.setdefault("Registrar", {})["AbuseEmail"] = abuse_emails  # type: ignore[index]

    emails = raw_data.get("emails")
    context_data["FeedRelatedIndicators"] = [
        {"Type": "email", "Value": email}
        for email in (emails if isinstance(emails, list) else [emails])
        if email
    ]
    context_data.update(
        {
            camelize_string(k): v
            for k, v in raw_data.items()
            if not k.startswith(("admin", "registrant", "registrar", "tech"))
        }
    )

    context_data = rename_keys(
        context_data, {"Org": "Organization", "Status": "DomainStatus"}
    )

    remove_nulls_from_dictionary(context_data)
    res = {**context_data, "WHOIS": context_data}
    res.pop("Raw", None)
    return res


def whois_and_domain_command(command: str, reliability: str) -> list[CommandResults]:
    args = demisto.args()
    domains = argToList(args.get("query") or args.get("domain"))
    should_error = argToBoolean(demisto.params().get('with_error', False))
    execution_metrics = ExecutionMetrics()
    results: List[CommandResults] = []
    demisto.debug(f"{command=} is called with the query '{domains}'")
    for domain in domains:
        demisto.debug(f"Getting whois for a single {domain=}")
        try:
            domain_data = whois.whois(domain)
            demisto.debug(
                f"'python-whois' lib return raw_data for {domain=} is: {domain_data=}"
            )
            execution_metrics.success += 1
            whois_res = {}
            context_output = arrange_raw_whois_data_to_context(domain_data, domain)
            whois_res.update({Common.Domain.CONTEXT_PATH: context_output})
            whois_res.update(
                Common.DBotScore(
                    indicator=domain,
                    indicator_type="domain",
                    integration_name="Whois",
                    score=0,
                    reliability=reliability,
                ).to_context()
            )
            hr_headers = [
                "Name",
                "ID",
                "CreationDate",
                "ExpirationDate",
                "UpdatedDate",
                "NameServers",
                "Organization",
                "Registrar",
                "Registrant",
                "DomainStatus",
                "Emails",
                "Whois_server",
            ]
            results.append(
                CommandResults(
                    outputs=whois_res,
                    readable_output=tableToMarkdown(
                        "Whois results for {}".format(domain),
                        context_output,
                        headers=hr_headers,
                        removeNull=True,
                    ),
                    raw_response=dict(domain_data),
                )
            )
        except PywhoisError as e:  # "DOMAIN NOT FOUND", "Invalid Domain Format", "Network Issues", "WHOIS Server Changes"
            demisto.debug(f"WHOIS lookup failed for {domain}: {e}")

            execution_metrics = increment_metric(
                execution_metrics=execution_metrics,
                mapping=whois_exception_mapping,
                caught_exception=type(e),
            )

            output = {
                outputPaths["domain"]: {
                    "Name": domain,
                    "WHOIS": {"QueryStatus": f"Failed domain lookup: {e}"},
                },
            }
            results.append(
                CommandResults(
                    outputs=output,
                    readable_output=f"Exception of type {e.__class__.__name__}"
                                    f" was caught while performing whois lookup with the domain '{domain}': {e}",
                    entry_type=EntryType.ERROR if should_error else EntryType.WARNING,
                    raw_response=str(e),
                )
            )
    return append_metrics(execution_metrics=execution_metrics, results=results)


def new_test_command():
    test_domain = "google.com"
    demisto.debug(f"Testing module using domain '{test_domain}'...")
    whois_result = arrange_raw_whois_data_to_context(whois.whois(test_domain), test_domain)
    try:
        if whois_result["WHOIS"]["NameServers"][0] == "ns1.google.com":
            return "ok"
    except Exception as e:
        raise WhoisException(
            f"Failed testing module using domain '{test_domain}': {e.__class__.__name__} {e}"
        )


''' EXECUTION CODE '''


def main():  # pragma: no cover
    demisto.debug(f"command is {demisto.command()}")
    command = demisto.command()
    params = demisto.params()
    should_error = argToBoolean(demisto.params().get('with_error', False))

    reliability = demisto.params().get('integrationReliability')
    reliability = reliability if reliability else DBotScoreReliability.B

    org_socket = None
    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        raise Exception("Please provide a valid value for the Source Reliability parameter.")

    old_version = argToBoolean(params.get("old-version", "true"))
    if old_version == False and command != "ip":
        demisto.debug("Run by new context data layout")
        if command == "domain" or command == "whois":
            return_results(whois_and_domain_command(command, reliability))
        if command == 'test-module':
            return_results(new_test_command())
    else:
        try:
            results: List[CommandResults] = []
            if command == 'ip':
                results = ip_command(reliability=reliability, should_error=should_error)

            else:
                org_socket = socket.socket
                setup_proxy()
                if command == 'test-module':
                    results = test_command()

                elif command == 'whois':
                    results = whois_command(reliability=reliability)

                elif command == "domain":
                    results = domain_command(reliability=reliability)

                else:
                    raise NotImplementedError()

            demisto.debug(f"Returning results for command {demisto.command()}")
            return_results(results)
        except Exception as e:
            msg = f"Exception thrown calling command '{demisto.command()}' {e.__class__.__name__}: {e}"
            demisto.error(msg)
            return_error(message=msg, error=e)
        finally:
            if command != 'ip':
                socks.set_default_proxy()  # clear proxy settings
                socket.socket = org_socket  # type: ignore


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

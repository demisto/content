import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
import pickle
import re
from nltk.tokenize import word_tokenize, sent_tokenize
import string
from bs4 import BeautifulSoup
from collections import Counter
import pandas as pd
import signal
import numpy as np
import zlib
from base64 import b64encode
from nltk import ngrams
from datetime import datetime
MODIFIED_TIMEFORMAT = '%Y-%m-%d %H:%M:%S'

EMAIL_BODY_FIELD = 'emailbody'
EMAIL_SUBJECT_FIELD = 'emailsubject'
EMAIL_HTML_FIELD = 'emailbodyhtml'
EMAIL_HEADERS_FIELD = 'emailheaders'
EMAIL_ATTACHMENT_FIELD = 'attachment'
EMBEDDING_DICT = None

FETCH_DATA_VERSION = '1.0'
LAST_EXECUTION_LIST_NAME = 'FETCH_DATA_ML_LAST_EXECUTION'
MAX_INCIDENTS_TO_FETCH_PERIODIC_EXECUTION = 500
MAX_INCIDENTS_TO_FETCH_FIRST_EXECUTION = 3000
DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'
'''
Define time out functionality
'''


class TimeoutException(Exception):  # Custom exception class
    pass


def timeout_handler(signum, frame):  # Custom signal handler
    if signum or frame:
        pass
    raise TimeoutException


# Change the behavior of SIGALRM
signal.signal(signal.SIGALRM, timeout_handler)


'''
Define vocabulary to search
'''

word_to_regex = {
    "x days": r"\d+ days",
    "x hours": r"(\d+ hours)|(\d+ hrs)|(\d+hrs)",
}

word_to_ngram = {
    "#1": ('#', '1'),
    "$": ('$',),
    "$$$": ('$', '$', '$'),
    "100%": ('100', '%'),
    "100% free": ('100', '%', 'free'),
    "100% more": ('100', '%', 'more'),
    "100% satisfied": ('100', '%', 'satisfied'),
    "a": ('a',),
    "accept": ('accept',),
    "accept credit cards": ('accept', 'credit', 'cards'),
    "accepted": ('accepted',),
    "access": ('access',),
    "accordance": ('accordance',),
    "account": ('account',),
    "accounting": ('accounting',),
    "act": ('act',),
    "act now": ('act', 'now'),
    "action": ('action',),
    "ad": ('ad',),
    "additional": ('additional',),
    "additional income": ('additional', 'income'),
    "affordable": ('affordable',),
    "all": ('all',),
    "all natural": ('all', 'natural'),
    "all new": ('all', 'new'),
    "amazed": ('amazed',),
    "and": ('and',),
    "any": ('any',),
    "apply": ('apply',),
    "apply now": ('apply', 'now'),
    "apply online": ('apply', 'online'),
    "are": ('are',),
    "as": ('as',),
    "as seen on": ('as', 'seen', 'on'),
    "asked": ('asked',),
    "at": ('at',),
    "attach": ('attach',),
    "attached": ('attached',),
    "attachment": ('attachment',),
    "authorize": ('authorize',),
    "authorizing": ('authorizing',),
    "avoid": ('avoid',),
    "back": ('back',),
    "bad": ('bad',),
    "bank": ('bank',),
    "bargain": ('bargain',),
    "be": ('be',),
    "be amazed": ('be', 'amazed'),
    "be your own boss": ('be', 'your', 'own', 'boss'),
    "become": ('become',),
    "become a member": ('become', 'a', 'member'),
    "been": ('been',),
    "believe": ('believe',),
    "below": ('below',),
    "beneficiary": ('beneficiary',),
    "best": ('best',),
    "best price": ('best', 'price'),
    "best regards": ('best', 'regards'),
    "big": ('big',),
    "big bucks": ('big', 'bucks'),
    "billing": ('billing',),
    "billion": ('billion',),
    "bonus": ('bonus',),
    "boss": ('boss',),
    "brand": ('brand',),
    "bucks": ('bucks',),
    "bulk": ('bulk',),
    "bulk email": ('bulk', 'email'),
    "buy": ('buy',),
    "buy direct": ('buy', 'direct'),
    "call": ('call',),
    "call free": ('call', 'free'),
    "call now": ('call', 'now'),
    "can't": ('ca', "n't"),
    "can't live without": ('ca', "n't", 'live', 'without'),
    "cancel": ('cancel',),
    "cancel at any time": ('cancel', 'at', 'any', 'time'),
    "candidate": ('candidate',),
    "capacity": ('capacity',),
    "card": ('card',),
    "cards": ('cards',),
    "cards accepted": ('cards', 'accepted'),
    "cash": ('cash',),
    "cash bonus": ('cash', 'bonus'),
    "casino": ('casino',),
    "catch": ('catch',),
    "cents": ('cents',),
    "cents on the dollar": ('cents', 'on', 'the', 'dollar'),
    "certified": ('certified',),
    "charges": ('charges',),
    "cheap": ('cheap',),
    "check": ('check',),
    "check or money order": ('check', 'or', 'money', 'order'),
    "claim": ('claim',),
    "claims": ('claims',),
    "clearance": ('clearance',),
    "click": ('click',),
    "click below": ('click', 'below'),
    "click here": ('click', 'here'),
    "collect": ('collect',),
    "compare": ('compare',),
    "compare rates": ('compare', 'rates'),
    "compliance": ('compliance',),
    "conditions": ('conditions',),
    "confidentiality": ('confidentiality',),
    "confirmation": ('confirmation',),
    "congratulations": ('congratulations',),
    "consideration": ('consideration',),
    "consolidate": ('consolidate',),
    "consolidate debt": ('consolidate', 'debt'),
    "consultation": ('consultation',),
    "contact": ('contact',),
    "contains": ('contains',),
    "contract": ('contract',),
    "control": ('control',),
    "cost": ('cost',),
    "costs": ('costs',),
    "crack": ('crack',),
    "cracked": ('cracked',),
    "credit": ('credit',),
    "credit card": ('credit', 'card'),
    "credit card offers": ('credit', 'card', 'offers'),
    "cures": ('cures',),
    "customer": ('customer',),
    "customers": ('customers',),
    "day": ('day',),
    "days": ('days',),
    "deal": ('deal',),
    "deals": ('deals',),
    "dear": ('dear',),
    "dear account holder": ('dear', 'account', 'holder'),
    "dear customer": ('dear', 'customer'),
    "dear friend": ('dear', 'friend'),
    "dear sir": ('dear', 'sir'),
    "dear somebody": ('dear', 'somebody'),
    "dear user": ('dear', 'user'),
    "dear valued member": ('dear', 'valued', 'member'),
    "debt": ('debt',),
    "delete": ('delete',),
    "deletedon't": ('deletedo', "n't"),
    "derivative": ('derivative',),
    "detail": ('detail',),
    "direct": ('direct',),
    "direct email": ('direct', 'email'),
    "direct marketing": ('direct', 'marketing'),
    "discount": ('discount',),
    "do": ('do',),
    "do it today": ('do', 'it', 'today'),
    "do not": ('do', 'not'),
    "document": ('document',),
    "dollar": ('dollar',),
    "dollars": ('dollars',),
    "don't": ('do', "n't"),
    "don't delete": ('do', "n't", 'delete'),
    "don't deletedon't hesitate": ('do', "n't", 'deletedo', "n't", 'hesitate'),
    "don't hesitate": ('do', "n't", 'hesitate'),
    "don’t": ('don', '’', 't'),
    "don’t delete": ('don', '’', 't', 'delete'),
    "double": ('double',),
    "double your cash": ('double', 'your', 'cash'),
    "double your income": ('double', 'your', 'income'),
    "e-mail": ('e-mail',),
    "earn": ('earn',),
    "earn extra cash": ('earn', 'extra', 'cash'),
    "earn money": ('earn', 'money'),
    "earnings": ('earnings',),
    "eliminate": ('eliminate',),
    "eliminate bad credit": ('eliminate', 'bad', 'credit'),
    "email": ('email',),
    "engine": ('engine',),
    "equity": ('equity',),
    "exclusive": ('exclusive',),
    "exclusive deal": ('exclusive', 'deal'),
    "expect": ('expect',),
    "expect to earn": ('expect', 'to', 'earn'),
    "experience": ('experience',),
    "expire": ('expire',),
    "expires": ('expires',),
    "extra": ('extra',),
    "extra cash": ('extra', 'cash'),
    "extra income": ('extra', 'income'),
    "eyes": ('eyes',),
    "fantastic": ('fantastic',),
    "fast": ('fast',),
    "fast cash": ('fast', 'cash'),
    "fax": ('fax',),
    "fees": ('fees',),
    "financial": ('financial',),
    "financial freedom": ('financial', 'freedom'),
    "flow": ('flow',),
    "for": ('for',),
    "for instant access": ('for', 'instant', 'access'),
    "for only": ('for', 'only'),
    "for you": ('for', 'you'),
    "for?": ('for', '?'),
    "free": ('free',),
    "free access": ('free', 'access'),
    "free consultation": ('free', 'consultation'),
    "free gift": ('free', 'gift'),
    "free hosting": ('free', 'hosting'),
    "free info": ('free', 'info'),
    "free investment": ('free', 'investment'),
    "free membership": ('free', 'membership'),
    "free money": ('free', 'money'),
    "free preview": ('free', 'preview'),
    "free quote": ('free', 'quote'),
    "free trial": ('free', 'trial'),
    "freedom": ('freedom',),
    "friend": ('friend',),
    "from": ('from',),
    "full": ('full',),
    "full refund": ('full', 'refund'),
    "gas": ('gas',),
    "get": ('get',),
    "get it now": ('get', 'it', 'now'),
    "get out of debt": ('get', 'out', 'of', 'debt'),
    "get paid": ('get', 'paid'),
    "get started": ('get', 'started'),
    "get started now": ('get', 'started', 'now'),
    "gift": ('gift',),
    "gimmick": ('gimmick',),
    "giveaway": ('giveaway',),
    "great": ('great',),
    "great offer": ('great', 'offer'),
    "growth": ('growth',),
    "guarantee": ('guarantee',),
    "guaranteed": ('guaranteed',),
    "hack": ('hack',),
    "hacked": ('hacked',),
    "hacker": ('hacker',),
    "hate": ('hate',),
    "have": ('have',),
    "hello": ('hello',),
    "here": ('here',),
    "hesitate": ('hesitate',),
    "hi": ('hi',),
    "hidden": ('hidden',),
    "hidden charges": ('hidden', 'charges'),
    "holder": ('holder',),
    "home": ('home',),
    "hormone": ('hormone',),
    "hosting": ('hosting',),
    "hours": ('hours',),
    "how": ('how',),
    "how are you?": ('how', 'are', 'you', '?'),
    "human": ('human',),
    "human growth hormone": ('human', 'growth', 'hormone'),
    "important": ('important',),
    "important information regardinginformation you requested": (
        'important', 'information', 'regardinginformation', 'you', 'requested'),
    "in": ('in',),
    "in accordance with laws": ('in', 'accordance', 'with', 'laws'),
    "income": ('income',),
    "increase": ('increase',),
    "increase sales": ('increase', 'sales'),
    "increase traffic": ('increase', 'traffic'),
    "incredible": ('incredible',),
    "incredible deal": ('incredible', 'deal'),
    "info": ('info',),
    "info you requested": ('info', 'you', 'requested'),
    "information": ('information',),
    "information you requested": ('information', 'you', 'requested'),
    "initial": ('initial',),
    "instant": ('instant',),
    "interest": ('interest',),
    "internet": ('internet',),
    "internet marketing": ('internet', 'marketing'),
    "investment": ('investment',),
    "isn’t": ('isn', '’', 't'),
    "it": ('it',),
    "item": ('item',),
    "join": ('join',),
    "join millions": ('join', 'millions'),
    "junk": ('junk',),
    "last": ('last',),
    "laws": ('laws',),
    "lifetime": ('lifetime',),
    "limited": ('limited',),
    "limited time": ('limited', 'time'),
    "live": ('live',),
    "loans": ('loans',),
    "lose": ('lose',),
    "lose weight": ('lose', 'weight'),
    "loss": ('loss',),
    "lower": ('lower',),
    "lower rates": ('lower', 'rates'),
    "lowest": ('lowest',),
    "lowest price": ('lowest', 'price'),
    "luxury": ('luxury',),
    "make": ('make',),
    "make $": ('make', '$'),
    "make money": ('make', 'money'),
    "manage": ('manage',),
    "market": ('market',),
    "marketing": ('marketing',),
    "marketing solution": ('marketing', 'solution'),
    "mass": ('mass',),
    "mass email": ('mass', 'email'),
    "mastrubate": ('mastrubate',),
    "mastrubating": ('mastrubating',),
    "medicine": ('medicine',),
    "meet": ('meet',),
    "meet singles": ('meet', 'singles'),
    "member": ('member',),
    "membership": ('membership',),
    "message": ('message',),
    "message contains": ('message', 'contains'),
    "million": ('million',),
    "million dollars": ('million', 'dollars'),
    "millions": ('millions',),
    "miracle": ('miracle',),
    "money": ('money',),
    "money back": ('money', 'back'),
    "months": ('months',),
    "more": ('more',),
    "mortgage": ('mortgage',),
    "mortgage rates": ('mortgage', 'rates'),
    "multi-level": ('multi-level',),
    "multi-level marketing": ('multi-level', 'marketing'),
    "name": ('name',),
    "name brand": ('name', 'brand'),
    "natural": ('natural',),
    "necessary": ('necessary',),
    "new": ('new',),
    "new customers only": ('new', 'customers', 'only'),
    "no": ('no',),
    "no catch": ('no', 'catch'),
    "no cost": ('no', 'cost'),
    "no credit check": ('no', 'credit', 'check'),
    "no credit check ": ('no', 'credit', 'check'),
    "no experience": ('no', 'experience'),
    "no fees": ('no', 'fees'),
    "no gimmick": ('no', 'gimmick'),
    "no hidden costs": ('no', 'hidden', 'costs'),
    "no hidden fees": ('no', 'hidden', 'fees'),
    "no interest": ('no', 'interest'),
    "no investment": ('no', 'investment'),
    "no obligation": ('no', 'obligation'),
    "no purchase necessary": ('no', 'purchase', 'necessary'),
    "no questions asked": ('no', 'questions', 'asked'),
    "no strings attached": ('no', 'strings', 'attached'),
    "not": ('not',),
    "not junk": ('not', 'junk'),
    "notspam": ('notspam',),
    "now": ('now',),
    "now only": ('now', 'only'),
    "number": ('number',),
    "obligation": ('obligation',),
    "of": ('of',),
    "offer": ('offer',),
    "offer expires": ('offer', 'expires'),
    "offers": ('offers',),
    "oil": ('oil',),
    "on": ('on',),
    "once": ('once',),
    "once in a lifetime": ('once', 'in', 'a', 'lifetime'),
    "once in lifetime": ('once', 'in', 'lifetime'),
    "one": ('one',),
    "one time": ('one', 'time'),
    "online": ('online',),
    "online marketing": ('online', 'marketing'),
    "only": ('only',),
    "open": ('open',),
    "opt": ('opt',),
    "opt in": ('opt', 'in'),
    "option": ('option',),
    "or": ('or',),
    "order": ('order',),
    "order now": ('order', 'now'),
    "order today": ('order', 'today'),
    "out": ('out',),
    "own": ('own',),
    "paid": ('paid',),
    "passwords": ('passwords',),
    "payment": ('payment',),
    "pennies": ('pennies',),
    "pennies a day": ('pennies', 'a', 'day'),
    "please": ('please',),
    "please read": ('please', 'read'),
    "porn": ('porn',),
    "porno": ('porno',),
    "potential": ('potential',),
    "potential earnings": ('potential', 'earnings'),
    "pre-approved": ('pre-approved',),
    "presently": ('presently',),
    "preview": ('preview',),
    "price": ('price',),
    "prize": ('prize',),
    "problem": ('problem',),
    "profit": ('profit',),
    "promise": ('promise',),
    "promotion": ('promotion',),
    "purchase": ('purchase',),
    "pure": ('pure',),
    "pure profit": ('pure', 'profit'),
    "questions": ('questions',),
    "quote": ('quote',),
    "rates": ('rates',),
    "read": ('read',),
    "recommend": ('recommend',),
    "record": ('record',),
    "recording": ('recording',),
    "refinance": ('refinance',),
    "refund": ('refund',),
    "regardinginformation": ('regardinginformation',),
    "regards": ('regards',),
    "removal": ('removal',),
    "remove": ('remove',),
    "request": ('request',),
    "requested": ('requested',),
    "requires": ('requires',),
    "requires initial investment": ('requires', 'initial', 'investment'),
    "reserve": ('reserve',),
    "reserves": ('reserves',),
    "reserves the right": ('reserves', 'the', 'right'),
    "review": ('review',),
    "right": ('right',),
    "risk": ('risk',),
    "risk-free": ('risk-free',),
    "sales": ('sales',),
    "satisfactin": ('satisfactin',),
    "satisfactin guaranteed": ('satisfactin', 'guaranteed'),
    "satisfaction": ('satisfaction',),
    "satisfied": ('satisfied',),
    "save": ('save',),
    "save big money": ('save', 'big', 'money'),
    "save up to": ('save', 'up', 'to'),
    "scam": ('scam',),
    "scan": ('scan',),
    "score": ('score',),
    "search": ('search',),
    "search engine": ('search', 'engine'),
    "section": ('section',),
    "security": ('security',),
    "see": ('see',),
    "see for yourself": ('see', 'for', 'yourself'),
    "seen": ('seen',),
    "selected": ('selected',),
    "send": ('send',),
    "sent": ('sent',),
    "sent in compliance": ('sent', 'in', 'compliance'),
    "serious": ('serious',),
    "share": ('share',),
    "shared": ('shared',),
    "sharing": ('sharing',),
    "sign": ('sign',),
    "sign up free": ('sign', 'up', 'free'),
    "singles": ('singles',),
    "sir": ('sir',),
    "social": ('social',),
    "social security number": ('social', 'security', 'number'),
    "solution": ('solution',),
    "somebody": ('somebody',),
    "spam": ('spam',),
    "special": ('special',),
    "special promotion": ('special', 'promotion'),
    "started": ('started',),
    "stock": ('stock',),
    "strings": ('strings',),
    "subject": ('subject',),
    "subject to": ('subject', 'to'),
    "success": ('success',),
    "supplies": ('supplies',),
    "supplies are limited": ('supplies', 'are', 'limited'),
    "supply": ('supply',),
    "take": ('take',),
    "take action": ('take', 'action'),
    "take action now": ('take', 'action', 'now'),
    "target": ('target',),
    "terms": ('terms',),
    "terms and conditions": ('terms', 'and', 'conditions'),
    "the": ('the',),
    "this": ('this',),
    "this isn’t a scam": ('this', 'isn', '’', 't', 'a', 'scam'),
    "this isn’t junk": ('this', 'isn', '’', 't', 'junk'),
    "this isn’t spam": ('this', 'isn', '’', 't', 'spam'),
    "this won’t last": ('this', 'won', '’', 't', 'last'),
    "time": ('time',),
    "time limited": ('time', 'limited'),
    "today": ('today',),
    "to": ('to',),
    "trader": ('trader',),
    "trading": ('trading',),
    "traffic": ('traffic',),
    "transfer": ('transfer',),
    "trial": ('trial',),
    "trip": ('trip',),
    "undisclosed": ('undisclosed',),
    "unlimited": ('unlimited',),
    "unsecured": ('unsecured',),
    "unsecured credit": ('unsecured', 'credit'),
    "unsecured debt": ('unsecured', 'debt'),
    "unsolicited": ('unsolicited',),
    "unsubscribe": ('unsubscribe',),
    "up": ('up',),
    "up?": ('up', '?'),
    "urgent": ('urgent',),
    "user": ('user',),
    "valium": ('valium',),
    "valued": ('valued',),
    "verify": ('verify',),
    "viagra": ('viagra',),
    "vicodin": ('vicodin',),
    "videos": ('videos',),
    "vids": ('vids',),
    "viedo": ('viedo',),
    "virus": ('virus',),
    "waiting": ('waiting',),
    "wallet": ('wallet',),
    "warranty": ('warranty',),
    "we": ('we',),
    "we hate spam": ('we', 'hate', 'spam'),
    "web": ('web',),
    "web traffic": ('web', 'traffic'),
    "weight": ('weight',),
    "weight loss": ('weight', 'loss'),
    "what": ('what',),
    "what are you waiting for?": ('what', 'are', 'you', 'waiting', 'for', '?'),
    "what's": ('what', "'s"),
    "what's up?": ('what', "'s", 'up', '?'),
    "while": ('while',),
    "while supplies last": ('while', 'supplies', 'last'),
    "will": ('will',),
    "will not believe your eyes": ('will', 'not', 'believe', 'your', 'eyes'),
    "win": ('win',),
    "winner": ('winner',),
    "winning": ('winning',),
    "wire": ('wire',),
    "wire transfer": ('wire', 'transfer'),
    "with": ('with',),
    "without": ('without',),
    "won’t": ('won', '’', 't'),
    "work": ('work',),
    "work from home": ('work', 'from', 'home'),
    "x days": ('x', 'days'),
    "x hours": ('x', 'hours'),
    "xanax": ('xanax',),
    "you": ('you',),
    "you are a winner": ('you', 'are', 'a', 'winner'),
    "you have been selected": ('you', 'have', 'been', 'selected'),
    "you?": ('you', '?'),
    "your": ('your',),
    "yourself": ('yourself',)
}


'''
Define heuristics for finding label field
'''
LABEL_FIELDS_BLACKLIST = set(['CustomFields', 'ShardID', 'account', 'activated', 'attachment', 'autime', 'canvases',
                              'category', 'closeNotes', 'closed', 'closingUserId', 'created', 'criticalassets',
                              'dbotCreatedBy', 'details', 'detectionsla', 'droppedCount', 'dueDate', 'emailbody',
                              'emailheaders', 'emailsubject', 'hasRole', 'id', 'investigationId', 'isPlayground',
                              'labels', 'lastJobRunTime', 'lastOpen', 'linkedCount', 'linkedIncidents', 'modified',
                              'name', 'notifyTime', 'occurred', 'openDuration', 'owner', 'parent', 'phase',
                              'playbookId', 'previousRoles', 'rawCategory', 'rawCloseReason', 'rawJSON', 'rawName',
                              'rawPhase', 'rawType', 'reason', 'remediationsla', 'reminder', 'roles', 'runStatus',
                              'severity', 'sla', 'sortValues', 'sourceBrand', 'sourceInstance',
                              'status', 'timetoassignment', 'type', 'urlsslverification', 'version'])
LABEL_VALUES_KEYWORDS = ['spam', 'malicious', 'legit', 'false', 'positive', 'phishing', 'fraud', 'internal', 'test']

'''
Define html tags to count
'''
HTML_TAGS = ["a", "abbr", "acronym", "address", "area", "b", "base", "bdo", "big", "blockquote", "body", "br", "button",
             "caption", "cite", "code", "col", "colgroup", "dd", "del", "dfn", "div", "dl", "DOCTYPE", "dt", "em",
             "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "head", "html",
             "hr", "i", "img", "input", "ins", "invalidtag", "kbd", "label", "legend", "li", "link", "map", "meta",
             "noscript", "object", "ol", "optgroup", "option", "p", "param", "pre", "q", "samp", "script", "section",
             "select", "small", "span", "strong", "style", "sub", "sup", "table", "tbody", "td", "textarea", "tfoot",
             "th", "thead", "title", "tr", "tt", "ul", "var"]
HTML_TAGS = set(HTML_TAGS)

'''
Define known shortened and drive domains
'''

DRIVE_URL_KEYWORDS = ['drive', 'transfer', 'formplus', 'dropbox', 'sendspace', 'onedrive', 'box', 'pcloud', 'icloud',
                      'mega', 'spideroak', 'sharepoint']
SHORTENED_DOMAINS = set(
    ["adf.ly", "t.co", "goo.gl", "adbooth.net", "adfoc.us", "bc.vc", "bit.ly", "j.gs", "seomafia.net", "adlock.in",
     "adbooth.com", "cutt.us", "is.gd", "cf.ly", "ity.im", "tiny.cc", "adfa.st", "budurl.com", "soo.gd",
     "prettylinkpro.com", "shrinkonce.com", "ad7.biz", "2tag.nl", "1o2.ir", "hotshorturl.com", "onelink.ir", "dai3.net",
     "9en.us", "kaaf.com", "rlu.ru", "awe.sm", "4ks.net", "s2r.co", "4u2bn.com", "multiurl.com", "tab.bz", "dstats.net",
     "iiiii.in", "nicbit.com", "l1nks.org", "at5.us", "bizz.cc", "fur.ly", "clicky.me", "magiclinker.com",
     "miniurl.com", "bit.do", "adurl.biz", "omani.ac", "1y.lt", "1click.im", "1dl.us", "4zip.in", "ad4.us", "adfro.gs",
     "adnld.com", "adshor.tk", "adspl.us", "adzip.us", "articleshrine.com", "asso.in", "b2s.me", "bih.cc", "biturl.net",
     "buraga.org", "cc.cr", "cf6.co", "dollarfalls.info", "domainonair.com", "gooplu.com", "hide4.me", "ik.my",
     "ilikear.ch", "infovak.com", "itz.bz", "jetzt-hier-klicken.de", "kly.so", "lst.bz", "mrte.ch",
     "multiurlscript.com", "nowlinks.net", "nsyed.com", "ooze.us", "ozn.st", "scriptzon.com", "short2.in",
     "shortxlink.com", "shr.tn", "shrt.in", "sitereview.me", "sk.gy", "snpurl.biz", "socialcampaign.com", "swyze.com",
     "theminiurl.com", "tinylord.com", "tinyurl.ms", "tip.pe", "ty.by"])


def find_label_fields_candidates(incidents_df):
    candidates = [col for col in list(incidents_df) if
                  sum(isinstance(x, str) for x in incidents_df[col]) > 0.5 * len(incidents_df)]
    candidates = [col for col in candidates if col not in LABEL_FIELDS_BLACKLIST]

    candidate_to_values = {col: incidents_df[col].unique() for col in candidates}
    candidate_to_values = {col: values for col, values in candidate_to_values.items() if
                           all(isinstance(v, str) for v in values)}

    # filter columns by unique values count
    candidate_to_values = {col: values for col, values in candidate_to_values.items() if 0 < len(values) < 15}
    candidate_to_values = {col: [v.lower() for v in values] for col, values in candidate_to_values.items()}
    candidate_to_score = {col: 0 for col in candidate_to_values}
    for col, values in candidate_to_values.items():
        for v in values:
            if any(w in v for w in LABEL_VALUES_KEYWORDS):
                candidate_to_score[col] += 1
    return [k for k, v in sorted(candidate_to_score.items(), key=lambda item: item[1], reverse=True)]


def get_text_from_html(html):
    soup = BeautifulSoup(html)
    # kill all script and style elements
    for script in soup(["script", "style"]):
        script.extract()  # rip it out
    # get text
    text = soup.get_text()
    # break into lines and remove leading and trailing space on each
    lines = (line.strip() for line in text.splitlines())
    # break multi-headlines into a line each
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    # drop blank lines
    text = '\n'.join(chunk for chunk in chunks if chunk)
    return text


def get_vocab_features(text, ngrams_counter):
    global word_to_ngram, word_to_regex
    vocav_features = {}
    for word, regex in word_to_regex.items():
        count = len(re.findall(regex, text))
        if count > 0:
            vocav_features[word] = count
    for word, ngram in word_to_ngram.items():
        count = ngrams_counter[ngram] if ngram in ngrams_counter else 0
        if count > 0:
            vocav_features[word] = count
    return vocav_features


def get_lexical_features(email_subject, email_body, email_body_word_tokenized, email_subject_word_tokenized):
    words = [w for w in email_body_word_tokenized if any(c.isalnum() for c in w)]
    num_of_words = len(words)
    avg_word_length = 0 if len(words) == 0 else float(sum([len(w) for w in words])) / len(words)
    sentences = sent_tokenize(email_body)
    num_of_sentences = len(sentences)
    avg_sentence_length = 0 if len(sentences) == 0 else float(sum([len(s) for s in sentences])) / len(sentences)
    text_length = len(email_body)
    subject_length = len(email_subject)
    number_of_lines = email_body.count('\n') + 1
    word_subject = [w for w in email_subject_word_tokenized if any(c.isalnum() for c in w)]
    num_of_words_subject = len(word_subject)
    ending_dots = len([s for s in sentences if s.strip().endswith('.')])
    ending_explanation = len([s for s in sentences if s.strip().endswith('!')])
    ending_question = len([s for s in sentences if s.strip().endswith('?')])

    return {'num_of_words': num_of_words,
            'avg_word_length': avg_word_length,
            'num_of_sentences': num_of_sentences,
            'avg_sentence_length': avg_sentence_length,
            'avg_number_of_words_in_sentence': float(num_of_words) / num_of_sentences if num_of_sentences > 0 else 0,
            'text_length': text_length,
            'num_of_words_subject': num_of_words_subject,
            'subject_length': subject_length,
            'ending_dots': ending_dots,
            'ending_explanation': ending_explanation,
            'ending_question': ending_question,
            'number_of_lines': number_of_lines
            }


def get_characters_features(text):
    characters_count = {}
    for c in string.printable:
        if c in ['[', ']', '<']:
            continue
        count = text.count(c)
        if count > 0:
            characters_count[c] = count
    return characters_count


def get_url_features(email_body, email_html, soup):
    http_regex = r'http://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    https_regex = r'https://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    http_urls = re.findall(http_regex, email_body)
    https_urls = re.findall(https_regex, email_body)
    embedded_urls = [a['href'] for a in soup.findAll('a')]
    all_urls = http_urls + https_urls + embedded_urls
    all_urls_lengths = [len(u) for u in all_urls]
    average_url_length = 0 if len(all_urls) == 0 else sum(all_urls_lengths) / len(all_urls)
    min_url_length = 0 if len(all_urls_lengths) == 0 else min(all_urls_lengths)
    max_url_length = 0 if len(all_urls_lengths) == 0 else max(all_urls_lengths)
    shortened_urls_count = len([u for u in all_urls if any(shortened_u in u for shortened_u in SHORTENED_DOMAINS)])
    drive_count = len([u for u in all_urls if any(drive in u for drive in DRIVE_URL_KEYWORDS)])
    return {
        'http_urls_count': len(http_urls),
        'https_urls_count': len(https_urls),
        'embedded_urls_count': len(embedded_urls),
        'all_urls_count': len(all_urls),
        'average_url_length': average_url_length,
        'min_url_length': min_url_length,
        'max_url_length': max_url_length,
        'shortened_urls_count': shortened_urls_count,
        'drive_count': drive_count
    }


def get_html_features(soup):
    global HTML_TAGS
    html_counter = Counter([tag.name for tag in soup.find_all()])
    for t in HTML_TAGS:
        html_counter[t] = 0 if t not in html_counter else html_counter[t]
    html_counter = {k: v for k, v in html_counter.items() if k in HTML_TAGS}
    return html_counter


def get_ml_features(tokenized_text):
    global EMBEDDING_DICT
    if EMBEDDING_DICT is None:
        with open('/var/glove_top_20k.p', 'rb') as file:
            EMBEDDING_DICT = pickle.load(file)
    vectors = [EMBEDDING_DICT[w] for w in tokenized_text if w in EMBEDDING_DICT]
    if len(vectors) == 0:
        mean_vector = np.zeros(50)
    else:
        mean_vector = np.mean(vectors, axis=0)
    res = {'glove_avg_{}'.format(i): mean_vector[i].item() for i in range(len(mean_vector))}
    return res


def get_header_value(email_headers, header_name, index=0, ignore_case=False):
    if ignore_case:
        header_name = header_name.lower()
        headers_with_name = [header_dict for header_dict in email_headers if header_dict['name'].lower() == header_name]
    else:
        headers_with_name = [header_dict for header_dict in email_headers if header_dict['name'] == header_name]
    if len(headers_with_name) == 0:
        return None
    else:
        return headers_with_name[index]['value']


def get_headers_features(email_headers):
    spf_result = get_header_value(email_headers, header_name='Received-SPF')
    if spf_result is not None:
        spf_result = spf_result.split()[0].lower()
    else:
        spf_result = 'other'
    res_spf = {k: 0 for k in ['none', 'neutral', 'pass', 'fail', 'softfail', 'other', 'temperror', 'permerror']}
    if spf_result in res_spf:
        res_spf[spf_result] += 1
    else:
        res_spf['other'] += 1
    res_spf['non-positive'] = spf_result in set(['none', 'fail', 'softfail'])
    authentication_results = get_header_value(email_headers, header_name='Authentication-Results')
    if authentication_results is not None:
        if 'dkim=' in authentication_results:
            dkim_result = authentication_results.split('dkim=')[-1].split()[0].lower().strip()
        else:
            dkim_result = 'other'
    else:
        dkim_result = 'other'
    res_dkim = {k: 0 for k in ['none', 'neutral', 'pass', 'fail', 'softfail', 'other', 'temperror', 'permerror']}
    if dkim_result in res_dkim:
        res_dkim[dkim_result] += 1
    else:
        res_dkim['other'] += 1
    res_dkim['non-positive'] = spf_result in set(['none', 'fail', 'softfail'])
    list_unsubscribe = get_header_value(email_headers, header_name='List-Unsubscribe')
    unsubscribe_post = get_header_value(email_headers, header_name='List-Unsubscribe-Post-SPF')
    res_unsubscribe = 1 if list_unsubscribe is not None or unsubscribe_post is not None else 0
    from_value = get_header_value(email_headers, header_name='From')
    return_path_value = get_header_value(email_headers, header_name='Return-Path')
    last_received_value = get_header_value(email_headers, header_name='Received', index=-1)
    if from_value is not None:
        from_address = re.findall(r'<\S+>', from_value)[0][1:-1]
    else:
        from_address = ''
    if return_path_value is not None:
        return_path_adress = return_path_value.strip().lstrip('<').rstrip('>').strip()
    else:
        return_path_adress = ''
    if last_received_value is not None:
        received_address_list = re.findall(r'(?<=from )\S+', last_received_value)
        if len(received_address_list) > 0:
            received_address = received_address_list[0]
        else:
            received_address = ''
    else:
        received_address = ''
    try:
        from_domain = from_address.split('@')[-1].split('.')[-2] if from_address != '' else ''
    except Exception:
        print('error on from_address: {}'.format(from_address))
        from_domain = ''

    if from_address == '':
        return_path_same_as_from = float('nan')
    else:
        return_path_same_as_from = from_address == return_path_adress

    if from_domain == '' or received_address == '':
        from_domain_with_received = float('nan')
    else:
        from_domain_with_received = from_domain in received_address
    received_res = {}
    recevied_headers = [header_dict for header_dict in email_headers if header_dict['name'] == 'Received']
    count_received = len(recevied_headers)
    received_res['count_received'] = count_received
    content_type_value = get_header_value(email_headers, header_name='Content-Type', index=0, ignore_case=True)
    if content_type_value is not None and ';' in content_type_value:
        content_type_value = content_type_value.split(';')[0]
    adress_res = {
        'return_path_same_as_from': return_path_same_as_from,
        'from_domain_with_received': from_domain_with_received
    }
    res = {}
    for k, v in res_spf.items():
        res['spf::{}'.format(k)] = v
    for k, v in res_dkim.items():
        res['dkim::{}'.format(k)] = v
    res['unsubscribe_headers'] = res_unsubscribe
    for k, v in adress_res.items():
        res[k] = v  # type: ignore
    for k, v in received_res.items():
        res[k] = v
    res['content-type::{}'.format(content_type_value)] = 1
    return res


def get_attachments_features(email_attachments):
    res = {}
    res['number_of_attachments'] = len(email_attachments)
    all_attachments_names = []
    for a in email_attachments:
        attachment_name = a['name']
        if attachment_name is not None:
            all_attachments_names.append(attachment_name.lower())
    all_attachments_names_lengths = [len(name) for name in all_attachments_names]
    res['min_attachment_name_length'] = min(all_attachments_names_lengths) if len(
        all_attachments_names_lengths) > 0 else 0
    res['max_attachment_name_length'] = max(all_attachments_names_lengths) if len(
        all_attachments_names_lengths) > 0 else 0
    res['avg_attachment_name_length'] = float(sum(all_attachments_names_lengths)) / len(  # type: ignore
        all_attachments_names_lengths) if len(all_attachments_names_lengths) > 0 else 0  # type: ignore
    res['image_extension'] = 0
    for image_format in ['.jepg', '.gif', '.bmp', '.png']:
        res['image_extension'] += sum([name.endswith(image_format) for name in all_attachments_names])
    res['txt_extension'] = sum([name.endswith('.txt') for name in all_attachments_names])
    res['exe_extension'] = sum([name.endswith('.exe') for name in all_attachments_names])
    res['archives_extension'] = sum(
        [name.endswith('.zip') or name.endswith('.rar') or name.endswith('.lzh') or name.endswith('.7z') for name in
         all_attachments_names])
    res['pdf_extension'] = sum([name.endswith('.pdf') for name in all_attachments_names])
    res['disk_img_extension'] = sum([name.endswith('.iso') or name.endswith('.img') for name in all_attachments_names])
    res['other_executables_extension'] = sum(
        [any(name.endswith(ext) for ext in ['.jar', '.bat', '.psc1', '.vb', '.vbs', '.msi', '.cmd', '.reg', '.wsf']) for
         name in all_attachments_names])

    res['office_extension'] = 0
    for offic_format in ['.doc', '.xls', '.ppt', 'xlsx', 'xlsm']:
        res['office_extension'] += sum([name.endswith(offic_format) for name in all_attachments_names])
    return res


def transform_text_to_ngrams_counter(email_body_word_tokenized, email_subject_word_tokenized):
    text_ngram = []
    for n in range(1, 4):
        text_ngram += list(ngrams(email_body_word_tokenized, n))
        text_ngram += list(ngrams(email_subject_word_tokenized, n))
    text_ngrams = Counter(text_ngram)
    return text_ngrams


def extract_features_from_incident(row):
    global EMAIL_BODY_FIELD, EMAIL_SUBJECT_FIELD, EMAIL_HTML_FIELD, EMAIL_ATTACHMENT_FIELD, EMAIL_HEADERS_FIELD
    email_body = row[EMAIL_BODY_FIELD] if EMAIL_BODY_FIELD in row else ''
    email_subject = row[EMAIL_SUBJECT_FIELD] if EMAIL_SUBJECT_FIELD in row else ''
    email_html = row[EMAIL_HTML_FIELD] if EMAIL_HTML_FIELD in row else ''
    email_headers = row[EMAIL_HEADERS_FIELD] if EMAIL_HEADERS_FIELD in row else {}
    email_attachments = row[EMAIL_ATTACHMENT_FIELD] if EMAIL_ATTACHMENT_FIELD in row else []
    email_attachments = email_attachments if email_attachments is not None else []
    if email_body is None or email_body.strip() == '' or isinstance(email_body, float):
        email_body = get_text_from_html(email_html)
    if isinstance(email_html, float):
        email_html = ''
    if isinstance(email_subject, float):
        email_subject = ''
    email_body, email_subject = email_body.strip().lower(), email_subject.strip().lower()
    text = email_subject + ' ' + email_body
    email_body_word_tokenized = word_tokenize(email_body)
    email_subject_word_tokenized = word_tokenize(email_subject)
    text_ngrams = transform_text_to_ngrams_counter(email_body_word_tokenized, email_subject_word_tokenized)
    vocab_features = get_vocab_features(text, text_ngrams)
    soup = BeautifulSoup(email_html, "html.parser")

    lexical_features = get_lexical_features(email_subject, email_body, email_body_word_tokenized,
                                            email_subject_word_tokenized)
    characters_features = get_characters_features(text)
    html_feature = get_html_features(soup)
    ml_features = get_ml_features(email_body_word_tokenized + email_subject_word_tokenized)
    headers_features = get_headers_features(email_headers)
    url_feautres = get_url_features(email_body=email_body, email_html=email_html, soup=soup)
    attachments_features = get_attachments_features(email_attachments=email_attachments)

    return {
        'vocab_features': vocab_features,
        'lexical_features': lexical_features,
        'characters_features': characters_features,
        'html_feature': html_feature,
        'ml_features': ml_features,
        'headers_features': headers_features,
        'url_features': url_feautres,
        'attachments_features': attachments_features
    }


def extract_features_from_all_incidents(incidents_df):
    X = {  # type: ignore
        'vocab_features': [],
        'lexical_features': [],
        'characters_features': [],
        'html_feature': [],
        'ml_features': [],
        'headers_features': [],
        'url_features': [],
        'attachments_features': []
    }   # type: ignore
    exceptions_log = []
    exception_indices = set()
    timeout_indices = set()

    for index, row in incidents_df.iterrows():
        signal.alarm(5)
        try:
            X_i = extract_features_from_incident(row)
            for k, v in X_i.items():
                X[k].append(v)
        except TimeoutException:
            timeout_indices.add(index)
        except Exception:
            exception_indices.add(index)
            exceptions_log.append(traceback.format_exc())
        finally:
            signal.alarm(0)
    return X, exceptions_log, exception_indices, timeout_indices


def extract_data_from_incidents(incidents):
    incidents_df = pd.DataFrame(incidents)
    label_fields = find_label_fields_candidates(incidents_df)
    y = []
    for i, label in enumerate(label_fields):
        y.append({'field_name': label,
                  'rank': '#{}'.format(i + 1),
                  'values': incidents_df[label].tolist()})
    incidents_df.dropna(how='all', subset=label_fields, inplace=True)
    X, exceptions_log, exception_indices, timeout_indices = extract_features_from_all_incidents(incidents_df)
    indices_to_drop = exception_indices.union(timeout_indices)
    for label_dict in y:
        label_dict['values'] = [l for i, l in enumerate(label_dict['values']) if i not in indices_to_drop]
    return {'X': X,
            'y': y,
            'log':
                {'exceptions': exceptions_log,
                 'n_timout': len(timeout_indices),
                 'n_other_exceptions': len(exception_indices)}
            }


def return_json_entry(obj):
    entry = {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": obj,
    }
    demisto.results(entry)


def get_args_based_on_last_execution():
    lst = demisto.executeCommand('getList', {'listName': LAST_EXECUTION_LIST_NAME})
    if isError(lst[0]):  # if first execution
        return {'limit': MAX_INCIDENTS_TO_FETCH_FIRST_EXECUTION}
    else:
        last_execution_datetime = datetime.strptime(lst[0]['Contents'], DATETIME_FORMAT)
        query = 'modified:>="{}"'.format(datetime.strftime(last_execution_datetime, MODIFIED_TIMEFORMAT))
        max_incidents_to_fetch = MAX_INCIDENTS_TO_FETCH_PERIODIC_EXECUTION
        return {'limit': max_incidents_to_fetch,
                'query': query}


def update_last_execution_time():
    demisto.results('here')
    execution_datetime_str = datetime.strftime(datetime.now(), DATETIME_FORMAT)
    res = demisto.executeCommand("createList", {"listName": LAST_EXECUTION_LIST_NAME, "listData": execution_datetime_str})
    demisto.results(res)

def main():
    incidents_query_args = demisto.args()
    args = get_args_based_on_last_execution()
    incidents_query_args.update(args)
    incidents_query_res = demisto.executeCommand('GetIncidentsByQuery', incidents_query_args)
    if is_error(incidents_query_res):
        return_error(get_error(incidents_query_res))
    incidents = json.loads(incidents_query_res[-1]['Contents'])
    data = extract_data_from_incidents(incidents)
    encoded_data = json.dumps(data).encode('utf-8', errors='ignore')
    compressed_data = zlib.compress(encoded_data, 4)
    compressed_hr_data = b64encode(compressed_data).decode('utf-8')
    res = {'PayloadVersion': FETCH_DATA_VERSION, 'PayloadData': compressed_hr_data}
    return_json_entry(res)
    update_last_execution_time()


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

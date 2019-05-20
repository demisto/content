import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import socket
import socks
import whois
from urlparse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# flake8: noqa

''' GLOBAL VARS '''
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


PROXY = demisto.params()['proxy']
# Setting proxy to be used in Socks
if PROXY is True:
    proxy_url = os.environ.get('HTTPS_PROXY', None)
    if proxy_url:
        uri = urlparse(proxy_url)
        socks.set_default_proxy(socks.PROXY_TYPE_HTTP, uri.hostname, uri.port)
        socket.socket = socks.socksocket
DOMAIN = demisto.args().get('query')


''' HELPER FUNCTIONS '''
# Returns an item in a list at a given index
def list_tool(item, list, number):
    if isinstance(item, list):
        return str(item[number])
    else:
        return item

# converts inputs into a string w/o u' prepended
def my_converter(obj):
    if isinstance(obj, datetime):
        return obj.__str__()
    else:
        return obj

# Converts a list of time objects into human readable format
def time_list_tool(obj):
    tformat = '%m/%d/%Y %H:%M:%S %p'
    if obj is not None and isinstance(obj, list):
        for string in obj:
            my_converter(string)
        return string
    else:
        return obj


'''COMMANDS'''
def whois_command():
    try:
        whois_result = whois.whois(DOMAIN)
        md = {}
        try:
          for key in whois_result:
              value = whois_result[key]
              value = my_converter(value)
              key = string_to_table_header(key)
              md.update({key: value})
        except:
          demisto.results('No result was found for {}'.format(DOMAIN))
        ec = {}
        ec.update({
            'Domain': {
                'Name': str(list_tool(whois_result.domain_name, list, 0)),
                'Whois': {
                    'Domain': str(list_tool(whois_result.domain_name, list, 0)),
                    'DomainStatus': whois_result.status,
                    'DNSSec': str(whois_result.dnssec),
                    'Raw': str(whois_result),
                    'NameServers': whois_result.name_servers,
                    'CreationDate': str(time_list_tool(whois_result.creation_date)),
                    'UpdatedDate': str(time_list_tool(whois_result.updated_date)),
                    'ExpirationDate': str(time_list_tool(whois_result.expiration_date)),
                    'Registrar': {
                        'Name': str(whois_result.registrar),
                        'AbuseEmail': str(list_tool(whois_result.emails, list, 0))
                    },
                    'Registrant': {
                        'Name': str(whois_result.get('name')),
                        'Email': str(list_tool(whois_result.emails, list, 1))
                    }
                }
            }
        })
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': str(whois_result),
            'HumanReadable': tableToMarkdown('Whois results for {}'.format(DOMAIN), md, removeNull=True),
            'EntryContext': createContext(ec, removeNull=True)
            })
    except OSError as msg:
        return_error(msg)


def test_command():
    try:
        whois_result = whois.whois('google.com')

        domain_test = list_tool(whois_result.domain_name, list, 1)

        if domain_test == 'google.com':
            demisto.results('ok')
    except:
        demisto.results('error')


''' EXECUTION CODE '''
LOG('command is %s' % (demisto.command(), ))
try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_command()
    elif demisto.command() == 'whois':
        whois_command()
except Exception as e:
    LOG(e)
    LOG.print_log(False)
    return_error(e.message)

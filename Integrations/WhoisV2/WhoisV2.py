import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import whopy

'''COMMANDS'''


def whois_command(domain):
    whois_result = whopy.get_whois(domain)
    md = {'Name': domain}
    ec = {'Name': domain}
    if 'status' in whois_result:
        ec['DomainStatus'] = whois_result.get('status')
        md['Domain Status'] = whois_result.get('status')
    if 'raw' in whois_result:
        ec['Raw'] = whois_result.get('raw')
    if 'nameservers' in whois_result:
        ec['NameServers'] = whois_result.get('nameservers')
        md['NameServers'] = whois_result.get('nameservers')
    if 'creation_date' in whois_result:
        ec['CreationDate'] = whois_result.get('creation_date')[0].strftime('%d-%m-%Y')
        md['Creation Date'] = whois_result.get('creation_date')[0].strftime('%d-%m-%Y')
    if 'updated_date' in whois_result:
        ec['UpdatedDate'] = whois_result.get('updated_date')[0].strftime('%d-%m-%Y')
        md['Updated Date'] = whois_result.get('updated_date')[0].strftime('%d-%m-%Y')
    if 'expiration_date' in whois_result:
        ec['ExpirationDate'] = whois_result.get('expiration_date')[0].strftime('%d-%m-%Y')
        md['Expiration Date'] = whois_result.get('expiration_date')[0].strftime('%d-%m-%Y')
    if 'registrar' in whois_result:
        ec.update({'Registrar': {'Name': whois_result.get('registrar')}})
        md['Registrar'] = whois_result.get('registrar')
    if 'id' in whois_result:
        ec['ID'] = whois_result.get('id')
        md['ID'] = whois_result.get('id')
    if 'contacts' in whois_result:
        contacts = whois_result['contacts']
        if 'registrant' in contacts and contacts['registrant'] is not None:
            md['Registrant'] = contacts['registrant']
            ec['Registrant'] = contacts['registrant']
        if 'admin' in contacts and contacts['admin'] is not None:
            md['Administrator'] = contacts['admin']
            ec['Administrator'] = contacts['admin']
        if 'tech' in contacts and contacts['tech'] is not None:
            md['Tech Admin'] = contacts['tech']
            ec['TechAdmin'] = contacts['tech']
        if 'billing' in contacts and contacts['billing'] is not None:
            md['Billing Admin'] = contacts['billing']
            ec['BillingAdmin'] = contacts['billing']
    if 'emails' in whois_result:
        ec['Emails'] = whois_result.get('emails')
        md['Emails'] = whois_result.get('emails')

    context = ({
        'Domain': {
            'Name': domain
        },
        'Domain.Whois(val.Name && val.Name == obj.Name)': ec
    })

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': str(whois_result),
        'HumanReadable': tableToMarkdown('Whois results for {}'.format(domain), md, removeNull=True),
        'EntryContext': context
    })


def test_command():
    whois_result = whopy.get_whois('google.com')

    domain_test = whois_result.get('id')

    if domain_test == '2138514_DOMAIN_COM-VRSN':
        demisto.results('ok')


''' EXECUTION CODE '''
LOG('command is %s' % (demisto.command(),))
try:
    if demisto.command() == 'test-module':
        test_command()
    elif demisto.command() == 'whois':
        whois_command(demisto.args().get('query'))
except (RuntimeError, TypeError, NameError) as e:
    LOG(e)
    LOG.print_log(False)
    return_error(e.message)

import demistomock as demisto
from CommonServerPython import *
import tempfile

''' IMPORTS '''
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''

ALERT_TITLE = 'Prisma Compute Alert - '
ALERT_TYPE_VULNERABILITY = 'vulnerability'
ALERT_TYPE_COMPLIANCE = 'compliance'


''' COMMANDS + REQUESTS FUNCTIONS '''


class Client(BaseClient):
    def test(self):
        return self._http_request(
            method='GET',
            url_suffix='/demisto-alerts',
            params={'to': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(0))})

    def list_incidents(self):
        return self._http_request(
            method='GET',
            url_suffix='/demisto-alerts')


def translate_severity(sev):
    """
    Translates Prisma Compute alert severity into Demisto's severity score
    """
    sev = sev.capitalize()

    if sev == 'Critical':
        return 4
    elif sev == 'High':
        return 3
    elif sev == 'Important':
        return 3
    elif sev == 'Medium':
        return 2
    elif sev == 'Low':
        return 1
    return 0


def cammel_case_transformer(header):
    """
    e.g. input: 'camelCase' output: 'Camel Case '

    """

    return re.sub("([a-z])([A-Z])", "\g<1> \g<2>", header).capitalize()


def test_module(client):
    """
    Test connection, authentication and user authorization
    Args:
        client: Prisma Compute client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    client.test()
    return 'ok'


def fetch_incidents(client):
    incidents = []
    alerts = client.list_incidents()

    if alerts:
        for a in alerts:
            alert_type = a.get('type')
            name = ALERT_TITLE
            severity = 0

            tables = {}
            for key, value in a.items():
                if isinstance(value, list):
                    tables[key + 'MarkdownTable'] = tableToMarkdown(cammel_case_transformer(key + ' table'), value, headerTransform=cammel_case_transformer)

            a.update(tables)

            if alert_type == ALERT_TYPE_VULNERABILITY:
                # vulnerabilities = a.get('vulnerabilities')
                # a['vulnerabilitiesMarkdownTable'] = tableToMarkdown('Discovered Vulnerabilities', vulnerabilities, headerTransform=cammel_case_transformer)
                name += cammel_case_transformer(alert_type) + ' in ' + a.get('imageName')
                # severity = translate_severity(vulnerabilities[0].get('severity'))

            elif alert_type == ALERT_TYPE_COMPLIANCE:
                entity = a.get('entityType')
                table_name = '%s new compliance' % entity
                name += cammel_case_transformer(entity) + ' '
                # a['complianceMarkdownTable'] = tableToMarkdown(table_name, a.get('data'), headerTransform=cammel_case_transformer)
            else:
                name += cammel_case_transformer(alert_type)

            incidents.append({
                'name': name,
                'occurred': a.get('time'),
                'severity': severity,
                'rawJSON': json.dumps(a)
            })

    return incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    base_url = urljoin(params.get('address'), '/api/v1')
    verify_certificate = not params.get('insecure', False)
    cert = params.get('certificate')
    proxy = params.get('proxy', False)

    LOG(f'verify  {verify_certificate}, cert {cert}, type {type(cert)}')

    if verify_certificate and cert:
        tmp = tempfile.NamedTemporaryFile(delete=False, mode='w')
        tmp.write(cert)
        tmp.close()
        verif = tmp.name
    else:
        verif = verify_certificate

    try:
        LOG(f'Command being called is {demisto.command()}')

        client = Client(
            base_url=base_url,
            verify=verif,
            auth=(username, password),
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            incidents = fetch_incidents(client)
            demisto.incidents(incidents)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')

   # finally:
    #    if verify:
     #       os.unlink(tmp.name)
      #      tmp.close()

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

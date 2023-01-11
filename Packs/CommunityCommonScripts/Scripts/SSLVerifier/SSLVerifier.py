import json
import socket
import ssl
from datetime import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def results_return(command: str, item: dict):
    results = CommandResults(
        outputs_prefix=f'SSLVerifier.{command}',
        outputs_key_field='',
        outputs=item
    )
    return_results(results)


def get_cert_info(hostname: str, port: str) -> dict:
    data = {}
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
    s.connect((hostname, int(port)))
    cert: Any = s.getpeercert()
    issuer: str = json.dumps(cert['issuer'])
    jsonissuer = json.loads(
        issuer.replace('\",', '\":').replace('[[[', '{').replace(']]]', '}').replace('[[', '').replace(']]', ''))
    expiration_obj = datetime.strptime(str(cert['notAfter']), '%b %d %H:%M:%S %Y %Z')
    converteddate = datetime.strftime(expiration_obj, '%Y-%m-%dT%H:%M:%S.%fZ')
    now_obj = datetime.now()
    dateresults_obj = expiration_obj - now_obj
    days = int(dateresults_obj.days)
    data['Expiry'] = converteddate
    data['Site'] = hostname
    data['TimeToExpiration'] = f'{days} days'
    data['Issuer'] = jsonissuer['organizationName']
    return data


def main():
    hostname = demisto.args().get('URL')
    port = demisto.args().get('Port')
    try:
        results_return('Certificate', get_cert_info(hostname, port))
    except Exception as e:
        return_error(f'Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

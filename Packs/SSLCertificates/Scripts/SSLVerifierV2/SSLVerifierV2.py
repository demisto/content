import demistomock as demisto
from CommonServerPython import *
from typing import Any

from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import socket
import ssl


def results_return(command: str, item: list):
    results = CommandResults(
        outputs_prefix=f'SSLVerifierV2.{command}',
        outputs_key_field='',
        outputs=item
    )
    return_results(results)


def get_cert_info(hostname: str, port: str):
    varExcept = ""
    data = {}
    cert: Any
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL
    s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)

    try:
        s.connect((hostname, int(port)))
    except Exception as e:
        varExcept = str(e)
    finally:
        # Expired/Self-Signed/Unable-to-get-local-issuer errors
        if str.__contains__(varExcept, "certificate has expired") or str.__contains__(varExcept,
                                                                                      "self signed certificate") \
                or str.__contains__(varExcept, "unable to get local issuer certificate"):
            pem_cert = ssl.get_server_certificate((hostname, int(port)))
            cert_bytes = str.encode(pem_cert)
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            expiration_obj = datetime.strptime(str(cert.not_valid_after), '%Y-%m-%d %H:%M:%S')
            expiration_date = datetime.strftime(expiration_obj, '%Y/%m/%d - %H:%M:%S')
            now_obj = datetime.now()
            dateresults_obj = expiration_obj - now_obj
            days = int(dateresults_obj.days)
            data['Domain'] = hostname
            data['ExpirationDate'] = expiration_date
            data['TimeToExpiration'] = str(days)
        elif varExcept == "":
            cert = s.getpeercert()
            expiration_obj = datetime.strptime(str(cert['notAfter']), '%b %d %H:%M:%S %Y %Z')
            converteddate = datetime.strftime(expiration_obj, '%Y/%m/%d - %H:%M:%S')
            now_obj = datetime.now()
            dateresults_obj = expiration_obj - now_obj
            days = int(dateresults_obj.days)
            data['Domain'] = hostname
            data['ExpirationDate'] = converteddate
            data['TimeToExpiration'] = str(days)
        # Unhandled Exception
        else:
            return_error("Unhandled exception for hostname: " + hostname + ".\n\nRaw Error Message: " + varExcept)
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

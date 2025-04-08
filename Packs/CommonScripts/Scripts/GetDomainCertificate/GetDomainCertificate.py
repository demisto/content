import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ssl
import socket
from datetime import datetime


def SSL_info(domain: str, verbose: bool = False) -> dict:
    """
    Retrieve SSL certificate information for a given domain.

    Args:
        domain (str): The domain name to retrieve SSL certificate information for.
        verbose (bool, optional): If True, include the full certificate response in the output. Defaults to False.

    Returns:
        dict: A dictionary containing SSL certificate information, including issuer details, subject details,
              issue date, and expiry date. If verbose is True, it also includes the full certificate response.
              Returns an empty dictionary if there's an error retrieving the certificate.

    Raises:
        None: Exceptions are caught and logged, returning an empty dictionary in case of errors.
    """

    ca_info = {}

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443)) as sock, context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            version = ssock.version()

            if cert is None:
                return {}

            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            issue_date = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
            expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

            ca_info = {
                'domain': domain,
                'issuer_country': issuer.get('countryName', ''),
                'issuer_organization': issuer.get('organizationName', ''),
                'issuer_common_name': issuer.get('commonName', ''),
                'subject_country': subject.get('countryName', ''),
                'subject_organization': subject.get('organizationName', ''),
                'issue_date': issue_date.isoformat(),
                'expire_date': expiry_date.isoformat(),
                'version': version
            }

            if verbose:
                ca_info['full_response'] = cert

    except ssl.SSLCertVerificationError as e:
        demisto.debug(f"Error verifying certificate for {domain}: {e}")
        ca_info = {
            'domain': domain,
            'error': f"Error verifying certificate: {e.verify_message}"
        }

    except OSError as e:
        demisto.debug(f"Error retrieving certificate for {domain}: {str(e)}")

    return ca_info


def main():
    domains = argToList(demisto.args().get('domains'))
    verbose = demisto.args().get('verbose', 'false').lower() == 'true'
    results = []

    for domain in domains:
        ca_info = SSL_info(domain, verbose)

        if ca_info:
            results.append(
                CommandResults(
                    outputs_prefix='SSLInfo',
                    outputs_key_field='Domain',
                    outputs=ca_info,
                    readable_output=tableToMarkdown(
                        f'SSL Certificate Information for {domain}',
                        ca_info
                    ),
                )
            )
        else:
            return_results(
                f"Unable to retrieve SSL certificate information for {domain}. "
                "Please check the domain name or make sure it uses SSL (HTTPS)."
            )

    if results:
        for result in results:
            return_results(result)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

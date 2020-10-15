import os
import socket
import ssl
from pathlib import Path
from typing import List, Dict, Optional, Any

import demistomock as demisto  # noqa: F401
import pem
from CommonServerPython import *  # noqa: F401
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def parse_issuer_certificate_attr(certificate: x509.Name, oid: x509.ObjectIdentifier) -> Optional[List[str]]:
    """ Get attribute from decoded certificate.

    Args:
        certificate: Certificate as x509.Certificate .
        oid: Enum value from x509.NameOID .

    Returns:
        list: Decoded values.
    """
    attributes = [attr.value for attr in certificate.get_attributes_for_oid(oid)]

    return attributes if attributes else None


def certificate_to_ec(certificate_name: x509.Name) -> dict:
    """ Translate abstrcat object x509.Name to entry context.

    Args:
        certificate_name: Issuer or subject.

    Returns:
        dict: Corresponding enrty context.
    """
    return {
        # Contact details
        "EmailAddress": parse_issuer_certificate_attr(certificate_name, x509.NameOID.EMAIL_ADDRESS),
        "SurName": parse_issuer_certificate_attr(certificate_name, x509.NameOID.SURNAME),
        # Location related
        "CountryName": parse_issuer_certificate_attr(certificate_name, x509.NameOID.COUNTRY_NAME),
        "StateOrProvinceName": parse_issuer_certificate_attr(certificate_name, x509.NameOID.STATE_OR_PROVINCE_NAME),
        "LocalityName": parse_issuer_certificate_attr(certificate_name, x509.NameOID.LOCALITY_NAME),
        "JurisdictionCountryName": parse_issuer_certificate_attr(certificate_name,
                                                                 x509.NameOID.JURISDICTION_COUNTRY_NAME),
        "JurisdictionLocalityName": parse_issuer_certificate_attr(certificate_name,
                                                                  x509.NameOID.JURISDICTION_LOCALITY_NAME),
        "JurisdictionStateOrProvinceName": parse_issuer_certificate_attr(certificate_name,
                                                                         x509.NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME),
        "PostalAddress": parse_issuer_certificate_attr(certificate_name, x509.NameOID.POSTAL_ADDRESS),
        "PostalCode": parse_issuer_certificate_attr(certificate_name, x509.NameOID.POSTAL_CODE),
        "StreetAddress": parse_issuer_certificate_attr(certificate_name, x509.NameOID.STREET_ADDRESS),
        # Domain / URL
        "DomainNameQualifier": parse_issuer_certificate_attr(certificate_name, x509.NameOID.DN_QUALIFIER),
        "DomainComponent": parse_issuer_certificate_attr(certificate_name, x509.NameOID.DOMAIN_COMPONENT),
        "GenerationQualifier": parse_issuer_certificate_attr(certificate_name, x509.NameOID.GENERATION_QUALIFIER),
        "GivenName": parse_issuer_certificate_attr(certificate_name, x509.NameOID.GIVEN_NAME),
        "CommonName": parse_issuer_certificate_attr(certificate_name, x509.NameOID.COMMON_NAME),
        # Business
        "BusinessCategory": parse_issuer_certificate_attr(certificate_name, x509.NameOID.BUSINESS_CATEGORY),
        "OrganizationName": parse_issuer_certificate_attr(certificate_name, x509.NameOID.ORGANIZATION_NAME),
        "OrganizationalUnitName": parse_issuer_certificate_attr(certificate_name,
                                                                x509.NameOID.ORGANIZATIONAL_UNIT_NAME),
        # General
        "Title": parse_issuer_certificate_attr(certificate_name, x509.NameOID.TITLE),
        "SerialNumber": parse_issuer_certificate_attr(certificate_name, x509.NameOID.SERIAL_NUMBER),
        "Pseudonym": parse_issuer_certificate_attr(certificate_name, x509.NameOID.PSEUDONYM),
    }


def parse_certificate(certificate: str) -> dict:
    """ Decode certificate from

    Args:
        certificate: certificate as string.

    Returns:
        dict: Corresponding enrty context.
    """
    decode_certificate = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
    return {
        "Raw": certificate,
        "Decode": {
            "Issuer": certificate_to_ec(decode_certificate.issuer),
            "Subject": certificate_to_ec(decode_certificate.subject)
        }
    }


def parse_all_certificates(certifcates: str) -> List[Dict[Any, Any]]:
    """ Parse all certificates in a given string.

    Args:
        certifcates: certificates as a single string.

    Returns:
        list: Corresponding enrty context.
    """
    return [parse_certificate(cert.as_text()) for cert in pem.parse(certifcates.encode())]


def docker_container_details() -> dict:
    """ Gather docker container SSL/TLS Certificate information (Which set by demisto engine), The following details:
            1. Global veriables which used by requests module:
                a. SSL_CERT_FILE
                b. REQUESTS_CA_BUNDLE
            2. Custom python ssl file located in docker container - /etc/custom-python-ssl/certs.pem

    Returns:
        dict: Corresponding enrty context.
    """
    container_ca_file = Path('/etc/custom-python-ssl/certs.pem')
    certificates = "" if not container_ca_file.is_file() else container_ca_file.read_text()
    return {
        "ShellVariables": {
            "SSL_CERT_FILE": os.environ.get('SSL_CERT_FILE'),
            "CERT_FILE": os.environ.get('REQUESTS_CA_BUNDLE'),
        },
        "CustomCertificateAuthorities": parse_all_certificates(certificates),
    }


def get_certificate(endpoint: str, port: str) -> str:
    """Download certificate from remote server.

    Args:
        endpoint: url to get certificate from.
        port: endpoint port.

    Returns:
        str: certificate string in PEM format.
    """
    hostname = endpoint
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sock = context.wrap_socket(conn, server_hostname=hostname)
    sock.connect((hostname, int(port)))

    return ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))  # type: ignore


def endpoint_certificate(endpoint: str, port: str) -> dict:
    """ Get certificate issuer from endpoint.

    Args:
        endpoint: Enpoint url:port, if no port will be 443 by default.
        port: endpoint port.

    Returns:
        dict: Corresponding enrty context.
    """
    certificates = get_certificate(endpoint, port)
    return {
        "Identifier": endpoint,
        "Certificates": parse_all_certificates(certificates)
    }


def build_human_readable(entry_context: dict) -> str:
    human_readable = ""
    entry_context = entry_context.get("TroubleShoot", {})
    # Engine docker container
    engine: dict = dict_safe_get(entry_context, ['Engine', 'SSL/TLS'], {}, dict)
    human_readable += "## Docker container engine - custom certificate\n"
    readable_engine_issuer = [dict_safe_get(item, ('Decode', 'Issuer')) for item in
                              engine.get('CustomCertificateAuthorities', {})]
    readable_engine_subject = [dict_safe_get(item, ('Decode', 'Subject')) for item in
                               engine.get('CustomCertificateAuthorities', {})]
    readable_engine_vars = engine.get('ShellVariables')
    human_readable += tableToMarkdown(name="Enviorment variables", t=readable_engine_vars)
    human_readable += tableToMarkdown(name="Issuer", t=readable_engine_issuer, removeNull=True)
    human_readable += tableToMarkdown(name="Subject", t=readable_engine_subject, removeNull=True)
    # Endpoint
    endpoint: dict = entry_context.get('Endpoint', {}).get('SSL/TLS', {})
    readable_endpoint_issuer = [item.get('Decode').get('Issuer') for item in endpoint.get('Certificates', {})]
    readable_endpoint_subject = [item.get('Decode').get('Subject') for item in endpoint.get('Certificates', {})]
    human_readable += f"\n\n## Endpoint certificate - {endpoint.get('Identifier')}\n"
    human_readable += tableToMarkdown(name="Issuer", t=readable_endpoint_issuer, removeNull=True)
    human_readable += tableToMarkdown(name="Subject", t=readable_endpoint_subject, removeNull=True)
    human_readable += "\n"

    return human_readable


def main():
    try:
        entry_context = {
            "TroubleShoot": {
                'Engine': {
                    'SSL/TLS': docker_container_details(),
                },
                'Endpoint': {
                    'SSL/TLS': endpoint_certificate(demisto.getArg('endpoint'), demisto.getArg("port") or "443"),
                }
            }
        }
        human_readable = build_human_readable(entry_context)

        return_outputs(human_readable, entry_context, {})
    except Exception as e:
        return_error(f'Failed to execute Certificate Troubleshoot.\n Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

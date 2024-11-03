import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """
# Std imports

import re
# 3-rd party imports
from datetime import datetime

import urllib3

# Local imports
# N/A

"""

GLOBALS/PARAMS

Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written in all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'Keyfactor'
INTEGRATION_COMMAND_NAME = 'keyfactor'
INTEGRATION_CONTEXT_NAME = 'Keyfactor'

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):

    def test_module(self) -> dict:
        """
            Performs basic GET request to check if the API is reachable and authentication is successful.
        Returns:
            Response dictionary
        """
        return self.get_enrollment_csr_context_template()

    def get_enrollment_csr_context_template(self) -> dict:
        """
            Get enrollment CSR context my
            > Retrieve a list of existing certificate templates
        Args:
            N/A

        Returns:
            Json response as dictionary
        """

        headers = {
            'x-keyfactor-api-version': '1',
            'x-keyfactor-requested-with': 'APIClient',
            'Accept': 'application/json'
        }

        return self._http_request(method='GET',
                                  url_suffix='Enrollment/CSR/Context/My',
                                  headers=headers)

    def post_enrollment_csr(self,
                            csr_base64: str,
                            cert_authority: str,
                            include_chain: str,
                            time_stamp: str,
                            template: str,
                            sans_ip4: str,
                            keyAlgorithm: str,
                            metadata: dict) -> dict:
        """
            Post Enrollment CSR
            Send the certifcate CSR and return the certificate
        Args:
            csr_base64: The base-64 encoded CSR that will be passed in for enrollment.
            cert_authority:  A string that sets the name of the certificate authority
            include_chain: A Boolean that sets whether to include the certificate chain
                            in theresponse (true) or not (false). The default is false.
            time_stamp: The current date and time. The date and time should be given using
                        the ISO 8601 UTC time format YYYY-MM-DDTHH:mm:ss.000Z (e.g.2021-05-19T16:23:01Z).
            template: A string that sets the name of the certificate template thatshould be used to
                        issue the certificate.
            sans_ip4: Subject alternative name (SAN) ip addresses
            keyAlgorithm: A string indicating the cryptographic algorithm to use to generate the key
            metadata: An array of key/value pairs that set the values for the metadata fields

        Returns:
            Json response as dictionary
        """
        if sans_ip4 == '':
            body = {
                "CSR": csr_base64,
                "CertificateAuthority": cert_authority,
                "includeChain": include_chain,
                "Timestamp": time_stamp,
                "Template": template,
                "Metadata": metadata
            }

        else:
            ip4 = {
                'ip4': [sans_ip4]
            }

            body = {
                "CSR": csr_base64,
                "CertificateAuthority": cert_authority,
                "includeChain": include_chain,
                "Timestamp": time_stamp,
                "Template": template,
                "SANs": ip4,
                "Metadata": metadata
            }

        headers = {
            'x-keyfactor-api-version': '1',
            'x-keyfactor-requested-with': 'APIClient',
            'x-certificateformat': 'PEM',
            'Accept': 'application/json'
        }

        return self._http_request(method='POST',
                                  url_suffix='Enrollment/CSR',
                                  headers=headers,
                                  json_data=body)


''' HELPER FUNCTIONS '''


def get_enrollment_csr_context_template_ec(raw_response: dict) -> tuple[list, list]:
    """
        Get raw response of Enrollment csr templates and parse to ec
    Args:
        raw_response: Enrollment csr templates list

    Returns:
        List of Enrollment csr templates entry context for human readable
    """
    entry_context = []
    human_readable = []
    if raw_response:
        for template in raw_response['Templates']:
            entry_context.append(assign_params(**{
                "Name": template.get('Name'),
                "CAs": template.get('CAs')[0].get('Name')
            }))
            human_readable.append(assign_params(**{
                "Name": template.get('Name'),
                "CAs": template.get('CAs')[0].get('Name')
            }))
    return entry_context, human_readable


def post_enrollment_csr_command_ec(raw_response: dict) -> tuple[list, list]:
    """
        Parse the post enrollment CSR
        > Parse the Certificate received from keyFactor
    Args:
        raw_response: Certificate Info received from keyFactor

    Returns:
        List of Certificate info

    """
    entry_context = []
    human_readable = []
    if raw_response:
        certificateinfo: dict = raw_response["CertificateInformation"]
        regex = r"-----BEGIN CERTIFICATE-----[\w\W]*END CERTIFICATE-----"
        formated_certs: list = []

        certificates: list = certificateinfo['Certificates']

        for certs in certificates:
            matches = re.findall(regex, certs)
            formated_certs = formated_certs + matches
        new_formated_certs = []
        for cert in formated_certs:
            new_formated_certs.append(cert.replace('\r\n', ' '))
        formated_chain = new_formated_certs[1] + ' ' + new_formated_certs[2]

        entry_context.append(assign_params(**{
            "SerialNumber": certificateinfo.get('SerialNumber'),
            "IssuerDN": certificateinfo.get('IssuerDN'),
            "Thumbprint": certificateinfo.get('Thumbprint'),
            "KeyfactorID": certificateinfo.get('KeyfactorID'),
            "KeyfactorRequestId": certificateinfo.get('KeyfactorRequestId'),
            "Certificates": certificateinfo.get('Certificates'),
            "RequestDisposition": certificateinfo.get('RequestDisposition'),
            "DispositionMessage": certificateinfo.get('DispositionMessage'),
            "EnrollmentContext": certificateinfo.get('EnrollmentContext'),
            "formated_certs": new_formated_certs,
            "formated_cert": new_formated_certs[0],
            "formated_chain": formated_chain,
        }))
        human_readable.append(assign_params(**{
            "SerialNumber": certificateinfo.get('SerialNumber'),
            "IssuerDN": certificateinfo.get('IssuerDN'),
            "Thumbprint": certificateinfo.get('Thumbprint'),
            "KeyfactorID": certificateinfo.get('KeyfactorID'),
            "KeyfactorRequestId": certificateinfo.get('KeyfactorRequestId'),
            "Certificates": certificateinfo.get('Certificates'),
            "RequestDisposition": certificateinfo.get('RequestDisposition'),
            "DispositionMessage": certificateinfo.get('DispositionMessage'),
            "EnrollmentContext": certificateinfo.get('EnrollmentContext'),
            "formated_certs": formated_certs,
            "formated_cert": formated_certs[0],
            "formated_chain": formated_chain,
        }))

    return entry_context, human_readable


''' COMMANDS '''


@logger
def post_enrollment_csr_command(client: Client,
                                csr_base64: dict,
                                cert_authority: str,
                                include_chain: str,
                                template: str,
                                metadata: str,
                                keyAlgorithm: str,
                                sans_ip4: str = ''
                                ) -> tuple[object, dict, Union[list, dict]]:
    """
        Post Enrollment CSR
        Send the certifcate CSR and return the certificate created
    Args:
        client: Client object with request
        csr_base64: The base-64 encoded CSR that will be passed in for enrollment.
        cert_authority:  A string that sets the name of the certificate authority
        include_chain: A Boolean that sets whether to include the certificate chain in theresponse (true) or not (false).
                        The default is false.
        template: A string that sets the name of the certificate template thatshould be used to issue the certificate.
        sans_ip4: Subject alternative name (SAN) ip addresses
        keyAlgorithm: A string indicating the cryptographic algorithm to use to generate the key
        metadata: An array of key/value pairs that set the values for the metadata fields

    Returns:
        human readable (markdown format), entry context and raw response
    """
    import json
    if keyAlgorithm != '':
        csr_base64_changed = ''
        for csr in csr_base64['csrs']:
            if csr['keyAlgorithm'] == keyAlgorithm:
                csr_base64_changed = csr['csr']
    now_iso8601 = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z')

    raw_response: dict = client.post_enrollment_csr(csr_base64=csr_base64_changed,
                                                    cert_authority=cert_authority,
                                                    include_chain=include_chain,
                                                    time_stamp=now_iso8601,
                                                    template=template,
                                                    keyAlgorithm=keyAlgorithm,
                                                    sans_ip4=sans_ip4,
                                                    metadata=json.loads(metadata)
                                                    )
    if raw_response:
        title = f'{INTEGRATION_NAME} - Post Enrollment CSR'
        entry_context, human_readable_ec = post_enrollment_csr_command_ec(raw_response)

        context_entry: dict = {
            f"{INTEGRATION_CONTEXT_NAME}.CertInfo.Lists(val.UniqueID && val.UniqueID == obj.UniqueID &&"
            f" val.UpdateDate && val.UpdateDate == obj.UpdateDate)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)
        return human_readable, context_entry, raw_response
    else:
        return {}, {}, raw_response


@logger
def get_enrollment_csr_context_template_command(client: Client, *_) -> tuple[object, dict, Union[list, dict]]:
    """Get all Enrollment CSR Context My (templates)

    Args:
        client: Client object with request

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.get_enrollment_csr_context_template()

    if raw_response:
        title = f'{INTEGRATION_NAME} - Get enrollment csr context my'
        entry_context, human_readable_ec = get_enrollment_csr_context_template_ec(raw_response)
        context_entry: dict = {
            f"{INTEGRATION_CONTEXT_NAME}.CSRTemplate.Lists(val.UniqueID && val.UniqueID == obj.UniqueID &&"
            f" val.UpdateDate && val.UpdateDate == obj.UpdateDate)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)
        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def test_module_command(client: Client, *_) -> tuple[None, None, str]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        *_: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    results = client.test_module()
    if 'Templates' in results or 'CertificateInformation' in results:
        return None, None, 'ok'
    raise DemistoException(f'Test module failed, {results}')


def main():
    params = demisto.params()
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    client = Client(
        base_url=params.get('host'),
        verify=verify_ssl,
        proxy=proxy,
        auth=(
            username, password
        )
    )
    command = demisto.command()
    commands = {
        'test-module': test_module_command,
        f'{INTEGRATION_COMMAND_NAME}-get-enrollment-csr': get_enrollment_csr_context_template_command,
        f'{INTEGRATION_COMMAND_NAME}-post-enrollment-csr': post_enrollment_csr_command
    }

    try:
        readable_output, outputs, raw_response = commands[command](client=client, **demisto.args())
        results = CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=raw_response
        )
        return_results(results)

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

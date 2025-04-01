import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


INTEGRATION_NAME = "RDAP"
VCARD_MAPPING = {
    "title": 0,
    "label": 1,
    "data_type": 2,
    "data": 3
}


class RDAPClient(BaseClient):
    def __init__(self, base_url):
        super().__init__(base_url=base_url, verify=False)
        demisto.debug(f"RDAPClient initialized with base_url: {base_url}")

    def rdap_query(self, indicator_type, value):
        url_suffix = f"{indicator_type}/{value}"
        demisto.debug(f"Sending RDAP query for {indicator_type}: {value}")
        response = self._http_request(
            method='GET',
            url_suffix=url_suffix,
        )
        demisto.debug(f"RDAP query response received for {indicator_type}: {value}")
        return response


def parse_indicator_data(input: str, indicator_type: str, response: dict[str, Any]) -> tuple[Common.Indicator, dict[str, Any], str]:
    """
    Parse the RDAP response for an indicator and return the appropriate Common.Indicator object.

    This function takes the input indicator, its type, and the RDAP response, then delegates
    the parsing to the appropriate function based on the indicator type.

    Args:
        input (str): The indicator value being queried.
        indicator_type (str): The type of the indicator (e.g., 'ip', 'domain').
        response (dict[str, Any]): The RDAP response dictionary for the indicator.

    Returns:
        Common.Indicator|None: An object containing parsed information about the indicator,
        or None if the indicator type is not supported.

    Raises:
        DemistoException: If an unsupported indicator type is provided.
    """
    demisto.debug(f"Parsing indicator data for {indicator_type}: {input}")

    match indicator_type:
        case 'ip':
            return parse_ip_response(input, response)

        case 'domain':
            return parse_domain_response(input, response)

        case _:
            raise TypeError(f"Unsupported indicator type: {indicator_type}")


def parse_domain_response(indicator: str, response: dict[str, Any]) -> tuple[Common.Domain, dict[str, Any], str]:
    demisto.debug(f"Parsing domain response for: {indicator}")
    domain = Common.Domain(
        domain=indicator,
        dbot_score=Common.DBotScore(
            indicator=indicator,
            indicator_type=DBotScoreType.DOMAIN,
            score=Common.DBotScore.NONE,
            reliability=DBotScoreReliability.A
        )
    )
    
    if "Error" in response:
        context = {'Value': indicator, 'IndicatorType': 'Domain'}
        human_readable = response["Error"]
        return domain, context, human_readable
    
    events = response.get('events', []) if isinstance(response, dict) else []

    for event in events:
        if isinstance(event, dict):
            if event.get('eventAction') == 'registration':
                domain.creation_date = event.get('eventDate')
            elif event.get('eventAction') == 'expiration':
                domain.expiration_date = event.get('eventDate')
            elif event.get('eventAction') == 'last changed':
                last_changed_date = event.get('eventDate')

    secure_dns = response.get('secureDNS', {}) if isinstance(response, dict) else {}
    delegation_signed = secure_dns.get('delegationSigned', False) if isinstance(secure_dns, dict) else False

    # Human readable output
    readable_output = tableToMarkdown(
        f'RDAP Information for {indicator}',
        [
            {'Field': 'Registration Date', 'Value': domain.creation_date},
            {'Field': 'Expiration Date', 'Value': domain.expiration_date},
            {'Field': 'Secure DNS', 'Value': delegation_signed}
        ]
    )

    # Context output
    context_output = {
        'Value': indicator,
        'IndicatorType': 'Domain',
        'RegistrationDate': domain.creation_date,
        'ExpirationDate': domain.expiration_date,
        'LastChangedDate': last_changed_date,
        'SecureDNS': delegation_signed
    }

    return domain, context_output, readable_output


def parse_ip_response(indicator: str, response: dict[str, Any]) -> tuple[Common.IP, dict[str, Any], str]:
    """
    Parse the RDAP response for an IP address and return a Common.IP object.

    This function takes the RDAP response for an IP address and extracts relevant information
    to create a Common.IP object. It populates various fields of the IP object including
    IP type, geographical country, description, and registrar abuse contact information.

    Args:
        input (str): The IP address being queried.
        response (dict[str, Any]): The RDAP response dictionary for the IP address.

    Returns:
        Common.IP: An object containing parsed information about the IP address.
    """
    demisto.debug(f"Parsing IP response for: {indicator}")

    ip = Common.IP(
        ip=indicator,
        dbot_score=Common.DBotScore(
            indicator=indicator,
            indicator_type=DBotScoreType.IP,
            score=Common.DBotScore.NONE,
            reliability=DBotScoreReliability.A
        )
    )

    ip.ip_type = "IP" if response.get("ipVersion", "") == "v4" else "IPv6"
    
    if "error" in response:
        context = {'Value': indicator, 'IndicatorType': 'IP'}
        human_readable = response["Error"]
        return ip, context, human_readable
    
    ip.geo_country = response.get('country', '')

    for remark in response.get('remarks', []):
        if remark.get('title') == 'description':
            ip.description = remark.get('description', '')[0]
            break

    entities = response.get('entities', [])

    for entity in entities:
        if "abuse" in entity.get("roles", []):

            vcard_array = entity.get("vcardArray", [])

            if len(vcard_array) >= 2:  # check if vcard array has info in it
                for vcard in vcard_array[1]:

                    match vcard[0]:
                        case "adr":  # Address
                            ip.registrar_abuse_address = vcard[VCARD_MAPPING['label']]['label'] or ''

                        case "fn":  # Full Name
                            ip.organization_name = vcard[VCARD_MAPPING['data']] or ''
                            ip.registrar_abuse_name = vcard[VCARD_MAPPING['data']] or ''

                        case "email":  # Email Address
                            ip.registrar_abuse_email = vcard[VCARD_MAPPING['data']] or ''

                        case "tel":  # Telephone Number
                            ip.registrar_abuse_phone = vcard[VCARD_MAPPING['data']] or ''

    # Human readable output
    readable_output = tableToMarkdown(
        f'RDAP Information for {indicator}',
        [
            {'Field': 'Abuse Address', 'Value': ip.registrar_abuse_address},
            {'Field': 'Abuse Name', 'Value': ip.registrar_abuse_name},
            {'Field': 'Abuse Email', 'Value': ip.registrar_abuse_email}
        ]
    )

    # Context output
    context_output = {
        'Value': indicator,
        'IndicatorType': 'IP',
        'RegistrarAbuseAddress': ip.registrar_abuse_address,
        'RegistrarAbuseName': ip.registrar_abuse_name,
        'RegistrarAbuseEmail': ip.registrar_abuse_email,
    }

    return ip, context_output, readable_output


def test_module(client: RDAPClient) -> str | None:
    demisto.debug("Running test_module")
    try:
        client.rdap_query(indicator_type="domain", value="example.com")

    except Exception as e:
        return_error(f"Failed to execute test-module command. Error: {str(e)}")

    else:
        return "ok"


def main():
    args = demisto.args()
    base_url = args.get('base_url', 'https://rdap.org')
    command = demisto.command()
    results = []

    client = RDAPClient(base_url=base_url)

    match command:
        case "test-module":
            demisto.debug("Executing test-module command")
            return_results(test_module(client))

        case "ip":
            indicators = argToList(args.get('ip', []))

            if not indicators:
                return_error("IP address is required.")

            outputs_prefix = 'IP'
            parse_command = parse_ip_response

        case "domain":
            indicators = argToList(args.get('domain', []))

            if not indicators:
                return_error("A domain is required.")

            outputs_prefix = 'Domain'
            parse_command = parse_domain_response

        case _:
            return_error(f"Unknown command '{demisto.command()}'")
    
    for value in indicators:
        demisto.debug(f"Executing {demisto.command()} command for value: {value}")
        try:
            response = client.rdap_query(indicator_type=command, value=value)
            indicator, context, readable_output = parse_command(value, response)
        
        except Exception as e:
            if hasattr(e, 'res') and e.res.status_code == 404:
                response = {"Error": "Indicator Not Found"}
                indicator, context, readable_output = parse_command(value, response)
            
            else:
                raise e
        
        results.append(
            CommandResults(
                outputs_prefix=f'{INTEGRATION_NAME}.{outputs_prefix}',
                outputs_key_field=outputs_prefix,
                outputs=context,
                indicator=indicator,
                readable_output=readable_output,
                # raw_response=response
            )
        )

    return_results(results)

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

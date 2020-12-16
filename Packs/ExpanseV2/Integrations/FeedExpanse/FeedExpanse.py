"""Cortex XSOAR Integration for Expanse Expander and Behavior

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
import base64
from datetime import datetime, timedelta
from ipaddress import IPv4Address, AddressValueError, summarize_address_range
from typing import (
    Any, Dict, Optional, Iterable, List
)


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """

TOKEN_DURATION = 7200
DEFAULT_MAX_INDICATORS = 10  # used in expanse-get-indicators
DEFAULT_FETCH_MAX_INDICATORS = 1000  # used in fetch-indicators
DEFAULT_FETCH_MIN_LAST_OBSERVED = 7  # used in fetch-indicators


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the Expanse API"""

    def __init__(
        self, base_url: str, api_key: str, verify: bool, proxy: bool, **kwargs
    ):
        self.api_key = api_key
        hdr = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Expanse_XSOAR/0.0.1",
        }
        super().__init__(base_url, verify=verify, proxy=proxy, headers=hdr, **kwargs)

    def authenticate(self) -> None:
        """
        Perform authentication using API_KEY,
        stores token and stored timestamp in integration context,
        retrieves new token when expired
        """
        current_utc_timestamp = int(datetime.utcnow().timestamp())

        stored_token = demisto.getIntegrationContext()
        if (
            isinstance(stored_token, dict)
            and "token" in stored_token
            and "expires" in stored_token
            and current_utc_timestamp < int(stored_token["expires"])
        ):
            self._headers['Authorization'] = f'JWT {stored_token["token"]}'
        else:
            # fetch new token
            hdr = self._headers.copy()
            hdr["Authorization"] = f"Bearer {self.api_key}"

            r = self._http_request("GET", "/v1/IdToken", headers=hdr)
            if isinstance(r, dict) and r.get("token", None) is None:
                raise ValueError("Authorization failed")

            token_expiration = current_utc_timestamp + TOKEN_DURATION

            self._headers['Authorization'] = f'JWT {r["token"]}'
            demisto.setIntegrationContext(
                {"token": r["token"], "expires": token_expiration}
            )

    def _paginate(self, method: str, url_suffix: str, params: Optional[Dict[str, Any]]) -> Iterable[Any]:
        next_url: Optional[str] = None

        while True:
            result = self._http_request(
                method=method,
                url_suffix=url_suffix,
                full_url=next_url,
                params=params,
                raise_on_status=True,
                timeout=30
            )

            data = result.get('data', [])
            if data is not None:
                yield from data

            pagination = result.get('pagination', None)
            if pagination is None:
                break
            next_url = pagination.get('next', None)
            if next_url is None:
                break

            params = None

    def get_iprange_by_id(self, iprange_id: str) -> Dict[str, Any]:
        result = self._http_request(
            method="GET",
            url_suffix=f"/v2/ip-range/{iprange_id}",
            raise_on_status=True,
            params={
                'include': "severityCounts,annotations,attributionReasons,relatedRegistrationInformation,locationInformation"
            }
        )
        return result

    def get_domain_by_domain(self, domain: str, last_observed_date: Optional[str]) -> Dict[str, Any]:
        params = {}
        if last_observed_date is not None:
            params['minRecentIpLastObservedDate'] = last_observed_date

        result = self._http_request(
            method="GET",
            url_suffix=f"/v2/assets/domains/{domain}",
            raise_on_status=True,
            params=params
        )
        return result

    def get_certificate_by_pem_md5_hash(self, pem_md5_hash: str, last_observed_date: Optional[str]) -> Dict[str, Any]:
        params = {}

        if last_observed_date is not None:
            params['minRecentIpLastObservedDate'] = last_observed_date

        result = self._http_request(
            method="GET",
            url_suffix=f"/v2/assets/certificates/{pem_md5_hash}",
            raise_on_status=True,
            params=params
        )
        return result

    def get_ipranges(self, params: Dict[str, Any]) -> Iterable[Any]:
        return self._paginate(
            method="GET",
            url_suffix="/v2/ip-range",
            params=params
        )

    def get_domains(self, params: Dict[str, Any]) -> Iterable[Any]:
        return self._paginate(
            method="GET",
            url_suffix="/v2/assets/domains",
            params=params
        )

    def get_certificates(self, params: Dict[str, Any]) -> Iterable[Any]:
        return self._paginate(
            method="GET",
            url_suffix="/v2/assets/certificates",
            params=params
        )

    def get_ips(self, params: Dict[str, Any]) -> Iterable[Any]:
        return self._paginate(
            method="GET",
            url_suffix="/v2/assets/ips",
            params=params
        )


""" HELPER FUNCTIONS """


def check_int(arg: Any, arg_name: str, min_val: int = None, max_val: int = None, required: bool = False) -> Optional[int]:
    """Converts a string argument to a Python int
    This function is used to quickly validate an argument provided and convert
    it into an ``int`` type. It will throw a ValueError if the input is invalid
    or outside the optional range. If the input is None, it will throw a ValueError
    if required is ``True``, or ``None`` if required is ``False.
    """

    # check if argument is mandatory
    if arg is None:
        if required is True:
            raise ValueError(f'Missing argument "{arg_name}"')
        return None

    i: Optional[int] = None

    if isinstance(arg, str):
        if not arg.isdigit():
            raise ValueError(f'Integer invalid: "{arg_name}"="{arg}"')
        try:
            i = int(arg)
        except ValueError:
            raise ValueError(f'Integer invalid: "{arg_name}"="{arg}"')
    elif isinstance(arg, int):
        i = arg
    else:
        raise ValueError(f'Invalid number: "{arg_name}"')

    # range check
    if min_val and i < min_val:
        raise ValueError(f'Integer outside minimum range: "{arg_name}"="{arg}" ("min={min_val}")')
    if max_val and i > max_val:
        raise ValueError(f'Integer outside maximum range: "{arg_name}"="{arg}" ("max={max_val}")')

    return i


def validate_max_indicators(max_indicators_param: Optional[str]) -> Optional[int]:
    try:
        max_indicators = check_int(
            max_indicators_param,
            'maxIndicators',
            None, None, False
        )
    except ValueError:
        return None

    if max_indicators is None:
        max_indicators = DEFAULT_FETCH_MAX_INDICATORS

    return max_indicators


def validate_min_last_observed(min_last_observed_param: Optional[str]) -> Optional[str]:
    try:
        min_last_observed = check_int(
            min_last_observed_param,
            'minLastObserved',
            None, None, False
        )
    except ValueError:
        return None

    if min_last_observed is None:
        min_last_observed = DEFAULT_FETCH_MIN_LAST_OBSERVED

    start_time = datetime.utcnow() - timedelta(days=min_last_observed)

    return start_time.strftime("%Y-%m-%d")


def safe_b64_to_hex(i: str) -> Optional[str]:
    if not i:
        return None

    try:
        return base64.urlsafe_b64decode(i).hex()
    except Exception:
        return None


""" INDICATORS HANDLING FUNCTIONS """


def ip_to_demisto_indicator(ip_indicator: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    value = ip_indicator.get('ip', None)
    if value is None:
        return None

    provider_name = ip_indicator.get('provider', {}).get('name')

    tenant_name = ip_indicator.get('tenant', {}).get('name')

    business_units = ip_indicator.get("businessUnits", [])
    business_unit_names = [bu['name'] for bu in business_units if bu.get('name')]

    # to faciliate classifiers
    ip_indicator['expanseType'] = 'ip'

    return {
        'type': FeedIndicatorType.IP,
        'value': value,
        'rawJSON': ip_indicator,
        'score': Common.DBotScore.NONE,
        'fields': {
            'expansetype': ip_indicator.get('type', None),
            'expanseassetype': ip_indicator.get('assetType', None),
            'expansedomain': ip_indicator.get('domain', None),
            'expansecommonname': ip_indicator.get('commonName', None),
            'expanselastobserved': ip_indicator.get('lastObserved', None),
            'lastseenbysource': ip_indicator.get('lastObserved', None),
            'expanseprovidername': provider_name,
            'expansetenantname': tenant_name,
            'expansebusinessunits': business_unit_names
        }
    }


def certificate_to_demisto_indicator(certificate: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    certificate_details = certificate.get('certificate')
    if certificate_details is None:
        return None

    ec_sha256 = certificate_details.get('pemSha256')
    if ec_sha256 is None:
        return None
    indicator_value = safe_b64_to_hex(ec_sha256)
    if indicator_value is None:
        return None

    ec_md5 = certificate_details.get('md5Hash')
    ec_sha1 = certificate_details.get('pemSha1')
    ec_spki = certificate_details.get('publicKeySpki')

    ec_modulus = certificate_details.get('publicKeyModulus')
    ec_publickey = None
    if (pktemp := certificate_details.get('publicKey')) is not None:
        ec_publickey = safe_b64_to_hex(pktemp)

    ec_san = certificate_details.get('subjectAlternativeNames')

    ec_names = set()
    if isinstance(ec_san, str) and len(ec_san) > 0:
        ec_names.update([san for san in ec_san.split() if len(san) != 0])
    if (ec_subject_name := certificate_details.get('subjectName')) is not None:
        ec_names.add(ec_subject_name)

    annotations = certificate.get('annotations', {})
    tags = [tag['name'] for tag in annotations.get('tags', [])]

    providers = certificate.get('providers', [])
    provider_name = None if len(providers) == 0 else providers[0].get('name')

    tenant_name = certificate.get('tenant', {}).get('name')

    business_units = certificate.get("businessUnits", [])
    business_unit_names = [bu['name'] for bu in business_units if bu.get('name')]

    return {
        'type': 'Certificate',
        'value': indicator_value,
        'rawJSON': certificate,
        'score': Common.DBotScore.NONE,
        'fields': {
            # standard context
            "serialnumber": certificate_details.get('serialNumber'),
            "certificatenames": '\n'.join(sorted(list(ec_names))) if ec_names else None,
            "subjectdn": certificate_details.get('subject'),
            "certificatesignature": {'algorithm': certificate_details.get('signatureAlgorithm')},
            "subjectalternativenames": [{'value': san} for san in ec_san.split() if len(san) != 0] if ec_san else None,
            "validitynotafter": certificate_details.get('validNotAfter'),
            "spkisha256": safe_b64_to_hex(ec_spki) if ec_spki else None,
            "validitynotbefore": certificate_details.get('validNotBefore'),
            "publickey": {
                "algorithm": certificate_details.get('publicKeyAlgorithm'),
                "length": certificate_details.get('publicKeyBits'),
                "modulus": ':'.join([ec_modulus[i:i + 2] for i in range(0, len(ec_modulus), 2)]) if ec_modulus else None,
                "exponent": certificate_details.get('publicKeyRsaExponent'),
                "publickey": ':'.join([ec_publickey[i:i + 2] for i in range(0, len(ec_publickey), 2)]) if ec_publickey else None
            },
            "issuerdn": certificate_details.get('issuer'),
            "md5": safe_b64_to_hex(ec_md5) if ec_md5 else None,
            "sha1": safe_b64_to_hex(ec_sha1) if ec_sha1 else None,
            "sha256": indicator_value,

            # expanse specific
            'expansetags': tags,
            'expansecertificateadvertisementstatus': certificate.get('certificateAdvertisementStatus', None),
            'expansedateadded': certificate.get('dateAdded', None),
            'expansefirstobserved': certificate.get('firstObserved', None),
            'firstseenbysource': certificate.get('firstObserved', None),
            'expanselastobserved': certificate.get('lastObserved', None),
            'lastseenbysource': certificate.get('lastObserved', None),
            'expanseproperties': '\n'.join(certificate.get('properties', [])),
            'expanseservicestatus': certificate.get('serviceStatus', None),
            'expanseprovidername': provider_name,
            'expansetenantname': tenant_name,
            'expansebusinessunits': business_unit_names
        }
    }


def domain_to_demisto_indicator(domain_indicator: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    domain = domain_indicator.get('domain', None)
    if domain is None:
        return None

    annotations = domain_indicator.get('annotations', {})
    tags = [tag['name'] for tag in annotations.get('tags', [])]

    providers = domain_indicator.get('providers', [])
    provider_name = None if len(providers) == 0 else providers[0].get('name')

    tenant_name = domain_indicator.get('tenant', {}).get('name')

    business_units = domain_indicator.get("businessUnits", [])
    business_unit_names = [bu['name'] for bu in business_units if bu.get('name')]

    # to faciliate classifiers
    domain_indicator['expanseType'] = 'domain'

    return {
        'type': 'DomainGlob' if '*' in domain else 'Domain',
        'value': domain,
        'rawJSON': domain_indicator,
        'score': Common.DBotScore.NONE,
        'fields': {
            'expansetags': tags,
            'expansednsresolutionstatus': domain_indicator.get('dnsResolutionStatus', None),
            'expansedateadded': domain_indicator.get('dateAdded', None),
            'expansefirstobserved': domain_indicator.get('firstObserved', None),
            'firstseenbysource': domain_indicator.get('firstObserved', None),
            'expanselastobserved': domain_indicator.get('lastObserved', None),
            'lastseenbysource': domain_indicator.get('lastObserved', None),
            'expanselastsampledip': domain_indicator.get('lastSampledIp', None),
            'expanseservicestatus': domain_indicator.get('serviceStatus', None),
            'expansesourcedomain': domain_indicator.get('sourceDomain', None),
            'expanseprovidername': provider_name,
            'expansetenantname': tenant_name,
            'expansebusinessunits': business_unit_names
        }
    }


def iprange_to_demisto_indicator(iprange_indicator: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    demisto.debug(f"{iprange_indicator!r}")

    ipVersion = iprange_indicator.get('ipVersion', "4")
    if ipVersion != "4":
        return []

    start_address = iprange_indicator.get('startAddress', None)
    if start_address is None:
        return []
    try:
        start_address = IPv4Address(start_address)
    except AddressValueError:
        return []

    end_address = iprange_indicator.get('endAddress', None)
    if end_address is None:
        return []
    try:
        end_address = IPv4Address(end_address)
    except AddressValueError:
        return []

    if end_address < start_address:
        return []

    annotations = iprange_indicator.get('annotations', {})
    tags = [tag['name'] for tag in annotations.get('tags', []) if tag.get('name')]

    business_units = iprange_indicator.get("businessUnits", [])
    business_unit_names = [bu['name'] for bu in business_units if bu.get('name')]

    attribution_reasons: List[str] = [ar['reason'] for ar in iprange_indicator.get('attributionReason', []) if ar.get('reason')]

    # to faciliate classifiers
    iprange_indicator['expanseType'] = 'iprange'

    for cidr in summarize_address_range(start_address, end_address):
        yield {
            'type': 'CIDR',
            'value': str(cidr),
            'rawJSON': iprange_indicator,
            'score': Common.DBotScore.NONE,
            'fields': {
                'expansetags': tags,
                'expansebusinessunits': business_unit_names,
                'expanseseveritycount': iprange_indicator.get('severityCounts', {}),
                'expanseattributionreason': attribution_reasons,
                'expanseresponsiveipcount': iprange_indicator.get('responsiveIpCount', None)
            }
        }


""" COMMAND FUNCTIONS """


def test_module(
        client: Client,
        max_indicators_param: Optional[str],
        min_last_observed_param: Optional[str],
        tlp_color: Optional[str],
        feed_tags: str) -> str:
    feed_tags = argToList(feed_tags)

    max_indicators = validate_max_indicators(max_indicators_param)
    if max_indicators is None:
        return "Invalid value for max indicators"

    min_last_observed = validate_min_last_observed(min_last_observed_param)
    if min_last_observed is None:
        return "Invalide value for last observed range"

    try:
        client.get_ips(params={
            'limit': 1,
            'minLastObservedDate': min_last_observed
        })
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization failed" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return "ok"


def indicator_generator(client: Client,
                        max_indicators: Optional[int] = None,
                        min_last_observed: Optional[str] = None,
                        retrieve_ip: Optional[bool] = True,
                        retrieve_domain: Optional[bool] = True,
                        retrieve_certificate: Optional[bool] = True,
                        retrieve_iprange: Optional[bool] = True,
                        tlp_color: Optional[str] = '',
                        feed_tags: str = '') -> Iterable[Dict[str, Any]]:
    if retrieve_ip:
        get_ips_params = {}
        if min_last_observed is not None:
            get_ips_params['minLastObservedDate'] = min_last_observed

        num_indicators = 0
        for ip_indicator in client.get_ips(params=get_ips_params):
            if max_indicators is not None and num_indicators >= max_indicators:
                break

            demisto_indicator = ip_to_demisto_indicator(ip_indicator)
            if demisto_indicator is None:
                continue

            if tlp_color is not None:
                demisto_indicator['fields']['trafficlightprotocol'] = tlp_color
            if feed_tags:
                demisto_indicator['fields']['tags'] = feed_tags

            yield demisto_indicator
            num_indicators += 1

    if retrieve_certificate:
        get_certificates_params = {'sort': '-dateAdded'}
        if min_last_observed is not None:
            get_certificates_params['minLastObservedDate'] = min_last_observed

        num_indicators = 0
        for cert_indicator in client.get_certificates(params=get_certificates_params):
            if max_indicators is not None and num_indicators >= max_indicators:
                break

            demisto_indicator = certificate_to_demisto_indicator(cert_indicator)
            if demisto_indicator is None:
                continue

            if tlp_color is not None:
                demisto_indicator['fields']['trafficlightprotocol'] = tlp_color
            if feed_tags:
                demisto_indicator['fields']['tags'] = feed_tags

            yield demisto_indicator
            num_indicators += 1

    if retrieve_domain:
        get_domains_params = {'sort': '-dateAdded'}
        if min_last_observed is not None:
            get_domains_params['minLastObservedDate'] = min_last_observed

        num_indicators = 0
        for domain_indicator in client.get_domains(params=get_domains_params):
            if max_indicators is not None and num_indicators >= max_indicators:
                break

            demisto_indicator = domain_to_demisto_indicator(domain_indicator)
            if demisto_indicator is None:
                continue

            if tlp_color is not None:
                demisto_indicator['fields']['trafficlightprotocol'] = tlp_color
            if feed_tags:
                demisto_indicator['fields']['tags'] = feed_tags

            yield demisto_indicator
            num_indicators += 1

    if retrieve_iprange:
        num_indicators = 0
        iprange_params = {'include': 'severityCounts,annotations,attributionReasons'}
        for iprange_indicator in client.get_ipranges(params=iprange_params):
            if max_indicators is not None and num_indicators >= max_indicators:
                break

            for demisto_indicator in iprange_to_demisto_indicator(iprange_indicator):
                if tlp_color is not None:
                    demisto_indicator['fields']['trafficlightprotocol'] = tlp_color
                if feed_tags:
                    demisto_indicator['fields']['tags'] = feed_tags

                yield demisto_indicator
                num_indicators += 1


def get_indicators_command(client: Client, args: Dict[str, Any],
                           tlp_color: Optional[str] = '',
                           feed_tags: str = '') -> CommandResults:
    retrieve_ip = argToBoolean(args.get('ip', 'yes'))
    retrieve_domain = argToBoolean(args.get('domain', 'yes'))
    retrieve_certificate = argToBoolean(args.get('certificate', 'yes'))
    retrieve_iprange = argToBoolean(args.get('iprange', 'yes'))

    max_indicators = check_int(args.get('max_indicators'), 'max_indicators', None, None, False)
    if not max_indicators:
        max_indicators = DEFAULT_MAX_INDICATORS

    indicators: List[Dict[str, Any]] = []
    for indicator in indicator_generator(
            client,
            max_indicators=max_indicators,
            retrieve_ip=retrieve_ip,
            retrieve_domain=retrieve_domain,
            retrieve_certificate=retrieve_certificate,
            retrieve_iprange=retrieve_iprange,
            tlp_color=tlp_color,
            feed_tags=feed_tags):
        indicators.append(indicator)

    readable_output = tableToMarkdown(
        f'Expanse Indicators (capped at {max_indicators})',
        indicators,
        headers=['value', 'type']
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=None,
        outputs_key_field=None,
        outputs=None,
        raw_response=indicators
    )


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    api_key = params.get("apikey")
    base_url = urljoin(params["url"], "/api")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_indicators_param = params.get('max_fetch')
    min_last_observed_param = params.get('min_last_observed')
    tlp_color = params.get('tlp_color')
    feed_tags = params.get('feedTags', '')

    try:
        client = Client(
            api_key=api_key, base_url=base_url, verify=verify_certificate, proxy=proxy
        )

        client.authenticate()

        if demisto.command() == "test-module":
            result = test_module(client, max_indicators_param, min_last_observed_param, tlp_color, feed_tags)
            return_results(result)

        elif demisto.command() == "fetch-indicators":
            max_indicators = validate_max_indicators(max_indicators_param)
            if validate_max_indicators is None:
                raise ValueError("Invalid value for max indicators")

            min_last_observed = validate_min_last_observed(min_last_observed_param)
            if min_last_observed is None:
                raise ValueError("Invalid value for last observed day range")

            indicator_batch = []
            for indicator in indicator_generator(client, tlp_color=tlp_color, feed_tags=feed_tags, max_indicators=max_indicators):
                indicator_batch.append(indicator)
                if len(indicator_batch) == 2000:
                    demisto.createIndicators(indicator_batch)
                    indicator_batch = []
            if len(indicator_batch) != 0:
                demisto.createIndicators(indicator_batch)

        elif demisto.command() == "feedexpanse-get-indicators":
            return_results(get_indicators_command(client, demisto.args(), tlp_color=tlp_color, feed_tags=feed_tags))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

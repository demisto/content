"""Cortex XSOAR Integration for Expanse Expander and Behavior

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
import copy

from base64 import b64decode
from hashlib import sha256
from typing import (
    Any, Dict, Optional, Iterator,
    Tuple, Union, cast,
)

from itertools import islice
from dateparser import parse
from datetime import datetime, timezone
import ipaddress

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """

SERVER = "https://expander.expanse.co"
TOKEN_DURATION = 7200
DEFAULT_RESULTS = 20  # default results per search
MAX_RESULTS = 5000  # max results per search
MAX_PAGE_SIZE = 1000  # max results per page
MAX_INCIDENTS = 100  # max incidents per fetch
MAX_UPDATES = 100  # max updates received
PREFIX = SERVER + "/api"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

ISSUE_PROGRESS_STATUS = ['New', 'Investigating', 'InProgress', 'AcceptableRisk', 'Resolved']
ISSUE_PROGRESS_STATUS_CLOSED = ['AcceptableRisk', 'Resolved']
ISSUE_ACTIVITY_STATUS = ['Active', 'Inactive']
ISSUE_PRIORITY = ['Critical', 'High', 'Medium', 'Low']
ISSUE_SORT_OPTIONS = ['created', '-created', 'modified', '-modified', 'assigneeUsername',
                      '-assigneeUsername', 'priority', '-priority', 'progressStatus', '-progressStatus',
                      'activityStatus', '-activityStatus', 'headline', '-headline']

EXPANSE_RESOLVEDSTATUS_TO_XSOAR = {
    'Resolved': 'Resolved',
    'AcceptableRisk': 'Other'
}

MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Both': 'Both'
}

TAGGABLE_ASSET_TYPE_MAP = {
    'Domain': 'domains',
    'Certificate': 'certificates',
    'cloud-resource': 'cloud_resource',
    'IpRange': 'ip-range'
}

ASSET_TAG_OPERATIONS = ['ASSIGN', 'UNASSIGN']

ISSUE_UPDATE_TYPES = {
    'Assignee': 'assigneeUsername',
    'Comment': 'comment',
    'Priority': 'priority',
    'ProgressStatus': 'progressStatus',
    'ActivityStatus': 'activityStatus'
}

PRIORITY_SEVERITY_MAP = {
    'Unknown': 0,  # unknown
    'Low': 1,  # low severity
    'Medium': 2,  # medium severity
    'High': 3,  # high severity
    'Critical': 4   # critical severity
}

SEVERITY_PRIORITY_MAP = {v: k for k, v in PRIORITY_SEVERITY_MAP.items()}

IPRANGE_INCLUDE_OPTIONS = ["none", "annotations", "severityCounts", "attributionReasons",
                           "relatedRegistrationInformation", "locationInformation"]

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

    def _paginate(self, method: str, url_suffix: str,
                  params: Optional[Dict[str, Any]]) -> Iterator[Any]:
        next_url: Optional[str] = None

        while True:
            if '/issues' in url_suffix and 'updates' not in url_suffix:
                pass
                # demisto.debug(f'DEBUGDEBUG Client._paginate: calling {url_suffix} with {params}')
            result = self._http_request(
                method=method,
                url_suffix=url_suffix,
                full_url=next_url,
                params=params,
                raise_on_status=True
            )

            data = result.get('data', [])
            if data is not None:
                if '/issues' in url_suffix and 'updates' not in url_suffix:
                    pass
                    # demisto.debug(f'DEBUGDEBUG Client._paginate: returning {len(data)} results')
                for a in data:
                    yield a

            pagination = result.get('pagination', None)
            if pagination is None:
                break
            next_url = pagination.get('next', None)
            if next_url is None:
                break

            params = None

    def authenticate(self) -> None:
        """
        Perform authentication using API_KEY,
        stores token and stored timestamp in integration context,
        retrieves new token when expired
        """
        current_utc_timestamp = int(datetime.utcnow().timestamp())
        token_expiration = current_utc_timestamp + TOKEN_DURATION

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

            r = self._http_request('GET', "/v1/IdToken", headers=hdr)
            if isinstance(r, dict) and r.get("token", None) is None:
                raise ValueError("Authorization failed")

            token_expiration = current_utc_timestamp + TOKEN_DURATION

            self._headers['Authorization'] = f'JWT {r["token"]}'
            demisto.setIntegrationContext(
                {"token": r["token"], "expires": token_expiration}
            )

    def get_issue_count(self) -> int:
        r = self._http_request(
            method='GET', url_suffix='/v1/issues/issues/count',
        )
        if not isinstance(r, dict) or 'count' not in r:
            raise RuntimeError('Error determining issue count')
        return int(r['count'])

    def get_issues(self,
                   limit: int,
                   content_search: Optional[str] = None,
                   provider: Optional[str] = None,
                   business_units: Optional[str] = None,
                   assignee: Optional[str] = None,
                   issue_type: Optional[str] = None,
                   inet_search: Optional[str] = None,
                   domain_search: Optional[str] = None,
                   port_number: Optional[str] = None,
                   progress_status: Optional[str] = None,
                   activity_status: Optional[str] = None,
                   priority: Optional[str] = None,
                   tags: Optional[str] = None,
                   created_before: Optional[str] = None,
                   created_after: Optional[str] = None,
                   modified_before: Optional[str] = None,
                   modified_after: Optional[str] = None,
                   sort: Optional[str] = None
                   ) -> Iterator[Any]:

        params = {
            'limit': limit,
            'contentSearch': content_search,
            'providerName': provider if provider else None,
            'businessUnitName': business_units if business_units else None,
            'assigneeUsername': assignee if assignee else None,
            'issueTypeName': issue_type if issue_type else None,
            'inetSearch': inet_search,
            'domainSearch': domain_search,
            'portNumber': port_number if port_number else None,
            'progressStatus': progress_status if progress_status else None,
            'activityStatus': activity_status if activity_status else None,
            'priority': priority if priority else None,
            'tagName': tags if tags else None,
            'createdBefore': created_before,
            'createdAfter': created_after,
            'modifiedBefore': modified_before,
            'modifiedAfter': modified_before,
            'sort': sort
        }

        return self._paginate(
            method='GET', url_suffix="/v1/issues/issues", params=params
        )

    def get_issue_by_id(self, issue_id: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET', url_suffix=f'/v1/issues/issues/{issue_id}')

    def get_issue_updates(self, issue_id: str, update_types: Optional[List],
                          created_after: Optional[str], limit: int = DEFAULT_RESULTS) -> Iterator[Any]:
        updates = self._paginate(
            method='GET', url_suffix=f'/v1/issues/issues/{issue_id}/updates',
            params=dict(limit=limit))
        after = datestring_to_timestamp_us(created_after) if created_after else None

        for u in updates:
            if after and 'created' in u and datestring_to_timestamp_us(u['created']) <= after:
                continue
            if update_types and 'updateType' in u and u['updateType'] not in update_types:
                continue
            yield u

    def list_businessunits(self, limit: int = DEFAULT_RESULTS) -> Iterator[Any]:
        params = dict(limit=limit)
        return self._paginate(
            method='GET',
            url_suffix='/v1/issues/businessUnits',
            params=params
        )

    def list_providers(self, limit: int = DEFAULT_RESULTS) -> Iterator[Any]:
        params = dict(limit=limit)
        return self._paginate(
            method='GET',
            url_suffix='/v1/issues/providers',
            params=params
        )

    def list_tags(self, limit: int = DEFAULT_RESULTS) -> Iterator[Any]:
        params = dict(limit=limit)
        return self._paginate(
            method='GET',
            url_suffix='/v3/annotations/tags',
            params=params
        )

    def create_tag(self, name: str, description: Optional[str]) -> Dict[str, Any]:
        data: Dict = {
            'name': name,
            'description': description

        }
        return self._http_request(
            method='POST',
            url_suffix='/v3/annotations/tags',
            data=json.dumps(data)
        )

    def get_asset_details(self, asset_type: str, asset_id: str,
                          include: str = 'annotations,attributionReasons') -> Dict[str, Any]:
        data: Dict = {}
        # demisto.debug(f'DEBUGDEBUG get_asset_details: retrieving details for asset {asset_id} of type {asset_type}')
        if asset_type == 'IpRange':
            data = self.get_iprange_by_id(
                iprange_id=asset_id,
                include=include
            )
        elif asset_type == 'Certificate':
            data = self.get_certificate_by_pem_md5_hash(asset_id)
        elif asset_type == 'Domain':
            data = self.get_domain_by_domain(domain=asset_id)
        else:
            demisto.debug(f'get_asset_details: unsupported asset type {asset_type}')
        return data

    def manage_asset_tags(self, asset_type: str, operation_type: str, asset_id: str, tag_ids: List[str]) -> Dict[str, Any]:
        endpoint_base = asset_type if asset_type == "ip-range" else f"assets/{asset_type}"

        data: Dict = {"operations": [{
            'operationType': operation_type,
            'tagIds': tag_ids,
            'assetId': asset_id

        }]}
        return self._http_request(
            method='POST',
            url_suffix=f'/v2/{endpoint_base}/tag-assignments/bulk',
            json_data=data
        )

    def update_issue(self, issue_id: str, update_type: str, value: str) -> Dict[str, Any]:
        # demisto.debug(f'DEBUGDEBUG update_issue: {issue_id}, {update_type}, {value}')
        data: Dict = {
            'updateType': update_type,
            'value': value
        }
        return self._http_request(
            method='POST',
            url_suffix=f'/v1/issues/issues/{issue_id}/updates',
            data=json.dumps(data)
        )

    def get_iprange_by_id(self, iprange_id: str, include: str) -> Dict[str, Any]:
        result: Dict = self._http_request(
            method='GET',
            url_suffix=f'/v2/ip-range/{iprange_id}',
            raise_on_status=True,
            params={
                'include': include
            }
        )
        return result

    def get_domain_by_domain(self, domain: str, last_observed_date: Optional[str] = None) -> Dict[str, Any]:
        params = {}
        if last_observed_date is not None:
            params['minRecentIpLastObservedDate'] = last_observed_date

        try:
            result: Dict = self._http_request(
                method='GET',
                url_suffix=f'/v2/assets/domains/{domain}',
                raise_on_status=True,
                params=params
            )
        except DemistoException as e:
            if str(e).startswith('Error in API call [404]') or str(e).startswith('Error in API call [400]'):
                return {}
            raise e
        return result

    def get_certificate_by_pem_md5_hash(self, pem_md5_hash: str, last_observed_date: Optional[str] = None) -> Dict[str, Any]:
        params = {}

        if last_observed_date is not None:
            params['minRecentIpLastObservedDate'] = last_observed_date

        result: Dict = self._http_request(
            method='GET',
            url_suffix=f'/v2/assets/certificates/{pem_md5_hash}',
            raise_on_status=True,
            params=params
        )
        return result

    def get_ipranges(self, params: Dict[str, Any]) -> Iterator[Any]:
        return self._paginate(
            method='GET',
            url_suffix='/v2/ip-range',
            params=params
        )

    def get_domains(self, params: Dict[str, Any]) -> Iterator[Any]:
        return self._paginate(
            method='GET',
            url_suffix='/v2/assets/domains',
            params=params
        )

    def get_certificates(self, params: Dict[str, Any]) -> Iterator[Any]:
        return self._paginate(
            method='GET',
            url_suffix='/v2/assets/certificates',
            params=params
        )

    def get_ips(self, params: Dict[str, Any]) -> Iterator[Any]:
        return self._paginate(
            method='GET',
            url_suffix='/v2/assets/ips',
            params=params
        )

    def list_risk_rules(self, params: Dict[str, Any]) -> Iterator[Any]:
        return self._paginate(
            method='GET',
            url_suffix='/v1/behavior/risk-rules',
            params=params
        )

    def get_risky_flows(self, limit: int, created_before: Optional[str], created_after: Optional[str],
                        internal_ip_range: Optional[str], risk_rule: Optional[str], tag_names: Optional[str]) -> Iterator[Any]:

        params = {
            "limit": limit,
            "created-before": created_before,
            "created-after": created_after,
            "internal-ip-range": internal_ip_range,
            "risk-rule": risk_rule,
            "tag-names": tag_names
        }

        return self._paginate(
            method='GET',
            url_suffix='/v1/behavior/risky-flows',
            params=params
        )

    def parse_asset_data(self, issue: Dict[str, Any],
                         fetch_details: Optional[bool] = False) -> Tuple[List[Dict[str, Any]], List[str], bool]:
        assets: List[Dict[str, Any]] = []
        changed = False
        ml_feature_list: List[str] = []
        if 'assets' in issue and isinstance(issue['assets'], list) and len(issue['assets']) > 0:
            assets = copy.deepcopy(issue['assets'])
            for n, a in enumerate(assets):
                if not isinstance(a, dict) or 'assetType' not in a:
                    continue

                # Handle conversion of IP ranges to CIDRs for AutoExtract
                if (
                        a['assetType'] == 'IpRange'
                        and 'displayName' in a
                        and isinstance(dn := a['displayName'], str)
                        and len(r := dn.split('-')) == 2
                ):
                    assets[n]['displayName'] = ','.join(range_to_cidrs(r[0], r[1]))
                    changed = True

                if not fetch_details or 'assetKey' not in a:
                    continue

                # Fetch additional details for assets
                details = self.get_asset_details(a['assetType'], a['assetKey'])
                if not isinstance(details, dict):
                    continue

                # Replace asset ID with the real asset ID (the ID shown in asset is a reference of the association table)
                if real_id := details.get('id', None):
                    assets[n]['id'] = real_id
                    changed = True

                # Handle Tags
                if (annotations := details.get('annotations', None)) and isinstance(annotations, dict):
                    if (tags := annotations.get('tags', None)) and isinstance(tags, list) and len(tags) > 0:
                        assets[n]['tags'] = '\n'.join(sorted(t['name'] for t in tags if 'name' in t))
                        changed = True

                # Handle Attribution reasons
                if (ar := details.get('attributionReasons', None)) and isinstance(ar, list) and len(ar) > 0:
                    assets[n]['attributionReasons'] = '\n'.join(sorted(a['reason'] for a in ar if 'reason' in a))
                    changed = True

                # Handle ML fields

                # assets[n]['moredetails'] = details
                if a['assetType'] == 'IpRange':
                    # for IP Range collect relatedRegistrarInformation.registryEntities.formattedName
                    if (
                        (rri := details.get('relatedRegistrationInformation', None))
                        and isinstance(rri, list)
                        and len(rri) > 0
                        and isinstance(rri[0], dict)
                        and (re := rri[0].get('registryEntities', None))
                        and isinstance(re, list)
                        and len(re) > 0
                    ):
                        ml_feature_list.extend(set(r['formattedName'] for r in re if 'formattedName' in r))

                elif a['assetType'] == "Certificate":
                    # for Certificate collect issuerOrg, issuerName,
                    # subjectName, subjectAlternativeNames, subjectOrg, subjectOrgUnit
                    if (
                        (cert := details.get('certificate', None))
                        and isinstance(cert, dict)
                    ):
                        for f in ['issuerOrg', 'issuerName', 'subjectOrg', 'subjectName', 'subjectOrgUnit']:
                            if (x := cert.get(f, None)):
                                ml_feature_list.append(x)
                        if (
                                (san := cert.get('subjectAlternativeNames', None))
                                and isinstance(san, str)
                        ):
                            ml_feature_list.extend(san.split(' '))

                elif a['assetType'] == "Domain":
                    # for Domain collect domain, name servers, registrant and admin name/organization
                    if (
                        (whois := details.get('whois', None))
                        and isinstance(whois, list)
                        and len(whois) > 0
                        and isinstance(whois[0], dict)
                    ):
                        if (x := whois[0].get('domain', None)):
                            ml_feature_list.append(x)

                        # nameServers
                        if (
                            (ns := whois[0].get('nameServers', None))
                            and isinstance(ns, list)
                            and len(ns) > 0
                        ):
                            ml_feature_list.extend(ns)

                        # admin
                        if (admin := whois[0].get('admin', None)):
                            for f in ['name', 'organization']:
                                if (x := admin.get(f, None)):
                                    ml_feature_list.append(x)
                        # registrant
                        if (reg := whois[0].get('registrant', None)):
                            for f in ['name', 'organization']:
                                if (x := reg.get(f, None)):
                                    ml_feature_list.append(x)

        # demisto.debug(f'DEBUGDEBUG parse_asset_data: fetch_details is {fetch_details}, ml_features_list is {ml_feature_list!r}')
        if len(ml_feature_list) > 0:
            changed = True
        return assets, ml_feature_list, changed


""" HELPER FUNCTIONS """


def calculate_limits(limit: str) -> Tuple[int, int]:
    total_results = check_int(limit, 'limit', None, None, False)
    if not total_results:
        total_results = DEFAULT_RESULTS
    elif total_results > MAX_RESULTS:
        total_results = MAX_RESULTS
    max_page_size = MAX_PAGE_SIZE if total_results > MAX_PAGE_SIZE else total_results
    return (total_results, max_page_size)


def handle_iprange_include(arg: Optional[str], arg_name: Optional[str]) -> str:
    include = argToList(arg)
    sanitized_include: str = ''
    if include and not any('none' in i for i in include):
        if not all(i in IPRANGE_INCLUDE_OPTIONS for i in include):
            raise ValueError(f'{arg_name} must contain the following options: {", ".join(IPRANGE_INCLUDE_OPTIONS)}')
        else:
            sanitized_include = ','.join(include)

    return sanitized_include


def range_to_cidrs(start: str, end: str) -> Iterator[str]:
    try:
        for i in ipaddress.summarize_address_range(ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)):
            yield str(i)
    except ipaddress.AddressValueError as e:
        raise ValueError(f'Invalid IP address in range: {str(e)}')


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


def convert_priority_to_xsoar_severity(priority: str) -> int:
    """Maps Expanse priority to Cortex XSOAR severity
    Converts the Expanse issue priority  ('Low', 'Medium', 'High',
    'Critical') to Cortex XSOAR incident severity (1 to 4) for mapping.
    :type priority: ``str``
    :param priority: priority as returned from the Expanse API (str)
    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    return PRIORITY_SEVERITY_MAP[priority] if priority in PRIORITY_SEVERITY_MAP else PRIORITY_SEVERITY_MAP['Unknown']


def datestring_to_timestamp_us(ds: str) -> int:
    dt = parse(ds)
    ts = int(dt.timestamp()) * 1000000 + dt.microsecond
    # demisto.debug(f'DEBUGDEBUG datestring_to_timestamp_us source: {ds}, dt: {dt}, ts: {ts}')
    return ts


def timestamp_us_to_datestring_utc(ts: int, date_format: str = DATE_FORMAT) -> str:
    dt = datetime.fromtimestamp(ts // 1000000, timezone.utc).replace(microsecond=ts % 1000000)
    ds = dt.strftime(date_format)
    # demisto.debug(f'DEBUGDEBUG timestamp_us_to_datestring_utc source: {ts}, dt: {dt}, ts: {ds}')
    return ds


def format_domain_data(domains: List[Dict[str, Any]]) -> CommandResults:
    class DomainGlob(Common.Domain):
        def to_context(self):
            DBOT_CONTEXT_PATH = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator && ' \
                                'val.Vendor == obj.Vendor && val.Type == obj.Type)'
            c = super(DomainGlob, self).to_context()
            if not c or not isinstance(c, dict):
                return {}
            if DBOT_CONTEXT_PATH in c:
                if isinstance(c[DBOT_CONTEXT_PATH], dict):
                    c[DBOT_CONTEXT_PATH]['Type'] = 'domainglob'
                elif isinstance(c[DBOT_CONTEXT_PATH], list):
                    for n, l in enumerate(c['CONTEXT_PATH']):
                        if isinstance(l, dict):
                            c[DBOT_CONTEXT_PATH][n]['Type'] = 'domainglob'
            return c

    domain_standard_list: List[Union[Common.Domain, DomainGlob]] = []
    domain_data_list: List[Dict[str, Any]] = []

    for domain_data in domains:
        if not isinstance(domain_data, dict) or 'domain' not in domain_data:
            continue
        domain = domain_data['domain']

        whois_args = {}
        whois = domain_data.get('whois', None)
        if whois is not None and len(whois) > 0:
            whois = whois[0]
            admin = whois.get('admin', None)
            registrar = whois.get('registrar', None)
            registrant = whois.get('registrant', None)
            domain_statutes = whois.get('domainStatuses', None)

            whois_args['creation_date'] = whois.get('creationDate', None)
            whois_args['updated_date'] = whois.get('updatedDate', None)
            whois_args['expiration_date'] = whois.get('registryExpiryDate', None)
            whois_args['name_servers'] = whois.get('nameServers', None)
            whois_args['domain_status'] = domain_statutes[0] if domain_statutes is not None and len(domain_statutes) > 0 else None

            whois_args['organization'] = admin.get('organization', None) if admin is not None else None
            whois_args['admin_name'] = admin.get('name', None) if admin is not None else None
            whois_args['admin_email'] = admin.get('emailAddress', None) if admin is not None else None
            whois_args['admin_phone'] = admin.get('phoneNumber', None) if admin is not None else None
            whois_args['admin_country'] = admin.get('country', None) if admin is not None else None

            whois_args['registrar_name'] = registrar.get('name', None) if registrar is not None else None

            whois_args['registrant_email'] = registrant.get('emailAddress', None) if registrar is not None else None
            whois_args['registrant_name'] = registrant.get('name', None) if registrar is not None else None
            whois_args['registrant_phone'] = registrant.get('phoneNumber', None) if registrar is not None else None
            whois_args['registrant_country'] = registrant.get('country', None) if registrar is not None else None

        domain_standard_context: Union[Common.Domain, DomainGlob]
        if domain.startswith('*.'):
            # DomainGlob
            domain_standard_context = DomainGlob(
                domain=domain,
                dbot_score=Common.DBotScore(
                    indicator=domain,
                    indicator_type=DBotScoreType.DOMAIN,
                    integration_name="ExpanseV2",
                    score=Common.DBotScore.NONE
                ),
                **whois_args
            )
        else:
            # Domain
            domain_standard_context = Common.Domain(
                domain=domain,
                dbot_score=Common.DBotScore(
                    indicator=domain,
                    indicator_type=DBotScoreType.DOMAIN,
                    integration_name="ExpanseV2",
                    score=Common.DBotScore.NONE
                ),
                **whois_args
            )
        domain_standard_list.append(domain_standard_context)

        domain_context_excluded_fields: List[str] = []
        domain_data_list.append({
            k: domain_data[k]
            for k in domain_data if k not in domain_context_excluded_fields
        })

    readable_output = tableToMarkdown(
        'Expanse Domain List', domain_data_list) if len(domain_data_list) > 0 else "## No Domains found"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expanse.Domain',
        outputs_key_field='domain',
        outputs=domain_data_list if len(domain_data_list) > 0 else None,
        indicators=domain_standard_list if len(domain_standard_list) > 0 else None
    )


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.get_issue_count()
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization failed" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return "ok"


def get_issues_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    total_results, max_page_size = calculate_limits(args.get('limit', None))

    provider = ','.join(argToList(args.get('provider')))
    business_units = ','.join(argToList(args.get('business_unit')))
    assignee = ','.join(argToList(args.get('assignee')))
    issue_type = ','.join(argToList(args.get('issue_type')))
    tags = ','.join(argToList(args.get('tag')))

    content_search = args.get('content_search')
    inet_search = args.get('domain_search')
    domain_search = args.get('domain_search')

    arg_list = argToList(args.get('port_number'))
    # this will trigger exceptions if data is invalid
    all(check_int(i, 'port_number', 0, 65535, True) for i in arg_list)
    port_number = ','.join(arg_list)

    arg_list = argToList(args.get('progress_status'))
    if arg_list and not all(i in ISSUE_PROGRESS_STATUS for i in arg_list):
        raise ValueError(f'progress_status must include: {", ".join(ISSUE_PROGRESS_STATUS)}')
    progress_status = ','.join(arg_list)

    arg_list = argToList(args.get('activity_status'))
    if arg_list and not all(i in ISSUE_ACTIVITY_STATUS for i in arg_list):
        raise ValueError(f'activity_status must include: {", ".join(ISSUE_ACTIVITY_STATUS)}')
    activity_status = ','.join(arg_list)

    arg_list = argToList(args.get('priority'))
    if arg_list and not all(i in ISSUE_PRIORITY for i in arg_list):
        raise ValueError(f'priority must include: {", ".join(ISSUE_PRIORITY)}')
    priority = ','.join(arg_list)

    arg_list = argToList(args.get('sort'))
    if arg_list and not all(i in ISSUE_SORT_OPTIONS for i in arg_list):
        raise ValueError(f'sort must include: {", ".join(ISSUE_SORT_OPTIONS)}')
    sort = ','.join(arg_list)

    d = args.get('created_before', None)
    created_before = parse(d).strftime(DATE_FORMAT) if d else None

    d = args.get('created_after', None)
    created_after = parse(d).strftime(DATE_FORMAT) if d else None

    d = args.get('modified_before', None)
    modified_before = parse(d).strftime(DATE_FORMAT) if d else None

    d = args.get('modified_after', None)
    modified_after = parse(d).strftime(DATE_FORMAT) if d else None

    issues = list(
        islice(
            client.get_issues(limit=max_page_size, content_search=content_search, provider=provider,
                              business_units=business_units, assignee=assignee, issue_type=issue_type,
                              inet_search=inet_search, domain_search=domain_search, port_number=port_number,
                              progress_status=progress_status, activity_status=activity_status, priority=priority,
                              tags=tags, created_before=created_before, created_after=created_after,
                              modified_before=modified_before, modified_after=modified_after, sort=sort),
            total_results
        )
    )

    if len(issues) < 1:
        return CommandResults(readable_output='No Issues Found')

    return CommandResults(
        outputs_prefix="Expanse.Issue", outputs_key_field="id", outputs=issues
    )


def get_issue_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    issue_id = args.get('issue_id', None)
    if not issue_id:
        raise ValueError('issue_id not specified')

    issue = client.get_issue_by_id(issue_id=issue_id)

    return CommandResults(
        outputs_prefix="Expanse.Issue", outputs_key_field="id", outputs=issue
    )


def get_issue_updates_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    total_results, max_page_size = calculate_limits(args.get('limit', None))

    issue_id = args.get('issue_id', None)
    if not issue_id:
        raise ValueError('issue_id not specified')

    update_types = argToList(args.get('update_types'))
    if update_types and not all(i in ISSUE_UPDATE_TYPES.keys() for i in update_types):
        raise ValueError(f'Invalid update_type: {update_types}. Must include: {",".join(ISSUE_UPDATE_TYPES.keys())}')

    d = args.get('created_after', None)
    created_after = parse(d).strftime(DATE_FORMAT) if d else None

    issue_updates = [
        {**u, "issueId": issue_id}  # this adds the issue id to the resulting dict
        for u in sorted(
            islice(
                client.get_issue_updates(
                    issue_id=issue_id,
                    limit=max_page_size,
                    update_types=update_types,
                    created_after=created_after
                ),
                total_results
            ),
            key=lambda k: k['created']
        )
    ]

    # demisto.debug(f'DEBUGDEBUG issue_updates is {json.dumps(issue_updates)}')
    return CommandResults(
        outputs_prefix="Expanse.IssueUpdate", outputs_key_field="id", outputs=issue_updates
    )


def get_issue_comments_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    total_results, max_page_size = calculate_limits(args.get('limit', None))

    issue_id = args.get('issue_id', None)
    if not issue_id:
        raise ValueError('issue_id not specified')

    d = args.get('created_after', None)
    created_after = parse(d).strftime(DATE_FORMAT) if d else None

    issue_comments = [
        {**u, "issueId": issue_id}  # this adds the issue id to the resulting dict
        for u in sorted(
            islice(
                client.get_issue_updates(
                    issue_id=issue_id,
                    limit=max_page_size,
                    update_types=['Comment'],
                    created_after=created_after
                ),
                total_results
            ),
            key=lambda k: k['created']
        )
    ]

    for n, c in enumerate(issue_comments):
        if (u := c.get('user'), None) and isinstance(u, dict) and 'username' in u:
            issue_comments[n]['user'] = u['username']

    md = tableToMarkdown(
        name='Expanse Issue Comments',
        t=issue_comments,
        headers=['user', 'value', 'created'],
        headerTransform=pascalToSpace,
        removeNull=True
    )

    return CommandResults(
        outputs_prefix="Expanse.IssueComment",
        outputs_key_field="id",
        outputs=issue_comments,
        readable_output=md
    )


def update_issue_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    issue_id = args.get('issue_id', None)
    if not issue_id:
        raise ValueError('issue_id not specified')

    update_type = args.get("update_type", None)
    if not update_type or update_type not in ISSUE_UPDATE_TYPES:
        raise ValueError(f'update_type must be one of: {",".join(ISSUE_UPDATE_TYPES.keys())}')

    value = args.get('value', None)
    if not value:
        raise ValueError('value must be specified')

    issue_update = client.update_issue(issue_id, update_type, value)

    return CommandResults(
        outputs_prefix="Expanse.IssueUpdate", outputs_key_field="id", outputs=issue_update
    )


def fetch_incidents(client: Client, max_incidents: int,
                    last_run: Dict[str, Union[Optional[int], Optional[str]]], first_fetch: Optional[int],
                    priority: Optional[str], activity_status: Optional[str],
                    progress_status: Optional[str], business_units: Optional[str], issue_types: Optional[str],
                    tags: Optional[str], mirror_direction: Optional[str], sync_tags: Optional[List[str]],
                    fetch_details: Optional[bool], fetch_behavior: Optional[bool]
                    ) -> Tuple[Dict[str, Union[Optional[int], Optional[str]]], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).
    This function has to implement the logic of making sure that incidents are
    fetched only onces and no incidents are missed. By default it's invoked by
    XSOAR every minute. It will use last_run to save the timestamp of the last
    incident it processed. If last_run is not provided, it should use the
    integration parameter first_fetch to determine when to start fetching
    the first time. Uses "createdAfter" in the Expanse API for timestamp.

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch, and the last issue id.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR
    :rtype: ``Tuple[Dict[str, Union[Optional[int], Optional[str]]], List[dict]]``
    """

    last_fetch = last_run.get('last_fetch', None)
    if last_fetch is None:
        last_fetch = cast(int, first_fetch)
    else:
        last_fetch = cast(int, last_fetch)

    latest_created_time = last_fetch
    # demisto.debug(
    # f'DEBUGDEBUG fetch_incidents: last_fetch is {last_fetch}'
    # f' [{timestamp_us_to_datestring_utc(latest_created_time, DATE_FORMAT)}]')

    last_issue_id = last_run.get('last_issue_id', None)
    # demisto.debug(f'DEBUGDEBUG fetch_incidents: last_issue_id is {last_issue_id}')
    latest_issue_id: Optional[str] = None

    incidents: List[Dict[str, Any]] = []

    arg_list = argToList(priority)
    if arg_list and not all(i in ISSUE_PRIORITY for i in arg_list):
        raise ValueError(f'priority must include: {", ".join(ISSUE_PRIORITY)}')
    _priority = ','.join(arg_list)

    arg_list = argToList(progress_status)
    if arg_list and not all(i in ISSUE_PROGRESS_STATUS for i in arg_list):
        raise ValueError(f'progressStatus must include: {", ".join(ISSUE_PROGRESS_STATUS)}')
    _progress_status = ','.join(arg_list)

    arg_list = argToList(activity_status)
    if arg_list and not all(i in ISSUE_ACTIVITY_STATUS for i in arg_list):
        raise ValueError(f'activityStatus must include: {", ".join(ISSUE_ACTIVITY_STATUS)}')
    _activity_status = ','.join(arg_list)

    created_after = timestamp_us_to_datestring_utc(latest_created_time, DATE_FORMAT)

    r = client.get_issues(
        limit=max_incidents if not last_issue_id else max_incidents + 1,  # workaround to avoid unnecessary API calls
        priority=_priority, business_units=business_units,
        progress_status=_progress_status, activity_status=_activity_status, tags=tags,
        created_after=created_after, sort='created'
    )

    broken = False
    issues: List = []
    skip = cast(str, last_issue_id)
    for i in r:
        if skip and not broken:
            if 'id' not in i or 'created' not in i:
                # demisto.debug('DEBUGDEBUG get_issues: skipping an incident that does not have id or created')
                continue

            # fix created time to make sure precision is the same to microsecond with no rounding
            i['created'] = timestamp_us_to_datestring_utc(datestring_to_timestamp_us(i['created']), DATE_FORMAT)

            # demisto.debug(f'DEBUGDEBUG get_issues: skip check is on loop: processing issue {i["id"]}')
            if i['created'] != created_after:
                # demisto.debug(f'DEBUGDEBUG get_issues: breaking as {i["id"]}  time different than created_after '
                #               f'[{i["created"]} vs {created_after}]')
                issues.append(i)
                broken = True
            elif i['id'] == skip:
                # demisto.debug(f'DEBUGDEBUG get_issues: breaking as found id {skip} (skipping this one)')
                broken = True
            else:
                pass
                # demisto.debug(f'DEBUGDEBUG get_issues: skipping possible dup incident {i["id"]}')
        else:
            # demisto.debug(f'DEBUGDEBUG get_issues: adding incident {i["id"]}')
            issues.append(i)
        if len(issues) == max_incidents:
            # demisto.debug(f'DEBUGDEBUG get_issues: got enough incidents ({max_issues}), exiting for cycle')
            break

    # demisto.debug(f'DEBUGDEBUG get_issues: returning IDs: [{str([i["id"] for i in ret])}]')
    # demisto.debug(f'DEBUGDEBUG fetch_incidents: created_after is {created_after}')

    for issue in issues:
        ml_feature_list: List[str] = []

        if 'created' not in issue or 'id' not in issue:
            continue
        incident_created_time = datestring_to_timestamp_us(issue['created'])

        # demisto.debug(
        #     f'DEBUGDEBUG fetch_incidents: loop: issue id is {issue["id"]} created at '
        #     f'{issue["created"]} and incident_created_time is {incident_created_time} '
        #     f'[{timestamp_us_to_datestring_utc(incident_created_time, DATE_FORMAT)}]')
        if last_fetch:
            if incident_created_time < last_fetch:
                # demisto.debug(f'DEBUGDEBUG fetch_incidents loop: skipping issue id {issue["id"]}')
                continue
        incident_name = issue['headline'] if 'headline' in issue else issue['id']

        # Mirroring
        issue['xsoar_mirroring'] = {
            'mirror_direction': mirror_direction,
            'mirror_id': issue['id'],
            'mirror_instance': demisto.integrationInstance(),
            'sync_tags': sync_tags
        }
        issue['xsoar_severity'] = convert_priority_to_xsoar_severity(issue.get('priority', 'Unknown'))

        # Handle asset information
        issue['assets'], ml_feature_list, _ = client.parse_asset_data(issue, fetch_details)

        # add issue specific information to ml key
        if (
            (provider := issue.get('providers', None))
            and isinstance(provider, list)
            and len(provider) > 0
            and 'name' in provider[0]
        ):
            ml_feature_list.append(provider[0]['name'])
        if (
            (latest_evidence := issue.get('latestEvidence', None))
            and isinstance(latest_evidence, dict)
        ):
            if (
                (geolocation := latest_evidence.get('geolocation', None))
                and isinstance(geolocation, dict)
            ):
                for f in ['countryCode', 'city']:
                    if (x := geolocation.get(f, None)):
                        ml_feature_list.append(x)

        # demisto.debug(f'DEBUGDEBUG fetch_incidents: ml_features_list is {ml_feature_list!r}')
        # dedup, sort and join ml feature list
        issue['ml_features'] = ' '.join(sorted(list(set(ml_feature_list))))
        incident = {
            'name': incident_name,
            'details': issue['helpText'] if 'helpText' in issue else None,
            'occurred': issue['created'],
            'rawJSON': json.dumps(issue),
            'severity': issue['xsoar_severity']
        }
        latest_issue_id = issue['id']
        incidents.append(incident)
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time
            # demisto.debug(
            #     f'DEBUGDEBUG fetch_incidents loop: issue id is {issue["id"]} and '
            #     f' updating latest_created_time to {latest_created_time} '
            #     f'[{timestamp_us_to_datestring_utc(latest_created_time, DATE_FORMAT)}]')

    next_run = {
        'last_fetch': latest_created_time,
        'last_issue_id': latest_issue_id if latest_issue_id else last_issue_id}
    # demisto.debug(f'DEBUGDEBUG fetch_incidents: next_run is {next_run} ({timestamp_us_to_datestring_utc(latest_created_time)}')
    return next_run, incidents


def get_remote_data_command(client: Client, args: Dict[str, Any], sync_owners: bool = False,
                            incoming_tags: Optional[List[str]] = [], mirror_details: bool = False) -> GetRemoteDataResponse:
    parsed_args = GetRemoteDataArgs(args)
    # demisto.debug(f'DEBUGDEBUG get_remote_data_command invoked on incident {parsed_args.remote_incident_id} '
    #               f'with last_update: {parsed_args.last_update}')
    issue_updates: List[Dict[str, Any]] = sorted(
        islice(
            client.get_issue_updates(
                issue_id=parsed_args.remote_incident_id,
                limit=MAX_UPDATES,
                update_types=None,
                created_after=parsed_args.last_update
            ),
            MAX_UPDATES
        ),
        key=lambda k: k['created']
    )

    new_entries: List = []
    incident_updates: Dict[str, Any] = {}
    latest_comment: Dict[str, Any] = {}  # used for closing comment
    for update in issue_updates:
        update_type = update['updateType']
        if not update_type or update_type not in ISSUE_UPDATE_TYPES:
            demisto.debug('Skipping unknown Expanse incoming update type: {update_type}')
            continue

        new_value = update['value']
        if not new_value:
            continue

        updated_field = ISSUE_UPDATE_TYPES[update_type]
        previous_value = update['previousValue'] if 'previousValue' in update else None
        update_user = update['user']['username'] if 'user' in update and 'username' in update['user'] else 'Unknown user'

        # handle incoming comment
        if update_type == 'Comment':
            new_entries.append({
                'Type': EntryType.NOTE,
                'Contents': f'{update_user} added a comment: [{new_value}]',
                'ContentsFormat': EntryFormat.TEXT,
                'Note': True,
                'Tags': incoming_tags
            })
            latest_comment = update

        # handle incoming ownership change
        elif update_type == 'Assignee':
            incident_updates[updated_field] = new_value
            new_entries.append({
                'Type': EntryType.NOTE,
                'Contents': f'Mirroring: {update_user} changed assignee from [{previous_value}] to [{new_value}]',
                'ContentsFormat': EntryFormat.TEXT,
                'Note': False
            })
            if not sync_owners:
                continue
            # handle unassignment
            if new_value == 'Unassigned':
                incident_updates['xsoar_owner'] = ''
                continue
            # new user assignment
            user_info = demisto.findUser(email=new_value)
            if user_info:
                incident_updates['xsoar_owner'] = user_info.get('username')
            else:
                demisto.debug(f'The user assigned to Expanse incident {parsed_args.remote_incident_id} [{new_value}]'
                              f'is not registered on XSOAR, cannot change owner')

        # handle issue closure
        elif update_type == 'ProgressStatus' and new_value in ISSUE_PROGRESS_STATUS_CLOSED:
            close_reason = EXPANSE_RESOLVEDSTATUS_TO_XSOAR[new_value] if new_value in EXPANSE_RESOLVEDSTATUS_TO_XSOAR else 'Other'
            resolve_comment = latest_comment['value'] if 'value' in latest_comment else ''
            demisto.debug(f'Closing Expanse issue {parsed_args.remote_incident_id}')
            new_entries.append({
                'Type': EntryType.NOTE,
                'Contents': {
                    'dbotIncidentClose': True,
                    'closeReason': close_reason,
                    'closeNotes': resolve_comment
                },
                'ContentsFormat': EntryFormat.JSON
            })
            incident_updates['closeReason'] = close_reason
            incident_updates['closeNotes'] = resolve_comment

        # handle everything else
        else:
            incident_updates[updated_field] = new_value
            if update_type == 'Priority':
                incident_updates['xsoar_severity'] = convert_priority_to_xsoar_severity(new_value)
            new_entries.append({
                'Type': EntryType.NOTE,
                'Contents': f'Mirroring: {update_user} updated field [{updated_field}] from [{previous_value}] to [{new_value}]',
                'ContentsFormat': EntryFormat.TEXT,
                'Note': False
            })

    # update_assets
    if mirror_details:
        issue_details: Dict[str, Any] = client.get_issue_by_id(issue_id=parsed_args.remote_incident_id)
        assets, ml_feature_list, changed = client.parse_asset_data(issue_details, mirror_details)
        if changed:
            incident_updates['assets'] = assets
            # dedup, sort and join ml feature list
            incident_updates['ml_features'] = ' '.join(sorted(set(ml_feature_list)))

    # process incident updates only if anything has changed
    if len(incident_updates) > 0 or len(new_entries) > 0:
        incident_updates['id'] = parsed_args.remote_incident_id

    # demisto.debug(f'DEBUGDEBUG get-remote-data returning {json.dumps(incident_updates)} and {json.dumps(new_entries)}')
    return GetRemoteDataResponse(incident_updates, new_entries)


def update_remote_system_command(client: Client, args: Dict[str, Any], sync_owners: bool = False) -> str:
    remote_args = UpdateRemoteSystemArgs(args)
    # demisto.debug(f'DEBUGDEBUG update-remote-system: remote args is {json.dumps(args)}')
    remote_incident_id = remote_args.remote_incident_id
    # demisto.debug(f'DEBUGDEBUG update-remote-system remote ID is: [{remote_incident_id}]')
    try:
        # demisto.debug(f'DEBUGDEBUG update-remote-system entries {json.dumps(remote_args.entries)}')
        changed: bool = False
        entries: List = remote_args.entries if remote_args.entries else []
        for e in entries:
            # demisto.debug(f'DEBUGDEBUG update-remote-system entry is: {json.dumps(e)}')
            if 'contents' in e and 'category' in e and e['category'] == 'chat':
                # demisto.debug(f'DEBUGDEBUG update-remote-system sending comment {e["contents"]}')
                client.update_issue(
                    issue_id=remote_incident_id,
                    update_type='Comment',
                    value=e['contents']
                )
                changed = True

        if remote_args.delta and remote_args.incident_changed:
            delta = remote_args.delta
            # demisto.debug(f'DEBUGDEBUG update-remote-system delta keys {str(list(remote_args.delta.keys()))}'
            #              f' on remote ID [{remote_incident_id}]')
            # demisto.debug(f'DEBUGDEBUG update-remote-system deltas {json.dumps(remote_args.delta)}'
            #              f' on remote ID [{remote_incident_id}]')

            # handle ownership change
            if 'owner' in delta:
                owner_email: Optional[str] = None
                owner_user = delta.get('owner')
                if owner_user:
                    user_info = demisto.findUser(username=owner_user)
                    if user_info and isinstance(user_info, dict) and 'email' in user_info:
                        owner_email = user_info.get('email')
                if owner_email:
                    client.update_issue(
                        issue_id=remote_incident_id,
                        update_type='Assignee',
                        value=owner_email
                    )
                    # demisto.debug(f'DEBUGDEBUG update-remote-system set owner to {owner_email}'
                    #               f' on remote ID [{remote_incident_id}]')
                else:
                    # demisto.debug(f'DEBUGDEBUG update-remote-system removing owner on remote ID [{remote_incident_id}]')
                    client.update_issue(
                        issue_id=remote_incident_id,
                        update_type='Assignee',
                        value='Unassigned'
                    )

            # handle severity
            if 'severity' in delta and delta['severity'] in SEVERITY_PRIORITY_MAP:
                client.update_issue(
                    issue_id=remote_incident_id,
                    update_type='Priority',
                    value=SEVERITY_PRIORITY_MAP[delta['severity']]
                )

            # handle issue closing
            if remote_args.inc_status == 2:
                close_reason = remote_args.data.get('closeReason', None)
                close_notes = remote_args.data.get('closeNotes', None)
                client.update_issue(
                    issue_id=remote_incident_id,
                    update_type='Comment',
                    value=f'Issue closed in XSOAR with reason: {close_reason}\nNotes: {close_notes}'
                )
                client.update_issue(
                    issue_id=remote_incident_id,
                    update_type='ProgressStatus',
                    value='Resolved'
                )

            #     demisto.debug(f'DEBUGDEBUG update-remote-system closing remote ID [{remote_incident_id}]'
            #                   f'with close reason {close_reason} and close_notes {close_notes}')
            # # handle Progress Status change
            elif 'expanseprogressstatus' in delta and delta['expanseprogressstatus'] in ISSUE_PROGRESS_STATUS:
                client.update_issue(
                    issue_id=remote_incident_id,
                    update_type='ProgressStatus',
                    value=delta['expanseprogressstatus']
                )

        if changed:
            pass
            # demisto.debug(f'DEBUGDEBUG update-remote-system Updating on remote ID [{remote_incident_id}]')
        else:
            pass
            # demisto.debug(f'DEBUGDEBUG update-remote-system Skipping update on remote ID [{remote_incident_id}] [no changes]')

    except Exception as e:
        # demisto.debug(f"DEBUGDEBUG update-remote-system Error in Expanse outgoing mirror for incident {remote_incident_id} \n"
        #               f"Error message: {str(e)}")
        raise e

    return remote_incident_id


def list_businessunits_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    total_results, max_page_size = calculate_limits(args.get('limit', None))
    outputs = list(
        islice(client.list_businessunits(limit=max_page_size), total_results)
    )

    return CommandResults(
        outputs_prefix="Expanse.BusinessUnit",
        outputs_key_field="id",
        outputs=outputs if len(outputs) > 0 else None,
        readable_output="## No Business Units found" if len(outputs) == 0 else None
    )


def list_providers_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    total_results, max_page_size = calculate_limits(args.get('limit', None))
    outputs = list(
        islice(client.list_providers(limit=max_page_size), total_results)
    )
    return CommandResults(
        outputs_prefix="Expanse.Provider",
        outputs_key_field="id",
        outputs=outputs if len(outputs) > 0 else None,
        readable_output="## No Providers found" if len(outputs) == 0 else None
    )


def list_tags_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    total_results, max_page_size = calculate_limits(args.get('limit', None))
    outputs = list(
        islice(client.list_tags(limit=max_page_size), total_results)
    )
    return CommandResults(
        outputs_prefix="Expanse.Tag",
        outputs_key_field="id",
        outputs=outputs if len(outputs) > 0 else None,
        readable_output="## No Tags found" if len(outputs) == 0 else None
    )


def create_tag_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name: str = args.get('name', '')
    if not name or len(name) < 1 or len(name) > 127:
        raise ValueError('Tag name must be less than 128 characters long')

    description: str = args.get('description', '')
    if description and len(description) > 511:
        raise ValueError('Tag description must be less than 512 characters long')

    try:
        tag = client.create_tag(name, description)
    except DemistoException as e:
        if str(e).startswith('Error in API call [409]'):
            return CommandResults(readable_output='Tag already exists')
        raise e

    return CommandResults(
        outputs_prefix="Expanse.Tag",
        outputs_key_field="id",
        outputs=tag
    )


def manage_asset_tags_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_type = args.get('operation_type', None)
    if operation_type not in ASSET_TAG_OPERATIONS:
        raise ValueError(f'Operation type must be one of {",".join(ASSET_TAG_OPERATIONS)}')

    asset_type = args.get('asset_type', None)
    if not asset_type or asset_type not in TAGGABLE_ASSET_TYPE_MAP:
        raise ValueError(f'Asset type must be one of {",".join(TAGGABLE_ASSET_TYPE_MAP.keys())}')
    mapped_asset_type = TAGGABLE_ASSET_TYPE_MAP[asset_type]

    asset_id = args.get('asset_id', None)
    if not asset_id:
        raise ValueError('Asset id must be provided')

    tag_ids = argToList(args.get('tags'))
    tag_names = argToList(args.get('tagnames'))
    if len(tag_names) > 0:
        [tag_ids.append(t['id']) for t in client.list_tags() if t['name'] in tag_names]
    tags: List[str] = list(set(tag_ids))
    if len(tags) < 1:
        raise ValueError('Must provide valid tag IDs or names')

    client.manage_asset_tags(mapped_asset_type, operation_type, asset_id, tags)
    return CommandResults(
        readable_output='Operation complete'
    )


def get_iprange_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    include = handle_iprange_include(args.pop('include', None), 'include')
    id_: Optional[str] = args.pop('id', None)

    if id_ is not None and len(args) != 0:
        raise ValueError("You can only use [id] only with [include] parameter")

    total_results, max_page_size = calculate_limits(args.get('limit', None))

    outputs: Iterator[Any] = iter([])
    ip_ranges: List = []
    if id_ is not None:
        outputs = iter([client.get_iprange_by_id(id_, include)])
    else:
        params: Dict = {
            "include": include,
            "limit": max_page_size
        }

        business_units = argToList(args.get('businessunits'))
        if len(business_units) != 0:
            params['business-units'] = ','.join(business_units)
        business_unit_names = argToList(args.get('businessunitnames'))
        if len(business_unit_names) != 0:
            params['business-unit-names'] = ','.join(business_unit_names)
        inet = args.get('inet')
        if inet is not None:
            params['inet'] = inet
        tags = argToList(args.get('tags'))
        if len(tags) != 0:
            params['tags'] = ','.join(tags)
        tag_names = argToList(args.get('tagnames'))
        if len(tag_names) != 0:
            params['tag-names'] = ','.join(tag_names)

        outputs = client.get_ipranges(params=params)

    for o in outputs:
        o['cidr'] = ','.join(range_to_cidrs(o['startAddress'], o['endAddress'])) if (
            'startAddress' in o
            and 'endAddress' in o
        ) else None

        cidr_context_excluded_fields: List[str] = ['startAddress', 'endAddress']
        ip_ranges.append({
            k: o[k]
            for k in o if k not in cidr_context_excluded_fields
        })
        if len(ip_ranges) >= total_results:
            break

    return CommandResults(
        outputs_prefix="Expanse.IPRange",
        outputs_key_field="id",
        readable_output="## No IP Ranges found" if len(ip_ranges) == 0 else None,
        outputs=ip_ranges if len(ip_ranges) > 0 else None
    )


def get_domain_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    domain: Optional[str] = args.pop('domain', None)
    last_observed_date: Optional[str] = args.pop('last_observed_date', None)

    if domain is not None and len(args) != 0:
        raise ValueError("The only argument allowed with domain is last_observed_date")

    total_results, max_page_size = calculate_limits(args.get('limit', None))

    if domain is not None:
        output = client.get_domain_by_domain(domain=domain, last_observed_date=last_observed_date)
        if output and isinstance(output, dict) and 'domain' not in output:
            output['domain'] = domain
        return format_domain_data([output])

    params: Dict[str, Any] = {
        "limit": max_page_size
    }

    domain_search: Optional[str] = args.get('search', None)
    if domain_search is not None:
        params['domainSearch'] = domain_search

    provider_id = argToList(args.get('providers'))
    if len(provider_id) > 0:
        params['providerId'] = ','.join(provider_id)

    provider_name = argToList(args.get('providernames'))
    if len(provider_name) > 0:
        params['providerName'] = ','.join(provider_name)

    business_unit_id = argToList(args.get('businessunits'))
    if len(business_unit_id) > 0:
        params['businessUnitId'] = ','.join(business_unit_id)

    business_unit_name = argToList(args.get('businessunitnames'))
    if len(business_unit_name) > 0:
        params['businessUnitName'] = ','.join(business_unit_name)

    tag_id = argToList(args.get('tags'))
    if len(tag_id) > 0:
        params['tagId'] = ','.join(tag_id)

    tag_name = argToList(args.get('tagnames'))
    if len(tag_name) > 0:
        params['tagName'] = ','.join(tag_name)

    dns_resolution_status = args.get('has_dns_resolution')
    if dns_resolution_status is not None:
        params['dnsResolutionStatus'] = "HAS_DNS_RESOLUTION" if argToBoolean(dns_resolution_status) else "NO_DNS_RESOLUTION"

    service_status = args.get('has_active_service')
    if service_status is not None:
        params['serviceStatus'] = "HAS_ACTIVE_SERVICE" if argToBoolean(service_status) else "NO_ACTIVE_SERVICE"

    has_related_cloud_resources = args.get('has_related_cloud_resources')
    if has_related_cloud_resources is not None:
        params['hasRelatedCloudResources'] = "true" if argToBoolean(has_related_cloud_resources) else "false"

    if last_observed_date is not None:
        params['minLastObservedDate'] = last_observed_date

    domain_data = list(
        islice(
            client.get_domains(params=params),
            total_results
        )
    )
    return format_domain_data(domain_data)


def get_certificate_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    pem_md5_hash: Optional[str] = args.pop('pem_md5_hash', None)
    last_observed_date: Optional[str] = args.pop('last_observed_date', None)

    if pem_md5_hash is not None and len(args) != 0:
        raise ValueError("The only argument allowed with pem_md5_hash is last_observed_date")

    total_results, max_page_size = calculate_limits(args.get('limit', None))

    if pem_md5_hash is not None:
        output = client.get_certificate_by_pem_md5_hash(
            pem_md5_hash=pem_md5_hash,
            last_observed_date=last_observed_date
        )
        return CommandResults(
            outputs_prefix="Expanse.Certificate",
            outputs_key_field="id",
            readable_output="## No Certificates found" if not output else None,
            outputs=output if output else None
        )

    params: Dict[str, Any] = {
        "limit": max_page_size
    }
    cn_search: Optional[str] = args.get('search', None)
    if cn_search is not None:
        params['commonNameSearch'] = cn_search

    provider_id = argToList(args.get('providers'))
    if len(provider_id) > 0:
        params['providerId'] = ','.join(provider_id)

    provider_name = argToList(args.get('providernames'))
    if len(provider_name) > 0:
        params['providerName'] = ','.join(provider_name)

    business_unit_id = argToList(args.get('businessunits'))
    if len(business_unit_id) > 0:
        params['businessUnitId'] = ','.join(business_unit_id)

    business_unit_name = argToList(args.get('businessunitnames'))
    if len(business_unit_name) > 0:
        params['businessUnitName'] = ','.join(business_unit_name)

    tag_id = argToList(args.get('tags'))
    if len(tag_id) > 0:
        params['tagId'] = ','.join(tag_id)

    tag_name = argToList(args.get('tagnames'))
    if len(tag_name) > 0:
        params['tagName'] = ','.join(tag_name)

    certificate_advertisement_status = args.get('has_certificate_advertisement')
    if certificate_advertisement_status is not None:
        if argToBoolean(certificate_advertisement_status):
            params['certificateAdvertisementStatus'] = "HAS_CERTIFICATE_ADVERTISEMENT"
        else:
            params['certificateAdvertisementStatus'] = "NO_CERTIFICATE_ADVERTISEMENT"

    service_status = args.get('has_active_service')
    if service_status is not None:
        params['serviceStatus'] = "HAS_ACTIVE_SERVICE" if argToBoolean(service_status) else "NO_ACTIVE_SERVICE"

    has_related_cloud_resources = args.get('has_related_cloud_resources')
    if has_related_cloud_resources is not None:
        params['hasRelatedCloudResources'] = "true" if argToBoolean(has_related_cloud_resources) else "false"

    if last_observed_date is not None:
        params['minLastObservedDate'] = last_observed_date

    cert_data = list(
        islice(
            client.get_certificates(params=params),
            total_results
        )
    )
    return CommandResults(
        outputs_prefix="Expanse.Certificate",
        outputs_key_field="id",
        readable_output="## No Certificates found" if len(cert_data) == 0 else None,
        outputs=cert_data if len(cert_data) > 0 else None
    )


def expanse_certificate_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    # XXX - should we dump the full timeline of the certificate inside the details?
    class ExpanseCertificate(Common.Indicator):
        def __init__(self, indicator: str):
            self.indicator = indicator

        def to_context(self):
            return {
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator && '
                'val.Vendor == obj.Vendor && val.Type == obj.Type)': {
                    'Score': Common.DBotScore.NONE,
                    'Vendor': 'ExpanseV2',
                    'Type': 'ExpanseCertificate',
                    'Indicator': self.indicator
                }
            }

    pem_md5_hashes = argToList(args.get('pem_md5_hash'))
    if len(pem_md5_hashes) == 0:
        raise ValueError('pem_md5_hash(s) not specified')

    certificate_standard_list: List[Common.Indicator] = []
    certificate_data_list: List[Dict[str, Any]] = []

    for pem_md5_hash in pem_md5_hashes:
        certificate_data = client.get_certificate_by_pem_md5_hash(pem_md5_hash=pem_md5_hash)
        certificate_data['pemMD5Hash'] = pem_md5_hash

        # We can't use Common.DBotScore here because ExpanseCertificate is not one of the well known
        # Indicator types
        certificate_standard_context = ExpanseCertificate(pem_md5_hash)
        certificate_standard_list.append(certificate_standard_context)

        if 'certificate' in certificate_data:
            details = certificate_data['details']

            if 'base64Encoded' in details:
                try:
                    cert_der = b64decode(details['base64Encoded'])
                    sha256_fingerprint = sha256(cert_der).hexdigest()
                    certificate_data['sha256Fingerprint'] = sha256_fingerprint
                except ValueError:
                    pass

            if 'recentIps' in details:
                certificate_data['feedrelatedindicators'] = [
                    {'value': rip['ip'], 'type': 'IP', 'description': ""}
                    for rip in details['recentIps'] if 'ip' in rip
                ]

        certificate_context_excluded_fields: List[str] = []
        certificate_data_list.append({
            k: certificate_data[k]
            for k in certificate_data if k not in certificate_context_excluded_fields
        })

    readable_output = tableToMarkdown(
        'ExpanseCertificate List', certificate_data_list) if len(certificate_data_list) > 0 else "## No Certificates found"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expanse.ExpanseCertificate',
        outputs_key_field='pemMD5Hash',
        outputs=certificate_data_list if len(certificate_data_list) > 0 else None,
        indicators=certificate_standard_list if len(certificate_standard_list) > 0 else None
    )


def domain_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    # XXX - implement feed related indicators using recentIPs
    domains = argToList(args.get('domain'))
    if len(domains) == 0:
        raise ValueError('domain(s) not specified')

    domain_data: List[Dict[str, Any]] = []

    for domain in domains:
        d = client.get_domain_by_domain(domain=domain)
        if not d or not isinstance(d, dict):
            continue
        if 'domain' not in d:
            d['domain'] = 'domain'
        domain_data.append(d)

    return format_domain_data(domain_data)


def ip_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('ip(s) not specified')

    ip_standard_list: List[Common.IP] = []
    ip_data_list: List[Dict[str, Any]] = []

    for ip in ips:
        ip_data = next(client.get_ips(params={'inetSearch': f"{ip}", "limit": 1}), None)
        if ip_data is None:
            continue

        ip_data['ip'] = ip

        ip_standard_context = Common.IP(
            ip=ip,
            dbot_score=Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name="ExpanseV2",
                score=Common.DBotScore.NONE
            ),
            hostname=ip_data.get('domain', None)
        )
        ip_standard_list.append(ip_standard_context)

        ip_context_excluded_fields: List[str] = []
        ip_data_list.append({
            k: ip_data[k]
            for k in ip_data if k not in ip_context_excluded_fields
        })

    readable_output = tableToMarkdown(
        'Expanse IP List', ip_data_list) if len(ip_data_list) > 0 else "## No IPs found"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expanse.IP',
        outputs_key_field='IP',
        outputs=ip_data_list if len(ip_data_list) > 0 else None,
        indicators=ip_standard_list if len(ip_standard_list) > 0 else None
    )


def cidr_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    class ExpanseCIDR(Common.Indicator):
        def __init__(self, indicator: str):
            self.indicator = indicator

        def to_context(self):
            return {
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator && '
                'val.Vendor == obj.Vendor && val.Type == obj.Type)': {
                    'Score': Common.DBotScore.NONE,
                    'Vendor': 'ExpanseV2',
                    'Type': 'CIDR',
                    'Indicator': self.indicator
                }
            }
    cidrs = argToList(args.get('cidr'))
    if len(cidrs) == 0:
        raise ValueError('cidr(s) not specified')

    # trim down the list to the max number of supported results
    if len(cidrs) > MAX_RESULTS:
        cidrs = cidrs[:MAX_RESULTS]

    include = handle_iprange_include(args.get('include'), 'include')

    cidr_data_list: List[Dict[str, Any]] = []
    cidr_standard_list: List[Common.Indicator] = []

    for cidr in cidrs:
        cidr_data = next(client.get_ipranges(params={'inet': cidr, 'include': include, 'limit': 1}), None)
        if cidr_data is None:
            continue

        cidr_data['cidr'] = ','.join(range_to_cidrs(cidr_data['startAddress'], cidr_data['endAddress'])) if (
            'startAddress' in cidr_data
            and 'endAddress' in cidr_data
        ) else None

        if not cidr_data['cidr']:
            continue

        cidr_context_excluded_fields: List[str] = ['startAddress', 'endAddress']
        cidr_data_list.append({
            k: cidr_data[k]
            for k in cidr_data if k not in cidr_context_excluded_fields
        })

        # We can't use Common.DBotScore here because CIDR is not one of the well known
        # Indicator types
        cidr_standard_context = ExpanseCIDR(cidr_data['cidr'])
        cidr_standard_list.append(cidr_standard_context)

    readable_output = tableToMarkdown(
        'Expanse IP Range List', cidr_data_list) if len(cidr_standard_list) > 0 else "## No IP Ranges found"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expanse.IPRange',
        outputs_key_field='IP',
        outputs=cidr_data_list if len(cidr_data_list) > 0 else None,
        indicators=cidr_standard_list if len(cidr_standard_list) > 0 else None
    )


def list_risk_rules_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    total_results, max_page_size = calculate_limits(args.get('limit', None))

    params = {
        "limit": max_page_size
    }
    risk_rules = list(
        islice(
            client.list_risk_rules(params),
            total_results
        )
    )

    return CommandResults(
        outputs_prefix="Expanse.RiskRules",
        outputs_key_field="id",
        readable_output="## No Risk Rules found" if len(risk_rules) == 0 else None,
        outputs=risk_rules if len(risk_rules) > 0 else None
    )


def get_risky_flows_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    total_results, max_page_size = calculate_limits(args.get('limit', None))

    d = args.get('created_before', None)
    created_before = parse(d).strftime(DATE_FORMAT) if d else None

    d = args.get('created_after', None)
    created_after = parse(d).strftime(DATE_FORMAT) if d else None

    internal_ip_range = args.get('internal_ip_range', None)
    risk_rule = args.get('risk_rule', None)

    tags = argToList(args.get('tagnames'))
    if len(tags) > 0:
        tag_names = ','.join(tags)

    risky_flows = list(
        islice(
            client.get_risky_flows(limit=max_page_size, created_before=created_before, created_after=created_after,
                                   internal_ip_range=internal_ip_range, risk_rule=risk_rule, tag_names=tag_names),
            total_results
        )
    )

    return CommandResults(
        outputs_prefix="Expanse.RiskyFlows",
        outputs_key_field="id",
        readable_output="## No Risky Flows found" if len(risky_flows) == 0 else None,
        outputs=risky_flows if len(risky_flows) > 0 else None
    )


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get("apikey")
    base_url = urljoin(demisto.params()["url"], "/api")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    try:
        client = Client(
            api_key=api_key, base_url=base_url, verify=verify_certificate, proxy=proxy
        )

        client.authenticate()

        if demisto.command() == "test-module":
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            max_incidents = check_int(arg=demisto.params().get('max_fetch'), arg_name='max_fetch',
                                      min_val=None, max_val=None, required=False)
            if not max_incidents or max_incidents > MAX_INCIDENTS:
                max_incidents = MAX_INCIDENTS

            ff = demisto.params().get('first_fetch', None)
            if not ff:
                raise ValueError('firstFetch not specified')
            first_fetch = datestring_to_timestamp_us(ff)

            priority = demisto.params().get('priority', None)
            activity_status = demisto.params().get('activityStatus', None)
            progress_status = demisto.params().get('progressStatus', None)
            business_units = argToList(demisto.params().get('businessUnit', None))
            issue_types = argToList(demisto.params().get('issueType', None))
            tags = argToList(demisto.params().get('tags', None))

            sync_tags = argToList(demisto.params().get('sync_tags', None))
            fetch_details = argToBoolean(demisto.params().get('fetch_details'))
            fetch_behavior = argToBoolean(demisto.params().get('fetch_behavior'))

            mirror_direction = MIRROR_DIRECTION.get(demisto.params().get('mirror_direction', 'None'), None)
            next_run, incidents = fetch_incidents(
                client=client,
                max_incidents=max_incidents,
                last_run=demisto.getLastRun(),
                first_fetch=first_fetch,
                priority=priority,
                activity_status=activity_status,
                progress_status=progress_status,
                business_units=business_units,
                tags=tags,
                issue_types=issue_types,
                mirror_direction=mirror_direction,
                sync_tags=sync_tags,
                fetch_details=fetch_details,
                fetch_behavior=fetch_behavior
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == "get-remote-data":
            sync_owners = argToBoolean(demisto.params().get('sync_owners'))
            mirror_details = argToBoolean(demisto.params().get('mirror_details'))
            incoming_tags = argToList(demisto.params().get('incoming_tags', None))
            return_results(get_remote_data_command(client, demisto.args(), sync_owners, incoming_tags, mirror_details))

        elif demisto.command() == "update-remote-system":
            sync_owners = argToBoolean(demisto.params().get('sync_owners'))
            return_results(update_remote_system_command(client, demisto.args(), sync_owners))

        elif demisto.command() == "expanse-get-issues":
            return_results(get_issues_command(client, demisto.args()))

        elif demisto.command() == "expanse-get-issue":
            return_results(get_issue_command(client, demisto.args()))

        elif demisto.command() == "expanse-get-issue-updates":
            return_results(get_issue_updates_command(client, demisto.args()))

        elif demisto.command() == "expanse-update-issue":
            return_results(update_issue_command(client, demisto.args()))

        elif demisto.command() == "expanse-get-issue-comments":
            return_results(get_issue_comments_command(client, demisto.args()))

        elif demisto.command() == "expanse-list-businessunits":
            return_results(list_businessunits_command(client, demisto.args()))

        elif demisto.command() == "expanse-list-providers":
            return_results(list_providers_command(client, demisto.args()))

        elif demisto.command() == "expanse-list-tags":
            return_results(list_tags_command(client, demisto.args()))

        elif demisto.command() == "expanse-get-iprange":
            return_results(get_iprange_command(client, demisto.args()))

        elif demisto.command() == "expanse-create-tag":
            return_results(create_tag_command(client, demisto.args()))

        elif demisto.command() == "expanse-assign-tags-to-asset":
            args = demisto.args()
            args['operation_type'] = 'ASSIGN'
            return_results(manage_asset_tags_command(client, demisto.args()))

        elif demisto.command() == "expanse-unassign-tags-from-asset":
            args = demisto.args()
            args['operation_type'] = 'UNASSIGN'
            return_results(manage_asset_tags_command(client, demisto.args()))

        elif demisto.command() == "expanse-assign-tags-to-iprange":
            args = demisto.args()
            args['operation_type'] = 'ASSIGN'
            args['asset_type'] = 'IpRange'
            return_results(manage_asset_tags_command(client, demisto.args()))

        elif demisto.command() == "expanse-unassign-tags-from-iprange":
            args = demisto.args()
            args['operation_type'] = 'UNASSIGN'
            args['asset_type'] = 'IpRange'
            return_results(manage_asset_tags_command(client, demisto.args()))

        elif demisto.command() == "expanse-assign-tags-to-certificate":
            args = demisto.args()
            args['operation_type'] = 'ASSIGN'
            args['asset_type'] = 'Certificate'
            return_results(manage_asset_tags_command(client, demisto.args()))

        elif demisto.command() == "expanse-unassign-tags-from-certificate":
            args = demisto.args()
            args['operation_type'] = 'UNASSIGN'
            args['asset_type'] = 'Certificate'
            return_results(manage_asset_tags_command(client, demisto.args()))

        elif demisto.command() == "expanse-assign-tags-to-domain":
            args = demisto.args()
            args['operation_type'] = 'ASSIGN'
            args['asset_type'] = 'Domain'
            return_results(manage_asset_tags_command(client, demisto.args()))

        elif demisto.command() == "expanse-unassign-tags-from-domain":
            args = demisto.args()
            args['operation_type'] = 'UNASSIGN'
            args['asset_type'] = 'Domain'
            return_results(manage_asset_tags_command(client, demisto.args()))

        elif demisto.command() == "expanse-get-domain":
            return_results(get_domain_command(client, demisto.args()))

        elif demisto.command() == "expanse-get-certificate":
            return_results(get_certificate_command(client, demisto.args()))

        elif demisto.command() == "expanse-certificate":
            return_results(expanse_certificate_command(client, demisto.args()))

        elif demisto.command() == "domain":
            return_results(domain_command(client, demisto.args()))

        elif demisto.command() == "ip":
            return_results(ip_command(client, demisto.args()))

        elif demisto.command() == "cidr":
            return_results(cidr_command(client, demisto.args()))

        elif demisto.command() == "expanse-get-risky-flows":
            return_results(get_risky_flows_command(client, demisto.args()))

        elif demisto.command() == "expanse-list-risk-rules":
            return_results(list_risk_rules_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

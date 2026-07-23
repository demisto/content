import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import html
import json
import re
import traceback
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import requests
import urllib3


# Display timezone used for all human-readable dates returned by this integration.
# Internal API query timestamps and freshness calculations remain in UTC/epoch.
DISPLAY_TIMEZONE = timezone(timedelta(hours=3))
DISPLAY_TIMEZONE_LABEL = 'UTC+3'


def format_utc_plus_3(date_value: Optional[datetime]) -> str:
    """
    Convert an aware or UTC-naive datetime to Saudi Arabia time (UTC+3).

    Example output:
        2026-07-22 15:14:36 +03:00
    """
    if not date_value:
        return ''

    if date_value.tzinfo is None:
        date_value = date_value.replace(tzinfo=timezone.utc)

    return date_value.astimezone(DISPLAY_TIMEZONE).strftime(
        '%Y-%m-%d %H:%M:%S +03:00'
    )


class TenableSCClient:
    def __init__(
        self,
        base_url: str,
        access_key: str,
        secret_key: str,
        verify: bool = True,
        timeout: int = 120
    ):
        self.base_url = str(base_url or '').rstrip('/')
        self.verify = verify
        self.timeout = timeout
        self.session = requests.Session()

        self.session.headers.update({
            'x-apikey': 'accesskey={}; secretkey={};'.format(
                access_key,
                secret_key
            ),
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })

    def request(
        self,
        method: str,
        path: str,
        json_body: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        url = '{}{}'.format(self.base_url, path)

        try:
            response = self.session.request(
                method=method,
                url=url,
                json=json_body,
                verify=self.verify,
                timeout=self.timeout
            )
        except requests.exceptions.RequestException as error:
            raise DemistoException(
                'Failed to connect to Tenable.sc at {}: {}'.format(
                    url,
                    str(error)
                )
            )

        try:
            data = response.json()
        except Exception:
            raise DemistoException(
                'Tenable.sc returned a non-JSON response. '
                'HTTP {}: {}'.format(
                    response.status_code,
                    response.text[:1000]
                )
            )

        if response.status_code >= 400:
            raise DemistoException(
                'Tenable.sc HTTP error {}: {}'.format(
                    response.status_code,
                    json.dumps(data, ensure_ascii=False)
                )
            )

        error_code = data.get('error_code') if isinstance(data, dict) else None

        if error_code not in [None, 0, '0']:
            raise DemistoException(
                'Tenable.sc API error: {}'.format(
                    json.dumps(data, ensure_ascii=False)
                )
            )

        return data

    def current_user(self) -> Dict[str, Any]:
        return self.request('GET', '/rest/currentUser')

    def vulnerability_analysis(
        self,
        plugin_id: str,
        repository_ids: str = '',
        severity: str = '',
        limit: int = 50,
        source_type: str = 'cumulative'
    ) -> Dict[str, Any]:
        source_type = str(source_type or 'cumulative').strip().lower()

        if source_type not in ['cumulative', 'patched']:
            raise DemistoException(
                'source_type must be either "cumulative" or "patched".'
            )

        if limit < 1:
            raise DemistoException('limit must be greater than 0.')

        filters: List[Dict[str, str]] = [
            {
                'filterName': 'pluginID',
                'operator': '=',
                'value': str(plugin_id)
            }
        ]

        if repository_ids:
            filters.append({
                'filterName': 'repository',
                'operator': '=',
                'value': str(repository_ids)
            })

        severity_map = {
            'informational': '0',
            'info': '0',
            'low': '1',
            'medium': '2',
            'high': '3',
            'critical': '4'
        }

        severity_value = severity_map.get(
            str(severity or '').strip().lower()
        )

        if severity and severity_value is None:
            raise DemistoException(
                'severity must be one of: Informational, Low, Medium, High, Critical.'
            )

        if severity_value is not None:
            filters.append({
                'filterName': 'severity',
                'operator': '=',
                'value': severity_value
            })

        payload = {
            'type': 'vuln',
            'sourceType': source_type,
            'sortField': 'severity',
            'sortDir': 'desc',
            'startOffset': 0,
            'endOffset': int(limit),
            'query': {
                'name': '',
                'description': '',
                'context': '',
                'createdTime': 0,
                'modifiedTime': 0,
                'groups': [],
                'type': 'vuln',
                'tool': 'vulndetails',
                'sourceType': source_type,
                'startOffset': 0,
                'endOffset': int(limit),
                'filters': filters
            }
        }

        return self.request(
            'POST',
            '/rest/analysis',
            json_body=payload
        )

    def vulnerability_dataset_page(
        self,
        repository_ids: List[str],
        severity: str,
        start_offset: int,
        end_offset: int,
        source_type: str = 'cumulative',
        last_seen_range: str = ''
    ) -> Dict[str, Any]:
        """
        Retrieves one page of detailed vulnerability records from Tenable.sc.
        This uses the vulndetails analysis tool so fields such as pluginText,
        firstSeen and lastSeen are included.

        When last_seen_range is supplied, Tenable.sc returns only findings whose
        lastSeen value is inside that Analysis range. Example: ``0:1`` means
        "within the last day".
        """
        source_type = str(source_type or 'cumulative').strip().lower()

        if source_type not in ['cumulative', 'patched']:
            raise DemistoException(
                'source_type must be either "cumulative" or "patched".'
            )

        severity_map = {
            'informational': '0',
            'info': '0',
            'low': '1',
            'medium': '2',
            'high': '3',
            'critical': '4'
        }

        severity_value = severity_map.get(
            str(severity or '').strip().lower()
        )

        if severity_value is None:
            raise DemistoException(
                'severity must be one of: Informational, Low, Medium, High, Critical.'
            )

        repository_value = [
            {'id': str(repository_id)}
            for repository_id in repository_ids
        ]

        query_timestamp = int(
            datetime.now(timezone.utc).timestamp()
        )

        filters: List[Dict[str, Any]] = [
            {
                'id': 'repository',
                'filterName': 'repository',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': repository_value
            },
            {
                'id': 'severity',
                'filterName': 'severity',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': severity_value
            }
        ]

        if last_seen_range:
            filters.append({
                'id': 'lastSeen',
                'filterName': 'lastSeen',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': str(last_seen_range)
            })

        payload = {
            'query': {
                'tags': '',
                'name': '_xsoar_vulndetails_{}_{}'.format(
                    severity_value,
                    query_timestamp
                ),
                'description': '',
                'context': 'analysis',
                'status': 0,
                'createdTime': query_timestamp,
                'modifiedTime': query_timestamp,
                'groups': [],
                'type': 'vuln',
                'tool': 'vulndetails',
                'sourceType': source_type,
                'startOffset': int(start_offset),
                'endOffset': int(end_offset),
                'filters': filters,
                'vulnTool': 'vulndetails'
            },
            'sourceType': source_type,
            'columns': [],
            'type': 'vuln'
        }

        return self.request(
            'POST',
            '/rest/analysis',
            json_body=payload
        )

    def count_vulnerabilities(
        self,
        repository_ids: List[str],
        severity: str,
        last_seen_range: str,
        first_seen_range: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Runs the same listvuln count query used by the Tenable.sc dashboard.

        last_seen_range:
            Limits the findings to vulnerabilities observed during the
            requested period.

        first_seen_range:
            Optional SLA-age filter based on when Tenable.sc first discovered
            the vulnerability. This is used for Within SLA and Overdue counts.
        """
        severity_map = {
            'informational': '0',
            'info': '0',
            'low': '1',
            'medium': '2',
            'high': '3',
            'critical': '4'
        }

        severity_value = severity_map.get(
            str(severity or '').strip().lower()
        )

        if severity_value is None:
            raise DemistoException(
                'severity must be one of: Informational, Low, Medium, High, Critical.'
            )

        repository_value = [
            {'id': str(repository_id)}
            for repository_id in repository_ids
        ]

        query_timestamp = int(
            datetime.now(timezone.utc).timestamp()
        )

        filters: List[Dict[str, Any]] = [
            {
                'id': 'repository',
                'filterName': 'repository',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': repository_value
            }
        ]

        if first_seen_range:
            filters.append({
                'id': 'firstSeen',
                'filterName': 'firstSeen',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': str(first_seen_range)
            })

        filters.extend([
            {
                'id': 'lastSeen',
                'filterName': 'lastSeen',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': str(last_seen_range)
            },
            {
                'id': 'severity',
                'filterName': 'severity',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': severity_value
            }
        ])

        payload = {
            'query': {
                'tags': '',
                'name': '_xsoar_sla_{}_{}'.format(
                    severity_value,
                    query_timestamp
                ),
                'description': '',
                'context': 'dashboard',
                'status': 0,
                'createdTime': query_timestamp,
                'modifiedTime': query_timestamp,
                'groups': [],
                'type': 'vuln',
                'tool': 'listvuln',
                'sourceType': 'cumulative',
                'startOffset': 0,
                'endOffset': 50,
                'filters': filters,
                'vulnTool': 'listvuln'
            },
            'sourceType': 'cumulative',
            'columns': [],
            'type': 'vuln'
        }

        return self.request(
            'POST',
            '/rest/analysis',
            json_body=payload
        )


def get_analysis_results(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    response = data.get('response', {})

    if not isinstance(response, dict):
        return []

    results = response.get('results', [])

    if not isinstance(results, list):
        return []

    return [
        item for item in results
        if isinstance(item, dict)
    ]


def clean(value: Any) -> str:
    if value is None:
        return ''

    if isinstance(value, dict):
        preferred_value = (
            value.get('name')
            or value.get('Name')
            or value.get('value')
            or value.get('id')
        )

        if preferred_value is not None:
            return str(preferred_value).strip()

        return json.dumps(value, ensure_ascii=False)

    if isinstance(value, list):
        cleaned_items = []

        for item in value:
            cleaned_item = clean(item)

            if cleaned_item:
                cleaned_items.append(cleaned_item)

        return ', '.join(cleaned_items)

    return str(value).strip()


def clean_plugin_output(value: Any) -> str:
    """
    Removes Tenable plugin_output XML tags and decodes HTML entities,
    while preserving the actual evidence text.
    """
    text = clean(value)

    if not text:
        return ''

    text = html.unescape(text)
    text = text.replace('\x00', '')

    text = re.sub(
        r'</?plugin_output[^>]*>',
        '',
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r'<br\s*/?>',
        '\n',
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(r'\r\n?', '\n', text)
    text = re.sub(r'\n{3,}', '\n\n', text)

    return text.strip()


def normalize_epoch_date(value: Any) -> str:
    """
    Normalize Tenable.sc epoch or ISO timestamps to UTC+3 for display.

    Epoch values remain the same instant; only their displayed timezone changes.
    Values that already contain an offset, including +03:00, are handled without
    adding the offset twice.
    """
    value_text = clean(value)

    if not value_text:
        return ''

    # Epoch seconds or milliseconds.
    try:
        timestamp = float(value_text)

        if timestamp > 9999999999:
            timestamp = timestamp / 1000.0

        parsed_date = datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc
        )

        return format_utc_plus_3(parsed_date)

    except (TypeError, ValueError, OverflowError):
        pass

    # ISO or already formatted datetime.
    try:
        normalized_value = value_text.strip()

        if normalized_value.upper().endswith(' UTC'):
            normalized_value = normalized_value[:-4].strip() + '+00:00'
        elif normalized_value.endswith('Z'):
            normalized_value = normalized_value[:-1] + '+00:00'

        parsed_date = datetime.fromisoformat(normalized_value)

        if parsed_date.tzinfo is None:
            parsed_date = parsed_date.replace(tzinfo=timezone.utc)

        return format_utc_plus_3(parsed_date)

    except (TypeError, ValueError):
        return value_text


def normalize_boolean(value: Any) -> bool:
    return str(value or '').strip().lower() in [
        'true',
        '1',
        'yes',
        'y'
    ]


def normalize_severity(value: Any) -> str:
    severity_map = {
        '0': 'Informational',
        '1': 'Low',
        '2': 'Medium',
        '3': 'High',
        '4': 'Critical'
    }

    value_text = clean(value)

    return severity_map.get(
        value_text,
        value_text
    )


def extract_repository_name(value: Any) -> str:
    if isinstance(value, dict):
        return clean(
            value.get('name')
            or value.get('Name')
            or value.get('id')
        )

    return clean(value)


def convert_result_to_output(
    result: Dict[str, Any],
    source_type: str
) -> Dict[str, Any]:
    source_type_normalized = clean(source_type).lower()

    raw_plugin_output = (
        result.get('pluginText')
        or result.get('pluginOutput')
        or result.get('output')
        or ''
    )

    plugin_output = clean_plugin_output(raw_plugin_output)

    first_seen = normalize_epoch_date(
        result.get('firstSeen')
    )

    last_seen = normalize_epoch_date(
        result.get('lastSeen')
    )

    last_mitigated = normalize_epoch_date(
        result.get('lastMitigated')
    )

    historical_mitigation_flag = normalize_boolean(
        result.get('hasBeenMitigated')
    )

    if source_type_normalized == 'patched':
        current_status = 'Mitigated'
    else:
        current_status = 'Active'

    return {
        'PluginID': clean(result.get('pluginID')),
        'PluginName': clean(result.get('pluginName')),
        'Severity': normalize_severity(result.get('severity')),
        'IP': clean(result.get('ip')),
        'DNSName': clean(result.get('dnsName')),
        'Port': clean(result.get('port')),
        'Protocol': clean(result.get('protocol')),
        'Repository': extract_repository_name(
            result.get('repository')
        ),
        'FirstDiscovered': first_seen,
        'LastObserved': last_seen,
        'LastMitigated': last_mitigated,
        'CurrentStatus': current_status,
        'HasBeenMitigatedHistorically': historical_mitigation_flag,
        'PluginOutput': plugin_output,
        'Description': clean(result.get('description')),
        'Solution': clean(result.get('solution')),
        'CVE': clean(
            result.get('cve')
            or result.get('cves')
        ),
        'CVSSBaseScore': clean(
            result.get('baseScore')
            or result.get('cvssV3BaseScore')
            or result.get('cvssV4BaseScore')
        ),
        'RiskFactor': clean(result.get('riskFactor')),
        'SourceType': source_type_normalized
    }


def build_table_rows(
    converted_results: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    rows = []

    for result in converted_results:
        plugin_output = result.get('PluginOutput', '')

        if len(plugin_output) > 250:
            plugin_output_preview = plugin_output[:250] + '...'
        else:
            plugin_output_preview = plugin_output

        rows.append({
            'Plugin ID': result.get('PluginID', ''),
            'Plugin Name': result.get('PluginName', ''),
            'Severity': result.get('Severity', ''),
            'IP': result.get('IP', ''),
            'DNS Name': result.get('DNSName', ''),
            'Port': result.get('Port', ''),
            'Protocol': result.get('Protocol', ''),
            'Repository': result.get('Repository', ''),
            'First Discovered': result.get('FirstDiscovered', ''),
            'Last Observed': result.get('LastObserved', ''),
            'Current Status': result.get('CurrentStatus', ''),
            'Last Mitigated': result.get('LastMitigated', ''),
            'Previously Mitigated': result.get(
                'HasBeenMitigatedHistorically',
                False
            ),
            'Plugin Output Preview': plugin_output_preview
        })

    return rows


def parse_command_arguments(
    args: Dict[str, Any],
    default_limit: int
) -> Dict[str, Any]:
    plugin_id = args.get('plugin_id')
    repository_ids = args.get('repository_ids', '')
    severity = args.get('severity', '')
    source_type = str(
        args.get('source_type', 'cumulative')
    ).strip().lower()

    try:
        limit = int(args.get('limit', default_limit))
    except Exception:
        raise DemistoException('limit must be a valid integer.')

    if not plugin_id:
        raise DemistoException('plugin_id is required.')

    return {
        'plugin_id': plugin_id,
        'repository_ids': repository_ids,
        'severity': severity,
        'limit': limit,
        'source_type': source_type
    }


def test_module(client: TenableSCClient) -> CommandResults:
    client.current_user()

    return CommandResults(
        readable_output='ok',
        raw_response='ok'
    )


def analysis_test_command(
    client: TenableSCClient,
    args: Dict[str, Any]
) -> CommandResults:
    command_args = parse_command_arguments(
        args,
        default_limit=5
    )

    data = client.vulnerability_analysis(
        plugin_id=command_args['plugin_id'],
        repository_ids=command_args['repository_ids'],
        severity=command_args['severity'],
        limit=command_args['limit'],
        source_type=command_args['source_type']
    )

    raw_results = get_analysis_results(data)

    converted_results = [
        convert_result_to_output(
            result,
            command_args['source_type']
        )
        for result in raw_results
    ]

    if converted_results:
        readable_output = tableToMarkdown(
            'Tenable.sc Analysis API Test',
            build_table_rows(converted_results),
            removeNull=True
        )
    else:
        readable_output = (
            '### Tenable.sc Analysis API Test\n\n'
            'No matching vulnerability records were returned.'
        )

    output = {
        'PluginID': str(command_args['plugin_id']),
        'SourceType': command_args['source_type'],
        'ReturnedResults': len(converted_results),
        'Results': converted_results
    }

    return CommandResults(
        outputs_prefix='TenableSC.CustomAnalysis',
        outputs_key_field='PluginID',
        outputs=output,
        readable_output=readable_output,
        raw_response=data
    )


def vulnerability_details_command(
    client: TenableSCClient,
    args: Dict[str, Any]
) -> CommandResults:
    command_args = parse_command_arguments(
        args,
        default_limit=50
    )

    data = client.vulnerability_analysis(
        plugin_id=command_args['plugin_id'],
        repository_ids=command_args['repository_ids'],
        severity=command_args['severity'],
        limit=command_args['limit'],
        source_type=command_args['source_type']
    )

    raw_results = get_analysis_results(data)

    converted_results = [
        convert_result_to_output(
            result,
            command_args['source_type']
        )
        for result in raw_results
    ]

    if converted_results:
        readable_output = tableToMarkdown(
            'Tenable.sc Vulnerability Details',
            build_table_rows(converted_results),
            removeNull=True
        )
    else:
        readable_output = (
            '### Tenable.sc Vulnerability Details\n\n'
            'No matching vulnerability records were returned.'
        )

    return CommandResults(
        outputs_prefix='TenableSC.VulnerabilityDetails',
        outputs_key_field='PluginID',
        outputs=converted_results,
        readable_output=readable_output,
        raw_response=data
    )


def parse_severity_values(value: Any) -> List[str]:
    supported = {
        'critical': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'informational': 'Informational',
        'info': 'Informational'
    }

    output: List[str] = []

    for item in str(value or '').split(','):
        normalized = str(item or '').strip().lower()

        if not normalized:
            continue

        severity_name = supported.get(normalized)

        if not severity_name:
            raise DemistoException(
                'Unsupported severity: {}. Supported values are: '
                'Critical, High, Medium, Low, Informational.'.format(item)
            )

        if severity_name not in output:
            output.append(severity_name)

    if not output:
        raise DemistoException('At least one severity is required.')

    return output


def to_boolean(value: Any) -> bool:
    return str(value or '').strip().lower() in [
        'true',
        '1',
        'yes',
        'y'
    ]


def normalize_analysis_range(
    value: Any,
    argument_name: str
) -> str:
    """
    Validate a Tenable.sc Analysis age range such as 0:1, 0:30, or 17:all.
    An empty value disables the corresponding Analysis filter.
    """
    value_text = clean(value).lower()

    if not value_text:
        return ''

    match = re.fullmatch(r'(\d+):(\d+|all)', value_text)

    if not match:
        raise DemistoException(
            '{} must use Tenable.sc range format such as 0:1, 0:30, '
            '17:all, or be left empty.'.format(argument_name)
        )

    start_value = int(match.group(1))
    end_text = match.group(2)

    if end_text != 'all' and int(end_text) < start_value:
        raise DemistoException(
            '{} has an invalid range: the end value cannot be less '
            'than the start value.'.format(argument_name)
        )

    return value_text


def dataset_record_last_observed_timestamp(
    record: Dict[str, Any]
) -> float:
    """Return a sortable UTC timestamp for a converted dataset record."""
    value_text = clean(record.get('LastObserved'))

    if not value_text:
        return 0.0

    formats = [
        '%Y-%m-%d %H:%M:%S UTC',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%d %H:%M:%S'
    ]

    for date_format in formats:
        try:
            parsed = datetime.strptime(value_text, date_format)
            parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except Exception:
            pass

    try:
        parsed = datetime.fromisoformat(
            value_text.replace(' UTC', '+00:00').replace('Z', '+00:00')
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)

        return parsed.timestamp()

    except Exception:
        return 0.0


def should_replace_dataset_record(
    existing: Optional[Dict[str, Any]],
    candidate: Dict[str, Any]
) -> bool:
    """
    Keep the newest observation for the same plugin/asset/port/protocol.

    Quality is used only as a tie-breaker. This prevents an older cumulative
    record with more populated fields from replacing the current observation.
    """
    if existing is None:
        return True

    candidate_timestamp = dataset_record_last_observed_timestamp(candidate)
    existing_timestamp = dataset_record_last_observed_timestamp(existing)

    if candidate_timestamp > existing_timestamp:
        return True

    if candidate_timestamp < existing_timestamp:
        return False

    return record_quality_score(candidate) > record_quality_score(existing)


def build_dataset_record_key(record: Dict[str, Any]) -> str:
    plugin_id = clean(record.get('PluginID')).lower()
    asset = clean(record.get('IP') or record.get('DNSName')).lower()
    port = clean(record.get('Port')).lower()
    protocol = clean(record.get('Protocol')).lower()

    return '{}|{}|{}|{}'.format(
        plugin_id,
        asset,
        port,
        protocol
    )


def record_quality_score(record: Dict[str, Any]) -> int:
    important_fields = [
        'PluginOutput',
        'FirstDiscovered',
        'LastObserved',
        'DNSName',
        'IP',
        'Port',
        'Protocol',
        'Repository',
        'Description',
        'Solution'
    ]

    return sum(
        1
        for field_name in important_fields
        if clean(record.get(field_name))
    )


def vulnerability_dataset_command(
    client: TenableSCClient,
    args: Dict[str, Any]
) -> CommandResults:
    repository_ids = parse_repository_ids(
        args.get('repository_ids', '')
    )
    severities = parse_severity_values(
        args.get(
            'severity',
            'Critical,High,Medium,Low'
        )
    )
    source_type = str(
        args.get('source_type', 'cumulative')
    ).strip().lower()
    last_seen_range = normalize_analysis_range(
        args.get('last_seen_range', ''),
        'last_seen_range'
    )

    page_size = validate_positive_integer(
        args.get('page_size', 200),
        'page_size'
    )
    max_pages = validate_positive_integer(
        args.get('max_pages', 100),
        'max_pages'
    )
    preview_rows = validate_positive_integer(
        args.get('preview_rows', 20),
        'preview_rows'
    )

    if page_size < 1:
        raise DemistoException('page_size must be greater than 0.')

    if max_pages < 1:
        raise DemistoException('max_pages must be greater than 0.')

    save_to_list = to_boolean(
        args.get('save_to_list', 'true')
    )
    output_list = str(
        args.get(
            'output_list',
            'Tenable_SC_Daily_Advanced_Dataset_JSON'
        )
    ).strip()

    deduplicated: Dict[str, Dict[str, Any]] = {}
    severity_stats: List[Dict[str, Any]] = []
    pagination_limit_reached = False

    for severity_name in severities:
        severity_expected_total = 0
        severity_collected = 0
        pages_requested = 0
        severity_limit_reached = False

        for page_number in range(max_pages):
            start_offset = page_number * page_size
            end_offset = start_offset + page_size
            pages_requested += 1

            data = client.vulnerability_dataset_page(
                repository_ids=repository_ids,
                severity=severity_name,
                start_offset=start_offset,
                end_offset=end_offset,
                source_type=source_type,
                last_seen_range=last_seen_range
            )

            if page_number == 0:
                severity_expected_total = get_total_records(data)

            raw_results = get_analysis_results(data)

            if not raw_results:
                break

            converted_results = [
                convert_result_to_output(
                    result,
                    source_type
                )
                for result in raw_results
            ]

            severity_collected += len(converted_results)

            for converted in converted_results:
                record_key = build_dataset_record_key(converted)

                if not record_key.strip('|'):
                    continue

                existing = deduplicated.get(record_key)

                if should_replace_dataset_record(existing, converted):
                    deduplicated[record_key] = converted

            if len(raw_results) < page_size:
                break

            # Do not stop only because totalRecords was reached. Some Tenable.sc
            # analysis views can report a summary total that differs from the full
            # number of detailed host rows. Stop on a short/empty page or max_pages.
            if page_number == max_pages - 1:
                severity_limit_reached = True
                pagination_limit_reached = True

        severity_stats.append({
            'Severity': severity_name,
            'ExpectedTotal': severity_expected_total,
            'CollectedRowsBeforeDedup': severity_collected,
            'PagesRequested': pages_requested,
            'PaginationLimitReached': severity_limit_reached
        })

    records = list(deduplicated.values())

    severity_order = {
        'Critical': 1,
        'High': 2,
        'Medium': 3,
        'Low': 4,
        'Informational': 5
    }

    records.sort(
        key=lambda item: (
            severity_order.get(
                clean(item.get('Severity')),
                99
            ),
            clean(item.get('PluginName')).lower(),
            clean(item.get('IP') or item.get('DNSName')).lower(),
            clean(item.get('Port')).lower()
        )
    )

    generated_at = format_utc_plus_3(
        datetime.now(timezone.utc)
    )

    dataset_payload = {
        'GeneratedAt': generated_at,
        'RepositoryIDs': repository_ids,
        'Severity': severities,
        'SourceType': source_type,
        'LastSeenRange': last_seen_range,
        'CollectedRecords': len(records),
        'PaginationLimitReached': pagination_limit_reached,
        'SeverityStats': severity_stats,
        'Records': records
    }

    # Integration commands cannot call demisto.executeCommand/setList.
    # The full dataset is returned to the caller. The automation that invokes
    # this command is responsible for saving it to an XSOAR list when needed.
    saved_to_list = False

    preview = records[:preview_rows]

    summary_output = {
        'GeneratedAt': generated_at,
        'RepositoryIDs': ','.join(repository_ids),
        'Severity': ','.join(severities),
        'SourceType': source_type,
        'LastSeenRange': last_seen_range,
        'CollectedRecords': len(records),
        'PaginationLimitReached': pagination_limit_reached,
        'SavedToList': saved_to_list,
        'OutputList': output_list if saved_to_list else '',
        'SeverityStats': severity_stats,
        'Preview': preview,
        'Records': records
    }

    readable_output = tableToMarkdown(
        'Tenable.sc Detailed Vulnerability Dataset Summary',
        {
            'Generated At': generated_at,
            'Repository IDs': ','.join(repository_ids),
            'Severities': ','.join(severities),
            'Source Type': source_type,
            'Last Seen Range': last_seen_range or 'Not filtered',
            'Collected Records': len(records),
            'Pagination Limit Reached': pagination_limit_reached,
            'Saved To List': saved_to_list,
            'Output List': output_list if saved_to_list else ''
        },
        removeNull=True
    )

    if preview:
        readable_output += '\n\n' + tableToMarkdown(
            'Detailed Vulnerability Dataset Preview',
            build_table_rows(preview),
            removeNull=True
        )

    return CommandResults(
        outputs_prefix='TenableSC.VulnerabilityDataset',
        outputs_key_field='GeneratedAt',
        outputs=summary_output,
        readable_output=readable_output,
        raw_response={
            'GeneratedAt': generated_at,
            'RepositoryIDs': repository_ids,
            'Severity': severities,
            'SourceType': source_type,
            'CollectedRecords': len(records),
            'PaginationLimitReached': pagination_limit_reached,
            'SeverityStats': severity_stats,
            'SavedToList': saved_to_list,
            'OutputList': '',
            'Preview': preview,
            'Records': records
        }
    )


def parse_repository_ids(value: Any) -> List[str]:
    repository_ids = []

    for item in str(value or '').split(','):
        repository_id = item.strip()

        if repository_id:
            repository_ids.append(repository_id)

    if not repository_ids:
        raise DemistoException(
            'repository_ids is required. '
            'Provide comma-separated Tenable.sc repository IDs.'
        )

    return repository_ids


def get_total_records(data: Dict[str, Any]) -> int:
    response = data.get('response', {})

    if not isinstance(response, dict):
        return 0

    for key in [
        'totalRecords',
        'total',
        'count',
        'totalRecordsAvailable'
    ]:
        if key not in response:
            continue

        try:
            return int(response.get(key))
        except Exception:
            continue

    results = response.get('results', [])

    if isinstance(results, list):
        return len(results)

    return 0


def validate_positive_integer(
    value: Any,
    field_name: str
) -> int:
    try:
        parsed_value = int(value)
    except Exception:
        raise DemistoException(
            '{} must be a valid integer.'.format(field_name)
        )

    if parsed_value < 0:
        raise DemistoException(
            '{} cannot be negative.'.format(field_name)
        )

    return parsed_value


def sla_summary_command(
    client: TenableSCClient,
    args: Dict[str, Any]
) -> CommandResults:
    repository_ids = parse_repository_ids(
        args.get('repository_ids', '')
    )

    # Keep the existing lookback argument for backward compatibility.
    lookback_days = validate_positive_integer(
        args.get('lookback_days', 30),
        'lookback_days'
    )

    # Apply the same Tenable.sc Last Observed window used by the daily CSV.
    # Default 0:1 means findings observed within the last day.
    last_seen_range = normalize_analysis_range(
        args.get('last_seen_range', '0:1'),
        'last_seen_range'
    )

    # Treat an explicitly empty value as the safe daily default.
    if not last_seen_range:
        last_seen_range = '0:1'

    critical_sla_days = validate_positive_integer(
        args.get('critical_sla_days', 3),
        'critical_sla_days'
    )

    high_sla_days = validate_positive_integer(
        args.get('high_sla_days', 10),
        'high_sla_days'
    )

    medium_sla_days = validate_positive_integer(
        args.get('medium_sla_days', 17),
        'medium_sla_days'
    )

    low_sla_days = validate_positive_integer(
        args.get('low_sla_days', 50),
        'low_sla_days'
    )

    # Daily external SLA logic:
    # - Every Total query uses the configured Last Observed range.
    # - Within SLA and Overdue are calculated from firstSeen.
    # - The same Last Observed range is applied to every severity and every
    #   Total/Within-SLA/Overdue query.
    #
    # The Medium and Low boundaries intentionally match the approved
    # Tenable.sc dashboard definitions supplied by the VAPT team.
    severity_settings = [
        {
            'Severity': 'Critical',
            'SLADays': critical_sla_days,
            'TotalLastSeenRange': last_seen_range,
            'WithinFirstSeenRange': '0:{}'.format(critical_sla_days),
            'WithinLastSeenRange': last_seen_range,
            'OverdueFirstSeenRange': '{}:all'.format(
                critical_sla_days + 1
            ),
            'OverdueLastSeenRange': last_seen_range
        },
        {
            'Severity': 'High',
            'SLADays': high_sla_days,
            'TotalLastSeenRange': last_seen_range,
            'WithinFirstSeenRange': '0:{}'.format(high_sla_days),
            'WithinLastSeenRange': last_seen_range,
            'OverdueFirstSeenRange': '{}:all'.format(
                high_sla_days + 1
            ),
            'OverdueLastSeenRange': last_seen_range
        },
        {
            'Severity': 'Medium',
            'SLADays': medium_sla_days,
            'TotalLastSeenRange': last_seen_range,
            'WithinFirstSeenRange': '0:{}'.format(medium_sla_days),
            'WithinLastSeenRange': last_seen_range,
            'OverdueFirstSeenRange': '{}:all'.format(
                medium_sla_days
            ),
            'OverdueLastSeenRange': last_seen_range
        },
        {
            'Severity': 'Low',
            'SLADays': low_sla_days,
            'TotalLastSeenRange': last_seen_range,
            'WithinFirstSeenRange': '0:{}'.format(low_sla_days),
            'WithinLastSeenRange': last_seen_range,
            'OverdueFirstSeenRange': '{}:all'.format(
                low_sla_days
            ),
            'OverdueLastSeenRange': last_seen_range
        }
    ]

    summary_rows: List[Dict[str, Any]] = []
    raw_queries: List[Dict[str, Any]] = []
    last_updated = format_utc_plus_3(
        datetime.now(timezone.utc)
    )

    for setting in severity_settings:
        severity_name = setting['Severity']

        total_data = client.count_vulnerabilities(
            repository_ids=repository_ids,
            severity=severity_name,
            last_seen_range=setting['TotalLastSeenRange']
        )

        within_sla_data = client.count_vulnerabilities(
            repository_ids=repository_ids,
            severity=severity_name,
            first_seen_range=setting['WithinFirstSeenRange'],
            last_seen_range=setting['WithinLastSeenRange']
        )

        overdue_data = client.count_vulnerabilities(
            repository_ids=repository_ids,
            severity=severity_name,
            first_seen_range=setting['OverdueFirstSeenRange'],
            last_seen_range=setting['OverdueLastSeenRange']
        )

        total_vulnerabilities = get_total_records(total_data)
        within_sla = get_total_records(within_sla_data)
        overdue = get_total_records(overdue_data)

        summary_row = {
            'Severity': severity_name,
            'SLADays': setting['SLADays'],
            'TotalVulnerabilities': total_vulnerabilities,
            'WithinSLA': within_sla,
            'Overdue': overdue,
            'TotalLastSeenRange': setting['TotalLastSeenRange'],
            'WithinFirstSeenRange': setting['WithinFirstSeenRange'],
            'WithinLastSeenRange': setting['WithinLastSeenRange'],
            'OverdueFirstSeenRange': setting['OverdueFirstSeenRange'],
            'OverdueLastSeenRange': setting['OverdueLastSeenRange'],
            'LastSeenRange': last_seen_range,
            'RepositoryIDs': ','.join(repository_ids),
            'SourceType': 'cumulative',
            'Tool': 'listvuln',
            'LookbackDaysArgument': lookback_days,
            'LastUpdated': last_updated
        }

        summary_rows.append(summary_row)

        raw_queries.append({
            'Severity': severity_name,
            'TotalFilters': {
                'lastSeen': setting['TotalLastSeenRange']
            },
            'WithinSLAFilters': {
                'firstSeen': setting['WithinFirstSeenRange'],
                'lastSeen': setting['WithinLastSeenRange']
            },
            'OverdueFilters': {
                'firstSeen': setting['OverdueFirstSeenRange'],
                'lastSeen': setting['OverdueLastSeenRange']
            },
            'TotalResponse': total_data,
            'WithinSLAResponse': within_sla_data,
            'OverdueResponse': overdue_data
        })

    table_rows = [
        {
            'Severity': '{} (SLA {} Days)'.format(
                row['Severity'],
                row['SLADays']
            ),
            'Total Vulns': row['TotalVulnerabilities'],
            'Within SLA': row['WithinSLA'],
            'Overdue': row['Overdue']
        }
        for row in summary_rows
    ]

    readable_output = tableToMarkdown(
        'SLA Progress - Unmitigated External Vulnerabilities',
        table_rows,
        removeNull=True
    )

    return CommandResults(
        outputs_prefix='TenableSC.ExternalSLA',
        outputs_key_field='Severity',
        outputs=summary_rows,
        readable_output=readable_output,
        raw_response={
            'RepositoryIDs': repository_ids,
            'SourceType': 'cumulative',
            'Tool': 'listvuln',
            'LastSeenRange': last_seen_range,
            # Kept to avoid breaking any existing context references.
            'DailyLastSeenRange': last_seen_range,
            'Results': summary_rows,
            'QueryResponses': raw_queries
        }
    )


def main():
    params = demisto.params()
    command = demisto.command()

    base_url = params.get('url')
    access_key = params.get('access_key')
    secret_key = params.get('secret_key')

    insecure = argToBoolean(
        params.get('insecure', False)
    )

    try:
        timeout = int(
            params.get('request_timeout', 120)
        )
    except Exception:
        raise DemistoException(
            'Request Timeout must be a valid integer.'
        )

    if not base_url:
        raise DemistoException(
            'Tenable.sc Server URL is required.'
        )

    if not access_key or not secret_key:
        raise DemistoException(
            'Access Key and Secret Key are required.'
        )

    if insecure:
        urllib3.disable_warnings(
            urllib3.exceptions.InsecureRequestWarning
        )

    client = TenableSCClient(
        base_url=base_url,
        access_key=access_key,
        secret_key=secret_key,
        verify=not insecure,
        timeout=timeout
    )

    if command == 'test-module':
        return_results(
            test_module(client)
        )

    elif command == 'tenable-sc-analysis-test':
        return_results(
            analysis_test_command(
                client,
                demisto.args()
            )
        )

    elif command == 'tenable-sc-vulnerability-details':
        return_results(
            vulnerability_details_command(
                client,
                demisto.args()
            )
        )

    elif command == 'tenable-sc-get-vulnerability-dataset':
        return_results(
            vulnerability_dataset_command(
                client,
                demisto.args()
            )
        )

    elif command == 'tenable-sc-get-external-sla-summary':
        return_results(
            sla_summary_command(
                client,
                demisto.args()
            )
        )

    else:
        raise NotImplementedError(
            'Unsupported command: {}'.format(command)
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        main()

    except Exception as error:
        return_error(
            '{}\n\nTraceback:\n{}'.format(
                str(error),
                traceback.format_exc()
            )
        )

"""conftest.py - Setup mock XSOAR modules for local pytest execution.

This file is loaded automatically by pytest before any test imports.
It injects mock versions of demistomock, CommonServerPython, and
CommonServerUserPython into sys.modules so Brandefense.py can be
imported outside of the XSOAR runtime.
"""
import sys
import types
from unittest.mock import MagicMock


def setup_demistomock():
    """Create a mock demistomock module with standard XSOAR functions."""
    mock_demisto = MagicMock()
    mock_demisto.params.return_value = {}
    mock_demisto.args.return_value = {}
    mock_demisto.command.return_value = 'test-module'
    mock_demisto.results = MagicMock()
    mock_demisto.incidents = MagicMock()
    mock_demisto.getLastRun.return_value = {}
    mock_demisto.setLastRun = MagicMock()
    mock_demisto.getIntegrationContext.return_value = {}
    mock_demisto.setIntegrationContext = MagicMock()
    mock_demisto.debug = MagicMock()
    mock_demisto.info = MagicMock()
    mock_demisto.error = MagicMock()

    module = types.ModuleType('demistomock')
    module.demisto = mock_demisto
    # Also expose functions at module level
    for attr in dir(mock_demisto):
        if not attr.startswith('_'):
            setattr(module, attr, getattr(mock_demisto, attr))
    return module


def setup_common_server_python():
    """Create a mock CommonServerPython module with standard XSOAR classes."""
    module = types.ModuleType('CommonServerPython')

    # --- IncidentSeverity ---
    class IncidentSeverity:
        UNKNOWN = 0
        INFO = 0.5
        LOW = 1
        MEDIUM = 2
        HIGH = 3
        CRITICAL = 4

    module.IncidentSeverity = IncidentSeverity

    # --- DBotScoreType ---
    class DBotScoreType:
        IP = 'ip'
        DOMAIN = 'domain'
        URL = 'url'
        FILE = 'file'
        HASH = 'hash'
        EMAIL = 'email'
        CVE = 'cve'

    module.DBotScoreType = DBotScoreType

    # --- DBotScoreReliability ---
    class DBotScoreReliability:
        A_PLUS = 'A+ - 3rd party enrichment'
        A = 'A - Completely reliable'
        B = 'B - Usually reliable'
        C = 'C - Fairly reliable'
        D = 'D - Not usually reliable'
        E = 'E - Unreliable'
        F = 'F - Reliability cannot be judged'

    module.DBotScoreReliability = DBotScoreReliability

    # --- Common namespace ---
    class DBotScore:
        NONE = 0
        GOOD = 1
        SUSPICIOUS = 2
        BAD = 3

        def __init__(self, indicator, indicator_type, integration_name, score,
                     reliability=None, message=None, malicious_description=None):
            self.indicator = indicator
            self.indicator_type = indicator_type
            self.integration_name = integration_name
            self.score = score
            self.reliability = reliability
            self.message = message

    class IP:
        def __init__(self, ip, dbot_score, malicious_description=None, **kwargs):
            self.address = ip
            self.ip = ip
            self.dbot_score = dbot_score
            self.malicious_description = malicious_description

    class Domain:
        def __init__(self, domain, dbot_score, malicious_description=None, **kwargs):
            self.domain = domain
            self.dbot_score = dbot_score
            self.malicious_description = malicious_description

    class URL:
        def __init__(self, url, dbot_score, malicious_description=None, **kwargs):
            self.url = url
            self.dbot_score = dbot_score
            self.malicious_description = malicious_description

    class File:
        def __init__(self, dbot_score, md5=None, sha1=None, sha256=None, **kwargs):
            self.md5 = md5
            self.sha1 = sha1
            self.sha256 = sha256
            self.dbot_score = dbot_score

    # Use local refs to avoid class-scope lookup issues
    _DBotScore = DBotScore
    _IP = IP
    _Domain = Domain
    _URL = URL
    _File = File

    class Common:
        DBotScore = _DBotScore
        IP = _IP
        Domain = _Domain
        URL = _URL
        File = _File

    module.Common = Common

    # --- BaseClient ---
    class BaseClient:
        def __init__(self, base_url='', verify=True, proxy=False, ok_codes=None,
                     headers=None, auth=None, timeout=None, retries=0,
                     backoff_factor=0, status_list_to_retry=None, **kwargs):
            self._base_url = base_url
            self._verify = verify
            self._proxy = proxy
            self._headers = headers or {}

        def _http_request(self, method, url_suffix='', params=None,
                          json_data=None, resp_type='json', **kwargs):
            return {}

    module.BaseClient = BaseClient

    # --- Utility functions ---
    def tableToMarkdown(name, t, headers=None, headerTransform=None, removeNull=False, **kwargs):
        if isinstance(t, dict):
            t = [t]
        if not t:
            return f'### {name}\n**No entries.**\n'
        lines = [f'### {name}']
        if headers and t:
            display_headers = headers
        elif t and isinstance(t[0], dict):
            display_headers = list(t[0].keys())
        else:
            display_headers = []
        if headerTransform and callable(headerTransform):
            display_headers_formatted = [headerTransform(h) for h in display_headers]
        else:
            display_headers_formatted = display_headers
        lines.append('|' + '|'.join(str(h) for h in display_headers_formatted) + '|')
        lines.append('|' + '|'.join(['---'] * len(display_headers)) + '|')
        for row in t:
            if isinstance(row, dict):
                vals = [str(row.get(h, '')) for h in display_headers]
            else:
                vals = [str(row)]
            lines.append('|' + '|'.join(vals) + '|')
        return '\n'.join(lines) + '\n'

    module.tableToMarkdown = tableToMarkdown

    class CommandResults:
        def __init__(self, readable_output=None, outputs=None, outputs_prefix=None,
                     outputs_key_field=None, indicator=None, raw_response=None, **kwargs):
            self.readable_output = readable_output
            self.outputs = outputs
            self.outputs_prefix = outputs_prefix
            self.outputs_key_field = outputs_key_field
            self.indicator = indicator
            self.raw_response = raw_response

    module.CommandResults = CommandResults

    class DemistoException(Exception):
        pass

    module.DemistoException = DemistoException

    def return_results(results):
        pass

    module.return_results = return_results

    def return_error(message, error='', outputs=None):
        raise DemistoException(message)

    module.return_error = return_error

    def argToList(arg, separator=',', transform=None):
        if not arg:
            return []
        if isinstance(arg, list):
            return arg
        return [item.strip() for item in arg.split(separator)]

    module.argToList = argToList

    def arg_to_datetime(arg, arg_name='', is_utc=True, required=False, settings=None):
        from datetime import datetime, timedelta, timezone
        if not arg:
            return None
        arg = arg.strip()
        parts = arg.split()
        if len(parts) == 2:
            try:
                num = int(parts[0])
                unit = parts[1].lower().rstrip('s')
                if unit == 'day':
                    return datetime.now(timezone.utc) - timedelta(days=num)
                elif unit == 'hour':
                    return datetime.now(timezone.utc) - timedelta(hours=num)
                elif unit == 'minute':
                    return datetime.now(timezone.utc) - timedelta(minutes=num)
            except (ValueError, IndexError):
                pass
        try:
            return datetime.fromisoformat(arg)
        except ValueError:
            return datetime.now(timezone.utc) - timedelta(days=3)

    module.arg_to_datetime = arg_to_datetime

    def timestamp_to_datestring(timestamp, date_format='%Y-%m-%dT%H:%M:%SZ', is_utc=True):
        from datetime import datetime, timezone
        if isinstance(timestamp, (int, float)):
            if timestamp > 1e12:
                timestamp = timestamp / 1000
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.strftime(date_format)
        return str(timestamp)

    module.timestamp_to_datestring = timestamp_to_datestring

    def urljoin(base, path):
        if base.endswith('/'):
            base = base[:-1]
        if not path.startswith('/'):
            path = '/' + path
        return base + path

    module.urljoin = urljoin

    return module


# --- Install mock modules into sys.modules BEFORE any test imports ---

if 'demistomock' not in sys.modules:
    sys.modules['demistomock'] = setup_demistomock()

if 'CommonServerPython' not in sys.modules:
    sys.modules['CommonServerPython'] = setup_common_server_python()

if 'CommonServerUserPython' not in sys.modules:
    sys.modules['CommonServerUserPython'] = types.ModuleType('CommonServerUserPython')

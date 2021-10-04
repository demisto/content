DATE_FORMAT: str = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
DATE_FORMAT_WITH_MICROSECOND = '%Y-%m-%dT%H:%M:%S.%fZ'
DEFAULT_FETCH_LIMIT = '50'
DEFAULT_FIRST_FETCH = '1 hour'
CONTENT_TYPE_JSON = 'application/json'

URL_SUFFIX = {
    'FETCH_INCIDENTS': 'get_incidents',
    'GET_COLUMN': 'get_columns',
    'GET_COUNT': 'get_count',
    'TEST_API': 'test_api'
}

CHECK_ARG_MOCK_DATA = {
    "test_int": 15,
    "test_str": "logsign",
    "test_list": [1, 2, 3],
    "test_dict": {"str": "unix"}
}

PARAMS = {
    'url': 'https://192.168.0.1',
    'apikey': 'apikey',
    'last_run': '',
    'insecure': False,
    'proxy': False,
    'first_fetch': DEFAULT_FIRST_FETCH,
    'max_fetch': DEFAULT_FETCH_LIMIT
}

ARGS_Q = {'query': '*', 'grouped_column': 'Source.IP', 'criteria': 'value', 'time_frame': '1 hour'}

MOCK_INCIDENTS = {'incidents': [
    {
            "EventSource": {
                "Vendor": "PaloAlto",
                "Description": "palo_alto_fw",
                "Category": "Firewall",
                "Type": "Security System",
                "PrefixID": 3029,
                "Collector": "alert.flow",
                "Tag": "palo_alto",
                "IP": "192.168.1.151",
                "Serial": "0011C100469"
            },
            "Details": {
                "Flags": "0x400000",
                "LogProfile": "Threat Alert",
                "ThreatID": "Virus/Win32.WGeneric.hjykm(3081002)"
            },
            "_insert_time": 1619013913,
            "Source": {
                "Location": "location",
                "Zone": "untrust",
                "Position": "out",
                "City": "Unknown",
                "Port": "80",
                "Interface": "ethernet1/20",
                "IP": "192.168.1.17",
                "Country": "Curacao"
            },
            "Application": {
                "Name": "smtp"
            },
            "EventMap": {
                "Type": "Virus",
                "ID": 20503,
                "Context": "Security",
                "Info": "Virus Block",
                "SubType": "Block"
            },
            "External": {
                "IP": "228.x.249.122"
            },
            "Event": {
                "SystemID": 302991,
                "SubCategory": "vulnerability",
                "Category": "THREAT",
                "VendorID": 91,
                "Info": "wildfire-virus smtp drop",
                "Action": "drop"
            },
            "URL": {
                "Category": "any",
                "Domain": "po.sen260216kk.exe",
                "Scheme": "http"
            },
            "Internal": {
                "IP": "192.168.1.17"
            },
            "Action": {
                "Object": "192.168.1.17"
            },
            "Protocol": {
                "Name": "tcp"
            },
            "Severity": {
                "ID": 4,
                "Name": "warning"
            },
            "_es_type": "flow@alert@generic_log",
            "Session": {
                "ID": "48247132",
                "Direction": "client-to-server"
            },
            "Time": {
                "Received": "2021-04-21 14:05:01",
                "Generated": "2021-04-21 14:05:13"
            },
            "Rule": {
                "Name": "rule5"
            },
            "Alert": {
                "AlertUID": "94d17e7f2ace2688110e0bf9f579e142",
                "Info": "Infected Host Detected",
                "Category": "Malware",
                "Reason": "EventMap.Type:Virus\nEventMap.SubType:Block"
            },
            "DataType": "alert",
            "Destination": {
                "Location": "unknown",
                "Zone": "trust",
                "Position": "in",
                "City": "East Berbice-Corentyne",
                "Port": "8091",
                "Interface": "ethernet1/21",
                "IP": "228.x.249.122",
                "Country": "Guyana"
            }
        },
    {
            "EventSource": {
                "Vendor": "PaloAlto",
                "Description": "palo_alto_fw",
                "Category": "Firewall",
                "Type": "Security System",
                "PrefixID": 3029,
                "Collector": "alert.flow",
                "Tag": "palo_alto",
                "IP": "192.168.1.151",
                "Serial": "0011C100469"
            },
            "Details": {
                "Flags": "0x400000",
                "LogProfile": "Threat Alert",
                "ThreatID": "Virus/Win32.WGeneric.hjykm(3081002)"
            },
            "_insert_time": 1619013913,
            "Source": {
                "Location": "location",
                "Zone": "untrust",
                "Position": "out",
                "City": "Unknown",
                "Port": "80",
                "Interface": "ethernet1/20",
                "IP": "192.168.1.17",
                "Country": "Curacao"
            },
            "Application": {
                "Name": "smtp"
            },
            "EventMap": {
                "Type": "Virus",
                "ID": 20503,
                "Context": "Security",
                "Info": "Virus Block",
                "SubType": "Block"
            },
            "External": {
                "IP": "228.x.249.122"
            },
            "Event": {
                "SystemID": 302991,
                "SubCategory": "vulnerability",
                "Category": "THREAT",
                "VendorID": 91,
                "Info": "wildfire-virus smtp drop",
                "Action": "drop"
            },
            "URL": {
                "Category": "any",
                "Domain": "po.sen260216kk.exe",
                "Scheme": "http"
            },
            "Internal": {
                "IP": "192.168.1.17"
            },
            "Action": {
                "Object": "192.168.1.17"
            },
            "Protocol": {
                "Name": "tcp"
            },
            "Severity": {
                "ID": 4,
                "Name": "warning"
            },
            "_es_type": "flow@alert@generic_log",
            "Session": {
                "ID": "48247132",
                "Direction": "client-to-server"
            },
            "Time": {
                "Received": "2021-04-21 14:05:01",
                "Generated": "2021-04-21 14:05:13"
            },
            "Rule": {
                "Name": "rule5"
            },
            "Alert": {
                "AlertUID": "94d17e7f2ace2688110e0bf9f579e142",
                "Info": "Infected Host Detected",
                "Category": "Malware",
                "Reason": "EventMap.Type:Virus\nEventMap.SubType:Block"
            },
            "DataType": "alert",
            "Destination": {
                "Location": "unknown",
                "Zone": "trust",
                "Position": "in",
                "City": "East Berbice-Corentyne",
                "Port": "8091",
                "Interface": "ethernet1/21",
                "IP": "228.x.249.122",
                "Country": "Guyana"
            }
        }]
}

MOCK_INC = {'last_fetch': '2021-04-21T01:00:00Z', 'incidents': MOCK_INCIDENTS['incidents']}

RESULT_COUNT_HR = """
### Results
|count|
|---|
| 785045 |
"""

RESULT_COLUMNS_HR = """
### Results
|columns|
|---|
| 192.168.1.35,<br>192.168.1.17 |
"""

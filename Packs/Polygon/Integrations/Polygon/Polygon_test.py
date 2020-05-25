import json
import pytest

from Polygon import demisto, Client, ANALGIN_UPLOAD, ATTACH, FILE_TYPE, HASH_REPUTATION
from pprint import pprint

with open("test_data/test_report.json", "r") as f:
    MOCKED_REPORT = json.load(f)
MOCKED_CLIENT_KWARGS = {
    "base_url": "http://123-fake-api.com",
    "api_key": "12345678",
    "verify": False,
    "proxies": None,
    "language": "en"
}

'''MOCKED ARGS'''
MOCKED_UPLOAD_FILE_ARGS = {
    "file_id": "12345",
    "password": ""
}
MOCKED_UPLOAD_URL_ARGS = {
    "url": "http://test.com"
}
MOCKED_ANALYSIS_INFO_ARGS = {
    "tds_analysis_id": ["F1"]
}
MOCKED_FILE_ARGS = {
    "file": [
        "44b3f79dfd7c5861501a19a3bac89f544c7ff815"
    ]
}

'''MOCKED API RETURN DATA'''
MOCKED_FILE_REPUTATION_DATA = {
    "data": {
        "found": True,
        "verdict": True,
        "score": 21.0,
        "malware_families": ["Trojan"]
    }
}
MOCKED_UPLOAD_DATA = {
    "data": {
        "ids": [100]
    },
    "errors": [],
    "messages": []
}
MOCKED_ANALYSIS_INFO_DATA = { "data": { "results": [{
    "file_url": "foo/bar",
    "analgin_result": {
        "error": None,
        "commit": "f0eb1fe9df628438ba32b9be9624901a37918a35",
        "reports": [],
        "verdict": True,
        "context_desired": False
    },
    "src": "",
    "dst": "",
    "is_restorible": False,
    "id": 2118597,
    "search_id": "2118597",
    "uploader": "Demisto Integration",
    "sensor": "ООО GROUP-IB TDS HUNTBOX",
    "msp_id": None,
    "sha256": "0d1b77c84c68c50932e28c3462a1962916abbbebb456ce654751ab401aa37697",
    "sha1": "44b3f79dfd7c5861501a19a3bac89f544c7ff815",
    "md5": "ba9fe2cb8ee2421ea24a55306ce9d923",
    "file_size": 36375,
    "original_filename": "link.pdf",
    "ts_created": "2020-05-07T13:27:26.000165+03:00",
    "ts_analized": None,
    "ts_last_sync": None,
    "verdict": None,
    "is_whitelisted": False,
    "is_deleted": False,
    "is_blocked": False,
    "src_ip": None,
    "dst_ip": None,
    "meta": {
        "analgin": {
            "error": None,
            "commit": "f0eb1fe9df628438ba32b9be9624901a37918a35",
            "reports": [],
            "verdict": True,
            "context_desired": False
        }
    },
    "source": "MANUAL",
    "sandbox_url": None,
    "sandbox_version": None,
    "envelope": None,
    "appliance": 1,
    "department": None
}]}}

'''MOCKED COMMAND RESULTS'''
MOCKED_UPLOAD_FILE_RESULTS = {
    "Contents": {
        "EntryID": "12345",
        "FileName": "abc",
        "ID": "F100",
        "Status": "In Progress"
    },
    "ContentsFormat": "json",
    "EntryContext": {
        "Polygon.Analysis(val.ID == obj.ID)": {
            "EntryID": "12345",
            "FileName": "abc",
            "ID": "F100",
            "Status": "In Progress"
        }
    },
    "HumanReadable": "File uploaded successfully. Analysis ID: F100",
    "Type": 1
}
MOCKED_UPLOAD_URL_RESULTS = {
    "Contents": {
        "ID": "U100",
        "Status": "In Progress",
        "URL": "http://test.com"
    },
    "ContentsFormat": "json",
    "EntryContext": {
        "Polygon.Analysis(val.ID == obj.ID)": {
            "ID": "U100",
            "Status": "In Progress",
            "URL": "http://test.com"
        }
    },
    "HumanReadable": "Url uploaded successfully. Analysis ID: U100",
    "Type": 1
}
MOCKED_ANALYSIS_INFO_RESULTS = [{
    "Contents": {
        "ID": "F2118597",
        "MD5": "ba9fe2cb8ee2421ea24a55306ce9d923",
        "Name": "link.pdf",
        "Result": None,
        "SHA1": "44b3f79dfd7c5861501a19a3bac89f544c7ff815",
        "SHA256": "0d1b77c84c68c50932e28c3462a1962916abbbebb456ce654751ab401aa37697",
        "Size": 36375,
        "Status": "In Progress"
    },
    "ContentsFormat": "json",
    "EntryContext": {
        "Polygon.Analysis(val.ID == obj.ID)": {
            "ID": "F2118597",
            "MD5": "ba9fe2cb8ee2421ea24a55306ce9d923",
            "Name": "link.pdf",
            "Result": None,
            "SHA1": "44b3f79dfd7c5861501a19a3bac89f544c7ff815",
            "SHA256": "0d1b77c84c68c50932e28c3462a1962916abbbebb456ce654751ab401aa37697",
            "Size": 36375,
            "Status": "In Progress"
        }
    },
    "HumanReadable": "### Analysis F2118597\n|ID|MD5|Name|SHA1|SHA256|Size|Status|\n|---|---|---|---|---|---|---|\n| F2118597 | ba9fe2cb8ee2421ea24a55306ce9d923 | link.pdf | 44b3f79dfd7c5861501a19a3bac89f544c7ff815 | 0d1b77c84c68c50932e28c3462a1962916abbbebb456ce654751ab401aa37697 | 36375 | In Progress |\n",
    "Type": 1
}]
MOCKED_SERIALIZED_REPORT = {
    'Analyzed': '2020-05-19 09:48:27',
    'DumpExists': True,
    'Families': '',
    'Internet-connection': 'Available',
    'Probability': '68.00%',
    'Score': 24.0,
    'Started': '2020-05-19 09:46:15',
    'Type': 'ASCII text, with no line terminators',
    'Verdict': 'Malicious'
}
MOCKED_MAIN_INDICATOR = {
    'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': {
        'Name': 'url.txt',
        'MD5': '9b52c8a74353d82ef1ebca42c9a7358c',
        'SHA1': 'eb57446af5846faa28a726a8b7d43ce5a7fcbd55',
        'SHA256': '34ce805b7131eda3cec905dfd4e2708ab07dd3f038345b2ba9df51eb8fc915eb',
        'Type': 'ASCII text, with no line terminators',
        'Malicious': {
            'Vendor': 'Group-IB TDS Polygon',
            'Description': 'Verdict probability: 68.0%, iocs: JS:Trojan.Agent.DQBF'
        }
    },
    'DBotScore': {
        'Indicator': '9b52c8a74353d82ef1ebca42c9a7358c',
        'Type': 'file',
        'Vendor': 'Group-IB TDS Polygon',
        'Score': 3
    }
}
MOCKED_PACKAGES_INDICATORS = [
    {
        'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': {
            'Name': 'url.txt',
            'MD5': '9b52c8a74353d82ef1ebca42c9a7358c',
            'SHA1': 'eb57446af5846faa28a726a8b7d43ce5a7fcbd55',
            'SHA256': '34ce805b7131eda3cec905dfd4e2708ab07dd3f038345b2ba9df51eb8fc915eb',
            'Type': 'ASCII text, with no line terminators'
        },
        'DBotScore': {
            'Indicator': 'eb57446af5846faa28a726a8b7d43ce5a7fcbd55',
            'Type': 'file',
            'Vendor': 'Group-IB TDS Polygon',
            'Score': 0
        }
    },
    {
        'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': {
            'Name': 'tmpwDwvW_',
            'MD5': '9b52c8a74353d82ef1ebca42c9a7358c',
            'SHA1': 'eb57446af5846faa28a726a8b7d43ce5a7fcbd55',
            'SHA256': '34ce805b7131eda3cec905dfd4e2708ab07dd3f038345b2ba9df51eb8fc915eb',
            'Type': 'ASCII text, with no line terminators'
        },
        'DBotScore': {
            'Indicator': 'eb57446af5846faa28a726a8b7d43ce5a7fcbd55',
            'Type': 'file',
            'Vendor': 'Group-IB TDS Polygon',
            'Score': 0
        }
    },
    {
        'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': {
            'Name': 'pik.zip',
            'MD5': '3641c180f1a2c3f41fb1d974687e3553',
            'SHA1': '3a29353e30ddd1af92f07ee0f61a3a706ee09a64',
            'SHA256': 'c296d2895ac541ba16a237b2ad344b28e803b6990b7713c4c73faa9f722cf9fc',
            'Type': 'Zip archive data, at least v2.0 to extract'
        },
        'DBotScore': {
            'Indicator': '3a29353e30ddd1af92f07ee0f61a3a706ee09a64',
            'Type': 'file',
            'Vendor': 'Group-IB TDS Polygon',
            'Score': 0
        }
    },
    {
        'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': {
            'Name': 'Ğ\x9fĞ\x90Ğ\x9e Â«Ğ\x93Ñ\x80Ñ\x83Ğ¿Ğ¿Ğ° Ğ\x9aĞ¾Ğ¼Ğ¿Ğ°Ğ½Ğ¸Ğ¹ Ğ\x9fĞ\x98Ğ\x9aÂ» Ğ¿Ğ¾Ğ´Ñ\x80Ğ¾Ğ±Ğ½Ğ¾Ñ\x81Ñ\x82Ğ¸ Ğ·Ğ°ĞºĞ°Ğ·Ğ°.js',
            'MD5': '9cd53f781ba0bed013ee87c5e7956f64',
            'SHA1': 'c41542c7dd5a714adfeafec77022ae0a722ff3a8',
            'SHA256': '422ea8f21b8652dd760a3f02ac3e2a4345d7e45fce49e1e45f020384c93a29ea',
            'Type': 'ASCII text, with CRLF, LF line terminators'
        },
        'DBotScore': {
            'Indicator': 'c41542c7dd5a714adfeafec77022ae0a722ff3a8',
            'Type': 'file',
            'Vendor': 'Group-IB TDS Polygon',
            'Score': 0
        }
    }
]
MOCKED_NETWORK_INDICATORS = [
    {
        'Domain(val.Name && val.Name == obj.Name)': {
            'Name': 'svettenkirch.de',
            'DNS': '217.114.216.252'
        },
        'DBotScore': {
            'Indicator': 'svettenkirch.de',
            'Type': 'domain',
            'Vendor': 'Group-IB TDS Polygon',
            'Score': 0
        }
    },
    {
        'Domain(val.Name && val.Name == obj.Name)': {
            'Name': 'super.esu.as',
            'DNS': '79.98.29.14'
        },
        'DBotScore': {
            'Indicator': 'super.esu.as',
            'Type': 'domain',
            'Vendor': 'Group-IB TDS Polygon',
            'Score': 0
        }
    },
    {
        'IP(val.Address && val.Address == obj.Address)': {
            'Address': '8.8.8.8'
        },
        'DBotScore': {
            'Indicator': '8.8.8.8',
            'Type': 'ip',
            'Vendor': 'Group-IB TDS Polygon',
            'Score': 0
        }
    },
    {
        'IP(val.Address && val.Address == obj.Address)': {
            'Address': '79.98.29.14'
        },
        'DBotScore': {
            'Indicator': '79.98.29.14',
            'Type': 'ip',
            'Vendor': 'Group-IB TDS Polygon',
            'Score': 0
        }
    },
    {
        'IP(val.Address && val.Address == obj.Address)': {
            'Address': '217.114.216.252'
        },
        'DBotScore': {
            'Indicator': '217.114.216.252',
            'Type': 'ip',
            'Vendor': 'Group-IB TDS Polygon',
            'Score': 0
        }
    },
    {
        'IP(val.Address && val.Address == obj.Address)': {
            'Address': '217.114.216.252'
        },
        'DBotScore': {
            'Indicator': '217.114.216.252',
            'Type': 'ip',
            'Vendor': 'Group-IB TDS Polygon',
            'Score': 0
        }
    },
    {
        'URL(val.Data && val.Data == obj.Data)': {
            'Data': 'http://super.esu.as/wp-content/themes/twentyeleven/inc/images/msg.jpg'
        },
        'DBotScore': {
            'Indicator': 'http://super.esu.as/wp-content/themes/twentyeleven/inc/images/msg.jpg',
            'Type': 'url',
            'Vendor': 'Group-IB TDS Polygon',
            'Score': 0
        }
    }
]
MOCKED_MONITOR_INDICATORS = [{'Process': {'Child': None,
              'CommandLine': '"C:\\Users\\John\\AppData\\Local\\Temp\\tmps8zsgu\\Ğ\x9fĞ\x90Ğ\x9e '
                             'Â«Ğ\x93Ñ\x80Ñ\x83Ğ¿Ğ¿Ğ° Ğ\x9aĞ¾Ğ¼Ğ¿Ğ°Ğ½Ğ¸Ğ¹ '
                             'Ğ\x9fĞ\x98Ğ\x9aÂ» '
                             'Ğ¿Ğ¾Ğ´Ñ\x80Ğ¾Ğ±Ğ½Ğ¾Ñ\x81Ñ\x82Ğ¸ Ğ·Ğ°ĞºĞ°Ğ·Ğ°.js"',
              'EndTime': 132343804138750000,
              'Hostname': None,
              'MD5': None,
              'Name': 'wscript.exe',
              'PID': '972',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\wscript.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': 132343803741562500}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\EnableFileTracing',
                  'Value': '0'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\EnableConsoleTracing',
                  'Value': '0'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\FileTracingMask',
                  'Value': '-65536'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\ConsoleTracingMask',
                  'Value': '-65536'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\MaxFileSize',
                  'Value': '1048576'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\FileDirectory',
                  'Value': '%windir%\\tracing'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\EnableFileTracing',
                  'Value': '0'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\EnableConsoleTracing',
                  'Value': '0'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\FileTracingMask',
                  'Value': '-65536'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\ConsoleTracingMask',
                  'Value': '-65536'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\MaxFileSize',
                  'Value': '1048576'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\FileDirectory',
                  'Value': '%windir%\\tracing'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                          'Settings\\ProxyEnable',
                  'Value': '0'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                          'Settings\\Connections\\SavedLegacySettings',
                  'Value': "{'data': "
                           "'RgAAADcAAAAJAAAAAAAAAAAAAAAAAAAABAAAAAAAAADwtLKVehjTAQAAAAAAAAAAAAAAAAIAAAAXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAVHNMAFRzTAAAAAAAAAAAAAQAAAAAAAAAeHNMAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AwAAAAAAAAACAAAAAQAAAAIAAADAqAEOAAAAAAAAAADa2traAAAAAAAAAAAFAAAAAAAAAAAAAAAptQYAAAAAAAAAAAAAAAAA8HNMAPBzTAAAAAAAAAAAAP////8AAAAAAAAAAAAAAAAAAAAAFHRMABR0TAAAAAAAIHRMACB0TAAAAAAAAAAAAAAAAAAAAAAA', "
                           "'type': 'b64_struct'}"}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                          'Settings\\ZoneMap\\UNCAsIntranet',
                  'Value': '0'}},
 {'RegistryKey': {'Name': None,
                  'Path': '\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                          'Settings\\ZoneMap\\AutoDetect',
                  'Value': '1'}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': '(null)',
              'PID': '4',
              'Parent': None,
              'Path': '(null)',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'OSPPSVC.EXE',
              'PID': '180',
              'Parent': None,
              'Path': 'C:\\Program Files\\Common Files\\microsoft '
                      'shared\\OfficeSoftwareProtectionPlatform\\OSPPSVC.EXE',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'audiodg.exe',
              'PID': '1116',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\audiodg.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'csrss.exe',
              'PID': '296',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\csrss.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'csrss.exe',
              'PID': '340',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\csrss.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'dwm.exe',
              'PID': '1276',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\dwm.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'lsass.exe',
              'PID': '396',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\lsass.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'lsm.exe',
              'PID': '404',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\lsm.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'services.exe',
              'PID': '380',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\services.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'smss.exe',
              'PID': '216',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\smss.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'spoolsv.exe',
              'PID': '1168',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\spoolsv.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'svchost.exe',
              'PID': '776',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\svchost.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'svchost.exe',
              'PID': '944',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\svchost.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'svchost.exe',
              'PID': '804',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\svchost.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'svchost.exe',
              'PID': '636',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\svchost.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'svchost.exe',
              'PID': '560',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\svchost.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'svchost.exe',
              'PID': '704',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\svchost.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'svchost.exe',
              'PID': '1220',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\svchost.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'svchost.exe',
              'PID': '724',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\svchost.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'svchost.exe',
              'PID': '1004',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\svchost.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'taskhost.exe',
              'PID': '1296',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\taskhost.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': 132343804331406250,
              'Hostname': None,
              'MD5': None,
              'Name': 'WmiPrvSE.exe',
              'PID': '1608',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'winlogon.exe',
              'PID': '460',
              'Parent': None,
              'Path': 'C:\\Windows\\System32\\winlogon.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}},
 {'Process': {'Child': None,
              'CommandLine': '',
              'EndTime': None,
              'Hostname': None,
              'MD5': None,
              'Name': 'explorer.exe',
              'PID': '1344',
              'Parent': None,
              'Path': 'C:\\Windows\\explorer.exe',
              'SHA1': None,
              'Sibling': None,
              'StartTime': None}}
]
MOCKED_FILE_REPUTATION_RESULTS = [
    {
        "Contents": {
            "Found": True,
            "Malware-families": [
                "Trojan"
            ],
            "SHA1": "44b3f79dfd7c5861501a19a3bac89f544c7ff815",
            "Score": 21.0,
            "Verdict": True
        },
        "ContentsFormat": "json",
        "EntryContext": {
            "DBotScore": {
                "Indicator": "44b3f79dfd7c5861501a19a3bac89f544c7ff815",
                "Score": 3,
                "Type": "file",
                "Vendor": "Group-IB TDS Polygon"
            },
            "File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)": {
                "Malicious": {
                    "Description": "TDS Polygon score: 21.0, Trojan",
                    "Vendor": "Group-IB TDS Polygon"
                },
                "SHA1": "44b3f79dfd7c5861501a19a3bac89f544c7ff815"
            },
            "Polygon.Analysis(val.SHA1 == obj.SHA1)": {
                "Found": True,
                "Malware-families": [
                    "Trojan"
                ],
                "SHA1": "44b3f79dfd7c5861501a19a3bac89f544c7ff815",
                "Score": 21.0,
                "Verdict": True
            }
        },
        "HumanReadable": "### Results\n|Found|Malware-families|SHA1|Score|Verdict|\n|---|---|---|---|---|\n| true | Trojan | 44b3f79dfd7c5861501a19a3bac89f544c7ff815 | 21.0 | true |\n",
        "Type": 1
    }
]


class MockedClient(Client):
    def _http_request(self, method, url_suffix, params=None, data=None, files=None, decode=True):
        if url_suffix == ANALGIN_UPLOAD:
            return MOCKED_UPLOAD_DATA
        elif url_suffix == ATTACH.format(1):
            return MOCKED_ANALYSIS_INFO_DATA
        elif url_suffix == HASH_REPUTATION.format("sha1", MOCKED_FILE_ARGS["file"][0]):
            return MOCKED_FILE_REPUTATION_DATA
        return dict()

    def upload_file(self, file_name, file_path, password=""):
        return 100


def test_file_command(mocker):
    from Polygon import file_command
    mocked_client = MockedClient(**MOCKED_CLIENT_KWARGS)
    results = file_command(mocked_client, MOCKED_FILE_ARGS)
    assert MOCKED_FILE_REPUTATION_RESULTS == [r.to_context() for r in results]

def test_upload_file_command(mocker):
    from Polygon import upload_file_command
    mocked_client = MockedClient(**MOCKED_CLIENT_KWARGS)
    mocker.patch.object(demisto, "getFilePath", return_value={"name": "abc", "path": "abc"})
    results = upload_file_command(mocked_client, MOCKED_UPLOAD_FILE_ARGS)
    assert results.to_context() == MOCKED_UPLOAD_FILE_RESULTS

def test_upload_url_command(mocker):
    from Polygon import upload_url_command
    mocked_client = MockedClient(**MOCKED_CLIENT_KWARGS)
    results = upload_url_command(mocked_client, MOCKED_UPLOAD_URL_ARGS)
    assert results.to_context() == MOCKED_UPLOAD_URL_RESULTS

def test_analysis_info_command(mocker):
    from Polygon import analysis_info_command
    mocked_client = MockedClient(**MOCKED_CLIENT_KWARGS)
    results = analysis_info_command(mocked_client, MOCKED_ANALYSIS_INFO_ARGS)
    assert [r.to_context() for r in results] == MOCKED_ANALYSIS_INFO_RESULTS

def test_serialize_report_info(mocker):
    from Polygon import serialize_report_info
    results = serialize_report_info(MOCKED_REPORT, FILE_TYPE)
    assert results == MOCKED_SERIALIZED_REPORT

def test_get_main_indicator(mocker):
    from Polygon import get_main_indicator
    results = get_main_indicator(MOCKED_REPORT, FILE_TYPE)
    assert results.to_context() == MOCKED_MAIN_INDICATOR

def test_get_packages_indicators(mocker):
    from Polygon import get_packages_indicators
    results = get_packages_indicators(MOCKED_REPORT)
    assert MOCKED_PACKAGES_INDICATORS == [r.to_context() for r in results]

def test_get_network_indicators(mocker):
    from Polygon import get_network_indicators
    results = get_network_indicators(MOCKED_REPORT)
    assert MOCKED_NETWORK_INDICATORS == [r.to_context() for r in results]

def test_get_monitor_indicators(mocker):
    from Polygon import get_monitor_indicators
    results = get_monitor_indicators(MOCKED_REPORT)
    # assert MOCKED_MONITOR_INDICATORS == [r.to_context() for r in results]
    pprint([r.to_context() for r in results])

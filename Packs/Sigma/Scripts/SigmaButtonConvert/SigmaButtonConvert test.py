import pytest
import demistomock as demisto
from unittest.mock import patch

from SigmaButtonConvert import main as sigma_button

rule_example = ('{"title": "Potential AMSI COM Server Hijacking", \
                "logsource": {"category": "registry_set", "product": "windows"}, \
                "detection": {"selection": \
                {"TargetObject|endswith": "\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\InProcServer32\\(Default)"}, \
                "filter": {"Details": "%windir%\\system32\\amsi.dll"}, "condition": "selection and not filter"}, \
                "id": "160d2780-31f7-4922-8b3a-efce30e63e96", "status": "test", "level": "high", \
                "author": "Nasreddine Bencherchali (Nextron Systems)", \
                "description": "Detects changes to the AMSI come server registry key in order disable AMSI scanning \
                functionalities. When AMSI attempts to starts its COM component, it will query its registered CLSID and return \
                a non-existent COM server. This causes a load failure and prevents any scanning methods from being accessed, \
                ultimately rendering AMSI useless", \
                "references": ["https://enigma0x3.net/2017/07/19/bypassing-amsi-via-com-server-hijacking/", \
                "https://github.com/r00t-3xp10it/hacking-material-books/blob/43cb1e1932c16ff1f58b755bc9ab6b096046853f/obfuscation/simple_obfuscation.md#amsi-comreg-bypass"], \
                "falsepositives": ["Unknown"], "tags": ["attack.defense-evasion", "attack.t1562.001"], "date": "2023-01-04"}')

xql_query = ('dataset=xdr_data | \
             filter event_type = ENUM.REGISTRY and \
             (agent_os_type = ENUM.AGENT_OS_WINDOWS and \
             (action_registry_key_name contains "\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\InProcServer32\\(Default)" \
             and (not \
             (action_registry_value_name = "%windir%\\system32\\amsi.dll" \
             or action_registry_data = "%windir%\\system32\\amsi.dll"))))')

splunk_query = ('TargetObject="*\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\InProcServer32\\ \
                (Default)" NOT Details="%windir%\\system32\\amsi.dll"')

@pytest.mark.parametrize("siem_name, result, expect_exception", [
    ("xql", xql_query, False),
    ("splunk", splunk_query, False),
    ("bad_siem", "Unknown SIEM - bad_siem", True)
])
@patch.object(demisto, 'executeCommand')
@patch.object(sigma_button, 'return_error')
def test_sigma_button(mock_return_error, mock_executeCommand, siem_name, backend, result, expect_exception):
    
    mock_executeCommand.side_effect = {'args': {'indicator': {'CustomFields': {'sigmaruleraw': rule_example}}, "SIEM": siem_name}}

    if expect_exception:
        mock_return_error.side_effect = Exception(result)
        with pytest.raises(Exception, match=result):
            sigma_button()
    
    else:
        query = sigma_button()
        assert query == result
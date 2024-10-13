# import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# from typing import Dict, Any
import pandas as pd
from io import BytesIO
''' STANDALONE FUNCTION '''

def list_custom_details(alert_rule: dict) -> Union[dict[str, str], list]:
    """Returns a dict containing rule_id, name, sentinel_field, xsoar_type, and xsoar_field
    :type ret: ``dict``
    :return: dict as {}
    :rtype: ``dict``
    """
    rule_id: str = alert_rule.get("name","")
    rule_name: str = alert_rule.get("properties",{}).get("displayName", "NoName")
    cust_details: dict = alert_rule.get("properties",{}).get("customDetails", {})
    sentinel_fields = cust_details.keys()
    new_rule = [{
                "RuleID": rule_id, "RuleName": rule_name, "XSOARType": "Empty", "XSOARField": "" ,"SentinelField": k
                }
                for k in sentinel_fields]
    ret = new_rule

    return ret

def dict_to_excel_pandas(data):
    # Convert the dictionary to a DataFrame
    df = pd.DataFrame(data)
    
    # Create a BytesIO object to store the Excel file
    excel_file = BytesIO()
    
    # Use ExcelWriter to save the DataFrame to the BytesIO object
    with pd.ExcelWriter(excel_file, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='CustomDetails')
    
    # Move the cursor to the beginning of the BytesIO object
    excel_file.seek(0)
    
    return excel_file.getvalue()

def convert_dict_to_excel_and_return(alert_rules_list, filename):
    excel_data = dict_to_excel_pandas(alert_rules_list)
    return fileResult(filename, excel_data, file_type=EntryType.ENTRY_INFO_FILE)


''' COMMAND FUNCTION '''


def list_custom_details_command(args: dict[str, Any]) -> CommandResults:
    # command: str = "azure-sentinel-list-alert-rule"
    # command_args: dict = {
    #     "limit": 200
    # }
    
    # command_results: Any = execute_command(command, command_args, extract_contents=True, fail_on_error=True)
    ctxt = demisto.context()
    command_results = ctxt.get("AzureSentinel",{}).get("AlertRule")
    alert_rules = [list_custom_details(v) for v in command_results]
    result = [rule_pair for rule_set in alert_rules for rule_pair in rule_set]
    # return_results(convert_dict_to_excel_and_return(result,"CustomDetailsMapping.xlsx"))

    return CommandResults(
        outputs_prefix='AzureSentinelListCustomDetails',
        outputs_key_field='',
        outputs=result,
        raw_response=alert_rules,
        readable_output=json.dumps(result, indent=4)
    )

''' MAIN FUNCTION '''

def main():
    try:
        return_results(list_custom_details_command(demisto.args()))
    except Exception as ex:

        return_error(f'Failed to execute AzureSentinelListCustomDetails. Error: {str(ex)}')

''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

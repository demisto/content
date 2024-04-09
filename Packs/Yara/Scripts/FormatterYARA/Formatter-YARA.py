import demistomock as demisto
from CommonServerPython import *  # lgtm [py/polluting-import]

def main():
    try:
        the_input = demisto.args().get('input')

        # argToList returns the argument as is if it's already a list so no need to check here
        the_input = argToList(the_input)
        entries_list = []
        rule_name_regex = re.compile(r'\brule\s+(?P<name>\w+?)\s')
        
        # Otherwise assumes it's already an array
        for item in the_input:
            rule_name = rule_name_regex.search(item)

            if item and rule_name:
                rule_name = rule_name.group("name")
                input_entry = {
                    "Type": entryTypes["note"],
                    "ContentsFormat": formats["json"],
                    "Contents": [rule_name],
                    "EntryContext": {"YARA": rule_name}
                }
                
            else:
                input_entry = ''
            
            entries_list.append(input_entry)
        
        if entries_list:
            demisto.results(entries_list)
        
        else:
            # Return empty string so it wouldn't create an empty domain indicator.
            demisto.results('')

    except Exception as e:
        return_error(
            f'Failed to execute the automation. Error: \n{str(e)}'
        )


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

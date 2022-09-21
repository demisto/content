import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def main():
    # args = demisto.args()
    # entry_id = args.get("entry_id", "")
    # if not entry_id:
    #     return_error(f"Could not find file for entry id {entry_id}.")
    # comm_output = demisto.executeCommand("StixParserV2", {"entry_id": entry_id})
    # indicators = comm_output[0].get("Contents")
    # if is_error(comm_output[0]):
    #     return_error(indicators)
    # errors = list()
    # for indicator in indicators:
    #     res = demisto.executeCommand("createNewIndicator", indicator)
    #     if is_error(res[0]):
    #         errors.append(f'Error creating indicator - {(res[0]["Contents"])}')
    # return_outputs(
    #     f"Create Indicators From STIX: {len(indicators) - len(errors)} indicators were created."
    # )
    # if errors:
    #     return_error(json.dumps(errors, indent=4))

    n = '18'
    entity_relationship = EntityRelationship(name='indicated-by',
                                             entity_a=f"http://darya{n}.com/",
                                             entity_a_type="URL",
                                             entity_b="Darya55",
                                             entity_b_type="Malware")

    body_request = {'relationship': entity_relationship.to_indicator()}
    res = demisto.internalHttpRequest(
        'POST', uri='/relationship/indicators/manual/create', body=json.dumps(body_request)
    )
    return_outputs(res)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

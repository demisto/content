from CommonServerPython import *


def get_scan_info(entity: str):
    return demisto.executeCommand(
        "checkpointhec-get-scan-info",
        {'entity': entity}
    )


def main():  # pragma: no cover
    try:
        custom_fields = demisto.incident()['CustomFields']
        result = get_scan_info(custom_fields['checkpointhecentity'])
        scan_info = result[0]['Contents']
        for k, v in scan_info.items():
            scan_info[k] = json.loads(v)

        return_results({
            'ContentsFormat': EntryFormat.JSON,
            'Type': EntryType.NOTE,
            'Contents': json.dumps(scan_info)
        })
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

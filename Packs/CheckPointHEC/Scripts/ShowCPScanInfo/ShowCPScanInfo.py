from CommonServerPython import *

SCAN_INFO_FIELD = 'checkpointhecscaninfo'


def get_scan_info(entity: str) -> str:
    scan_info = demisto.executeCommand(
        "checkpointhec-get-scan-info",
        {'entity': entity}
    )[0]['Contents']

    for k, v in scan_info.items():
        scan_info[k] = json.loads(v)

    return json.dumps(scan_info)


def main():  # pragma: no cover
    try:
        custom_fields = demisto.incident()['CustomFields']
        if not (scan_info := custom_fields.get(SCAN_INFO_FIELD)):
            entity = custom_fields.get('checkpointhecentity')
            scan_info = get_scan_info(entity)
            demisto.executeCommand(
                "setIncident",
                {
                    'customFields': json.dumps({
                        SCAN_INFO_FIELD: scan_info,
                    })
                }
            )

        return_results({
            'ContentsFormat': EntryFormat.JSON,
            'Type': EntryType.NOTE,
            'Contents': scan_info
        })
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

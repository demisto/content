from CommonServerPython import *

SCAN_INFO_FIELD = 'checkpointhecscaninfo'


def get_scan_info(entity: str, instance: str) -> tuple[bool, str]:
    scan_info = demisto.executeCommand(
        "checkpointhec-get-scan-info",
        {'entity': entity, 'using': instance}
    )[0]['Contents']

    if isinstance(scan_info, str):
        return False, scan_info

    for k, v in scan_info.items():
        scan_info[k] = json.loads(v)

    return True, json.dumps(scan_info)


def main():  # pragma: no cover
    try:
        incident = demisto.incident()
        instance = incident['sourceInstance']
        custom_fields = incident['CustomFields']
        if not (scan_info := custom_fields.get(SCAN_INFO_FIELD)):
            entity = custom_fields.get('checkpointhecentity')
            success, scan_info = get_scan_info(entity, instance)
            if not success:
                raise Exception(scan_info)

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

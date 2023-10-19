from CommonServerPython import *


def get_email_info(entity: str):
    result = demisto.executeCommand(
        "checkpointhec-get-email-info",
        {'entity': entity}
    )
    email_info = result[0]['Contents']
    demisto.executeCommand(
        "setIncident",
        {
            'customFields': json.dumps({
                'checkpointhecemailsender': email_info['fromEmail'],
                'checkpointhecemailsubject': email_info['subject']
            })
        }
    )
    return result


def dict_to_md(info: dict) -> str:
    lines = ['|field|value|', '|-|-|']
    for key, value in info.items():
        if value:
            _value = ', '.join(value) if isinstance(value, list) else value
            lines.append(f'|{key}|{_value}|')
    return '\n'.join(lines)


def main():  # pragma: no cover
    try:
        custom_fields = demisto.incident()['CustomFields']
        result = get_email_info(custom_fields['checkpointhecentity'])
        email_info = result[0]['Contents']
        return_results({
            'ContentsFormat': EntryFormat.MARKDOWN,
            'Type': EntryType.NOTE,
            'Contents': dict_to_md(email_info),
        })
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

from CommonServerPython import *

EMAIL_INFO_FIELD = 'checkpointhecemailinfo'
FIELDS_TO_SHOW = {
    'fromEmail',
    'to',
    'replyToEmail',
    'replyToNickname',
    'recipients',
    'subject',
    'cc',
    'bcc',
    'isRead',
    'received',
    'isDeleted',
    'isIncoming',
    'isOutgoing',
    'internetMessageId',
    'isUserExposed',
    'emailLinks',
}


def dict_to_md(info: dict) -> str:
    lines = ['|field|value|', '|-|-|']
    for key, value in info.items():
        if key in FIELDS_TO_SHOW and value not in (None, []):
            _value = ', '.join(value) if isinstance(value, list) else value
            lines.append(f'|{key}|{_value}|')
    return '\n'.join(lines)


def get_email_info(entity: str, instance: str) -> tuple[bool, str]:
    email_info = demisto.executeCommand(
        "checkpointhec-get-entity",
        {'entity': entity, 'using': instance}
    )[0]['Contents']

    if isinstance(email_info, str):
        return False, email_info

    return True, dict_to_md(email_info)


def main():  # pragma: no cover
    try:
        incident = demisto.incident()
        instance = incident['sourceInstance']
        custom_fields = incident['CustomFields']
        if not (email_info := custom_fields.get(EMAIL_INFO_FIELD)):
            entity = custom_fields.get('checkpointhecentity')
            success, email_info = get_email_info(entity, instance)
            if not success:
                raise Exception(email_info)

            demisto.executeCommand(
                "setIncident",
                {
                    'customFields': json.dumps({
                        EMAIL_INFO_FIELD: email_info,
                    })
                }
            )

        return_results({
            'ContentsFormat': EntryFormat.MARKDOWN,
            'Type': EntryType.NOTE,
            'Contents': email_info,
        })
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def convert_to_table():
    incident = demisto.incident()
    comments = []
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident "
                         "from context but returned None")
    demisto.debug(f'ibm_convert_comments_to_table {incident=}')
    fields = incident.get('CustomFields', [])
    mirror_tags = incident.get('dbotMirrorTags', [])

    if fields:
        ibm_qradar_notes = fields.get('ibmsecurityqradarsoarnotes', [])

        for data in ibm_qradar_notes:
            parsed_data = json.loads(data)
            comment_entry = {
                'ID': parsed_data.get('id', ''),
                'Comment': parsed_data.get('text', {}).get('content', ''),
                'Created at': parsed_data.get('create_date', ''),
                'Created by': parsed_data.get('created_by', ''),
                'tags': []}
            # Extract mirror tags from message content
            for tag in mirror_tags:
                if tag in comment_entry['Comment']:
                    comment_entry['Comment'] = comment_entry['Comment'].replace(tag, '').strip()
                    comment_entry['tags'].append(tag)

            comments.append(comment_entry)
    if not comments:
        return CommandResults(readable_output='No comments were found in the notable')
    demisto.debug(f"ibm_convert_comments_to_table {comments=}")
    markdown = tableToMarkdown("", comments, sort_headers=False)
    return CommandResults(
        readable_output=markdown
    )


def main():
    try:
        return_results(convert_to_table())
    except Exception as e:
        return_error(f'Got an error while parsing: {e}', error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

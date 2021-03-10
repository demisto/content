from CommonServerPython import *
import demistomock as demisto


def assigned_synced_apps(args) -> CommandResults:
    indicator = args['indicator']
    assigned_synced_apps = indicator.get('CustomFields', {}).get('oktasyncedapps', [])

    assigned_apps = json.loads(assigned_synced_apps)

    content = []

    for item in assigned_apps:
        content.append({
            'App Name': item.get('Name', ''),
            'App ID': item.get('ID', ''),
            'App Label': item.get('Label')
        })

    output = tableToMarkdown('', content, ['App Name', 'App Label', 'App ID'], removeNull=True)
    return CommandResults(readable_output=output)


def main(args):
    try:
        return_results(assigned_synced_apps(args))
    except Exception as e:
        return_error(f'Failed to execute Widget. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main(demisto.args())

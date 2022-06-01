"""
Aggregating results into a single file
"""
from CommonServerPython import *


def find_entry_id_by_name(doc_file_name: str) -> str:
    context = demisto.context()
    file_context = context.get('File', {})
    if not file_context:
        return ''
    if isinstance(file_context, dict) and file_context['Name'] == doc_file_name:
        return file_context['EntryID']
    # List of files
    for file_obj in file_context:
        if file_obj['Name'] == doc_file_name:
            return file_obj['EntryID']
    return ''


def main():
    try:
        args = demisto.args()
        changed_succeeded = argToList(args.get('succeeded_changed_params'))
        file_names = argToList(args.get('file_names'))
        execute_command_errors = argToList(args.get('execute_command_errors'))
        configuration = args['configuration']
        if not isinstance(configuration, dict):
            json.loads(configuration)
        raw_instance = configuration.get('RawInstance')
        brand = raw_instance.get('brand')
        errors = argToList(args.get('errors'))
        instance_name = configuration.get("instance_name")
        doc = f"""\
# Configuration Troubleshooting summary for {brand}.
---
Instance name : {instance_name}

{tableToMarkdown('Configuration Info:', configuration, ['proxy', 'system', 'isFetch', 'dockerImage', 'engine', 'deprecated'])}
{tableToMarkdown('Errors encountered in test-module (Test button)', errors, ['Errors'])}
{tableToMarkdown('Parameters changed resulted in test succeeded', changed_succeeded, ['Changed keys'])}
{tableToMarkdown('Errors encountered in command running:', execute_command_errors, ['Errors'])}
{tableToMarkdown('Files found in the investigation:', file_names, ['File Names'])}
"""
        configuration_name = f'{instance_name}_configuration.md'
        demisto.results(fileResult(
            configuration_name,
            json.dumps(raw_instance, indent=4)
        ))

        doc_file_name = f'{instance_name}_summary.md'
        demisto.results(fileResult(
            doc_file_name,
            doc
        ))
        context = {
            'TroubleshootAggregateResults': {
                'configuration_file_name': configuration_name,
                'summary_file_name': doc_file_name
            }
        }
        return_outputs(doc, context)
    except Exception as exc:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(str(exc))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

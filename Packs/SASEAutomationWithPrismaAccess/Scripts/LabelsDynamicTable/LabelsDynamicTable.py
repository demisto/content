import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def dynamic_table(incident: dict = None):
    if not incident:
        raise ValueError('No incident')

    details_table = tableToMarkdown('Threat Information', incident['labels'])
    return details_table


def main():
    try:
        incident = demisto.incidents()[0]
        details_table = dynamic_table(incident)
        return_outputs(readable_output=details_table)

    except Exception as e:
        return_error(f'Error in creating LabelsDynamicTable: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def find_folder(data: list) -> str:
    for item in data:
        urn = item.get('urn', '')

        if urn:
            urn_parts = urn.split(';')
            folder_entries = [part for part in urn_parts if part.startswith('folder:')]

            if folder_entries:
                last_folder_value = folder_entries[-1].split('folder:')[1]
                return last_folder_value

    return ''


def main():
    try:
        args = demisto.args()
        data_arg = args.get('data', '')
        data: list[dict] = []

        if isinstance(data_arg, dict):
            data.append(data_arg)
        elif isinstance(data_arg, list):
            data.extend(data_arg)

        parsed_value = find_folder(data)
        parsed_data = {'parsed_value': parsed_value}

        command_results = CommandResults(
            outputs_prefix='Veeam.FOLDER',
            outputs=parsed_data
        )
        return_results(command_results)

    except ValueError as e:
        return_error(str(e))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def find_host(data: list) -> str:
    for item in data:
        urn = item.get('urn')

        if urn:
            urn_parts = urn.split(';')
            hostsystem_entry = next((part for part in urn_parts if part.startswith('hostsystem:')), None)

            if hostsystem_entry:
                hostsystem_value = hostsystem_entry.split('hostsystem:')[1]
                return hostsystem_value

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

        parsed_value = find_host(data)
        parsed_data = {'parsed_value': parsed_value}

        command_results = CommandResults(
            outputs_prefix='Veeam.HOST',
            outputs=parsed_data
        )
        return_results(command_results)

    except Exception as e:
        return_error(str(e))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

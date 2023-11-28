import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def is_integration_available(brand_name: str, all_instances: Dict[str, dict]) -> CommandResults:
    brand_instances = [instance_name for instance_name in all_instances
                       if all_instances[instance_name]['brand'].lower() == brand_name.lower()
                       and all_instances[instance_name].get('state', '') == 'active']
    readable_output = 'yes' if brand_instances else 'no'

    return CommandResults(
        outputs_prefix='brandInstances',
        outputs=brand_instances,
        readable_output=readable_output,
        raw_response=readable_output
    )


def main():  # pragma: no cover
    try:
        brand_names = argToList(demisto.args()['brandname'])
        all_instances = demisto.getModules()

        results = []
        for brand_name in brand_names:
            result = is_integration_available(brand_name, all_instances)
            results.append(result)

        return_results(results)

    except Exception as e:
        return_error(
            f'Failed to execute the automation. Error: \n{str(e)}'
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

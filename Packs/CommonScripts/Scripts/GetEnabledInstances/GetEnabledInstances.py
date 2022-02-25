import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_enabled_instances():
    enabled_instances = []
    readable_output = []
    instances = demisto.getModules()
    for instance_name, data in instances.items():
        if data.get('state') == 'active':
            enabled_instances.append(instance_name)
            readable_output.append({
                'Instance Name': instance_name,
                'Brand': data.get('brand')
            })

    return CommandResults(
        outputs_prefix='EnabledInstances',
        outputs=enabled_instances,
        readable_output=tableToMarkdown('Enabled Instances', readable_output),
        raw_response=enabled_instances
    )


def main() -> None:
    return_results(get_enabled_instances())


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

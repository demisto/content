from typing import Dict, Iterator

import demistomock as demisto
from CommonServerPython import *

INTERNAL_MODULES_BRANDS = ['Scripts', 'Builtin', 'testmodule']


def filter_config(module: Dict, filter_brand: Optional[List[str]] = None, instance_status: str = 'active'):
    brand = module.get('brand')
    if brand in INTERNAL_MODULES_BRANDS:
        return False
    elif filter_brand and brand not in filter_brand:
        return False
    elif instance_status != 'both' and module.get('state') != instance_status:
        return False

    return True


def prepare_args(args: Dict):
    if 'brand' in args:
        args['filter_brand'] = argToList(args.pop('brand'))

    if args.get('instance_status') not in ['active', 'both', 'disabled']:
        raise ValueError("instance_status should be one of the following 'active', 'both', 'disabled'")

    return args


def filter_instances(modules: Dict, **kwargs) -> Iterator[Dict]:
    for instance, config in modules.items():
        if filter_config(config, **kwargs):
            config['name'] = instance
            yield config


def main():
    try:
        args = prepare_args(demisto.args())
        context_config = list(filter_instances(demisto.getModules(), **args))
        return_results(CommandResults(
            outputs=context_config,
            outputs_prefix='Modules',
        ))
    except Exception as error:
        return_error(str(error), error)


if __name__ in ['__main__', 'builtins']:
    main()

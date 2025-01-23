import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def prepare_arg_dict(ids_arg_name, ids, additional_arg_names, additional_arg_values, using_instance=''):
    if not isinstance(ids, list):
        ids = [ids]
    for i, val in enumerate(ids):
        ids[i] = str(ids[i])

    args_names = [str(name).strip() for name in argToList(additional_arg_names)]
    args_values = [str(value).strip() for value in argToList(additional_arg_values)]

    if len(args_names) != len(args_values):
        raise ValueError('arg names and arg values lists does not match, please check your inputs:\n'
                         f'arg names ({len(args_names)}): {args_names}\narg values ({len(args_values)}): {args_values}'
                         )

    args = dict(zip(args_names, args_values))
    args[ids_arg_name] = ','.join(argToList(ids))
    if using_instance:
        args['using'] = str(using_instance)

    return args


def main(args):     # pragma: no cover
    try:
        encoded_id = args.get('ids')

        additional_polling_command_arg_names = args.get('additionalPollingCommandArgNames')

        additional_polling_command_arg_values = args.get('additionalPollingCommandArgValues')

        using = args.get('using', '')
        using_instance = using

        args = prepare_arg_dict(args.get('pollingCommandArgName'),
                                encoded_id,
                                additional_polling_command_arg_names,
                                additional_polling_command_arg_values,
                                using_instance
                                )

        demisto.results(demisto.executeCommand(demisto.getArg('pollingCommand'), args))
    except Exception as exp:
        return_error(f'An error occurred: {exp}', error=exp)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main(demisto.args())

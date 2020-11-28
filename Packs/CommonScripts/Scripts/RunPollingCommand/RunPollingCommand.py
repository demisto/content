import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def prepare_arg_dict(ids_arg_name, ids, additional_arg_names, additional_arg_values):
    if not isinstance(ids, list):
        ids = [ids]
    for i, val in enumerate(ids):
        ids[i] = str(ids[i])

    args_names = [name.strip() for name in argToList(additional_arg_names)]
    args_values = [value.strip() for value in argToList(additional_arg_values)]

    if len(args_names) != len(args_values):
        raise ValueError('arg names and arg values lists does not match, please check your inputs:\n'
                         'arg names ({}): {}\narg values ({}): {}'.format(len(args_names), args_names,
                                                                          len(args_values), args_values)
                         )

    args = dict(zip(args_names, args_values))
    args[ids_arg_name] = ','.join(argToList(ids))

    return args


def main(args):
    try:
        encoded_id = args.get('ids').encode('utf-8') if type(args.get('ids')) != int else args.get('ids')
        args = prepare_arg_dict(args.get('pollingCommandArgName'),
                                encoded_id,
                                args.get('additionalPollingCommandArgNames'),
                                args.get('additionalPollingCommandArgValues'),
                                )

        demisto.results(demisto.executeCommand(demisto.getArg('pollingCommand'), args))
    except Exception as exp:
        return_error('An error occurred: {}'.format(exp), error=exp)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main(demisto.args())

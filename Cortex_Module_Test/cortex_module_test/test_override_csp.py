import json

STRING_TYPES = (str, bytes)


try:
     # Try to access the global demisto object provided at runtime
    import builtins
    if hasattr(builtins, 'demisto'):
        demisto = builtins.demisto # reference the global runtime demisto
    else:
        import demistomock as demisto  # fallback for testing
except Exception:
    demisto = None
    

def arg_to_number(arg, arg_name=None, required=False):
    
    demisto.info("In arg_to_number from cortex module test! - testing demisto info")
    demisto.debug("In arg_to_number from cortex module test! - testing demisto debug")

    return "In arg_to_number from cortex module test!"

def argToBoolean(value):
    
    demisto.debug("In argToBoolean from cortex module test! - testing log")
    
    return "In argToBoolean from cortex module test!"

def is_integration_command_execution():
    """
    This function determines whether the current execution a script execution or a integration command execution.

    :return: Is the current execution a script execution or a integration command execution.
    :rtype: ``bool``
    """

    try:
        return demisto.callingContext['context']['ExecutedCommands'][0]['moduleBrand'] != 'Scripts'
    except (KeyError, IndexError, TypeError):
        try:
            # In dynamic-section scripts ExecutedCommands is None and another way is needed to verify if we are in a Script.
            return demisto.callingContext['context']['ScriptName'] == ''
        except (KeyError, IndexError, TypeError):
            return True

def argToList(arg, separator=',', transform=None):
    """
       Converts a string representation of args to a python list

       :type arg: ``str`` or ``list``
       :param arg: Args to be converted (required)

       :type separator: ``str``
       :param separator: A string separator to separate the strings, the default is a comma.

       :type transform: ``callable``
       :param transform: A function transformer to transfer the returned list arguments.

       :return: A python list of args
       :rtype: ``list``
    """
    if not arg:
        return []

    result = []
    if isinstance(arg, list):
        result = arg
    elif isinstance(arg, STRING_TYPES):
        is_comma_separated = True
        if arg[0] == '[' and arg[-1] == ']':
            try:
                result = json.loads(arg)
                is_comma_separated = False
            except Exception:
                demisto.debug('Failed to load {} as JSON, trying to split'.format(arg))  # type: ignore[str-bytes-safe]
        if is_comma_separated:
            result = [s.strip() for s in arg.split(separator)]
    else:
        result = [arg]

    if transform:
        return [transform(s) for s in result]

    return result
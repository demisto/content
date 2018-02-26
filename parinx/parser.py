#!/usr/bin/env python

import inspect
from collections import defaultdict
from itertools import takewhile
import re
import sys

from parinx.utils import LastUpdatedOrderedDict
from parinx.errors import MethodParsingException

if sys.version_info >= (3,):
    def iteritems(val):
        return val.items()
else:
    def iteritems(val):
        return val.iteritems()

# map between request header name and libcloud's attribute name
XHEADERS_TO_ARGS_DICT = {
    'x-auth-user': 'key',
    'x-api-key': 'secret',
    'x-provider-path': 'path',
    'x-provider-port': 'port',
    'x-provider-host': 'host',
    'x-dummy-creds': 'creds',  # FIXME: for tests only
    'x-provider-key': 'key',
    'x-provider-uri': 'uri',
    'x-provider-api-version': 'api_version',
    'x-provider-secure': 'secure',
    'x-provider-datacenter': 'datacenter',
}

#FIXME: GK?
ARGS_TO_XHEADERS_DICT = dict(
    ([k, v] for v, k in XHEADERS_TO_ARGS_DICT.items()))

_SUPPORTED_FIELDS = set([
    ':param',
    ':type',
    ':keyword',
    ':rtype:',
    '@inherits:',
    ':return:',
])


def parse_request_headers(headers):
    """
    convert headers in human readable format

    :param headers:
    :return:
    """
    request_header_keys = set(headers.keys(lower=True))
    request_meta_keys = set(XHEADERS_TO_ARGS_DICT.keys())
    data_header_keys = request_header_keys.intersection(request_meta_keys)
    return dict(([XHEADERS_TO_ARGS_DICT[key],
                  headers.get(key, None)] for key in data_header_keys))


def _ignored_field(field_str):
    return not field_str.split(None, 1)[0] in _SUPPORTED_FIELDS


def _parse_docstring_field(cls, field_lines):
    """

    :param field_string:
    :type field_string:
    :return: return pair:
        argument name, dict of updates for argument info
    :rtype: ``dict``
    """

    match_name = __get_class_name(cls)

    if field_lines.startswith(':type'):
        field_data = field_lines.split(None, 2)
        arg_name = field_data[1].strip(':')
        arg_type = field_data[2].replace('\n', '').strip(':').strip()
        if arg_type.startswith('class:`.'):
            arg_type = arg_type.replace('class:`.', 'class:`'+match_name+'.')
        return arg_name, {'type_name': arg_type}
    if field_lines.startswith(
            ':keyword') or field_lines.startswith(':param'):
        field_data = field_lines.split(None, 2)
        arg_name = field_data[1].strip(':')
        arg_description = field_data[2].strip()
        return arg_name, {'description': arg_description,
                          'required': '(required)' in arg_description}


def _find_parent_cls(cls, cls_name):
    if cls.__name__ == cls_name:
        return cls
    for base_cls in cls.__bases__:
        res = _find_parent_cls(base_cls, cls_name)
        if res is not None:
            return res
    return None


def _parse_inherit(cls, inherits):
    pattern = r"\`(?P<cls_name>[_0-9a-zA-Z]+).(?P<method_name>"
    pattern += "[_0-9a-zA-Z]+)\`"
    m = re.match(pattern, inherits.strip())
    cls_name = m.group('cls_name')
    method_name = m.group('method_name')
    parent_cls = _find_parent_cls(cls, cls_name)
    docstring = get_method_docstring(parent_cls, method_name)
    return parse_docstring(docstring, parent_cls)


def _check_arguments_dict(arguments):
    for argument, info in iteritems(arguments):
        if info['type_name'] is None:
            raise MethodParsingException(
                'Can not get type for argument %s' % (argument))
        if info['description'] is None:
            raise MethodParsingException(
                'Can not get description for argument %s' % (argument))


def split_docstring(docstring):
    """
    Separates the method's description and paramter's

    :return: Return description string and list of fields strings
    """
    docstring_list = [line.strip() for line in docstring.splitlines()]
    description_list = list(
        takewhile(lambda line: not (line.startswith(':') or
                                    line.startswith('@inherit')), docstring_list))
    description = ' '.join(description_list).strip()
    first_field_line_number = len(description_list)

    fields = []
    if first_field_line_number >= len(docstring_list):
        return description, fields  # only description, without any field
    last_field_lines = [docstring_list[first_field_line_number]]

    for line in docstring_list[first_field_line_number + 1:]:
        if line.strip().startswith(':') or line.strip().startswith('@inherit'):
            fields.append(' '.join(last_field_lines))
            last_field_lines = [line]
        else:
            last_field_lines.append(line)

    fields.append(' '.join(last_field_lines))
    return description, fields


def get_method_docstring(cls, method_name):
    """
    return method  docstring
    if method docstring is empty we get docstring from parent

    :param method:
    :type method:
    :return:
    :rtype:
    """
    method = getattr(cls, method_name, None)
    if method is None:
        return
    docstrign = inspect.getdoc(method)
    if docstrign is None:
        for base in cls.__bases__:
            docstrign = get_method_docstring(base, method_name)
            if docstrign:
                return docstrign
        else:
            return None

    return docstrign


def parse_args(method):
    args, varargs, varkw, argspec_defaults = inspect.getargspec(method)
    if inspect.ismethod(method):
        args.pop(0)
    defaults = LastUpdatedOrderedDict()
    if argspec_defaults is not None:
        defaults = dict(zip(reversed(args), reversed(argspec_defaults)))
    args_dict = LastUpdatedOrderedDict()
    for arg in args:
        if arg in defaults:
            args_dict[arg] = {
                'required': False,
                'default': defaults[arg]
            }
        else:
            args_dict[arg] = {'required': True, }
    return args_dict


def __get_class_name(cls):
    if not cls:
        return
    pattern = r"\<class (?P<cls_name>(.*?))\>"
    cls_match = re.match(pattern, str(cls))
    match_name = cls_match.group('cls_name').replace("'", "")
    return match_name


def parse_docstring(docstring, cls=None):
    """
    :return: return dict
        description - method description
        arguments - dict of dicts arg_name: {description, type_name, required}
        return - dict: {description, type}
    """
    def_arg_dict = lambda: {'description': None,
                            'type_name': None,
                            'required': False,
                            }
    description, fields_lines = split_docstring(docstring)
    arguments_dict = defaultdict(def_arg_dict)
    return_value_types = []
    #parse fields
    return_description = ''
    for docstring_line in fields_lines:
        if _ignored_field(docstring_line):
            continue
        #parse inherits
        if docstring_line.startswith('@inherits'):
            if not cls:
                raise MethodParsingException()
            inherit_tmp = docstring_line.split(None, 1)[1]
            inherit_str = inherit_tmp.split(':class:', 1)[1]
            result = _parse_inherit(cls, inherit_str)

            description = description or result['description']
            for arg_name, update_dict in result['arguments'].items():
                arguments_dict[arg_name].update(update_dict)
            return_value_types = result['return']['type_name']
            return_description = result['return']['description']
        #parse return value
        elif docstring_line.startswith(':rtype:'):
            class_name = __get_class_name(cls)
            types_str = docstring_line.split(None, 1)[1]
            return_value_types = types_str.replace('\n', '').strip(':').strip()
            if return_value_types.startswith('class:`.'):
                return_value_types = return_value_types.replace('class:`.', 'class:`'+class_name+'.')
        #parse return description
        elif docstring_line.startswith(':return:'):
            return_description = docstring_line.split(None, 1)[1].strip()
        #parse arguments
        else:
            arg_name, update_dict = _parse_docstring_field(cls, docstring_line)
            arguments_dict[arg_name].update(update_dict)
    #check fields
    _check_arguments_dict(arguments_dict)
    if not return_value_types:
        raise MethodParsingException('Can not get return types for method')
    return {'description': description,
            'arguments': arguments_dict,
            'return': {'description': return_description,
                       'type_name': return_value_types}}

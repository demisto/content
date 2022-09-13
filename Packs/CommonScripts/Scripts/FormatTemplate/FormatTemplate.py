from typing import Any, Callable, Dict, Optional, Tuple

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class ContextData:
    def __init__(self,
                 context: Optional[Dict[str, Any]] = None,
                 inputs: Optional[Dict[str, Any]] = None,
                 incident: Optional[Dict[str, Any]] = None):

        self.__context = context
        self.__specials = {
            'inputs': inputs if isinstance(inputs, dict) else {},
            'incident': incident if isinstance(incident, dict) else {}
        }

    def get(self, key: Optional[str] = None) -> Any:
        """ Get the context value

        :param key: The dt expressions (string within ${}).
        :return: The value.
        """
        if not key:
            return None

        dx = self.__context
        for prefix in self.__specials.keys():
            if prefix == key or (key.startswith(prefix)
                                 and key[len(prefix):len(prefix) + 1] in ('.', '(', '=')):
                dx = self.__specials
                break
        return demisto.dt(dx, key)


class Formatter:
    def __init__(self, start_marker: str, end_marker: str, keep_symbol_to_null: bool):
        if not start_marker:
            raise ValueError('start-marker is required.')

        self.__start_marker = start_marker
        self.__end_marker = end_marker
        self.__keep_symbol_to_null = keep_symbol_to_null

    @staticmethod
    def __is_end_mark(source: str, ci: int, end_marker: str) -> bool:
        if end_marker:
            return source[ci:ci + len(end_marker)] == end_marker
        else:
            c = source[ci]
            if c.isspace():
                return True
            elif c.isascii():
                return c != '_' and not c.isalnum()
            else:
                return False

    def __extract(self,
                  source: str,
                  extractor: Optional[Callable[[str,
                                                Optional[ContextData]],
                                               Any]],
                  dx: Optional[ContextData],
                  si: int,
                  end_marker: Optional[str]) -> Tuple[Any, Optional[int]]:
        """ Extract a template text, or a string within a DT syntax

        :param source: The template text, or the string starts with the next charactor of a start marker
        :param extractor: The function to extract a DT value
        :param dx: The context data
        :param si: The index of `source` to start extracting
        :param end_marker: The end marker to parse a string within a DT. It must be None when the template text is given to `source`.
        :return: The extracted value and index of `source` when parsing ended.
        """
        out = None
        ci = si
        while ci < len(source):
            if end_marker is not None and Formatter.__is_end_mark(source, ci, end_marker):
                key = source[si:ci] if out is None else str(out) + source[si:ci]
                xval = ''
                if extractor:
                    xval = extractor(key, dx)
                    if self.__keep_symbol_to_null and xval is None:
                        xval = self.__start_marker + key + self.__end_marker
                return xval, ci + len(end_marker)
            else:
                if extractor and source[ci:ci + len(self.__start_marker)] == self.__start_marker:
                    xval, ei = self.__extract(source, extractor, dx,
                                              ci + len(self.__start_marker), self.__end_marker)
                    if si != ci:
                        out = source[si:ci] if out is None else str(out) + source[si:ci]

                    if ei is None:
                        xval = self.__start_marker
                        ei = ci + len(self.__start_marker)

                    if out is None:
                        out = xval
                    elif xval is not None:
                        out = str(out) + str(xval)
                    si = ci = ei
                else:
                    nextec = {'(': ')', '{': '}', '[': ']', '"': '"', "'": "'"}.get(source[ci])
                    if nextec:
                        _, ei = self.__extract(source, None, dx, ci + 1, nextec)
                        ci = ci + 1 if ei is None else ei
                    elif source[ci] == '\\':
                        ci += 2
                    else:
                        ci += 1

        if end_marker is not None:
            # unbalanced braces, brackets, quotes, etc.
            return None, None
        elif not extractor:
            return None, ci
        elif si >= len(source):
            return out, ci
        elif out is None:
            return source[si:], ci
        else:
            return str(out) + source[si:], ci

    def build(self,
              template: Any,
              extractor: Callable[[str,
                                   Optional[ContextData]],
                                  Optional[Dict[str, Any]]],
              dx: Optional[ContextData]) -> Any:
        """ Format a text from a template including DT expressions

        :param template: The template.
        :param extractor: The extractor to get real value within ${dt}.
        :param dx: The context instance.
        :return: The text built from the template.
        """
        if isinstance(template, dict):
            return {
                self.build(k, extractor, dx): self.build(v, extractor, dx)
                for k, v in template.items()}
        elif isinstance(template, list):
            return [self.build(v, extractor, dx) for v in template]
        elif isinstance(template, str):
            return self.__extract(template, extractor, dx, 0, None)[0] if template else ''
        else:
            return template


def extract_dt(dtstr: str, dx: Optional[ContextData]) -> Any:
    """ Extract dt expression

    :param dtstr: The dt expressions (string within ${}).
    :param dx: The context instance.
    :return: The value extracted.
    """
    try:
        return dx.get(dtstr) if dx else dtstr
    except Exception:
        return None


def main():
    args = demisto.args()
    try:
        template = args.get('value')
        variable_markers = argToList(args.get('variable_markers') or '${,}')
        if not variable_markers or not variable_markers[0]:
            raise ValueError('variable_markers must have a start marker.')
        elif len(variable_markers) >= 3:
            raise ValueError('too many values for variable_markers.')
        elif len(variable_markers) == 1:
            variable_markers = variable_markers + ['']

        dx = args.get('ctx_demisto')
        if dx and isinstance(dx, str):
            dx = json.loads(dx)

        dx = ContextData(
            context=dx,
            inputs=args.get('ctx_inputs'),
            incident=args.get('ctx_incident'))

        formatter = Formatter(
            variable_markers[0],
            variable_markers[1],
            argToBoolean(args.get('keep_symbol_to_null') or False))
        output = formatter.build(template, extract_dt, dx)
    except Exception as err:
        # Don't return an error by return_error() as this is transformer.
        raise DemistoException(str(err))

    return_results(output)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

import re
from typing import List

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def concat_values(item1: Any, item2: Any) -> List[Any]:
    """
    Concatinate item1 and item2 into a list

    :param item1: The leading values to be concatinated.
    :param item2: The values to add to item1.
    :return: The result in list.
    """
    item1 = item1 or []
    item1 = item1 if isinstance(item1, list) else [item1]
    item2 = item2 or []
    item2 = item2 if isinstance(item2, list) else [item2]
    return item1 + item2


def expand_template(match: re.Match, template: Any) -> Any:
    """
    Return the string obtained by doing backslash substitution on the template.

    :param match: The match object.
    :param template: The template.
    :return: The template replaced with backslash substitution symbols.
    """
    if template is None:
        return match.group(0)
    elif isinstance(template, str):
        return match.expand(template.replace(r'\0', r'\g<0>'))
    elif isinstance(template, list):
        return [expand_template(match, t) for t in template]
    elif isinstance(template, dict):
        return {expand_template(match, k): expand_template(match, v) for k, v in template.items()}
    else:
        return template


def main():
    args = demisto.args()
    template = args.get('template')
    template_type = args.get('template_type') or ''
    if template_type == 'text':
        pass
    elif template_type == 'json':
        template = json.loads(template)
    elif template_type == 'list':
        template = argToList(template)
    else:
        raise ValueError(f'Unknown template type: {template_type}')

    regex_flags = 0
    for flag in argToList(args.get('flags')):
        if flag in ('dotall', 's'):
            regex_flags |= re.DOTALL
        elif flag in ('multiline', 'm'):
            regex_flags |= re.MULTILINE
        elif flag in ('ignorecase', 'i'):
            regex_flags |= re.IGNORECASE
        elif flag in ('unicode', 'u'):
            regex_flags |= re.UNICODE
        else:
            raise ValueError(f'Unknown flag: {flag}')

    search_limit = int(args.get('search_limit') or 0)
    if search_limit < 0:
        raise ValueError(f'Bad search limit: {search_limit}')

    results: List[Any] = []
    value_takes = args.get('value_takes') or 'text'
    if value_takes == 'text':
        # Pattern matching for each text in the input order
        regex_list = concat_values(args.get('regex'), [])
        text_list = concat_values(args.get('value'), args.get('text'))

        regexes = [re.compile(str(r), flags=regex_flags) for r in regex_list if isinstance(r, (str, int))]
        for text in text_list:
            for regex in regexes:
                for i, match in enumerate(re.finditer(regex, str(text)), start=1):
                    results = concat_values(results, expand_template(match, template))
                    if search_limit != 0 and search_limit <= i:
                        break

    elif value_takes == 'regex':
        # Pattern matching for each regex in the input order
        regex_list = concat_values(args.get('value'), args.get('regex'))
        text_list = concat_values(args.get('text'), [])

        for regex_pattern in regex_list:
            if isinstance(regex_pattern, (str, int)):
                regex = re.compile(str(regex_pattern), flags=regex_flags)
                for text in text_list:
                    for i, match in enumerate(re.finditer(regex, str(text)), start=1):
                        results = concat_values(results, expand_template(match, template))
                        if search_limit != 0 and search_limit <= i:
                            break
    else:
        raise ValueError(f'Unknown value_takes: {value_takes}')

    demisto.results(results)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

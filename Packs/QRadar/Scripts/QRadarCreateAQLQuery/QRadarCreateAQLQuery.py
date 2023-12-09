import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from enum import Enum
from typing import Dict, List


REPLACE_KEYS = [
    ('base_values_to_search', 'base_additional_values'),
    ('base_fields_to_search', 'base_additional_fields'),
    ('base_field_state', 'base_additional_field_state'),
    ('base_field_match', 'base_additional_field_match')
]


class SectionNotFound(Exception):
    pass


class Operators(Enum):
    OR = 'OR'
    AND = 'AND'


class MatchRule(Enum):
    EQUAL = "{} = '{}'"
    NOT_EQUAL = "{} != '{}'"
    ILIKE = "{} ILIKE '%{}%'"
    NOT_ILIKE = "{} NOT ILIKE '%{}%'"


def fields_section(fields_list: List[str], values_list: List[str], operator: Operators = Operators.OR,
                   match_rule: MatchRule = MatchRule.EQUAL) -> str:
    condition_list: List[str] = []
    for field in map(lambda x: x if ' ' not in x else f"'{x}'", fields_list):
        for value in values_list:
            condition_list.append(match_rule.value.format(field, value))

    return f"({f' {operator.value} '.join(condition_list)})"


def complete_query(select_fields: str, combined_sections: str, time_frame: str) -> str:
    return f"select {select_fields} from events where {combined_sections} {time_frame}"


def prepare_section(args: Dict, section_prefix: str) -> Dict:
    try:
        values_list = argToList(args[f'{section_prefix}_additional_values'])
    except KeyError:
        raise SectionNotFound(section_prefix)
    fields_list = args.get(f'{section_prefix}_additional_fields')
    if args[f'{section_prefix}_additional_field_match'] == 'partial':
        if args[f'{section_prefix}_additional_field_state'] == 'include':
            match_rule = MatchRule.ILIKE
        else:
            match_rule = MatchRule.NOT_ILIKE
        fields_list = fields_list or ['UTF8(payload)']
    else:
        if not fields_list:
            raise KeyError(f'{section_prefix}_additional_fields')
        if args[f'{section_prefix}_additional_field_state'] == 'include':
            match_rule = MatchRule.EQUAL
        else:
            match_rule = MatchRule.NOT_EQUAL

    return {
        'values_list': values_list,
        'match_rule': match_rule,
        'fields_list': argToList(fields_list)
    }


def prepare_args(args: Dict) -> Dict:
    for key in list(args):
        if not args[key]:
            args.pop(key)
    for original_key, new_key in REPLACE_KEYS:
        try:
            args[new_key] = args.pop(original_key)
        except KeyError:
            # ignore the key beacuse a part of them are not required and we already handeling the key errors in the main function
            pass
    return args


def original_key_name(key_name) -> str:
    for original_key, new_key in REPLACE_KEYS:
        if key_name == new_key:
            return original_key

    return key_name


def create_sections_str(args: Dict[str, str], operator: Operators = Operators.AND) -> str:
    sections = []
    for section_prefix in ['base', 'first', 'second']:
        try:
            sections.append(fields_section(**prepare_section(args, section_prefix)))
        except SectionNotFound:
            if section_prefix == 'base':
                raise DemistoException('base arguments not given correctly')
    return f' {operator.value} '.join(sections)


def main():
    try:
        args = prepare_args(demisto.args())
        time_frame = args['time_frame']
        select_fields = args['select_fields']
        aql_string = complete_query(
            select_fields=select_fields,
            combined_sections=create_sections_str(args),
            time_frame=time_frame,
        )
        return_results(CommandResults(readable_output=aql_string, outputs={'QRadarQuery': aql_string}))
    except KeyError as key_error:
        key_name = original_key_name(key_error.args[0])
        return_error(f'Missing {key_name}.')
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import plyara
import plyara.utils
import plyara.exceptions


YARA_META_TO_XSOAR = {
    'descr': 'description',
    'description': 'description',
    'author': 'author',
    'authour': 'author',
    'id': 'ruleid',
    'reference': 'rulereference',
    'link': 'rulereference',
}
# TODO - Add creation date as well

RELATIONSHIPS = ["Malware", "CVE", "Attack_Pattern"]


def parse_rules(rules: str, create_relationships: bool = False) -> CommandResults:
    """Parses a YARA rule in its string format into an XSOAR indicator

    Args:
        rules (list[str]): A string of one or more YARA rules

    Returns:
        CommandResults: Results in XSOAR format.
    """

    parser = plyara.Plyara()
    indicators: list[dict] = []
    successfully_created_indicators: int = 0
    relationships = []

    try:
        parsed_rules = parser.parse_string(rules)
        demisto.debug(f'Parsed {len(parsed_rules)} YARA Rules.')

    except plyara.exceptions.ParseError:
        demisto.debug(f'Failed to parse - {rules}')
        raise

    for parsed_rule in parsed_rules:
        indicators.append(build_indicator(parsed_rule))

    for indicator in indicators:
        execute_command('createNewIndicator', indicator)
        successfully_created_indicators += 1
        demisto.debug(f'Created new indicator {indicator["value"]} ({successfully_created_indicators}/len(parsed_rules))')

    if create_relationships:
        for indicator in indicators:
            relationships = build_relationships(indicator)

    readable_output = f'{tblToMd(f"{len(indicators)} new YARA rules created", indicators, ["value", "author", "description"])}'

    # Removing "type" from and MD blocks from context dict
    outputs = [{k: v.replace('```', '') if isinstance(v, str) else v for k, v in d.items() if k != 'type'} for d in indicators]

    return CommandResults(
        outputs_prefix='ImportYARARule',
        outputs_key_field='Rule',
        outputs=outputs,
        readable_output=readable_output,
        relationships=relationships
    )


def build_indicator(rule: dict[str, Any]) -> dict[str, Any]:
    """ Builds the indicator in the correct XSOAR format to be created.

    Args:
        rule (dict[str, Any]): A given YARA rule.

    Returns:
        dict[str, Any]: An XSOAR indicator of type YARA Rule.
    """

    indicator = {
        "value": rule['rule_name'],
        "type": "YARA Rule",
        "rulestrings": [{"index": entry["name"][1:], "string": entry["value"]} for entry in rule["strings"]],
        "rulecondition": ' '.join(rule["condition_terms"]),
        "rawrule": f'```\n{plyara.utils.rebuild_yara_rule(rule)}\n```'
    }

    if 'tags' in rule:
        indicator["tags"] = rule['tags']

    meta: list[Any] = rule.get('metadata', [])

    for key in YARA_META_TO_XSOAR:
        # populate metadata fields

        if value := parse_metadata(meta, key):
            indicator[YARA_META_TO_XSOAR[key]] = value

    return indicator


def parse_metadata(meta: list[dict], key: str) -> str:
    """
    Extracts the value of a YARA rule metadata key

    Args:
        meta (list[dict]): The YARA Rule metadata
        key (str): The metadata key to be extracted

    Returns:
        str: The value of the metadata key
    """

    for item in meta:

        lowered_dict = {key.lower(): value for key, value in item.items()}

        if key in lowered_dict:
            return lowered_dict[key]

    return ''


def build_relationships(indicator: dict) -> list[EntityRelationship]:

    relationships = []
    related_iocs: list[Any] = demisto.executeCommand('extractIndicators', args={"text": indicator["rawrule"]})
    related_iocs = json.loads(related_iocs[0].get('Contents', {}))

    demisto.debug(f'Found the following indicators in the YARA Rule {related_iocs}')

    for indicator_type in RELATIONSHIPS:

        demisto.debug(f'Handling {indicator_type} relationships')

        if indicator_type == 'Malware':
            # Will extract only malware with APTXXX prefix.
            indicators = set(re.findall(r'(?i)apt[-_]?\d{1,2}', indicator["rawrule"]))

        else:
            indicators = related_iocs.get(indicator_type, [])

        for related_indicator in indicators:
            demisto.debug(f'Creating relationship object for {related_indicator}')

            relationships.append(EntityRelationship(entity_a=indicator['value'],
                                                    entity_a_type='YARA Rule',
                                                    entity_b=related_indicator,
                                                    entity_b_type=indicator_type.replace('_', ' '),
                                                    name=EntityRelationship.Relationships.RELATED_TO))

    return relationships


def main():  # pragma: no cover
    try:
        # TODO: replace the invoked command function with yours
        args = demisto.args()

        if args.get('yara_signatures', ''):
            yara_rules: str = args['yara_signatures']

        elif args.get('entry_id', ''):
            file_path = demisto.getFilePath(args['entry_id'])['path']
            with open(file_path) as f:
                yara_rules = f.read()

        else:
            raise Exception('Please provide exactly one input to the script yara_signatures or entry_id.')

        return_results(parse_rules(yara_rules, argToBoolean(args.get("create_relationships"))))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

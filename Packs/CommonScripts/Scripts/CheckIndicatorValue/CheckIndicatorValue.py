import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import urllib.parse
from typing import Any


def exists_indicator(indicator: str) -> bool:
    if contents := execute_command('getIndicator', {'value': indicator}):
        if len(contents) > 0 and contents[0].get('value') in [indicator]:
            return True
    return False


def decode_indicator(indicator: str, encoding: str | None) -> str:
    if not encoding or encoding == 'none':
        return indicator
    elif encoding == 'base64':
        return base64.b64decode(indicator.encode()).decode()
    elif encoding == 'url-encoding':
        return urllib.parse.unquote(indicator)
    else:
        raise DemistoException(f'Unknown encoding mode: {encoding}')


def check_indicators(indicators: List[str], encoding: str) -> List[dict[str, Any]]:
    # Decode and dedup indicators
    pairs = {decode_indicator(encoded_indicator, encoding): encoded_indicator for encoded_indicator in indicators}

    # Check if each indicator exists
    return [{
        'Indicator': indicator,
        'EncodedIndicator': encoded_indicator,
        'Exists': exists_indicator(indicator)
    } for indicator, encoded_indicator in pairs.items()]


def main():
    try:
        args = demisto.args()
        encoding = args.get('encoding') or 'none'
        indicators = argToList(args.get('indicator') or [])

        outputs = check_indicators(indicators, encoding)
        count = sum(1 for ent in outputs if ent.get('Exists'))

        return_results(CommandResults(
            outputs_key_field='Indicator',
            outputs_prefix='CheckIndicatorValue',
            outputs=outputs,
            readable_output=f'{count} indicators exist.',
            raw_response=outputs
        ))
    except Exception as e:
        return_error(f'Failed to execute CheckIndicatorValue. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, Dict, List, Optional


FINAL_VERDICT_VENDOR = 'XSOAR'


def reliability_level(reliability: Optional[str]) -> int:
    if reliability is None:
        return -1

    return {
        DBotScoreReliability.A_PLUS: 6,
        DBotScoreReliability.A: 5,
        DBotScoreReliability.B: 4,
        DBotScoreReliability.C: 3,
        DBotScoreReliability.D: 2,
        DBotScoreReliability.E: 1,
        DBotScoreReliability.F: 0,
    }.get(reliability, -1)


def is_source_reliable(final: Optional[Dict[str, Any]], source: Dict[str, Any]) -> bool:
    if source.get('Vendor') == 'Manual':
        return True

    source_reliability = reliability_level(source.get('Reliability'))
    if source_reliability < 0:
        return False

    if final is None:
        return True

    final_reliability = reliability_level(final.get('Reliability'))
    if source_reliability > final_reliability:
        return True
    elif source_reliability == final_reliability:
        source_score = source.get('Score') or 0
        final_score = final.get('Score') or 0
        if source_score > final_score:
            return True
    return False


def get_final_verdict(sources: List[Dict[str, Any]], indicator_value: str) -> Optional[Dict[str, Any]]:
    """ Get the DBotScore of the final verdict of an indicator from list of source DBotScores

        Vendor = Manual:
         - The most reliable DBotScore

        If DBotScore by Manual is not found:
         - The most reliable DBotScore is decided by 'Reliability'

            If some different DBotScores having the same Reliability are found:
             - The DBotScores having the highest risk are applied for the final verdict.
               (Malicious > Suspicious > Benign > Unknown)

                If there are some different DBotScores filtered by the highest risk:
                 - The DBotScore found at first is applied for the final verdict.

    :param sources: The list of source DBotScore
    :param indicator_value: The indicator value
    :return: The DBotScore of the final verdict.
    """
    final = None
    for source in sources:
        source_indicator = source.get('Indicator')
        if source_indicator == indicator_value and is_source_reliable(final, source):
            final = assign_params(
                Indicator=source_indicator,
                Type=source.get('Type'),
                Score=source.get('Score') or 0,
                Reliability=source.get('Reliability'),
                Vendor=FINAL_VERDICT_VENDOR,
            )
    return final


def main():
    try:
        args = demisto.args()
        indicator_value = args.get('indicator_value')

        final_dbot_store = None
        if source_dbot_scores := demisto.dt(demisto.context(), 'DBotScore(val.Indicator && val.Score)'):
            source_dbot_scores = source_dbot_scores if isinstance(source_dbot_scores, list) else [source_dbot_scores]
            final_dbot_store = get_final_verdict(source_dbot_scores, indicator_value)

        if final_dbot_store:
            return_results(CommandResults(
                outputs_prefix='FinalDBotScore',
                outputs_key_field='Indicator',
                outputs=final_dbot_store,
                readable_output=tblToMd('Final Verdict', final_dbot_store),
                raw_response=final_dbot_store
            ))
        else:
            return_results(f'No DBotScore found for {indicator_value}')

    except Exception as err:
        return_error(f'Failed to execute GetIndicatorDBotScoreFromContext script. Error: {str(err)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import traceback

RELIABILITY = 'C - Fairly reliable'

SCORE_DICT = {
    "UNKNOWN": 0,
    "UNCLASSIFIED": 0,
    "KNOWN": 1,
    "GOODWARE": 1,
    "SUSPICIOUS": 2,
    "MALICIOUS": 3
}


def overall_classification_command(args: Dict[str, Any]) -> CommandResults:
    a1000_classification_report = args.get('a1000_classification_report')
    a1000_full_report = args.get('a1000_full_report')

    if not a1000_classification_report:
        raise ValueError('A1000 classification report not specified')
    if not a1000_full_report:
        raise ValueError('A1000 full report not specified')

    cloud_classification = a1000_classification_report.get('classification')
    if not cloud_classification:
        return_error("There is no classification field in the classification report.")

    cloud_classification = cloud_classification.upper()

    a1000_results = a1000_full_report.get('results')
    a1000_result = a1000_results[0] if a1000_results else {}
    a1000_classification = a1000_result.get('classification', "")
    if not a1000_classification:
        return_error("There is no threat_status field in the A1000 report")

    a1000_classification = a1000_classification.upper()

    if a1000_classification_report.get('sha1') != a1000_result.get('sha1'):
        return CommandResults(readable_output="Hash mismatch!")

    if a1000_classification in ("UNKNOWN", "UNCLASSIFIED"):
        overall_classification = cloud_classification
    else:
        if SCORE_DICT.get(cloud_classification, 0) > SCORE_DICT.get(a1000_classification, 0):
            overall_classification = cloud_classification
        else:
            overall_classification = a1000_classification

    markdown = f"### ReversingLabs A1000 overall classification for sha1: {a1000_classification_report.get('sha1')}:" \
               f"\n **Threat status:** {overall_classification}\n"

    if overall_classification == "UNKNOWN":
        markdown += "**NOTE:** The file is not yet classified because this is the first time TiCloud has seen the" \
                    " file OR the file is still being analyzed. Please check the classification result later."

    d_bot_score = SCORE_DICT.get(overall_classification, 0)

    dbot_score = Common.DBotScore(
        indicator=a1000_classification_report.get('sha1'),
        indicator_type=DBotScoreType.FILE,
        integration_name='ReversingLabs A1000',
        score=d_bot_score,
        malicious_description=overall_classification,
        reliability=RELIABILITY
    )

    common_file = Common.File(
        md5=a1000_classification_report.get('md5'),
        sha1=a1000_classification_report.get('sha1'),
        sha256=a1000_classification_report.get('sha256'),
        dbot_score=dbot_score
    )

    command_results = CommandResults(
        outputs_prefix='ReversingLabs',
        indicator=common_file,
        readable_output=markdown
    )
    return command_results


def main():
    try:
        results = overall_classification_command(demisto.args())
        return_results(results)
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute A1000FinalClassification. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

indicator_types = {
    'IP': "ip",
    'File SHA1': "file",
    'File MD5': "file",
    'File SHA256': "file",
    'Email': "email",
    'URL': "url"
}


def iterate_indicator_entry(indicator, entry):
    indicator_type = entry["indicator_type"]
    indicator_type = indicator_types.get(indicator_type, indicator_type)
    sources = entry.get('sourceBrands', [])
    sources = sources if sources else ['']
    for source in sources:
        dbot_score = Common.DBotScore(indicator=indicator, indicator_type=indicator_type,
                                      integration_name=source, score=entry["score"]).to_context()
        yield CommandResults(
            readable_output=tableToMarkdown('Indicator DBot Score', dbot_score),
            outputs=dbot_score
        )


def main():
    indicator = demisto.args()['indicator']
    resp = demisto.executeCommand("getIndicator", {'value': indicator})

    if isError(resp):
        demisto.results(resp)
        sys.exit(0)

    data = demisto.get(resp[0], "Contents")

    if not data:
        demisto.results("No results.")
        sys.exit(0)
    for entry in data:
        for db_entry in iterate_indicator_entry(indicator, entry):
            return_results(db_entry)


if __name__ in ["builtins", "__main__"]:
    main()

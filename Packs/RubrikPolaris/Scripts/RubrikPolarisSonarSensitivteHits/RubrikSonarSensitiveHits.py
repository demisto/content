# Only needed for local development
import demistomock as demisto
from CommonServerPython import *
import traceback


def main() -> None:
    try:

        sonar_context = demisto.context()["Rubrik"]["Sonar"]

        # TODO - We can be more programmatic here.
        hit_summary = [
            {
                'stat': 'Open Access Folders',
                'result': sonar_context["openAccessFolders"]
            },
            {
                'stat': 'Total Hits',
                'result': sonar_context["totalHits"]
            },
            {
                'stat': 'Stale Hiles',
                'result': sonar_context["staleFiles"]
            },
            {
                'stat': 'Open Access Files',
                'result': sonar_context["openAccessFiles"]
            },
            {
                'stat': 'Open Access Files with Hits',
                'result': sonar_context["openAccessFilesWithHits"]
            },
            {
                'stat': 'Stale Files with Hits',
                'result': sonar_context["staleFilesWithHits"]
            },
            {
                'stat': 'Files with Hits',
                'result': sonar_context["filesWithHits"]
            },
            {
                'stat': 'OpenAccess Stale Files',
                'result': sonar_context["openAccessStaleFiles"]
            },
        ]

        markdown = tableToMarkdown('Hit Summary', hit_summary)

        for policy, analyzer in sonar_context["policy_hits"].items():
            analyzer_details = []

            for a, total_hits in analyzer.items():

                analyzer_details.append(
                    {
                        "analyzer": a,
                        "hits": total_hits
                    }
                )
            markdown += tableToMarkdown(policy, analyzer_details)

        demisto.results({
            "Type": 1,
            "ContentsFormat": formats["markdown"],
            "Contents": markdown
        })

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Could not load widget:\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

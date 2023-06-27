import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' STANDALONE FUNCTION '''


def create_number_widget(score):
    return {
        "Type": 17,
        "ContentsFormat": "number",
        "Contents": {
            "stats": score,
            "sign": "@",
            "params": {
                "layout": "horizontal",
                "name": "Threat Score",
                "colors": {
                    "items": {
                        "#28a745": {"value": 0},
                        "#ffc107": {"value": 60},
                        "#dc3545": {"value": 80}
                    }
                },
                "type": "above"
            }
        }
    }


''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        indicator = args.get('indicator', {})
        indicator_value = indicator.get('value', '')
        score = int(indicator.get('CustomFields', {}).get('threatscore', 0))

        # if the threat score is 0, update score
        if score == 0:
            '''
            Enrich indicator is removed from the flow, because the script caused performance issues and kept timing out.
            Enable `demisto.executeCommand('enrichIndicators', {'indicatorsValues': indicator_value})` at your own risk.'''
            # enrich indicator
            # demisto.executeCommand('enrichIndicators', {'indicatorsValues': indicator_value})

            # calculate threat score
            res = demisto.executeCommand('CalculateThreatScore', {'indicator': indicator_value})

            try:
                score = int(res[0]['Contents']['threatScore'])
                demisto.executeCommand(
                    'setIndicator',
                    {
                        'value': indicator_value,
                        'customFields': {'threatscore': score}
                    })
            except (KeyError, TypeError) as e:
                demisto.debug(e)

        # return the widget data
        return (create_number_widget(score))

    except Exception as e:
        demisto.error(f"Threat score widget failed with [{e}]")
        msg = f"Could not load widget:\n{e}"
        return msg


if __name__ == "__builtin__" or __name__ == "builtins":
    # call the main function and return the widget data
    widget_data = main()
    demisto.results(widget_data)

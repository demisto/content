import demistomock as demisto  # noqa: F401


def main() -> None:

    ORANGE_HTML_STYLE = "color:#FF9000;>"
    GREEN_HTML_STYLE = "color:#00CD33;>"
    DIV_HTML_STYLE = "display:block;text-align:center;padding:15%;"

    try:
        sonar_total_hits = demisto.context()["Rubrik"]["Sonar"]["totalHits"]
        
        if not sonar_total_hits:
            html = f"<div style={DIV_HTML_STYLE}><h1 style={GREEN_HTML_STYLE}{str(sonar_total_hits)} Total Hits</h1></div>"
        else:
            html = f"<div style={DIV_HTML_STYLE}><h1 style={ORANGE_HTML_STYLE}{str(sonar_total_hits)} Total Hits</h1></div>"

    except KeyError:

        sonar_total_hits = -1
    """
    if sonar_total_hits == -1:
        data = {
                    "Type": 17,
                    "ContentsFormat": "number",
                    "Contents": {
                        "stats": 0,
                        "params": {
                            "layout": "horizontal",
                            "name": "No Results Found",
                            "sign": "",
                            "colors": {
                                "items": {
                                    "#00CD33": {
                                        "value": -1
                                    },
                                    "#00CD33": {
                                        "value": 0
                                    },
                                    "#ff1744": {
                                        "value": 3
                                    }
                                }
                            },
                            "type": "above"
                        }
                    }
                }
    else:
        data = {
                    "Type": 17,
                    "ContentsFormat": "number",
                    "Contents": {
                        "stats": int(sonar_total_hits),
                        "params": {
                            "layout": "horizontal",
                            "name": "Total Hits",
                            "sign": "",
                            "colors": {
                                "items": {
                                    "#00CD33": {
                                        "value": -1
                                    },
                                    "#FF9000": {
                                        "value": 0
                                    },
                                    "#ff1744": {
                                        "value": 3
                                    }
                                }
                            },
                            "type": "above"
                        }
                    }
                }
    """

    #demisto.results(data)

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
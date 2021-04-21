import demistomock as demisto  # noqa: F401


def main() -> None:

    try:
        sonar_open_access_files = demisto.context()["Rubrik"]["Sonar"]["openAccessFiles"]

    except KeyError:

        sonar_open_access_files = -1
    if sonar_open_access_files == -1:
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
                        "stats": int(sonar_open_access_files),
                        "params": {
                            "layout": "horizontal",
                            "name": "Files with Open Access Permissions (Windows Only)",
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
    demisto.results(data)


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

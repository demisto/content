import demistomock as demisto  # noqa: F401
import json

def main() -> None:

    try:
        radar_files_added = demisto.context()["incident"]["labels"]["radar_files_added"]
        
    except KeyError:

        radar_files_added = -1
    if radar_files_added == -1:
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
                        "stats": int(radar_files_added),
                        "params": {
                            "layout": "horizontal",
                            "name": "Files Added",
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

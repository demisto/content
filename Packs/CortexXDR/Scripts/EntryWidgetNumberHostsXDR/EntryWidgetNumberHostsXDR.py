import demistomock as demisto

incident = demisto.incidents()
data = {
    "Type": 17,
    "ContentsFormat": "number",
    "Contents": {
        "stats": int(incident[0].get('CustomFields', {}).get('xdrhostcount', 0)),
        "params": {
            "layout": "horizontal",
            "name": "Hosts Count",
            "sign": "",
            "colors": {
                "items": {
                    "#00CD33": {
                        "value": -1
                    },
                    "#FF9000": {
                        "value": 0
                    },
                    "#FF1744": {
                        "value": 3
                    }
                }
            },
            "type": "above"
        }
    }
}

demisto.results(data)

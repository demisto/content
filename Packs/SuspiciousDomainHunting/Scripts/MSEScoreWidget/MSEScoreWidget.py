import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_widget_entry(mse_score) -> dict:
    stats = int(mse_score)
    if stats >= 0 and stats < 25:
        color_mse = "#fe1403"
    elif stats >= 25 and stats < 75:
        color_mse = "#f57d00"
    else:
        color_mse = "#00cd33"

    data = {
        "Type": 17,
        "size": 30,
        "ContentsFormat": "number",
        "Contents": {
            "stats": stats,
            "params": {
                "layout": "horizontal",
                "name": "MSE Calculation",
                "description": "The Mean Square Error calculation - 0 means identical",
                "sign": "%",
                "signAlignment": "right",
                "colors": {
                        "isEnabled": True,
                        "items": {
                            color_mse: {
                                "value": -100
                            }
                        }
                },
                "type": "below"
            }
        }
    }

    return data


def main():
    try:
        mse_score = demisto.context()['ImageSimilarity']["MSE"]

        mse_score = 100 if not mse_score else float(mse_score)

        return_results(create_widget_entry(mse_score))

    except Exception:
        return_results("MSE Score was not found in the context.")


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_widget_entry(ssim_score) -> dict:
    stats = int(ssim_score * 100)
    if stats >= 0 and stats < 25:
        color_ssim = "#00cd33"
    elif stats >= 25 and stats < 75:
        color_ssim = "#f57d00"
    else:
        color_ssim = "#fe1403"

    data = {
        "Type": 17,
        "size": 30,
        "ContentsFormat": "number",
        "Contents": {
            "stats": stats,
            "params": {
                "layout": "horizontal",
                "name": "SSIM Calculation",
                "description": "The SSIM index calculation between -1/1 - 1 indicates perfect similarity,  \
                    0 indicates no similarity, and -1 indicates perfect anti-correlation",
                "sign": "%",
                "signAlignment": "right",
                "colors": {
                        "isEnabled": True,
                        "items": {
                            color_ssim: {
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
        ssim_score = demisto.context()['ImageSimilarity']["SSIM"]

        ssim_score = 100 if not ssim_score else float(ssim_score)

        return_results(create_widget_entry(ssim_score))

    except Exception:
        return_results("SSIM Score was not found in the context.")


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

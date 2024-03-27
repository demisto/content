import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_widget_entry(mse_score, ssim_score, color_mse, color_ssim) -> dict:
    data = {
        "Type": 17,
        "size": 30,
        "ContentsFormat": "number",
        "Contents": {
            "stats": int(mse_score),
            "params": {
                "layout": "horizontal",
                "name": "MSE caclulation",
                "description": "The Mean Square Error callculation - 0 means indentical",
                "sign": "",
                "colors": {
                        "isEnabled": True,
                        "items": {
                            "#e72416": {
                                "value": 1
                            },
                            "#E88080": {
                                "value": 10
                            },
                            "#EFC23C": {
                                "value": 25
                            },
                            "#56C724": {
                                "value": 40
                            }
                        }
                },
                "type": "below"
            }
        }
    }

    return data


def get_color(num: int | float) -> str:
    """
    Gets a MSE score as an integer\float and sends back the correct hex code for a color as a string.

    Args:
        num (int\float): A MSE score.

    Returns:
        str: The color of the score in hex format
    """
    num = int(num)
    if num < 0 or num > 100:
        return "Invalid input. Please enter a number between 0 and 100."
    else:
        red = int(255 * (num / 100))
        green = int(255 * ((100 - num) / 100))
        blue = 0
        return f"rgb({red}, {green}, {blue})"


def main():
    try:
        mse_score = demisto.get(demisto.context(), 'ImageSimilarity.MSE')
        ssim_score = demisto.get(demisto.context(), 'ImageSimilarity.SSIM')
        demisto.callingContext.get('context', 'light').get('User', 'light').get('theme', 'light')

        mse_score = 0 if not mse_score else float(mse_score)

        if not mse_score:
            return_results("MSE Score was not found in the context.")
        else:
            return_results(create_widget_entry(mse_score, ssim_score, get_color(mse_score), get_color(ssim_score)))

    except Exception as e:
        return_error(f"Error: {str(e)}")


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

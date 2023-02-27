import json
import traceback
from base64 import b64decode
from typing import Any, Dict, List

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def build_report(template: List[Dict], alert_id: str) -> Dict:
    """Take a JSON template input and return a PDF Summary Report

    Args:
        template (List[Dict]): Python list of dicts built from args

    Returns:
        Dict: File Result object
    """

    # Convert Dict to json string
    template_str = json.dumps(template)
    # Encode json to b64 for SanePdfReports
    template_b64 = base64.b64encode(template_str.encode("utf8")).decode()
    # Convert json to PDF
    results = demisto.executeCommand(
        "SanePdfReports", {"sane_pdf_report_base64": template_b64, "raw-response": True}
    )
    pdf_b64 = results[0]["Contents"]["data"]
    # Decode returned b64 bytecode from SanePDF to write to PDF file
    pdf_raw = b64decode(pdf_b64)
    file_entry = fileResult(
        filename=f"asm_alert_investigation_summary_{alert_id}.pdf",
        data=pdf_raw,
        file_type=EntryType.ENTRY_INFO_FILE,
    )

    return file_entry


def build_template(args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build a template to be used to create Summary report

    Args:
        args (Dict[str, Any]): Demisto.args() object

    Returns:
        List[Dict[str, Any]]: Python list of dicts that will become the JSON template
    """
    cur_date = demisto.executeCommand("GetTime", {"dateFormat": "ISO"})[0]["Contents"]

    # Grab ASM args from demisto.args()
    asm_args = get_asm_args(args)

    # Cortex Logo
    cortex_img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAcsAAAHKCAYAAABsXmDiAAAACXBIWXMAAFxGAABcRgEUlENBAAAgAElEQVR4nO3dC3BU153n8X/rhQRCIAkkEI8ISwYDEg/zMvYEMHhtB2dtHCceFq+nnIep2nKKsFVOPIknVdRMnGTX2RpCrXeqPHHGGRuK8cYOdhzHdmEPOLPhZZuHeBiCjACLh0BCgBAvqXvrtLql7lZLp7vVj3Pu/X5cslqt27dPnyP61+fcc8/1+Hw+AQAAfcuibgAA6B9hCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgAZhCQCABmEJAIAGYQkAgEYOFRTu9SNvfnVvy6Hqkrxh1cevnKoJ/aVPwn/q9bNPoorcMtqjg3v3htztUT9H2Sbqs0d97t5lDLvl6/M3/ZSz616vv3ThPOp+X/h2Qd7A6wn9Oerz9VWJwfrp3otPSnILzwzJLmgtLyg9E3xstBpS93sCP/lCnsMX8apDn9sX+K+nXMFy9+zLG+UxPSX1dT936Cvy79UXrbZ9IeXqa/s49tX9/OHbh9/u2cYb5bE9j4/2uiLKEdHWPY/vKXvo34A37DkiH9v7+ULv94T9OwnuN3S73mXv9ZwS/vhe9/p6Pyb09XbvM+zfax/7ini8N7IVo/zJh77e/vbmjXhstHrovd/wbaNsvyXwfc+2r6xv7WNXruPp+83J+Xad/mT4p017VzVcOfW1M9dbJh2/3pzf5r3p9r8J6+R5smTCoFIZX1AuxXlFgeITlqHl7v16CcvQx/e6191hGeqizyd7RHwqQDdtX7phT9+bOpsrw3Ljod8+vefCodWHrpwcc/pmmwElQrIMzc6TeUUTpSRvKGFJWBKWUfcbvm1/20vvejwuIi+rr+1LNzT08zDHcU1Yfnpmz/BdZz9de+Bi/YrtbcdyDSgSUqi2YJTcWjhOsrNyCMsojyYswx/f617CsucZI+oxxG9EZI1bQtMVYfn6kTf//t3GP/1w79VTHKN1kdKcAllYXCNZnmzCkrAkLJMflkGuCE1Hh+Xus/tmvHN887tvnv+43IDiIANUYC4orpEcT9fEb8Iy9DZhSVj2vj9SDGGpXPSKrNm5dMNa3Ya2cmxYvnHkrb9/4+TmHx+5ft6A0iCTJg4aIdOHVflLQFiG3iYsCcve90eKMSyD+9gqIst2Lt3guFm0jgvLvU37h287veON105/dDczWxG0ZPiU7kk/hCVhSVimLCwlMAlIBaajZs46alGCQFDu+3XjBwQlwhy8cpIKAdLjS+pczbnvrJjhpPp2TFjuazoQDMpxBhQHhjl987Jc6minWYD0GOa0wHREWNY1HSQoofXF1XNUEpA+jgpMR4TltjM73nipcTNBiX61dFyhgoD0CgZmpe31bn1Yvnpw4/P/dnrr3QYUBYZrJiyBTFCBucn2mrc6LOvOHZrx3pltT1/uvGFAaWC6G77+5vwBSKHpc99ZYfU5mFaH5R8a3n338DWOQwGABb43950Vi2xtKGvD8p3699a+cW4XK/MgZnkeLt8KZJi1vUsr3z32n/ts+JsnP3jKgKLAIqU5Q2guILPUcOwTNraBlWG548zOtbvbv2BRdMSlPLeICgMyb42NbWBdWB44/9nwnc37HzOgKLBMeX4JTQZk3pds7F1aF5ZHWv7yHXqViFdhVq4U5Qym3gAzEJaptqfl4DO2lRmZd3vhBFoBMMdC2xYqsCosD54/XLn38ucjDCgKLDI6d6iU5xfTZIBZltnUHlaF5a6zn/zNqZuXDSgJbKFOF7lj+G20F2Aeq4ZirQrLzy+f/JoBxYAlVFAuLq6RbE82TQaYZ7pNbWJVWJ6+dm6SAcWABUpzCvxBOTSXcysBU9m0oo9Vs0rrr5/PN6AYMNzMwWPlliEVkpVFjxIwnLp81xYbGsmasHzlwMblLJiOvgzNzpNb88tkbEG55GcPEhGf+KgtwHTWzIi1JixPXjk1yoBiRFVbMEomF02QiUWVUj6kTEYOLou6nUe9gcf1Du4L+b9+u5h/E2MZem8We+F9UW7F9Lj4KkhysnIky5Pl/+q7hOH39jxFnPUW4Am2S58b9ffqfX3/1Mf+YnlNumfttW2M9RxrDcVSF/08OqZyeLRbaZ4zgX8MsdZ9v/tI+FNbov+KRK7cvCLHLh6Xfa1H5D8uHkm0AOlgzYWhrQnL7Kxso8a2pxWMlgVls2T+6LkytmisFOQwQgzAHPPHzJcVItJ2o022n9oum05slk+vfEELJciasGy5fnG4AcXwh+R9o++U2aNmybiisf6eDQCYqjCvUO6pvMf/ta9przy//yWpv95Ce8WJd/o4PDxyttw3brFMHnEbPUkA1plWNl1eWbxO1h/cKP/n+O9pwDgQljH65pjFsnjsAplUOtGK8gJAXx6bslxuGTZenjvwa7nQeZV6igFXw42BCsol4xYSlAAcY/6YO2Xt7L+V4uwCGjUGhKXGwyPn+INyYsmtRpcTAOJVXVLtD0zoEZb9mF5QIfePX0JQAnAsFZjPVD9KA2sQlv24r+IumVLKCnsAnG3ZrQ/Jl4t4r+sPYdkH1aucM2qWDMoZZGT5ACCZ/vv0ldRnPwjLPiwqny1jh1YYWTYASLbRhaPkG+Xzqdc+EJZ9uGP0PMlmwQEALvJfJn6d5u4DYRmFGoKlVwnAbVTv8vbBY2n3KAjLKO4cOY1jlQBc6T9V3EnDR0FYRjGucIxxZQKAdKgpnUo9R0FYRjFy8EjjygQA6aDOu0RvhGUURXlDjSsTAKRLVV4JdR2BsAQAhKnIH0GFRCAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQyKGCALu03WiTz1uP+ct8sPlwd9k/b2uUKx3X+n0tEwor5Du1j9PiQJwIS8BAwUBsuHRC2m9elbrWemnruCp17Y00F5ABhCVggH1Ndf5eouodHm07JQ03WmgWwCCEJZBmqte4/9xB2d9y2N9jpLcImI+wBNKg/kK9HGj+THac2y/bLh2lygHLEJZAiqiA/Pcv/ix/Pr+fYVXAcoQlkEQEJOBMhCUwQOoY5IcntsoHp3dx/BFwKMISSJCawbqlcZtsatpFFQIOR1gCcfqgYYu8dXILvUjARQhLIAbBodZNJz/iWCTgQoQl0A8Vkm/XvyuvNW6V1s7+l5ID4FyEJRAFIQkgFGEJRFDHJF84+johCaAbYQkEqNmtaw+8yjFJAL0QlnC9021n5X/XvcwydAD6RFjCtYLHJV888R5/BAD6RVjClRhyBRAPwhKuonqTGw//Tjac+oiGBxAzwhKuQW8SQKIISzgevUkAA0VYwtHUJbPW7X+FdVwBDAhhCcdicQEAyUJYwnHUsOuvD2zg0lkAkoawhKOoBQZ+vvufGHYFkFSEJRxDHZ/8/idrGXYFkHSEJRxBHZ987vB6GhNAShCWsN7GQ79lyToAKUVYwmrrdr/IRB4AKUdYwkpqxuu6vS/J5pb9NCCAlCMsYR0VlM/u+AUzXgGkTRZVDZsQlAAygbCENQhKAJlCWMIKBCWATLImLMcNGXUmXc+Vlz0oXU+FGBCUADLNmrAsyx/Rmq7nysnKTtdTQYOgBGACa8KyZsTUM0Oz89LyXHlpeh7oqQXRCUoAmWbVMcs7h92W8ueoHlQqWR56liZgwQEAprAqLBeNmpfy51g4YmbKnwN6agk7ghKAKawKy9GFFTJryLiU7b88t1Cmj6xN2f4RG7UoOmu9AjCJdaeOPFa1LGX7fmT0wpTtG7FRl9l64ejr1BYAo1gXlsX5xfKtMUuSvt+7h0+W20omJn2/iJ2a+cr1KAGYyMpFCf6q4i65tzh5w6XVg0bI0rF3J21/SIw6RYSgBGAiaxdSX179sMhRn7x/YWBXnZg/9Bb52pe+Ivk5g8QnvqSVD/H5Vd0rnCICwFhWX3Xkr6sflqqz4+XVxs1yufNGXI8tzMqV+0bcLndX/JX/Z4Iyc7Y37pQNpz5y68tPqtrBY6Qwp0CG5OTLLYVjwnZdWTRedjbtkcXvPdm9XVDo9mq7wbkFMq2MyW5AkPWX6JpddrvUlE6WTQ3vybaLh6XNe7Pf7VVILiyukbvKZ8mwQcPER0Zm1Om2s/I/D73i4hpITGVeiVQXVvgDbkrpJBk5uExGF5Zr99Vw6YT/e9RefJRrg0Y+zy3DJ0hhXmGGXjWQOY64nmV+doH8ddVD8qj45GDzQWlsb5LG9rPS3nnd//vSQUVSnDdMJhSOlcphleLrTkiSMtN+vvufOE4ZAxVad46okZqSSVIzckraAqvhRos0tLR0BWngdB7VK60dXiVzy2fQ+4RrOO7iz1NKp8jkkslhw6o+n7frO8OtRlELD3Ccsm8qlJaMniNzRs2OqdeYLqrN1JcaOh+enS+LSmtlbtkMuWPMXGPKCCSb48ISdtjXVMfCA1GoHuSycQuMC8i+qFEBtdKS+hp+6BV/cD5QuUSqiqvMLDCQIMISaafOp1x74FUqPsSysjmyaMx8q4c1Q4NT9YofHLdIllQuMqBkwMARlki7jYd/5z8W5nZqCHNp+Vx5YMK9VvQi4+Efqj28XtYf+6PcO2qOfLXqfiYGwWqEJdJKDb+6/TQRFZKPjlnoigBRH4rUcPtrjVtd85rhTIQl0uqlw+5e93VFxQJZPulh1wWGGqINhuZT1Y8wPAvrEJZIGzfPfp1fVC3frX3CccOt8VKh+dzh9fLWyS3y7UmPcOoJrEFYIi3U4gOqV+E2anbryomPcFpFBPWhafXudf6JTd+auoKhWRiPsERa/N+/vOm6xQfcOuQaDzVzdktznfxg8uN8oIDRCEuknJrUo94U3UJN4FkzbSVDjDFSH6J+tP+fZVnTHnqZMBZhiZT7t/p3XFPJ95TUyKrp3+YNPwHqA9We1np5dsZKFjWAcay8niXs8UHDFtl26agrWmx11TL50ZzvEZQDoE41eXLnz/1/N4BJCEuklDop3enUsOvamavkweoH+GNKEjVjdt3uFx3xWuAMhCVSRvUOnL5Sj1rW7flZqzk+mQJqWPbZbf/DvzwikGmEJVLG6b1KFZTPzXua42sppIbwn93xCwITGUdYIiWc3qtUiwyooOT4ZOqpczJVYNZfqHf6S4XBCEukhJN7lepE+ufmP0NQppEKzO9/spbARMYQlkg6J/cqVVCumrnSgJK4jzofk8BEphCWSDq17qcTqaFXgjKz/GvL7nmRY5hIO8ISSaVW63HiYulqMs8PZz1lQEmgRi2Y9IN0IyyRVG8f/9BxFRqc9coxSnMEJ/0A6UJYImnUlUU2t+x3VIWqBQdW1TxOUBpIBSYLFyBdCEskzR+Ove+4ylQLonMepbnUwgVvHf2D26sBaUBYImneObvTUZW5cvx9rMxjgbX1m5ghi5QjLJEU6nQRJ12vUl09ZPnkrxtQEsSCGbJINcISSbHj3F7HVKT/OOX0bxtQEsRKzZBdt/cl6gspQ1hiwNQneidN7FHHKZnQYx/1N8jxS6QKYYkB+/DEVsdU4oqKBRyntNjLDe/6Z2UDyUZYYsA+OL3LEZWohl+XT3rYgJIgUeq4+b8c2kj9IekISwyI+hTvlBV7fjCZ8ymdQA3Hbm901sxsZB5hiQHZdeZjR1SgWvf1jjFzDSgJkuHFI68zOxZJRVhiQHacc8bEnu/WPmFAKZAsanbs2/XvUp9IGsISCVOf3NWV7G2nLrs1urCcPwSHea1xK71LJA1hiYTtOGX/EKya1POtqSsMKAmSTU322Xj4d9QrkoKwRMIOXDhifeU9OmYhk3ocbMOpjziVBElBWCJhe1rtX4/zq1X3G1AKpJITF/hH+hGWSIhauFpNorCZOlZJr9L51AL/HLvEQBGWSMiB5s+sr7hv3PqQAaVAqqljl8yMxUARlkjI/gt2z4JVVxVhBqx7vH/GGatMIXMISyTkaNspqytuccV8A0qBdFGHDFjVBwNBWCJuanahzccrK/NKWK3HhT48tc3tVYABICwRt+MXj1tdaXeOqDGgFEg3tWYsE32QKMIScWu4dMLqSntgwr0GlAKZ4KTLySG9CEvErc7i8ytrB49hYo+LOeVyckg/whJxO3TlC2srbT5DsK6mLifHUCwSQVgiLuqNRp23Zqs5o2bS4C7nhDWNkX6EJeLyeesxaytMzYKtKq4yoCTIpB3n9lL/iBthibjYPLlnxnCCEiIfX7T/snJIP8IScWm/edXaCptaPNGAUiDT1GEEtbYxEA/CEnGxeSbslBGTDSgFTOCEtY2RXoQl4tLWYWfPUl3kmVNGENRwuZG6QFwIS8RFTb230eQhY2lodKu3fG1jpB9hCVeoZXIPQtj6oQ+ZQ1giZvua6qytrMqi8QaUAiax+e8Z6UdYwhUG5xbQ0Ahj88xupB9hiZjZ/OYyrazWgFLAJLZfEADpRVgiZra+uaiZsECkpmv2XpMV6UdYwvGYCYtozl67QL0gZoQlAAAahCUcrzy/mEZGLzZfag7pR1giZp+32XluWll+iQGlgGlsvtQc0o+wRMyudPDmAsCdCEsAADQISwAANAhLAAA0CEsAADQISwAANAhLAAA0CEvEbEgOa6wCcCfCEjG7pXCMlZXV1sGlmAAMDGEJxzvWdopGRi/zi6qpFMSMsAQAQIOwhOOxYDaiYYF9xIOwRMwqi8ZbWVksmI1oWGAf8SAsEbPBuQXWVlb9hXoDSgGTjCwYQXsgZoQlXOFcezMNjTAjB5dSIYgZYYmYTSurtbayGi6dMKAUMInNf89IP8ISrmDrhauRGpV5HK9EfAhLxKV2sJ0LExzlXEuEqC6soDoQF8IScSnMsXOST8ONFjnddtaAksAENcUsSID4EJaIywSLP5EfPH/IgFLABFNLb6MdEBfCEnGxtWepHLhwxIBSINOGZ+dLVXEV7YC4EJaIy5TSSdZW2J5WzrWEyOxhDMEifoQl4jJycJm1FaaOW7I4AeaNnO76OkD8CEvEZXRhuX8Yy1YHmj+jwV1uyojJbq8CJICwRNwmDxlrbaV9cHqXAaVApqhTn9QHPiBehCXiZvOM2Lr2Rk4hcbElo+e4vQqQIMIScZswdJzVlbbrzMcGlAKZMGfUbOodCSEsETfbj/lsOvmRAaVAus0vqmYIFgkjLBE32yf5qFmx+5rqDCgJ0mnx6HnUNxJGWCIhtp+rtqVxmwGlQLqoD3dLKhdR30gYYYmE2L625qamXUz0cZFHxyx0exVggAhLJMQJa2tuPfknA0qBdFg47svUMwaEsERC1NqaNh+3VF5r3CptN9oMKAlSaVnZHCb2YMAISyRsUandV5pv7bwmb9e/a0BJkErfuPUh6hcDRlgiYVOLJ1pfefQunY1eJZKFsETC5lXYf4I3vUtno1eJZCEskbDCvEL/Wpu2e/HEe8yMdaCV4++jV4mkISwxIE5Za/NfDm00oBRIFjX57KtV91OfSBrCEgPilLU2N7fsZ1UfB3mq+hH/yAeQLIQlBkQNczlhKFZZe+BVJvs4gFoDltV6kGyEJQbMKUOxas3YjYd/Z0BJkCg1/Prd2ieoPyQdYYkBc9Jljzac+ojhWIs9UXk/k3qQEoQlBky9OamhL6dgONZO6m/wweoH3F4NSBHCEknhpMsfqeHYdXtfMqAkiJUafv3hrKeoL6QMYYmkUBMqbF8rNpSaHftBwxZzCoR+/WDy48x+RUoRlkiapeVzHVWZzx1eL/UX6g0oCfqjFh+4Y4yz/vZgHsISSfPAhHsdV5nf/2Qtxy8Ndk9JjSyf/HW3VwPSgLBE0jhtoo8E1o59dscvCEwDqfN7V03/tturAWlCWCKp/vP4ux1XoXXtjfKzT14woCQIqswrkefmPc1xSqQNYYmkUseO1BuZ02y7dFTW7X6RPxYDqIlkz85YSVAirQhLJN1jE77iyErd1LSLwMwwFZTPz1otVcVVrq4HpB9hiaRTp5E4sXcpBGZGEZTIJMISKXHvKGesFxsNgZl+BCUyjbBESqhrCTppkYJIKjB/uuuXzJJNAzVKQVAi0whLpISafPHomIWOrly1yg+nlaSWOj1k3V0/JiiRcYQlUkadLO7UY5dB6rSSv/noh6z0kwLLyuZwegiMQVgipZw6MzaUWrhArfTDWrLJo5awWzWT00NgDsISKeXkmbGhVGCqtWTVxB+GZROnjnOvnbmKJexgHMISKbd66n91TSWriT/qOCbDsvFTSyX+64KfybSyWtuKDhcgLJFy6s3PaWvG9kcdx3xy589l46HfmltIg6je5OqqZfLc/GcYdoWxCEukxXdrn3BdRb944j353p/WyL6mOgNKYyb1IeqFO/5OHqx+wO1VAcMRlkgLdUUSNWnDbVQvc/XudRzLjKCOY/+05kl/b1L9bQCmy6GFkC5qoYL3z+yShhstrqtzdSxzS3Od/9xTVQ9uHW5UQ65urwPYiZ4l0ka9Obppsk8kNWNWDc2u+n//4MrTTNR5k2oCj5rpSlDCNvQskVZqss+KigWy4dRHrq141bNWp5msP/ZH/xq6Tu5lqZ7k0vK58sCEexluhdUIS6Td8kkPyztnd/p7Wm6mQlP1NF9r3CqLSmvlG7c+5JhAUcckl41bIIvHL6QXCUcgLJF26s1zzbSV/okv6BqeVcc01ZeaHbp49DyZVzHbypC5p6RGFlfM918EHHASwhIZwXBsdNsuHfV/yeH1/uCZN3K68cFpSzmBgSAskTFqOLautd5/egV6U1c1UV8qOFWPs3Z4lUwpnZTxFW7UEOuM4VUytXgiAQnXICyRMepNdlXN4/7VbtC/7h7niff826nwnFBYIROGjpORg0tTGqChzzVlxGQm6sCVCEtklLpOoVrqbG39JhoiDt3hGULNPJ08ZKwMycmXWwrHdP9C9UaDmq6Fn+Oqeomj87sWug8+bnBugVQWjZeRg8sIRiCAsETGqaXOGi43+ie4IHFqolB3gKrh26BAb1QCvcQP7/tnahmIE4sSwAjfmrrCf1V8ADARYQkjqOOXfzvzv/mHEgHANIQljKGOj6nzLwHANIQljKJmdT476TEaBYBRCEsYZ0nlIv+i2wBgCsISRlo1cyWBCcAYhCWMxQxZAKYgLGEsNUP2uXlPE5gAMo6whNEITAAmICxhPAITQKYRlrACgQkgkwhLWIPABJAphCWsQmACyATCEtYhMAGkG2EJKwUD856SGhoQQMoRlrCWCswfzfkeK/0ASDnCEtZTS+OtrlpGQwJIGcISjvBg9QPy05onuR4mgJQgLOEYd4yZK8/PWi2VeSU0KoCkIizhKFXFVbLurh8z8QdAUhGWcJzgxJ+V4++jcQEkBWEJx1o++euyduYqhmUBDBhhCUebVlbLsCyAASMs4XjBYVlmywJIFGEJ11CzZV+44+9kflE1jQ4gLoQlXGV0Ybk8N/8ZepkA4kJYwpVUL/NfF/yMpfIAxISwhGupY5lqqTw1Y5YrmADoD2EJ11MzZn/55TXy7KTHGJoFEBVhCQQsqVzkH5pVixkQmgBCEZZACDU0qxYzUKG5omIBVQPAj7AEolCh+Z3ax2X9XT9hEhAAwhLojzrVRE0Ceuvuf2R4FnAxwhKIQejwrLrQNOvNAu6SQ3sDsVOhqS40rb62N+6U35/4d9l26Sg1CDgcYQkkSC1soL5Ot52VPxx7X/58fr803GihOgEHIiyBAVLHNdVkoO+I+HubO5v2yJbmOmntvEbVAg5BWAJJFOxtriI4AUchLIEUiQzO/S2HGaoFLEVYAmkQDE41VKuOcR48f0gOXDgie1rrCU/AAoQlkGbqGKf6UsvrSSA8j1887u95Hms7xexawECEJZBhwfBUPc+g+gv1cq69WRounZDP2xrlSsc1QhTIIMISMFBVcZX/KzRAg/Y11flvHWw+3H1fXWt92DaHrnzBpCIgiQhLwDLqkmIS8l1ZTiMCKcVydwAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJYAAGgQlgAAaBCWAABoEJZRdHg7jCsTAKTLny4doa4jEJZRtN1oM65MAJAOp9tOU89REJZRXCYsAbjUsdZjNH0UhGUUl29clk6GYgG40PamT2j2KAjLPpy/2mxkuQAglT44v4f6jYKw7MO5dsISgLtsbtgsLZ3XaPUoCMs+XLpxWVqvXTSybACQCi/Xv0m99oGw7EfDxRPGlg0AkmnTX96U+hst1GkfCMt+tHe0E5gAHO9oy1F58djvaeh+EJYajZdPMRwLwLHUeeX/WPcrudB5lUbuB2EZg8Mth1moAIAj/cOu/yWftp+kcTUIyxh0eDvlwPmDBCYAx1DvZz/Z+bz8B0vbxYSwjJEKzP3nDsrptrNWlBcA+nK67Yw8s+0n8sdmzqmMVY4dxTRDh69Djl6ol+arzVJVfIsU5OS7vUoAWEbNev3VsbflQmc7TRcHwjIBF661yu6ze2VkQamMLRpLaAIwnlpw4DefvyX117tOD/HQZHGxKSwbDChDN3UZr1NtZ/xfJfnFUjRoqJQUFMvQvD/AT/oAAAbjSURBVKGGlBCAm6ljknXn6mT72U/lw+Y9cqHjqnj5i0gYYZkEzdda5Py1Fqlv7SpiYe5gyc7K9t/2iU884uu67ZPALXXbJz0/dW3Xs034/V3bhm4VuB2439e9vy7B5/OG3d/z+8j9qtud3k7xBr77xCudPq94fT7J8nhCyiv+bTw+n/97111dt4PbBEvo9XlDyuaVsFfgf3xXOYPl6C5J4LYv5BFeX1ipQ+rIF/aq1POEvxn4wuqz+xX4emrEI4Gy+ML3FSx/z556t1PPb0JLGyxL73oP3gq+dq+v597QT/nekK3D/h/ehGHlifqzL7LVo72i3vsI/X205+z6rafXtn3T/T56+bMkS3KysiXXkyN5WXniCXnK8PqXiJqKXqq+/y30XQ5vlAro3VbRSh9yq9+X37sFu//vi7w3+uOj/bz/ykl/OFqg1YZCCmGZGpdvtnX/gwoNEJ8v9E01MgR7h2XwseEBGRpCvohHB7cJ/Yfa9zZef2h55aa3I1Aerz8kvIHn7fB1Spb/lXi6wyn4O2932Xzdbyhdt73+R3gDAekL2U5t5g17jC8sTEODM/R19gRXMKRDwjXsNaqQ77k//Pe+kPKE1oh6lKerPkIioDPsOT3dewzGcbCKvYEPQ91bR36ACKnz4CvqeWzPFqGto0I09ANPtCAI/YAiYfeHiv7m7Q1/SB9hGW1/keXqX+9A0+tvv0Oz82R4doHkerLCPkB5+yhXsC16XkvUKAt5TO+A80Ype2RbhdZN1H1FPD58n76oYRra7v3tLbIt42kfQ1gzw8ia2bBTRkyyJixtoMJKTViK7EEBprrceUMab1ySS53XaSPnICxTZKtl5TWSv/cY2QcJHcYNdK88TAGAYVSv7HxHu5zv4JxnhyAsU2SLZeU1jn94tP+DKN1Dwf0NzwGZ1Oa9SWDa7/jOpRusGTG0LSw3GVAGy0UPQI8nvBfpCfwHmEoF5hUvQ7IWs6rzY1VYThkxSXXZjxtQFCv116OM/B09S9igueMaf6f2sqrzY+Nyd/QuU8xDhxKWUMcwL3SwEo2FLu5cuoGwTLG1FpY543SfvUOHYXXHNAGTtHs7op7iAaNZ9z5uXVhOHXFbA7Niky88IOlawh4qKNu9N2kxu7xsW4FtverIGgPK4CihPUt1kwk+sMl1bwftZY/f2DQLNsjKsKwZeZuaRfWmAUVxjPBVf5jgA7vcZHENW1y0tbNj8/UsVwcqHkkQeeoIYJObvk7ayw5rbexVis1hWTPSf+ySyT5JwqQe2Ix+pRX27ly6wdpDaDb3LKV25OQ1TPYBkMvIiOnUKOATNr8Aq8MyYBnDsQMXbYIPYIssR7yVOdrqnUs3WLMObDTW/4XVlk1R10NbRGAOTLQJPoAt8gLXj4WR1OxX604VieSIj2O1ZVP2BCb8IEFM8IHNBnlsujSvq6igtHr4NcgxYxfTyqaqTy7fNKAoVoq8RBfnWcIW6gLlQ7JyaS/zOCYoxUlhqUwvq1GBOZMh2d7iiT3Os4RNhmbn0V7mcVRQitPCUroCc0/gGOZeA4pjJUZkYQvVqyzKzqe9zPJNpwWlODEslRnltcHA/KUBxTFGf8clwxdSZzYs7DAiZzB/q+ZQHZSZTpjME41jj4rPLJ+mZsmu3n1236bAor1fMqBYGeeRLPEJq53AfiooB2flsiBB5l0MrMzj6DW7HX9y0szyaVtuHzWjMjD5x/UXjlY9yGg9zMgJPv7vfGKHoVRQFmYNonky7zdqMG+7w4NSnNyzjHT7qBmqd/nyx2d2PxE4zWS6WSVMnyxP12ckbx+LT4dO8CEwYRJ1jLI8d4gM8jD7NYMuBkbr1m63dJ3XRLju5KTZo2b6Q3PX6U9nBFb/WebG4FQhmJuVI50+rz80VW8zrHfJqSMwSLbHI8OyBvkn82R5POJlona6qYBUh7Q2bV+6YZO7XnoX157JO2f07WoSkPpas/PUJ8PVUEJgUlBl4EsZ7vQgzfZkSVZWnnT4OqSzOxy90uHz0rNExgzyZPtDUX0vyMqV/Cx1eggJmWIXA++JSmvgtuo57tlu+VJ1yeDhahMAAPSP1YcBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA0CAsAQDQICwBANAgLAEA6I+I/H92vO76/y9HIAAAAABJRU5ErkJggg=="  # noqa: E501

    # See examples here for template: https://github.com/demisto/sane-reports/tree/master/templates
    template = [
        {
            "type": "image",
            "data": cortex_img,
            "layout": {
                "sectionStyle": {"width": 80},
                "rowPos": 1,
                "columnPos": 1,
                "classes": "small square",
                "alt": "Cortex",
            },
        },
        {
            "type": "header",
            "data": "ASM Investigation Summary Report",
            "layout": {
                "rowPos": 1,
                "columnPos": 2,
                "style": {
                    "textAlign": "center",
                    "fontSize": 28,
                    "color": "black",
                    "background-color": "white",
                },
            },
        },
        {
            "type": "text",
            "data": "Alert ID: ",
            "layout": {
                "rowPos": 2,
                "columnPos": 1,
                "sectionStyle": {"width": 150},
                "style": {
                    "textAlign": "left",
                    "font-weight": "bold",
                    "fontSize": 16,
                },
            },
        },
        {
            "type": "text",
            "data": args.get("alert_id", "Alert ID"),
            "layout": {
                "rowPos": 2,
                "columnPos": 2,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                },
            },
        },
        {
            "type": "date",
            "data": cur_date,
            "layout": {
                "sectionStyle": {"width": 200},
                "columnPos": 3,
                "format": "YYYY-MM-DD HH:mm",
                "rowPos": 2,
                "style": {"fontSize": 14, "textAlign": "right"},
            },
        },
        {
            "type": "text",
            "data": "Alert Summary: ",
            "layout": {
                "sectionStyle": {"width": 150},
                "rowPos": 3,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "font-weight": "bold",
                    "fontSize": 16,
                },
            },
        },
        {
            "type": "text",
            "data": args.get("alert_name", "Alert Name not found"),
            "layout": {
                "rowPos": 3,
                "columnPos": 2,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                },
            },
        },
        {
            "type": "text",
            "data": "Alert Severity: ",
            "layout": {
                "sectionStyle": {"width": 150},
                "rowPos": 4,
                "columnPos": 1,
                "style": {"textAlign": "left", "font-weight": "bold", "fontSize": 16},
            },
        },
        {
            "type": "text",
            "data": args.get("alert_severityStr", "Severity"),
            "layout": {
                "rowPos": 4,
                "columnPos": 2,
                "style": {
                    "textAlign": "left",
                    "font-weight": "bold",
                    "fontSize": 16,
                    "color": color_for_severity(
                        args.get("alert_severityStr", "Unknown")
                    ),
                },
            },
        },
        {
            "type": "header",
            "data": "Alert Details",
            "layout": {
                "rowPos": 5,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                    "color": "black",
                    "background-color": "#00cc66ff",
                },
            },
        },
        {
            "type": "text",
            "data": args.get("alert_details", "Alert Details not found"),
            "layout": {
                "rowPos": 6,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "display": "flex",
                    "alignItems": "center",
                    "padding": "20px",
                    "fontSize": 12,
                },
            },
        },
        {
            "type": "header",
            "data": "Remediation Taken",
            "layout": {
                "rowPos": 7,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                    "color": "black",
                    "background-color": "#00cc66ff",
                },
            },
        },
        {
            "type": "table",
            "data": asm_args["asmremediation"],
            "layout": {
                "rowPos": 8,
                "columnPos": 1,
                "tableColumns": [
                    "Action",
                    "ActionTimestamp",
                    "Outcome",
                    "OutcomeTimestamp",
                ],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Remediation Rule Match",
            "layout": {
                "rowPos": 9,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                    "color": "black",
                    "background-color": "#00cc66ff",
                },
            },
        },
        {
            "type": "table",
            "data": asm_args["asmremediationpathrule"],
            "layout": {
                "rowPos": 10,
                "columnPos": 1,
                "tableColumns": [
                    "RuleName",
                    "Criteria",
                    "CreatedBy",
                    "Action",
                ],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Service Owner Information",
            "layout": {
                "rowPos": 11,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                    "color": "black",
                    "background-color": "#00cc66ff",
                },
            },
        },
        {
            "type": "table",
            "data": asm_args["asmserviceowner"],
            "layout": {
                "rowPos": 12,
                "columnPos": 1,
                "tableColumns": ["Name", "Email", "Source", "Timestamp"],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Notifications Sent",
            "layout": {
                "rowPos": 13,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                    "color": "black",
                    "background-color": "#00cc66ff",
                },
            },
        },
        {
            "type": "table",
            "data": asm_args["asmnotification"],
            "layout": {
                "rowPos": 14,
                "columnPos": 1,
                "tableColumns": ["Type", "Value", "URL", "Timestamp"],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Data Collected from Owner",
            "layout": {
                "rowPos": 15,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                    "color": "black",
                    "background-color": "#00cc66ff",
                },
            },
        },
        {
            "type": "table",
            "data": asm_args["asmdatacollection"],
            "layout": {
                "rowPos": 16,
                "columnPos": 1,
                "tableColumns": ["Options", "Selected", "Answerer", "Timestamp"],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Private IP Addresses",
            "layout": {
                "rowPos": 17,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                    "color": "black",
                    "background-color": "#00cc66ff",
                },
            },
        },
        {
            "type": "table",
            "data": asm_args["asmprivateip"],
            "layout": {
                "rowPos": 18,
                "columnPos": 1,
                "tableColumns": ["Source", "IP"],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Cloud Asset Information",
            "layout": {
                "rowPos": 19,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                    "color": "black",
                    "background-color": "#00cc66ff",
                },
            },
        },
        {
            "type": "table",
            "data": asm_args["asmcloud"],
            "layout": {
                "rowPos": 20,
                "columnPos": 1,
                "tableColumns": [
                    "Provider",
                    "Organization",
                    "Project",
                    "Region",
                    "Other",
                ],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Object Tag Information",
            "layout": {
                "rowPos": 21,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                    "color": "black",
                    "background-color": "#00cc66ff",
                },
            },
        },
        {
            "type": "table",
            "data": asm_args["asmtags"],
            "layout": {
                "rowPos": 22,
                "columnPos": 1,
                "tableColumns": [
                    "Key",
                    "Value",
                    "Source",
                ],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Related System Identifiers",
            "layout": {
                "rowPos": 23,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "fontSize": 16,
                    "color": "black",
                    "background-color": "#00cc66ff",
                },
            },
        },
        {
            "type": "table",
            "data": asm_args["asmsystemids"],
            "layout": {
                "rowPos": 24,
                "columnPos": 1,
                "tableColumns": [
                    "Type",
                    "ID",
                    "Link",
                ],
                "classes": "striped stackable",
            },
        },
    ]

    return template


def color_for_severity(severity: str) -> str:
    sev_map = {"low": "green", "medium": "gold", "high": "red", "critical": "maroon"}
    return sev_map.get(severity.lower(), "black")


def RPR_criteria(criteria: Any) -> Any:
    if criteria:
        criteria_dict = json.loads(criteria)
        statements = []
        for entry in criteria_dict:
            statements.append(f"({entry.get('field')} {'=' if entry.get('operator') == 'eq' else '!='} {entry.get('value')})")
        return " AND ".join(statements)
    else:
        return None


def get_asm_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get relevant ASM Arguments & Keys for Report template
    Args:
        args (Dict[str, Any]): Demisto.args() object
    Returns:
        Dict[str, Any]: Dictionary containing ASM Args in KV
    """

    # Set up default object for any empty arguments
    asm_args: Dict[str, Any] = {
        "asmserviceowner": args.get("asm_service_owner")
        if args.get("asm_service_owner")
        else {"Email": "n/a", "Name": "n/a", "Source": "n/a", "Timestamp": "n/a"},
        "asmcloud": (
            args.get("asm_cloud")
            if args.get("asm_cloud")
            else {
                "Organization": "n/a",
                "Other": "n/a",
                "Project": "n/a",
                "Provider": "n/a",
                "Region": "n/a",
            }
        ),
        "asmremediationpathrule":
            {
                "RuleName": args.get("asm_remediation_path_rule", {}).get("rule_name"),
                "Criteria": RPR_criteria(args.get("asm_remediation_path_rule", {}).get("criteria")),
                "CreatedBy": args.get("asm_remediation_path_rule", {}).get("created_by_pretty"),
                "Action": args.get("asm_remediation_path_rule", {}).get("action")
        }
            if args.get("asm_remediation_path_rule")
            else {
            "RuleName": "n/a",
            "Criteria": "n/a",
            "CreatedBy": "n/a",
            "Action": "n/a"
        },
        "asmdatacollection": args.get("asm_data_collection")
        if args.get("asm_data_collection")
        else {
            "Answerer": "n/a",
            "Options": "n/a",
            "Selected": "n/a",
            "Timestamp": "n/a",
        },
        "asmnotification": args.get("asm_notification")
        if args.get("asm_notification")
        else {
            "Timestamp": "n/a",
            "Type": "n/a",
            "Url": "n/a",
            "Value": "n/a",
        },
        "asmprivateip": args.get("asm_private_ip")
        if args.get("asm_private_ip")
        else {"IP": "n/a", "Source": "n/a"},
        "asmremediation": args.get("asm_remediation")
        if args.get("asm_remediation")
        else {
            "Action": "n/a",
            "ActionTimestamp": "n/a",
            "Outcome": "n/a",
            "OutcomeTimestamp": "n/a",
        },
        "asmservicedetection": args.get("asm_service_detection")
        if args.get("asm_service_detection")
        else {
            "ScanDone": "n/a",
            "ScanNum": "n/a",
            "ScanResult": "n/a",
            "ScanState": "n/a",
            "Timestamp": "n/a",
        },
        "asmsystemids": args.get("asm_system_ids")
        if args.get("asm_system_ids")
        else {
            "ID": "n/a",
            "Link": "n/a",
            "Type": "n/a",
        },
        "asmtags": args.get("asm_tags")
        if args.get("asm_tags")
        else {"Key": "n/a", "Value": "n/a", "Source": "n/a"},
        "asmrelated": args.get("asmrelated")
        if args.get("asmrelated")
        else {"Type": "n/a", "Link": "n/a"},
    }

    for arg in asm_args:
        # Force all ASM args to List types
        if not isinstance(asm_args[arg], list):
            asm_args.update({arg: [asm_args.get(arg)]})

    return asm_args


""" MAIN FUNCTION """


def main():

    try:
        args = demisto.args()
        template = build_template(args)
        return_results(build_report(template, args.get("alert_id", "")))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute Generate Summary Report. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_impacted_assets_html(impacted_assets_data: dict, alert_url: str) -> str:
    """
    Create HTML content for the impacted assets.

    :type impacted_assets_data: ``dict``
    :param impacted_assets_data: Impacted Assets data.

    :type alert_url: ``str``
    :param alert_url: Alert URL.

    :rtype: ``str``
    :return: HTML content for the impacted assets.
    """
    html_content = []

    def append_section(icon: str, header: str, sub_header: str) -> None:
        html_content.append('<div style="display:flex; align-items:flex-start;">')
        html_content.append(f'<div style="width:20px; text-align:center; overflow:hidden; margin-right:15px;">{icon}</div>')
        html_content.append(f'<div style="flex:1;">{header}{sub_header}</div>')  # noqa: E231,E702
        html_content.append("</div>")
        html_content.append("<hr>")

    # locationAssets
    for section in impacted_assets_data.get("locationAssets", []):
        distance_from_event = section.get("distanceFromEventLocation", "")
        name = section.get("name", "")
        address = section.get("address", "")
        if distance_from_event:
            header = (
                '<p style="margin:0; padding:0;"><strong>'  # noqa: E231,E702
                f"{distance_from_event} km from {name}</strong></p>"
            )
        else:
            header = f'<p style="margin:0; padding:0;"><strong>{name}</strong></p>'  # noqa: E231,E702
        sub_header = f'<p style="margin:0; padding:0;">{address}</p>'  # noqa: E231,E702
        append_section(
            '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAeCAYAAAA7MK6iAAADfUlEQVR4AbSXy0sVYRjG32+'
            "gpUbjMchsVesKoout+wO6k9GNWgS2qKxoUUtdhGW1UGhRdCNFLf0DWpciQbXOlZdAxxE9EYJ0vt7f5xk5Z5yZczST8zjv5XmfZ27nRT"
            "2p8icIFo5NB/muYPbX8EyYn5mZzf9x0Jia6ymnSjnJNB4Lw81BmG/DyBrzwRhpsWIPipWcGjDrEVNzPeXAZYZZ5aR+GE5sTs8uXK6VTT"
            "+slXuIJ5KSinpSzDCLRhKFWqLxdJjvMmKer8kQtVLoCaCBVmk5ilcZ63N7Z6y0RIR/PaKFZlynzLh4ds1x0gbkzUXtFakVY54HZ7fS2eA"
            "AbTwiWWfMG2iMeRAVk47hbCidT7oyASdpNqrhgRe5M94sm+5UepFmMH7aLZ0ZCMI5NNOhL5zzUoYztiJXNc78eJ6jyqkTR6W/96U0bm+Qx"
            "sYGF1NjWK+IQyYiL4+NlHa1ExNT8nlk1OHrt++ZglU39arx9ApijqQN9Q0Myqkzlxxu3r7naP3vh1w+MTklnBh9ajStbg6OlYCn5xmzrxLx"
            "4vlmAfAOHdovrddbZIu/Rfw638XU6FULPD1r7M5KA5heOHfG0Q4fVOMb1ySnxqBVY2quWeUvPFnyfiV+q97mW3fuO1rfwJCcbL6kt/mnjI9"
            "PuZgaTXj0QL/yqCXCir/8qiZ211dc/L0ow8OjMj4xmSngiZEwk6HNzoft8qijTSOR0yePykCPfp0at8mOHQ0upkazlEeeCvX0jDVjqYRi49"
            "WbHnn9ttdln/TrxQZjWQBiajRLeeRpwNMrWPsljRDVEQTk3Ea215xuKVYkMTV6cABxFvD09O36mEWi91hvNSCOQA6inCM5IM4Cnl4uVzuozz"
            "nIIib19u7ZLSCpl1kzEuDpQTIizzimga0FSvtsqUKhUFoSOKCsGEsiL2c8L0sdSVfd1HTAbSY2VRwsj/ri5or3yJmNeQoezktk+a/Mnb4/r1"
            "dwV/OyT1NxS7Gd4mBdgng9ypktE9MED7w0XDYm2FpX+8Ia6Sb+H0Abj0jb3eoo2erXXNO4R7HRn56i9opumTHV+rqas5wd8UYALTTjWquMIX"
            "B2+t/BFV4G8nXBSIAGWknzicYQeR4LsrTLGGlf0wmoITPMooFWElKNIfMG5vya+/V+Tb2x9rj+gdFtxIwUT4QvcYGYmuspBy4zzKKRhr8AAA"
            'D//3VNGSwAAAAGSURBVAMAF1fNZsjaURMAAAAASUVORK5CYII=" style="max-width:100%; max-height:20px; '
            'object-fit:contain;"/>',
            header,
            sub_header,
        )

    # thirdPartyAssets
    for section in impacted_assets_data.get("thirdPartyAssets", []):
        name = section.get("name", "")
        url = section.get("href", "")
        header = f'<p style="margin:0; padding:0;"><strong>{name}</strong></p>'  # noqa: E231,E702
        sub_header = f'<p style="margin:0; padding:0;">{url}</p>'  # noqa: E231,E702
        append_section(
            '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAeCAYAAAA7MK6iAAAEjUlEQVR4AaxXW2xURRj+5qQ3H1p'
            "kty0J9kW2CKLxQpXVGIVAtUUQaQuSpaEWMIEsGoRwa1pai4UiJLaaUmxA5cEUIoKtIgUtD4YQNXGhmoiCLXS7lZJ2uwldHyTVPc43e3Gv7W"
            "ns5vwz//z/93/fnJ3ZmawGgx+3e6Ro0O095B7+8/shj3doaNj7jzLpM6ZyEmOQDmMK93g8U9webx2FdCFOCwG7Dt0KHZlSgLUafcZUTmKIZ"
            "Q1rJSbhw+K4ycHhkXUZSO7WdVSSPC4oXlBOijWsJUc8CGNxhQc93kMC4sMJCZIt3OQEyEGu8HDQjxGW69YqdNiDgP/bk4uc0TwRwoHZ2aJB"
            "kzC2BbhDVCFhrgdnF8qM49y42Qun0zUO6r80uakRjChh7kAhxDvB4Fj9rYEBvPBiMZ5buATPLChEwZISDNy+PVZJKEcNajGghKcgebvRjbR"
            "vfwOu/noN9XXVqNtThV+u/ob6A43kGt/khlNaEqmEdWCD9A09Pzqu4KE5s7GmdBXK19gwe9ZMOC53GaolKKil8UQy+rYstFhm4Nr1bnzV8T"
            "W+ONOB67/3YGbuDKaMmXxramo+iHxjFX7UW7t3Ii01BRvsW2B/YxvuSUtDVcV2f9JgS01NEyLPIF7B+Had59thMptglnZB+rmW+1XOaENNT"
            "Re6xWhBEJdz33SYp94Ls2kqcnKmB8OGe2rykDcZrggAdXkY/3X3Lmj0A2HjnQ6T2tXGKwCfz4fNW3fB5foDfX39eH3zDhWbCAexGgQ8dIzY"
            "6Ojf2LhpK063nUH+ovlYMP9ZtH95Vm60N8GcEQ6FkZqa0EWPGiRoHI4uNB0+ipYjx1C+3o6z577B4oJFOPrB+/j4SBMKnl+IjvMXULZ2o8I"
            "Qe6Xr5wRs/jA1NZ+uO/zD2HZHRQ1eXlGK/Qca8Pa+g/j24iUUL1+KluZGJCUlITk5SfoNWLZ0MS5e+k5hiH2pyIZdlbVI9KGmJndXZzxAd8"
            "9NtJ74DFbrEzh54hhKipYpWGFBPjRZpQay4QQK5TcgXaxcsVxh583Lwyetn6p9wHi0UVPLzMz4XK6zOzrZ1+dSIdsrxXja+iTKy/y3pdPZr"
            "+LhjdPlj619dbXCriopUukbvb2qj2gE3NTUGBRAC/tw43mckpKMd99rxslTbaiurVfpp6yx5401b67K7a7Zq7CNTYeRmpqKh+c8qOLhTVBL"
            "Cd/B6MHot542LRu11RXqJ7NlWyW4YV5bV4bHH3sknEf5/Gp5YTgu/wRi+/tvYU9NBXiyKUCwkW+rtORYCVtMpjvyINgpxxEPb6DOc21q3dp"
            "PtYLndAQgbMArkhjuB9aU2laGZf0uNajFkRKmk23O+EgXaKYfbrz2uMZ5cx8ND8f1iSF21gO5MXlyUyOYCAkzkG1K3yT749Im+zke4A7xRg"
            "gzmmVOX83Z0Z8MIxc5o7lihAng7OS/g/XRG445wybgJge54tXEFSaQ6zGC0VwhsHdCE5CCrGEtOcgVzxIKE8wdmGlKr8oypWcJXS+Wt2Gzg"
            'PghMBGfxPjoM6ZyEkMsa1gr8wmffwEAAP//xc8P6wAAAAZJREFUAwDfu81m29u+PgAAAABJRU5ErkJggg==" style="max-width:100%; '
            'max-height:20px; object-fit:contain;"/>',
            header,
            sub_header,
        )

    # travelSegments
    for section in impacted_assets_data.get("travelSegments", []):
        distance_from_event = section.get("distanceFromEventLocation", "")
        name = section.get("name", "")
        travel_type = section.get("travelType", "")
        travelers_count = section.get("countImpactedTravelers", 1)
        if distance_from_event:
            header = (
                '<p style="margin:0; padding:0;"><strong>'  # noqa: E231,E702
                f"{distance_from_event} km from {travelers_count} "
                f'{"traveler" if int(travelers_count) == 1 else "travelers"}</strong></p>'
            )
        else:
            header = (
                '<p style="margin:0; padding:0;"><strong>'  # noqa: E231,E702
                f'{travelers_count} {"traveler" if int(travelers_count) == 1 else "travelers"} '
                "at risk</strong></p>"
            )
        sub_header = f'<p style="margin:0; padding:0;">{name}</p>'  # noqa: E231,E702
        if travel_type.lower() == "hotel":
            append_section(
                '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAeCAYAAAA7MK6iAAADeElEQVR4AbxWTUhUURQ+94GJyii'
                "Mo5A/K1sXJaKB1CL7kQItFdICB1sItouiyBYtamFtgtCwqGxRE2gptImoRRGkiNHPqlA0/AmcN6MzE1pqc7vfZd7zzZvrMDOODe+8e+453/"
                "m+894776lGCf50PXh8Xg91675fw15/yOv1hf5KEz5iMicwCdJRXOEJvz9P94euQYgz9pwx6uDEK4mTSwigVoOPmMwJDLCoQa3AbHigWJmc9"
                "wXbciljnHPqBLkSpAqKplCDWnCoIIgphef9oW5G7H5SgmCzmmgAHOCyhg0/Rlg8tyeMU4cB2OwKLnDaeaKEI90120Fp2DdHuE0qUxjPA92Z"
                "mTQ74IaGQSuFMYGMsS4juFUrNKAFfimcRxkXNjVIYErExMBJLYGVwpyoXfjmMTM7R43NbuofGDJj6XIMLQ1fJPvVLi//puHhUZqemTX1vn0"
                "fp4WFRXP/6ctX+jAyqjQ0bgLtjrhqaGphYjX2nHUfCIaorqGFDhyuo53l1XT7zj2ZPne+k5pOupVWVX2QTrW202IgKLH2EzQ1jbFye8K677"
                "37kMY+fpYhLj5JXTdu0eTUD7mPd3r77j1dunxVCYGmxhkvU2YjQa9Pj3jry+zcz/VNHO/lqze08mclBgFNfOSdMRlL4FjtIcuOqLhoO+3Zv"
                "YsS+a2trdG0GNQYLCennOqYhCWwf181PX7US0dFA23u0/Ri0EPZWVkWRHw3HA4rARox8iszIjg9M0eY3G2ZmeRubaHaIzU0MTklY0tLywKR"
                "4iE0NcbZhL3c6LL/2ZByajHNcV8ZCyEG0rKVLjS1MOdjcvcfT9DUxHS9tmtqIopYU0M99T/tS8lQCw7xfcYSZdDUXK7cQfGco94Z41aXlhT"
                "R3sqKlAy1UIu51Yx0aGpIMqJerIbl5GRTVVUFlZYUG6GkV9SCIzs7+g0wtKRwgFZvWq+6pLiIBjx91NRYn7SgUYBacIDLiEFDaomAFC5zOg"
                "PillwU+y09oAEtiEhhOIX5uQ84ox74W2HghobBbQojUOh0nBWrR1i6D0+E2+SNEka0IN/Rgu7gp8PABU47V4wwAOiOEz+DYcA+JWOkgwNcq"
                "nqlMIB4HkFa3cEYXU+qASGIGtSCA1wq21AYYEygy+m4UuB0FDDOT4j/A3oYsZFII/izE4aPmMwJDLCoQS04NrJ/AAAA//9hH9u1AAAABklE"
                'QVQDAOdvo2afurW1AAAAAElFTkSuQmCC" style="max-width:100%; max-height:20px; object-fit:contain;"/>',
                header,
                sub_header,
            )
        elif travel_type.lower() == "flight":
            append_section(
                '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAeCAYAAAA7MK6iAAAD90lEQVR4AbxV729TVRh+'
                "zk1IJLEdKxvJ0OgHEP8AoxsrkGimQfygAyEbiXHxB5ChBE0WElETzMikoBgj+INMY4zgJxQ1JsogfBEoYbCSQfg1fmVh0HVNWNnI"
                "2OjhfU53L23vXXubLTTn3POe533e5zk3982pBZ+/RGKwPp5I7UgM3D7an0z19w+k7pkpMTGTE45PORQ07kkmyxLJVCuNtFJ7lUKz"
                "hq6GRoUYsNZiTMzkhEMua1grnAkHiz2T8YHBt4KYdlFrbKS4J8kLlEOxhrXU8KIQ8zSOJ1M7FFR7SYZUy55yAGpQKxu2Y5exfLfd"
                "SqPZJkx2pRY183VyjMdP15hPmoJ947i2I+UY83vwdE6mSHD23AWcO3+xCOtBmtr0sBFjzA5USm2xwWJrb+911C1+DS++XI+bN+PF"
                "6E6eHvQiYIzLMK2llEa61tvLWqTTaVy+fNXEvh7ScMZLyMZYA6slfijD9rJ4I5XytpM+nbw1Pa00VN2kxUoUoKdlKfVMiXXoPBlz"
                "Sk7Gup3Yb0BPSys9x2/B+Qs9WNbwJrZEvnJKNn++zWA9l644WLGAnrzkQ8WIQ8PD2NQawUtLliIaPe6iE6tb/Cpa27aBXBchH9AI"
                "ma7Ox7P3e//4GwufX4Jd7T9jbGwsO5UTj46O4bsffsKiF17Bvr/+ycl5bSwoJL0S1/v6UL/iDaz7YAPi8X5DeWx2FVY2vI71768x"
                "ez4YNzYsw+yqKm7NhbJ2XQuWNzSh78YNg7ke4mkprXpcCQE6T8QQO9WNRQtq8enGFhz8709E/+9ApG0TwuEaYWTGwvB8bG37DMcO"
                "d+DAv/vwyUctWFBbIw3YBWpkWLlPelpprTtz4cyOxae7DmP3L7uw6p0mzHvKuwflGswUyPPpeXOx+t0m/PZrO07HjiA8v1pQ96Cn"
                "Jd3V4U4B5eUzMP2R6V4paPmntxO8Nu04e2UtNbIxO6anVVER/F2+c8IG/axDt4cd2tDwHSf2FSgk6GmRrIDvuRabIyMj+GL7N1jz"
                "3ocOdVXzemz/+lvcHbnrYIUC28sY38LoVj9vvf/AIWPy5BOPm+5esbwejHmY/QcPFfLL5ORtjZfsjPGcUOiWfLcNsi84wjXP4cyp"
                "qOnwiHT3l5FWE3d3HUFt9bMFa5mkB70YG2MGs2YGf9QKOxlPNMtD5QgGHnWlZ5QFwZwrkQVQmx425BgTmBUKrJV1j8ypHnvGtR3d"
                "HGOilTMDK3k6xlMxqUXNfC2XMQk8nYZ+20/Dke85FRLUoJZX3tOYRH6PQYzOVQqbSzqAGLKGtdSgltec0JhkdmBFKPBxZShQqbRe"
                'KhfWTgUVHT9IWjhpxsRMTjjksoa1kp9w3AcAAP//P7eF1AAAAAZJREFUAwAV9JpmTBexMgAAAABJRU5ErkJggg==" '
                'style="max-width:100%; max-height:20px; object-fit:contain;"/>',
                header,
                sub_header,
            )
        else:
            append_section("📍", header, sub_header)

    if html_content:
        incident_footer = (
            '<p style="margin:0; padding:0;">View employee and traveler locations '  # noqa: E231,E702
            "in the vicinity with Dataminr Pulse: "
            f'<a href="{alert_url}">{alert_url}</a>'
        )
        html_content.append(incident_footer)
    impacted_assets_html = "".join(html_content)
    return impacted_assets_html


def main():
    try:
        impacted_assets_data = demisto.incident().get("CustomFields", {}).get("dataminrpulseimpactedassetstext", "")
        alert_url = demisto.incident().get("CustomFields", {}).get("dataminrpulseexpandalerturl", "")

        if not impacted_assets_data:
            return_results(
                {
                    "ContentsFormat": EntryFormat.HTML,
                    "Type": EntryType.NOTE,
                    "Contents": "<p>N/A</p>",  # noqa: E231,E702
                }
            )
            return
        else:
            try:
                impacted_assets_data = json.loads(impacted_assets_data)
            except json.JSONDecodeError:
                raise ValueError('Failed to parse "Dataminr Pulse Impacted Assets" JSON string.')

        if not isinstance(impacted_assets_data, dict):
            raise ValueError("Invalid format for impacted assets data.")

        impacted_assets_html = create_impacted_assets_html(impacted_assets_data, alert_url)

        if not impacted_assets_html:
            return_results(
                {
                    "ContentsFormat": EntryFormat.HTML,
                    "Type": EntryType.NOTE,
                    "Contents": "<p>N/A</p>",  # noqa: E231,E702
                }
            )
            return

        html_content_start = '<div style="padding:10px; line-height:1.2; font-size:14px;">'

        data = []

        data.append(html_content_start)
        data.append(impacted_assets_html)
        data.append("</div>")

        html_content = "".join(data)

        return_results(
            {
                "ContentsFormat": EntryFormat.HTML,
                "Type": EntryType.NOTE,
                "Contents": html_content,
            }
        )

    except Exception as e:
        return_error(f"Failed to render data: {str(e)}")


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()

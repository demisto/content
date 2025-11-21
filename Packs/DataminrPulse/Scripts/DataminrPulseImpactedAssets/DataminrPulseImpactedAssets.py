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
        html_content.append(f'<div style="width:20px; text-align:center;">{icon}</div>')
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
        append_section("🏢", header, sub_header)

    # thirdPartyAssets
    for section in impacted_assets_data.get("thirdPartyAssets", []):
        name = section.get("name", "")
        address = section.get("address", "")
        header = f'<p style="margin:0; padding:0;"><strong>{name}</strong></p>'  # noqa: E231,E702
        sub_header = f'<p style="margin:0; padding:0;">{address}</p>'  # noqa: E231,E702
        html_content.append('<div style="display:flex; align-items:flex-start;">')
        html_content.append(
            '<div style="width:20px; text-align:center; overflow:hidden;">'
            '<img src="data:image/png;base64,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" '
            'style="max-width:100%; max-height:20px; object-fit:contain;" /></div>'
        )
        html_content.append(f'<div style="flex:1;">{header}{sub_header}</div>')  # noqa: E231,E702
        html_content.append("</div>")
        html_content.append("<hr>")

    # travelSegments
    for section in impacted_assets_data.get("travelSegments", []):
        distance_from_event = section.get("distanceFromEventLocation", "")
        name = section.get("name", "")
        travel_type = section.get("travelType", "")
        if distance_from_event:
            header = (
                '<p style="margin:0; padding:0;"><strong>'  # noqa: E231,E702
                f"{distance_from_event} km from {name}</strong></p>"
            )
        else:
            header = f'<p style="margin:0; padding:0;"><strong>{name}</strong></p>'  # noqa: E231,E702
        sub_header = f'<p style="margin:0; padding:0;">{travel_type}</p>'  # noqa: E231,E702
        if travel_type.lower() == "hotel":
            append_section("🛏️", header, sub_header)
        elif travel_type.lower() == "flight":
            append_section("✈️", header, sub_header)
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

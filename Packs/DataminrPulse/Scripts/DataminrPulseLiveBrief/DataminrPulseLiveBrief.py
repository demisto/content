import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


PANEL_NAME = "ReGenAI Live Brief"


def create_live_brief_html(live_brief_data: list, alert_url: str) -> str:
    """
    Create HTML content for the live brief.

    :type live_brief_data: ``list``
    :param live_brief_data: Live Brief data.

    :type alert_url: ``str``
    :param alert_url: Alert URL.

    :rtype: ``str``
    :return: HTML content for the live brief.
    """
    html_content = []

    for section in live_brief_data:
        timestamp = arg_to_datetime(section.get("timestamp", ""))
        summary = section.get("summary", "")
        time_html = f"<p>{timestamp.strftime('%d %b %Y, %I:%M %p UTC') if timestamp else timestamp}</p>"
        summary_html = f'<p style="margin:0; padding:0;">{summary}</p>'  # noqa: E231,E702
        html_content.append(time_html)
        html_content.append(summary_html)
        html_content.append("<hr>")

    incident_footer = (
        '<p style="margin:0; padding:0;">View latest in Dataminr Pulse: '  # noqa: E231,E702
        f'<a href="{alert_url}">{alert_url}</a>'
    )
    html_content.append(incident_footer)
    live_brief_html = "".join(html_content)
    return live_brief_html


def main():
    try:
        live_brief_data = demisto.incident().get("CustomFields", {}).get("dataminrpulselivebrief", "")
        alert_url = demisto.incident().get("CustomFields", {}).get("dataminrpulseexpandalerturl", "")
        theme = demisto.callingContext.get("context", {}).get("User", {}).get("theme", "")

        if not live_brief_data:
            return_results(
                {
                    "ContentsFormat": EntryFormat.HTML,
                    "Type": EntryType.NOTE,
                    "Contents": f'<h4 style="margin:10px 0;">{PANEL_NAME}</h4><p>N/A</p>',  # noqa: E231,E702
                }
            )
            return
        else:
            try:
                live_brief_data = json.loads(live_brief_data)
            except json.JSONDecodeError:
                raise ValueError('Failed to parse "Dataminr Pulse Live Brief" JSON string.')

        if isinstance(live_brief_data, dict):
            live_brief_data = [live_brief_data]

        live_brief_html = create_live_brief_html(live_brief_data, alert_url)

        html_content_start = (
            '<div style="background:{}; color:{}; '
            "border:2px solid {}; border-radius:5px; "
            'padding:10px; margin-top:10px; line-height:1.2; font-size:14px;">'
            '<h4 style="color:{};">'
            f"{PANEL_NAME}</h4>"
        )

        data = []
        if theme == "":
            html_content_start = html_content_start.format("", "", "#53DFCD", "")
        elif theme != "light":
            html_content_start = html_content_start.format("#082223", "#FFFFFF", "#53DFCD", "#53DFCD")
        else:
            html_content_start = html_content_start.format("#E9FBF9", "#000000", "#016558", "#016558")

        data.append(html_content_start)
        data.append(live_brief_html)
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

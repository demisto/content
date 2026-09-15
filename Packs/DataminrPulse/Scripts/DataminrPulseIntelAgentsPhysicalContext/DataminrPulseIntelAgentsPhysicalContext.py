import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


PANEL_NAME = "ReGenAI Intel Agents"


def create_intel_agents_html(intel_agents_summary: list, event_corroboration_summary: list, alert_url: str) -> str:
    """
    Create HTML content for the intel agents.

    :type intel_agents_summary: ``list``
    :param intel_agents_summary: Intel Agents summary data.

    :type event_corroboration_summary: ``list``
    :param event_corroboration_summary: Event Corroboration summary data.

    :type alert_url: ``str``
    :param alert_url: Alert URL.

    :rtype: ``str``
    :return: HTML content for the intel agent.
    """
    physical_intel_agent_summary = []

    for summary in intel_agents_summary:
        if "PHYSICAL" in summary.get("type", []):
            physical_intel_agent_summary.append(summary)

    if not physical_intel_agent_summary:
        return ""

    html_content = ['<h4 style="margin:0; padding:0;">Physical Context</h4>', '<div style="margin:10px 0;">']

    for section in physical_intel_agent_summary:
        title = section.get("title", "")
        contents = section.get("content", [])
        for content in contents:
            html_content.append('<div style="display:flex; align-items:flex-start;">')
            html_content.append('<div style="width:30px; text-align:center;">•</div>')
            html_content.append(f'<div style="flex:1;"><strong>{title}</strong>: {content}</div>')  # noqa: E231,E702
            html_content.append("</div>")

    html_content.append("</div>")

    if event_corroboration_summary:
        html_content.extend(['<h4 style="margin:0; padding:0;">Event Corroboration</h4>', '<div style="margin:10px 0;">'])

        for section in event_corroboration_summary:
            title = section.get("title", "")
            content = section.get("content", "")
            html_content.append('<div style="display:flex; align-items:flex-start;">')
            html_content.append('<div style="width:30px; text-align:center;">•</div>')
            html_content.append(f'<div style="flex:1;"><strong>{title}</strong>: {content}</div>')  # noqa: E231,E702
            html_content.append("</div>")

        html_content.append("</div>")

    incident_footer = (
        "<p>View more context, supporting information, and explore entities in Dataminr Pulse: "
        f'<a href="{alert_url}">{alert_url}</a>'
    )
    html_content.append(incident_footer)

    intel_agents_html = "".join(html_content)
    return intel_agents_html


def main():
    try:
        intel_agents_summary_data = demisto.incident().get("CustomFields", {}).get("dataminrpulseintelagentssummary", "")
        alert_url = demisto.incident().get("CustomFields", {}).get("dataminrpulseexpandalerturl", "")
        theme = demisto.callingContext.get("context", {}).get("User", {}).get("theme", "")
        event_corroboration_data = demisto.incident().get("CustomFields", {}).get("dataminrpulseeventcorroborationsummary", "")
        event_corroboration_summary = []

        if not intel_agents_summary_data:
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
                intel_agents_summary = json.loads(intel_agents_summary_data)
                if event_corroboration_data:
                    event_corroboration_summary = json.loads(event_corroboration_data)
            except json.JSONDecodeError:
                raise ValueError('Failed to parse "Dataminr Pulse Intel Agents Summary" JSON string.')

        if isinstance(intel_agents_summary, dict):
            intel_agents_summary = [intel_agents_summary]
        if isinstance(event_corroboration_summary, dict):
            event_corroboration_summary = [event_corroboration_summary]

        intel_agents_physical_context = create_intel_agents_html(intel_agents_summary, event_corroboration_summary, alert_url)

        if not intel_agents_physical_context:
            return_results(
                {
                    "ContentsFormat": EntryFormat.HTML,
                    "Type": EntryType.NOTE,
                    "Contents": f'<h4 style="margin:10px 0;">{PANEL_NAME}</h4><p>N/A</p>',  # noqa: E231,E702
                }
            )
            return

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
        data.append(intel_agents_physical_context)
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

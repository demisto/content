import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


PANEL_NAME = "ReGenAI Intel Agents Discovered Entities"
CYBER_ENTITY_TYPES = ["vulnerability", "threatActor", "malware"]


def create_discovered_entities_html(intel_agents_discovered_entities_data: list) -> str:
    """
    Create HTML content and Markdown for the discovered entities.

    :type intel_agents_discovered_entities_data: ``list``
    :param intel_agents_discovered_entities_data: Intel Agents Discovered Entities data.

    :rtype: ``str``
    :return: HTML content for the discovered entities.
    """
    intel_agents_discovered_entities_data = [
        item for item in intel_agents_discovered_entities_data if item.get("type") not in CYBER_ENTITY_TYPES
    ]

    if not intel_agents_discovered_entities_data:
        return ""

    html_content = [
        '<h4 style="margin:0; padding:0;">Discovered Entities '  # noqa: E231,E702
        f"({len(intel_agents_discovered_entities_data)})</h4>"
    ]

    for entity in intel_agents_discovered_entities_data:
        html_content.append(f'<div style="padding:6px 0;">{entity.get("name", "")}</div>')  # noqa: E231,E702

    discovered_entities_html = "".join(html_content)
    return discovered_entities_html


def main():
    try:
        intel_agents_discovered_entities_data = (
            demisto.incident().get("CustomFields", {}).get("dataminrpulseintelagentsdiscoveredentities", "")
        )
        theme = demisto.callingContext.get("context", {}).get("User", {}).get("theme", "")

        if not intel_agents_discovered_entities_data:
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
                intel_agents_discovered_entities_data = json.loads(intel_agents_discovered_entities_data)
            except json.JSONDecodeError:
                raise ValueError('Failed to parse "Dataminr Pulse Intel Agents Discovered Entities" JSON string.')

        if isinstance(intel_agents_discovered_entities_data, dict):
            intel_agents_discovered_entities_data = [intel_agents_discovered_entities_data]

        discovered_entities_html = create_discovered_entities_html(intel_agents_discovered_entities_data)

        if not discovered_entities_html:
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
        data.append(discovered_entities_html)
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

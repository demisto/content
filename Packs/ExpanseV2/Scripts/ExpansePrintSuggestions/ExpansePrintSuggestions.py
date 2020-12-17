import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

"""ExpansePrintSuggestions

"""

from typing import Dict, Any
import traceback


EXPANSE_LOGO = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAeIAAADFCAMAAAC/6QGrAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAJPUExURUdwTO"
    "nr7vn6+vv8/P39/fDx8fH38/7+/v7+/v////r6+/n7+v7+/v/+/v7+/v39/v3+/vf4+f39/fz9/P39/f7///z8/Pv499jd4f39/ff4+f39/klXbNbb3////6"
    "y1vv///+rs7v7+/srP1fv8/OHl5+Hk5vv7+/P09u7x88fO1Pv+/c/U2fz8/Pz8/Ons7ba9xfDy9IGOnPj5+vv7/J+ps73Eyt7i5fj5+ebo6s7V24+bpvPw8O"
    "zu8L7Gzs7U2ra/yKm0vtDV18XL0HiGlG9+jba8xG5+jj5TZvDy842YpMLJ0LrBx+Xp7bG5wK+4wp+qtd7j5zNIXr3EypWhrtLX24SRoP3u7lBidqartWx7i+"
    "Dj53+LlImWoezv8X6MmZGeq9XY3JagrFxsfoiVo4aToKOrs+/w8fvT0frS0jZKYUxgcamyuv3w7ytAV4+bphAnQjtPZS1CWkdZb5ikrSA1UPdwbB40Tx0zTi"
    "E2URsxTRowTCI4UhgvSh41UBYtSRMqRhAoRD9TaSU7VDdLYv///y5DWw4lQio/WNTa4FRmeQohPzJHXkpdcUZZbniGlXKBkWZ2h1prfU9hdTxQZkJVazlNZf"
    "doZPdsaLe/yMrR2PL092Fxg/z+/+fr78/W3K+5w/b5/H2KmW18jOHm652ptIiVooyZpcDI0KOuuPhuauzv8pGdqZeirwMcOdvg5aeyvISRnvZ5df/w7/eAfv"
    "/MyviLh//W1P/j4vZzb/menPiVkvZkX/67uPyzsf7DwQAQMPZva/atqv+qp/uqqRXzhNQAAAB1dFJOUwA0DRbMAwEGSx6LCY+mnnt1SJcQZVVfQFPt6oIF+G"
    "n99PovT/f6YNb36/0n+7C5i/h2/jnF9vvu4Vbh96ih6u7g5ZJf+fRQ3BXbXfei8oTx4uKVbeGs2u6ZDZV2FfrWo+hq9u3nlJq39S/U1NTe1PD599Tk7yu+2j"
    "kAAB1BSURBVHja7d3ndxTHtijwPhLdIyQjIRSJAoRkEMZkTLDBmOCHsQ1+OPs5huPj9+59595331aFjjM9SZOjcs6yEtngdA73nD/sfpDAYPX09My0wl2r6p"
    "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"
)

""" STANDALONE FUNCTION """


""" COMMAND FUNCTION """


def expanse_print_suggestions(args: Dict[str, Any]) -> CommandResults:
    ip = args.get("ip")
    port = args.get("port")
    fqdn = args.get("fqdn")
    expanse_users = argToList(args.get("expanse_users", []))
    expanse_devices = argToList(args.get("expanse_devices", []))
    expanse_ips = argToList(args.get("expanse_ips", []))
    expanse_issue_tags = argToList(args.get("expanse_issue_tags", []))
    expanse_asset_tags = argToList(args.get("expanse_asset_tags", []))
    expanse_business_units = argToList(args.get("expanse_business_units", []))
    shadow_it = argToList(args.get("shadow_it", []))
    provider = args.get("provider")
    region = args.get("region")
    service = args.get("service")
    prisma_cloud_assets = argToList(args.get("prisma_cloud_assets", []))

    md = f"![expanse_logo]({EXPANSE_LOGO})\n\n"

    md += f"# Expanse Attribution for service {ip}:{port}\n\n"

    md += "## Executive Summary\n\n"

    md += (
        "The Expanse Attribution Playbook has performed **enrichment** across several systems to help you determine the owner of"
        " this asset. Data has been searched in **Cortex Data Lake**, **Panorama**, **Prisma Cloud** and **Splunk**.\n\n The"
        " findings are reported in the following sections.\n"
    )

    md += "## Service Details\n\n"
    md += "Logs and asset information were searched for the following service:\n"
    md += tableToMarkdown(
        name="Service Information",
        t=[{"IP": ip, "port": port, "FQDN": fqdn}]
    )

    if provider:
        md += f"The asset has been attributed to the following provider: **{provider}**\n"

    if region:
        md += f"The IP address belongs to the following Public Cloud region: **{region}**\n"

    if service:
        md += f"The IP address belongs to the following Public Cloud service: **{service}**\n"
    md += "\n\n"

    if shadow_it and isinstance(shadow_it, list):
        md += "## Shadow IT\n\n"
        md += (
            "Based on the information above, the Playbook tries to determine whether this service is sanctioned or can be Shadow"
            " IT. The following conditions are checked:\n"
        )
        shadow = False
        for n, c in enumerate(shadow_it):
            if isinstance(c, dict) c.get('value')  is True:
                shadow_it[n]["result"] = "✅"
                shadow = True
            else:
                shadow_it[n]["result"] = "❌"
        md += tableToMarkdown("Shadow IT Conditions", shadow_it, headers=["condition", "result"], headerTransform=pascalToSpace)
        md += "\n\n"
        if shadow:
            md += "### Enrichment determined that this service **IS NOT** Shadow IT.\n"
        else:
            md += "### Enrichment determined that this service **MIGHT BE** Shadow IT.\n"
        md += "\n\n"

    md += "## Attribution\n\n"
    md += (
        "This section reports attribution information based on Expanse detected business units and tags for this issue and its"
        " related assets.\n\n"
    )
    if expanse_business_units:
        md += f'Business Units: **{", ".join(expanse_business_units)}**.'
    else:
        md += "No Business Units reported by Expanse for this Issue."
    md += "\n\n"
    if expanse_issue_tags:
        md += f'Issue Tags: **{", ".join(expanse_issue_tags)}**.'
    else:
        md += "No relevant tags reported by Expanse for this Issue."
    md += "\n\n"
    if expanse_asset_tags:
        md += f'Related Asset Tags: **{", ".join(expanse_asset_tags)}**.'
    else:
        md += "No relevant tags reported by Expanse for assets related to this Issue."
    md += "\n\n"

    md += "## Detected users connecting to this service\n\n"
    md += (
        "The enrichment correlates log information from Firewalls with UserID enabled. If users from within your corporate"
        " network or **Prisma Access** are connecting to this service, they will appear in the following table.\n\n"
    )
    if expanse_users and isinstance(expanse_users, list):
        for n, u in enumerate(expanse_users):
            if not isinstance(u, dict):
                continue
            if (groups := u.get("groups", [])) and isinstance(groups, list):
                for m, g in enumerate(groups):
                    f = re.search("CN=([^,]*),*", g)
                    if f:
                        expanse_users[n]["groups"][m] = str(f.groups(0)[0])
            if (manager := u.get("manager", [])) and isinstance(manager, str):
                f = re.search("CN=([^,]*),*", manager)
                if f:
                    expanse_users[n]["manager"] = str(f.groups(0)[0])
        md += tableToMarkdown(
            name="Detected users connecting to this service",
            t=expanse_users,
            headers=["username", "domain", "mail", "groups", "manager", "sightings"],
            headerTransform=pascalToSpace,
        )
    else:
        md += "*No user evidence found in logs.*\n"
    md += "\n\n"

    md += "## Top IPs communicating to this service\n\n"
    md += (
        "The enrichment correlates log information from Firewalls that terminate connections on this service. If any firewall"
        " that is sending logs to Panorama, Cortex Data lake or Splunk is seeing traffic to this service from any network,"
        " the information will be reported. The top talkers that are connecting to this service are displayed in the following"
        " table.\n\n"
    )
    if expanse_ips and isinstance(expanse_ips, list) and all(isinstance(x, dict) for x in expanse_ips):
        md += tableToMarkdown(
            name="Top IPs communicating to this service",
            t=expanse_ips,
            headers=["ip", "internal", "sightings"],
            headerTransform=pascalToSpace
        )
    else:
        md += "*No IP evidence found in logs.*\n"
    md += "\n\n"

    md += "## PAN-OS Firewalls with sightings\n\n"
    md += (
        "The enrichment correlates log information from Firewalls that terminate connections on this service. If any firewall"
        " that is sending logs to Panorama, Cortex Data lake or Splunk is seeing traffic to this service, they will be reported"
        " in the following table.\n\n"
    )
    if expanse_devices and isinstance(expanse_devices, list) and all(isinstance(x, dict) for x in expanse_devices):
        md += tableToMarkdown(
            name="PAN-OS Firewalls",
            t=expanse_devices,
            headers=["serial", "vsys", "device-group", "exposing_service", "expanse-tag", "sightings"],
            headerTransform=pascalToSpace
        )
        md += (
            "(*) ***exposing_service*** *means that Firewall logs were found where the destination IP:port corresponds to this"
            " service, and the source is a non-private IP. Such Firewalls are likely to be protecting the service.*"
        )
    else:
        md += "*No PAN-OS devices found in logs.*\n"
    md += "\n\n"

    md += "## Prisma Cloud Inventory\n\n"
    md += (
        "The enrichment correlates asset information from Prisma Cloud inventory, searching for assets that own the IP address or"
        " the FQDN. If found, the cloud asset details are reported in the following table.\n\n"
    )
    if prisma_cloud_assets and isinstance(prisma_cloud_assets, list) and all(isinstance(x, dict) for x in prisma_cloud_assets):
        md += tableToMarkdown(
            name="Asset information from Prisma Cloud inventory",
            t=prisma_cloud_assets,
            headers=[
                "cloudType",
                "service",
                "regionId",
                "accountName",
                "accountId",
                "resourceType",
                "resourceName",
                "ip",
                "fqdn",
                "rrn",
                "id",
            ],
            headerTransform=pascalToSpace,
        )
    else:
        md += "*The asset was not found in Prisma Cloud inventory.*\n"
    md += "\n\n"

    return CommandResults(
        readable_output=md,
        outputs=None,
    )


""" MAIN FUNCTION """


def main():
    try:
        return_results(expanse_print_suggestions(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute ExpansePrintSuggestions. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

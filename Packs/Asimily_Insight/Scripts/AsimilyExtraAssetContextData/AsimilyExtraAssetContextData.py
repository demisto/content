import demistomock as demisto  # noqa: F401
from CommonServerPython import *

ASIMILY_ASSET_CONTEXT_OUTPUT_KEY_ORDER = [
    "asimilydeviceid",
    "asimilydevicemacaddress",
    "asimilydeviceipv4address",
    "asimilydevicemanufacturer",
    "asimilydevicemodel",
    "asimilydevicehostname",
    "asimilydeviceos",
    "asimilydeviceosversion",
    "asimilydevicetype",
    "asimilydeviceserialnumber",
    "asimilydevicefamilies",
    "asimilydevicetag",
    "asimilydevicedepartment",
    "asimilydevicefacility",
    "asimilydevicehardwarearchitecture",
    "asimilydevicelocation",
    "asimilydeviceregion",
    "asimilydevicesoftwareverison",
    "asimilydeviceifstoreephi",
    "asimilydeviceiftransmitephi",
    "asimilydeviceifusingendpointsecurity",
    "asimilydeviceriskscore",
    "asimilydevicelikelihood",
    "asimilydeviceimpact",
    "asimilydeviceaverageutilizationpercent",
    "asimilydeviceuptime",
    "asimilydeviceisconnected",
    "asimilydeviceiscurrentlyinuse",
    "asimilydeviceisnetworkingdevice",
    "asimilydeviceiswireless",
    "asimilydeviceclass",
    "asimilydevicemanagedby",
    "asimilydeviceanomalypresent",
    "asimilydevicemds2",
    "asimilydevicecmmsid",
    "asimilydevicelastdiscoveredtime",
    "asimilydevicemasterfamily",
    "asimilydevicediscoverysource",
    "asimilydeviceapplications",
    "asimilydeviceurl",
    "asimilydeviceipv6address",
]


def main():
    try:
        context_data = demisto.context().get("AsimilyInsight", {}).get("Asset", {})
        table = tableToMarkdown("Asset Details", context_data, headers=ASIMILY_ASSET_CONTEXT_OUTPUT_KEY_ORDER)
        return_results(
            CommandResults(readable_output=table, outputs_prefix="AsimilyInsight.Asset", outputs_key_field="asimilydeviceid")
        )
    except Exception as ex:
        return_error(f"Failed to execute AsimilyExtraAssetContextData. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

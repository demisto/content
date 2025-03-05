import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import sys
from re import escape


FILTER_CONFIG_PATH = "/opt/WCG/config/filter.config"
CMD_DEL_RULE_FORMAT = "sed -i '/^{0}={1} action=[A-Za-z]*$/d' {2}"
CMD_TRITON_RELOAD_CONFIG = "/opt/WCG/bin/content_line -x"  # && /opt/WCG/WCGAdmin runds"
ALLOWED_TYPES = ["dest_domain", "dest_ip", "dest_host", "url_regex"]


def delete_rule(ruleType):
    if ruleType not in ALLOWED_TYPES:
        demisto.results(
            {
                "Type": entryTypes["error"],
                "ContentsFormat": formats["text"],
                "Contents": 'Type argument must be "dest_domain", "dest_ip", "dest_host" or "url_regex".'
                " Invalid value: " + ruleType,
            }
        )
    else:
        valueFormat = escape(demisto.args()["value"])
        if ruleType in ["dest_domain", "url_regex"]:
            valueFormat = r"\"" + valueFormat + r"\""
        # sed command that deletes the rule
        cmdDelRule = CMD_DEL_RULE_FORMAT.format(ruleType, valueFormat, FILTER_CONFIG_PATH)
        sshArgs = {"cmd": cmdDelRule + " && " + CMD_TRITON_RELOAD_CONFIG}
        if "tritonsystem" in demisto.args():
            if "remoteaccessname" in demisto.args():
                demisto.results(
                    {
                        "Type": entryTypes["error"],
                        "ContentsFormat": formats["markdown"],
                        "Contents": "You cannot uses both **tritonsystem** and " "**remoteaccessname**. Please choose one.",
                    }
                )
                return
            sshArgs["system"] = demisto.args()["tritonsystem"]
        elif "remoteaccessname" in demisto.args():
            sshArgs["using"] = demisto.args()["remoteaccessname"]
        else:
            demisto.results(
                {
                    "Type": entryTypes["error"],
                    "ContentsFormat": formats["markdown"],
                    "Contents": "You must provide either **tritonsystem** or" " **remoteaccessname** as arguments.",
                }
            )
            return
        if "using" in sshArgs or "system" in sshArgs:
            resSSH = demisto.executeCommand("ssh", sshArgs)
            if not isError(resSSH[0]) and demisto.gets(resSSH[0], "Contents.success"):
                demisto.results("Command executed successfully.")
            else:
                demisto.results(resSSH)


def main():  # pragma: no cover
    ruleType = demisto.args()["type"]
    delete_rule(ruleType)
    sys.exit(0)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

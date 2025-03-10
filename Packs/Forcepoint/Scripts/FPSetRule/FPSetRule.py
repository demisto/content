import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from re import escape


FILTER_CONFIG_PATH = "/opt/WCG/config/filter.config"
CMD_SET_RULE_FORMAT = (
    "sed -i '/^{0}={1} action=/{{h;s/{0}={1} action=[A-Za-z]*$/{0}={1} action={2}/}};${{x;/^$/{{"
    "s//{0}={1} action={2}/;H}};x}}' {3} "
)
CMD_TRITON_RELOAD_CONFIG = "/opt/WCG/bin/content_line -x"  # && /opt/WCG/WCGAdmin runds"
ALLOWED_TYPES = ["dest_domain", "dest_ip", "dest_host", "url_regex"]


def set_rule(policy, ruleType):
    if policy not in ["allow", "deny"]:
        demisto.results(
            {
                "Type": entryTypes["error"],
                "ContentsFormat": formats["text"],
                "Contents": 'Policy argument must be "allow" or "deny". Invalid value: ' + policy,
            }
        )
    elif ruleType not in ALLOWED_TYPES:
        demisto.results(
            {
                "Type": entryTypes["error"],
                "ContentsFormat": formats["text"],
                "Contents": 'Type argument must be "dest_domain", "dest_ip", "dest_host" or "url_regex". '
                "Invalid value: " + ruleType,
            }
        )
    else:
        valueFormat = escape(demisto.args()["value"])
        if ruleType in ["dest_domain", "url_regex"]:
            valueFormat = r"\"" + valueFormat + r"\""
        # sed command that modifies the action of the rule if found, otherwise it adds it in a new line
        cmdSetRule = CMD_SET_RULE_FORMAT.format(ruleType, valueFormat, policy, FILTER_CONFIG_PATH)
        sshArgs = {"cmd": cmdSetRule + " && " + CMD_TRITON_RELOAD_CONFIG}
        if "tritonsystem" in demisto.args():
            if "remoteaccessname" in demisto.args():
                demisto.results(
                    {
                        "Type": entryTypes["error"],
                        "ContentsFormat": formats["markdown"],
                        "Contents": "You cannot uses both **tritonsystem** and **remoteaccessname**. " "Please choose one.",
                    }
                )
                sys.exit(0)
            sshArgs["system"] = demisto.args()["tritonsystem"]
        elif "remoteaccessname" in demisto.args():
            sshArgs["using"] = demisto.args()["remoteaccessname"]
        else:
            demisto.results(
                {
                    "Type": entryTypes["error"],
                    "ContentsFormat": formats["markdown"],
                    "Contents": "You must provide either **tritonsystem** or **remoteaccessname** " "as arguments.",
                }
            )
            sys.exit(0)
        if "using" in sshArgs or "system" in sshArgs:
            resSSH = demisto.executeCommand("ssh", sshArgs)
            if not isError(resSSH[0]) and demisto.gets(resSSH[0], "Contents.success"):
                demisto.results("Command executed successfully.")
            else:
                demisto.results(resSSH)


def main():  # pragma: no cover
    policy = demisto.args()["policy"]
    ruleType = demisto.args()["type"]
    set_rule(policy, ruleType)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

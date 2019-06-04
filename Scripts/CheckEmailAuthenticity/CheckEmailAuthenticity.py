import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import re
import traceback

'''HELPER FUNCTIONS'''


def get_spf(auth, spf):
    spf_context = {}
    if auth is None:
        spf_context["Validation-Result"] = spf.split(" ")[0].lower()
        sender_ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", spf)
    else:
        result = re.search(r"spf=(\w+)", auth)
        if result is not None:
            spf_context["Validation-Result"] = result.group(1).lower()
        sender_ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", auth)
    if sender_ip != []:
        spf_context["Sender-IP"] = sender_ip[0]
    if spf is not None:
        spf_context["Reason"] = re.findall(r"[(](.+)[)]", spf)[0]
    return spf_context


def get_dkim(auth):
    dkim_context = {}
    if auth is not None:
        result = re.search(r"dkim=(\w+)", auth)
        if result is not None:
            dkim_context["Validation-Result"] = result.group(1).lower()
        reason = re.search("dkim=\w+ [(](.+?)[)]", auth)
        if reason is not None:
            dkim_context["Reason"] = reason.group(1)
        domain = re.findall("dkim=[\w\W]+?[=@](\w+\.[^ ]+)", auth)
        if domain != []:
            dkim_context["Signing-Domain"] = domain[0]
    return dkim_context


def get_dmarc(auth):
    dmarc_context = {}
    if auth is not None:
        result = re.search(r"dmarc=(\w+)", auth)
        if result is not None:
            dmarc_context["Validation-Result"] = result.group(1).lower()
        reason = re.findall("dmarc=\w+ [(](.+?)[)]", auth)
        if reason != []:
            tags = reason[0]
            tags_data = {}
            for tag in tags.split(" "):
                values = tag.split("=")
                tags_data[values[0]] = values[1]
            dmarc_context["Tags"] = tags_data
        domain = re.findall("dmarc=[\w\W]+header.from=(\w+\.[^ ]+)", auth)
        if domain != []:
            dmarc_context["Signing-Domain"] = domain[0]
    return dmarc_context


def auth_check(spf_data, dkim_data, dmarc_data, override_dict):
    spf = spf_data.get('Validation-Result')
    dmarc = dmarc_data.get('Validation-Result')
    dkim = dkim_data.get('Validation-Result')

    if "spf-{}".format(spf) in override_dict:
        return override_dict.get("spf-{}".format(spf))
    if "dkim-{}".format(dkim) in override_dict:
        return override_dict.get("dkim-{}".format(dkim))
    if "dmarc-{}".format(dmarc) in override_dict:
        return override_dict.get("dmarc-{}".format(dmarc))

    if spf == 'fail' or dkim == 'fail' or dmarc == 'fail':
        return "Fail"
    if spf == 'softfail' or dkim == 'policy':
        return "Suspicious"
    undetermined = [None, "none", "temperror", "permerror"]
    if dmarc in undetermined or spf in undetermined or dkim in undetermined \
            or dkim == "neutral":
        return "Undetermined"
    return "Pass"


'''MAIN FUNCTION'''

try:
    headers = argToList(demisto.args().get("headers"))

    auth = None
    spf = None
    message_id = ""

    # getting override options from user
    override_dict = {}

    override_options = ["fail", "suspicious", "undetermined", "pass", "Fail", "Suspicious", "Undetermined", "Pass"]

    override = demisto.args().get("SPF_override_none")
    if override in override_options:
        override_dict["spf-none"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("SPF_override_neutral")
    if override in override_options:
        override_dict["spf-neutral"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("SPF_override_pass")
    if override in override_options:
        override_dict["spf-pass"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("SPF_override_fail")
    if override in override_options:
        override_dict["spf-fail"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("SPF_override_softfail")
    if override in override_options:
        override_dict["spf-softfail"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("SPF_override_temperror")
    if override in override_options:
        override_dict["spf-temperror"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("SPF_override_perm")
    if override in override_options:
        override_dict["spf-permerror"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DKIM_override_none")
    if override in override_options:
        override_dict["dkim-none"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DKIM_override_pass")
    if override in override_options:
        override_dict["dkim-pass"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DKIM_override_fail")
    if override in override_options:
        override_dict["dkim-fail"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DKIM_override_policy")
    if override in override_options:
        override_dict["dkim-policy"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DKIM_override_neutral")
    if override in override_options:
        override_dict["dkim-neutral"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DKIM_override_temperror")
    if override in override_options:
        override_dict["dkim-temperror"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DKIM_override_permerror")
    if override in override_options:
        override_dict["dkim-permerror"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DMARC_override_none")
    if override in override_options:
        override_dict["dmarc-none"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DMARC_override_pass")
    if override in override_options:
        override_dict["dmarc-pass"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DMARC_override_fail")
    if override in override_options:
        override_dict["dmarc-fail"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DMARC_override_temperror")
    if override in override_options:
        override_dict["dmarc-temperror"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")

    override = demisto.args().get("DMARC_override_permerror")
    if override in override_options:
        override_dict["dmarc-permerror"] = override.lower()
    else:
        if override is not None:
            return_error("Invaild override input.")
    # done override options

    for header in headers:
        if isinstance(header, dict):
            if header.get('name') == "Authentication-Results":
                auth = header.get('value')
            if header.get('name') == "Received-SPF":
                spf = header.get('value')
            if header.get('name') == 'Message-ID':
                message_id = header.get('value')

    email_key = "Email(val.Headers.filter(function(header) { return header && header.name ===" \
                " 'Message-ID' && header.value === '%s';}))" % \
                (message_id)

    if auth is None and spf is None:
        context = {
            "{}.AuthenticityCheck".format(email_key): "undetermined"
        }
        return_outputs("No header information was found.", context)
        sys.exit(0)
    spf_data = get_spf(auth, spf)
    dkim_data = get_dkim(auth)
    dmarc_data = get_dmarc(auth)

    authenticity = auth_check(spf_data, dkim_data, dmarc_data, override_dict)

    md = "This Email's authenticity is: **{}**\n".format(authenticity)
    md = md + tableToMarkdown("SPF", spf_data, ["Validation-Result", "Reason", "Sender-IP"])
    md = md + tableToMarkdown("DKIM", dkim_data, ["Validation-Result", "Reason", "Signing-Domain"])
    md = md + tableToMarkdown("DMARC", dmarc_data, ["Validation-Result", "Tags", "Signing-Domain"])

    ec = {
        "{}.SPF".format(email_key): spf_data,
        "{}.DMARC".format(email_key): dmarc_data,
        "{}.DKIM".format(email_key): dkim_data,
        "{}.AuthenticityCheck".format(email_key): authenticity
    }
    return_outputs(md, ec)

except Exception as ex:
    demisto.error(str(ex) + "\n\nTrace:\n" + traceback.format_exc())
    return_error(ex.message)

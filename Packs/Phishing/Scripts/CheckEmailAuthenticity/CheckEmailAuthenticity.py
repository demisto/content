import re
import traceback
from email.parser import HeaderParser

import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *

"""HELPER FUNCTIONS"""


def _headers_from_mapping(headers: dict) -> list[dict]:
    """
    Convert a HeadersMap object into a list of {name, value} entries.
    A single key may hold several values (for example a Received header per hop),
    in which case each value becomes its own entry.
    """
    normalized: list[dict] = []
    for name, value in headers.items():
        values = value if isinstance(value, list) else [value]
        normalized.extend({"name": str(name), "value": item} for item in values)
    return normalized


def _headers_from_string(headers: str) -> list[dict]:
    """
    Parse a raw header block into a list of {name, value} entries.
    An email parser is used so that folded (multi line) values are joined correctly
    and values containing commas are kept intact.
    """
    parsed = HeaderParser().parsestr(headers)
    return [{"name": name, "value": value} for name, value in parsed.items()]


def normalize_headers(headers: Any) -> list[dict]:
    """
    Normalize the supported header containers into a single list of {name, value} entries.

    'ParseEmailFilesV2' deprecated the 'Email.Headers' list in favor of the 'Email.HeadersMap'
    object, so the headers may arrive as a list of {name, value} entries, as a HeadersMap
    object, or as the raw header block. Normalizing them here keeps the rest of the script
    working with a single structure, regardless of the integration that fetched the email.

    Args:
        headers: The headers argument given by the user, in any of the supported containers.

    Returns:
        A list of {name, value} entries. An empty list is returned when there are no headers.
    """
    if not headers:
        return []

    if isinstance(headers, dict):
        return _headers_from_mapping(headers)

    if isinstance(headers, str):
        return _headers_from_string(headers)

    if isinstance(headers, list):
        normalized_list: list[dict] = []
        for header in headers:
            if isinstance(header, dict) and "name" in header:
                normalized_list.append({"name": str(header.get("name")), "value": header.get("value")})
            elif isinstance(header, dict):
                normalized_list.extend(_headers_from_mapping(header))
            elif isinstance(header, str):
                normalized_list.extend(_headers_from_string(header))
        return normalized_list

    return []


def get_spf(auth, spf):
    """
    Get SPF validation information
    :param auth: authentication header value (if exist), contains the validation result and sender ip.
    :param spf: spf header value (if exist), contains the validation result and sender ip.
    :return: SPF validation information
    """
    spf_context = {"Validation-Result": "Unspecified", "Sender-IP": "Unspecified", "Reason": "Unspecified"}
    if auth is None:
        spf_context["Validation-Result"] = spf.split(" ")[0].lower()
        sender_ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", spf)
    else:
        result = re.search(r"spf=(\w+)", auth)
        if result is not None:
            spf_context["Validation-Result"] = result.group(1).lower()
        sender_ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", auth)
    if sender_ip:
        spf_context["Sender-IP"] = sender_ip[0]
    if spf is not None:
        if reason := re.findall(r"\((.+)\)", spf):
            spf_context["Reason"] = reason[0]
        else:
            reason = spf.split(" ", 1)
            spf_context["Reason"] = reason[1] if len(reason) > 1 else ""

    return spf_context


def get_dkim(auth):
    """
    Get DKIM validation information
    :param auth: authentication header value (if exist), contains the validation result.
    :return: DKIM validation information
    """
    dkim_context = {"Validation-Result": "Unspecified", "Signing-Domain": "Unspecified"}
    if auth is not None:
        result = re.search(r"dkim=(\w+)", auth)
        if result is not None:
            dkim_context["Validation-Result"] = result.group(1).lower()
        reason = re.search(r"dkim=\w+ \((.+?)\)", auth)
        if reason is not None:
            dkim_context["Reason"] = reason.group(1)
        domain = re.findall(r"dkim=[\w\W]+?[=@](\w+\.[^ ]+)", auth)
        if domain:
            dkim_context["Signing-Domain"] = domain[0]
    return dkim_context


def get_dmarc(auth):
    """
    Get DMARC validation information
    :param auth: authentication header value (if exist), contains the validation result and sender ip.
    :return: DMARC validation information
    """
    dmarc_context = {"Validation-Result": "Unspecified", "Tags": {"Unspecified": "Unspecified"}, "Signing-Domain": "Unspecified"}
    if auth is not None:
        result = re.search(r"dmarc=(\w+)", auth)
        if result is not None:
            dmarc_context["Validation-Result"] = result.group(1).lower()
        reason = re.findall(r"dmarc=\w+ \((.+?)\)", auth)
        if reason:
            tags = reason[0]
            tags_data = {}
            for tag in tags.split(" "):
                values = tag.split("=")
                tags_data[values[0]] = values[1]
            dmarc_context["Tags"] = tags_data
        domain = re.findall(r"dmarc=.+header.from=([\w-]+\.[^; ]+)", auth)
        if domain:
            dmarc_context["Signing-Domain"] = domain[0]
    return dmarc_context


def auth_check(spf_data, dkim_data, dmarc_data, override_dict):
    spf = spf_data.get("Validation-Result")
    dmarc = dmarc_data.get("Validation-Result")
    dkim = dkim_data.get("Validation-Result")

    if f"spf-{spf}" in override_dict:
        return override_dict.get(f"spf-{spf}")
    if f"dkim-{dkim}" in override_dict:
        return override_dict.get(f"dkim-{dkim}")
    if f"dmarc-{dmarc}" in override_dict:
        return override_dict.get(f"dmarc-{dmarc}")

    if "fail" in [spf, dkim, dmarc]:
        return "Fail"
    if spf == "softfail" or dkim == "policy":
        return "Suspicious"
    undetermined = [None, "none", "temperror", "permerror"]
    if dmarc in undetermined or spf in undetermined or dkim in undetermined or dkim == "neutral":
        return "Undetermined"
    return "Pass"


def get_authentication_value(headers, original_authentication_header):
    """
    Handles the case where the authentication header is given under a different header.
    This header is represented by the 'original_authentication_header' argument.
    This can happen when an intermediate server changes the email and holds the original value of the header
    in a different header.
    For more info, see issue #46364.
    Args:
        headers: The headers dict argument given by the user
        original_authentication_header: The name of a header which holds the original value of the
        Authentication-Results header.

    Returns:
        The suitable authenticator header.

    """
    header_dict = {str(header.get("name")).lower(): header.get("value") for header in headers if isinstance(header, dict)}
    if original_authentication_header and original_authentication_header in header_dict:
        authentication_value = header_dict[original_authentication_header]
    else:
        authentication_value = header_dict.get("authentication-results")

    return authentication_value


"""MAIN FUNCTION"""


def main():
    try:
        args = demisto.args()
        raw_headers = args.get("headers")
        headers = normalize_headers(raw_headers)
        if raw_headers and not headers:
            demisto.debug(f"CheckEmailAuthenticity: could not read any header from a {type(raw_headers).__name__} input.")
        original_authentication_header = args.get("original_authentication_header", "").lower()
        auth = get_authentication_value(headers, original_authentication_header)
        spf = None
        message_id = ""

        # getting override options from user
        override_dict = {}

        override_options = ["fail", "suspicious", "undetermined", "pass", "Fail", "Suspicious", "Undetermined", "Pass"]

        override_fields = {
            "SPF_override_none": "spf-none",
            "SPF_override_neutral": "spf-neutral",
            "SPF_override_pass": "spf-pass",
            "SPF_override_fail": "spf-fail",
            "SPF_override_softfail": "spf-softfail",  # disable-secrets-detection
            "SPF_override_temperror": "spf-temperror",
            "SPF_override_perm": "spf-permerror",
            "DKIM_override_none": "dkim-none",
            "DKIM_override_pass": "dkim-pass",
            "DKIM_override_fail": "dkim-fail",
            "DKIM_override_policy": "dkim-policy",
            "DKIM_override_neutral": "dkim-neutral",  # disable-secrets-detection
            "DKIM_override_temperror": "dkim-temperror",
            "DKIM_override_permerror": "dkim-permerror",
            "DMARC_override_none": "dmarc-none",
            "DMARC_override_pass": "dmarc-pass",
            "DMARC_override_fail": "dmarc-fail",
            "DMARC_override_temperror": "dmarc-temperror",
            "DMARC_override_permerror": "dmarc-permerror",
        }

        for field, value in override_fields.items():
            override = args.get(field)
            if override in override_options:
                override_dict[value] = override.lower()
            else:
                if override is not None:
                    return_error(
                        f"Invalid override input for argument {field}: got {override}, expected one of {override_options}."
                    )

        for header in headers:
            if isinstance(header, dict):
                if str(header.get("name")).lower() == "received-spf":
                    spf = header.get("value")
                if str(header.get("name")).lower() == "message-id":
                    message_id = header.get("value")  # type: ignore

        email_key = (
            "Email(val.Headers.filter(function(header) { return header && header.name === 'Message-ID' && "
            f"header.value === '{message_id}';}}))"
        )

        if not auth and not spf:
            demisto.debug(
                f"CheckEmailAuthenticity: no Authentication-Results or Received-SPF header found "
                f"in {len(headers)} header(s), the authenticity check is undetermined."
            )
            context = {f"{email_key}.AuthenticityCheck": "undetermined"}
            return_outputs("No header information was found.", context)
            sys.exit(0)
        spf_data = get_spf(auth, spf)
        dkim_data = get_dkim(auth)
        dmarc_data = get_dmarc(auth)

        authenticity = auth_check(spf_data, dkim_data, dmarc_data, override_dict)

        md = f"Email's authenticity is: **{authenticity}**\n"
        md += tableToMarkdown("SPF", spf_data, ["Validation-Result", "Reason", "Sender-IP"])
        md += tableToMarkdown("DKIM", dkim_data, ["Validation-Result", "Reason", "Signing-Domain"])
        md += tableToMarkdown("DMARC", dmarc_data, ["Validation-Result", "Tags", "Signing-Domain"])

        ec = {
            f"{email_key}.SPF": spf_data,
            f"{email_key}.DMARC": dmarc_data,
            f"{email_key}.DKIM": dkim_data,
            f"{email_key}.AuthenticityCheck": authenticity,
        }
        return_outputs(md, ec)

    except Exception as ex:
        demisto.error(str(ex) + "\n\nTrace:\n" + traceback.format_exc())
        return_error(str(ex))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

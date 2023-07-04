import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import random
import time
import urllib3
import requests

# disable insecure warnings
urllib3.disable_warnings()

""" GLOBAL VARS """
ADD = "ADD_TO_LIST"
REMOVE = "REMOVE_FROM_LIST"
INTEGRATION_NAME = "Zscaler"
SUSPICIOUS_CATEGORIES = ["SUSPICIOUS_DESTINATION", "SPYWARE_OR_ADWARE"]
CLOUD_NAME = demisto.params()["cloud"]
USERNAME = demisto.params()["credentials"]["identifier"]
PASSWORD = demisto.params()["credentials"]["password"]
API_KEY = str(demisto.params().get("creds_key", {}).get("password", "")) or str(
    demisto.params().get("key", "")
)
if not API_KEY:
    raise Exception("API Key is missing. Please provide an API Key.")
BASE_URL = CLOUD_NAME + "/api/v1"
USE_SSL = not demisto.params().get("insecure", False)
PROXY = demisto.params().get("proxy", True)
REQUEST_TIMEOUT = int(demisto.params().get("requestTimeout", 15))
DEFAULT_HEADERS = {"content-type": "application/json"}
EXCEEDED_RATE_LIMIT_STATUS_CODE = 429
MAX_SECONDS_TO_WAIT = 100
SESSION_ID_KEY = "session_id"
ERROR_CODES_DICT = {
    400: "Invalid or bad request",
    401: "Session is not authenticated or timed out",
    403: "One of the following permission errors occurred:\n-The API key was disabled by your service provider\n"
    "-User role has no access permissions or functional scope\n-A required SKU subscription is missing\n"
    "Contact support or your account team for assistance.",
    404: "Resource does not exist",
    409: "Request could not be processed because of possible edit conflict occurred. Another admin might be saving a "
    "configuration change at the same time. In this scenario, the client is expected to retry after a short "
    "time period.",
    406: "Not Acceptable",
    415: "Unsupported media type.",
    429: "Exceeded the rate limit or quota.",
    500: "Unexpected error",
    503: "Service is temporarily unavailable",
}
AUTO_ACTIVATE_CHANGES_COMMANDS = (
    "zscaler-blacklist-url",
    "zscaler-undo-blacklist-url",
    "zscaler-whitelist-url",
    "zscaler-undo-whitelist-url",
    "zscaler-blacklist-ip",
    "zscaler-undo-blacklist-ip",
    "zscaler-whitelist-ip",
    "zscaler-undo-whitelist-ip",
    "zscaler-category-add-url",
    "zscaler-category-add-ip",
    "zscaler-category-remove-url",
    "zscaler-category-remove-ip",
    "zscaler-list-ip-destination-groups",
    "zscaler-edit-ip-destination-groups",
    "zscaler-create-ip-destination-group",
    "zscaler-delete-ip-destination-groups",
)

""" HANDLE PROXY """
# Remove proxy if not set to true in params
handle_proxy()

""" HELPER CLASSES """


class AuthorizationError(DemistoException):
    """Error to be raised when 401/403 headers are present in http response"""


""" HELPER FUNCTIONS """


def http_request(method, url_suffix, data=None, headers=None, num_of_seconds_to_wait=3):
    if headers is None:
        headers = DEFAULT_HEADERS
    data = {} if data is None else data
    url = BASE_URL + url_suffix
    try:
        res = requests.request(
            method,
            url,
            verify=USE_SSL,
            data=data,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        if res.status_code not in (200, 204):
            if (
                res.status_code == EXCEEDED_RATE_LIMIT_STATUS_CODE
                and num_of_seconds_to_wait <= MAX_SECONDS_TO_WAIT
            ):
                random_num_of_seconds = random.randint(
                    num_of_seconds_to_wait, num_of_seconds_to_wait + 3
                )
                time.sleep(random_num_of_seconds)  # pylint: disable=sleep-exists
                return http_request(
                    method,
                    url_suffix,
                    data,
                    headers=headers,
                    num_of_seconds_to_wait=num_of_seconds_to_wait + 3,
                )
            elif res.status_code in (401, 403):
                raise AuthorizationError(res.content)
            elif (
                res.status_code == 400
                and method == "PUT"
                and "/urlCategories/" in url_suffix
            ):
                raise Exception(
                    "Bad request, This could be due to reaching your organizations quota."
                    " For more info about your quota usage, run the command zscaler-url-quota."
                )
            else:
                if res.status_code in ERROR_CODES_DICT:
                    raise Exception(
                        "Your request failed with the following error: {}.\nMessage: {}".format(
                            ERROR_CODES_DICT[res.status_code], res.text
                        )
                    )
                else:
                    raise Exception(
                        "Your request failed with the following error: {}.\nMessage: {}".format(
                            res.status_code, res.text
                        )
                    )
    except Exception as e:
        LOG(
            "Zscaler request failed with url={url}\tdata={data}".format(
                url=url, data=data
            )
        )
        LOG(e)
        raise e
    return res


def validate_urls(urls):
    for url in urls:
        if url.startswith(("http://", "https://")):
            return_error(
                "Enter a valid URL address without an http:// or https:// prefix. URL should have at least host."
                "domain pattern to qualify."
            )


""" FUNCTIONS """


def login():
    """
    Try to use integration context if available and valid, otherwise create new session
    """
    cmd_url = "/authenticatedSession"

    def obfuscateApiKey(seed):
        now = str(int(time.time() * 1000))
        n = now[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        for i in range(0, len(n), 1):
            key += seed[int(n[i])]
        for j in range(0, len(r), 1):
            key += seed[int(r[j]) + 2]
        return now, key

    ctx = get_integration_context() or {}
    session_id = ctx.get(SESSION_ID_KEY)
    if session_id:
        DEFAULT_HEADERS["cookie"] = session_id
        try:
            return test_module()
        except AuthorizationError as e:
            demisto.info(
                "Zscaler encountered an authentication error.\nError: {}".format(str(e))
            )
    ts, key = obfuscateApiKey(API_KEY)
    data = {"username": USERNAME, "timestamp": ts, "password": PASSWORD, "apiKey": key}
    json_data = json.dumps(data)
    result = http_request("POST", cmd_url, json_data, DEFAULT_HEADERS)
    auth = result.headers["Set-Cookie"]
    ctx[SESSION_ID_KEY] = DEFAULT_HEADERS["cookie"] = auth[: auth.index(";")]
    set_integration_context(ctx)
    return test_module()


def activate_changes():
    cmd_url = "/status/activate"
    return http_request("POST", cmd_url, None, DEFAULT_HEADERS)


def logout():
    cmd_url = "/authenticatedSession"
    return http_request("DELETE", cmd_url, None, DEFAULT_HEADERS)


def blacklist_url(url):
    urls_to_blacklist = argToList(url)
    validate_urls(urls_to_blacklist)
    cmd_url = "/security/advanced/blacklistUrls?action=ADD_TO_LIST"
    data = {"blacklistUrls": urls_to_blacklist}
    json_data = json.dumps(data)
    http_request("POST", cmd_url, json_data, DEFAULT_HEADERS)
    list_of_urls = ""
    for url in urls_to_blacklist:
        list_of_urls += "- " + url + "\n"
    return "Added the following URLs to the blacklist successfully:\n" + list_of_urls


def unblacklist_url(url):
    urls_to_unblacklist = argToList(url)
    cmd_url = "/security/advanced/blacklistUrls?action=REMOVE_FROM_LIST"

    # Check if given URLs is blacklisted
    blacklisted_urls = get_blacklist()["blacklistUrls"]
    if len(urls_to_unblacklist) == 1:  # Given only one URL to unblacklist
        if urls_to_unblacklist[0] not in blacklisted_urls:
            raise Exception("Given URL is not blacklisted.")
    elif not any(
        url in urls_to_unblacklist for url in blacklisted_urls
    ):  # Given more than one URL to blacklist
        raise Exception("Given URLs are not blacklisted.")

    data = {"blacklistUrls": urls_to_unblacklist}
    json_data = json.dumps(data)
    http_request("POST", cmd_url, json_data, DEFAULT_HEADERS)
    list_of_urls = ""
    for url in urls_to_unblacklist:
        list_of_urls += "- " + url + "\n"
    return (
        "Removed the following URLs from the blacklist successfully:\n" + list_of_urls
    )


def blacklist_ip(ip):
    ips_to_blacklist = argToList(ip)
    cmd_url = "/security/advanced/blacklistUrls?action=ADD_TO_LIST"
    data = {"blacklistUrls": ips_to_blacklist}
    json_data = json.dumps(data)
    http_request("POST", cmd_url, json_data, DEFAULT_HEADERS)
    list_of_ips = ""
    for ip in ips_to_blacklist:
        list_of_ips += "- " + ip + "\n"
    return (
        "Added the following IP addresses to the blacklist successfully:\n"
        + list_of_ips
    )


def unblacklist_ip(ip):
    ips_to_unblacklist = argToList(ip)
    cmd_url = "/security/advanced/blacklistUrls?action=REMOVE_FROM_LIST"
    # Check if given IPs is blacklisted
    blacklisted_ips = get_blacklist()["blacklistUrls"]
    if len(ips_to_unblacklist) == 1:  # Given only one IP address to blacklist
        if ips_to_unblacklist[0] not in blacklisted_ips:
            raise Exception("Given IP address is not blacklisted.")
    elif not set(ips_to_unblacklist).issubset(
        set(blacklisted_ips)
    ):  # Given more than one IP address to blacklist
        raise Exception("Given IP addresses are not blacklisted.")
    data = {"blacklistUrls": ips_to_unblacklist}
    json_data = json.dumps(data)
    http_request("POST", cmd_url, json_data, DEFAULT_HEADERS)
    list_of_ips = ""
    for ip in ips_to_unblacklist:
        list_of_ips += "- " + ip + "\n"
    return (
        "Removed the following IP addresses from the blacklist successfully:\n"
        + list_of_ips
    )


def whitelist_url(url):
    cmd_url = "/security"
    urls_to_whitelist = argToList(url)
    # Get the current whitelist
    whitelist_urls = get_whitelist()
    if not whitelist_urls:
        whitelist_urls["whitelistUrls"] = []

    whitelist_urls["whitelistUrls"] += urls_to_whitelist
    json_data = json.dumps(whitelist_urls)
    http_request("PUT", cmd_url, json_data, DEFAULT_HEADERS)
    list_of_urls = ""
    for url in urls_to_whitelist:
        list_of_urls += "- " + url + "\n"
    return "Added the following URLs to the whitelist successfully:\n" + list_of_urls


def unwhitelist_url(url):
    cmd_url = "/security"
    urls_to_unwhitelist = argToList(url)
    # Get the current whitelist
    whitelist_urls = get_whitelist()
    if not whitelist_urls:
        whitelist_urls["whitelistUrls"] = []

    # Check if given URL is whitelisted
    if len(urls_to_unwhitelist) == 1:  # Given only one URL to whitelist
        if urls_to_unwhitelist[0] not in whitelist_urls["whitelistUrls"]:
            raise Exception("Given host address is not whitelisted.")
    elif not set(urls_to_unwhitelist).issubset(
        set(whitelist_urls["whitelistUrls"])
    ):  # Given more than one URL to whitelist
        raise Exception("Given host addresses are not whitelisted.")
    # List comprehension to remove requested URLs from the whitelist
    whitelist_urls["whitelistUrls"] = [
        x for x in whitelist_urls["whitelistUrls"] if x not in urls_to_unwhitelist
    ]
    json_data = json.dumps(whitelist_urls)
    http_request("PUT", cmd_url, json_data, DEFAULT_HEADERS)
    list_of_urls = ""
    for url in whitelist_urls:
        list_of_urls += "- " + url + "\n"
    return (
        "Removed the following URLs from the whitelist successfully:\n" + list_of_urls
    )


def whitelist_ip(ip):
    cmd_url = "/security"
    ips_to_whitelist = argToList(ip)
    # Get the current whitelist
    whitelist_ips = get_whitelist()
    if not whitelist_ips:
        whitelist_ips["whitelistUrls"] = []

    whitelist_ips["whitelistUrls"] += ips_to_whitelist
    json_data = json.dumps(whitelist_ips)
    http_request("PUT", cmd_url, json_data, DEFAULT_HEADERS)
    list_of_ips = ""
    for ip in ips_to_whitelist:
        list_of_ips += "- " + ip + "\n"
    return "Added the following URLs to the whitelist successfully:\n" + list_of_ips


def unwhitelist_ip(ip):
    cmd_url = "/security"
    ips_to_unwhitelist = argToList(ip)
    # Get the current whitelist
    whitelist_ips = get_whitelist()
    if not whitelist_ips:
        whitelist_ips["whitelistUrls"] = []

    # Check if given IP is whitelisted
    if len(ips_to_unwhitelist) == 1:  # Given only one IP to whitelist
        if ips_to_unwhitelist[0] not in whitelist_ips["whitelistUrls"]:
            raise Exception("Given IP address is not whitelisted.")
    elif not set(ips_to_unwhitelist).issubset(
        set(whitelist_ips["whitelistUrls"])
    ):  # Given more than one IP to whitelist
        raise Exception("Given IP address is not whitelisted.")
    # List comprehension to remove requested IPs from the whitelist
    whitelist_ips["whitelistUrls"] = [
        x for x in whitelist_ips["whitelistUrls"] if x not in ips_to_unwhitelist
    ]
    json_data = json.dumps(whitelist_ips)
    http_request("PUT", cmd_url, json_data, DEFAULT_HEADERS)
    list_of_ips = ""
    for ip in ips_to_unwhitelist:
        list_of_ips += "- " + ip + "\n"
    return (
        "Removed the following IP addresses from the whitelist successfully:\n"
        + list_of_ips
    )


def get_blacklist_command(args):
    blacklist = get_blacklist().get("blacklistUrls")
    if blacklist:
        filter_ = args.get("filter", "")
        query = args.get("query", "")
        if filter_ or query:
            filtered_blacklist = []
            for entity in blacklist:
                # if filter / query were not provided, then there is a match on it vacuously
                is_filter_match = not filter_
                is_query_match = not query
                if filter_:
                    if re.match(ipv4Regex, entity):
                        if filter_ == "ip":
                            is_filter_match = True
                    elif filter_ == "url":
                        is_filter_match = True
                if query:
                    if re.search(query, entity):
                        is_query_match = True
                    else:
                        is_query_match = False
                if is_filter_match and is_query_match:
                    filtered_blacklist.append(entity)
            blacklist = filtered_blacklist
    if blacklist:
        hr = "### Zscaler blacklist\n"
        for url in blacklist:
            hr += "- " + url + "\n"
        ec = {"Zscaler.Blacklist": blacklist}
        entry = {
            "Type": entryTypes["note"],
            "Contents": blacklist,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": hr,
            "EntryContext": ec,
        }
        return entry
    else:
        return "No results found"


def get_blacklist():
    cmd_url = "/security/advanced"
    result = http_request("GET", cmd_url, None, DEFAULT_HEADERS)
    return json.loads(result.content)


def get_whitelist_command():
    whitelist = get_whitelist().get("whitelistUrls")
    if whitelist:
        hr = "### Zscaler whitelist\n"
        for url in whitelist:
            hr += "- " + url + "\n"
        ec = {"Zscaler.Whitelist": whitelist}
        entry = {
            "Type": entryTypes["note"],
            "Contents": whitelist,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": hr,
            "EntryContext": ec,
        }
        return entry
    else:
        return "No results found"


def get_whitelist():
    cmd_url = "/security"
    result = http_request("GET", cmd_url, None, DEFAULT_HEADERS)
    return json.loads(result.content)


def url_lookup(args):
    url = args.get("url", "")
    multiple = args.get("multiple", "true").lower() == "true"
    response = lookup_request(url, multiple)
    raw_res = json.loads(response.content)

    urls_list = argToList(url)
    results: List[CommandResults] = []

    for data in raw_res:
        res_url = data.get("url")
        for url in urls_list:
            # since zscaler expects to recieve a URL without the protocol, we omit it in `lookup_request`
            # in the response, the URL is returned as it was sent, so we add back the protocol by replacing
            # the URL retruned with the one we got as an argument
            if "http://" + res_url in url or "https://" + res_url in url:
                data["url"] = url

        ioc_context = {"Address": data["url"], "Data": data["url"]}
        score = Common.DBotScore.GOOD

        if len(data["urlClassifications"]) == 0:
            data["urlClassifications"] = ""
        else:
            data["urlClassifications"] = "".join(data["urlClassifications"])
            ioc_context["urlClassifications"] = data["urlClassifications"]
            if data["urlClassifications"] == "MISCELLANEOUS_OR_UNKNOWN":
                score = Common.DBotScore.NONE

        if len(data["urlClassificationsWithSecurityAlert"]) == 0:
            data["urlClassificationsWithSecurityAlert"] = ""
        else:
            data["urlClassificationsWithSecurityAlert"] = "".join(
                data["urlClassificationsWithSecurityAlert"]
            )
            ioc_context["urlClassificationsWithSecurityAlert"] = data[
                "urlClassificationsWithSecurityAlert"
            ]
            if data["urlClassificationsWithSecurityAlert"] in SUSPICIOUS_CATEGORIES:
                score = Common.DBotScore.SUSPICIOUS
            else:
                score = Common.DBotScore.BAD

            data["ip"] = data.pop("url")

        url_indicator = Common.URL(
            url=ioc_context["Data"],
            dbot_score=Common.DBotScore(
                indicator=ioc_context["Data"],
                indicator_type=DBotScoreType.URL,
                integration_name=INTEGRATION_NAME,
                malicious_description=data.get(
                    "urlClassificationsWithSecurityAlert", None
                ),
                score=score,
                reliability=demisto.params().get("reliability")
            ),
        )

        results.append(
            CommandResults(
                outputs_prefix=f"{INTEGRATION_NAME}.URL",
                outputs_key_field="Data",
                indicator=url_indicator,
                readable_output=tableToMarkdown(
                    f'Zscaler URL Lookup for {ioc_context["Data"]}',
                    data,
                    removeNull=True,
                ),
                outputs=createContext(data=ioc_context, removeNull=True),
                raw_response=data,
            )
        )

    return results or "No results found."


def ip_lookup(ip):
    results: List[CommandResults] = []

    response = lookup_request(ip, multiple=True)
    raw_res = json.loads(response.content)

    for data in raw_res:
        ioc_context = {"Address": data["url"]}
        score = Common.DBotScore.GOOD

        if len(data["urlClassifications"]) == 0:
            data["iplClassifications"] = ""
        else:
            data["ipClassifications"] = "".join(data["urlClassifications"])
            ioc_context["ipClassifications"] = data["ipClassifications"]

        del data["urlClassifications"]

        if len(data["urlClassificationsWithSecurityAlert"]) == 0:
            data["ipClassificationsWithSecurityAlert"] = ""
        else:
            data["ipClassificationsWithSecurityAlert"] = "".join(
                data["urlClassificationsWithSecurityAlert"]
            )
            ioc_context["ipClassificationsWithSecurityAlert"] = data[
                "ipClassificationsWithSecurityAlert"
            ]
            if data["urlClassificationsWithSecurityAlert"] in SUSPICIOUS_CATEGORIES:
                score = Common.DBotScore.SUSPICIOUS
            else:
                score = Common.DBotScore.BAD

        del data["urlClassificationsWithSecurityAlert"]

        data["ip"] = data.pop("url")

        ip_indicator = Common.IP(
            ip=data["ip"],
            dbot_score=Common.DBotScore(
                indicator=data["ip"],
                indicator_type=DBotScoreType.IP,
                integration_name=INTEGRATION_NAME,
                malicious_description=data.get(
                    "ipClassificationsWithSecurityAlert", None
                ),
                score=score,
                reliability=demisto.params().get("reliability"),
            ),
        )
        results.append(
            CommandResults(
                outputs_prefix=f"{INTEGRATION_NAME}.IP",
                indicator=ip_indicator,
                outputs_key_field="Address",
                readable_output=tableToMarkdown(
                    f'Zscaler IP Lookup for {ioc_context["Address"]}',
                    data,
                    removeNull=True,
                ),
                outputs=createContext(data=ioc_context, removeNull=True),
                raw_response=data,
            )
        )

    return results or "No results found."


def lookup_request(ioc, multiple=True):
    cmd_url = "/urlLookup"
    if multiple:
        ioc_list = argToList(ioc)
    else:
        ioc_list = [ioc]
    ioc_list = [url.replace("https://", "").replace("http://", "") for url in ioc_list]
    json_data = json.dumps(ioc_list)
    response = http_request("POST", cmd_url, json_data, DEFAULT_HEADERS)
    return response


def category_add_url(category_id, url):
    category_data = get_category_by_id(category_id)
    if category_data:  # check if the category exists
        url_list = argToList(url)
        all_urls = url_list[:]
        all_urls.extend(list(map(lambda x: x.strip(), category_data["urls"])))
        category_data["urls"] = all_urls
        add_or_remove_urls_from_category(
            ADD, url_list, category_data
        )  # add the urls to the category
        context = {
            "ID": category_id,
            "CustomCategory": category_data.get("customCategory"),
            "URL": category_data.get("urls"),
        }
        if category_data.get("description"):  # Custom might not have description
            context["Description"] = category_data["description"]
        ec = {"Zscaler.Category(val.ID && val.ID === obj.ID)": context}
        urls = ""
        for url in url_list:
            urls += "- " + url + "\n"
        hr = "Added the following URL addresses to category {}:\n{}".format(
            category_id, urls
        )
        entry = {
            "Type": entryTypes["note"],
            "Contents": category_data,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": hr,
            "EntryContext": ec,
        }
        return entry
    else:
        return return_error("Category could not be found.")


def category_add_ip(category_id, ip):
    categories = get_categories()
    found_category = False
    for category in categories:
        if category["id"] == category_id:
            category_data = category
            found_category = True
            break
    if found_category:
        ip_list = argToList(ip)
        all_ips = ip_list[:]
        all_ips.extend(category_data["urls"])
        category_data["urls"] = all_ips
        response = category_ioc_update(category_data)
        context = {
            "ID": category_id,
            "CustomCategory": category_data["customCategory"],
            "URL": category_data["urls"],
        }
        if (
            "description" in category_data and category_data["description"]
        ):  # Custom might not have description
            context["Description"] = category_data["description"]
        ec = {"Zscaler.Category(val.ID && val.ID === obj.ID)": context}
        ips = ""
        for ip in ip_list:
            ips += "- " + ip + "\n"
        hr = "Added the following IP addresses to category {}:\n{}".format(
            category_id, ips
        )
        entry = {
            "Type": entryTypes["note"],
            "Contents": response,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": hr,
            "EntryContext": ec,
        }
        return entry
    else:
        return return_error("Category could not be found.")


def category_remove_url(category_id, url):
    category_data = get_category_by_id(category_id)  # check if the category exists
    if category_data:
        url_list = argToList(url)
        updated_urls = [
            url for url in category_data["urls"] if url not in url_list
        ]  # noqa
        if updated_urls == category_data["urls"]:
            return return_error("Could not find given URL in the category.")
        add_or_remove_urls_from_category(
            REMOVE, url_list, category_data
        )  # remove the urls from list
        category_data["urls"] = updated_urls
        context = {
            "ID": category_id,
            "CustomCategory": category_data.get("customCategory"),
            "URL": category_data.get("urls"),
        }
        if category_data.get("description"):  # Custom might not have description
            context["Description"] = category_data["description"]
        ec = {"Zscaler.Category(val.ID && val.ID === obj.ID)": context}
        urls = ""
        for url in url_list:
            urls += "- " + url + "\n"
        hr = "Removed the following URL addresses to category {}:\n{}".format(
            category_id, urls
        )
        entry = {
            "Type": entryTypes["note"],
            "Contents": category_data,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": hr,
            "EntryContext": ec,
        }
        return entry
    else:
        return return_error("Category could not be found.")


def category_remove_ip(category_id, ip):
    categories = get_categories()
    found_category = False
    for category in categories:
        if category["id"] == category_id:
            category_data = category
            found_category = True
            break
    if found_category:
        ip_list = argToList(ip)
        updated_ips = [ip for ip in category_data["urls"] if ip not in ip_list]  # noqa
        if updated_ips == category_data["urls"]:
            return return_error("Could not find given IP in the category.")
        category_data["urls"] = updated_ips
        response = category_ioc_update(category_data)
        context = {
            "ID": category_id,
            "CustomCategory": category_data["customCategory"],
            "URL": category_data["urls"],
        }
        if (
            "description" in category_data and category_data["description"]
        ):  # Custom might not have description
            context["Description"] = category_data["description"]
        ec = {"Zscaler.Category(val.ID && val.ID === obj.ID)": context}
        ips = ""
        for ip in ip_list:
            ips += "- " + ip + "\n"
        hr = "Removed the following IP addresses to category {}:\n{}".format(
            category_id, ips
        )
        entry = {
            "Type": entryTypes["note"],
            "Contents": response,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": hr,
            "EntryContext": ec,
        }
        return entry
    else:
        return return_error("Category could not be found.")


def category_ioc_update(category_data):
    cmd_url = "/urlCategories/" + category_data["id"]
    data = {
        "customCategory": category_data["customCategory"],
        "urls": category_data["urls"],
        "id": category_data["id"],
    }
    if "description" in category_data:
        data["description"] = category_data["description"]
    if "configuredName" in category_data:
        data["configuredName"] = category_data["configuredName"]
    json_data = json.dumps(data)
    response = http_request("PUT", cmd_url, json_data).json()
    return response


def add_or_remove_urls_from_category(action, urls, category_data):
    """
    Add or remove urls from a category.
    Args:
        str action: The action requested, can be 'ADD_TO_LIST' for adding or 'REMOVE_FROM'_LIST for removing.
        List[Any] urls: the list of urls to add or remove from the category
        Dict[str: Any] category_data: the data of the category as returned from the API

    Returns:
        The response as returned from the API

    """

    cmd_url = "/urlCategories/" + category_data.get("id") + "?action=" + action
    data = {
        "customCategory": category_data.get("customCategory"),
        "urls": urls,
        "id": category_data.get("id"),
    }
    if "description" in category_data:
        data["description"] = category_data["description"]
    if "configuredName" in category_data:
        data["configuredName"] = category_data["configuredName"]
    json_data = json.dumps(data)
    http_request(
        "PUT", cmd_url, json_data
    )  # if the request is successful, it returns an empty response


def url_quota_command():
    cmd_url = "/urlCategories/urlQuota"
    response = http_request("GET", cmd_url).json()

    human_readable = {
        "Unique Provisioned URLs": response.get("uniqueUrlsProvisioned"),
        "Remaining URLs Quota": response.get("remainingUrlsQuota"),
    }
    entry = {
        "Type": entryTypes["note"],
        "Contents": response,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown("Quota Information", human_readable),
        "EntryContext": {"Zscaler.Quota": response},
    }
    return entry


def get_categories_command(args):
    display_urls = argToBoolean(
        args.get("displayURL")
    )  # urls returned to context data even if set to false
    custom_only = argToBoolean(args.get("custom_categories_only", False))
    ids_and_names_only = argToBoolean(
        args.get("get_ids_and_names_only", False)
    )  # won't get URLs at all
    categories = []
    raw_categories = get_categories(custom_only, ids_and_names_only)
    for raw_category in raw_categories:
        category = {
            "ID": raw_category["id"],
            "CustomCategory": raw_category["customCategory"],
        }
        if raw_category.get("urls"):
            category["URL"] = raw_category["urls"]
        if "description" in raw_category:
            category["Description"] = raw_category["description"]
        if "configuredName" in raw_category:
            category["Name"] = raw_category["configuredName"]
        categories.append(category)
    ec = {"Zscaler.Category(val.ID && val.ID === obj.ID)": categories}
    if display_urls and not ids_and_names_only:
        headers = ["ID", "Description", "URL", "CustomCategory", "Name"]
    else:
        headers = ["ID", "Description", "CustomCategory", "Name"]
    title = "Zscaler Categories"
    entry = {
        "Type": entryTypes["note"],
        "Contents": raw_categories,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown(title, categories, headers),
        "EntryContext": ec,
    }
    return entry


def get_categories(custom_only=False, ids_and_names_only=False):
    if ids_and_names_only:
        # if you only want a list of URL category IDs and names (i.e without urls list).
        # Note: API does not support the combination of custom_only and 'lite' endpoint
        cmd_url = "/urlCategories/lite"
    else:
        cmd_url = "/urlCategories?customOnly=true" if custom_only else "/urlCategories"

    response = http_request("GET", cmd_url).json()
    return response


def sandbox_report_command():
    md5 = demisto.getArg("md5")
    details = demisto.getArg("details")
    res = sandbox_report(md5, details)

    report = "Full Details" if details == "full" else "Summary"
    ctype = demisto.get(res, "{}.Classification.Type".format(report))
    dbot_score = (
        3
        if ctype == "MALICIOUS"
        else 2
        if ctype == "SUSPICIOUS"
        else 1
        if ctype == "BENIGN"
        else 0
    )

    ec = {
        outputPaths["dbotscore"]: {
            "Indicator": md5,
            "Type": "file",
            "Vendor": "Zscaler",
            "Score": dbot_score,
            "Reliability": demisto.params().get("reliability"),
        }
    }

    human_readable_report = ec["DBotScore"].copy()
    human_readable_report["Detected Malware"] = str(
        demisto.get(res, "{}.Classification.DetectedMalware".format(report))
    )
    human_readable_report["Zscaler Score"] = demisto.get(
        res, "{}.Classification.Score".format(report)
    )
    human_readable_report["Category"] = demisto.get(
        res, "{}.Classification.Category".format(report)
    )
    ec[outputPaths["file"]] = {
        "MD5": md5,
        "Zscaler": {
            "DetectedMalware": demisto.get(
                res, "{}.Classification.DetectedMalware".format(report)
            ),
            "FileType": demisto.get(res, "{}.File Properties.File Type".format(report)),
        },
    }
    if dbot_score == 3:
        ec[outputPaths["file"]]["Malicious"] = {
            "Vendor": "Zscaler",
            "Description": "Classified as Malicious, with threat score: "
            + str(human_readable_report["Zscaler Score"]),
        }
    entry = {
        "Type": entryTypes["note"],
        "Contents": res,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown(
            "Full Sandbox Report", human_readable_report, removeNull=True
        ),
        "EntryContext": ec,
    }

    return entry


def sandbox_report(md5, details):
    cmd_url = "/sandbox/report/{md5Hash}?details={details}".format(
        md5Hash=md5, details=details
    )

    response = http_request("GET", cmd_url).json()
    return response


def login_command():
    ctx = get_integration_context() or {}
    session_id = ctx.get(SESSION_ID_KEY)
    if session_id:
        try:
            DEFAULT_HEADERS["cookie"] = session_id
            demisto.info(
                "Zscaler logout active session triggered by zscaler-login command."
            )
            logout()
        except Exception as e:
            demisto.info("Zscaler logout failed with: {}".format(str(e)))
    login()
    return CommandResults(readable_output="Zscaler session created successfully.")


def logout_command():
    ctx = get_integration_context() or {}
    session_id = ctx.get(SESSION_ID_KEY)
    if not session_id:
        return CommandResults(
            readable_output="No API session was found. No action was performed."
        )
    try:
        DEFAULT_HEADERS["cookie"] = session_id
        raw_res = logout().json()
    except AuthorizationError:
        return CommandResults(
            readable_output="API session is not authenticated. No action was performed."
        )
    return CommandResults(
        readable_output="API session logged out of Zscaler successfully.",
        raw_response=raw_res,
    )


def activate_command():
    raw_res = activate_changes().json()
    return CommandResults(
        readable_output="Changes have been activated successfully.",
        raw_response=raw_res,
    )


def test_module():
    http_request("GET", "/status", None, DEFAULT_HEADERS)
    return "ok"


def get_category_by_id(category_id):
    categories = get_categories()
    for category in categories:
        if category["id"] == category_id:
            return category
    return None


def get_users_command(args):
    name = args.get("name", None)
    pageSize = args.get("pageSize")
    pageNo = args.get("page", 1)
    if name is not None:
        cmd_url = "/users?page={}&pageSize={}&name={}".format(pageNo, pageSize, name)
    else:
        cmd_url = "/users?page={}&pageSize={}".format(pageNo, pageSize)
    response = http_request("GET", cmd_url).json()

    if len(response) < 10:
        human_readable = tableToMarkdown("Users ({})".format(len(response)), response)
    else:
        human_readable = "Retrieved {} users".format(len(response))

    entry = {
        "Type": entryTypes["note"],
        "Contents": response,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": human_readable,
        "EntryContext": {"Zscaler.Users": response},
    }
    return entry


def get_departments_command(args):
    name = args.get("name", None)
    pageSize = args.get("pageSize")
    pageNo = args.get("page", 1)
    if name is not None:
        cmd_url = "/departments?page={}&pageSize={}&search={}&limitSearch=true".format(
            pageNo, pageSize, name
        )
    else:
        cmd_url = "/departments?page={}&pageSize={}".format(pageNo, pageSize)
    response = http_request("GET", cmd_url).json()

    if len(response) < 10:
        human_readable = tableToMarkdown(
            "Departments ({})".format(len(response)), response
        )
    else:
        human_readable = "Retrieved {} departments".format(len(response))

    entry = {
        "Type": entryTypes["note"],
        "Contents": response,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": human_readable,
        "EntryContext": {"Zscaler.Departments": response},
    }
    return entry


def get_usergroups_command(args):
    name = args.get("name", None)
    pageSize = args.get("pageSize")
    pageNo = args.get("page", 1)
    if name is not None:
        cmd_url = "/groups?page={}&pageSize={}&search={}".format(pageNo, pageSize, name)
    else:
        cmd_url = "/groups?page={}&pageSize={}".format(pageNo, pageSize)
    response = http_request("GET", cmd_url).json()

    if len(response) < 10:
        human_readable = tableToMarkdown(
            "User groups ({})".format(len(response)), response
        )
    else:
        human_readable = "Retrieved {} user groups".format(len(response))

    entry = {
        "Type": entryTypes["note"],
        "Contents": response,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": human_readable,
        "EntryContext": {"Zscaler.UserGroups": response},
    }
    return entry


def set_user_command(args):
    userId = args.get("id")
    params = json.loads(args.get("user"))
    cmd_url = "/users/{}".format(userId)

    response = http_request("PUT", cmd_url, json.dumps(params), DEFAULT_HEADERS)
    responseJson = response.json()
    if response.status_code == 200:
        entry = {
            "Type": entryTypes["note"],
            "Contents": responseJson,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": "Successfully updated the user (id: {} name: {})".format(
                responseJson["id"], responseJson["name"]
            ),
            "EntryContext": {"Zscaler.Users": responseJson},
        }
        return entry
    else:
        return responseJson


def create_ip_destination_group(args: dict):
    headers = [
        "ID",
        "Name",
        "Type",
        "Description",
        "Addresses",
        "Countries",
        "IpCategories",
        "IsNonEditable",
    ]
    payload = {
        "name": args.get("name", ""),
        "type": args.get("type", ""),
        "countries": argToList(args.get("countries", "")),
        "ipCategories": argToList(args.get("ip_categories", "")),
        "description": args.get("description", ""),
        "addresses": argToList(args.get("addresses", "")),
        "isNonEditable": args.get("is_non_editable", False),
    }
    cmd_url = "/ipDestinationGroups"
    response = http_request(
        "POST", cmd_url, data=json.dumps(payload), headers=DEFAULT_HEADERS
    ).json()
    content = {
        "ID": int(response.get("id", "")),
        "Name": response.get("name", ""),
        "Type": response.get("type", ""),
        "Description": response.get("description", ""),
        "Addresses": response.get("addresses", []),
        "IpCategories": response.get("ipCategories", []),
        "Countries": response.get("countries", []),
        "IsNonEditable": response.get("isNonEditable", False),
    }
    markdown = tableToMarkdown(
        "IPv4 Destination group created", content, headers, removeNull=True
    )
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="Zscaler.IPDestinationGroup",
        outputs_key_field="ID",
        outputs=content,
    )
    return results


def list_ip_destination_groups(args: dict):
    ip_group_ids = argToList(args.get("ip_group_id", ""))
    exclude_type = str(args.get("exclude_type", "")).strip()
    category_type = argToList(args.get("type", ""))
    include_ipv6 = argToBoolean(args.get("include_ipv6", False))
    limit = arg_to_number(args.get("limit", 50))
    all_results = argToBoolean(args.get("all_results", False))
    lite = argToBoolean(args.get("lite", False))
    headers = [
        "ID",
        "Name",
        "Type",
        "Description",
        "Addresses",
        "Countries",
        "IpCategories",
    ]

    def get_contents(responses: List[dict]):
        contents = list()
        for response in responses:
            content = {
                "ID": int(response.get("id", "")),
                "Name": response.get("name", ""),
                "Type": response.get("type", ""),
                "Description": response.get("description", ""),
                "Addresses": response.get("addresses", []),
                "IpCategories": response.get("ipCategories", []),
                "Countries": response.get("countries", []),
            }
            contents.append(content)
        return contents

    def get_contents_lite(responses: List[dict]):
        contents = list()
        for response in responses:
            content = dict()
            for key, value in response.items():
                if key == "extensions":
                    for extensions_key, extensions_value in value.items():
                        content[f"{extensions_key.capitalize()}"] = extensions_value
                elif key == "id":
                    content[key.upper()] = value
                else:
                    content[key.capitalize()] = value
            contents.append(content)
        return contents

    if len(ip_group_ids) == 0:
        lite_endpoint = "/lite" if lite else ""
        if exclude_type:
            exclude_type_param = f"?excludeType={exclude_type}&"
        else:
            exclude_type_param = "?"
        type_params = [f"type={t}" for t in category_type]
        type_params_str = "&".join(type_params)
        if include_ipv6:
            ipv4_cmd_url = (
                "/ipDestinationGroups"
                + lite_endpoint
                + exclude_type_param
                + type_params_str
            )
            ipv6_cmd_url = (
                "/ipDestinationGroups/ipv6DestinationGroups"
                + lite_endpoint
                + exclude_type_param
                + type_params_str
            )
            ipv4_responses = http_request("GET", ipv4_cmd_url).json()
            ipv6_responses = http_request("GET", ipv6_cmd_url).json()
            ipv4_contents_filter = (
                get_contents_lite(ipv4_responses)
                if lite
                else get_contents(ipv4_responses)
            )
            ipv4_contents = (
                ipv4_contents_filter if all_results else ipv4_contents_filter[:limit]
            )
            ipv6_contents_filter = (
                get_contents_lite(ipv6_responses)
                if lite
                else get_contents(ipv6_responses)
            )
            ipv6_contents = (
                ipv6_contents_filter if all_results else ipv6_contents_filter[:limit]
            )
            markdown = tableToMarkdown(
                f"IPv4 Destination groups ({len(ipv4_contents)})",
                ipv4_contents,
                headers,
                removeNull=True,
            )
            markdown += tableToMarkdown(
                f"IPv6 Destination groups ({len(ipv6_contents)})",
                ipv6_contents,
                headers,
                removeNull=True,
            )
            contents = ipv4_contents + ipv6_contents

            results = CommandResults(
                readable_output=markdown,
                outputs_prefix="Zscaler.IPDestinationGroup",
                outputs_key_field="ID",
                outputs=contents,
            )
            return results
        else:
            cmd_url = (
                "/ipDestinationGroups"
                + lite_endpoint
                + exclude_type_param
                + type_params_str
            )
            responses = http_request("GET", cmd_url).json()
            contents_filter = (
                get_contents_lite(responses) if lite else get_contents(responses)
            )
            contents = contents_filter if all_results else contents_filter[:limit]
            markdown = tableToMarkdown(
                f"IPv4 Destination groups ({len(contents)})",
                contents,
                headers,
                removeNull=True,
            )

            results = CommandResults(
                readable_output=markdown,
                outputs_prefix="Zscaler.IPDestinationGroup",
                outputs_key_field="ID",
                outputs=contents,
            )
            return results
    else:
        responses = list()
        for ip_group_id in ip_group_ids:
            cmd_url = f"/ipDestinationGroups/{ip_group_id}"
            responses.append(http_request("GET", cmd_url).json())
        contents = get_contents(responses)
        markdown = tableToMarkdown(
            f"IPv4 Destination groups ({len(contents)})",
            contents,
            headers,
            removeNull=True,
        )

        results = CommandResults(
            readable_output=markdown,
            outputs_prefix="Zscaler.IPDestinationGroup",
            outputs_key_field="ID",
            outputs=contents,
        )
        return results


def edit_ip_destination_group(args: dict):
    headers = [
        "ID",
        "Name",
        "Type",
        "Description",
        "Addresses",
        "Countries",
        "IpCategories",
    ]
    payload = dict()
    ip_group_id = str(args.get("ip_group_id", "")).strip()
    check_url = f"/ipDestinationGroups/{ip_group_id}"
    response_data = dict()
    response_data = http_request("GET", check_url).json()
    if response_data.get("id", 0) == 0:
        raise Exception(f"Resource not found with ip_group_id {ip_group_id}")

    payload["name"] = args.get("name", response_data["name"])
    payload["countries"] = argToList(args.get("countries", response_data["countries"]))
    payload["ipCategories"] = argToList(
        args.get("ip_categories", response_data["ipCategories"])
    )
    payload["addresses"] = argToList(args.get("addresses", response_data["addresses"]))
    payload["description"] = args.get("description", response_data["description"])
    payload["isNonEditable"] = args.get("is_non_editable", False)
    payload["type"] = response_data["type"]

    cmd_url = f"/ipDestinationGroups/{ip_group_id}"
    json_data = json.dumps(payload)
    response = http_request("PUT", cmd_url, json_data, DEFAULT_HEADERS).json()
    content = {
        "ID": int(response.get("id", "")),
        "Name": response.get("name", ""),
        "Type": response.get("type", ""),
        "Description": response.get("description", ""),
        "Addresses": response.get("addresses", []),
        "IpCategories": response.get("ipCategories", []),
        "Countries": response.get("countries", []),
    }
    markdown = tableToMarkdown(
        "IPv4 Destination group updated", content, headers, removeNull=True
    )
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="Zscaler.IPDestinationGroup",
        outputs_key_field="ID",
        outputs=content
    )
    return results


def delete_ip_destination_groups(args: dict):
    ip_group_ids = argToList(args.get("ip_group_id", ""))
    for ip_group_id in ip_group_ids:
        cmd_url = f"/ipDestinationGroups/{ip_group_id}"
        _ = http_request("DELETE", cmd_url, None, DEFAULT_HEADERS)
    markdown = "### IP Destination Group {} deleted successfully".format(
        ",".join(ip_group_ids)
    )

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix="Zscaler.IPDestinationGroup",
        outputs_key_field=None,
        outputs=None
    )
    return results


""" EXECUTION CODE """


def main():  # pragma: no cover
    command = demisto.command()

    demisto.debug("command is %s" % (command,))
    args = demisto.args()
    if command == "zscaler-login":
        return_results(login_command())
    elif command == "zscaler-logout":
        return_results(logout_command())
    else:
        login()
        try:
            if command == "test-module":
                return_results(test_module())
            elif command == "url":
                return_results(url_lookup(demisto.args()))
            elif command == "ip":
                return_results(ip_lookup(args.get("ip")))
            elif command == "zscaler-blacklist-url":
                return_results(blacklist_url(args.get("url")))
            elif command == "zscaler-undo-blacklist-url":
                return_results(unblacklist_url(args.get("url")))
            elif command == "zscaler-whitelist-url":
                return_results(whitelist_url(args.get("url")))
            elif command == "zscaler-undo-whitelist-url":
                return_results(unwhitelist_url(args.get("url")))
            elif command == "zscaler-blacklist-ip":
                return_results(blacklist_ip(args.get("ip")))
            elif command == "zscaler-undo-blacklist-ip":
                return_results(unblacklist_ip(args.get("ip")))
            elif command == "zscaler-whitelist-ip":
                return_results(whitelist_ip(args.get("ip")))
            elif command == "zscaler-undo-whitelist-ip":
                return_results(unwhitelist_ip(args.get("ip")))
            elif command == "zscaler-category-add-url":
                return_results(
                    category_add_url(args.get("category-id"), args.get("url"))
                )
            elif command == "zscaler-category-add-ip":
                return_results(category_add_ip(args.get("category-id"), args.get("ip")))
            elif command == "zscaler-category-remove-url":
                return_results(
                    category_remove_url(args.get("category-id"), args.get("url"))
                )
            elif command == "zscaler-category-remove-ip":
                return_results(
                    category_remove_ip(args.get("category-id"), args.get("ip"))
                )
            elif command == "zscaler-get-categories":
                return_results(get_categories_command(args))
            elif command == "zscaler-get-blacklist":
                return_results(get_blacklist_command(args))
            elif command == "zscaler-get-whitelist":
                return_results(get_whitelist_command())
            elif command == "zscaler-sandbox-report":
                return_results(sandbox_report_command())
            elif command == "zscaler-activate-changes":
                return_results(activate_command())
            elif command == "zscaler-url-quota":
                return_results(url_quota_command())
            elif command == "zscaler-get-users":
                return_results(get_users_command(demisto.args()))
            elif command == "zscaler-update-user":
                return_results(set_user_command(demisto.args()))
            elif command == "zscaler-get-departments":
                return_results(get_departments_command(demisto.args()))
            elif command == "zscaler-get-usergroups":
                return_results(get_usergroups_command(demisto.args()))
            elif command == "zscaler-list-ip-destination-groups":
                return_results(list_ip_destination_groups(demisto.args()))
            elif command == "zscaler-create-ip-destination-group":
                return_results(create_ip_destination_group(demisto.args()))
            elif command == "zscaler-edit-ip-destination-group":
                return_results(edit_ip_destination_group(demisto.args()))
            elif command == "zscaler-delete-ip-destination-groups":
                return_results(delete_ip_destination_groups(demisto.args()))
        except Exception as e:
            return_error(f"Failed to execute {command} command. Error: {str(e)}")
            raise
        finally:
            try:
                # activate changes only when required
                if (
                    demisto.params().get("auto_activate")
                    and command in AUTO_ACTIVATE_CHANGES_COMMANDS
                ):
                    activate_changes()
                if demisto.params().get("auto_logout"):
                    logout()
            except Exception as err:
                demisto.info("Zscaler error: " + str(err))


# python2 uses __builtin__ python3 uses builtins
if __name__ in ("__builtin__", "builtins", "__main__"):
    main()

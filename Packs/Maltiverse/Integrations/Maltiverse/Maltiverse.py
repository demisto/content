import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """
from typing import Tuple, Dict, Any
from _collections import defaultdict
import urllib3
import hashlib

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
SERVER_URL = "https://api.maltiverse.com"
DBOT_SCORE_KEY = "DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)"
DEFAULT_THRESHOLD = 5


class Error(Exception):
    """Base class for exceptions in this module."""

    pass


class NotFoundError(Error):
    """Exception raised for 404 - Page Not Found errors.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, url: str, use_ssl: bool, use_proxy: bool, auth_token=None, reliability=DBotScoreReliability.C):
        self.auth_token = auth_token
        self.reliability = reliability
        super().__init__(url, verify=use_ssl, proxy=use_proxy, headers={"Accept": "application/json"})
        if self.auth_token:
            self._headers.update({"Authorization": "Bearer " + self.auth_token})

    def http_request(self, method, url_suffix):
        ok_codes = (200, 401, 403, 404, 500)  # includes responses that are ok (200) and error responses that should be
        # handled by the client and not in the BaseClient
        try:
            res = self._http_request(method, url_suffix, resp_type="response", ok_codes=ok_codes)
            if res.status_code == 200:
                try:
                    return res.json()
                except ValueError as exception:
                    raise DemistoException("Failed to parse json object from response: {}".format(res.content), exception)

            if res.status_code in [401, 403, 500]:
                try:
                    err_msg = str(res.json())
                    if self.auth_token:
                        err_msg = f"Check server URL and API key \n{err_msg}"
                    else:
                        err_msg = f"Check server URL or try using an API key \n{err_msg}"
                except ValueError:
                    err_msg = "Check server URL or API key -\n" + str(res)
                raise DemistoException(err_msg)

            if res.status_code == 404:
                raise NotFoundError("Page Not Found")

        except Exception as e:
            if "<requests.exceptions.ConnectionError>" in e.args[0]:
                raise DemistoException(
                    "Connection error - Verify that the server URL parameter is correct and that "
                    "you have access to the server from your host.\n"
                )
            raise e

    def ip_report(self, ip: str) -> dict:
        if not is_ip_valid(ip):
            raise DemistoException("The given IP was invalid")
        return self.http_request("GET", f"/ip/{ip}")

    def url_report(self, url: str) -> dict:
        sha256_url = urlToSHA256(url)
        try:
            report = self.http_request("GET", f"/url/{sha256_url}")
            return report
        except NotFoundError:
            LOG(f"URL {url} was not found")
            return {"NotFound": True}
        except Exception as e:
            raise e

    def domain_report(self, domain: str) -> dict:
        return self.http_request("GET", f"/hostname/{domain}")

    def file_report(self, sha256: str) -> dict:
        try:
            report = self.http_request("GET", f"/sample/{sha256}")
            return report
        except NotFoundError:
            LOG(f"file {sha256} was not found")
            return {"NotFound": True}
        except Exception as e:
            raise e


def test_module(client=None):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: Maltiverse client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.http_request("GET", "/ip/8.8.8.8")
        return "ok"
    except NotFoundError as e:
        return_error("Check server URL - " + e.message)
    except Exception as e:
        raise e


def calculate_score(positive_detections: int, classification: str, threshold: int, anti_virus: int = 0) -> int:
    """
    Calculates Demisto score based on the classification of Maltiverse and number of positive detections in the blacklist.

    Args:
        positive_detections (int): the number of items in the blacklist
        classification (str): the classification given to the IoC by Maltiverse. Can be one of: neutral, whitelist,
        suspicious, malicious
        threshold (int): the score threshold configured by the user.
        anti_virus (int) - optional: used to calculate the score only in the case that the IoC is a file. Indicates the
        number of items in the list of antivirus detections.

    Returns:
        int - Demisto's score for the indicator
    """
    if positive_detections == 0 and classification == "neutral":
        return 0
    elif classification == "whitelist":
        return 1
    elif positive_detections <= threshold and classification != "malicious":
        if anti_virus > 1:
            return 3
        return 2
    elif positive_detections > threshold or classification == "malicious":
        return 3
    else:  # if reached this line there is a problem with the logic
        return -1


def urlToSHA256(url: str) -> str:
    """
    Converts a url into its SHA256 hash.

    Args:
        url (str): the url that should be converted into  SHA256

    Returns:
        str - the SHA256 hash of the url
    """
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def create_blacklist_keys(blacklist):
    """
    Converts the Blacklist keys into context keys format.

    Args:
    blacklist (list): a list of dictionaries, where each dictionary is a positive detection of the IoC

    Returns:
    A new blacklist in which the keys are context keys
    """
    if not blacklist:
        return []
    new_blacklist = []
    for detection in blacklist:
        detection_keys = {}
        for key in detection.keys():
            detection_keys[string_to_context_key(key)] = detection[key]
        new_blacklist.append(detection_keys)
    return new_blacklist


def create_tags(tags: list) -> list:
    """
    Removes all urls from the tags list

    Args:
    tags (list): a list of tags as returned by Maltiverse

    Returns:
    A new list that includes all the tags given by Maltiverse without urls
    """
    clean_tags = []
    if tags:
        for tag in tags:
            if not re.match(urlRegex, tag):
                clean_tags.append(tag)
    return clean_tags


def ip_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Executes IP enrichment against Maltiverse.

    Args:
        client (Client): Maltiverse client.
        args (Dict[str, str]): the arguments for the command.
    Returns:
        str: human readable presentation of the IP report.
        dict: the results to return into Demisto's context.
        Any: the raw data from Maltiverse client (used for debugging).
    """

    threshold = int(args.get("threshold", DEFAULT_THRESHOLD))
    markdown = ""
    context: dict = defaultdict(list)
    reports = []

    for ip in argToList(args.get("ip")):
        report = client.ip_report(ip)
        positive_detections = len(report.get("blacklist", []))

        blacklist_context = {"Blacklist": report.get("blacklist", [])}
        blacklist_context["Blacklist"] = create_blacklist_keys(blacklist_context["Blacklist"])
        blacklist_description = [
            blacklist_context["Blacklist"][i]["Description"] for i in range(len(report.get("blacklist", [])))
        ]

        outputs = {
            "Address": report.get("ip_addr", ""),
            "Geo": {"Country": report.get("country_code", "")},
            "PositiveDetections": positive_detections,
            "Malicious": {"Description": blacklist_description},
            "Tags": create_tags(report.get("tag", "")),
            "ThreatTypes": {"threatcategory": blacklist_description},
        }

        additional_info = {
            "Tags": create_tags(report.get("tag", "")),
            "Classification": report.get("classification", ""),
            "Address": report.get("ip_addr", ""),
        }

        dbot_score = {
            "Indicator": report.get("ip_addr", ""),
            "Type": "ip",
            "Vendor": "Maltiverse",
            "Score": calculate_score(positive_detections, report.get("classification", ""), threshold),
            "Reliability": client.reliability,
        }

        maltiverse_ip = {**blacklist_context, **additional_info}

        context[outputPaths["ip"]].append(outputs)
        context[f'Maltiverse.{outputPaths["ip"]}'].append(maltiverse_ip)
        context[DBOT_SCORE_KEY].append(dbot_score)

        markdown = f'## Maltiverse IP reputation for: {report["ip_addr"]}\n'
        markdown += f'IP Address: **{report.get("ip_addr", "")}**\n'
        markdown += f'Country: **{report.get("country_code", "")}**\n'
        markdown += f"Positive Detections: **{positive_detections}**\n"
        markdown += f'Maltiverse Classification: **{report.get("classification", "")}**\n'
        if positive_detections:
            markdown += tableToMarkdown(
                "Blacklist",
                blacklist_context["Blacklist"],
                removeNull=True,
                headers=["Source", "Description", "FirstSeen", "LastSeen"],
            )

        reports.append(report)

    return markdown, context, reports


def url_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Executes URL enrichment against Maltiverse.

    Args:
        client (Client): Maltiverse client.
        args (Dict[str, str]): the arguments for the command.
    Returns:
        str: human readable presentation of the URL report.
        dict: the results to return into Demisto's context.
        Any: the raw data from Maltiverse client (used for debugging).
    """

    threshold = int(args.get("threshold", DEFAULT_THRESHOLD))
    markdown = ""
    context: dict = defaultdict(list)
    reports = []

    for url in argToList(args.get("url", "")):
        report = client.url_report(url)
        if "NotFound" in report:
            markdown += f"No results found for {url}"
            dbot_score = {"Indicator": url, "Type": "Url", "Vendor": "Maltiverse", "Score": 0, "Reliability": client.reliability}
            context[DBOT_SCORE_KEY].append(dbot_score)
            break
        positive_detections = len(report.get("blacklist", []))
        blacklist_context = {"Blacklist": report.get("blacklist", [])}
        blacklist_context["Blacklist"] = create_blacklist_keys(blacklist_context["Blacklist"])

        outputs = {
            "Data": report.get("url", ""),
            "PositiveDetections": positive_detections,
            "Tags": create_tags(report.get("tag", "")),
            "ThreatTypes": {
                "threatcategory": [
                    blacklist_context["Blacklist"][i]["Description"] for i in range(len(report.get("blacklist", [])))
                ]
            },
        }

        dbot_score = {
            "Indicator": url,
            "Type": "Url",
            "Vendor": "Maltiverse",
            "Score": calculate_score(positive_detections, report.get("classification", ""), threshold),
            "Reliability": client.reliability,
        }

        maltiverse_url = {
            string_to_context_key(field): report.get(field, "")
            for field in ["classification", "modification_time", "creation_time", "hostname", "domain", "tld"]
        }
        maltiverse_url["Address"] = report.get("url", "")
        maltiverse_url["Tags"] = create_tags(report.get("tag", ""))
        maltiverse_url = {**maltiverse_url, **blacklist_context}

        markdown = f"## Maltiverse URL reputation for: {url}\n"
        markdown += f"URL: {url}\n"
        markdown += f'URL Domain: **{report.get("domain", "")}**\n'
        markdown += f'URL Creation Time: **{report.get("creation_time", "")}**\n'
        markdown += f'URL Modification Time: **{report.get("modification_time", "")}**\n'
        markdown += f"Positive Detections: **{positive_detections}**\n"
        markdown += f'Maltiverse Classification: **{report.get("classification", "")}**\n'

        if positive_detections:
            malicious_info = {
                "Malicious": {
                    "Description": [
                        blacklist_context["Blacklist"][i]["Description"] for i in range(len(report.get("blacklist", [])))
                    ],
                    "Vendor": "Maltiverse",
                }
            }
            outputs = {**outputs, **malicious_info}
            markdown += "URL Malicious Vendor: **Maltiverse**\n"
            markdown += tableToMarkdown(
                "Blacklist",
                blacklist_context["Blacklist"],
                removeNull=True,
                headers=["Source", "Description", "FirstSeen", "LastSeen"],
            )

        context[outputPaths["url"]].append(outputs)
        context[DBOT_SCORE_KEY].append(dbot_score)
        context[f'Maltiverse.{outputPaths["url"]}'].append(maltiverse_url)

        reports.append(report)

    return markdown, context, reports


def domain_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Executes domain enrichment against Maltiverse.

    Args:
        client (Client): Maltiverse client.
        args (Dict[str, str]): the arguments for the command.
    Returns:
        str: human readable presentation of the domain report.
        dict: the results to return into Demisto's context.
        Any: the raw data from Maltiverse client (used for debugging).
    """
    threshold = int(args.get("threshold", DEFAULT_THRESHOLD))
    markdown = ""
    context: dict = defaultdict(list)
    reports = []

    for domain in argToList(args.get("domain", "")):
        report = client.domain_report(domain)
        positive_detections = len(report.get("blacklist", []))

        blacklist_context = {"Blacklist": report.get("blacklist", [])}
        blacklist_context["Blacklist"] = create_blacklist_keys(blacklist_context["Blacklist"])

        outputs = {string_to_context_key(field): report.get(field, "") for field in ["creation_time", "modification_time"]}
        outputs["Tags"] = create_tags(report.get("tag", ""))
        outputs["TLD"] = report.get("tld", "")
        outputs["Name"] = report.get("hostname", "")
        outputs["ASName"] = report.get("as_name", "")
        outputs["ThreatTypes"] = {
            "threatcategory": [blacklist_context["Blacklist"][i]["Description"] for i in range(len(report.get("blacklist", [])))]
        }

        dbot_score = {
            "Indicator": domain,
            "Type": "Domain",
            "Vendor": "Maltiverse",
            "Score": calculate_score(positive_detections, report.get("classification", ""), threshold),
            "Reliability": client.reliability,
        }

        maltiverse_domain = {
            string_to_context_key(field): report.get(field, "")
            for field in ["creation_time", "modification_time", "classification"]
        }
        maltiverse_domain["TLD"] = report.get("tld", "")
        maltiverse_domain["Tags"] = create_tags(report.get("tag", ""))
        maltiverse_domain["Address"] = report.get("hostname", "")
        maltiverse_domain = {**maltiverse_domain, **blacklist_context}

        context[outputPaths["domain"]].append(outputs)
        context[DBOT_SCORE_KEY].append(dbot_score)
        context[f'Maltiverse.{outputPaths["domain"]}'].append(maltiverse_domain)

        markdown = f'## Maltiverse Domain reputation for: {report.get("hostname", "")}\n'
        markdown += f'Domain Name: {report.get("hostname", "")}\n'
        markdown += f'Domain Creation Time: **{report.get("creation_time", "")}**\n'
        markdown += f'Domain Modification Time: **{report.get("modification_time", "")}**\n'
        markdown += f'Maltiverse Classification: **{report.get("classification", "")}**\n'

        reports.append(report)

    return markdown, context, reports


def file_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Executes file hash enrichment against Maltiverse.

    Args:
        client (Client): Maltiverse client.
        args (Dict[str, str]): the arguments for the command.

    Returns:
         str: human readable presentation of the file hash report.
         dict: the results to return into Demisto's context.
         Any: the raw data from Maltiverse client (used for debugging).
    """
    threshold = int(args.get("threshold", DEFAULT_THRESHOLD))
    markdown = ""
    context: dict = defaultdict(list)
    reports = []

    for file in argToList(args.get("file", "")):
        report = client.file_report(file)
        if "NotFound" in report:
            markdown += f"No results found for file hash {file}"
            dbot_score = {
                "Indicator": file,
                "Type": "File",
                "Vendor": "Maltiverse",
                "Score": 0,
                "Reliability": client.reliability,
            }
            context[DBOT_SCORE_KEY].append(dbot_score)
            break
        positive_detections = len(report.get("blacklist", []))

        blacklist_context = {"Blacklist": report.get("blacklist", [])}
        blacklist_context["Blacklist"] = create_blacklist_keys(blacklist_context["Blacklist"])

        outputs = {
            "Name": report["filename"][0],
            "MD5": report.get("md5", ""),
            "SHA1": report.get("sha1", ""),
            "SHA256": report.get("sha256", ""),
            "Size": report.get("size", ""),
            "Type": report.get("type", ""),
            "Extension": (report["filename"][0]).split(".")[-1],
            "Path": report.get("process_list", [{}])[0].get("normalizedpath"),
            "Tags": create_tags(report.get("tag", "")),
            "ThreatTypes": {
                "threatcategory": [
                    blacklist_context["Blacklist"][i]["Description"] for i in range(len(report.get("blacklist", [])))
                ]
            },
        }

        dbot_score = {
            "Indicator": file,
            "Type": "File",
            "Vendor": "Maltiverse",
            "Score": calculate_score(
                positive_detections, report.get("classification", ""), threshold, len(report.get("antivirus", []))
            ),
            "Reliability": client.reliability,
        }

        process_list = {
            "ProcessList": {
                string_to_context_key(field): report.get("process_list", [{}])[0].get(field)
                for field in ["name", "normalizedpath", "sha256", "uid"]
            }
        }
        file_malicious = {
            "Malicious": {
                "Vendor": "Maltiverse",
                "Description": [
                    blacklist_context["Blacklist"][i]["Description"] for i in range(len(report.get("blacklist", [])))
                ],
            }
        }

        maltiverse_file = {
            string_to_context_key(field): report.get(field, "")
            for field in [
                "score",
                "classification",
                "modification_time",
                "creation_time",
                "size",
                "contacted_host",
                "dns_request",
            ]
        }
        maltiverse_file["PositiveDetections"] = positive_detections
        maltiverse_file["Name"] = report["filename"][0]
        maltiverse_file["Tags"] = create_tags(report.get("tag", ""))

        maltiverse_file = {**maltiverse_file, **process_list}
        maltiverse_file = {**maltiverse_file, **blacklist_context}
        if positive_detections > 0:
            maltiverse_file = {**maltiverse_file, **file_malicious}

        context[outputPaths["file"]].append(outputs)
        context[DBOT_SCORE_KEY].append(dbot_score)
        context[f'Maltiverse.{outputPaths["file"]}'].append(maltiverse_file)

        markdown = f'## Maltiverse File reputation for: {report["filename"][0]}\n'
        markdown += f'File Name: {report["filename"][0]}\n'
        markdown += f'File SHA256: **{report.get("sha256", "")}**\n'
        markdown += f'File Type: **{report.get("type", "")}**\n'
        markdown += f"Positive Detections: **{positive_detections}**\n"
        markdown += f'Maltiverse Classification: **{report.get("classification", "")}**\n'

        reports.append(report)

    return markdown, context, reports


def main():
    params = demisto.params()
    server_url = params.get("server_url") if params.get("server_url") else SERVER_URL
    reliability = params.get("integrationReliability", "C - Fairly reliable")

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        return_error("Please provide a valid value for the Source Reliability parameter.")

    client = Client(
        url=server_url,
        use_ssl=not params.get("insecure", False),
        use_proxy=params.get("proxy", False),
        auth_token=params.get("credentials_api_key", {}).get("password") or params.get("api_key", None),
        reliability=reliability,
    )

    commands = {
        "ip": ip_command,
        "url": url_command,
        "domain": domain_command,
        "file": file_command,
    }

    command = demisto.command()
    LOG(f"Command being called is {command}")

    try:
        if command == "test-module":
            demisto.results(test_module(client))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            return_error("Command not found.")
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

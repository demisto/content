import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import json
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" GLOBAL VARS """
BASE_URL = demisto.getParam("url")
USERNAME = demisto.getParam("credentials")["identifier"]
PASSWORD = demisto.getParam("credentials")["password"]
AUTH = (USERNAME, PASSWORD)
USE_SSL = not demisto.params().get("insecure", False)
IS_USING_PROXY = demisto.params().get("proxy", False)
LAST_TIME_KEY = "time_last"


def http_request(method, url):
    response = requests.request(method, url, auth=AUTH, verify=USE_SSL)

    if response.status_code != 200:
        return_error(f"Error in API call: [{response.status_code}] - {response.reason}")
    return response


def validate_sha1(sha1):
    if len(sha1) != 40:
        return_error(f"Invalid SHA-1, expected 40 characters: {sha1}")


def validate_ip_of_cidr(ip):
    regex = r"^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$"

    match = re.search(regex, ip)

    if match is None:
        return_error(f"Invalid IP or CIDR: {ip}")


def timestamp_to_string(timestamp):
    if timestamp is None:
        return None

    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def dns_get_command(url):
    response = http_dns_get(url)

    results = [json.loads(line) for line in response.text.splitlines()]
    results = merge_by_rdata(results)

    records = []

    for result in results:
        records.append(create_dns_record_context(result))

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": response.text,
            "HumanReadable": tableToMarkdown(f"CIRCL Dns - {url}", records),
            "EntryContext": {
                "CIRCLdns.Query(val.Value===obj.Value)": {
                    "Value": url,
                    "Record": records,
                }
            },
        }
    )


def http_dns_get(url):
    query_url = f"{BASE_URL}/pdns/query/{url}"

    return http_request("GET", query_url)


# The results may contain several records with the same 'rdata' but different (not interesting) other properties.
# This function will merge the records and keep the later "last seen time".


def merge_by_rdata(results):
    results_map = {}  # type: dict

    for e in results:
        key = e["rdata"]
        other = results_map.get(key)

        if other is not None and other[LAST_TIME_KEY] > e[LAST_TIME_KEY]:
            e = other

        results_map[key] = e

    return list(results_map.values())


def create_dns_record_context(record):
    last_time = timestamp_to_string(record[LAST_TIME_KEY])

    return {
        "Data": record["rdata"],
        "LastTime": last_time,
    }


def list_certificates(queryValue):
    validate_ip_of_cidr(queryValue)
    response = http_list_certificates(queryValue)

    data = response.json()
    records = []

    for ip, ip_data in list(data.items()):
        records.append(create_ip_context(ip, ip_data))

    result = {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": data,
        "HumanReadable": tableToMarkdown(f"List certificates for {queryValue}", records),
        "EntryContext": {"CIRCLssl.IPAddress(val.Value===obj.Value)": records},
    }

    demisto.results(result)


def http_list_certificates(queryValue):
    query_url = f"{BASE_URL}/v2pssl/query/{queryValue}"

    return http_request("GET", query_url)


def create_ip_context(ip, ipData):
    certificates = []

    for sha1 in ipData["certificates"]:
        subjects = ipData["subjects"].get(sha1, {}).get("values", [])
        certificates.append(create_list_certificate_context(sha1, subjects))

    return {"Value": ip, "Certificate": certificates}


def create_list_certificate_context(sha1, subjects):
    return {"SHA1": sha1, "Subjects": subjects}


def list_certificate_seen_ips(sha1, limit):
    validate_sha1(sha1)
    response = http_list_certificate_seen_ips(sha1)

    data = response.json()
    certificate = create_certificate_seen_ips_context(sha1, data, limit)

    result = {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": data,
        "HumanReadable": f'Hits: {str(certificate["Hits"])}',
        "EntryContext": {
            "CIRCLssl.Certificate(val.SHA1===obj.SHA1)": certificate,
        },
    }

    demisto.results(result)


def http_list_certificate_seen_ips(sha1):
    query_url = f"{BASE_URL}/v2pssl/cquery/{sha1}"

    return http_request("GET", query_url)


def create_certificate_seen_ips_context(sha1, data, limit):
    return {
        "SHA1": sha1,
        "Hits": data["hits"],
        "IPAddress": data["seen"][:limit],
    }


def get_certificate_details(sha1):
    validate_sha1(sha1)
    response = http_get_certificate_details(sha1)

    data = response.json()
    certificate = create_certificate_details(sha1, data)

    result = {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": data,
        "HumanReadable": tableToMarkdown(f"CIRCL ssl certificate - {sha1}", certificate),
        "EntryContext": {
            "CIRCLssl.Certificate(val.SHA1===obj.SHA1)": certificate,
        },
    }

    demisto.results(result)


def http_get_certificate_details(sha1):
    query_url = f"{BASE_URL}/v2pssl/cfetch/{sha1}"
    return http_request("GET", query_url)


def create_certificate_details(sha1, data):
    info = data["info"]
    usage = ""
    distribution = ""

    extension = info.get("extension", {})

    usage = extension.get("keyUsage", usage)
    usage = extension.get("extendedKeyUsage", usage)
    distribution = extension.get("crlDistributionPoints", distribution)
    times_seen = data.get("icsi", {}).get("times_seen")

    return {
        "SHA1": sha1,
        "Usage": usage,
        "Distribution": distribution,
        "Issuer": info["issuer"],
        "Time": info["not_before"],
        "Subject": info["subject"],
        "Key": info["key"],
        "Pem": data["pem"],
        "Seen": times_seen,
    }


""" EXECUTION CODE """

LOG(f"command is {demisto.command()}")
try:
    command = demisto.command()
    args = demisto.args()
    handle_proxy()

    if command == "test-module":
        result = http_dns_get("test.com")
        demisto.results("ok")

    elif command == "circl-dns-get":
        dns_get_command(args.get("queryValue"))

    elif command == "circl-ssl-list-certificates":
        list_certificates(args.get("queryValue"))

    elif command == "circl-ssl-query-certificate":
        limit = int(args.get("limitResults", 100))
        sha1 = args.get("certificate")

        list_certificate_seen_ips(sha1, limit)

    elif command == "circl-ssl-get-certificate":
        get_certificate_details(args.get("certificate"))

except Exception as e:
    return_error(str(e))

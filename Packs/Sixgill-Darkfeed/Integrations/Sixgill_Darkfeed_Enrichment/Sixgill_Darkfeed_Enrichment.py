import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """

from typing import Dict, List, Any, Callable
import traceback
import requests

from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from sixgill.sixgill_enrich_client import SixgillEnrichClient

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

""" GLOBALS/PARAMS """

CHANNEL_CODE = "7698e8287dfde53dcd13082be750a85a"
SUSPICIOUS_FEED_IDS = ["darkfeed_003"]
VERIFY = not demisto.params().get("insecure", True)
SESSION = requests.Session()

HASH_MAPPING = {
    "hashes.md5": "md5",
    "hashes.'sha-1'": "sha1",
    "hashes.'sha-256'": "sha256",
    "hashes.'sha-512'": "sha512",
    "hashes.ssdeep": "ssdeep",
}

""" HELPER FUNCTIONS """

hashes: Dict[str, Any] = {}

stix_regex_parser = re.compile(r"([\w-]+?):(\w.+?) (?:[!><]?=|IN|MATCHES|LIKE) '(.*?)' *[OR|AND|FOLLOWEDBY]?")


def to_demisto_score(feed_id: str, revoked: bool):
    if revoked:
        return Common.DBotScore.NONE  # unknown
    if feed_id in SUSPICIOUS_FEED_IDS:
        return Common.DBotScore.SUSPICIOUS  # suspicious
    return Common.DBotScore.BAD  # bad


""" COMMANDS + REQUESTS FUNCTIONS """


def test_module_command(*args):
    """
    Performs basic Auth request
    """
    response = SESSION.send(
        request=SixgillAuthRequest(
            demisto.params()["client_id"], demisto.params()["client_secret"], CHANNEL_CODE
        ).prepare(),
        verify=VERIFY,
    )
    if not response.ok:
        raise Exception("Auth request failed - please verify client_id, and client_secret.")
    return "ok", None, "ok"


def get_score(indicator):
    return to_demisto_score(indicator.get("sixgill_feedid"), indicator.get("revoke", False))


def get_file_hashes(indicators: list = []):
    for indicator in indicators:
        process_file_hashes(indicator, demisto)

    return hashes


def process_file_hashes(stix2obj: Dict[str, Any], log):
    pattern = stix2obj.get("pattern", "")
    global hashes

    for match in stix_regex_parser.findall(pattern):
        try:
            _, sub_type, value = match
            if HASH_MAPPING[sub_type.lower()] not in hashes:
                hashes[HASH_MAPPING[sub_type.lower()]] = value

        except Exception as e:
            log.error(f"failed to get file hashes from: {e}, STIX object: {stix2obj}")
            continue


def ip_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    ips = argToList(args.get("ip"))
    skip = int(args.get("skip"))

    if len(ips) == 0:
        raise ValueError("IP(s) not specified")

    command_results: List[CommandResults] = []

    for ip in ips:
        ip_data = client.enrich_ioc("ip", ip, skip)

        score = 0
        if len(ip_data) != 0:
            score = max(list(map(get_score, ip_data)))

        dbot_score = Common.DBotScore(
            indicator=ip, indicator_type=DBotScoreType.IP, integration_name="SixgillDarkfeedEnrichment", score=score
        )

        ip_standard_context = Common.IP(ip=ip, dbot_score=dbot_score)

        readable_output = tableToMarkdown("IP", ip_data)

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="Sixgill.IP",
                outputs_key_field="ip",
                outputs=ip_data,
                indicator=ip_standard_context,
            )
        )
    return command_results


def domain_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    domains = argToList(args.get("domain"))
    skip = int(args.get("skip"))

    if len(domains) == 0:
        raise ValueError("DOMAIN(s) not specified")

    command_results: List[CommandResults] = []

    for domain in domains:
        domain_data = client.enrich_ioc("domain", domain, skip)

        score = 0
        if len(domain_data) != 0:
            score = max(list(map(get_score, domain_data)))

        dbot_score = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name="SixgillDarkfeedEnrichment",
            score=score,
        )

        domain_standard_context = Common.Domain(domain=domain, dbot_score=dbot_score)

        readable_output = tableToMarkdown("Domain", domain_data)

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="Sixgill.DOMAIN",
                outputs_key_field="domain",
                outputs=domain_data,
                indicator=domain_standard_context,
            )
        )
    return command_results


def url_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    urls = argToList(args.get("url"))
    skip = int(args.get("skip"))

    if len(urls) == 0:
        raise ValueError("URL(s) not specified")

    command_results: List[CommandResults] = []

    for url in urls:
        url_data = client.enrich_ioc("url", url, skip)

        score = 0
        if len(url_data) != 0:
            score = max(list(map(get_score, url_data)))

        dbot_score = Common.DBotScore(
            indicator=url, indicator_type=DBotScoreType.URL, integration_name="SixgillDarkfeedEnrichment", score=score
        )

        url_standard_context = Common.URL(url=url, dbot_score=dbot_score)

        readable_output = tableToMarkdown("URL", url_data)

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="Sixgill.URL",
                outputs_key_field="url",
                outputs=url_data,
                indicator=url_standard_context,
            )
        )
    return command_results


def file_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    files = argToList(args.get("file"))
    skip = int(args.get("skip"))

    if len(files) == 0:
        raise ValueError("HASH(s) not specified")

    command_results: List[CommandResults] = []

    for file_hash in files:
        file_data = client.enrich_ioc("hash", file_hash, skip)

        score = 0
        if len(file_data) != 0:
            score = max(list(map(get_score, file_data)))

        file_hash_types = get_file_hashes(file_data)

        dbot_score = Common.DBotScore(
            indicator=file_hash,
            indicator_type=DBotScoreType.FILE,
            integration_name="SixgillDarkfeedEnrichment",
            score=score,
        )

        file_standard_context = Common.File(
            md5=file_hash_types.get("md5"),
            sha256=file_hash_types.get("sha256"),
            sha1=file_hash_types.get("sha1"),
            sha512=file_hash_types.get("sha512"),
            ssdeep=file_hash_types.get("ssdeep"),
            dbot_score=dbot_score,
        )

        readable_output = tableToMarkdown("File", file_data)

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="Sixgill.File",
                outputs_key_field="file",
                outputs=file_data,
                indicator=file_standard_context,
            )
        )
    return command_results


def actor_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    actors = argToList(args.get("actor"))
    skip = int(args.get("skip"))

    if len(actors) == 0:
        raise ValueError("ACTOR(s) not specified")

    command_results: List[CommandResults] = []

    for actor in actors:
        actor_data = client.enrich_actor(actor, skip)

        readable_output = tableToMarkdown("ACTOR", actor_data)

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="Sixgill.ACTOR",
                outputs_key_field="actor",
                outputs=actor_data,
            )
        )
    return command_results


def postid_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    postids = argToList(args.get("post_id"))
    skip = int(args.get("skip"))

    if len(postids) == 0:
        raise ValueError("POSTID(s) not specified")

    command_results: List[CommandResults] = []

    for post_id in postids:
        post_id_data = client.enrich_postid(post_id, skip)

        readable_output = tableToMarkdown("POSTID", post_id_data)

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="Sixgill.POSTID",
                outputs_key_field="postid",
                outputs=post_id_data,
            )
        )
    return command_results


""" COMMANDS MANAGER / SWITCH PANEL """


def main():
    SESSION.proxies = handle_proxy()

    enrich_client = SixgillEnrichClient(
        demisto.params()["client_id"], demisto.params()["client_secret"], CHANNEL_CODE, demisto, SESSION, VERIFY
    )

    command = demisto.command()
    demisto.info(f"Command being called is {command}")
    commands: Dict[str, Callable] = {
        "test-module": test_module_command,
    }
    try:
        if demisto.command() == "ip":
            return_results(ip_reputation_command(enrich_client, demisto.args()))
        elif demisto.command() == "domain":
            return_results(domain_reputation_command(enrich_client, demisto.args()))
        elif demisto.command() == "url":
            return_results(url_reputation_command(enrich_client, demisto.args()))
        elif demisto.command() == "file":
            return_results(file_reputation_command(enrich_client, demisto.args()))
        elif demisto.command() == "actor":
            return_results(actor_reputation_command(enrich_client, demisto.args()))
        elif demisto.command() == "post_id":
            return_results(postid_reputation_command(enrich_client, demisto.args()))
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())

            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Error failed to execute {demisto.command()}, error: [{e}]")


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

from CommonServerPython import *  # noqa: F401
import traceback
from certstream.core import CertStreamClient
from datetime import datetime


VENDOR = "Kali Dog Security"
PRODUCT = "CertStream"


def build_xsoar_grid(data: dict) -> list:
    return [{"title": key.lower(), "value": value} for key, value in data.items()]


def set_incident_severity(similarity: float) -> int:
    """

    Args:
        similarity (float): Similarity score between 0 and 1.

    Returns:
        int: Cortex XSOAR Severity (1 to 4)
    """

    if similarity >= 0.85:
        return IncidentSeverity.CRITICAL

    elif 0.85 > similarity >= 0.75:
        return IncidentSeverity.HIGH

    elif 0.75 > similarity >= 0.65:
        return IncidentSeverity.MEDIUM

    else:
        return IncidentSeverity.LOW


def create_xsoar_incident(certificate: dict, domain: str, current_time: datetime, result: dict):
    """Creates an XSOAR 'New Suspicious Domain` incident using the certificate and domain details

    Args:
        certificate (dict): The certificate details from CertStream
        domain (str): The domain matching the homograph
        current_time (datetime): The time the match occurred at
        result (dict): A dictionary containing details about the match like similarity score and matched asset.
    """
    demisto.info(f'Creating a new suspicious domain incident for {domain}')

    incident = {
        "name": f"Suspicious Domain Discovered - {domain}",
        "occured": current_time,
        "type": "newsuspiciousdomain",
        "severity": set_incident_severity(result["similarity"]),
        "CustomFields": {
            "fingerprint": certificate["data"]["leaf_cert"]["fingerprint"],
            "levenshtein_distance": result["similarity"],
            "userasset": result["asset"]
        }
    }

    demisto.createIncidents([incident])


def create_xsoar_certificate_indicator(certificate: dict):
    """Creates an XSOAR certificate indicator

    Args:
        certificate (dict): An X.509 certificate object from CertStream
    """
    certificate_data = certificate["data"]["leaf_cert"]

    demisto.info(f'Creating an X.509 indicator {certificate_data["fingerprint"]}')

    demisto.createIndicators([{
        "type": "X.509 Certificate",
        "value": certificate_data["fingerprint"],
        "sourcetimestamp": datetime.fromtimestamp(certificate_data["seen"]),
        "fields": {
            "serialnumber": certificate_data["serial_number"],
            "validitynotbefore": datetime.fromtimestamp(certificate_data["not_before"]),
            "validitynotafter": datetime.fromtimestamp(certificate_data["not_after"]),
            "source": certificate["data"]["source"]["name"],
            "domains": [{"domain": domain} for domain in certificate_data["all_domains"]],
            "signaturealgorithm": certificate_data["signature_algorithm"].sub(" ", "").split(","),
            "subject": build_xsoar_grid(certificate_data["subject"]),
            "issuer": build_xsoar_grid(certificate_data["issuer"]),
            "x.509v3extensions": build_xsoar_grid(certificate_data["issuer"]),
            "tags": ["Fake Domain", "CertStream"]
        },
        "rawJSON": certificate,
        "relationships": create_relationship_list(certificate_data["fingerprint"], certificate_data["all_domains"])
    }])


def create_relationship_list(value: str, domains: list[str]) -> list[EntityRelationship]:
    """Creates an XSOAR relationship object

    Args:
        value (str): The certificate fingerprint value
        domains (list[str]): A list of domains in the certificate

    Returns:
        list[EntityRelationship]: A list of XSOAR relationship objects
    """
    relationships = []
    entity_a = value
    for domain in domains:
        relation_obj = EntityRelationship(
            name=EntityRelationship.Relationships.RELATED_TO,
            entity_a=entity_a,
            entity_a_type="X.509 Certificate",
            entity_b=domain,
            entity_b_type="Domain")
        relationships.append(relation_obj.to_indicator())
    return relationships


def check_homographs(domain: str, user_homographs: dict, levenshtein_distance_threshold: float) -> tuple[bool, dict]:
    """Checks each word in a domain for similarity to the provided homograph list.

    Args:
        domain (str): The domain to check for homographs
        user_homographs (dict): A list of homograph strings from XSOAR
        levenshtein_distance_threshold (float): The Levenshtein distance threshold for determining similarity between strings

    Returns:
        bool: Returns True if any word in the domain matches a homograph, False otherwise
    """
    words = domain.split(".")[:-1]  # All words in the domain without the TLD

    for word in words:
        for asset, homographs in user_homographs.items():
            for homograph in homographs:
                similarity = compute_similarity(homograph, word)
                if similarity > levenshtein_distance_threshold:
                    return True, {"similarity": similarity,
                                  "homograph": homograph,
                                  "asset": asset}

    return False, {"similarity": similarity,
                   "homograph": homograph,
                   "asset": asset}


def fetch_certificates(message: dict, context: dict) -> None:
    """A callback function that handles each message from the CertStream feed.

    Args:
        message (dict): A single X.509 certificate message from the Certificate Transparency feed.
        context (dict): The context object passed to the callback which can be used to store state across messages.
    """

    if message["message_type"] == "certificate_update":
        all_domains = message["data"]["leaf_cert"]["all_domains"]

        if len(all_domains) == 0:
            return  # No domains found in the certificate
        else:
            for domain in all_domains:
                # Check for homographs
                is_suspicious_domain, result = check_homographs(domain, context["homographs"],
                                                                context["levenshtein_distance_threshold"])
                if is_suspicious_domain:
                    now = datetime.now()
                    demisto.info(f"Potential homograph match found for domain: {domain}")
                    create_xsoar_certificate_indicator(message)
                    create_xsoar_incident(message, domain, now, result)


def get_homographs_list(list_name: str) -> dict:
    """Fetches ths latest list of homographs from XSOAR

    Args:
        list_name (str): The name of the XSOAR list to fetch

    Returns:
        list: A list of homographs
    """
    try:
        lists = json.loads(demisto.internalHttpRequest("GET", "/lists/").get("body", {}))
        demisto.info('Fetching homographs list from XSOAR ({word_list_name})')

    except Exception as e:
        demisto.error(f"{e}")

    for user_list in lists:
        if user_list["id"] != list_name:
            continue

        else:
            return json.loads(user_list["data"])

    demisto.error("List of words not found")
    raise OSError


def levenshtein_distance(original_string: str, reference_string: str) -> float:
    """The Levenshtein distance is a string metric for measuring the difference between two sequences.

    Args:
        original_string (str): The initial string to compare to
        reference_string (str): The string to compare against the original

    Returns:
        float: The Levenshtein distance between the two strings
    """
    m, n = len(original_string), len(reference_string)
    if m < n:
        original_string, reference_string = reference_string, original_string
        m, n = n, m
    d = [list(range(n + 1))] + [[i] + [0] * n for i in range(1, m + 1)]
    for j in range(1, n + 1):
        for i in range(1, m + 1):
            if original_string[i - 1] == reference_string[j - 1]:
                d[i][j] = d[i - 1][j - 1]
            else:
                d[i][j] = min(d[i - 1][j], d[i][j - 1], d[i - 1][j - 1]) + 1
    return d[m][n]


def compute_similarity(input_string: str, reference_string: str) -> float:
    """Computes the Levenshtein similarity between two strings.

    Args:
        input_string (str): The initial string to compare
        reference_string (str): The new string to compare against the input string

    Returns:
        float: _description_
    """
    distance = levenshtein_distance(input_string, reference_string)
    max_length = max(len(input_string), len(reference_string))
    similarity = 1 - (distance / max_length)
    return similarity


def long_running_execution_command(host: str, word_list_name: str, list_update_interval: int, levenshtein_distance_threshold: float):
    demisto.info("Starting CertStream Listener")
    c = CertStreamClient(fetch_certificates, url=host, skip_heartbeats=True, on_open=None, on_error=None)
    c._context = {
        "fetch_time": datetime.now(),
        "homographs": get_homographs_list(word_list_name),
        "levenshtein_distance_threshold": levenshtein_distance_threshold
    }

    while True:
        try:
            now = datetime.now()
            if now - c._context["fetch_time"] >= timedelta(minutes=list_update_interval):
                demisto.info('Updating homographs list "{word_list_name}"')
                c._context["fetch_time"] = now
                c._context["homographs"] = get_homographs_list(word_list_name)

            c.run_forever(ping_interval=15)
            time.sleep(5)

        except Exception as e:
            demisto.error(e)


def test_module(host: str, word_list_name: str):
    def on_message(message: dict, context: dict):
        """ A callback function that handles each message from the CertStream feed.

        Args:
            message (dict): A single X.509 certificate message from the Certificate Transparency feed.
            context (dict): The context object passed to the callback which can be used to store state across messages.

        Raises:
            KeyboardInterrupt: After 2 messages raises an interruption to stop the loop.
        """
        context["messages"] += 1
        demisto.debug(f'Got {context["messages"]} message(s)')
        if context["messages"] == 2:
            raise KeyboardInterrupt

    try:
        try:
            get_homographs_list(word_list_name)

        except Exception:
            demisto.error(f'Words list {word_list_name} not found')
            return f'Words list "{word_list_name}" not found'

        c = CertStreamClient(on_message, url=host, skip_heartbeats=True, on_open=None, on_error=None)
        c._context = {"messages": 0}
        c.run_forever(ping_interval=15)
        c.close()
        return "ok"

    except Exception as e:
        demisto.error(e)


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    host: str = params["url"]
    word_list_name: str = params["list_name"]
    list_update_interval: int = params.get("update_interval", 30)
    levenshtein_distance_threshold: float = float(params.get("levenshtein_distance_threshold", 0.85))

    try:
        if command == "long-running-execution":
            return_results(long_running_execution_command(host,
                                                          word_list_name,
                                                          list_update_interval,
                                                          levenshtein_distance_threshold))
        elif command == "test-module":
            return_results(test_module(host, word_list_name))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception:
        return_error(f"Failed to execute {command} command.\nError:\n{traceback.format_exc()}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

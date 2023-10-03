from CommonServerPython import *  # noqa: F401
import traceback
from certstream.core import CertStreamClient
from datetime import datetime


VENDOR = "Kali Dog Security"
PRODUCT = "CertStream"


def build_xsoar_grid(data: dict) -> list:
    return [{"title": key.lower(), "value": value} for key, value in data.items()]


def create_xsoar_certificate_indicator(certificate: dict):
    """Creates an XSOAR certificate indicator

    Args:
        certificate (dict): An X.509 certificate object from CertStream
    """
    certificate_data = certificate["data"]["leaf_cert"]
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

def check_homographs(domain: str, homographs: list, levenshtein_distance_threshold: float) -> bool:
    """Checks each word in a domain for similarity to the provided homograph list.

    Args:
        domain (str): The domain to check for homographs
        homographs (list): A list of homograph strings from XSOAR
        levenshtein_distance_threshold (float): The Levenshtein distance threshold for determining similarity between strings

    Returns:
        bool: Returns True if any word in the domain matches a homograph, False otherwise
    """
    words = domain.split(".")[:-1]  # All words in the domain without the TLD
    for word in words:
        for homograph in homographs:
            if compute_similarity(homograph, word) > levenshtein_distance_threshold:
                return True
    return False


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
                if check_homographs(domain, context["homographs"], context["levenshtein_distance_threshold"]):
                    demisto.info(f"Potential homograph match found for domain: {domain}")
                    create_xsoar_certificate_indicator(message)
                    ## TODO create incident or alert ##

        now = datetime.now()
        domains = ", ".join(message["data"]["leaf_cert"]["all_domains"][1:])
        demisto.info(f"[{now:%m/%d/%y %H:%M:%S}] {domain} (SAN: {domains})\n")


def test_module(host: str):
    def on_message(message: dict, context: dict):
        """ A callback function that handles each message from the CertStream feed.

        Args:
            message (dict): A single X.509 certificate message from the Certificate Transparency feed.
            context (dict): The context object passed to the callback which can be used to store state across messages.

        Raises:
            KeyboardInterrupt: After 2 messages raises an interruption to stop the loop.
        """
        context["messages"] += 1
        if context["messages"] == 2:
            raise KeyboardInterrupt

    try:
        c = CertStreamClient(on_message, url=host, skip_heartbeats=True, on_open=None, on_error=None)
        c._context = {"messages": 0}
        c.run_forever(ping_interval=15)
        c.close()
        return "ok"

    except Exception as e:
        demisto.error(e)


def get_homographs_list(list_name: str) -> list:
    """Fetches ths latest list of homographs from XSOAR

    Args:
        list_name (str): The name of the XSOAR list to fetch

    Returns:
        list: A list of homographs
    """
    lists = json.loads(demisto.internalHttpRequest("GET", "/lists/")).get("body", {})
    for list in lists:
        if list["id"] != list_name:
            continue

        else:
            return list["data"].split("\n")

    demisto.error("List of words not found")
    raise


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
                c._context["fetch_time"] = now
                c._context["homographs"] = get_homographs_list(word_list_name)

            c.run_forever(ping_interval=15)
            time.sleep(5)
        except Exception as e:
            demisto.error(e)


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


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    host: str = params["url"]
    word_list_name: str = params["list_name"]
    list_update_interval: int = params.get("update_interval", 30)
    levenshtein_distance_threshold: float = params.get("levenshtein_distance_threshold", 0.85)

    try:
        if command == "long-running-execution":
            return_results(long_running_execution_command(host,
                                                          word_list_name,
                                                          list_update_interval,
                                                          levenshtein_distance_threshold))
        elif command == "test-module":
            return_results(test_module(host))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception:
        return_error(f"Failed to execute {command} command.\nError:\n{traceback.format_exc()}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

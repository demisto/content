import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import base64
import requests


class MinemeldException(Exception):
    pass


class MinemeldClient:
    def __init__(self, url, user, pw):
        self.url = url
        self.user = user
        self.pw = pw

        auth_str = "{}:{}".format(user, pw)
        b = auth_str.encode()
        self.auth = base64.b64encode(b)
        self.headers = {
            "Authorization": "Basic {}".format(self.auth.decode())
        }

    def get(self, path):
        full_url = "/".join([self.url, path])
        r = requests.get(full_url, headers=self.headers, verify=False)
        if r.status_code != 200:
            raise MinemeldException("Failed to send request {}: {}".format(full_url, r.content))
        return r.json()

    def get_nodes(self):
        data = self.get("config/running")
        return data.get("result").get("nodes")

    def get_indicators(self, node_name):
        path = f"config/data/{node_name}_indicators"
        try:
            data = self.get(path)
        # If the list is empty, exception is raised, so we catch that and return an empty list.
        except MinemeldException:
            return []

        return data.get("result")


def process_ip_list(client: MinemeldClient, node_name: str, node, indicator_type):
    """
    Process generic IPv4 lists, which can contain addresses and CIDR blocks
    """
    indicator_list = client.get_indicators(node_name)
    new_indicators = []
    for indicator in indicator_list:
        indicator_value = indicator.get("indicator")
        # Check if indicator is CIDR
        if "/" in indicator_value:
            if ":" in indicator_value:
                indicator_type = "IPv6CIDR"
            else:
                indicator_type = "CIDR"

        new_indicator = {
            "value": indicator_value,
            "description": indicator.get("comment", ""),
            "trafficlightprotocol": indicator.get("share_level", "green"),
            "type": indicator_type,
            "tags": node_name
        }
        new_indicators.append(new_indicator)

    return new_indicators


def process_generic_list(client: MinemeldClient, node_name: str, node, indicator_type):
    """
    Process all other types of manual lists, importing the indicators based on given indicator_type
    """
    indicator_list = client.get_indicators(node_name)
    new_indicators = []
    for indicator in indicator_list:
        indicator_value = indicator.get("indicator")
        new_indicator = {
            "value": indicator_value,
            "description": indicator.get("comment", ""),
            "trafficlightprotocol": indicator.get("share_level", "green"),
            "type": indicator_type,
            "tags": node_name
        }
        new_indicators.append(new_indicator)

    return new_indicators


SUPPORTED_PROTOTYPES = {
    "stdlib.listIPv4Generic": process_ip_list,
    "stdlib.listIPv6Generic": process_ip_list,
    "stdlib.listDomainGeneric": process_generic_list,
    "stdlib.listURLGeneric": process_generic_list,
}
PROTOTYPE_MAP = {
    "stdlib.listIPv4Generic": "IP",
    "stdlib.listIPv6Generic": "IPv6",
    "stdlib.listDomainGeneric": "Domain",
    "stdlib.listURLGeneric": "URL",
}


def process_nodes(client, node_dict):
    """
    Given the dictionary of minemeld nodes, retrieve each indicator list and convert into indicator dicts.
    """
    new_indicators = []
    for node_name, node in node_dict.items():
        prototype = node.get("prototype")
        if prototype in SUPPORTED_PROTOTYPES:
            indicator_type = PROTOTYPE_MAP.get(prototype)
            new_indicators = new_indicators + SUPPORTED_PROTOTYPES[prototype](client, node_name, node, indicator_type)

    return new_indicators


def main(client):
    node_dict = client.get_nodes()
    indicators = process_nodes(client, node_dict)
    for i in indicators:
        res = demisto.executeCommand("createNewIndicator", i)
        if is_error(res):
            raise DemistoException("Failed to run set indicator for: {}".format(":".join(i.values())))

    md = "## Added {} indicators to system from {} nodes\n".format(len(indicators), len(node_dict.keys()))
    md = md + tableToMarkdown("Created Indicators", indicators)
    cr = CommandResults(
        readable_output=md
    )
    return_results(cr)
    return indicators


if __name__ in ('__builtin__', 'builtins'):
    user = demisto.args().get("username")
    password = demisto.args().get("password")
    url = demisto.args().get("url")
    c = MinemeldClient(
        url,
        user,
        password
    )
    main(c)

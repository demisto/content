import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib3
import json
import re
from typing import Any, Dict

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, address: str,
                 username: str,
                 password: str,
                 port: int = 41395,
                 version: str = "v3"):
        super().__init__(base_url=f"https://{address}:{port}/{version}/",
                         auth=(username, password),
                         verify=False,
                         proxy=False,
                         headers={'Content-Type': "application/json"})
        self._session.cookies.set(name='rest_token', value=self._get_auth(), domain=address)

    def create_search(self, args: Dict[str, Any]):
        endpoint = 'fmsearch'
        json_data = {
            'rest_token': self._session.cookies.get('rest_token'),
            'search_name': args.get('search_name'),
            'search_filter': args.get('search_filter'),
            'begin_time': args.get('begin_time'),
            'end_time': args.get('end_time')
        }
        fmgroups = args.get('fmgroups')
        max_packets = args.get('max_packets')
        if fmgroups:
            json_data['fmgroups'] = fmgroups
        if max_packets:
            json_data['max_packets'] = max_packets

        return self._http_request(
            method='POST',
            full_url=urljoin(self._base_url, endpoint),
            json_data=json_data
        )

    def delete_search(self, search_id: str):
        endpoint = 'fmsearch'
        params = {
            "rest_token": self._session.cookies.get('rest_token'),
            "searchname": search_id
        }
        return self._http_request(
            method='DELETE',
            full_url=urljoin(self._base_url, endpoint),
            params=params
        )

    def download_pcap(self, search_id: str, node_name: str):
        endpoint = 'fnpcaps'
        params = {
            'searchname': search_id,
            'nodename': node_name
        }
        params.update(self._session.cookies)
        return self._http_request(
            method='GET',
            full_url=urljoin(self._base_url, endpoint),
            params=params
        )

    def download_metadata(self, search_id: str, node_name: str):
        endpoint = 'fnmetadata'
        params = {
            'searchname': search_id,
            'nodename': node_name
        }
        params.update(self._session.cookies)
        return self._http_request(
            method='GET',
            full_url=urljoin(self._base_url, endpoint),
            params=params
        )

    def get_search_status(self, node_name: str, search_id: str):
        endpoint = 'fnsearchstatus'
        params = {
            'searchname': search_id,
            'nodename': node_name
        }
        params.update(self._session.cookies)
        return self._http_request(
            method='GET',
            full_url=urljoin(self._base_url, endpoint),
            params=params
        )

    def get_server_status(self):
        endpoint = 'fmping'
        return self._http_request(
            method='GET',
            full_url=urljoin(self._base_url, endpoint),
            params=self._session.cookies)

    def _get_auth(self) -> str:
        endpoint = 'fmlogin'
        json_data = {
            'username': self._auth[0],
            'password': self._auth[1]
        }

        response = self._http_request(
            method='POST',
            full_url=urljoin(self._base_url, endpoint),
            json_data=json_data)

        if isinstance(response, Dict):
            return str(response.get('rest_token'))
        else:
            raise Exception(f'Authentication failed, unexpected response: {response}')


''' HELPER FUNCTIONS '''


def bytes_to_readable(response):
    # Search was cancelled
    if response["SearchResult"] == "Cancelled":
        readable_output = "Search was cancelled"
        response["SearchStatus"] = "Cancelled"
        response["SearchResult"] = "NoPcapData"
    # Search was completed with no pcap data
    elif response["SearchResult"] == "NoPcapData":
        readable_output = "Search completed: No results found"
        response["SearchStatus"] = "Completed"
    else:
        # Default
        results = response["SearchResult"]
        sizestr = response["SearchResult"].split(" ")[-1].split("=")[-1]
        size, unit = re.match(r"(\d+)(\D+)", sizestr).groups()
        if unit == "KB":
            response["PcapSize"] = int(size) * 1024
        elif unit == "MB":
            response["PcapSize"] = int(size) * (1024 ** 2)
        elif unit == "GB":
            response["PcapSize"] = int(size) * (1024 ** 3)
        else:
            response["PcapSize"] = ">=1TB"
        readable_output = f"Search completed: {results}"
        response["SearchStatus"] = "Completed"
    return response, readable_output


''' COMMANDS '''


def create_search_command(client: Client, args: Dict[str, Any]):
    generate_links = False

    response = client.create_search(args)

    SearchID = re.search("searchname=(.*?)&", response[0].get("checkstatus")).group(1)

    outputs = {"NodeName": []}
    node_str = ""
    for i in range(len(response)):
        NodeName = re.search(r"nodename=([\w\d]+)", response[i].get("checkstatus")).group(1)
        outputs["NodeName"].append(NodeName)
        node_str += f"{NodeName},"
    node_str = node_str[:-1]

    readable_output = f"SearchID : {SearchID}\nNodeName(s) : {node_str}"

    outputs["SearchID"] = SearchID

    if generate_links:
        readable_output += "\n"
        outputs["checkstatus"] = []
        outputs["getpcaps"] = []
        outputs["metadata"] = []
        for i in range(len(response)):
            for key in response[i]:
                value = str(response[i].get(key))
                readable_output += f"{key} : {value}\n"
            readable_output = readable_output[:-1]
            outputs["checkstatus"].append(response[i].get("checkstatus"))
            outputs["getpcaps"].append(response[i].get("getpcaps"))
            outputs["metadata"].append(response[i].get("metadata"))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SentryWire.Investigator.Search',
        outputs_key_field='SearchID',
        outputs=outputs
    )


def delete_search_command(client: Client, args: Dict[str, Any]):
    SearchID = args.get("SearchID")
    response = client.delete_search(search_id=str(SearchID))
    response["SearchID"] = SearchID
    return CommandResults(
        readable_output=f"{SearchID} has been deleted!",
        outputs_prefix='SentryWire.Investigator.Deleted',
        outputs_key_field='SearchID',
        outputs=response
    )


def download_pcap_command(client: Client, args: Dict[str, Any]):
    SearchID = args.get('SearchID')
    nodename = args.get('NodeName')
    file_entry = fileResult(
        filename=f'{SearchID}.pcap',
        data=client.download_pcap(search_id=str(SearchID), node_name=str(nodename)).content
    )
    return file_entry


def download_metadata_command(client: Client, args: Dict[str, Any]):
    SearchID = args.get('SearchID')
    nodename = args.get('NodeName')
    file_entry = fileResult(
        filename=f'{SearchID}.zip',
        data=client.download_metadata(search_id=str(SearchID), node_name=str(nodename)).content
    )
    return file_entry


def get_search_status_command(client: Client, args: Dict[str, Any]):
    SearchID = args.get('SearchID')
    nodename = args.get('NodeName')

    # Status request
    response = client.get_search_status(search_id=str(SearchID), node_name=str(nodename))

    # Add SearchID/NodeName
    response["SearchID"] = SearchID

    # Remove redundant/superfluous data
    redundant = ["SearchName",
                 "SearchKey",
                 "ID",
                 "CaseName",
                 "MasterToken",
                 "SearchPorts",
                 "SubmittedTime",
                 "MaxChunk",
                 "SearchType"]
    for key in redundant:
        try:
            response.pop(key)
        except KeyError:
            pass

    # Parse status
    if "SearchResult" in response:
        response, readable_output = bytes_to_readable(response)
    else:
        results = response["SearchStatus"]
        readable_output = f"Search status: {results}"
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SentryWire.Investigator.Status',
        outputs_key_field='SearchID',
        outputs=response
    )


def get_server_status_command(client: Client):
    response = client.get_server_status()
    status = json.loads(response.get("ServerInfo")).get("Status")
    readable_output = f"Status: {status}"
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SentryWire.Server',
        outputs_key_field='',
        outputs=response
    )


def test_module(client: Client) -> str:
    try:
        client.get_server_status()
    except Exception as e:
        raise Exception(f'Failed to execute test-module command. Error: {str(e)}')
    return 'ok'


def main() -> None: # pragma: no cover
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    unitaddress = params.get('unitaddress')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            address=unitaddress,
            username=username,
            password=password
        )

        if command == "test-module":
            return_results(test_module(client))

        if command == "sentrywire-get-pcap":
            return_results(download_pcap_command(client, demisto.args()))

        if command == "sentrywire-get-metadata":
            return_results(download_metadata_command(client, demisto.args()))

        if command == "sentrywire-get-search-status":
            return_results(get_search_status_command(client, demisto.args()))

        if command == "sentrywire-create-search":
            return_results(create_search_command(client, demisto.args()))

        if command == "sentrywire-delete-search":
            return_results(delete_search_command(client, demisto.args()))

        if command == "sentrywire-get-server-status":
            return_results(get_server_status_command(client))

    except Exception as e:
        return_error(f'Failed to execute {str(command)} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
from typing import List, Dict, Any

# Update the integration parameters to match your Listmonk setup
LISTMONK_URL = demisto.params().get("listmonk_url", None)
LISTMONK_USERNAME = demisto.params().get("listmonk_username", None)
LISTMONK_PASSWORD = demisto.params().get("listmonk_password", None)


class ListmonkClient:

    def __init__(self, url: str, username: str, password: str):
        self.base_url = url.rstrip('/')
        self.auth = (username, password)

    def get_lists(self) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/api/lists"
        response = self._send_request("GET", endpoint)
        lists = response.json()
        lists_entry = {
            "Type": entryTypes['note'],
            "Contents": lists,
            "ContentsFormat": formats['json'],
            "ReadableContentsFormat": formats['markdown'],
            "HumanReadable": tableToMarkdown('Listmonk Lists', lists),
            "EntryContext": {"Listmonk.ListsResults": createContext(lists)}
        }
        return lists_entry

    def get_subscribers(self, list_id: str) -> List[Dict[str, Any]]:
        endpoint = f"{self.base_url}/api/subscribers?list_id={list_id}"
        response = self._send_request("GET", endpoint)
        subscribers = response.json()
        subscribers_entry = {
            "Type": entryTypes['note'],
            "Contents": subscribers,
            "ContentsFormat": formats['json'],
            "ReadableContentsFormat": formats['markdown'],
            "HumanReadable": tableToMarkdown('Listmonk Subscribers', subscribers),
            "EntryContext": {"Listmonk.SubscribersResults": createContext(subscribers)}
        }
        return subscribers_entry

    def add_subscriber(self, email: str, name: str, status: str, list_ids: List[int], attributes: Dict[str, Any] = None) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/api/subscribers"
        data = {"email": email, "name": name, "status": status, "lists": list_ids, "attribs": attributes}
        response = self._send_request("POST", endpoint, json_data=data)
        return response.json()

    def _send_request(self, method: str, url: str, json_data: Dict[str, Any] = None) -> requests.Response:
        response = requests.request(method, url, auth=self.auth, json=json_data, verify=False)
        response.raise_for_status()
        return response


def main():
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    client = ListmonkClient(LISTMONK_URL, LISTMONK_USERNAME, LISTMONK_PASSWORD)

    try:
        if command == 'listmonk-get-lists':
            lists = client.get_lists()
            return_results(lists)

        elif command == 'listmonk-get-subscribers':
            list_id = args.get('list_id')
            if not list_id:
                return_error("Missing 'list_id' argument.")
            subscribers = client.get_subscribers(list_id)
            demisto.results(subscribers)

        elif command == 'listmonk-add-subscriber':
            list_ids = [int(id) for id in args.get('list_ids', '').split(',')]  # Convert a comma-separated string into a list of integerss
            email = args.get('email')
            name = args.get('name', '')
            status = args.get('status', 'enabled')
            attributes = args.get('attributes', {})
            if not (email):
                return_error("Missing 'list_ids' or 'email' argument.")
            subscriber = client.add_subscriber(email, name, status, list_ids, attributes)
            demisto.results(subscriber)

    except requests.exceptions.HTTPError as e:
        return_error(f"Listmonk API request failed: {str(e)}")


if __name__ in ('builtins', '__builtin__'):
    main()

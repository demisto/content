from CommonServerPython import *
import urllib3


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def fetchthephishkitdatawithticketid_request(self, ticketId):
        headers = self._headers
        return self._http_request("get", f"takedowns/{ticketId}/phishkit", headers=headers)

    def fetchthescreenshotdatawithticketid_request(self, ticketId):
        headers = self._headers
        return self._http_request("get", f"takedowns/{ticketId}/screenshot", headers=headers)

    def gethtmlsourcecodeforaticket_request(self, ticketId):
        headers = self._headers
        return self._http_request("get", f"takedowns/html/{ticketId}", headers=headers)

    def listofworklogsforticketid_request(self, ticketId):
        headers = self._headers
        return self._http_request("get", f"takedowns/{ticketId}/worklogs", headers=headers)

    def listtakedownevents_request(self, fromDate, toDate, page, limit):
        params = assign_params(fromDate=fromDate, toDate=toDate, page=page, limit=limit)
        headers = self._headers
        return self._http_request("get", "takedowns/list", params=params, headers=headers)

    def listtakedowneventswithfilters_request(
        self, fromDate, toDate, brandId, fraudType, ticketStatus, DetectionDate, AuthorizationDate, CompletedDate, page, limit
    ):
        params = assign_params(
            fromDate=fromDate,
            toDate=toDate,
            brandId=brandId,
            fraudType=fraudType,
            ticketStatus=ticketStatus,
            DetectionDate=DetectionDate,
            AuthorizationDate=AuthorizationDate,
            CompletedDate=CompletedDate,
            page=page,
            limit=limit,
        )
        headers = self._headers
        return self._http_request("get", "takedowns/filtered-list", params=params, headers=headers)

    def updatetheactionwithticketid_request(self, action, body_data):
        params = assign_params(action=action)
        headers = self._headers
        return self._http_request("put", "takedowns/control", params=params, headers=headers, json_data=body_data)


def fetchthephishkitdatawithticketid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.fetchthephishkitdatawithticketid_request(args.get("ticketId"))
    return CommandResults(outputs_prefix="CSCTakedowns", outputs=response, raw_response=response)


def fetchthescreenshotdatawithticketid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.fetchthescreenshotdatawithticketid_request(args.get("ticketId"))
    return CommandResults(outputs_prefix="CSCTakedowns", outputs=response, raw_response=response)


def gethtmlsourcecodeforaticket_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.gethtmlsourcecodeforaticket_request(args.get("ticketId"))
    return CommandResults(outputs_prefix="CSCTakedowns", outputs=response, raw_response=response)


def listofworklogsforticketid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.listofworklogsforticketid_request(args.get("ticketId"))
    return CommandResults(outputs_prefix="CSCTakedowns", outputs=response, raw_response=response)


def listtakedownevents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.listtakedownevents_request(args.get("fromDate"), args.get("toDate"), args.get("page"), args.get("limit"))
    return CommandResults(outputs_prefix="CSCTakedowns", outputs=response, raw_response=response)


def listtakedowneventswithfilters_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.listtakedowneventswithfilters_request(
        args.get("fromDate"),
        args.get("toDate"),
        args.get("brandId"),
        args.get("fraudType"),
        args.get("ticketStatus"),
        argToBoolean(args.get("DetectionDate", False)),
        argToBoolean(args.get("AuthorizationDate", False)),
        argToBoolean(args.get("CompletedDate", False)),
        args.get("page"),
        args.get("limit"),
    )
    return CommandResults(outputs_prefix="CSCTakedowns", outputs=response, raw_response=response)


def updatetheactionwithticketid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    action = str(args.get("action", ""))

    body_input = args.get("body")

    # 3. Handle cases where the playbook passes the JSON as a raw string
    if isinstance(body_input, str):
        try:
            body_data = json.loads(body_input)
        except json.JSONDecodeError:
            return_error(f"Provided 'body' input is not valid JSON format: {body_input}")
    else:
        body_data = body_input
    response = client.updatetheactionwithticketid_request(action, body_data)
    return CommandResults(outputs_prefix="CSCTakedowns", outputs=response, raw_response=response)


def test_module(client: Client) -> None:
    return_results("ok")


def main() -> None:
    params = demisto.params()
    args = demisto.args()

    url = params.get("url")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    headers = {}
    headers["APIKey"] = params["api_key"]
    command = demisto.command()

    try:
        urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ""), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            "csctakedowns-fetchthephishkitdatawithticketid": fetchthephishkitdatawithticketid_command,
            "csctakedowns-fetchthescreenshotdatawithticketid": fetchthescreenshotdatawithticketid_command,
            "csctakedowns-gethtmlsourcecodeforaticket": gethtmlsourcecodeforaticket_command,
            "csctakedowns-listofworklogsforticketid": listofworklogsforticketid_command,
            "csctakedowns-listtakedownevents": listtakedownevents_command,
            "csctakedowns-listtakedowneventswithfilters": listtakedowneventswithfilters_command,
            "csctakedowns-updatetheactionwithticketid": updatetheactionwithticketid_command,
        }

        if command == "test-module":
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()

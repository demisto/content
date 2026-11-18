import urllib3
from CommonServerPython import *


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def controldetectionflowbyeventidandaction_request(self, action, body_data):
        params = assign_params(action=action)
        headers = self._headers

        response = self._http_request("put", "detections/control", params=params, headers=headers, json_data=body_data)

        return response

    def performanactiononasingletarget_request(self, targetType, action, fraudType, body_data):
        params = assign_params(targetType=targetType, action=action, fraudType=fraudType)
        headers = self._headers
        response = self._http_request("post", "actions/addone", params=params, headers=headers, json_data=body_data)

        return response

    def retrieveeventscreenshotwitheventid_request(self, eventId):
        headers = self._headers

        response = self._http_request("get", f"detections/{eventId}/screenshot", headers=headers)

        return response

    def fetchthephishkitdatawithticketid_request(self, ticketId):
        headers = self._headers

        response = self._http_request("get", f"takedowns/{ticketId}/phishkit", headers=headers)

        return response

    def fetchthescreenshotdatawithticketid_request(self, ticketId):
        headers = self._headers

        response = self._http_request("get", f"takedowns/{ticketId}/screenshot", headers=headers)

        return response

    def gethtmlsourcecodeforaticket_request(self, ticketId):
        headers = self._headers

        response = self._http_request("get", f"takedowns/html/{ticketId}", headers=headers)

        return response

    def getlistofbrands_request(self):
        headers = self._headers

        response = self._http_request("get", "brands", headers=headers)

        return response

    def getlistoffraudtypes_request(self):
        headers = self._headers

        response = self._http_request("get", "fraud-types", headers=headers)

        return response

    def listofworklogsforticketid_request(self, ticketId):
        headers = self._headers

        response = self._http_request("get", f"takedowns/{ticketId}/worklogs", headers=headers)

        return response

    def listtakedownevents_request(self, fromDate, toDate, page, limit):
        params = assign_params(fromDate=fromDate, toDate=toDate, page=page, limit=limit)
        headers = self._headers

        response = self._http_request("get", "takedowns/list", params=params, headers=headers)

        return response

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

        response = self._http_request("get", "takedowns/filtered-list", params=params, headers=headers)

        return response

    def retrievefilteredlistofmonitoringresultswithinspecifiedtimeframe_request(
        self, startDate, endDate, brandId, fraudType, monitoringStatus, page, limit
    ):
        params = assign_params(
            startDate=startDate,
            endDate=endDate,
            brandId=brandId,
            fraudType=fraudType,
            monitoringStatus=monitoringStatus,
            page=page,
            limit=limit,
        )
        headers = self._headers

        response = self._http_request("get", "monitoring/filtered-list", params=params, headers=headers)

        return response

    def retrievelistofdetectionswithinspecifiedtimeframe_request(
        self, fromDate, toDate, scoreMin, ip, isp, registrar, monitoring, page, limit
    ):
        params = assign_params(
            fromDate=fromDate,
            toDate=toDate,
            scoreMin=scoreMin,
            ip=ip,
            isp=isp,
            registrar=registrar,
            monitoring=monitoring,
            page=page,
            limit=limit,
        )
        headers = self._headers

        response = self._http_request("get", "detections/list", params=params, headers=headers)

        return response

    def retrievelistofmonitoringresultswithinspecifiedtimeframe_request(self, startDate, endDate, page, limit):
        params = assign_params(startDate=startDate, endDate=endDate, page=page, limit=limit)
        headers = self._headers

        response = self._http_request("get", "monitoring/list", params=params, headers=headers)

        return response

    def retrievephishkitwitheventid_request(self, eventId):
        headers = self._headers

        response = self._http_request("get", f"detections/{eventId}/phishkit", headers=headers)

        return response

    def startorstopmonitoringforaspecificevent_request(self, action, body_data):
        params = assign_params(action=action)
        headers = self._headers

        response = self._http_request("put", "monitoring/control", params=params, headers=headers, json_data=body_data)

        return response

    def updatetheactionwithticketid_request(self, action, body_data):
        params = assign_params(action=action)
        headers = self._headers

        response = self._http_request("put", "takedowns/control", params=params, headers=headers, json_data=body_data)

        return response


def controldetectionflowbyeventidandaction_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    response = client.controldetectionflowbyeventidandaction_request(action, body_data)

    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def fetchthephishkitdatawithticketid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ticketId = args.get("ticketId", None)

    response = client.fetchthephishkitdatawithticketid_request(ticketId)
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def fetchthescreenshotdatawithticketid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ticketId = args.get("ticketId", None)

    response = client.fetchthescreenshotdatawithticketid_request(ticketId)
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def gethtmlsourcecodeforaticket_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ticketId = args.get("ticketId", None)

    response = client.gethtmlsourcecodeforaticket_request(ticketId)
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def getlistofbrands_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.getlistofbrands_request()
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def getlistoffraudtypes_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.getlistoffraudtypes_request()
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def listofworklogsforticketid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ticketId = args.get("ticketId", None)

    response = client.listofworklogsforticketid_request(ticketId)
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def listtakedownevents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fromDate = str(args.get("fromDate", ""))
    toDate = str(args.get("toDate", ""))
    page = args.get("page", None)
    limit = args.get("limit", None)

    response = client.listtakedownevents_request(fromDate, toDate, page, limit)
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def listtakedowneventswithfilters_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fromDate = str(args.get("fromDate", ""))
    toDate = str(args.get("toDate", ""))
    brandId = args.get("brandId", None)
    fraudType = str(args.get("fraudType", ""))
    ticketStatus = str(args.get("ticketStatus", ""))
    DetectionDate = argToBoolean(args.get("DetectionDate", False))
    AuthorizationDate = argToBoolean(args.get("AuthorizationDate", False))
    CompletedDate = argToBoolean(args.get("CompletedDate", False))
    page = args.get("page", None)
    limit = args.get("limit", None)

    response = client.listtakedowneventswithfilters_request(
        fromDate, toDate, brandId, fraudType, ticketStatus, DetectionDate, AuthorizationDate, CompletedDate, page, limit
    )
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def performanactiononasingletarget_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    targetType = str(args.get("targetType", ""))
    action = str(args.get("action", ""))
    fraudType = str(args.get("fraudType", ""))

    body_input = args.get("body")

    # 3. Handle cases where the playbook passes the JSON as a raw string
    if isinstance(body_input, str):
        try:
            body_data = json.loads(body_input)
        except json.JSONDecodeError:
            return_error(f"Provided 'body' input is not valid JSON format: {body_input}")
    else:
        body_data = body_input

    # 4. Pass the body_data into your client request function
    response = client.performanactiononasingletarget_request(
        targetType=targetType, action=action, fraudType=fraudType, body_data=body_data
    )

    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def retrieveeventscreenshotwitheventid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    eventId = args.get("eventId", None)

    response = client.retrieveeventscreenshotwitheventid_request(eventId)
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def getfilteredlistofmonitoringresultsspecifiedtime_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    startDate = str(args.get("startDate", ""))
    endDate = str(args.get("endDate", ""))
    brandId = args.get("brandId", None)
    fraudType = str(args.get("fraudType", ""))
    monitoringStatus = str(args.get("monitoringStatus", ""))
    page = args.get("page", None)
    limit = args.get("limit", None)

    response = client.retrievefilteredlistofmonitoringresultswithinspecifiedtimeframe_request(
        startDate, endDate, brandId, fraudType, monitoringStatus, page, limit
    )
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def retrievelistofdetectionswithinspecifiedtimeframe_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fromDate = str(args.get("fromDate", ""))
    toDate = str(args.get("toDate", ""))
    scoreMin = args.get("scoreMin", None)
    ip = str(args.get("ip", ""))
    isp = str(args.get("isp", ""))
    registrar = str(args.get("registrar", ""))
    monitoring = str(args.get("monitoring", ""))
    page = args.get("page", None)
    limit = args.get("limit", None)

    response = client.retrievelistofdetectionswithinspecifiedtimeframe_request(
        fromDate, toDate, scoreMin, ip, isp, registrar, monitoring, page, limit
    )
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def getlistofmonitoringresultsspecifiedtime_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    startDate = str(args.get("startDate", ""))
    endDate = str(args.get("endDate", ""))
    page = args.get("page", None)
    limit = args.get("limit", None)

    response = client.retrievelistofmonitoringresultswithinspecifiedtimeframe_request(startDate, endDate, page, limit)
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def retrievephishkitwitheventid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    eventId = args.get("eventId", None)

    response = client.retrievephishkitwitheventid_request(eventId)
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def startorstopmonitoringforaspecificevent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    response = client.startorstopmonitoringforaspecificevent_request(action, body_data)
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


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
    command_results = CommandResults(
        outputs_prefix="CSCFraudProtection", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    return_results("ok")


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get("url")
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    headers = {}
    headers["APIKey"] = params["api_key"]

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ""), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            "csc-controldetectionflowbyeventidandaction": controldetectionflowbyeventidandaction_command,
            "csc-fetchthephishkitdatawithticketid": fetchthephishkitdatawithticketid_command,
            "csc-fetchthescreenshotdatawithticketid": fetchthescreenshotdatawithticketid_command,
            "csc-gethtmlsourcecodeforaticket": gethtmlsourcecodeforaticket_command,
            "csc-getlistofbrands": getlistofbrands_command,
            "csc-getlistoffraudtypes": getlistoffraudtypes_command,
            "csc-listofworklogsforticketid": listofworklogsforticketid_command,
            "csc-listtakedownevents": listtakedownevents_command,
            "csc-listtakedowneventswithfilters": listtakedowneventswithfilters_command,
            "csc-performanactiononasingletarget": performanactiononasingletarget_command,
            "csc-retrieveeventscreenshotwitheventid": retrieveeventscreenshotwitheventid_command,
            "csc-getfilteredlistofmonitoringresultsspecifiedtime": getfilteredlistofmonitoringresultsspecifiedtime_command,
            "csc-retrievelistofdetectionswithinspecifiedtimeframe": retrievelistofdetectionswithinspecifiedtimeframe_command,
            "csc-getlistofmonitoringresultsspecifiedtime": getlistofmonitoringresultsspecifiedtime_command,
            "csc-retrievephishkitwitheventid": retrievephishkitwitheventid_command,
            "csc-startorstopmonitoringforaspecificevent": startorstopmonitoringforaspecificevent_command,
            "csc-updatetheactionwithticketid": updatetheactionwithticketid_command,
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

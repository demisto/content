import json
from base64 import b64encode
from datetime import datetime, timezone
from typing import Any, Dict

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
INTEGRATION_CONTEXT_BRAND = 'CytomicOrion'
ORION_INCIDENT_TYPE_NAME = 'Cytomic Orion Incident'

###########################
#          Utils          #
###########################


def convert_epoch_to_milli(timestamp):
    if timestamp is None:
        return None
    if 9 < len(str(timestamp)) < 13:
        timestamp = int(timestamp) * 1000
    return int(timestamp)


def convert_datetime_to_epoch(the_time=0):
    if the_time is None:
        return None
    try:
        if isinstance(the_time, datetime):
            return int(the_time.strftime('%s'))
    except Exception as err:
        demisto.debug(err)
        return 0


def convert_string_to_datetime(datetime_str):
    try:
        return datetime.strptime(datetime_str, TIME_FORMAT)
    except Exception as err:
        demisto.debug(err)
        return 0


def convert_datetime_string_to_epoch_millis(datetime_str):
    return convert_epoch_to_milli(convert_datetime_to_epoch(convert_string_to_datetime(datetime_str)))


def createQueryString(args, params):
    """Genera un string para los parámetros de la query utilizando el dict params para obtener el índice de args para obtener los valores (keys) y el nombre de los parametros de la query (values)'

    Args:
        args (dict): Diccionario con el que consultar los parametros
        params (dict): La clave es el indice donde buscar en 'args' y el valor es el nombre del parámetro en la query string

    Returns:
        string: Devuelve la query string formateada si existe (ej. 'a=a&b=b') o vacio
    """
    queryString = []
    for k in params:
        if k in args:
            queryString.append(params[k] + "=" + str(args[k]))
    if queryString:
        return "&".join(queryString)
    else:
        return ""


def createBody(args, params):
    """Genera un json (body) utilizando el dict params para obtener el índice de args para obtener los valores (keys) y el nombre de los campos del json (values)'

    Args:
        args (dict): Diccionario con el que consultar los parametros
        params (dict): La clave es el indice donde buscar en 'args' y el valor es lo que se escribira como campo en el query string

    Returns:
        dict: Devuelve el json formateado (ej. { "a"="a", "b"="b" }) o diccionario vacio
    """
    contentData = {}
    for k in params:
        if k in args:
            contentData[params[k]] = args[k]
    return json.dumps(contentData)


class HttpClient(BaseClient):

    def __init__(self, base_url: str, headers: dict, timeout: int = 120, proxy: bool = False, verify: bool = False):
        self.timeout = timeout
        super().__init__(base_url=base_url, headers=headers, proxy=proxy, verify=verify)

    def _request(self, method, path, headers, data=None):
        if data:
            data = json.loads(data)
        print(path)

        self._headers = headers
        response = self._http_request(
            method=method,
            url_suffix=path,
            json_data=data,
            ok_codes=(200, 201, 204)
        )
        return response

    ###########################
    #        IoCs API         #
    ###########################

    def iocImport(self, type, data, params):
        self._headers["content-type"] = "application/json-patch+json"
        response = self._request(
            method='POST',
            path=f'/applications/iocs/{type}?{params}',
            headers=self._headers,
            data=data
        )
        if response.get("success"):
            return response.get("message")
        else:
            raise Exception(response.get("error"))

    def iocDelete(self, type, data):
        self._headers["content-type"] = "application/json-patch+json"
        response = self._request(
            method='POST',
            path=f'/applications/iocs/{type}/eraser',
            headers=self._headers,
            data=data
        )
        if response.get("success"):
            return response.get("message")
        else:
            raise Exception(response.get("error"))

    def iocListByAttributes(self, type, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path=f'/applications/iocs/{type}/getter',
            headers=self._headers,
            data=data
        )

    def iocListByDate(self, type, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path=f'/applications/iocs/{type}',
            headers=self._headers,
            data=data
        )

    def iocRetrospectiveSearcher(self, type, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path=f'/applications/iocs/{type}/retrospectivesearcher',
            headers=self._headers,
            data=data
        )

    ###################################
    #          Forensics API          #
    ###################################

    def getMD5Info(self, md5):
        return self._request(
            method='GET',
            path=f'/applications/forensics/md5/{md5}/info',
            headers=self._headers
        )

    def getBatchSample(self, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path='/applications/forensics/md5/batch/sample',
            headers=self._headers,
            data=data
        )

    def getComputers(self, md5):
        return self._request(
            method='GET',
            path=f'/applications/forensics/md5/{md5}/muids',
            headers=self._headers
        )

    def getComputerInfo(self, muid):
        return self._request(
            method='GET',
            path=f'/applications/forensics/md5/muids/{muid}/info',
            headers=self._headers
        )

    def getComputerMUID(self, client_id, machine_name):
        return self._request(
            method='GET',
            path=f'/applications/clients/{client_id}/machine-name/{machine_name}/muid',
            headers=self._headers
        )

    def getComputerDetail(self, muid):
        return self._request(
            method='GET',
            path=f'/remediations/muids/{muid}/detail',
            headers=self._headers
        )

    ###################################
    #           Alerts API            #
    ###################################

    def alertsGenerated(self, alert_from, alert_to, params):
        return self._request(
            method='GET',
            path=f'/applications/alerts/{alert_from}/{alert_to}?{params}',
            headers=self._headers
        )

    ###################################
    #         Remediations API        #
    ###################################

    def isolateMUIDS(self, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path=f'/applications/remediations/muids/isolate',
            headers=self._headers,
            data=data
        )

    def deisolateMUIDS(self, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path=f'/applications/remediations/muids/deisolate',
            headers=self._headers,
            data=data
        )

    def rebootMUIDS(self, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path=f'/applications/remediations/muids/reboot',
            headers=self._headers,
            data=data
        )

    ###################################
    #            OsQuery API          #
    ###################################

    def osQueryMachine(self, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path=f'/osQuery/machine',
            headers=self._headers,
            data=data
        )

    def osQueryClient(self, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path=f'/osQuery/client',
            headers=self._headers,
            data=data
        )

    def osQueryState(self, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path=f'/osQuery/state',
            headers=self._headers,
            data=data
        )

    def osQueryInfo(self, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path=f'/osQuery/info',
            headers=self._headers,
            data=data
        )

    ######################################
    #          Data Access API           #
    ######################################

    def queryData(self, data):
        self._headers["content-type"] = "application/json-patch+json"
        return self._request(
            method='POST',
            path=f'/applications/explorations',
            headers=self._headers,
            data=data
        )

######################################
#          Authentication            #
######################################


def login():
    client_id = demisto.params().get("client_id")
    client_secret = demisto.params().get("client_secret")

    auth_bytes = bytes(f"{client_id}:{client_secret}", encoding="utf-8")
    auth_encoded = b64encode(auth_bytes).decode("ascii")

    headers = {
        'Authorization': f'Basic {auth_encoded}'
    }

    client = AuthClient(
        base_url=demisto.params().get("token_url"),
        proxy=False,
        verify=False,
        timeout=20,
        headers=headers
    )

    return client.generate_token(
        demisto.params().get('credentials', {}).get('identifier'),
        demisto.params().get('credentials', {}).get('password')
    )


class AuthClient(BaseClient):
    def __init__(self, base_url: str, headers: dict, timeout: int = 120, proxy: bool = False, verify: bool = False):
        self.timeout = timeout
        super().__init__(base_url=base_url, headers=headers, proxy=proxy, verify=verify)

    def generate_token(self, username, password):
        payload = {
            "username": username,
            "password": password,
            "scope": "orion.api",
            "grant_type": "password"
        }

        self._headers["content-type"] = "application/x-www-form-urlencoded"
        response = self._http_request(
            method='POST',
            url_suffix=f'/oauth/token',
            data=payload
        )

        if "access_token" in response:
            return response.get("access_token")
        else:
            raise TypeError(f'got unexpected response from api: {response}\n')

###########################
#        Commands         #
###########################


def iocImportCommand(client: HttpClient, args):
    iocType = args.get("ioc_type")
    iocData = args.get("ioc_data")
    params = createQueryString(args,
                               {
                                   "ttl_days": "ttlDays",
                                   "retrospective": "retrospective"
                               }
                               )
    return client.iocImport(iocType, iocData, params)


def iocDeleteCommand(client: HttpClient, args):
    iocType = args.get("ioc_type")
    iocData = args.get("ioc_data")
    return client.iocDelete(iocType, iocData)


def iocListByAttributesCommand(client: HttpClient, args):
    iocType = args.get("ioc_type")
    iocData = args.get("ioc_data")
    return client.iocListByAttributes(iocType, iocData)


def iocListByDateCommand(client: HttpClient, args):
    iocType = args.get("ioc_type")

    # Format YYYY-MM-DDTHH:mm:ss to millis
    fromDate = convert_datetime_string_to_epoch_millis(args.get("from"))
    toDate = convert_datetime_string_to_epoch_millis(args.get("to"))
    includeDeleted = args.get("include_deleted")
    iocData = json.dumps({
        "from": fromDate,
        "to": toDate,
        "includeDeleted": eval(includeDeleted)
    })
    print(iocData)

    return client.iocListByDate(iocType, iocData)


def iocRetrospectiveSearcherCommand(client: HttpClient, args):
    iocType = args.get("ioc_type")
    iocData = args.get("ioc_data")

    return client.iocRetrospectiveSearcher(iocType, iocData)


def getMD5InfoCommand(client: HttpClient, args):
    md5 = args.get("md5")
    return client.getMD5Info(md5)


def forensicsGetBatchSampleCommand(client: HttpClient, args):
    data = args.get("data")
    return client.getBatchSample(data)


def getComputersCommand(client: HttpClient, args):
    md5 = args.get("md5")
    return client.getComputers(md5)


def getComputerInfoCommand(client: HttpClient, args):
    muid = args.get("muid")
    return client.getComputerInfo(muid)


def getComputerMUIDCommand(client: HttpClient, args):
    clientId = args.get("client_id")
    machineName = args.get("machine_name")
    return client.getComputerMUID(clientId, machineName)


def getComputerDetailCommand(client: HttpClient, args):
    muid = args.get("muid")
    return client.getComputerDetail(muid)


def alertsGeneratedCommand(client: HttpClient, args):
    # Format YYYY-MM-DDTHH:mm:ss to millis
    fromDate = convert_datetime_string_to_epoch_millis(args.get("from"))
    toDate = convert_datetime_string_to_epoch_millis(args.get("to"))

    params = createQueryString(args,
                               {
                                   "statuses": "statuses",
                                   "muid": "MUID",
                                   "client_id": "clientid",
                                   "hunting_rule": "huntingrule",
                                   "case_id": "caseid",
                                   "machine_name": "machineName",
                                   "from_query": "from",
                                   "to_query": "to",
                                   "show_excluded": "showExcluded",
                                   "show_details": "showDetails"
                               }
                               )

    return client.alertsGenerated(fromDate, toDate, params)


def isolateMUIDSCommand(client: HttpClient, args):
    muidsData = json.dumps({"MUIDs": args.get("muid_list")})
    return client.isolateMUIDS(muidsData)


def deisolateMUIDSCommand(client: HttpClient, args):
    muidsData = json.dumps({"MUIDs": args.get("muid_list")})
    return client.deisolateMUIDS(muidsData)


def rebootMUIDSCommand(client: HttpClient, args):
    muidsData = json.dumps({"MUIDs": args.get("muid_list")})
    return client.rebootMUIDS(muidsData)


def osQueryMachineCommand(client: HttpClient, args):
    queryData = createBody(args, {
        "query": "query",
        "ttl": "ttl",
        "muids": "MUIDs"
    })
    return client.osQueryMachine(queryData)


def osQueryClientCommand(client: HttpClient, args):
    queryData = createBody(args, {
        "query": "query",
        "ttl": "ttl",
        "muids": "MUIDs"
    })
    return client.osQueryClient(queryData)


def osQueryStateCommand(client: HttpClient, args):
    queryData = args.get("osquery_data")
    return client.osQueryState(queryData)


def osQueryInfoCommand(client: HttpClient, args):
    queryData = args.get("osquery_data")
    return client.osQueryInfo(queryData)


def queryDataCommand(client: HttpClient, args):
    query = json.dumps({"sql": args.get("sql")})
    return client.queryData(query)


def main():
    """
    Executes an integration command
    """
    LOG(f'Command being called is {demisto.command()}')

    token = login()
    client = HttpClient(
        base_url=demisto.params().get("base_url"),
        proxy=False,
        verify=False,
        timeout=60,
        headers={
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json'
        }
    )

    try:
        if demisto.command() == 'test-module':
            demisto.results('ok')
        elif demisto.command() == 'orion-import-ioc':
            response = iocImportCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-delete-ioc':
            response = iocDeleteCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-list-ioc-by-attributes':
            response = iocListByAttributesCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-list-ioc-by-date':
            response = iocListByDateCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-ioc-retrospective-searcher':
            response = iocRetrospectiveSearcherCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-get-md5-info':
            response = getMD5InfoCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-get-batch-sample':
            response = forensicsGetBatchSampleCommand(client, demisto.args())
            return_result(response)
        elif demisto.command() == 'orion-get-computers':
            response = getComputersCommand(client, demisto.args())
            return_result(response)
        elif demisto.command() == 'orion-get-computer-info':
            response = getComputerInfoCommand(client, demisto.args())
            return_result(response)
        elif demisto.command() == 'orion-get-computer-muid':
            response = getComputerMUIDCommand(client, demisto.args())
            return_result(response)
        elif demisto.command() == 'orion-get-computer-detail':
            response = getComputerDetailCommand(client, demisto.args())
            return_result(response)
        elif demisto.command() == 'orion-get-alerts-generated':
            response = alertsGeneratedCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-isolate-muids':
            response = isolateMUIDSCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-deisolate-muids':
            response = deisolateMUIDSCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-reboot-muids':
            response = rebootMUIDSCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-osquery-machine':
            response = osQueryMachineCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-osquery-client':
            response = osQueryClientCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-osquery-state':
            response = osQueryStateCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-osquery-info':
            response = osQueryInfoCommand(client, demisto.args())
            return_results(response)
        elif demisto.command() == 'orion-query-data':
            response = queryDataCommand(client, demisto.args())
            return_results(response)

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

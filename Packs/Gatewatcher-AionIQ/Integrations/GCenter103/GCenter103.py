from typing import (
    Any
)

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401, F403
import urllib3
import json
import requests
from datetime import datetime

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


class GwAPIException(Exception):
    """A base class from which all other exceptions inherit.

    If you want to catch all errors that the gwapi_benedictine package might raise,
    catch this base exception.
    """


class GwRequests:
    """Allows to easily interact with HTTP server.

    Class features:
      - Get requests package wrapper.
      - Put requests package wrapper.
      - Post requests package wrapper.
      - Delete requests package wrapper.
    """

    PROXIES = {
        "http": "",
        "https": ""
    }

    def __init__(self, ip: str, headers: dict = {}, check_cert: bool = False,
                 proxy: bool = False) -> None:
        """Init.

        Disable urllib3 warning. Allow unsecure ciphers.

        Args:
            ip: IP address of the HTTP server.
            check_cert: True to validate server certificate and False instead.
            proxies: Requests proxies. Default to no proxies.
        """
        self.index_values = [
            "suricata",
            "codebreaker",
            "malware",
            "netdata",
            "syslog",
            "machine_learning",
            "retrohunt",
            "iocs"
        ]
        self.ip = ip
        self.headers = headers
        self.check_cert = check_cert

        if proxy:

            d = handle_proxy(proxy_param_name='proxy')
            self.PROXIES["http"] = d['http']
            self.PROXIES["https"] = d['https']

    def _gen_request_kwargs(self,
                            endpoint: str,
                            data: dict,
                            json_data: dict,
                            params: dict,
                            headers: dict,
                            cookies: dict,
                            redirects: bool,
                            files: dict | None = None) -> dict:
        """Generate requests arguments.

        Args:
            endpoint: URL endpoint in format /XX/YY/ZZ.
            data: request data.
            json_data: Set to True if data is in json_data format and False instead.
            params: Set to True if data need to be send with the url and False instead.
            headers: Set to True if redirection is allowed and False instead.
            cookies: Set to True if redirection is allowed and False instead.
            redirects: Set to True if redirection is allowed and False instead.
            files: files to upload in multipart/form-data

        Returns:
            Return requests arguments in dictionnary format.
        """
        kwargs = {
            "url": f"https://{self.ip}{endpoint}",
            "headers": headers if headers else self.headers,
            "cookies": cookies,
            "verify": self.check_cert,
            "proxies": self.PROXIES,
            "allow_redirects": redirects,
            "data": data,
            "json": json_data,
            "params": params,
            "files": files
        }
        return kwargs

    def _get(self, endpoint: str,
             data: dict | None = None,
             json_data: dict | None = None,
             params: dict | None = None,
             headers: dict | None = None,
             cookies: dict | None = None,
             redirects: bool = True) -> requests.Response:
        """Wrap the get requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,
            json_data=json_data,
            params=params,
            headers=headers,
            cookies=cookies,
            redirects=redirects
        )
        return requests.get(**kwargs)

    def _post(self, endpoint: str,
              data: dict | None = None,
              json_data: dict | None = None,
              params: dict | None = None,
              headers: dict | None = None,
              cookies: dict | None = None,
              redirects: bool = True,
              files: dict | None = None) -> requests.Response:
        """Wrap the post requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,
            json_data=json_data,
            params=params,
            headers=headers,
            cookies=cookies,
            redirects=redirects,
            files=files
        )
        return requests.post(**kwargs)

    def _put(self, endpoint: str,
             data: dict | None = None,
             json_data: dict | None = None,
             params: dict | None = None,
             headers: dict | None = None,
             cookies: dict | None = None,
             redirects: bool = True,
             files: dict | None = None) -> requests.Response:
        """Wrap the put requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,
            json_data=json_data,
            params=params,
            headers=headers,
            cookies=cookies,
            redirects=redirects,
            files=files
        )
        return requests.put(**kwargs)

    def _delete(self, endpoint: str,
                data: dict | None = None,
                json_data: dict | None = None,
                params: dict | None = None,
                headers: dict | None = None,
                cookies: dict | None = None,
                redirects: bool = True) -> requests.Response:
        """Wrap the delete requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,
            json_data=json_data,
            params=params,
            headers=headers,
            cookies=cookies,
            redirects=redirects
        )
        return requests.delete(**kwargs)


class GwClient(GwRequests):
    """Client class to interact with the service API."""

    def auth(self, user: str = None, password: str = None, token: str = None) -> None:
        """Authentication through the GCenter API.

        Args:
            user: GCenter WEBui username.
            password: GCenter WEBui password.
            token: GCenter API token.

        Raises:
            GwAPIException: If status_code != 200.
        """
        if user is None and password is None and token is None:
            raise AttributeError("A user/password or an API token must be provided: [ERROR]")
        elif ((user is None and password is not None)
                or (user is not None and password is None)):
            raise AttributeError("A user and a password must be provided: [ERROR]")
        if user is not None and password is not None:
            response = self._post(
                endpoint="/api/v1/auth/login",
                json_data={
                    "username": user,
                    "password": password
                }
            )
            if response.status_code == 200:
                demisto.info(
                    f"Authentication on GCenter {self.ip} with user {user}: [OK]"
                )
                self.headers["API-KEY"] = response.json()["token"]
            else:
                raise GwAPIException(
                    f"Authentication on GCenter {self.ip} with"
                    f" user {user}: [FAILED]",
                    response.text, response.status_code, response.reason
                )
        else:
            self.headers["API-KEY"] = token

    def is_authenticated(self) -> bool:
        """Return True if authenticated and False instead.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint="/api/v1/settings/"
        )
        if response.status_code == 200:
            demisto.info(
                f"Get settings on GCenter {self.ip}: [OK]"
            )
            return True
        else:
            demisto.error(
                f"Get settings on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )
            return False


def test_module(client: GwClient, user: str, password: str, token: str) -> str:  # noqa: E501
    """Tests API connectivity and authentication command.

    Args:
        client: Client to interact with the GCenter.

    Returns:
        'Authentication successful' when the GCenter connection works.
        'Authentication error' when the GCenter connection doesn't works.
    """
    client.auth(user=user if user != "" else None,
                password=password if password != "" else None,
                token=token)

    if client.is_authenticated():
        return "ok"
    else:
        return "Authentication error, please check ip/user/password/token: [ERROR]"


def gcenter103_alerts_list_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "date_from": args.get("date_from"),
        "date_to": args.get("date_to"),
        "since": args.get("since"),
        "ids": args.get("ids"),
        "excluded_ids": args.get("excluded_ids"),
        "acknowledged": args.get("acknowledged"),
        "gcap_id": args.get("gcap_id"),
        "ip": args.get("ip"),
        "src_ip": args.get("src_ip"),
        "dest_ip": args.get("dest_ip"),
        "risk_min": args.get("risk_min"),
        "risk_max": args.get("risk_max"),
        "name": args.get("name"),
        "description": args.get("description"),
        "tag": args.get("tag"),
        "no_tag": args.get("no_tag"),
        "excluded_tags": args.get("excluded_tags"),
        "sort_by": args.get("sort_by"),
        "type": args.get("type"),
        "mitre_tactic_name": args.get("mitre_tactic_name"),
        "hostname": args.get("hostname"),
        "src_hostname": args.get("src_hostname"),
        "dest_hostname": args.get("dest_hostname"),
        "username": args.get("username"),
        "note": args.get("note"),
        "state": args.get("state"),
        "search": args.get("search"),
        "page": args.get("page"),
        "page_size": args.get("page_size")
    }

    try:
        req = client._get(endpoint="/api/v1/alerts/", params=params)
    except requests.exceptions.HTTPError as e:
        raise Exception(str(e))

    res: dict[Any, Any] = req.json()

    if "results" not in res:

        return CommandResults(
            readable_output="# gcenter103-alerts-list - Empty alerts list",
            outputs_prefix="Gatewatcher.Alerts.List"
        )

    res_keys: list[dict[Any, Any]] = []

    for i in range(0, len(res['results'])):

        res_keys.append({
            "uuid": res.get('results', [{}])[i].get('uuid', ""),
        })

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-alerts-list", res.get('results', [{}])),
        outputs_prefix="Gatewatcher.Alerts.List",
        outputs_key_field="uuid",
        outputs=res_keys,
        raw_response=res
    )


def gcenter103_alerts_get_command(client: GwClient, args: dict[str, str]) -> CommandResults:

    params = {
        "uuid": args.get("uuid")
    }

    try:
        req = client._get(endpoint="/api/v1/alerts/" + params.get('uuid', ""))
        if req.status_code != 200:
            raise Exception(f"Request failed: {req.status_code}: {req.reason}, {req.json()}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    res_keys: dict[Any, Any] = {
        "uuid": res.get('uuid', "")
    }

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-alerts-get", res),
        outputs_prefix="Gatewatcher.Alerts.Get",
        outputs_key_field="uuid",
        outputs=res_keys,
        raw_response=res
    )


def gcenter103_alerts_note_add_command(client: GwClient, args: dict[str, str]) -> CommandResults:

    params = {
        "note": args.get("note"),
        "uuid": args.get("uuid"),
        "overwrite": args.get("overwrite")
    }

    if params.get('overwrite', "") == "true":

        data = {
            "note": params.get('note', "")
        }

        try:
            req = client._put(endpoint="/api/v1/alerts/" + params.get('uuid', "") + "/note", data=data)
            if req.status_code != 200:
                raise Exception(f"Request failed: {req.status_code}: {req.reason}, {req.json()}")
        except Exception as e:
            raise Exception(f"Exception: {str(e)}")

        res = req.json()

        res_keys: dict[Any, Any] = {
            "note": res.get('note', "")
        }

        return CommandResults(
            readable_output=tableToMarkdown("gcenter103-alerts-note-add", res),
            outputs_prefix="Gatewatcher.Alerts.Note.Add",
            outputs_key_field="note",
            outputs=res_keys,
            raw_response=res
        )

    else:

        try:
            req = client._get(endpoint="/api/v1/alerts/" + params.get('uuid', ""))
            if req.status_code != 200:
                raise Exception(f"Request failed: {req.status_code}: {req.reason}, {req.json()}")
        except Exception as e:
            raise Exception(f"Exception: {str(e)}")

        res = req.json()
        old_note = res.get('note', "")
        if old_note is None:
            old_note = ""
        data = {
            "note": old_note + "\n" + params.get('note', "")
        }

        try:
            req = client._put(endpoint="/api/v1/alerts/" + params.get('uuid', "") + "/note", json_data=data)
            if req.status_code != 200:
                raise Exception(f"Request failed: {req.status_code}: {req.reason}, {req.json()}")
        except Exception as e:
            raise Exception(f"Exception: {str(e)}")

        res = req.json()
        res_keys: dict[Any, Any] = {
            "note": res.get('note', "")
        }

        return CommandResults(
            readable_output=tableToMarkdown("gcenter103-alerts-note-add", res),
            outputs_prefix="Gatewatcher.Alerts.Note.Add",
            outputs_key_field="note",
            outputs=res_keys,
            raw_response=res

        )


def gcenter103_alerts_note_remove_command(client: GwClient, args: dict[str, str]) -> CommandResults:

    params = {
        "uuid": args.get("uuid")
    }

    try:
        req = client._delete(endpoint="/api/v1/alerts/" + params.get('uuid', "") + "/note")
        if req.status_code != 204:
            raise Exception(f"Request failed: {req.status_code}: {req.reason}, {req.json()}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    return CommandResults(
        readable_output="# gcenter103-alerts-note-remove - Note removed of the alert: " + params.get('uuid', ""),
        outputs_prefix="Gatewatcher.Alerts.Note.Remove",
        outputs_key_field="uuid",
        outputs=params.get('uuid', "")
    )


def gcenter103_alerts_tags_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "uuid": args.get("uuid")
    }

    try:
        req = client._get(endpoint="/api/v1/alerts/" + params['uuid'] + "/tags")
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    res_keys: dict[Any, Any] = {}
    res_keys = {
        "tags": [{"label": ""}],
        "uuid": params.get('uuid', "")
    }

    for i in range(0, len(res['tags'])):
        res_keys.get('tags').append({'label': res.get('tags', [{}])[i].get('label', "")})

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-alerts-tags-get", res.get('tags', [{}])),
        outputs_prefix="Gatewatcher.Alerts.Tags.Get",
        outputs_key_field="tags",
        outputs=res_keys,
        raw_response=res
    )


def get_tags(client: GwClient) -> list[dict[str, Any]]:

    try:
        req = client._get(endpoint="/api/v1/tags/")
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()
    tags = []

    for i in range(0, len(res['results'])):
        tags.append({"id": res.get('results', [{}])[i].get('id', ""), "label": res.get('results', [{}])[i].get('label', "")})

    return tags


def check_tags(client: GwClient, tags_args: list[str]) -> list[dict[str, Any]]:

    tags = get_tags(client=client)
    tags_l = ""
    for i in range(0, len(tags)):
        tags_l += tags[i].get('label', "") + ","

    for tag in tags_args:
        if tag not in str(tags_l):
            raise Exception("Tag not found on the GCenter")

    return tags


def match_tags(arg_tags: list[str], gcenter_tags: list[dict[str, Any]]) -> list[dict[Any, Any]]:

    tags: list[dict[Any, Any]] = []

    for tag in arg_tags:
        for i in range(0, len(gcenter_tags)):
            if tag == gcenter_tags[i].get('label', ""):
                tags.append({"id": int(gcenter_tags[i].get('id', ""))})

    return tags


def gcenter103_alerts_tags_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "uuid": args.get("uuid"),
        "tags": args.get("tags")
    }

    data = {"tags": [{}]}
    tags_gcenter = check_tags(client=client, tags_args=params.get('tags', ""))
    tags = params.get('tags', "").split(',')
    tags = match_tags(arg_tags=tags, gcenter_tags=tags_gcenter)

    data['tags'] = tags

    try:
        req = client._get(endpoint="/api/v1/alerts/" + params.get('uuid', "") + "/tags")
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    for i in range(0, len(res['tags'])):

        data.get('tags', [{}]).append(res.get('tags', {})[i])

    try:
        req = client._put(endpoint="/api/v1/alerts/" + params.get('uuid', "") + "/tags", json_data=data)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()
    res_keys: dict[Any, Any] = {
        "tags": res.get('tags', {}),
        "uuid": params.get('uuid', ""),
    }

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-alerts-tags-add", res.get('tags', {})),
        outputs_prefix="Gatewatcher.Alerts.Tags.Add",
        outputs_key_field="tags",
        outputs=res_keys,
        raw_response=res.get('tags', {})
    )


def gcenter103_alerts_tags_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "uuid": args.get("uuid"),
        "tags": args.get("tags")
    }

    data = {"tags": []}
    tags_gcenter = check_tags(client=client, tags_args=params.get('tags', ""))
    tags = params.get('tags', "").split(',')
    tags = match_tags(arg_tags=tags, gcenter_tags=tags_gcenter)

    data['tags'] = tags

    try:
        req = client._get(endpoint="/api/v1/alerts/" + params.get('uuid', "") + "/tags")
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()
    data2 = {"tags": []}

    r = []
    b = []
    for i in range(0, len(data['tags'])):
        r.append(data.get('tags', [{}])[i].get('id', ""))

    for i in range(0, len(res['tags'])):
        b.append(res.get('tags', [{}])[i].get('id', ""))

    r.sort()
    b.sort()

    li = []

    for i in b:
        if i not in r:
            li.append(i)

    for i in range(0, len(li)):
        data2.get('tags', [{}]).append({'id': int(li[i])})

    try:
        req = client._put(endpoint="/api/v1/alerts/" + params.get('uuid', "") + "/tags", json_data=data2)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-alerts-tags-remove", res.get('tags', {})),
        outputs_prefix="Gatewatcher.Alerts.Tags.Remove"
    )


def gcenter103_alerts_status_update_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "note_u": args.get("note_u"),
        "tag_u": args.get("tag_u"),
        "date_from": args.get("date_from"),
        "date_to": args.get("date_to"),
        "since": args.get("since"),
        "uuid": args.get("uuid"),
        "acknowledged": args.get("acknowledged"),
        "gcap_id": args.get("gcap_id"),
        "ip": args.get("ip"),
        "src_ip": args.get("src_ip"),
        "dest_ip": args.get("dest_ip"),
        "risk_min": args.get("risk_min"),
        "risk_max": args.get("risk_max"),
        "name": args.get("name"),
        "description": args.get("description"),
        "tag": args.get("tag"),
        "no_tag": args.get("no_tag"),
        "excluded_tags": args.get("excluded_tags"),
        "sort_by": args.get("sort_by"),
        "type": args.get("type"),
        "mitre_tactic_name": args.get("mitre_tactic_name"),
        "hostname": args.get("hostname"),
        "src_hostname": args.get("src_hostname"),
        "dest_hostname": args.get("dest_hostname"),
        "username": args.get("username"),
        "note": args.get("note"),
        "state": args.get("state"),
        "search": args.get("search"),
        "action": args.get("action"),
        "ids": 0
    }

    data = {"note": "",
            "tag": []}
    if params.get("note_u") is not None:
        data['note'] = params.get("note_u")
    if params.get("tag_u") is not None:
        tags = params.get('tag_u', "").split(',')
        for i in range(0, len(tags)):
            data['tag'].append(int(tags[i]))

    try:
        req = client._get(endpoint="/api/v1/alerts/" + params.get('uuid', ""))
        if req.status_code != 200:
            raise Exception(f"Request failed: {req.status_code}: {req.reason}, {req.json()}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()
    params['ids'] = res.get('id', "")

    action = params.get('action', "")
    del params['action']
    del params['note_u']
    del params['tag_u']
    del params['uuid']

    try:
        req = client._put(endpoint="/api/v1/alerts/action/" + action, json_data=data, params=params)
        if req.status_code != 204:
            raise Exception(f"Request failed: {req.status_code}: {req.reason}, {req.json()}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    return CommandResults(
        readable_output=f"# gcenter103-alerts-status-update {req.status_code}: OK",
        outputs_prefix="Gatewatcher.Alerts.Status.Update"
    )


def gcenter103_raw_alerts_get_command(client: GwClient, args: dict[str, str]) -> CommandResults:

    params = {
        "id": args.get("uuid")
    }

    try:
        req = client._get(endpoint="/api/v1/raw-alerts/" + params.get('id'))
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.json()}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-raw-alerts-get", res),
        outputs_prefix="Gatewatcher.Raw.Alerts.Get"
    )


def gcenter103_raw_alerts_file_get_command(client: GwClient, args: dict[str, str]) -> CommandResults:

    params = {
        "id": args.get("uuid")
    }

    try:
        req = client._get(endpoint="/api/v1/raw-alerts/" + params.get('id', "") + "/file")
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.content
    filename = str(params.get('id', "")) + "-file.zip"
    file_content = res

    return_results(fileResult(filename, file_content))

    return CommandResults(
        readable_output="# gcenter103-raw-alerts-file-get: Dumped zip file",
        outputs_prefix="Gatewatcher.Raw.Alerts.File.Get",
    )


def gcenter103_file_scan_command(client: GwClient, args: dict[str, str]) -> CommandResults:

    params = {
        "engine": args.get("engine"),
        "entryID": args.get("entryID")
    }

    fp_d = demisto.getFilePath(params.get('entryID', ""))
    files = {"file": open(fp_d['path'], 'rb')}

    try:
        req = client._post(endpoint="/api/v1/gscan/" + params.get('engine', ""), files=files)
        if req.status_code != 201:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()
    res.update({"file_name": str(fp_d.get('name', ""))})

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-file-scan results of " + str(params.get('engine', "")), res),
        outputs_prefix="Gatewatcher.File.Scan",
    )


def gcenter103_file_scan_result_get_command(client: GwClient, args: dict[str, str]) -> CommandResults:

    params = {
        "id": args.get("id")
    }

    try:
        req = client._get(endpoint="/api/v1/gscan/histories/" + params.get('id', ""))
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-file-scan-result-get", res),
        outputs_prefix="Gatewatcher.File.Scan.Result.Get",
    )


def gcenter103_assets_list_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "search": args.get("search"),
        "page": args.get("page"),
        "page_size": args.get("page_size"),
        "date_from": args.get("date_from"),
        "date_to": args.get("date_to"),
        "since": args.get("since"),
        "fast": args.get("fast"),
        "gcap_id": args.get("gcap_id"),
        "sort_by": args.get("sort_by"),
        "risk_min": args.get("risk_min"),
        "risk_max": args.get("risk_max"),
        "name": args.get("name"),
        "type": args.get("type"),
        "os_firmware": args.get("os_firmware"),
        "ip": args.get("ip"),
        "mac_address": args.get("mac_address"),
        "tag": args.get("tag"),
        "note": args.get("note"),
        "no_tag": args.get("no_tag")
    }

    try:
        req = client._get(endpoint="/api/v1/assets/", params=params)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-list", res['results']),
        outputs_prefix="Gatewatcher.Assets.List",
    )


def gcenter103_assets_alerts_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "date_from": args.get("date_from"),
        "date_to": args.get("date_to"),
        "since": args.get("since"),
        "ids": args.get("ids"),
        "excluded_ids": args.get("excluded_ids"),
        "acknowledged": args.get("acknowledged"),
        "gcap_id": args.get("gcap_id"),
        "ip": args.get("ip"),
        "src_ip": args.get("src_ip"),
        "dest_ip": args.get("dest_ip"),
        "risk_min": args.get("risk_min"),
        "risk_max": args.get("risk_max"),
        "name": args.get("name"),
        "description": args.get("description"),
        "tag": args.get("tag"),
        "no_tag": args.get("no_tag"),
        "excluded_tags": args.get("excluded_tags"),
        "sort_by": args.get("sort_by"),
        "type": args.get("type"),
        "mitre_tactic_name": args.get("mitre_tactic_name"),
        "hostname": args.get("hostname"),
        "src_hostname": args.get("src_hostname"),
        "dest_hostname": args.get("dest_hostname"),
        "username": args.get("username"),
        "note": args.get("note"),
        "state": args.get("state"),
        "page": args.get("page"),
        "page_size": args.get("page_size"),
        "asset_name": args.get("asset_name")
    }

    asset_name = params.get('asset_name', "")
    del params['asset_name']

    try:
        req = client._get(endpoint="/api/v1/assets/" + asset_name + "/alerts", params=params)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-alerts-get", res.get('results', "")),
        outputs_prefix="Gatewatcher.Assets.Alerts.Get",
    )


def gcenter103_assets_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "date_from": args.get("date_from"),
        "date_to": args.get("date_to"),
        "since": args.get("since"),
        "fast": args.get("fast"),
        "asset_name": args.get("asset_name")
    }

    asset_name = params.get('asset_name', "")
    del params['asset_name']

    try:
        req = client._get(endpoint="/api/v1/assets/" + asset_name, params=params)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-alerts-get", res),
        outputs_prefix="Gatewatcher.Assets.Get",
    )


def gcenter103_assets_note_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "note": args.get("note"),
        "asset_name": args.get("asset_name"),
        "overwrite": args.get("overwrite")
    }

    if params.get('overwrite', "") == "true":

        data = {"note": params.get('note', "")}

        try:
            req = client._put(endpoint="/api/v1/assets/" + params.get('asset_name', "") + "/note", json_data=data)
            if req.status_code != 200:
                raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
        except Exception as e:
            raise Exception(f"Exception: {str(e)}")

        res = req.json()

        return CommandResults(
            readable_output=tableToMarkdown("gcenter103-assets-note-add", res),
            outputs_prefix="Gatewatcher.Assets.Note.Add",
        )

    else:

        try:
            req = client._get(endpoint="/api/v1/assets/" + params.get('asset_name', ""))
            if req.status_code != 200:
                raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
        except Exception as e:
            raise Exception(f"Exception: {str(e)}")

        res = req.json()
        old_note = res.get('note', "")
        if old_note is None:
            old_note = ""
        data = {"note": old_note + "\n" + params.get('note', "")}

        try:
            req = client._put(endpoint="/api/v1/assets/" + params.get('asset_name') + "/note", json_data=data)
            if req.status_code != 200:
                raise Exception(f"Request failed: {req.status_code}: {req.reason}, {req.json()}")
        except Exception as e:
            raise Exception(f"Exception: {str(e)}")

        res = req.json()

        return CommandResults(
            readable_output=tableToMarkdown("gcenter103-assets-note-add", res),
            outputs_prefix="Gatewatcher.Assets.Note.Add"
        )


def gcenter103_assets_note_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "asset_name": args.get("asset_name")
    }

    try:
        req = client._delete(endpoint="/api/v1/assets/" + params.get('asset_name', "") + "/note")
        if req.status_code != 204:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    return CommandResults(
        readable_output="# gcenter103-assets-note-remove - Note removed of asset: " + params.get('asset_name', ""),
        outputs_prefix="Gatewatcher.Assets.Note.Remove"
    )


def gcenter103_assets_tags_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "asset_name": args.get("asset_name")
    }

    try:
        req = client._get(endpoint="/api/v1/assets/" + params.get('asset_name', "") + "/tags")
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    if len(res['tags']) == 0:
        return CommandResults(
            readable_output="# gcenter103-assets-tags-get - This asset has no associated tags",
            outputs_prefix="Gatewatcher.Assets.Tags.Get",
        )

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-tags-get", res.get('tags', [{}])),
        outputs_prefix="Gatewatcher.Assets.Tags.Get",
    )


def gcenter103_assets_tags_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "asset_name": args.get("asset_name"),
        "tags": args.get("tags")
    }

    data = {"tags": []}
    tags_gcenter = check_tags(client=client, tags_args=params.get('tags', ""))
    tags = params.get('tags', "").split(',')
    tags = match_tags(arg_tags=tags, gcenter_tags=tags_gcenter)

    data['tags'] = tags

    try:
        req = client._get(endpoint="/api/v1/assets/" + params.get('asset_name', "") + "/tags")
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    for i in range(0, len(res['tags'])):

        data.get('tags', [{}]).append(res.get('tags', [{}])[i])

    try:
        req = client._put(endpoint="/api/v1/assets/" + params.get('asset_name', "") + "/tags", json_data=data)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-tags-add", res.get('tags', [{}])),
        outputs_prefix="Gatewatcher.Assets.Tags.Add",
    )


def gcenter103_assets_tags_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "asset_name": args.get("asset_name"),
        "tags": args.get("tags")
    }

    data = {"tags": []}
    tags_gcenter = check_tags(client=client, tags_args=params.get('tags', ""))
    tags = params.get('tags', "").split(',')
    tags = match_tags(arg_tags=tags, gcenter_tags=tags_gcenter)

    data['tags'] = tags

    try:
        req = client._get(endpoint="/api/v1/assets/" + params.get('asset_name', "") + "/tags", json_data=data)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()
    data2 = {"tags": []}

    r = []
    b = []
    for i in range(0, len(data['tags'])):
        r.append(data.get('tags', [{}])[i].get('id', ""))

    for i in range(0, len(res['tags'])):
        b.append(res.get('tags', [{}])[i].get('id', ""))

    r.sort()
    b.sort()

    li = []

    for i in b:
        if i not in r:
            li.append(i)

    for i in range(0, len(li)):
        data2['tags'].append({'id': int(li[i])})

    try:
        req = client._put(endpoint="/api/v1/assets/" + params.get('asset_name', "") + "/tags", json_data=data2)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-tags-remove", res.get('tags', [{}])),
        outputs_prefix="Gatewatcher.Assets.Tags.Remove",
    )


def gcenter103_users_list_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "search": args.get("search"),
        "page": args.get("page"),
        "page_size": args.get("page_size"),
        "date_from": args.get("date_from"),
        "date_to": args.get("date_to"),
        "since": args.get("since"),
        "fast": args.get("fast"),
        "gcap_id": args.get("gcap_id"),
        "sort_by": args.get("sort_by"),
        "risk_min": args.get("risk_min"),
        "risk_max": args.get("risk_max"),
        "username": args.get("username"),
        "ip": args.get("ip"),
        "hostname": args.get("hostname"),
        "tag": args.get("tag"),
        "note": args.get("note"),
        "no_tag": args.get("no_tag")
    }

    try:
        req = client._get(endpoint="/api/v1/kusers", params=params)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-list", res.get('results', [{}])),
        outputs_prefix="Gatewatcher.Users.List",
    )


def gcenter103_users_alerts_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "date_from": args.get("date_from"),
        "date_to": args.get("date_to"),
        "since": args.get("since"),
        "ids": args.get("ids"),
        "excluded_ids": args.get("excluded_ids"),
        "acknowledged": args.get("acknowledged"),
        "gcap_id": args.get("gcap_id"),
        "ip": args.get("ip"),
        "src_ip": args.get("src_ip"),
        "dest_ip": args.get("dest_ip"),
        "risk_min": args.get("risk_min"),
        "risk_max": args.get("risk_max"),
        "name": args.get("name"),
        "description": args.get("description"),
        "tag": args.get("tag"),
        "no_tag": args.get("no_tag"),
        "excluded_tags": args.get("excluded_tags"),
        "sort_by": args.get("sort_by"),
        "type": args.get("type"),
        "mitre_tactic_name": args.get("mitre_tactic_name"),
        "hostname": args.get("hostname"),
        "src_hostname": args.get("src_hostname"),
        "dest_hostname": args.get("dest_hostname"),
        "username": args.get("username"),
        "note": args.get("note"),
        "state": args.get("state"),
        "page": args.get("page"),
        "page_size": args.get("page_size"),
        "kuser_name": args.get("kuser_name")
    }

    kuser_name = params.get('kuser_name', "")
    del params['kuser_name']

    try:
        req = client._get(endpoint="/api/v1/kusers/" + kuser_name + "/alerts", params=params)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-alerts-get", res.get('results', [{}])),
        outputs_prefix="Gatewatcher.Users.Alerts.Get",
    )


def gcenter103_users_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "date_from": args.get("date_from"),
        "date_to": args.get("date_to"),
        "since": args.get("since"),
        "fast": args.get("fast"),
        "kuser_name": args.get("kuser_name")
    }

    kuser_name = params.get('kuser_name', "")
    del params['kuser_name']

    try:
        req = client._get(endpoint="/api/v1/kusers/" + kuser_name, params=params)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-get", res),
        outputs_prefix="Gatewatcher.Users.Get",
    )


def gcenter103_users_note_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "note": args.get("note"),
        "kuser_name": args.get("kuser_name"),
        "overwrite": args.get("overwrite")
    }

    if params.get('overwrite', "") == "true":

        data = {"note": params.get('note', "")}

        try:
            req = client._put(endpoint="/api/v1/kusers/" + params.get('kuser_name', "") + "/note", json_data=data)
            if req.status_code != 200:
                raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
        except Exception as e:
            raise Exception(f"Exception: {str(e)}")

        res = req.json()

        return CommandResults(
            readable_output=tableToMarkdown("gcenter103-users-note-add", res),
            outputs_prefix="Gatewatcher.Users.Note.Add",
        )

    else:

        try:
            req = client._get(endpoint="/api/v1/kusers/" + params.get('kuser_name', ""))
            if req.status_code != 200:
                raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
        except Exception as e:
            raise Exception(f"Exception: {str(e)}")

        res = req.json()
        old_note = res.get('note', "")
        if old_note is None:
            old_note = ""
        data = {"note": old_note + "\n" + params.get('note', "")}

        try:
            req = client._put(endpoint="/api/v1/kusers/" + params.get('kuser_name', "") + "/note", json_data=data)
            if req.status_code != 200:
                raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
        except Exception as e:
            raise Exception(f"Exception: {str(e)}")

        res = req.json()

        return CommandResults(
            readable_output=tableToMarkdown("gcenter103-users-note-add", res),
            outputs_prefix="Gatewatcher.Users.Note.Add",
        )


def gcenter103_users_note_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "kuser_name": args.get("kuser_name")
    }

    try:
        req = client._delete(endpoint="/api/v1/kusers/" + params.get('kuser_name', "") + "/note")
        if req.status_code != 204:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    return CommandResults(
        readable_output="# gcenter103-users-note-remove - Note of: " + params.get('kuser_name', "") + " deleted",
        outputs_prefix="Gatewatcher.Users.Note.Remove",
    )


def gcenter103_users_tags_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "kuser_name": args.get("kuser_name")
    }

    try:
        req = client._get(endpoint="/api/v1/kusers/" + params.get('kuser_name', "") + "/tags")
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    if len(res['tags']) == 0:
        return CommandResults(
            readable_output="# gcenter103-users-tags-get - Empty tags list",
            outputs_prefix="Gatewatcher.Users.Tags.Get",
        )

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-tags-get", res.get('tags', [{}])),
        outputs_prefix="Gatewatcher.Users.Tags.Get",
    )


def gcenter103_users_tags_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "tags": args.get("tags"),
        "kuser_name": args.get("kuser_name")
    }

    data = {"tags": []}
    tags_gcenter = check_tags(client=client, tags_args=params.get('tags', ""))
    tags = params.get('tags', "").split(',')
    tags = match_tags(arg_tags=tags, gcenter_tags=tags_gcenter)

    data['tags'] = tags

    try:
        req = client._get(endpoint="/api/v1/kusers/" + params.get('kuser_name', "") + "/tags")
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    for i in range(0, len(res['tags'])):
        data.get('tags', [{}]).append(res.get('tags', [{}])[i])

    try:
        req = client._put(endpoint="/api/v1/kusers/" + params.get('kuser_name', "") + "/tags", json_data=data)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-tags-add", res.get('tags', [{}])),
        outputs_prefix="Gatewatcher.Users.Tags.Add",
    )


def gcenter103_users_tags_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "kuser_name": args.get("kuser_name"),
        "tags": args.get("tags")
    }

    data = {"tags": []}
    tags_gcenter = check_tags(client=client, tags_args=params.get('tags', ""))
    tags = params.get('tags', "").split(',')
    tags = match_tags(arg_tags=tags, gcenter_tags=tags_gcenter)

    data['tags'] = tags

    try:
        req = client._get(endpoint="/api/v1/kusers/" + params.get('kuser_name', "") + "/tags")
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()
    data2 = {"tags": []}

    r = []
    b = []
    for i in range(0, len(data['tags'])):
        r.append(data.get('tags', [{}])[i].get('id', ""))

    for i in range(0, len(res['tags'])):
        b.append(res.get('tags', [{}])[i].get('id', ""))

    r.sort()
    b.sort()

    li = []

    for i in b:
        if i not in r:
            li.append(i)

    for i in range(0, len(li)):
        data2.get('tags', [{}]).append({'id': int(li[i])})

    try:
        req = client._put(endpoint="/api/v1/kusers/" + params.get('kuser_name', "") + "/tags", json_data=data2)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-tags-remove", res.get('tags', [{}])),
        outputs_prefix="Gatewatcher.Users.Tags.Remove"
    )


def gcenter103_yara_rules_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "export": args.get("export")
    }

    try:
        req = client._get(endpoint="/api/v1/malcore/yara/settings", params=params)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-yara-rules-get", res),
        outputs_prefix="Gatewatcher.Yara.Rules.Get",
    )


def gcenter103_yara_rules_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "enabled": args.get("enabled"),
        "name": args.get("name"),
        "entryID": args.get("entryID")
    }

    data = {
        "enabled": params.get('enabled', ""),
        "filename": params.get('name', ""),
        "file": ""
    }

    fp_d = demisto.getFilePath(params.get('entryID', ""))
    data['file'] = open(fp_d.get('path', "")).read()

    try:
        req = client._put(endpoint="/api/v1/malcore/yara/settings/", json_data=data)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-yara-rules-add", res),
        outputs_prefix="Gatewatcher.Yara.Rules.Add",
    )


def gcenter103_malcore_fingerprints_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "ordering": args.get("ordering"),
        "page": args.get("page"),
        "list_type": args.get("list_type")
    }

    list_type = params.get('list_type', "")
    del params['list_type']

    try:
        req = client._get(endpoint="/api/v1/malcore/hash-" + list_type + "-list", params=params)
        if req.status_code != 200:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-malcore-fingerprints-get", res.get('results', [{}])),
        outputs_prefix="Gatewatcher.Malcore.Fingerprints.Get",
    )


def gcenter103_malcore_fingerprints_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "sha256": args.get("sha256"),
        "comment": args.get("comment"),
        "threat": args.get("threat"),
        "list_type": args.get("list_type")
    }

    data: dict[Any, Any] = {
        "sha256": params.get('sha256', ""),
        "comment": params.get('comment', ""),
        "threat": params.get('threat', "")
    }

    try:
        req = client._post(endpoint="/api/v1/malcore/hash-" + params.get('list_type', "") + "-list/", json_data=data)
        if req.status_code != 201:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-malcore-fingerprints-add", res),
        outputs_prefix="Gatewatcher.Malcore.Fingerprints.Add",
    )


def gcenter103_malcore_fingerprints_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:

    params = {
        "sha256": args.get("sha256"),
        "list_type": args.get("list_type")
    }

    try:
        req = client._delete(endpoint="/api/v1/malcore/hash-" + params.get('list_type', "") + "-list/" + params.get('sha256', ""))
        if req.status_code != 204:
            raise Exception(f"Request error: {req.status_code}: {req.reason}, {req.content}")
    except Exception as e:
        raise Exception(f"Exception: {str(e)}")

    return CommandResults(
        readable_output="# gcenter103-malcore-fingerprints-remove\n"
        "## Hash: " + params.get('sha256', "") + "\n"
        + "## Sucessfully deleted from "
        + params.get('list_type', "")
        + " list",
        outputs_prefix="Gatewatcher.Malcore.Fingerprints.Remove",
    )


def convert_event_severity(gw_sev: int) -> float:

    severity_map = {
        0: 0.5,
        1: 4,
        2: 2,
        3: 1
    }
    return severity_map.get(gw_sev, 0)


def gw_client_auth(params: dict) -> GwClient:

    ip: str = params.get('ip')
    token: str = params.get('token', {}).get('password')
    user: str = params.get('credentials', {}).get('identifier')
    password: str = params.get('credentials', {}).get('password')
    check_cert: bool = params.get("check_cert", False)

    client: GwClient = GwClient(ip=ip, check_cert=check_cert)
    client.auth(
        user=user if user != "" else None,
        password=password if password != "" else None,
        token=token
    )

    return client


def last_run_range(params: dict[str, Any]) -> list[str]:

    from_to: list[str] = ["", ""]
    first_fetch = params.get('first_fetch', '1 day')
    first_fetch_dt = arg_to_datetime(arg=first_fetch, arg_name='First fetch', required=True)  # noqa: F405

    last_run = demisto.getLastRun()
    now = datetime.today()
    now_str = now.isoformat(sep='T', timespec='milliseconds') + "Z"

    if last_run == {}:

        first_fetch_dt_str = first_fetch_dt.isoformat(sep='T', timespec='milliseconds') + "Z"

        from_to[0] = str(first_fetch_dt_str)
        from_to[1] = str(now_str)

        return from_to

    else:

        last_fetch = last_run.get('start_time')
        from_to[0] = str(last_fetch)
        from_to[1] = str(now_str)

        return from_to


def query_es_alerts(client: GwClient,
                    query: dict[str, Any]) -> list[dict[Any, Any]]:

    ret: requests.Response = client._post(endpoint="/api/v1/data/es/search/", params={"index": "engines_alerts"}, json_data=query)
    res: dict[Any, Any] = ret.json()

    if len(res['hits']['hits']) > 0:
        return res.get('hits', {}).get('hits', [{}])

    return [{}]


def query_es_metadata(client: GwClient,
                      query: dict[str, Any]) -> list[list[dict[Any, Any]]]:

    ret: requests.Response = client._post(endpoint="/api/v1/data/es/search/",
                                          params={"index": "engines_metadata"}, json_data=query)
    res: dict[Any, Any] = ret.json()

    if len(res['hits']['hits']) > 0:
        return res.get('hits', {}).get('hits', [{}])

    return [{}]


def handle_big_fetch_selected_engines(client: GwClient,
                                      query: dict[str, Any],
                                      engine_selection: list[str],
                                      max_fetch: int,
                                      fetch_type: str):

    gw_alerts = []
    search_after_id_a: int = -1

    if fetch_type in ("Alerts", "Both"):

        query['size'] = 10000
        query['query']['bool']['must'][0]['match']['event.module'] = str(engine_selection[0])

        res_a = query_es_alerts(client=client, query=query)
        gw_alerts = res_a
        search_after_id_a = gw_alerts[-1]['sort'][0]

        nb_req: int = max_fetch // 10000
        nb_req = nb_req + 1

        while nb_req > 0:

            query['search_after'] = [search_after_id_a]
            res_a = query_es_alerts(client=client, query=query)
            gw_alerts += res_a
            search_after_id_a = gw_alerts[-1]['sort'][0]

            nb_req = nb_req - 1

    for i in range(1, len(engine_selection)):

        query['query']['bool']['must'][0]['match']['event.module'] = str(engine_selection[i])
        res_a = query_es_alerts(client=client, query=query)
        gw_alerts += res_a
        search_after_id_a = gw_alerts[-1]['sort'][0]

        nb_req = max_fetch // 10000
        nb_req = nb_req + 1

        while nb_req > 0:

            query['search_after'] = [search_after_id_a]
            res_a = query_es_alerts(client=client, query=query)
            gw_alerts += res_a
            search_after_id_a = gw_alerts[-1]['sort'][0]

            nb_req = nb_req - 1

        query['search_after'] = []

    return gw_alerts


def handle_big_fetch_empty_selected_engines(client: GwClient,
                                            query: dict[str, Any],
                                            max_fetch: int,
                                            fetch_type: str):

    query['size'] = 10000
    search_after_id_a: int = -1
    gw_alerts = []

    if fetch_type in ("Alerts", "Both"):

        res_a = query_es_alerts(client=client, query=query)
        gw_alerts = res_a
        search_after_id_a = gw_alerts[-1]['sort'][0]

    nb_req: int = max_fetch // 10000
    nb_req = nb_req + 1

    while nb_req > 0:

        query['search_after'] = [search_after_id_a]
        res_a = query_es_alerts(client=client, query=query)
        gw_alerts += res_a
        search_after_id_a = gw_alerts[-1]['sort'][0]

        nb_req = nb_req - 1

    query['search_after'] = []

    return gw_alerts


def handle_big_fetch_metadata(client: GwClient,
                              query: dict[str, Any],
                              max_fetch: int,
                              fetch_type: str):

    query['size'] = 10000

    search_after_id_m: int = -1
    gw_metadata = []

    if fetch_type in ("Metadata", "Both"):

        res_m = query_es_metadata(client=client, query=query)
        gw_metadata = res_m
        search_after_id_m = gw_metadata[-1]['sort'][0]

    nb_req: int = max_fetch // 10000
    nb_req = nb_req + 1

    while nb_req > 0:

        query['search_after'] = [search_after_id_m]
        res_m = query_es_metadata(client=client, query=query)
        gw_metadata += res_m
        search_after_id_m = gw_metadata[-1]['sort'][0]

        nb_req = nb_req - 1

    return gw_metadata


def handle_little_fetch_alerts(client: GwClient,
                               fetch_type: str,
                               engine_selection: list[str],
                               query: dict[str, Any]) -> list[list[dict[Any, Any]]]:

    gw_alerts: list[list[dict[Any, Any]]] = []

    for i in range(0, len(engine_selection)):

        if fetch_type in ("Alerts", "Both"):

            query['query']['bool']['must'][0]['match']['event.module'] = str(engine_selection[i])
            res_a: list[dict[Any, Any]] = query_es_alerts(client=client, query=query)
            gw_alerts += res_a

    return gw_alerts


def handle_little_fetch_empty_selected_engines(client: GwClient,
                                               fetch_type: str,
                                               query: dict[str, Any]) -> list[dict[Any, Any]]:
    gw_alerts: list[dict[Any, Any]] = []
    if fetch_type in ("Alerts", "Both"):

        res_a: list[dict[Any, Any]] = query_es_alerts(client=client, query=query)
        gw_alerts: list[dict[Any, Any]] = res_a

    return gw_alerts


def handle_little_fetch_metadata(client: GwClient,
                                 fetch_type: str,
                                 query: dict[str, Any]) -> list[list[dict[Any, Any]]]:

    gw_metadata: list[list[dict[Any, Any]]] = []

    if fetch_type in ("Metadata", "Both"):

        res_m = query_es_metadata(client=client, query=query)
        gw_metadata = res_m

    return gw_metadata


def index_alerts_incidents(to_index: list[list[dict[Any, Any]]],
                           incidents: list[dict[Any, Any]],
                           params: dict[str, Any]) -> list[dict[Any, Any]]:

    webui_link: str = "https://" + str(params.get('ip', "")) + "/ui/alerts?drawer=alert&drawer_uuid="

    for i in range(0, len(to_index)):

        if to_index[i].get('_source', {}) == {}:
            return []

        webui_link += to_index[i].get('_source', {}).get('event', {}).get('id', "")

        incident: dict[Any, Any] = {
            'name': "Gatewatcher Alert: " + to_index[i].get('_source', {}).get('event', {}).get('module', ""),
            'occurred': to_index[i].get('_source', {}).get('@timestamp', ""),
            'dbotMirrorId': to_index[i].get('_source', {}).get('event', {}).get('id', ""),
            'labels': [
                {
                    "value": to_index[i].get('_source', {}).get('source', {}).get('ip', ""),
                    "type": "IP"
                },
                {
                    "value": to_index[i].get('_source', {}).get('destination', {}).get('ip', ""),
                    "type": "IP"
                }
            ],
            'rawJSON': json.dumps(to_index[i].get('_source', {})),
            'type': "Gatewatcher Incident",
            'CustomFields': {
                'GatewatcherRawEvent': json.dumps(to_index[i].get('_source', {})),
                'GatewatcherGCenterWebUI': webui_link
            }
        }

        webui_link = webui_link.rstrip(to_index[i].get('_source', {}).get('event', {}).get('id', ""))

        # XSOAR Severity
        if 'severity' in to_index[i].get('_source', {}).get('event', {}):
            incident['severity'] = convert_event_severity(to_index[i].get('_source', {}).get('event', {}).get('severity', ""))

        else:
            incident['severity'] = convert_event_severity(-1)

        # Sigflow alert signature
        if 'sigflow' in to_index[i].get('_source', {}) and 'signature' in to_index[i].get('_source', {}).get('sigflow', {}):
            incident['name'] = "Gatewatcher Alert: " + to_index[i].get('_source', {}).get('sigflow', {}).get('signature', "")

        # NBA alert signature
        if 'nba' in to_index[i].get('_source', {}) and 'signature' in to_index[i].get('_source', {}).get('nba', ""):
            incident['name'] = "Gatewatcher Alert: " + to_index[i].get('_source', {}).get('nba', {}).get('signature', "")

        incidents.append(incident)

    return incidents


def index_metadata_incidents(to_index: list[list[dict[Any, Any]]],
                             incidents: list[dict[Any, Any]]) -> list[dict[Any, Any]]:

    for i in range(0, len(to_index)):

        if to_index[i].get('_source', {}) == {}:
            return []

        incident: dict[Any, Any] = {
            'name': "Gatewatcher Metadata: " + to_index[i].get('_source', {}).get('event', {}).get('module', ""),
            'occurred': to_index[i].get('_source', {}).get('@timestamp', ""),
            'dbotMirrorId': to_index[i].get('_source', {}).get('event', {}).get('id', ""),
            'labels': [
                {
                    "value": to_index[i].get('_source', {}).get('source', {}).get('ip', ""),
                    "type": "IP"
                },
                {
                    "value": to_index[i].get('_source', {}).get('destination', {}).get('ip', ""),
                    "type": "IP"
                }
            ],
            'rawJSON': json.dumps(to_index[i].get('_source', {})),
            'type': "Gatewatcher Incident"
        }

        # XSOAR Severity
        if 'severity' in to_index[i].get('_source', {}).get('event', {}):
            incident['severity'] = convert_event_severity(to_index[i].get('_source', {}).get('event', {}).get('severity', ""))

        else:
            incident['severity'] = convert_event_severity(-1)

        incidents.append(incident)

    return incidents


def query_selected_engines_builder(max_fetch: int, engine_selection: list, from_to: list) -> dict[str, Any]:

    query: dict[str, Any] = {
        "size": max_fetch,
        "query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "event.module": str(engine_selection[0])
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gt": str(from_to[0]),
                                "lt": str(from_to[1])
                            }
                        }
                    }
                ]
            }
        },
        "sort": [
            {
                "@timestamp": "asc"
            }
        ]
    }

    return query


def query_empty_selected_engines_builder(from_to: list[str], max_fetch: int) -> dict[str, Any]:

    query: dict[str, Any] = {
        "size": max_fetch,
        "query": {
            "range": {
                "@timestamp": {
                    "gt": str(from_to[0]),
                    "lt": str(from_to[1])
                }
            }
        },
        "sort": [
            {
                "@timestamp": "asc"
            }
        ]
    }

    return query


def fetch_selected_engines(client: GwClient,
                           engine_selection: list[str],
                           params: dict[str, Any],
                           max_fetch: int,
                           fetch_type: str,
                           incidents: list[dict[Any, Any]]) -> list[dict[Any, Any]]:

    from_to: list[str] = last_run_range(params=params)
    query: dict[str, Any] = query_selected_engines_builder(max_fetch=max_fetch,
                                                           engine_selection=engine_selection,
                                                           from_to=from_to)

    if max_fetch > 10000:

        gw_alerts = handle_big_fetch_selected_engines(client=client,
                                                      query=query,
                                                      engine_selection=engine_selection,
                                                      max_fetch=max_fetch,
                                                      fetch_type=fetch_type)
        incidents_a = index_alerts_incidents(to_index=gw_alerts,
                                             incidents=incidents,
                                             params=params)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_big_fetch_metadata(client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents_m = index_metadata_incidents(to_index=gw_metadata, incidents=incidents)

        return incidents_a + incidents_m

    else:

        gw_alerts: list[list[dict[Any, Any]]] = handle_little_fetch_alerts(
            client=client, query=query, engine_selection=engine_selection, fetch_type=fetch_type)
        incidents_a: list[dict[Any, Any]] = []
        if len(gw_alerts) > 0:
            incidents_a = index_alerts_incidents(to_index=gw_alerts, incidents=incidents, params=params)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata: list[list[dict[Any, Any]]] = handle_little_fetch_metadata(client=client, query=query, fetch_type=fetch_type)
        incidents_m: list[dict[Any, Any]] = []
        if len(gw_metadata) > 0:
            incidents_m = index_metadata_incidents(to_index=gw_metadata, incidents=incidents)

        return incidents_a + incidents_m


def fetch_empty_selected_engines(client: GwClient,
                                 max_fetch: int,
                                 fetch_type: str,
                                 incidents,
                                 params: dict[str, Any]):

    from_to: list[str] = last_run_range(params=params)
    query: dict[str, Any] = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)

    if max_fetch > 10000:

        gw_alerts = handle_big_fetch_empty_selected_engines(
            client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents_a = index_alerts_incidents(to_index=gw_alerts, incidents=incidents, params=params)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_big_fetch_metadata(client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents_m = index_metadata_incidents(to_index=gw_metadata, incidents=incidents)

        return incidents_a + incidents_m

    else:

        gw_alerts: list[dict[Any, Any]] = handle_little_fetch_empty_selected_engines(
            client=client,
            query=query,
            fetch_type=fetch_type
        )
        incidents_a = []
        if len(gw_alerts) > 0:
            incidents_a = index_alerts_incidents(to_index=gw_alerts, incidents=incidents, params=params)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_little_fetch_metadata(client=client, query=query, fetch_type=fetch_type)
        incidents_m = []
        if len(gw_metadata) > 0:
            incidents_m = index_metadata_incidents(to_index=gw_metadata, incidents=incidents)

        return incidents_a + incidents_m


def fix_broken_list(params: dict[str, Any]) -> list[str]:

    if 'engine_selection' not in params or not isinstance(params.get('engine_selection', "malcore"), str | list):

        raise ValueError("Invalid 'engine_selection' parameter")

    bdl = params.get('engine_selection', "malcore")
    known_engines = {
        "malcore", "shellcode_detect", "malicious_powershell_detect",
        "sigflow_alert", "dga_detect", "active_cti", "retrohunt",
        "ransomware_detect", "beacon_detect"
    }
    e_s = []

    if isinstance(bdl, str):
        e_s = [engine for engine in known_engines if engine in bdl]

    elif isinstance(bdl, list):
        e_s = [engine for engine in known_engines if engine in bdl]

    return e_s


def fetch_incidents():

    params: dict[str, Any] = demisto.params()
    demisto.args()

    max_fetch: int = int(params.get('max_fetch', "200"))

    fetch_type: str = params.get('fetch_type', "Alerts")

    engine_selection: list[str] = fix_broken_list(params=params)

    client: GwClient = gw_client_auth(params=params)

    incidents: list[dict[Any, Any]] = []

    if len(engine_selection) > 0:

        incidents = fetch_selected_engines(client=client,
                                           engine_selection=engine_selection,
                                           params=params,
                                           max_fetch=max_fetch,
                                           fetch_type=fetch_type,
                                           incidents=incidents)

    else:

        incidents = fetch_empty_selected_engines(client=client, max_fetch=max_fetch,
                                                 fetch_type=fetch_type, incidents=incidents, params=params)

    if len(incidents) > 0:
        incidents_s = sorted(incidents, key=lambda d: d.get('occurred', ""))
        last_incident = incidents_s[len(incidents_s) - 1]
        demisto.setLastRun({'start_time': last_incident.get('occurred', "")})

    demisto.incidents(incidents=incidents)


def main() -> None:
    """Main function, parses params and runs command functions."""

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    ip = params.get("ip")
    token = params.get('token', {}).get('password')
    user = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    check_cert = params.get("check_cert", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = GwClient(ip=ip, check_cert=check_cert, proxy=proxy)
        client.auth(
            user=user if user != "" else None,
            password=password if password != "" else None,
            token=token
        )
        if command == "test-module":
            return_results(  # noqa: F405
                test_module(client=client, user=user, password=password, token=token)
            )
        elif command == "fetch-incidents":
            return_results(  # noqa: F405
                fetch_incidents()
            )
        elif command == "gcenter103-alerts-list":
            return_results(  # noqa: F405
                gcenter103_alerts_list_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-alerts-get":
            return_results(  # noqa: F405
                gcenter103_alerts_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-alerts-note-add":
            return_results(  # noqa: F405
                gcenter103_alerts_note_add_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-alerts-note-remove":
            return_results(  # noqa: F405
                gcenter103_alerts_note_remove_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-alerts-tags-get":
            return_results(  # noqa: F405
                gcenter103_alerts_tags_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-alerts-tags-add":
            return_results(  # noqa: F405
                gcenter103_alerts_tags_add_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-alerts-tags-remove":
            return_results(  # noqa: F405
                gcenter103_alerts_tags_remove_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-alerts-status-update":
            return_results(  # noqa: F405
                gcenter103_alerts_status_update_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-raw-alerts-get":
            return_results(  # noqa: F405
                gcenter103_raw_alerts_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-raw-alerts-file-get":
            return_results(  # noqa: F405
                gcenter103_raw_alerts_file_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-file-scan":
            return_results(  # noqa: F405
                gcenter103_file_scan_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-file-scan-result-get":
            return_results(  # noqa: F405
                gcenter103_file_scan_result_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-assets-list":
            return_results(  # noqa: F405
                gcenter103_assets_list_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-assets-alerts-get":
            return_results(  # noqa: F405
                gcenter103_assets_alerts_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-assets-get":
            return_results(  # noqa: F405
                gcenter103_assets_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-assets-note-add":
            return_results(  # noqa: F405
                gcenter103_assets_note_add_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-assets-note-remove":
            return_results(  # noqa: F405
                gcenter103_assets_note_remove_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-assets-tags-get":
            return_results(  # noqa: F405
                gcenter103_assets_tags_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-assets-tags-add":
            return_results(  # noqa: F405
                gcenter103_assets_tags_add_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-assets-tags-remove":
            return_results(  # noqa: F405
                gcenter103_assets_tags_remove_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-users-list":
            return_results(  # noqa: F405
                gcenter103_users_list_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-users-alerts-get":
            return_results(  # noqa: F405
                gcenter103_users_alerts_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-users-get":
            return_results(  # noqa: F405
                gcenter103_users_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-users-note-add":
            return_results(  # noqa: F405
                gcenter103_users_note_add_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-users-note-remove":
            return_results(  # noqa: F405
                gcenter103_users_note_remove_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-users-tags-get":
            return_results(  # noqa: F405
                gcenter103_users_tags_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-users-tags-add":
            return_results(  # noqa: F405
                gcenter103_users_tags_add_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-users-tags-remove":
            return_results(  # noqa: F405
                gcenter103_users_tags_remove_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-yara-rules-get":
            return_results(  # noqa: F405
                gcenter103_yara_rules_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-yara-rules-add":
            return_results(  # noqa: F405
                gcenter103_yara_rules_add_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-malcore-fingerprints-get":
            return_results(  # noqa: F405
                gcenter103_malcore_fingerprints_get_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-malcore-fingerprints-add":
            return_results(  # noqa: F405
                gcenter103_malcore_fingerprints_add_command(
                    client=client,
                    args=args)
            )
        elif command == "gcenter103-malcore-fingerprints-remove":
            return_results(  # noqa: F405
                gcenter103_malcore_fingerprints_remove_command(
                    client=client,
                    args=args)
            )

    except Exception as e:
        return_error(  # noqa: F405
            f"Failed to execute {command} command.\nError: {str(e)}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

from typing import Any

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

    PROXIES = {"http": "", "https": ""}

    def __init__(self, ip: str, headers: dict = {}, check_cert: bool = False, proxy: bool = False) -> None:
        """Init.

        Disable urllib3 warning. Allow unsecure ciphers.

        Args:
            ip: IP address of the HTTP server.
            check_cert: True to validate server certificate and False instead.
            proxies: Requests proxies. Default to no proxies.
        """
        self.index_values = ["suricata", "codebreaker", "malware", "netdata", "syslog", "machine_learning", "retrohunt", "iocs"]
        self.ip = ip
        self.headers = headers
        self.check_cert = check_cert

        if proxy:
            d = handle_proxy(proxy_param_name="proxy")
            self.PROXIES["http"] = d["http"]
            self.PROXIES["https"] = d["https"]

    def _gen_request_kwargs(
        self,
        endpoint: str,
        data: dict | None,
        json_data: dict | None,
        params: dict | None,
        headers: dict | None,
        cookies: dict | None,
        redirects: bool | None,
        files: dict | None = None,
    ) -> dict:
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
            "files": files,
        }
        return kwargs

    def _get(
        self,
        endpoint: str,
        data: dict | None = None,
        json_data: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
        cookies: dict | None = None,
        redirects: bool = True,
    ) -> requests.Response:
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
            redirects=redirects,
        )
        return requests.get(**kwargs)

    def _post(
        self,
        endpoint: str,
        data: dict | None = None,
        json_data: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
        cookies: dict | None = None,
        redirects: bool = True,
        files: dict | None = None,
    ) -> requests.Response:
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
            files=files,
        )
        return requests.post(**kwargs)

    def _put(
        self,
        endpoint: str,
        data: dict | None = None,
        json_data: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
        cookies: dict | None = None,
        redirects: bool = True,
        files: dict | None = None,
    ) -> requests.Response:
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
            files=files,
        )
        return requests.put(**kwargs)

    def _delete(
        self,
        endpoint: str,
        data: dict | None = None,
        json_data: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
        cookies: dict | None = None,
        redirects: bool = True,
    ) -> requests.Response:
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
            redirects=redirects,
        )
        return requests.delete(**kwargs)


class GwClient(GwRequests):
    """Client class to interact with the service API."""

    def auth(self, user: str | None = None, password: str | None = None, token: str | None = None) -> None:
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
        elif (user is None and password is not None) or (user is not None and password is None):
            raise AttributeError("A user and a password must be provided: [ERROR]")
        if user is not None and password is not None:
            response = self._post(endpoint="/api/v1/auth/login", json_data={"username": user, "password": password})
            if response.status_code == 200:
                demisto.info(f"Authentication on GCenter {self.ip} with user {user}: [OK]")
                self.headers["API-KEY"] = response.json()["token"]
            else:
                raise GwAPIException(
                    f"Authentication on GCenter {self.ip} with user {user}: [FAILED]",
                    response.text,
                    response.status_code,
                    response.reason,
                )
        else:
            self.headers["API-KEY"] = token

    def is_authenticated(self) -> bool:
        """Return True if authenticated and False instead.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(endpoint="/api/v1/settings/")
        if response.status_code == 200:
            demisto.info(f"Get settings on GCenter {self.ip}: [OK]")
            return True
        else:
            demisto.error(f"Get settings on GCenter {self.ip}: [FAILED]", response.text, response.status_code, response.reason)
            return False


def test_module(client: GwClient, user: str, password: str, token: str) -> str:  # noqa: E501
    """Tests API connectivity and authentication command.

    Args:
        client: Client to interact with the GCenter.

    Returns:
        'Authentication successful' when the GCenter connection works.
        'Authentication error' when the GCenter connection doesn't works.
    """
    client.auth(user=user if user != "" else None, password=password if password != "" else None, token=token)

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
        "page_size": args.get("page_size"),
    }

    req = client._get(endpoint="/api/v1/alerts/", params=params)

    res: dict[Any, Any] = req.json()

    if "results" not in res:
        return CommandResults(
            readable_output="# gcenter103-alerts-list - Empty alerts list", outputs_prefix="Gatewatcher.Alerts.List"
        )

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-alerts-list", res.get("results", [{}])),
        outputs_prefix="Gatewatcher.Alerts.List",
        outputs_key_field="uuid",
        outputs=[{"uuid": res_item.get("uuid", "")} for res_item in res["results"]],
        raw_response=res,
    )


def gcenter103_alerts_get_command(client: GwClient, args: dict[str, str]) -> CommandResults:
    req = client._get(endpoint="/api/v1/alerts/" + args.get("uuid", ""))

    res = req.json()

    res_keys: dict[Any, Any] = {"uuid": res.get("uuid", "")}

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-alerts-get", res),
        outputs_prefix="Gatewatcher.Alerts.Get",
        outputs_key_field="uuid",
        outputs=res_keys,
        raw_response=res,
    )


def gcenter103_alerts_note_add_command(client: GwClient, args: dict[str, str]) -> CommandResults:
    note = args.get("note", "")
    uuid = args.get("uuid", "")
    overwrite = args.get("overwrite", "")

    data = {"note": note}
    if overwrite != "true":
        req = client._get(endpoint="/api/v1/alerts/" + uuid)
        res = req.json()
        old_note = res.get("note")
        if old_note:
            data["note"] = old_note + "\n" + note

    req = client._put(endpoint="/api/v1/alerts/" + uuid + "/note", data=data)
    res = req.json()
    res_keys = {"note": res.get("note", "")}

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-alerts-note-add", res),
        outputs_prefix="Gatewatcher.Alerts.Note.Add",
        outputs_key_field="note",
        outputs=res_keys,
        raw_response=res,
    )


def gcenter103_alerts_note_remove_command(client: GwClient, args: dict[str, str]) -> CommandResults:
    uuid = args.get("uuid", "")
    client._delete(endpoint="/api/v1/alerts/" + uuid + "/note")

    return CommandResults(
        readable_output="# gcenter103-alerts-note-remove - Note removed of the alert: " + uuid,
        outputs_prefix="Gatewatcher.Alerts.Note.Remove",
        outputs_key_field="uuid",
        outputs=uuid,
    )


def gcenter103_alerts_tags_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    uuid = args.get("uuid", "")
    req = client._get(endpoint="/api/v1/alerts/" + uuid + "/tags")

    res = req.json()

    raw_tags = res.get("tags", [])

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-alerts-tags-get", raw_tags),
        outputs_prefix="Gatewatcher.Alerts.Tags.Get",
        outputs_key_field="tags",
        outputs={"tags": [{"label": tag.get("label", "")} for tag in raw_tags], "uuid": uuid},
        raw_response=res,
    )


def get_gcenter_tags(client: GwClient) -> dict[str, int]:
    req = client._get(endpoint="/api/v1/tags/")

    res = req.json()
    return {tag["label"]: tag["id"] for tag in res["results"]}


def get_tags_ids(client: GwClient, tags_args: list[str]) -> dict[str, int]:
    gcenter_tags = get_gcenter_tags(client=client)
    wrong_tags = [tag for tag in tags_args if tag not in gcenter_tags]
    if wrong_tags:
        raise Exception(f"Tag(s) {','.join(wrong_tags)} not found on the GCenter")
    return {tag: gcenter_tags[tag] for tag in tags_args}


def gcenter103_alerts_tags_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    uuid = args.get("uuid", "")
    tags: list[str] = args.get("tags", "").split(",")

    ids_to_add = set(get_tags_ids(client=client, tags_args=tags).values())
    req = client._get(endpoint="/api/v1/alerts/" + uuid + "/tags")
    ids_present = {tag["id"] for tag in req.json().get("tags", [])}

    res = req.json()
    data: dict[Any, Any] = {"tags": []}
    for tag in list(ids_present.union(ids_to_add)):
        data["tags"].append({"id": tag})

    req = client._put(endpoint="/api/v1/alerts/" + uuid + "/tags",
                      json_data=data,
                      )

    res = req.json()
    res_keys: dict[Any, Any] = {
        "tags": res.get("tags", {}),
        "uuid": uuid,
    }

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-alerts-tags-add", res.get("tags", {})),
        outputs_prefix="Gatewatcher.Alerts.Tags.Add",
        outputs_key_field="tags",
        outputs=res_keys,
        raw_response=res.get("tags", {}),
    )


def gcenter103_alerts_tags_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    uuid = args.get("uuid", "")
    tags: list[str] = args.get("tags", "").split(",")

    ids_to_remove = set(get_tags_ids(client=client, tags_args=tags).values())
    req = client._get(endpoint="/api/v1/alerts/" + uuid + "/tags")
    ids_present = {tag["id"] for tag in req.json().get("tags", [])}

    data: dict[Any, Any] = {"tags": []}
    for tag in list(ids_present.difference(ids_to_remove)):
        data["tags"].append({"id": tag})

    req = client._put(
        endpoint="/api/v1/alerts/" + uuid + "/tags",
        json_data=data,
    )

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-alerts-tags-remove", res.get("tags", {})),
        outputs_prefix="Gatewatcher.Alerts.Tags.Remove",
    )


def gcenter103_alerts_status_update_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    uuid = args.get("uuid", "")
    params = {
        "date_from": args.get("date_from"),
        "date_to": args.get("date_to"),
        "since": args.get("since"),
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
        "ids": 0,
    }

    data = {"note": args.get("note_u") or "", "tag": [int(tag) for tag in args.get("tag_u", "").split(",") if tag]}
    req = client._get(endpoint="/api/v1/alerts/" + uuid)

    res = req.json()
    params["ids"] = res.get("id", "")

    req = client._put(endpoint="/api/v1/alerts/action/" + args.get("action", ""), json_data=data, params=params)
    return CommandResults(
        readable_output=f"# gcenter103-alerts-status-update {req.status_code}: OK",
        outputs_prefix="Gatewatcher.Alerts.Status.Update",
    )


def gcenter103_raw_alerts_get_command(client: GwClient, args: dict[str, str]) -> CommandResults:
    req = client._get(endpoint="/api/v1/raw-alerts/" + args.get("uuid", ""))

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-raw-alerts-get", res), outputs_prefix="Gatewatcher.Raw.Alerts.Get"
    )


def gcenter103_raw_alerts_file_get_command(client: GwClient, args: dict[str, str]) -> CommandResults:
    uuid = args.get("uuid", "")

    req = client._get(endpoint="/api/v1/raw-alerts/" + uuid + "/file")

    res = req.content
    filename = uuid + "-file.zip"
    file_content = res

    return_results(fileResult(filename, file_content))

    return CommandResults(
        readable_output="# gcenter103-raw-alerts-file-get: Dumped zip file",
        outputs_prefix="Gatewatcher.Raw.Alerts.File.Get",
    )


def gcenter103_file_scan_command(client: GwClient, args: dict[str, str]) -> CommandResults:
    engine = args.get("engine", "")

    fp_d = demisto.getFilePath(args.get("entryID", ""))
    files = {"file": open(fp_d["path"], "rb")}

    req = client._post(endpoint="/api/v1/gscan/" + engine, files=files)

    res = req.json()
    res.update({"file_name": str(fp_d.get("name", ""))})

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-file-scan results of " + engine, res),
        outputs_prefix="Gatewatcher.File.Scan",
    )


def gcenter103_file_scan_result_get_command(client: GwClient, args: dict[str, str]) -> CommandResults:
    req = client._get(endpoint="/api/v1/gscan/histories/" + args.get("id", ""))

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
        "no_tag": args.get("no_tag"),
    }

    req = client._get(endpoint="/api/v1/assets/", params=params)

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-list", res["results"]),
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
    }

    req = client._get(endpoint="/api/v1/assets/" + args.get("asset_name", "") + "/alerts", params=params)

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-alerts-get", res.get("results", "")),
        outputs_prefix="Gatewatcher.Assets.Alerts.Get",
    )


def gcenter103_assets_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    params = {
        "date_from": args.get("date_from"),
        "date_to": args.get("date_to"),
        "since": args.get("since"),
        "fast": args.get("fast"),
    }

    req = client._get(endpoint="/api/v1/assets/" + args.get("asset_name", ""), params=params)

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-alerts-get", res),
        outputs_prefix="Gatewatcher.Assets.Get",
    )


def gcenter103_assets_note_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    note = args.get("note", "")
    asset_name = args.get("asset_name", "")
    overwrite = args.get("overwrite", "")

    if overwrite == "true":
        data = {"note": note}

        req = client._put(endpoint="/api/v1/assets/" + asset_name + "/note", json_data=data)

        res = req.json()

        return CommandResults(
            readable_output=tableToMarkdown("gcenter103-assets-note-add", res),
            outputs_prefix="Gatewatcher.Assets.Note.Add",
        )

    else:
        req = client._get(endpoint="/api/v1/assets/" + asset_name)

        res = req.json()
        old_note = res.get("note", "")
        if old_note is None:
            old_note = ""
        data = {"note": old_note + "\n" + note}

        req = client._put(endpoint="/api/v1/assets/" + asset_name + "/note", json_data=data)

        res = req.json()

        return CommandResults(
            readable_output=tableToMarkdown("gcenter103-assets-note-add", res), outputs_prefix="Gatewatcher.Assets.Note.Add"
        )


def gcenter103_assets_note_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    asset_name = args.get("asset_name", "")

    client._delete(endpoint="/api/v1/assets/" + asset_name + "/note")

    return CommandResults(
        readable_output="# gcenter103-assets-note-remove - Note removed of asset: " + asset_name,
        outputs_prefix="Gatewatcher.Assets.Note.Remove",
    )


def gcenter103_assets_tags_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    asset_name = args.get("asset_name", "")

    req = client._get(endpoint="/api/v1/assets/" + asset_name + "/tags")

    res = req.json()

    if len(res["tags"]) == 0:
        return CommandResults(
            readable_output="# gcenter103-assets-tags-get - This asset has no associated tags",
            outputs_prefix="Gatewatcher.Assets.Tags.Get",
        )

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-tags-get", res.get("tags", [])),
        outputs_prefix="Gatewatcher.Assets.Tags.Get",
    )


def gcenter103_assets_tags_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    asset_name = args.get("asset_name", "")
    tags = args.get("tags", "").split(",")

    ids_to_add = set(get_tags_ids(client=client, tags_args=tags).values())
    req = client._get(endpoint="/api/v1/assets/" + asset_name + "/tags")
    ids_present = {tag["id"] for tag in req.json().get("tags", [])}

    res = req.json()
    data: dict[Any, Any] = {"tags": []}
    for tag in list(ids_present.union(ids_to_add)):
        data["tags"].append({"id": tag})

    req = client._put(endpoint="/api/v1/assets/" + asset_name + "/tags",
                      json_data=data,
                      )
    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-tags-add", res.get("tags", [{}])),
        outputs_prefix="Gatewatcher.Assets.Tags.Add",
    )


def gcenter103_assets_tags_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    asset_name = args.get("asset_name", "")
    tags = args.get("tags", "").split(",")

    ids_to_remove = set(get_tags_ids(client=client, tags_args=tags).values())
    req = client._get(endpoint="/api/v1/assets/" + asset_name + "/tags")
    ids_present = {tag["id"] for tag in req.json().get("tags", [])}
    data: dict[Any, Any] = {"tags": []}
    for tag in list(ids_present.difference(ids_to_remove)):
        data["tags"].append({"id": tag})

    req = client._put(
        endpoint="/api/v1/assets/" + asset_name + "/tags",
        json_data=data,
    )
    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-assets-tags-remove", res.get("tags", [{}])),
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
        "no_tag": args.get("no_tag"),
    }

    req = client._get(endpoint="/api/v1/kusers", params=params)

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-list", res.get("results", [{}])),
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
    }

    kuser_name = args.get("kuser_name", "")

    req = client._get(endpoint="/api/v1/kusers/" + kuser_name + "/alerts", params=params)

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-alerts-get", res.get("results", [{}])),
        outputs_prefix="Gatewatcher.Users.Alerts.Get",
    )


def gcenter103_users_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    params = {
        "date_from": args.get("date_from"),
        "date_to": args.get("date_to"),
        "since": args.get("since"),
        "fast": args.get("fast"),
    }

    req = client._get(endpoint="/api/v1/kusers/" + args.get("kuser_name", ""), params=params)

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-get", res),
        outputs_prefix="Gatewatcher.Users.Get",
    )


def gcenter103_users_note_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    note = args.get("note", "")
    kuser_name = args.get("kuser_name", "")
    overwrite = args.get("overwrite", "")

    if overwrite == "true":
        data = {"note": note}

        req = client._put(endpoint="/api/v1/kusers/" + kuser_name + "/note", json_data=data)

        res = req.json()

        return CommandResults(
            readable_output=tableToMarkdown("gcenter103-users-note-add", res),
            outputs_prefix="Gatewatcher.Users.Note.Add",
        )

    else:
        req = client._get(endpoint="/api/v1/kusers/" + kuser_name)

        res = req.json()
        old_note = res.get("note", "")
        if old_note is None:
            old_note = ""
        data = {"note": old_note + "\n" + note}

        req = client._put(endpoint="/api/v1/kusers/" + kuser_name + "/note", json_data=data)

        res = req.json()

        return CommandResults(
            readable_output=tableToMarkdown("gcenter103-users-note-add", res),
            outputs_prefix="Gatewatcher.Users.Note.Add",
        )


def gcenter103_users_note_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    kuser_name = args.get("kuser_name", "")

    client._delete(endpoint="/api/v1/kusers/" + kuser_name + "/note")

    return CommandResults(
        readable_output="# gcenter103-users-note-remove - Note of: " + kuser_name + " deleted",
        outputs_prefix="Gatewatcher.Users.Note.Remove",
    )


def gcenter103_users_tags_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    req = client._get(endpoint="/api/v1/kusers/" + args.get("kuser_name", "") + "/tags")

    res = req.json()

    if not res.get("tags", []):
        return CommandResults(
            readable_output="# gcenter103-users-tags-get - Empty tags list",
            outputs_prefix="Gatewatcher.Users.Tags.Get",
        )

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-tags-get", res["tags"]),
        outputs_prefix="Gatewatcher.Users.Tags.Get",
    )


def gcenter103_users_tags_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    tags = args.get("tags", "").split(",")
    kuser_name = args.get("kuser_name", "")

    ids_to_add = set(get_tags_ids(client=client, tags_args=tags).values())
    req = client._get(endpoint="/api/v1/kusers/" + kuser_name + "/tags")
    ids_present = {tag["id"] for tag in req.json().get("tags", [])}
    res = req.json()
    data: dict[Any, Any] = {"tags": []}
    for tag in list(ids_present.union(ids_to_add)):
        data["tags"].append({"id": tag})

    req = client._put(endpoint="/api/v1/kusers/" + kuser_name + "/tags",
                      json_data=data
                      )
    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-tags-add", res.get("tags", [{}])),
        outputs_prefix="Gatewatcher.Users.Tags.Add",
    )


def gcenter103_users_tags_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    kuser_name = args.get("kuser_name", "")
    tags = args.get("tags", "").split(",")

    ids_to_remove = set(get_tags_ids(client=client, tags_args=tags).values())
    req = client._get(endpoint="/api/v1/kusers/" + kuser_name + "/tags")
    ids_present = {tag["id"] for tag in req.json().get("tags", [])}
    data: dict[Any, Any] = {"tags": []}
    for tag in list(ids_present.difference(ids_to_remove)):
        data["tags"].append({"id": tag})

    req = client._put(
        endpoint="/api/v1/kusers/" + kuser_name + "/tags",
        json_data=data,
    )
    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-users-tags-remove", res.get("tags", [{}])),
        outputs_prefix="Gatewatcher.Users.Tags.Remove",
    )


def gcenter103_yara_rules_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    params = {"export": args.get("export")}

    req = client._get(endpoint="/api/v1/malcore/yara/settings", params=params)

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-yara-rules-get", res),
        outputs_prefix="Gatewatcher.Yara.Rules.Get",
    )


def gcenter103_yara_rules_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    data = {"enabled": args.get("enabled", ""), "filename": args.get("name", ""), "file": ""}

    fp_d = demisto.getFilePath(args.get("entryID", ""))
    with open(fp_d.get("path", "")) as yara_file:
        data["file"] = yara_file.read()

    req = client._put(endpoint="/api/v1/malcore/yara/settings/", json_data=data)

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-yara-rules-add", res),
        outputs_prefix="Gatewatcher.Yara.Rules.Add",
    )


def gcenter103_malcore_fingerprints_get_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    params = {"ordering": args.get("ordering"), "page": args.get("page"), "list_type": args.get("list_type")}

    req = client._get(endpoint="/api/v1/malcore/hash-" + args.get("list_type", "") + "-list", params=params)

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-malcore-fingerprints-get", res.get("results", [{}])),
        outputs_prefix="Gatewatcher.Malcore.Fingerprints.Get",
    )


def gcenter103_malcore_fingerprints_add_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    data = {
        "sha256": args.get("sha256", ""),
        "comment": args.get("comment", ""),
        "threat": args.get("threat", ""),
    }

    req = client._post(endpoint="/api/v1/malcore/hash-" + args.get("list_type", "") + "-list/", json_data=data)

    res = req.json()

    return CommandResults(
        readable_output=tableToMarkdown("gcenter103-malcore-fingerprints-add", res),
        outputs_prefix="Gatewatcher.Malcore.Fingerprints.Add",
    )


def gcenter103_malcore_fingerprints_remove_command(client: GwClient, args: dict[str, Any]) -> CommandResults:
    sha256 = args.get("sha256", "")
    list_type = args.get("list_type", "")

    client._delete(endpoint="/api/v1/malcore/hash-" + list_type + "-list/" + sha256)

    return CommandResults(
        readable_output="# gcenter103-malcore-fingerprints-remove\n"
        "## Hash: " + sha256 + "\n" + "## Sucessfully deleted from " + list_type + " list",
        outputs_prefix="Gatewatcher.Malcore.Fingerprints.Remove",
    )


def convert_event_severity(gw_sev: int) -> float:
    severity_map = {0: 0.5, 1: 4, 2: 2, 3: 1}
    return severity_map.get(gw_sev, 0)


def gw_client_auth(params: dict) -> GwClient:
    ip: str = params["ip"]
    token: str = params.get("token", {}).get("password")
    user: str = params.get("credentials", {}).get("identifier")
    password: str = params.get("credentials", {}).get("password")
    check_cert: bool = params.get("check_cert", False)

    client: GwClient = GwClient(ip=ip, check_cert=check_cert)
    client.auth(user=user if user != "" else None, password=password if password != "" else None, token=token)

    return client


def last_run_range(params: dict[str, Any]) -> list[str]:
    from_to: list[str] = ["", ""]
    first_fetch = params.get("first_fetch", "1 day")
    first_fetch_dt = arg_to_datetime(arg=first_fetch, arg_name="First fetch", required=True)

    last_run = demisto.getLastRun()
    now = datetime.today()
    now_str = now.isoformat(sep="T", timespec="milliseconds") + "Z"

    if last_run == {}:
        assert first_fetch_dt
        first_fetch_dt_str = first_fetch_dt.isoformat(sep="T", timespec="milliseconds") + "Z"

        from_to[0] = str(first_fetch_dt_str)
        from_to[1] = str(now_str)

        return from_to

    else:
        last_fetch = last_run.get("start_time")
        from_to[0] = str(last_fetch)
        from_to[1] = str(now_str)

        return from_to


def query_es_alerts(client: GwClient, query: dict[str, Any]) -> list[dict[Any, Any]] | None:
    ret: requests.Response = client._post(endpoint="/api/v1/data/es/search/", params={"index": "engines_alerts"}, json_data=query)
    res: dict[Any, Any] = ret.json()

    if len(res.get("hits", {}).get("hits", [])) > 0:
        return res["hits"]["hits"]

    return None


def query_es_metadata(client: GwClient, query: dict[str, Any]) -> list[dict[Any, Any]] | None:
    ret: requests.Response = client._post(
        endpoint="/api/v1/data/es/search/", params={"index": "engines_metadata"}, json_data=query
    )
    res: dict[Any, Any] = ret.json()

    if len(res["hits"]["hits"]) > 0:
        return res.get("hits", {}).get("hits", [{}])

    return None


def handle_big_fetch_selected_engines(
    client: GwClient, query: dict[str, Any], engine_selection: list[str], max_fetch: int, fetch_type: str
):
    gw_alerts = []

    for engine in engine_selection:
        if fetch_type in ("Alerts", "Both"):
            query["size"] = 10000
            query["query"]["bool"]["must"][0]["match"]["event.module"] = engine

            found_alerts = query_es_alerts(client=client, query=query) or []
            gw_alerts.extend(found_alerts)
            search_after_id_a = cast(int, gw_alerts[-1]["sort"][0])

            for _ in range((max_fetch - 1) // 10000):
                if len(found_alerts) < 10000:
                    break
                query["search_after"] = [search_after_id_a]
                found_alerts = query_es_alerts(client=client, query=query) or []
                gw_alerts.extend(found_alerts)
                search_after_id_a = gw_alerts[-1]["sort"][0]
    return gw_alerts


def handle_big_fetch_empty_selected_engines(client: GwClient, query: dict[str, Any], max_fetch: int, fetch_type: str):
    query["size"] = 10000
    gw_alerts = []

    if fetch_type in ("Alerts", "Both"):
        found_alerts = query_es_alerts(client=client, query=query) or []
        gw_alerts.extend(found_alerts)
        search_after_id_a = gw_alerts[-1]["sort"][0]

        for _ in range((max_fetch - 1) // 10000):
            if len(found_alerts) < 10000:
                break
            query["search_after"] = [search_after_id_a]
            found_alerts = query_es_alerts(client=client, query=query) or []
            gw_alerts.extend(found_alerts)
            search_after_id_a = gw_alerts[-1]["sort"][0]
    return gw_alerts


def handle_big_fetch_metadata(client: GwClient, query: dict[str, Any], max_fetch: int, fetch_type: str):
    query["size"] = 10000

    gw_metadata = []

    if fetch_type in ("Metadata", "Both"):
        found_metadata = query_es_metadata(client=client, query=query) or []
        gw_metadata.extend(found_metadata)
        search_after_id = gw_metadata[-1]["sort"][0]
        for _ in range((max_fetch - 1) // 10000):
            if len(found_metadata) < 10000:
                break
            query["search_after"] = [search_after_id]
            found_metadata = query_es_metadata(client=client, query=query) or []
            gw_metadata.extend(found_metadata)
            search_after_id = gw_metadata[-1]["sort"][0]

    return gw_metadata


def handle_little_fetch_alerts(
    client: GwClient, fetch_type: str, engine_selection: list[str], query: dict[str, Any]
) -> list[list[dict[Any, Any]]]:
    gw_alerts: list[list[dict[Any, Any]]] = [[{}]]

    for engine in engine_selection:
        if fetch_type in ("Alerts", "Both"):
            query["query"]["bool"]["must"][0]["match"]["event.module"] = engine
            res_a: list[dict[Any, Any]] | None = query_es_alerts(client=client, query=query)
            if res_a is not None:
                gw_alerts.append(res_a)

    return gw_alerts


def handle_little_fetch_empty_selected_engines(client: GwClient, fetch_type: str, query: dict[str, Any]) -> list[dict[Any, Any]]:
    gw_alerts: list[dict[Any, Any]] | None = [{}]
    if fetch_type in ("Alerts", "Both"):
        res_a: list[dict[Any, Any]] | None = query_es_alerts(client=client, query=query)
        if res_a is not None:
            gw_alerts = res_a
            return gw_alerts

    return [{}]


def handle_little_fetch_metadata(client: GwClient, fetch_type: str, query: dict[str, Any]) -> list[dict[Any, Any]]:
    gw_metadata: list[dict[Any, Any]] | None = [{}]

    if fetch_type in ("Metadata", "Both"):
        res_m: list[dict[Any, Any]] | None = query_es_metadata(client=client, query=query)
        if res_m is not None:
            gw_metadata = res_m
            return gw_metadata

    return []


def index_alerts_incidents(
    to_index: list[dict[Any, Any]] | None, params: dict[str, Any]
) -> list[dict[Any, Any]]:
    webui_link: str = "https://" + str(params.get("ip", "")) + "/ui/alerts?drawer=alert&drawer_uuid="
    incidents = []
    for new_incident in to_index or []:
        if not new_incident.get("_source"):
            continue

        webui_link += new_incident.get("_source", {}).get("event", {}).get("id", "")

        incident: dict[Any, Any] = {
            "name": "Gatewatcher Alert: " + new_incident.get("_source", {}).get("event", {}).get("module", ""),
            "occurred": new_incident.get("_source", {}).get("@timestamp", ""),
            "dbotMirrorId": new_incident.get("_source", {}).get("event", {}).get("id", ""),
            "labels": [
                {"value": new_incident.get("_source", {}).get("source", {}).get("ip", ""), "type": "IP"},
                {"value": new_incident.get("_source", {}).get("destination", {}).get("ip", ""), "type": "IP"},
            ],
            "rawJSON": json.dumps(new_incident.get("_source", {})),
            "type": "Gatewatcher Incident",
            "CustomFields": {
                "GatewatcherRawEvent": json.dumps(new_incident.get("_source", {})),
                "GatewatcherGCenterWebUI": webui_link,
                "protocol": new_incident.get("_source", {}).get("network", {}).get("protocol", ""),
                "sourceip": new_incident.get("_source", {}).get("source", {}).get("ip", ""),
                "sourceport": new_incident.get("_source", {}).get("source", {}).get("port", ""),
                "sourcemacaddress": new_incident.get("_source", {}).get("source", {}).get("mac", ""),
                "destinationip": new_incident.get("_source", {}).get("destination", {}).get("ip", ""),
                "destinationport": new_incident.get("_source", {}).get("destination", {}).get("port", ""),
                "destinationmacaddress": new_incident.get("_source", {}).get("destination", {}).get("mac", "")
            }
        }

        webui_link = webui_link.rstrip(new_incident.get("_source", {}).get("event", {}).get("id", ""))

        # XSOAR Severity
        if "severity" in new_incident.get("_source", {}).get("event", {}):
            incident["severity"] = convert_event_severity(new_incident.get("_source", {}).get("event", {}).get("severity", ""))

        else:
            incident["severity"] = convert_event_severity(-1)

        # Sigflow alert signature
        if "sigflow" in new_incident.get("_source", {}) and "signature" in new_incident.get("_source", {}).get("sigflow", {}):
            incident["name"] = "Gatewatcher Alert: " + new_incident.get("_source", {}).get("sigflow", {}).get("signature", "")

        # NBA alert signature
        if "nba" in new_incident.get("_source", {}) and "signature" in new_incident.get("_source", {}).get("nba", ""):
            incident["name"] = "Gatewatcher Alert: " + new_incident.get("_source", {}).get("nba", {}).get("signature", "")

        incidents.append(incident)

    return incidents


def index_metadata_incidents(to_index: list[dict[Any, Any]] | None) -> list[dict[Any, Any]]:
    incidents = []
    for new_incident in to_index or []:
        if new_incident.get("_source", {}) == {}:
            return []

        incident: dict[Any, Any] = {
            "name": "Gatewatcher Metadata: " + new_incident.get("_source", {}).get("event", {}).get("module", ""),
            "occurred": new_incident.get("_source", {}).get("@timestamp", ""),
            "dbotMirrorId": new_incident.get("_source", {}).get("event", {}).get("id", ""),
            "labels": [
                {"value": new_incident.get("_source", {}).get("source", {}).get("ip", ""), "type": "IP"},
                {"value": new_incident.get("_source", {}).get("destination", {}).get("ip", ""), "type": "IP"},
            ],
            "rawJSON": json.dumps(new_incident.get("_source", {})),
            "type": "Gatewatcher Incident",
            "CustomFields": {
                "GatewatcherRawEvent": json.dumps(new_incident.get("_source", {})),
                "protocol": new_incident.get("_source", {}).get("network", {}).get("protocol", ""),
                "sourceip": new_incident.get("_source", {}).get("source", {}).get("ip", ""),
                "sourceport": new_incident.get("_source", {}).get("source", {}).get("port", ""),
                "sourcemacaddress": new_incident.get("_source", {}).get("source", {}).get("mac", ""),
                "destinationip": new_incident.get("_source", {}).get("destination", {}).get("ip", ""),
                "destinationport": new_incident.get("_source", {}).get("destination", {}).get("port", ""),
                "destinationmacaddress": new_incident.get("_source", {}).get("destination", {}).get("mac", "")
            }
        }

        # XSOAR Severity
        if "severity" in new_incident.get("_source", {}).get("event", {}):
            incident["severity"] = convert_event_severity(new_incident.get("_source", {}).get("event", {}).get("severity", ""))

        else:
            incident["severity"] = convert_event_severity(-1)

        incidents.append(incident)

    return incidents


def query_selected_engines_builder(max_fetch: int, engine_selection: list, from_to: list) -> dict[str, Any]:
    query: dict[str, Any] = {
        "size": max_fetch,
        "query": {
            "bool": {
                "must": [
                    {"match": {"event.module": str(engine_selection[0])}},
                    {"range": {"@timestamp": {"gt": str(from_to[0]), "lt": str(from_to[1])}}},
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
    }

    return query


def query_empty_selected_engines_builder(from_to: list[str], max_fetch: int) -> dict[str, Any]:
    query: dict[str, Any] = {
        "size": max_fetch,
        "query": {"range": {"@timestamp": {"gt": str(from_to[0]), "lt": str(from_to[1])}}},
        "sort": [{"@timestamp": "asc"}],
    }

    return query


def fetch_selected_engines(
    client: GwClient,
    engine_selection: list[str],
    params: dict[str, Any],
    max_fetch: int,
    fetch_type: str,
) -> list[dict[Any, Any]]:
    from_to: list[str] = last_run_range(params=params)
    query: dict[str, Any] = query_selected_engines_builder(
        max_fetch=max_fetch, engine_selection=engine_selection, from_to=from_to
    )
    gw_alerts: list[list[dict[Any, Any]]] = []
    incidents_a: list[dict[Any, Any]] = []
    gw_metadata: list[dict[Any, Any]] = []
    incidents_m: list[dict[Any, Any]] = []

    if max_fetch > 10000:
        gw_alerts = handle_big_fetch_selected_engines(
            client=client, query=query, engine_selection=engine_selection, max_fetch=max_fetch, fetch_type=fetch_type
        )
        incidents_a = []
        for gw_alert in gw_alerts:
            incidents_a.extend(index_alerts_incidents(to_index=gw_alert, params=params))

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_big_fetch_metadata(client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents_m = index_metadata_incidents(to_index=gw_metadata)

        return incidents_a + incidents_m

    else:
        gw_alerts = handle_little_fetch_alerts(
            client=client, query=query, engine_selection=engine_selection, fetch_type=fetch_type
        )
        if len(gw_alerts) > 0:
            for i in range(0, len(gw_alerts)):
                incidents_a += index_alerts_incidents(to_index=gw_alerts[i], params=params)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_little_fetch_metadata(client=client, query=query, fetch_type=fetch_type)
        if gw_metadata:
            incidents_m = index_metadata_incidents(to_index=gw_metadata)

        return incidents_a + incidents_m


def fetch_empty_selected_engines(client: GwClient, max_fetch: int, fetch_type: str, params: dict[str, Any]):
    from_to: list[str] = last_run_range(params=params)
    query: dict[str, Any] = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
    gw_alerts: list[dict[Any, Any]] | None = []
    gw_metadata: list[dict[Any, Any]] | None = []
    incidents_a: list[dict[Any, Any]] = []
    incidents_m: list[dict[Any, Any]] = []

    if max_fetch > 10000:
        gw_alerts = handle_big_fetch_empty_selected_engines(
            client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type
        )
        incidents_a = index_alerts_incidents(to_index=gw_alerts, params=params)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_big_fetch_metadata(client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents_m = index_metadata_incidents(to_index=gw_metadata)

        return incidents_a + incidents_m

    else:
        gw_alerts = handle_little_fetch_empty_selected_engines(client=client, query=query, fetch_type=fetch_type)
        if len(gw_alerts) > 0:
            incidents_a = index_alerts_incidents(to_index=gw_alerts, params=params)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_little_fetch_metadata(client=client, query=query, fetch_type=fetch_type)
        if gw_metadata:
            incidents_m = index_metadata_incidents(to_index=gw_metadata)

        return incidents_a + incidents_m


def fix_broken_list(params: dict[str, Any]) -> list[str]:
    if "engine_selection" not in params or not isinstance(params.get("engine_selection", "malcore"), str | list):
        raise ValueError("Invalid 'engine_selection' parameter")

    bdl = params.get("engine_selection", "malcore")
    known_engines = {
        "malcore",
        "malcore_retroanalyzer",
        "shellcode_detect",
        "malicious_powershell_detect",
        "sigflow_alert",
        "dga_detect",
        "active_cti",
        "retrohunt",
        "ransomware_detect",
        "beacon_detect",
    }
    e_s = []

    if isinstance(bdl, str):
        e_s = [engine for engine in known_engines if engine in bdl]

    elif isinstance(bdl, list):
        e_s = [engine for engine in known_engines if engine in bdl]

    return e_s


def fetch_incidents(client: GwClient) -> Any:
    params: dict[str, Any] = demisto.params()

    max_fetch: int = int(params.get("max_fetch", "200"))
    if max_fetch < 0:
        max_fetch = 200

    fetch_type: str = params.get("fetch_type", "Alerts")

    engine_selection: list[str] = fix_broken_list(params=params)

    incidents: list[dict[Any, Any]] = []

    if len(engine_selection) > 0:
        incidents = fetch_selected_engines(
            client=client,
            engine_selection=engine_selection,
            params=params,
            max_fetch=max_fetch,
            fetch_type=fetch_type,
        )

    else:
        incidents = fetch_empty_selected_engines(
            client=client, max_fetch=max_fetch, fetch_type=fetch_type, params=params
        )

    if len(incidents) > 0:
        incidents_s = sorted(incidents, key=lambda d: d.get("occurred", ""))
        last_incident = incidents_s[- 1]
        demisto.setLastRun({"start_time": last_incident.get("occurred", "")})

    return demisto.incidents(incidents=incidents)


def main() -> None:
    """Main function, parses params and runs command functions."""

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    ip = params.get("ip")
    token = params.get("token", {}).get("password")
    user = params.get("credentials", {}).get("identifier")
    password = params.get("credentials", {}).get("password")
    check_cert = params.get("check_cert", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = GwClient(ip=ip, check_cert=check_cert, proxy=proxy)
        client.auth(user=user if user != "" else None, password=password if password != "" else None, token=token)
        if command == "test-module":
            return_results(test_module(client=client, user=user, password=password, token=token))
        elif command == "fetch-incidents":
            return_results(fetch_incidents(client=client))
        elif command == "gcenter103-alerts-list":
            return_results(gcenter103_alerts_list_command(client=client, args=args))
        elif command == "gcenter103-alerts-get":
            return_results(gcenter103_alerts_get_command(client=client, args=args))
        elif command == "gcenter103-alerts-note-add":
            return_results(gcenter103_alerts_note_add_command(client=client, args=args))
        elif command == "gcenter103-alerts-note-remove":
            return_results(gcenter103_alerts_note_remove_command(client=client, args=args))
        elif command == "gcenter103-alerts-tags-get":
            return_results(gcenter103_alerts_tags_get_command(client=client, args=args))
        elif command == "gcenter103-alerts-tags-add":
            return_results(gcenter103_alerts_tags_add_command(client=client, args=args))
        elif command == "gcenter103-alerts-tags-remove":
            return_results(gcenter103_alerts_tags_remove_command(client=client, args=args))
        elif command == "gcenter103-alerts-status-update":
            return_results(gcenter103_alerts_status_update_command(client=client, args=args))
        elif command == "gcenter103-raw-alerts-get":
            return_results(gcenter103_raw_alerts_get_command(client=client, args=args))
        elif command == "gcenter103-raw-alerts-file-get":
            return_results(gcenter103_raw_alerts_file_get_command(client=client, args=args))
        elif command == "gcenter103-file-scan":
            return_results(gcenter103_file_scan_command(client=client, args=args))
        elif command == "gcenter103-file-scan-result-get":
            return_results(gcenter103_file_scan_result_get_command(client=client, args=args))
        elif command == "gcenter103-assets-list":
            return_results(gcenter103_assets_list_command(client=client, args=args))
        elif command == "gcenter103-assets-alerts-get":
            return_results(gcenter103_assets_alerts_get_command(client=client, args=args))
        elif command == "gcenter103-assets-get":
            return_results(gcenter103_assets_get_command(client=client, args=args))
        elif command == "gcenter103-assets-note-add":
            return_results(gcenter103_assets_note_add_command(client=client, args=args))
        elif command == "gcenter103-assets-note-remove":
            return_results(gcenter103_assets_note_remove_command(client=client, args=args))
        elif command == "gcenter103-assets-tags-get":
            return_results(gcenter103_assets_tags_get_command(client=client, args=args))
        elif command == "gcenter103-assets-tags-add":
            return_results(gcenter103_assets_tags_add_command(client=client, args=args))
        elif command == "gcenter103-assets-tags-remove":
            return_results(gcenter103_assets_tags_remove_command(client=client, args=args))
        elif command == "gcenter103-users-list":
            return_results(gcenter103_users_list_command(client=client, args=args))
        elif command == "gcenter103-users-alerts-get":
            return_results(gcenter103_users_alerts_get_command(client=client, args=args))
        elif command == "gcenter103-users-get":
            return_results(gcenter103_users_get_command(client=client, args=args))
        elif command == "gcenter103-users-note-add":
            return_results(gcenter103_users_note_add_command(client=client, args=args))
        elif command == "gcenter103-users-note-remove":
            return_results(gcenter103_users_note_remove_command(client=client, args=args))
        elif command == "gcenter103-users-tags-get":
            return_results(gcenter103_users_tags_get_command(client=client, args=args))
        elif command == "gcenter103-users-tags-add":
            return_results(gcenter103_users_tags_add_command(client=client, args=args))
        elif command == "gcenter103-users-tags-remove":
            return_results(gcenter103_users_tags_remove_command(client=client, args=args))
        elif command == "gcenter103-yara-rules-get":
            return_results(gcenter103_yara_rules_get_command(client=client, args=args))
        elif command == "gcenter103-yara-rules-add":
            return_results(gcenter103_yara_rules_add_command(client=client, args=args))
        elif command == "gcenter103-malcore-fingerprints-get":
            return_results(gcenter103_malcore_fingerprints_get_command(client=client, args=args))
        elif command == "gcenter103-malcore-fingerprints-add":
            return_results(gcenter103_malcore_fingerprints_add_command(client=client, args=args))
        elif command == "gcenter103-malcore-fingerprints-remove":
            return_results(gcenter103_malcore_fingerprints_remove_command(client=client, args=args))

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

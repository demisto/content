"""Base Integration for Cortex XSOAR (aka Demisto)"""
from typing import (
    Any,
    Dict
)
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


class GwAPIException(Exception):
    """A base class from which all other exceptions inherit.

    If you want to catch all errors that the gwapi_benedictine package might raise,
    catch this base exception.
    """


class GwRequests():
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
                 proxies: dict = None) -> None:
        """Init.

        Disable urllib3 warning. Allow unsecure ciphers.

        Args:
            ip: IP address of the HTTP server.
            check_cert: True to validate server certificate and False instead.
            proxies: Requests proxies. Default to no proxies.
        """
        self.ip = ip
        self.headers = headers
        self.check_cert = check_cert
        if proxies is not None:
            self.PROXIES = proxies

    def _gen_request_kwargs(self,
                            endpoint: str,
                            data: dict,
                            json_data: dict,
                            params: dict,
                            headers: dict,
                            cookies: dict,
                            redirects: bool,
                            files: dict = None) -> dict:
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
             data: dict = None,
             json_data: dict = None,
             params: dict = None,
             headers: dict = None,
             cookies: dict = None,
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
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects
        )
        return requests.get(**kwargs)

    def _post(self, endpoint: str,
              data: dict = None,
              json_data: dict = None,
              params: dict = None,
              headers: dict = None,
              cookies: dict = None,
              redirects: bool = True,
              files: dict = None) -> requests.Response:
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
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects,
            files=files
        )
        return requests.post(**kwargs)

    def _put(self, endpoint: str,
             data: dict = None,
             json_data: dict = None,
             params: dict = None,
             headers: dict = None,
             cookies: dict = None,
             redirects: bool = True,
             files: dict = None) -> requests.Response:
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
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects,
            files=files
        )
        return requests.put(**kwargs)

    def _delete(self, endpoint: str,
                data: dict = None,
                json_data: dict = None,
                params: dict = None,
                headers: dict = None,
                cookies: dict = None,
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
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
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
                endpoint="/api/auth/login",
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
            endpoint="/api/status/healthchecks/"
        )
        if response.status_code == 200:
            demisto.info(
                f"Get healthchecks on GCenter {self.ip}: [OK]"
            )
            return True
        else:
            demisto.error(
                f"Get healthchecks on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )
            return False

    def list_alerts(self) -> dict:
        """Get the latest elasticsearch alerts sorted by date
        in descending order (most recent first in the list).

        Returns:
            Alerts lists.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint="/api/raw-alerts/"
        )
        if response.status_code == 200:
            demisto.info(f"List alerts on GCenter {self.ip}: [OK]")
            return response.json()["results"]
        else:
            raise GwAPIException(
                f"List alerts on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_alert(self, uid: str) -> dict:
        """Get an elasticsearch alert by uid.

        Args:
            uid: An alert uuid.

        Returns:
            The alert document.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint=f"/api/raw-alerts/{uid}/"
        )
        if response.status_code == 200:
            demisto.info(f"Get alert {uid} on GCenter {self.ip}: [OK]")
            return response.json()
        else:
            raise GwAPIException(
                f"Get alert {uid} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def add_malcore_list_entry(self, ltype: str, sha256: str,
                               comment: str = None, threat: str = None) -> dict:  # noqa: E501
        """Add malcore whitelist/blacklist entry.

        Args:
            ltype: List type either white or black.
            sha256: Sha256 to be added.

        Returns:
            sha256 added to the whitelist/blacklist.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint=f"/api/malcore/{ltype}-list/",
            json_data={
                "sha256": sha256,
                "comment": comment,
                "threat": threat
            }
        )
        if response.status_code == 201:
            demisto.info(
                f"Add {ltype} list with sha256 {sha256} on"
                f" GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Add {ltype} list with sha256 {sha256} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_malcore_list_entry(self, ltype: str, sha256: str) -> None:
        """Del malcore whitelist/blacklist entry.

        Args:
            ltype: List type either white or black.
            sha256: Sha256 to be deleted.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/malcore/{ltype}-list/{sha256}"
        )
        if response.status_code == 204:
            demisto.info(
                f"Delete {ltype} list with sha256 {sha256} on"
                f" GCenter {self.ip}: [OK]"
            )
        else:
            raise GwAPIException(
                f"Delete {ltype} list with sha256 {sha256} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def add_dga_list_entry(self, ltype: str, domain: str, comment: str = None) -> dict:  # noqa: E501
        """Add malcore whitelist/blacklist entry.

        Args:
            ltype: List type either white or black.
            domain: Domain name to be added.

        Returns:
            Domain added to the whitelist/blacklist.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint=f"/api/dga-detection/{ltype}-list/",
            json_data={
                "domain_name": domain,
                "comment": comment
            }
        )
        if response.status_code == 201:
            demisto.info(
                f"Add {ltype} list with domain {domain} on"
                f" GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Add {ltype} list with domain {domain} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_dga_list_entry(self, ltype: str, domain: str) -> None:
        """Del malcore whitelist/blacklist entry.

        Args:
            ltype: List type either white or black.
            domain: Domain name to be deleted.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/dga-detection/{ltype}-list/{domain}"
        )
        if response.status_code == 204:
            demisto.info(
                f"Delete {ltype} list with domain {domain} on"
                f" GCenter {self.ip}: [OK]"
            )
        else:
            raise GwAPIException(
                f"Delete {ltype} list with domain {domain} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_es_query(self, index: str, query: str) -> list:
        """Get results of an elasticsearch query.

        Args:
            index: Index name between suricata, codebreaker, malware,
                    netdata, syslog.
            query: Query in a dictionary format.

        Returns:
            The elacticsearch response.

        Raises:
            GwAPIException: If status_code != 200.
            TypeError: If index value doesn't exist.
        """
        index_values = [
            "suricata",
            "codebreaker",
            "malware",
            "netdata",
            "syslog"
        ]
        if index not in index_values:
            raise TypeError(f"Index value must be between: {index_values}")
        response = self._post(
            endpoint=f"/api/data/es/search/?index={index}",
            json_data=json.loads(query)
        )
        if response.status_code == 200:
            demisto.info(
                f"Get elasticsearch results for index {index} on"
                f" GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Get elasticsearch results for index {index} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def ignore_asset_name(self, name: str, start: bool = True, end: bool = True) -> dict:  # noqa: E501
        """Ignore asset name.

        Args:
            name: Asset name.
            start: Will be ignored if they start with this name.
            end: Will be ignored if they end with this name.

        Returns:
            Asset ignored.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint="/api/ignore-lists/asset-names/",
            json_data={
                "name": name,
                "is_startswith_pattern": start,
                "is_endswith_pattern": end
            }
        )
        if response.status_code == 201:
            demisto.info(f"Ignore asset {name} on GCenter {self.ip}: [OK]")
            return response.json()
        else:
            raise GwAPIException(
                f"Ignore asset {name} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def ignore_mac_address(self, mac: str, start: bool = True) -> dict:
        """Ignore mac address.

        Args:
            mac: Mac address name.
            start: Will be ignored if they start with this name.

        Returns:
            Asset ignored.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint="/api/ignore-lists/mac-addresses/",
            json_data={
                "address": mac,
                "is_startswith_pattern": start
            }
        )
        if response.status_code == 201:
            demisto.info(
                f"Ignore mac address {mac} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Ignore mac address {mac} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def ignore_kuser_ip(self, ip: str) -> dict:
        """Ignore Kerberos ip.

        Args:
            ip: Kerberos ip.

        Returns:
            Kerberos ip ignored.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint="/api/ignore-lists/kuser-ips/",
            json_data={
                "ip": ip
            }
        )
        if response.status_code == 201:
            demisto.info(
                f"Ignore kerberos ip {ip} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Ignore kerberos ip {ip} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def ignore_kuser_name(self, name: str, start: bool = True, end: bool = True) -> dict:  # noqa: E501
        """Ignore Kerberos username.

        Args:
            name: Kerberos username.
            start: Will be ignored if they start with this name.
            end: Will be ignored if they end with this name.

        Returns:
            Kerberos ignored.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint="/api/ignore-lists/kuser-names/",
            json_data={
                "name": name,
                "is_startswith_pattern": start,
                "is_endswith_pattern": end
            }
        )
        if response.status_code == 201:
            demisto.info(
                f"Ignore kerberos username {name} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Ignore kerberos username {name} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_ignore_asset_name(self, ignore_id: int) -> None:  # noqa: E501
        """Delete an ignore asset name.

        Args:
            ignore_id: Ignore list identifier.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/ignore-lists/asset-names/{ignore_id}/"
        )
        if response.status_code == 204:
            demisto.info(f"Delete an ignore asset {ignore_id} on GCenter {self.ip}: [OK]")
        else:
            raise GwAPIException(
                f"Delete an ignore asset {ignore_id} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_ignore_mac_address(self, ignore_id: int) -> None:
        """Delete an ignore mac address.

        Args:
            ignore_id: Ignore list identifier.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/ignore-lists/mac-addresses/{ignore_id}/"
        )
        if response.status_code == 204:
            demisto.info(
                f"Delete an ignore mac address {ignore_id} on GCenter {self.ip}: [OK]"
            )
        else:
            raise GwAPIException(
                f"Delete an ignore mac address {ignore_id} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_ignore_kuser_ip(self, ignore_id: int) -> None:
        """Delete an ignore Kerberos ip.

        Args:
            ignore_id: Ignore list identifier.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/ignore-lists/kuser-ips/{ignore_id}/"
        )
        if response.status_code == 204:
            demisto.info(
                f"Delete an ignore kerberos ip {ignore_id} on GCenter {self.ip}: [OK]"
            )
        else:
            raise GwAPIException(
                f"Delete an ignore kerberos ip {ignore_id} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_ignore_kuser_name(self, ignore_id: int) -> None:  # noqa: E501
        """Delete an ignore Kerberos username.

        Args:
            ignore_id: Ignore list identifier.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/ignore-lists/kuser-names/{ignore_id}/"
        )
        if response.status_code == 204:
            demisto.info(
                f"Delete an ignore kerberos username {ignore_id} on GCenter {self.ip}: [OK]"
            )
        else:
            raise GwAPIException(
                f"Delete an ignore kerberos username {ignore_id} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def send_malware(self, filename: str, file_id: str) -> dict:
        """Send file to the GScan malcore analysis.

        Args:
            filename: Filename to be sent.
            file_id: The file entry id.

        Returns:
            Gscan analysis report.

        Raises:
            GwAPIException: If status_code != 201.
        """
        file = demisto.getFilePath(file_id)
        with open(file.get("path"), "rb") as fo:
            response = self._post(
                endpoint="/api/gscan/malcore/",
                files={
                    "file": (
                        filename,
                        fo
                    )
                }
            )
        if response.status_code == 201:
            demisto.info(
                f"Send malcore file {filename} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Send malcore file {filename} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def send_shellcode(self, filename: str, file_id: str, deep: bool = False, timeout: int = None) -> dict:
        """Send file to the GScan shellcode analysis.

        Args:
            filename: Filename to be sent.
            file_id: The file entry id.
            deep: True to enabled deep scan and False instead.
            timeout: Deep scan timeout.

        Returns:
            Gscan analysis report.

        Raises:
            GwAPIException: If status_code != 201.
        """
        file = demisto.getFilePath(file_id)
        with open(file.get("path"), "rb") as fo:
            response = self._post(
                endpoint="/api/gscan/shellcode/",
                files={
                    "file": (
                        filename,
                        fo
                    ),
                    "deep": deep,
                    "timeout": timeout
                }
            )
        if response.status_code == 201:
            demisto.info(
                f"Send shellcode file {filename} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Send shellcode file {filename} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def send_powershell(self, filename: str, file_id: str) -> dict:
        """Send file to the GScan powershell analysis.

        Args:
            filename: Filename to be sent.
            file_id: The file entry id.

        Returns:
            Gscan analysis report.

        Raises:
            GwAPIException: If status_code != 201.
        """
        file = demisto.getFilePath(file_id)
        with open(file.get("path"), "rb") as fo:
            response = self._post(
                endpoint="/api/gscan/powershell/",
                files={
                    "file": (
                        filename,
                        fo
                    )
                }
            )
        if response.status_code == 201:
            demisto.info(
                f"Send powershell file {filename} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Send powershell file {filename} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )


def test_module(client: GwClient) -> str:  # noqa: E501
    """Tests API connectivity and authentication command.

    Args:
        client: Client to interact with the GCenter.

    Returns:
        'Authentication successful' when the GCenter connection works.
        'Authentication error' when the GCenter connection doesn't works.
    """
    if client.is_authenticated():
        return "ok"
    else:
        return "Authentication error, please check ip/user/password/token: [ERROR]"


def gw_list_alerts(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Get the latest elasticsearch alerts sorted by date in
    descending order (most recent first in the list) command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Alert.List" prefix.
    """
    result = client.list_alerts()
    readable_result = tableToMarkdown("Elasticsearch alerts list", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Alert.List",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_get_alert(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Get an elasticsearch alert by uid command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Alert.Single" prefix.
    """
    result = client.get_alert(
        uid=args.get("uid")  # type: ignore
    )
    readable_result = tableToMarkdown("Elasticsearch alert entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Alert.Single",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_add_malcore_list_entry(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Add malcore whitelist/blacklist entry command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Malcore" prefix.
    """
    ltype = args.get("type")
    result = client.add_malcore_list_entry(
        ltype=ltype,  # type: ignore
        sha256=args.get("sha256"),  # type: ignore
        comment=args.get("comment", "added by cortex"),  # type: ignore
        threat=args.get("threat", "unknown")  # type: ignore
    )
    readable_result = tableToMarkdown(f"Malcore {ltype}list entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Malcore",
        outputs_key_field="sha256",
        outputs=result,
        raw_response=result
    )


def gw_del_malcore_list_entry(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Del malcore whitelist/blacklist entry command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Malcore" prefix.
    """
    client.del_malcore_list_entry(
        ltype=args.get("type"),  # type: ignore
        sha256=args.get("sha256")  # type: ignore
    )
    return CommandResults(
        readable_output=None,
        outputs_prefix="GCenter.Malcore",
        outputs_key_field=None,
        outputs=None,
        raw_response=None
    )


def gw_add_dga_list_entry(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Add dga whitelist/blacklist entry command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Dga" prefix.
    """
    ltype = args.get("type")
    result = client.add_dga_list_entry(
        ltype=ltype,  # type: ignore
        domain=args.get("domain"),  # type: ignore
        comment=args.get("comment", "added by cortex")  # type: ignore
    )
    readable_result = tableToMarkdown(f"DGA {ltype}list entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Dga",
        outputs_key_field="domain_name",
        outputs=result,
        raw_response=result
    )


def gw_del_dga_list_entry(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Del dga whitelist/blacklist entry command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Dga" prefix.
    """
    client.del_dga_list_entry(
        ltype=args.get("type"),  # type: ignore
        domain=args.get("domain")  # type: ignore
    )
    return CommandResults(
        readable_output=None,
        outputs_prefix="GCenter.Dga",
        outputs_key_field=None,
        outputs=None,
        raw_response=None
    )


def gw_es_query(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Get results of an elasticsearch query command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Elastic" prefix.
    """
    result = client.get_es_query(
        index=args.get("index"),  # type: ignore
        query=args.get("query")  # type: ignore
    )
    readable_result = tableToMarkdown("Elasticsearch query result", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Elastic",
        outputs_key_field=None,
        outputs=result,
        raw_response=result
    )


def gw_add_ignore_asset_name(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Ignore asset name command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.AssetName" prefix.
    """
    result = client.ignore_asset_name(
        name=args.get("name"),  # type: ignore
        start=args.get("start"),  # type: ignore
        end=args.get("end")  # type: ignore
    )
    readable_result = tableToMarkdown("Asset name entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.AssetName",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_add_ignore_kuser_ip(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Ignore Kerberos ip command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.KuserIP" prefix.
    """
    result = client.ignore_kuser_ip(
        ip=args.get("ip")  # type: ignore
    )
    readable_result = tableToMarkdown("Kuser IP entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.KuserIP",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_add_ignore_kuser_name(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Ignore Kerberos username command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.KuserName" prefix.
    """
    result = client.ignore_kuser_name(
        name=args.get("name"),  # type: ignore
        start=args.get("start"),  # type: ignore
        end=args.get("end")  # type: ignore
    )
    readable_result = tableToMarkdown("Kuser name entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.KuserName",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_add_ignore_mac_address(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Ignore mac address command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore" prefix.
    """
    result = client.ignore_mac_address(
        mac=args.get("mac"),  # type: ignore
        start=args.get("start")  # type: ignore
    )
    readable_result = tableToMarkdown("MAC adrress entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.MacAddress",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_del_ignore_asset_name(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Delete ignore asset name command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.AssetName" prefix.
    """
    result = client.del_ignore_asset_name(
        ignore_id=int(args.get("ignore_id"))  # type: ignore
    )
    readable_result = tableToMarkdown("Asset name entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.AssetName",
        outputs_key_field=None,
        outputs=result,
        raw_response=result
    )


def gw_del_ignore_kuser_ip(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Delete ignore Kerberos ip command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.KuserIP" prefix.
    """
    result = client.del_ignore_kuser_ip(
        ignore_id=int(args.get("ignore_id"))  # type: ignore
    )
    readable_result = tableToMarkdown("Kuser IP entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.KuserIP",
        outputs_key_field=None,
        outputs=result,
        raw_response=result
    )


def gw_del_ignore_kuser_name(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Delete ignore Kerberos username command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.KuserName" prefix.
    """
    result = client.del_ignore_kuser_name(
        ignore_id=int(args.get("ignore_id"))  # type: ignore
    )
    readable_result = tableToMarkdown("Kuser name entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.KuserName",
        outputs_key_field=None,
        outputs=result,
        raw_response=result
    )


def gw_del_ignore_mac_address(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Delete ignore mac address command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.MacAddress" prefix.
    """
    result = client.del_ignore_mac_address(
        ignore_id=int(args.get("ignore_id"))  # type: ignore
    )
    readable_result = tableToMarkdown("MAC address entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.MacAddress",
        outputs_key_field=None,
        outputs=result,
        raw_response=result
    )


def gw_send_malware(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Send file to the GScan malcore analysis.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Gscan.Malware" prefix.
    """
    result = client.send_malware(
        filename=args.get("filename"),  # type: ignore
        file_id=args.get("file_id")  # type: ignore
    )
    readable_result = tableToMarkdown("Malcore analysis result", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Gscan.Malware",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_send_powershell(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Send file to the GScan shellcode analysis command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Gscan.Powershell" prefix.
    """
    result = client.send_powershell(
        filename=args.get("filename"),  # type: ignore
        file_id=args.get("file_id")  # type: ignore
    )
    readable_result = tableToMarkdown("Powershell analysis result", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Gscan.Powershell",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_send_shellcode(client: GwClient, args: Dict[str, Any]) -> CommandResults:  # noqa: E501
    """Send file to the GScan powershell analysis command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Gscan.Shellcode" prefix.
    """
    result = client.send_shellcode(
        filename=args.get("filename"),  # type: ignore
        file_id=args.get("file_id"),  # type: ignore
        deep=args.get("deep"),  # type: ignore
        timeout=int(args.get("timeout"))  # type: ignore
    )
    readable_result = tableToMarkdown("Shellcode analysis result", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Gscan.Shellcode",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def main() -> None:
    """Main function, parses params and runs command functions."""

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    ip = params.get("ip")
    token = params.get("token", None)
    user = params.get("credentials", {}).get("identifier", None)
    password = params.get("credentials", {}).get("password", None)
    check_cert = params.get("check_cert", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = GwClient(ip=ip, check_cert=check_cert)
        client.auth(
            user=user if user != "" else None,
            password=password if password != "" else None,
            token=token
        )
        if command == "test-module":
            return_results(
                test_module(client=client)
            )
        elif command == "gw-list-alerts":
            return_results(
                gw_list_alerts(client=client, args=args)
            )
        elif command == "gw-get-alert":
            return_results(
                gw_get_alert(client=client, args=args)
            )
        elif command == "gw-add-malcore-list-entry":
            return_results(
                gw_add_malcore_list_entry(client=client, args=args)
            )
        elif command == "gw-del-malcore-list-entry":
            return_results(
                gw_del_malcore_list_entry(client=client, args=args)
            )
        elif command == "gw-add-dga-list-entry":
            return_results(
                gw_add_dga_list_entry(client=client, args=args)
            )
        elif command == "gw-del-dga-list-entry":
            return_results(
                gw_del_dga_list_entry(client=client, args=args)
            )
        elif command == "gw-es-query":
            return_results(
                gw_es_query(client=client, args=args)
            )
        elif command == "gw-add-ignore-asset-name":
            return_results(
                gw_add_ignore_asset_name(client=client, args=args)
            )
        elif command == "gw-add-ignore-kuser-ip":
            return_results(
                gw_add_ignore_kuser_ip(client=client, args=args)
            )
        elif command == "gw-add-ignore-kuser-name":
            return_results(
                gw_add_ignore_kuser_name(client=client, args=args)
            )
        elif command == "gw-add-ignore-mac-address":
            return_results(
                gw_add_ignore_mac_address(client=client, args=args)
            )
        elif command == "gw-del-ignore-asset-name":
            return_results(
                gw_del_ignore_asset_name(client=client, args=args)
            )
        elif command == "gw-del-ignore-kuser-ip":
            return_results(
                gw_del_ignore_kuser_ip(client=client, args=args)
            )
        elif command == "gw-del-ignore-kuser-name":
            return_results(
                gw_del_ignore_kuser_name(client=client, args=args)
            )
        elif command == "gw-del-ignore-mac-address":
            return_results(
                gw_del_ignore_mac_address(client=client, args=args)
            )
        elif command == "gw-send-malware":
            return_results(
                gw_send_malware(client=client, args=args)
            )
        elif command == "gw-send-powershell":
            return_results(
                gw_send_powershell(client=client, args=args)
            )
        elif command == "gw-send-shellcode":
            return_results(
                gw_send_shellcode(client=client, args=args)
            )
    except Exception as e:
        return_error(
            f"Failed to execute {command} command.\nError: {str(e)}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

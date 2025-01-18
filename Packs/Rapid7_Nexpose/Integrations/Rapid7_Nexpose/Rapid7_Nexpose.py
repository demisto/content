import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import urllib3
from copy import deepcopy
from enum import Enum, EnumMeta
from time import strptime, struct_time
from typing import overload


VENDOR_NAME = "Rapid7 Nexpose"  # Vendor name to use for indicators.
API_DEFAULT_PAGE_SIZE = 10  # Default page size that's set on the API. Used for calculations.
DEFAULT_PAGE_SIZE = 50  # Default page size to use
MATCH_DEFAULT_VALUE = "any"  # Default "match" value to use when using search filters. Can be either "all" or "any".
REMOVE_RESPONSE_LINKS = True  # Whether to remove `links` keys from responses.
REPORT_DOWNLOAD_WAIT_TIME = 60  # Time in seconds to wait before downloading a report after starting its generation
CONNECTION_ERRORS_RETRIES = 5  # num of times to retry in case of connection-errors
CONNECTION_ERRORS_INTERVAL = 1  # num of seconds between each time to send an http-request in case of a connection error.
VALID_TAG_TYPES = ["custom", "location", "owner"]
VALID_ASSET_GROUP_TYPES = ["dynamic", "static"]
VALID_TAG_COLORS = ["blue", "green", "orange", "red", "purple", "default"]

urllib3.disable_warnings()  # Disable insecure warnings


class ScanStatus(Enum):
    """An Enum of possible scan status values."""
    PAUSE = "pause"
    RESUME = "resume"
    STOP = "stop"


class FlexibleEnum(EnumMeta):
    """A custom EnumMeta to allow flexible conversion from strings to Enum."""

    def __getitem__(cls, item: Any):
        try:
            return super().__getitem__(item)

        except KeyError:
            return super().__getitem__(item.upper().replace(' ', '_').replace('-', '_'))


class CredentialService(Enum, metaclass=FlexibleEnum):
    """An Enum of possible service values for credentials."""
    AS400 = "as400"
    CIFS = "cifs"
    CIFSHASH = "cifshash"
    CVS = "cvs"
    DB2 = "db2"
    FTP = "ftp"
    HTTP = "http"
    MS_SQL = "ms-sql"
    MYSQL = "mysql"
    NOTES = "notes"
    ORACLE = "oracle"
    POP = "pop"
    POSTGRESQL = "postgresql"
    REMOTE_EXEC = "remote-exec"
    SNMP = "snmp"
    SNMPV3 = "snmpv3"
    SSH = "ssh"
    SSH_KEY = "ssh-key"
    SYBASE = "sybase"
    TELNET = "telnet"


class RepeatFrequencyType(Enum, metaclass=FlexibleEnum):
    """An Enum of possible repeat frequency for scheduled scans."""
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    DATE_OF_MONTH = "date-of-month"
    DAY_OF_MONTH = "day-of-month"


class SharedCredentialSiteAssignment(Enum, metaclass=FlexibleEnum):
    """An Enum of possible site assignment values for shared credentials."""
    ALL_SITES = "all-sites"
    SPECIFIC_SITES = "specific-sites"


class SNMPv3AuthenticationType(Enum, metaclass=FlexibleEnum):
    """An Enum of possible authentication type values for shared credentials."""
    NO_AUTHENTICATION = "no-authentication"
    MD5 = "md5"
    SHA = "sha"


class SNMPv3PrivacyType(Enum, metaclass=FlexibleEnum):
    """An Enum of possible privacy type values for SNMPv3P credentials."""
    NO_PRIVACY = "no-privacy"
    DES = "des"
    AES_128 = "aes-128"
    AES_192 = "aes-192"
    AES_192_WITH_3_DES_KEY_EXTENSION = "aes-192-with-3-des-key-extension"
    AES_256 = "aes-256"
    AES_265_WITH_3_DES_KEY_EXTENSION = "aes-265-with-3-des-key-extension"


class SSHElevationType(Enum, metaclass=FlexibleEnum):
    """An Enum of possible permission elevation values for SSH credentials."""
    NONE = "none"
    SUDO = "sudo"
    SUDOSU = "sudosu"
    SU = "su"
    PBRUN = "pbrun"
    PRIVILEGED_EXEC = "privileged-exec"


class VulnerabilityExceptionScopeType(Enum, metaclass=FlexibleEnum):
    """An Enum of possible vulnerability exception scope type values."""
    GLOBAL = "Global"
    SITE = "Site"
    ASSET = "Asset"
    ASSET_GROUP = "Asset Group"


class Client(BaseClient):
    """Client class for interactions with Rapid7 Nexpose API."""

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        token: str | None = None,
        verify: bool = True,
        connection_error_retries: int = CONNECTION_ERRORS_RETRIES
    ):
        """
        Initialize the client.

        Args:
            url (str): Nexpose server base URL.
            username (str): Username to use for authentication.
            password (str): Password to use for authentication.
            token (str | None, optional): 2FA token to use for authentication.
            verify (bool | None, optional): Whether to verify SSL certificates. Defaults to True.
        """
        self.base_url = url
        self._auth_username = username
        self._auth_password = password
        self._auth_token = token
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.connection_error_retries = CONNECTION_ERRORS_RETRIES

        # Add 2FA token to headers if provided
        if token:
            self._headers.update({"Token": token})

        super().__init__(
            base_url=url.rstrip("/") + "/api/3",
            auth=(username, password),
            headers=self._headers,
            ok_codes=(200, 201),
            verify=verify,
        )

    def _http_request(self, **kwargs):  # type: ignore[override]
        """Wrapper for BaseClient._http_request() that optionally removes `links` keys from responses."""
        for _time in range(1, self.connection_error_retries + 1):
            try:
                response = super()._http_request(**kwargs)
                if REMOVE_RESPONSE_LINKS:
                    return remove_dict_key(response, "links")
                return response
            except (DemistoException, requests.ReadTimeout) as error:
                demisto.error(f'Error {error} running _http_request in time {_time}')
                if (
                    isinstance(error, DemistoException) and not isinstance(
                        error.exception, requests.ConnectionError
                    ) or _time == self.connection_error_retries
                ):
                    raise
                else:
                    time.sleep(1)  # pylint: disable=sleep-exists

        return None

    def _generate_session_id(self) -> str:
        """
        Generate a new session ID for internal API requests.

        Note:
            This is used for internal non-documented API requests that are used when using the web interface,
            and have no alternative in the native API.

        Returns:
            str: A session ID.
        """
        internal_api_headers = self._headers.copy()
        internal_api_headers["Content-Type"] = "application/x-www-form-urlencoded"

        return self._http_request(
            method="POST",
            full_url=self.base_url.rstrip("/") + "/data/user/login",
            headers=internal_api_headers,
            data={
                "nexposeccusername": self._auth_username,
                "nexposeccpassword": self._auth_password,
            },
            ok_codes=(200,),
        ).get("sessionID")

    def _paged_http_request(self, page_size: int | None = None, page: int | None = None, sort: str | None = None,
                            limit: int | None = None, **kwargs) -> list:
        """
        Run _http_request with pagination handling.

        Args:
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of items to return. None means to not use a limit.
                Defaults to None.
            **kwargs: Parameters to pass when calling `_http_request`.

        Returns:
            list: A list containing all paginated items.
        """
        if DEFAULT_PAGE_SIZE and not page_size:
            page_size = DEFAULT_PAGE_SIZE

        kwargs["params"] = kwargs.get("params", {})  # If `params` is None, set it to an empty dict

        if page:
            kwargs["params"]["page"] = str(page)

        kwargs["params"].update(find_valid_params(
            page=page,
            size=page_size,
        ))

        # If sort is not None, split it into a list and add to kwargs
        if sort:
            kwargs["params"]["sort"] = sort.split(sep=";")

        response: dict = self._http_request(**kwargs)
        result = response.get("resources", [])

        if not result:
            return []

        if not page:
            total_pages = response.get("page", {}).get("totalPages", 1)
            demisto.debug(f'Total pages = {total_pages}')
            page_count = 0

            # Note: page indexing on Nexpose's API starts at 0
            while (page_count + 1) < total_pages and (limit is None or len(result) < limit):
                page_count += 1
                kwargs["params"]["page"] = str(page_count)
                response = self._http_request(**kwargs)
                resources = response["resources"]
                demisto.debug(f'Received {len(resources)} resources with page {page_count=}, {page_size=}')
                result.extend(resources)

        if limit and limit < len(result):
            return result[:limit]

        return result

    def create_asset(self, site_id: str, date: str, ip_address: str | None = None, hostname: str | None = None,
                     hostname_source: str | None = None) -> dict:
        """
        | Create a new asset on a site.
        |
        | https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createAsset

        Note:
            The API endpoint that's used has additional parameters, and can be also used to update existing assets.
            These options are currently not supported.

        Args:
            site_id (str): ID of the site to create the asset on.
            date (str): The date the data was collected on the asset.
            ip_address (str | None, optional): IP address of the asset to create.
            hostname (str | None, optional): Hostname of the asset to create.
            hostname_source (str | None, optional): Source of the hostname.

        Returns:
            dict: API response with information about the newly generated asset.
        """
        if ip_address is None and hostname is None:
            raise ValueError("At least one of \"ip\" and \"host_name\" arguments must be passed.")

        post_data: dict = {"date": date}

        if ip_address is not None:
            post_data["ip"] = ip_address

        if hostname is not None:
            post_data["hostName"] = {"name": hostname}

            if hostname_source is not None:
                post_data["hostName"]["source"] = hostname_source.lower()

        return self._http_request(
            method="POST",
            url_suffix=f"/sites/{site_id}/assets",
            json_data=post_data,
            resp_type="json",
        )

    def create_report(self, report_id: str) -> dict:
        """
        | Generates a configured report.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/generateReport

        Args:
            report_id (str): ID of the configured report to generate.

        Returns:
            dict: API response with information about the newly created report instance.
        """
        return self._http_request(
            url_suffix=f"/reports/{report_id}/generate",
            method="POST",
            resp_type="json",
        )

    def create_report_config(self, scope: dict[str, Any], template_id: str,
                             report_name: str, report_format: str) -> dict:
        """
        | Create a new report configuration.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createReport

        Args:
            scope (dict[str, Any]): Scope of the report, see Nexpose's documentation for more details.
            template_id (str): ID of report template to use.
            report_name (str): Name for the report that will be generated.
            report_format (str): Format of the report that will be generated.

        Returns:
            dict: API response with information about the newly created report configuration.
        """
        post_data = {
            "scope": scope,
            "template": template_id,
            "name": report_name,
            "format": report_format.lower(),
        }

        return self._http_request(
            url_suffix="/reports",
            method="POST",
            json_data=post_data,
            resp_type="json",
        )

    def create_shared_credential(self, name: str, site_assignment: SharedCredentialSiteAssignment,
                                 service: CredentialService, database_name: str | None = None,
                                 description: str | None = None, domain: str | None = None,
                                 host_restriction: str | None = None, http_realm: str | None = None,
                                 notes_id_password: str | None = None, ntlm_hash: str | None = None,
                                 oracle_enumerate_sids: bool | None = None, oracle_listener_password: str | None = None,
                                 oracle_sid: str | None = None, password: str | None = None,
                                 port_restriction: str | None = None, sites: list[int] | None = None,
                                 snmp_community_name: str | None = None,
                                 snmpv3_authentication_type: SNMPv3AuthenticationType | None = None,
                                 snmpv3_privacy_password: str | None = None,
                                 snmpv3_privacy_type: SNMPv3PrivacyType | None = None, ssh_key_pem: str | None = None,
                                 ssh_permission_elevation: SSHElevationType | None = None,
                                 ssh_permission_elevation_password: str | None = None,
                                 ssh_permission_elevation_username: str | None = None,
                                 ssh_private_key_password: str | None = None,
                                 use_windows_authentication: bool | None = None, username: str | None = None) -> dict:
        """
        | Create a new shared credential.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSharedCredential

        Args:
            name (str): Name of the credential.
            site_assignment (SharedCredentialSiteAssignment): Site assignment configuration for the credential.
            service (CredentialService): Credential service type.
            database_name (str | None, optional): Database name.
            description (str | None, optional): Description for the credential.
            domain (str | None, optional): Domain address.
            host_restriction (str | None, optional): Hostname or IP address to restrict the credentials to.
            http_realm (str | None, optional): HTTP realm.
            notes_id_password (str | None, optional):
                Password for the notes account that will be used for authenticating.
            ntlm_hash (str | None, optional): NTLM password hash.
            oracle_enumerate_sids (bool | None, optional): Whether the scan engine should attempt to enumerate
                SIDs from the environment.
            oracle_listener_password (str | None, optional): The Oracle Net Listener password.
                Used to enumerate SIDs from the environment.
            oracle_sid (str | None, optional): Oracle database name.
            password (str | None, optional): Password for the credential.
            port_restriction (str | None, optional): Further restricts the credential to attempt to authenticate
                on a specific port. Can be used only if `host_restriction` is used.
            sites (list[int] | None, optional): List of site IDs for the shared credential that are explicitly assigned
                access to the shared scan credential, allowing it to use the credential during a scan.
            snmp_community_name (str | None, optional): SNMP community for authentication.
            snmpv3_authentication_type (SNMPv3AuthenticationType): SNMPv3 authentication type for the credential.
            snmpv3_privacy_password (str | None, optional): SNMPv3 privacy password to use.
            snmpv3_privacy_type (SNMPv3PrivacyType, optional): SNMPv3 Privacy protocol to use.
            ssh_key_pem (str | None, optional): PEM formatted private key.
            ssh_permission_elevation (SSHElevationType | None, optional): Elevation type to use for scans.
            ssh_permission_elevation_password (str | None, optional): Password to use for elevation.
            ssh_permission_elevation_username (str | None, optional): Username to use for elevation.
            ssh_private_key_password (str | None, optional): Password for the private key.
            use_windows_authentication (bool | None, optional): Whether to use Windows authentication.
            username (str | None, optional): Username for the credential.

        Returns:
            dict: API response with information about the newly created shared credential.
        """
        account_data = create_credential_creation_body(
            service=service,
            database_name=database_name,
            domain=domain,
            http_realm=http_realm,
            notes_id_password=notes_id_password,
            ntlm_hash=ntlm_hash,
            oracle_enumerate_sids=oracle_enumerate_sids,
            oracle_listener_password=oracle_listener_password,
            oracle_sid=oracle_sid,
            password=password,
            snmp_community_name=snmp_community_name,
            snmpv3_authentication_type=snmpv3_authentication_type,
            snmpv3_privacy_password=snmpv3_privacy_password,
            snmpv3_privacy_type=snmpv3_privacy_type,
            ssh_key_pem=ssh_key_pem,
            ssh_permission_elevation=ssh_permission_elevation,
            ssh_permission_elevation_password=ssh_permission_elevation_password,
            ssh_permission_elevation_username=ssh_permission_elevation_username,
            ssh_private_key_password=ssh_private_key_password,
            use_windows_authentication=use_windows_authentication,
            username=username,
        )

        post_data = find_valid_params(
            description=description,
            hostRestriction=host_restriction,
            name=name,
            siteAssignment=site_assignment.value,
        )

        if port_restriction is not None and host_restriction is not None:
            post_data["portRestriction"] = port_restriction

        if sites is not None and site_assignment == SharedCredentialSiteAssignment.SPECIFIC_SITES:
            post_data["sites"] = sites

        post_data["account"] = account_data

        return self._http_request(
            method="POST",
            url_suffix="/shared_credentials",
            json_data=post_data,
            resp_type="json",
        )

    def create_site(self, name: str, description: str | None = None, assets: list[str] | None = None,
                    site_importance: str | None = None, template_id: str | None = None) -> dict:
        """
        | Create a new site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSite

        Args:
            name (str): Name of the site. Must be unique.
            description (str | None, optional): Description of the site. Defaults to None.
            assets (list[str] | None, optional): List of asset IDs to be included in site scans. Defaults to None.
            site_importance (str | None, optional): Importance of the site.
                Defaults to None (results in using API's default - "normal").
            template_id (str | None, optional): The identifier of a scan template.
                Defaults to None (results in using default scan template).

        Returns:
            dict: API response with information about the newly created site.
        """
        post_data = find_valid_params(
            name=name,
            description=description,
            importance=site_importance.lower() if site_importance else None,
            scanTemplateId=template_id,
        )

        if assets:
            post_data["scan"] = {
                "assets": {
                    "includedTargets": {
                        "addresses": assets
                    }}}

        return self._http_request(
            url_suffix="/sites",
            method="POST",
            json_data=post_data,
            resp_type="json",
        )

    def create_site_scan_credential(self, site_id: str, name: str, service: CredentialService,
                                    database_name: str | None = None, description: str | None = None,
                                    domain: str | None = None, host_restriction: str | None = None,
                                    http_realm: str | None = None, notes_id_password: str | None = None,
                                    ntlm_hash: str | None = None, oracle_enumerate_sids: bool | None = None,
                                    oracle_listener_password: str | None = None, oracle_sid: str | None = None,
                                    password: str | None = None, port_restriction: str | None = None,
                                    snmp_community_name: str | None = None,
                                    snmpv3_authentication_type: SNMPv3AuthenticationType | None = None,
                                    snmpv3_privacy_password: str | None = None,
                                    snmpv3_privacy_type: SNMPv3PrivacyType | None = None,
                                    ssh_key_pem: str | None = None,
                                    ssh_permission_elevation: SSHElevationType | None = None,
                                    ssh_permission_elevation_password: str | None = None,
                                    ssh_permission_elevation_username: str | None = None,
                                    ssh_private_key_password: str | None = None,
                                    use_windows_authentication: bool | None = None,
                                    username: str | None = None) -> dict:
        """
        | Create a new site scan credential.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSiteCredential

        Args:
            name (str): Name of the credential.
                Assign the shared scan credential either to be available to all sites, or a specific list of sites.
            site_id (str): ID of the site to create the credential for.
            service (CredentialService): Credential service type.
            database_name (str | None, optional): Database name.
            description (str | None, optional): Description for the credential.
            domain (str | None, optional): Domain address.
            host_restriction (str | None, optional): Hostname or IP address to restrict the credentials to.
            http_realm (str | None, optional): HTTP realm.
            notes_id_password (str | None, optional):
                Password for the notes account that will be used for authenticating.
            ntlm_hash (str | None, optional): NTLM password hash.
            oracle_enumerate_sids (bool | None, optional): Whether the scan engine should attempt to enumerate
                SIDs from the environment.
            oracle_listener_password (str | None, optional): The Oracle Net Listener password.
                Used to enumerate SIDs from the environment.
            oracle_sid (str | None, optional): Oracle database name.
            password (str | None, optional): Password for the credential.
            port_restriction (str | None, optional): Further restricts the credential to attempt to authenticate
                on a specific port. Can be used only if `host_restriction` is used.
            snmp_community_name (str | None, optional): SNMP community for authentication.
            snmpv3_authentication_type (SNMPv3AuthenticationType): SNMPv3 authentication type for the credential.
            snmpv3_privacy_password (str | None, optional): SNMPv3 privacy password to use.
            snmpv3_privacy_type (SNMPv3PrivacyType, optional): SNMPv3 Privacy protocol to use.
            ssh_key_pem (str | None, optional): PEM formatted private key.
            ssh_permission_elevation (SSHElevationType | None, optional): Elevation type to use for scans.
            ssh_permission_elevation_password (str | None, optional): Password to use for elevation.
            ssh_permission_elevation_username (str | None, optional): Username to use for elevation.
            ssh_private_key_password (str | None, optional): Password for the private key.
            use_windows_authentication (bool | None, optional): Whether to use Windows authentication.
            username (str | None, optional): Username for the credential.

        Returns:
            dict: API response with information about the newly created shared credential.
        """
        account_data = create_credential_creation_body(
            service=service,
            database_name=database_name,
            domain=domain,
            http_realm=http_realm,
            notes_id_password=notes_id_password,
            ntlm_hash=ntlm_hash,
            oracle_enumerate_sids=oracle_enumerate_sids,
            oracle_listener_password=oracle_listener_password,
            oracle_sid=oracle_sid,
            password=password,
            snmp_community_name=snmp_community_name,
            snmpv3_authentication_type=snmpv3_authentication_type,
            snmpv3_privacy_password=snmpv3_privacy_password,
            snmpv3_privacy_type=snmpv3_privacy_type,
            ssh_key_pem=ssh_key_pem,
            ssh_permission_elevation=ssh_permission_elevation,
            ssh_permission_elevation_password=ssh_permission_elevation_password,
            ssh_permission_elevation_username=ssh_permission_elevation_username,
            ssh_private_key_password=ssh_private_key_password,
            use_windows_authentication=use_windows_authentication,
            username=username,
        )

        post_data = find_valid_params(
            description=description,
            hostRestriction=host_restriction,
            name=name,
        )

        if port_restriction is not None and host_restriction is not None:
            post_data["portRestriction"] = port_restriction

        post_data["account"] = account_data

        return self._http_request(
            method="POST",
            url_suffix=f"/sites/{site_id}/site_credentials",
            json_data=post_data,
            resp_type="json",
        )

    def create_site_scan_schedule(self, site_id: str, start_date: str, enabled: bool,
                                  excluded_asset_groups: list[int] | None = None,
                                  excluded_targets: list[str] | None = None,
                                  included_asset_groups: list[int] | None = None,
                                  included_targets: list[str] | None = None, duration: str | None = None,
                                  repeat_behaviour: str | None = None,
                                  frequency: RepeatFrequencyType | None = None,
                                  interval: int | None = None, date_of_month: int | None = None,
                                  scan_name: str | None = None, scan_template_id: str | None = None) -> dict:
        """
        | Create a new site scan schedule.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSiteScanSchedule

        Args:
            site_id (str): ID of the site to create a new scheduled scan for.
            start_date (str): The scheduled start date and time formatted in ISO 8601 format.
            enabled (bool): A flag indicating whether the scan schedule is enabled.
            excluded_asset_groups (list[int] | None, optional): Asset groups to exclude from the scan.
            excluded_targets (list[str] | None, optional): Addresses to exclude from the scan.
                Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range,
                ipv6 address, or CIDR notation.
            included_asset_groups (list[int] | None, optional): Asset groups to include in the scan.
            included_targets (list[str] | None, optional): Addresses to include in the scan.
                Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range,
                ipv6 address, or CIDR notation.
            duration (str | None, optional): An ISO 8601 formatted duration string that Specifies the maximum duration
                the scheduled scan is allowed to run.
            repeat_behaviour (str | None, optional): The desired behavior of a repeating scheduled scan
                when the previous scan was paused due to reaching its maximum duration.
            frequency (RepeatFrequencyType | None, optional): Frequency for the schedule to repeat.
                Required if using other repeat settings.
            interval (int | None, optional): The interval time the schedule should repeat.
                Required if using other repeat settings.
            date_of_month(int | None, optional): Specifies the schedule repeat day of the interval month.
                Required and used only if frequency is set to "DATE_OF_MONTH".
            scan_name (str | None, optional): A unique user-defined name for the scan launched by the schedule.
                If not explicitly set in the schedule, the scan name will be generated prior to the scan launching.
            scan_template_id (str | None, optional): ID of the scan template to use.

        Returns:
            dict: API response with information about the newly created scan schedule.
        """
        assets: dict = {}
        repeat: dict = {}

        if excluded_asset_groups:
            assets["excludedAssetGroups"] = {"assetGroupIDs": excluded_asset_groups}

        if excluded_targets:
            assets["excludedTargets"] = {"addresses": excluded_targets}

        if included_asset_groups:
            assets["includedAssetGroups"] = {"assetGroupIDs": included_asset_groups}

        if included_targets:
            assets["includedTargets"] = {"addresses": included_targets}

        if frequency is not None:
            if interval is None:
                raise ValueError("'interval' parameter must be set when frequency is used.")

            if frequency == RepeatFrequencyType.DATE_OF_MONTH and date_of_month is None:
                raise ValueError("'date-of-month' parameter must be set if frequency is set to 'Date of month'.")

            repeat["every"] = frequency.value

        repeat.update(find_valid_params(
            interval=interval,
            dateOfMonth=date_of_month,
        ))

        post_data = find_valid_params(
            duration=duration,
            enabled=enabled,
            onScanRepeat=repeat_behaviour.lower() if repeat_behaviour is not None else None,
            scanName=scan_name,
            scanTemplateId=scan_template_id,
            start=start_date,
        )

        post_data.update(find_valid_params(
            strict_mode=True,
            assets=assets,
            repeat=repeat,
        ))

        return self._http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules",
            method="POST",
            json_data=post_data,
            resp_type="json",
        )

    def create_vulnerability_exception(self, vulnerability_id: str, scope_type: VulnerabilityExceptionScopeType,
                                       state: str, reason: str, scope_id: int | None = None,
                                       expires: str | None = None, comment: str | None = None) -> dict:
        """
        | Create a new vulnerability exception.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createVulnerabilityException

        Args:
            vulnerability_id (str): ID of the vulnerability to create an exception for.
            scope_type (VulnerabilityExceptionScopeType): The type of the exception scope.
            state (str): The state of the vulnerability exception.
            reason (str): The reason the vulnerability exception was submitted.
                Can be one of: "False Positive", "Compensating Control", "Acceptable Use",
                "Acceptable Risk", and "Other".
            scope_id (int): ID of the chosen `scope_type` (site ID, asset ID, etc.).
                Required if `scope_type` is anything other than `Global`
            expires (str | None, optional): The date and time the vulnerability exception is set to expire.
            comment (str | None, optional): A comment from the submitter as to why the exception was submitted.

        Returns:
            dict: API response with information about the newly created vulnerability exception.
        """
        scope_obj = {
            "id": scope_id,
            "type": scope_type.value,
            "vulnerability": vulnerability_id,
        }

        submit_obj = find_valid_params(
            reason=reason,
            comment=comment,
        )

        post_data = find_valid_params(
            expires=expires,
            scope=scope_obj,
            state=state,
            submit=submit_obj,
        )

        return self._http_request(
            url_suffix="/vulnerability_exceptions",
            method="POST",
            json_data=post_data,
            resp_type="json",
        )

    def delete_asset(self, asset_id: str) -> dict:
        """
        | Delete an asset.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/deleteAsset

        Args:
            asset_id (str): ID of the asset to delete.

        Returns:
            dict: API response.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=f"/assets/{asset_id}",
            resp_type="json",
        )

    def delete_scan_schedule(self, site_id: str, scheduled_scan_id: str) -> dict:
        """
        | Delete a scheduled scan.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/deleteSiteScanSchedule

        Args:
            site_id (str): ID of the site to delete the scheduled scan from.
            scheduled_scan_id (str): ID of the scheduled scan to delete.

        Returns:
            dict: API response.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules/{scheduled_scan_id}",
            method="DELETE",
            resp_type="json",
        )

    def delete_site(self, site_id: str) -> dict:
        """
        | Delete a site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/deleteSite

        Args:
            site_id (str): ID of the site to delete.

        Returns:
            dict: API response with information about the deleted site.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}",
            method="DELETE",
            resp_type="json",
        )

    def delete_shared_credential(self, shared_credential_id: str) -> dict:
        """
        | Delete a shared credential.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/deleteSharedCredential

        Args:
            shared_credential_id (str): ID of the shared credential to delete.

        Returns:
            dict: API response with information about the deleted shared credential.
        """
        return self._http_request(
            url_suffix=f"/shared_credentials/{shared_credential_id}",
            method="DELETE",
            resp_type="json",
        )

    def delete_site_scan_credential(self, site_id: str, site_credential_id: str) -> dict:
        """
        | Delete a site scan credential.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/deleteSiteCredential

        Args:
            site_id (str): ID of the site to delete the scan credential from.
            site_credential_id (str): ID of the scan credential to delete.

        Returns:
            dict: API response with information about the deleted site scan credential.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/site_credentials/{site_credential_id}",
            method="DELETE",
            resp_type="json",
        )

    def delete_vulnerability_exception(self, vulnerability_exception_id: str) -> dict:
        """
        | Delete a vulnerability exception.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/removeVulnerabilityException

        Args:
            vulnerability_exception_id (str): ID of the vulnerability exception to delete.

        Returns:
            dict: API response with information about the deleted vulnerability exception.
        """

        return self._http_request(
            url_suffix=f"/vulnerability_exceptions/{vulnerability_exception_id}",
            method="DELETE",
            resp_type="json",
        )

    def download_report(self, report_id: str, instance_id: str) -> bytes:
        """
        | Download a report.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/downloadReport

        Args:
            report_id (str): ID of the report to download.
            instance_id (str): ID of the report instance.

        Returns:
            bytes: Report file in bytes.
        """
        return self._http_request(
            url_suffix=f"/reports/{report_id}/history/{instance_id}/output",
            method="GET",
            resp_type="content",
        )

    def get_asset_vulnerability(self, asset_id: str, vulnerability_id: str) -> dict:
        """
        | Retrieve information about vulnerability findings on an asset.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssetVulnerability

        Args:
            asset_id (str): ID of the asset to retrieve information about.
            vulnerability_id (str): ID of the vulnerability to look for.

        Returns:
            dict: API response with information about vulnerability findings on the asset.
        """
        return self._http_request(
            url_suffix=f"/assets/{asset_id}/vulnerabilities/{vulnerability_id}",
            method="GET",
            resp_type="json",
        )

    def get_asset_vulnerabilities(self, asset_id: str, page_size: int | None = DEFAULT_PAGE_SIZE,
                                  page: int | None = None, sort: str | None = None,
                                  limit: int | None = None) -> list[dict]:
        """
        | Retrieves a list of all vulnerability findings on an asset.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssetVulnerabilities

        Args:
            asset_id (str): ID of the site to retrieve linked assets from.
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of assets to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list with all vulnerability findings on an asset.
        """
        return self._paged_http_request(
            url_suffix=f"/assets/{asset_id}/vulnerabilities",
            method="GET",
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_asset(self, asset_id: str) -> dict:
        """
        | Retrieve information about a specific asset.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAsset

        Args:
            asset_id (str): ID of the asset to retrieve information about.

        Returns:
            dict: API response with information about a specific asset.
        """
        return self._http_request(
            url_suffix=f"/assets/{asset_id}",
            method="GET",
            resp_type="json",
        )

    def get_asset_tags(self, asset_id: str) -> dict:
        """
        | Retrieve tags about a specific asset.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssetTags

        Args:
            asset_id (str): ID of the asset to retrieve information about.

        Returns:
            dict: API response with list of tags about a specific asset.
        """
        return self._http_request(
            url_suffix=f"/assets/{asset_id}/tags",
            method="GET",
            resp_type="json",
        )

    def get_asset_vulnerability_solution(self, asset_id: str, vulnerability_id: str) -> dict:
        """
        | Retrieve information about solutions that can be used to remediate a vulnerability on an asset.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssetVulnerabilitySolutions

        Args:
            asset_id (str): ID of the asset to retrieve solutions for.
            vulnerability_id (str): ID of the vulnerability to retrieve solutions for.

        Returns:
            dict: API response with information about solutions that can be used to remediate
                a vulnerability on an asset.
        """
        return self._http_request(
            url_suffix=f"/assets/{asset_id}/vulnerabilities/{vulnerability_id}/solution",
            method="GET",
            resp_type="json",
        )

    def get_assets(self, page_size: int | None = DEFAULT_PAGE_SIZE, page: int | None = None, sort: str | None = None,
                   limit: int | None = None) -> list[dict]:
        """
        | Retrieve a list of all assets.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssets

        Args:
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of assets to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list of all assets (up to a limit, if set).
        """
        return self._paged_http_request(
            url_suffix="/assets",
            method="GET",
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_assigned_shared_credentials(self, site_id: str) -> dict:
        """
        | Retrieve information about all credentials that are shared with a specific site.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteSharedCredentials

        Args:
            site_id (str): ID of the site to retrieve credentials that are shared with.

        Returns:
            dict: API response with information shared credentials that are shared with a specific site.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/shared_credentials",
            method="GET",
            resp_type="json",
        ).get("resources")

    def get_report_history(self, report_id: str, instance_id: str) -> dict:
        """
        | Retrieve information about a generated report.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getReportInstance

        Args:
            report_id (str): ID of the report to retrieve information about.
            instance_id (str): ID of the report instance to retrieve information about.

        Returns:
            dict: API response with information about the generated report.
        """
        return self._http_request(
            url_suffix=f"/reports/{report_id}/history/{instance_id}",
            method="GET",
            resp_type="json",
        )

    def get_report_templates(self) -> dict:
        """
        | Retrieve a list of all available report templates.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getReportTemplates

        Returns:
            dict: API response with information about all available report templates.
        """
        return self._http_request(
            url_suffix="/report_templates",
            method="GET",
            resp_type="json",
        )

    def get_scan(self, scan_id: str) -> dict:
        """
        | Retrieve information about a specific scan.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getScan

        Args:
            scan_id (str): ID of the scan to retrieve.

        Returns:
            dict: API response with information about a specific scan.
        """
        return self._http_request(
            url_suffix=f"/scans/{scan_id}",
            method="GET",
            resp_type="json",
        )

    def get_scans(self, active: bool | None = False, page_size: int | None = DEFAULT_PAGE_SIZE, page: int | None = None,
                  sort: str | None = None, limit: int | None = None) -> list[dict]:
        """
        | Retrieve a list of all scans.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getScans

        Args:
            active (bool | None, optional): Whether to return active scans or not. Defaults to False.
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list of all scans (up to a limit, if set).
        """
        params = {"active": active} if active is not None else {}

        return self._paged_http_request(
            url_suffix="/scans",
            method="GET",
            params=params,
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_scan_schedule(self, site_id: str, schedule_id: str) -> dict:
        """
        | Retrieve information about a specific scan schedule.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteScanSchedule

        Args:
            site_id (str): ID of the site to retrieve scan schedule from.
            schedule_id (str): ID of the scan schedule to retrieve.

        Returns:
            dict: A dictionary containing information about the scan schedule.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules/{schedule_id}",
            method="GET",
            resp_type="json",
        )

    def get_scan_schedules(self, site_id: str) -> list[dict]:
        """
        | Retrieve information about scan schedules for a specific site.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteScanSchedules

        Args:
            site_id (str): ID of the site to retrieve scan schedules from.

        Returns:
            list[dict]: A list of scan schedules for the site.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules",
            method="GET",
            resp_type="json",
        ).get("resources")

    def get_shared_credential(self, credential_id: str) -> dict:
        """
        | Retrieve information about a specific shared credential.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSharedCredential

        Args:
            credential_id (str): ID of the shared credential to retrieve information about.

        Returns:
            dict: API response with information about a specific shared credential.
        """
        return self._http_request(
            url_suffix=f"/shared_credentials/{credential_id}",
            method="GET",
            resp_type="json",
        )

    def get_shared_credentials(self) -> list[dict]:
        """
        | Retrieve information about all shared credentials.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSharedCredentials

        Returns:
            list[dict]: A list with all shared credentials.
        """
        return self._http_request(
            url_suffix="/shared_credentials",
            method="GET",
            resp_type="json",
        ).get("resources")

    def get_site_assets(self, site_id: str, page_size: int | None = DEFAULT_PAGE_SIZE, page: int | None = None,
                        sort: str | None = None, limit: int | None = None) -> list[dict]:
        """
        | Retrieve a list of all assets that are linked with a specific site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteAssets

        Args:
            site_id (str): ID of the site to retrieve linked assets from.
            page_size (int | None, optional): Number of assets to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of sites to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list with all assets that are linked with a specific site (up to a limit, if set).
        """
        return self._paged_http_request(
            url_suffix=f"/sites/{site_id}/assets",
            method="GET",
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_site_scan_credential(self, site_id: str, credential_id: str) -> dict:
        """
        | Retrieve information about a specific site scan credential.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteCredential

        Args:
            site_id (str): ID of the site to retrieve scan credentials from.
            credential_id (str): ID of the scan credential to retrieve.

        Returns:
            dict: API response with information about a specific site scan credential.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/site_credentials/{credential_id}",
            method="GET",
            resp_type="json",
        )

    def get_site_scan_credentials(self, site_id: str) -> list[dict]:
        """
        | Retrieve information about a specific site scan credential.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteCredentials

        Args:
            site_id (str): ID of the site to retrieve scan credentials from.

        Returns:
            list[dict]: A list with information about all site scan credentials.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/site_credentials",
            method="GET",
            resp_type="json",
        ).get("resources")

    def get_site_scans(self, site_id: str, page_size: int | None = DEFAULT_PAGE_SIZE, page: int | None = None,
                       sort: str | None = None, limit: int | None = None) -> list[dict]:
        """
        | Retrieve a list of scans from a specific site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteScans

        Args:
            site_id (str): ID of the site to retrieve scans from.
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: API response with information about all scans from the specific site.
        """
        return self._paged_http_request(
            url_suffix=f"/sites/{site_id}/scans",
            method="GET",
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_sites(self, page_size: int | None = DEFAULT_PAGE_SIZE, page: int | None = None, sort: str | None = None,
                  limit: int | None = None) -> list[dict]:
        """
        | Retrieve a list of sites.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSites

        Args:
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of sites to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list of sites (up to a limit, if set).
        """
        return self._paged_http_request(
            url_suffix="/sites",
            method="GET",
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_vulnerabilities(self, page_size: int | None = DEFAULT_PAGE_SIZE, page: int | None = None,
                            sort: str | None = None, limit: int | None = None) -> list[dict]:
        """
        | Retrieve information about all existing vulnerabilities.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerabilities

        Args:
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of sites to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list of sites (up to a limit, if set).
        """
        return self._paged_http_request(
            url_suffix="/vulnerabilities",
            method="GET",
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_vulnerability(self, vulnerability_id: str) -> dict:
        """
        | Retrieve information about a specific vulnerability.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerability

        Args:
            vulnerability_id (str): ID of the vulnerability to retrieve information about.

        Returns:
            dict: API response with information about a specific vulnerability.
        """
        return self._http_request(
            url_suffix=f"/vulnerabilities/{vulnerability_id}",
            method="GET",
            resp_type="json",
        )

    def get_vulnerability_exception(self, vulnerability_exception_id: str) -> dict:
        """
        | Retrieve information about an exception made on a vulnerability.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerabilityException

        Args:
            vulnerability_exception_id (str): ID of the vulnerability exception to retrieve information about.

        Returns:
            dict: API response with information about a specific exception made on a vulnerability.
        """
        return self._http_request(
            url_suffix=f"/vulnerability_exceptions/{vulnerability_exception_id}",
            method="GET",
            resp_type="json",
        )

    def get_vulnerability_exceptions(self, page_size: int | None = DEFAULT_PAGE_SIZE, page: int | None = None,
                                     sort: str | None = None, limit: int | None = None) -> list[dict]:
        """
        | Retrieve exceptions defined on vulnerabilities.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerabilityExceptions

        Args:
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of sites to return. None means to not use a limit.
        """
        return self._paged_http_request(
            url_suffix="/vulnerability_exceptions",
            method="GET",
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def search_assets(self, filters: list[dict] | None = None, match: str = MATCH_DEFAULT_VALUE,
                      page_size: int | None = DEFAULT_PAGE_SIZE, page: int | None = None, sort: str | None = None,
                      limit: int | None = None) -> list[dict]:
        """
        | Retrieve a list of all assets with access permissions that match the provided search filters.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/findAssets

        Args:
            filters (list[dict] | None, optional): List of filters to use for searching assets. Defaults to None.
            match (str): Determine if the filters should match all or any of the filters.
                Can be either "all" or "any". Defaults to MATCH_DEFAULT_VALUE.
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of sites to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list of assets (up to a limit, if set) matching the filters.
        """
        post_data = find_valid_params(
            filters=filters,
            match=match,
        )

        return self._paged_http_request(
            url_suffix="/assets/search",
            method="POST",
            json_data=post_data,
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def set_assigned_shared_credential_status(self, site_id: str, shared_credential_id: str, enabled: bool) -> dict:
        """
        | Update the status of a shared credential.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/enableSharedCredentialOnSite

        Args:
            site_id (str): ID of the site to update the shared credential status on.
            shared_credential_id (str): ID of the shared credential to update the status of.
            enabled (bool): A flag indicating whether the shared credential should be enabled or not.

        Returns:
            dict: API response with information about the updated shared credential.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/shared_credentials/{shared_credential_id}/enabled",
            method="PUT",
            data=json.dumps(enabled),  # type: ignore
            resp_type="json",
        )

    def update_scan_schedule(self, site_id: str, scan_schedule_id: int, repeat_behaviour: str, start_date: str,
                             enabled: bool, excluded_asset_groups: list[int] | None = None,
                             excluded_targets: list[str] | None = None, included_asset_groups: list[int] | None = None,
                             included_targets: list[str] | None = None, duration: str | None = None,
                             frequency: RepeatFrequencyType | None = None,
                             interval: int | None = None, date_of_month: int | None = None,
                             scan_name: str | None = None, scan_template_id: str | None = None) -> dict:
        """
        | Update a site scan schedule.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/updateSiteScanSchedule

        Args:
            site_id (str): ID of the site to create a new scheduled scan for.
            scan_schedule_id (int): ID of the scan schedule to update.
            repeat_behaviour (str | None, optional): The desired behavior of a repeating scheduled scan
                when the previous scan was paused due to reaching its maximum duration.
            start_date (str): The scheduled start date and time formatted in ISO 8601 format.
            enabled (bool): A flag indicating whether the scan schedule is enabled.
            excluded_asset_groups (list[int] | None, optional): Asset groups to exclude from the scan.
            excluded_targets (list[str] | None, optional): Addresses to exclude from the scan.
                Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range,
                ipv6 address, or CIDR notation.
            included_asset_groups (list[int] | None, optional): Asset groups to include in the scan.
            included_targets (list[str] | None, optional): Addresses to include in the scan.
                Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range,
                ipv6 address, or CIDR notation.
            duration (str | None, optional): An ISO 8601 formatted duration string that Specifies the maximum duration
                the scheduled scan is allowed to run.
            frequency (RepeatFrequencyType | None, optional): Frequency for the schedule to repeat.
                Required if using other repeat settings.
            interval (int | None, optional): The interval time the schedule should repeat.
                Required if using other repeat settings.
            date_of_month(int | None, optional): Specifies the schedule repeat day of the interval month.
                Required and used only if frequency is set to `DATE_OF_MONTH`.
            scan_name (str | None, optional): A unique user-defined name for the scan launched by the schedule.
                If not explicitly set in the schedule, the scan name will be generated prior to the scan launching.
            scan_template_id (str | None, optional): ID of the scan template to use.

        Returns:
            str: ID of the newly created scan schedule.
        """
        assets: dict = {}
        repeat: dict = {}

        if excluded_asset_groups:
            assets["excludedAssetGroups"] = {"assetGroupIDs": excluded_asset_groups}

        if excluded_targets:
            assets["excludedTargets"] = {"addresses": excluded_targets}

        if included_asset_groups:
            assets["includedAssetGroups"] = {"assetGroupIDs": included_asset_groups}

        if included_targets:
            assets["includedTargets"] = {"addresses": included_targets}

        if frequency is not None:
            if interval is None:
                raise ValueError("'interval' parameter must be set when frequency is used.")

            if frequency == RepeatFrequencyType.DATE_OF_MONTH and date_of_month is None:
                raise ValueError("'date-of-month' parameter must be set if frequency is set to 'Date of month'.")

            repeat["every"] = frequency.value

        repeat.update(find_valid_params(
            interval=interval,
            dateOfMonth=date_of_month,
        ))

        post_data = find_valid_params(
            duration=duration,
            enabled=enabled,
            onScanRepeat=repeat_behaviour.lower(),
            scanName=scan_name,
            scanTemplateId=scan_template_id,
            start=start_date,
        )

        post_data.update(find_valid_params(
            strict_mode=True,
            assets=assets,
            repeat=repeat,
        ))

        return self._http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules/{scan_schedule_id}",
            method="PUT",
            json_data=post_data,
            resp_type="json",
        )

    def start_site_scan(self, site_id: str, scan_name: str, hosts: list[str]) -> dict:
        """
        | Start a scan for a specific site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/startScan

        Args:
            site_id (str): ID of the site to start a scan on.
            scan_name (str): Name to set for the new scan.
            hosts (list[str]): Hosts to scan.

        Returns:
            dict: API response with information about the started scan.
        """
        post_data: dict = {
            "name": scan_name,
        }

        if hosts:
            post_data["hosts"] = hosts

        return self._http_request(
            url_suffix=f"/sites/{site_id}/scans",
            method="POST",
            json_data=post_data,
            resp_type="json",
        )

    def update_scan_status(self, scan_id: str, status: ScanStatus) -> dict:
        """
        | Update status for a specific scan.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/setScanStatus

        Args:
            scan_id (str): ID of the scan to update.
            status (ScanStatus): Status to set the scan to.
        """
        return self._http_request(
            url_suffix=f"/scans/{scan_id}/{status.value}",
            method="POST",
            resp_type="json",
        )

    def update_shared_credential(self, shared_credential_id: str, name: str,
                                 site_assignment: SharedCredentialSiteAssignment, service: CredentialService,
                                 database_name: str | None = None, description: str | None = None,
                                 domain: str | None = None, host_restriction: str | None = None,
                                 http_realm: str | None = None, notes_id_password: str | None = None,
                                 ntlm_hash: str | None = None, oracle_enumerate_sids: bool | None = None,
                                 oracle_listener_password: str | None = None, oracle_sid: str | None = None,
                                 password: str | None = None, port_restriction: str | None = None,
                                 sites: list[int] | None = None, snmp_community_name: str | None = None,
                                 snmpv3_authentication_type: SNMPv3AuthenticationType | None = None,
                                 snmpv3_privacy_password: str | None = None,
                                 snmpv3_privacy_type: SNMPv3PrivacyType | None = None, ssh_key_pem: str | None = None,
                                 ssh_permission_elevation: SSHElevationType | None = None,
                                 ssh_permission_elevation_password: str | None = None,
                                 ssh_permission_elevation_username: str | None = None,
                                 ssh_private_key_password: str | None = None,
                                 use_windows_authentication: bool | None = None, username: str | None = None) -> dict:
        """
        | Update an existing new shared credential.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/updateSharedCredential

        Args:
            shared_credential_id (str): ID of the shared credential to update.
            name (str): Name of the credential.
            site_assignment (SharedCredentialSiteAssignment): Site assignment configuration for the credential.
            service (CredentialService): Credential service type.
            database_name (str | None, optional): Database name.
            description (str | None, optional): Description for the credential.
            domain (str | None, optional): Domain address.
            host_restriction (str | None, optional): Hostname or IP address to restrict the credentials to.
            http_realm (str | None, optional): HTTP realm.
            notes_id_password (str | None, optional):
            Password for the notes account that will be used for authenticating.
            ntlm_hash (str | None, optional): NTLM password hash.
            oracle_enumerate_sids (bool | None, optional): Whether the scan engine should attempt to enumerate
                SIDs from the environment.
            oracle_listener_password (str | None, optional): The Oracle Net Listener password.
                Used to enumerate SIDs from the environment.
            oracle_sid (str | None, optional): Oracle database name.
            password (str | None, optional): Password for the credential.
            port_restriction (str | None, optional): Further restricts the credential to attempt to authenticate
                on a specific port. Can be used only if `host_restriction` is used.
            sites (list[int] | None, optional): List of site IDs for the shared credential that are explicitly assigned
                access to the shared scan credential, allowing it to use the credential during a scan.
            snmp_community_name (str | None, optional): SNMP community for authentication.
            snmpv3_authentication_type (SNMPv3AuthenticationType): SNMPv3 authentication type for the credential.
            snmpv3_privacy_password (str | None, optional): SNMPv3 privacy password to use.
            snmpv3_privacy_type (SNMPv3PrivacyType, optional): SNMPv3 Privacy protocol to use.
            ssh_key_pem (str | None, optional): PEM formatted private key.
            ssh_permission_elevation (SSHElevationType | None, optional): Elevation type to use for scans.
            ssh_permission_elevation_password (str | None, optional): Password to use for elevation.
            ssh_permission_elevation_username (str | None, optional): Username to use for elevation.
            ssh_private_key_password (str | None, optional): Password for the private key.
            use_windows_authentication (bool | None, optional): Whether to use Windows authentication.
            username (str | None, optional): Username for the credential.

        Returns:
            dict: API response with information about the newly created shared credential.
        """
        account_data = create_credential_creation_body(
            service=service,
            database_name=database_name,
            domain=domain,
            http_realm=http_realm,
            notes_id_password=notes_id_password,
            ntlm_hash=ntlm_hash,
            oracle_enumerate_sids=oracle_enumerate_sids,
            oracle_listener_password=oracle_listener_password,
            oracle_sid=oracle_sid,
            password=password,
            snmp_community_name=snmp_community_name,
            snmpv3_authentication_type=snmpv3_authentication_type,
            snmpv3_privacy_password=snmpv3_privacy_password,
            snmpv3_privacy_type=snmpv3_privacy_type,
            ssh_key_pem=ssh_key_pem,
            ssh_permission_elevation=ssh_permission_elevation,
            ssh_permission_elevation_password=ssh_permission_elevation_password,
            ssh_permission_elevation_username=ssh_permission_elevation_username,
            ssh_private_key_password=ssh_private_key_password,
            use_windows_authentication=use_windows_authentication,
            username=username,
        )

        post_data = find_valid_params(
            description=description,
            hostRestriction=host_restriction,
            name=name,
            siteAssignment=site_assignment.value,
        )

        if port_restriction is not None and host_restriction is not None:
            post_data["portRestriction"] = port_restriction

        if sites is not None and site_assignment == SharedCredentialSiteAssignment.SPECIFIC_SITES:
            post_data["sites"] = sites

        post_data["account"] = account_data

        return self._http_request(
            method="PUT",
            url_suffix=f"/shared_credentials/{shared_credential_id}",
            json_data=post_data,
            resp_type="json",
        )

    def update_site_scan_credential(self, site_id: str, credential_id: str, name: str, service: CredentialService,
                                    database_name: str | None = None, description: str | None = None,
                                    domain: str | None = None, host_restriction: str | None = None,
                                    http_realm: str | None = None, notes_id_password: str | None = None,
                                    ntlm_hash: str | None = None, oracle_enumerate_sids: bool | None = None,
                                    oracle_listener_password: str | None = None, oracle_sid: str | None = None,
                                    password: str | None = None, port_restriction: str | None = None,
                                    snmp_community_name: str | None = None,
                                    snmpv3_authentication_type: SNMPv3AuthenticationType | None = None,
                                    snmpv3_privacy_password: str | None = None,
                                    snmpv3_privacy_type: SNMPv3PrivacyType | None = None,
                                    ssh_key_pem: str | None = None,
                                    ssh_permission_elevation: SSHElevationType | None = None,
                                    ssh_permission_elevation_password: str | None = None,
                                    ssh_permission_elevation_username: str | None = None,
                                    ssh_private_key_password: str | None = None,
                                    use_windows_authentication: bool | None = None,
                                    username: str | None = None) -> dict:
        """
        | Update an existing site scan credential.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/updateSiteCredential

        Args:
            name (str): Name of the credential.
                Assign the shared scan credential either to be available to all sites, or a specific list of sites.
            site_id (str): ID of the site to create the credential for.
            credential_id (str): ID of the site scan credential to update.
            service (CredentialService): Credential service type.
            database_name (str | None, optional): Database name.
            description (str | None, optional): Description for the credential.
            domain (str | None, optional): Domain address.
            host_restriction (str | None, optional): Hostname or IP address to restrict the credentials to.
            http_realm (str | None, optional): HTTP realm.
            notes_id_password (str | None, optional):
                Password for the notes account that will be used for authenticating.
            ntlm_hash (str | None, optional): NTLM password hash.
            oracle_enumerate_sids (bool | None, optional): Whether the scan engine should attempt to enumerate
                SIDs from the environment.
            oracle_listener_password (str | None, optional): The Oracle Net Listener password.
                Used to enumerate SIDs from the environment.
            oracle_sid (str | None, optional): Oracle database name.
            password (str | None, optional): Password for the credential.
            port_restriction (str | None, optional): Further restricts the credential to attempt to authenticate
                on a specific port. Can be used only if `host_restriction` is used.
            snmp_community_name (str | None, optional): SNMP community for authentication.
            snmpv3_authentication_type (SNMPv3AuthenticationType): SNMPv3 authentication type for the credential.
            snmpv3_privacy_password (str | None, optional): SNMPv3 privacy password to use.
            snmpv3_privacy_type (SNMPv3PrivacyType, optional): SNMPv3 Privacy protocol to use.
            ssh_key_pem (str | None, optional): PEM formatted private key.
            ssh_permission_elevation (SSHElevationType | None, optional): Elevation type to use for scans.
            ssh_permission_elevation_password (str | None, optional): Password to use for elevation.
            ssh_permission_elevation_username (str | None, optional): Username to use for elevation.
            ssh_private_key_password (str | None, optional): Password for the private key.
            use_windows_authentication (bool | None, optional): Whether to use Windows authentication.
            username (str | None, optional): Username for the credential.

        Returns:
            dict: API response with information about the newly created shared credential.
        """
        account_data = create_credential_creation_body(
            service=service,
            database_name=database_name,
            domain=domain,
            http_realm=http_realm,
            notes_id_password=notes_id_password,
            ntlm_hash=ntlm_hash,
            oracle_enumerate_sids=oracle_enumerate_sids,
            oracle_listener_password=oracle_listener_password,
            oracle_sid=oracle_sid,
            password=password,
            snmp_community_name=snmp_community_name,
            snmpv3_authentication_type=snmpv3_authentication_type,
            snmpv3_privacy_password=snmpv3_privacy_password,
            snmpv3_privacy_type=snmpv3_privacy_type,
            ssh_key_pem=ssh_key_pem,
            ssh_permission_elevation=ssh_permission_elevation,
            ssh_permission_elevation_password=ssh_permission_elevation_password,
            ssh_permission_elevation_username=ssh_permission_elevation_username,
            ssh_private_key_password=ssh_private_key_password,
            use_windows_authentication=use_windows_authentication,
            username=username,
        )

        post_data = find_valid_params(
            description=description,
            hostRestriction=host_restriction,
            name=name,
        )

        post_data["id"] = credential_id

        if port_restriction is not None and host_restriction is not None:
            post_data["portRestriction"] = port_restriction

        post_data["account"] = account_data

        return self._http_request(
            method="PUT",
            url_suffix=f"/sites/{site_id}/site_credentials/{credential_id}",
            json_data=post_data,
            resp_type="json",
        )

    def update_vulnerability_exception_status(self, vulnerability_exception_id: str, status: str) -> dict:
        """
        | Update the status of a vulnerability exception.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/updateVulnerabilityExceptionStatus

        Args:
            vulnerability_exception_id (str): ID of the vulnerability exception to update.
            status (str): Status to set the vulnerability exception to.

        Returns:
            dict: API response with information about the updated vulnerability exception.
        """
        return self._http_request(
            url_suffix=f"/vulnerability_exceptions/{vulnerability_exception_id}/{status.lower()}",
            method="POST",
            resp_type="json",
        )

    def update_vulnerability_exception_expiration(self, vulnerability_exception_id: str, expiration_date: str) -> dict:
        """
        | Update the expiration date for a vulnerability exception.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/updateVulnerabilityExceptionExpiration

        Args:
            vulnerability_exception_id (str): ID of the vulnerability exception to update.
            expiration_date (str): The new expiration date for the vulnerability exception.

        Returns:
            dict: API response with information about the updated vulnerability exception.
        """
        return self._http_request(
            url_suffix=f"/vulnerability_exceptions/{vulnerability_exception_id}/expires",
            method="PUT",
            data=json.dumps(expiration_date),
            resp_type="json",
        )

    def find_asset_site(self, asset_id: str) -> Optional["Site"]:
        """
        Find the site of a given asset ID.

        Note:
            This method is from older versions of this pack. It uses an internal API to fetch a list of scans data
            for an asset, and fetches site data for these scans to determine asset's site. This will not work if:
            The asset has no previous scans, or if the asset has been moved to another site since the last scan.

        Args:
            asset_id (str): ID of the asset to find additional data for.

        Returns:
            Site: Site object containing data (ID, name) of the asset's site.
        """
        request_headers = self._headers.copy()
        request_headers.update({"nexposeCCSessionID": self._generate_session_id()})

        try:
            response_data: dict = self._http_request(
                full_url=self.base_url.rstrip("/") + f"/data/assets/{asset_id}/scans",
                method="POST",
                headers=request_headers,
                resp_type="json",
            )

        except Exception:
            return None

        finally:
            self._session.cookies.clear()  # Remove cookies received and saved to session be this request.

        if not response_data.get("records"):
            return None

        record_data = response_data["records"][0]

        if None in (record_data.get("siteID"), record_data.get("siteName")):
            return None

        return Site(
            site_id=str(response_data["records"][0]["siteID"]),
            site_name=str(response_data["records"][0]["siteName"]),
        )

    def find_site_id(self, name: str) -> str | None:
        """
        Find a site ID by its name.

        Returns:
            str | None: Site ID corresponding to the passed name. None if no match was found.
        """
        for site in self.get_sites():
            if site["name"] == name:
                return str(site["id"])

        return None

    def create_tag(self, name: str, type: str, color: str, filters: list[dict] | None = None,
                   match: str | None = MATCH_DEFAULT_VALUE) -> dict:
        """
        | Create a new tag.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createTag

        Args:
            name (str): Name of the tag.
            type (str): Type of the tag.
            color (str): Color of the tag.
            filters (list[dict], optional): Filters to apply to the tag.
            match (str, optional): Match criteria for the filters. Default is MATCH_DEFAULT_VALUE.

        Returns:
            dict: API response.
        """
        json_data: dict[str, str | dict] = {
            "type": type,
            "name": name,
            "color": color
        }
        if filters:
            json_data["searchCriteria"] = find_valid_params(filters=filters, match=match)

        return self._http_request(
            method="POST",
            url_suffix="/tags",
            json_data=json_data,
            resp_type="json",
        )

    def delete_tag(self, id: int) -> dict:
        """
        | Delete a tag by ID.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/deleteTag

        Args:
            id (int): ID of the tag to delete.

        Returns:
            dict: API response.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=f"/tags/{id}",
            resp_type="json"
        )

    def get_tag_by_id(self, id: int) -> dict:
        """
        | Get details of a tag by ID.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getTag

        Args:
            id (int): ID of the tag to retrieve.

        Returns:
            dict: API response.
        """
        return self._http_request(
            url_suffix=f"/tags/{id}",
            method="GET",
            resp_type="json"
        )

    def get_tags_list(self, name: str | None = None, type: str | None = None, page_size: int | None = DEFAULT_PAGE_SIZE,
                      page: int | None = None, limit: int | None = None):
        """
        | Get a list of tags.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getTags

        Args:
            name (str, optional): Filter tags by name.
            type (str, optional): Filter tags by type.
            page_size (int, optional): Number of results per page. Default is DEFAULT_PAGE_SIZE.
            page (int, optional): Page number to retrieve.
            limit (int, optional): Maximum number of results to retrieve.

        Returns:
            dict: API response.
        """
        params = assign_params(name=name, type=type)

        return self._paged_http_request(
            url_suffix="/tags",
            method="GET",
            params=params,
            page_size=page_size,
            page=page,
            limit=limit,
            resp_type="json",
        )

    def update_tag_search_criteria(self, id: int, filters: list[dict] = [], match: str | None = MATCH_DEFAULT_VALUE) -> dict:
        """
        | Update search criteria for a tag by ID.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/updateTagSearchCriteria

        Args:
            id (int): ID of the tag to update.
            filters (list[dict], optional): New filters to apply to the tag.
            match (str, optional): Match criteria for the filters. Default is MATCH_DEFAULT_VALUE.

        Returns:
            dict: API response.
        """
        return self._http_request(
            method="PUT",
            url_suffix=f"/tags/{id}/search_criteria",
            json_data=find_valid_params(filters=filters, match=match),
            resp_type="json",
        )

    def send_http_request(self, method: str, url: str, body: list[Any] | None = None) -> dict:
        """
        | Send a generic HTTP request.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html

        Args:
            method (str): HTTP method (e.g., 'GET', 'POST').
            url (str): URL suffix for the request.
            body (list[Any], optional): JSON data to send in the body of the request.

        Returns:
            dict: API response.
        """
        request_data: dict[str, Any] = {
            "method": method,
            "url_suffix": url,
            "resp_type": "json"
        }
        if body is not None:
            request_data["json_data"] = body

        return self._http_request(**request_data)

    def create_asset_group(self, name: str, type: str, description: str, filters: list[dict] | None = None,
                           match: str | None = MATCH_DEFAULT_VALUE) -> dict:
        json_data = assign_params(name=name, type=type, description=description,
                                  searchCriteria=find_valid_params(filters=filters, match=match))

        return self._http_request(
            method="POST",
            url_suffix="/asset_groups",
            json_data=json_data,
            resp_type="json"
        )

    def get_asset_groups(self, name: str | None = None, type: str | None = None, page_size: int | None = DEFAULT_PAGE_SIZE,
                         page: int | None = None, sort: str | None = None, limit: int | None = None) -> list[dict]:
        params = assign_params(name=name, type=type)

        return self._paged_http_request(
            url_suffix="/asset_groups",
            method="GET",
            params=params,
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_asset_group_by_id(self, id: int) -> list[dict]:
        return self._http_request(
            url_suffix=f"/asset_groups/{id}",
            method="GET",
            resp_type="json",
        )


class Site:
    """A class representing a site, which can be identified by ID or name."""

    def __init__(self, site_id: str | None = None, site_name: str | None = None, client: Client | None = None) -> None:
        """
        Create a new Site object.
        Required parameters are either `site_id`, or both `site_name` and `client`.

        Args:
            site_id (str | None, optional): ID of the site.
            site_name (str | None, optional): Name of the site to create an object for.
            client (Client | None): Client object to use for API requests.
                Required to fetch ID if only name is provided.

        Raises:
            ValueError: If neither of `site_id` and `site_name` was provided,
            or `site_name` was provided without a `site_id`, and `client` was not provided.
            InvalidSiteNameException: If no ID was provided and a site with a matching name could not be found.
        """
        self.id: str
        self.name: str | None = None

        if site_id:
            self.id = site_id

        elif site_name:
            if client:
                site_id = client.find_site_id(site_name)

                if not site_id:
                    raise DemistoException(f"No site with name \"{site_name}\" was found.")

                self.id = site_id

            else:
                raise ValueError("Can't fetch site ID as no Client was provided.")

        else:
            raise ValueError("Either a site ID or a site name must be passed as an argument.")

        self.name = site_name


def convert_asset_search_filters(search_filters: str | list[str]) -> list[dict]:
    """
    | Convert string-based asset search filters to dict-based asset search filters that can be used in Nexpose's API.
    |
    | Format specification can be found under "Search Criteria" on:
        https://help.rapid7.com/insightvm/en-us/api/index.html#section/Overview/Responses

    Args:
        search_filters (str | list[str]): List of string-based search filters.

    Returns:
        list(dict): List of the same search filters in a dict-based format.
    """
    range_operators = ["in-range", "is-between", "not-in-range"]
    numeric_operators = ["is-earlier-than", "is-greater-than"]
    numeric_operators.extend(range_operators)
    values_field = ["site-id"]

    if isinstance(search_filters, str):
        search_filters = [search_filters]

    normalized_filters = []

    for search_filter in search_filters:
        # Example: risk-score is-between 5,10
        #   _field = risk-score
        #   _operator = is-greater-than
        #   _value = 5,10
        _field, _operator, _value = search_filter.split(" ")
        values = argToList(_value)

        if _operator in numeric_operators:
            values = [float(value) for value in values]

        filter_dict = {
            "field": _field,
            "operator": _operator,
        }

        if len(values) > 1:
            if _operator in range_operators:
                filter_dict["lower"] = values[0]
                filter_dict["upper"] = values[1]
            else:
                filter_dict["values"] = values
        elif _field in values_field:
            filter_dict["values"] = values
        else:
            filter_dict["value"] = values[0]

        normalized_filters.append(filter_dict)

    return normalized_filters


def convert_datetime_str(time_str: str) -> struct_time:
    """
    Convert an ISO 8601 datetime string to a `struct_time` object.

    Args:
        time_str (str): A string representing an ISO 8601 datetime.

    Returns:
        struct_time: The datetime represented in a `struct_time` object.
    """
    try:
        return strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")

    except ValueError:
        return strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")


def create_credential_creation_body(service: CredentialService, database_name: str | None = None,
                                    domain: str | None = None, http_realm: str | None = None,
                                    notes_id_password: str | None = None, ntlm_hash: str | None = None,
                                    oracle_enumerate_sids: bool | None = None,
                                    oracle_listener_password: str | None = None,
                                    oracle_sid: str | None = None, password: str | None = None,
                                    snmp_community_name: str | None = None,
                                    snmpv3_authentication_type: SNMPv3AuthenticationType | None = None,
                                    snmpv3_privacy_password: str | None = None,
                                    snmpv3_privacy_type: SNMPv3PrivacyType | None = None,
                                    ssh_key_pem: str | None = None,
                                    ssh_permission_elevation: SSHElevationType | None = None,
                                    ssh_permission_elevation_password: str | None = None,
                                    ssh_permission_elevation_username: str | None = None,
                                    ssh_private_key_password: str | None = None,
                                    use_windows_authentication: bool | None = None,
                                    username: str | None = None) -> dict:
    """
    Create `account` body for credential-creation API requests.

    Args:
        service (CredentialService): Credential service type.
        database_name (str | None, optional): Database name.
        domain (str | None, optional): Domain address.
        http_realm (str | None, optional): HTTP realm.
        notes_id_password (str | None, optional):
            Password for the notes account that will be used for authenticating.
        ntlm_hash (str | None, optional): NTLM password hash.
        oracle_enumerate_sids (bool | None, optional): Whether the scan engine should attempt to enumerate
            SIDs from the environment.
        oracle_listener_password (str | None, optional): The Oracle Net Listener password.
            Used to enumerate SIDs from the environment.
        oracle_sid (str | None, optional): Oracle database name.
        password (str | None, optional): Password for the credential.
        snmp_community_name (str | None, optional): SNMP community for authentication.
        snmpv3_authentication_type (SNMPv3AuthenticationType): SNMPv3 authentication type for the credential.
        snmpv3_privacy_password (str | None, optional): SNMPv3 privacy password to use.
        snmpv3_privacy_type (SNMPv3PrivacyType, optional): SNMPv3 Privacy protocol to use.
        ssh_key_pem (str | None, optional): PEM formatted private key.
        ssh_permission_elevation (SSHElevationType | None, optional): Elevation type to use for scans.
        ssh_permission_elevation_password (str | None, optional): Password to use for elevation.
        ssh_permission_elevation_username (str | None, optional): Username to use for elevation.
        ssh_private_key_password (str | None, optional): Password for the private key.
        use_windows_authentication (bool | None, optional): Whether to use Windows authentication.
        username (str | None, optional): Username for the credential.

    Returns:
        dict: `account` body to use for credential-creation API requests.
    """
    missing_params: list[str] = []
    special_validation_errors: list[str] = []

    account_data: dict = {"service": service.value}

    s = CredentialService  # Simplify object name for shorter lines

    # Services where "username" field is required
    if service in (s.AS400, s.CIFS, s.CIFSHASH, s.CVS, s.DB2, s.FTP, s.HTTP, s.MS_SQL, s.MYSQL, s.ORACLE,
                   s.POP, s.POSTGRESQL, s.REMOTE_EXEC, s.SNMPV3, s.SSH, s.SSH_KEY, s.SYBASE, s.TELNET):
        if username is None:
            missing_params.append("Username")

        else:
            account_data["username"] = username

    # Services where "password" field is required
    if service in (s.AS400, s.CIFS, s.CIFSHASH, s.CVS, s.DB2, s.FTP, s.HTTP, s.MS_SQL, s.MYSQL,
                   s.ORACLE, s.POP, s.POSTGRESQL, s.REMOTE_EXEC, s.SSH, s.SYBASE, s.TELNET):
        if password is None:
            missing_params.append("Password")

        else:
            account_data["password"] = password

    # Services with optional "useWindowsAuthentication" field.
    if service in (s.MS_SQL, s.SYBASE) and use_windows_authentication is not None:
        account_data["useWindowsAuthentication"] = use_windows_authentication

    # Services with optional "domain" field.
    if service in (s.AS400, s.CIFS, s.CIFSHASH, s.CVS, s.MS_SQL, s.SYBASE) and domain is not None:
        if service in (s.MS_SQL, s.SYBASE):
            if use_windows_authentication:
                account_data["domain"] = domain

        else:
            account_data["domain"] = domain

    # Services with optional "database" field.
    if service in (s.DB2, s.MS_SQL, s.MYSQL, s.POSTGRESQL, s.SYBASE) and database_name is not None:
        account_data["database"] = database_name

    if service == s.CIFSHASH:
        if ntlm_hash is None:
            missing_params.append("NTLM hash")

        else:
            account_data["ntlmHash"] = ntlm_hash

    if service == s.HTTP and http_realm is not None:
        account_data["realm"] = http_realm

    if service == s.NOTES and notes_id_password is not None:
        account_data["notesIDPassword"] = notes_id_password

    if service == s.ORACLE:
        if oracle_sid is not None:
            account_data["sid"] = oracle_sid

        if oracle_enumerate_sids is not None:
            account_data["enumerateSids"] = oracle_enumerate_sids

            if oracle_enumerate_sids and oracle_listener_password is None:
                missing_params.append("Oracle Listener Password")

            else:
                account_data["oracleListenerPassword"] = oracle_listener_password

    if service == s.SNMP:
        if snmp_community_name is None:
            missing_params.append("Community Name")

        else:
            account_data["community"] = snmp_community_name

    if service == s.SNMPV3:
        if snmpv3_authentication_type is None:
            missing_params.append("Authentication Type")

        else:
            account_data["authenticationType"] = snmpv3_authentication_type.value

        if snmpv3_authentication_type != SNMPv3AuthenticationType.NO_AUTHENTICATION:
            if password is None:
                special_validation_errors.append(f"Password is required for {service.value} services "
                                                 "when authentication type is set to anything other "
                                                 "than \"no-authentication\".")

            else:
                account_data["password"] = password

        if snmpv3_privacy_type is not None:
            account_data["privacyType"] = snmpv3_privacy_type.value

            if snmpv3_privacy_type != SNMPv3PrivacyType.NO_PRIVACY and snmpv3_privacy_password is None:
                special_validation_errors.append(f"Privacy password is required for {service.value} services when the "
                                                 f"authentication type is set to any value other than "
                                                 f"\"no-authentication\", and privacy type is set to any value other "
                                                 f"than \"no-privacy\".")

            else:
                account_data["privacyPassword"] = snmpv3_privacy_password

    if service in (s.SSH, s.SSH_KEY):
        if ssh_permission_elevation:
            account_data["permissionElevation"] = ssh_permission_elevation.value

        if ssh_permission_elevation not in (SSHElevationType.NONE, SSHElevationType.PBRUN):
            missing_elevation_params: list[str] = []

            if ssh_permission_elevation_username is None:
                missing_elevation_params.append("Elevation Username")

            else:
                account_data["permissionElevationUsername"] = ssh_permission_elevation_username

            if ssh_permission_elevation_password is None:
                missing_elevation_params.append("Elevation Password")

            else:
                account_data["permissionElevationPassword"] = ssh_permission_elevation_password

            if len(missing_elevation_params) > 0:
                special_validation_errors.append(f"{', '.join(missing_elevation_params)} are required for "
                                                 f"\"{service.value}\" services when \"ssh_permission_elevation\" "
                                                 f"is not set to \"none\" or \"pbrun\".")

    if service == s.SSH_KEY:
        if ssh_key_pem is None:
            missing_params.append("SSH Key PEM")

        else:
            account_data["pemKey"] = ssh_key_pem

        if ssh_private_key_password is not None:
            account_data["privateKeyPassword"] = ssh_private_key_password

    error_message: str = ""
    if len(missing_params) > 0:
        error_message += f"Missing required parameters for \"{service.value}\": {', '.join(missing_params)}.\n"

    if len(special_validation_errors) > 0:
        for special_validation_error in special_validation_errors:
            error_message += f"{special_validation_error}\n"

    if error_message:
        raise ValueError(error_message.rstrip("\n"))

    return account_data


def create_report(client: Client, scope: dict[str, Any], template_id: str | None = None,
                  report_name: str | None = None, report_format: str | None = None,
                  download_immediately: bool | None = None) -> dict | CommandResults:
    """
    Create a report and optionally download it.

    Args:
        client (Client): Client to use for API requests.
        scope (dict[str, Any]): Scope of the report, see Nexpose's documentation for more details.
        template_id (str | None, optional): ID of report template to use.
            Defaults to None (will result in using the first available template)
        report_name (str | None, optional): Name for the report that will be generated. Uses "report {date}" by default.
        report_format (str | None, optional): Format of the report that will be generated. Defaults to PDF.
        download_immediately: (bool | None, optional) = Whether to download the report automatically after creation.
            Defaults to True.
    """
    if template_id is None:
        templates_data = client.get_report_templates()

        if not templates_data.get("resources"):
            return CommandResults(
                readable_output="No available templates were found.",
                raw_response=templates_data,
            )

        template_id = templates_data["resources"][0]["id"]

    if report_name is None:
        report_name = "report " + str(datetime.now())

    if not report_format:
        report_format = "pdf"

    if download_immediately is None:
        download_immediately = True

    report_data = client.create_report_config(
        scope=scope,
        template_id=template_id,
        report_name=report_name,
        report_format=report_format.lower(),
    )

    instance_data = client.create_report(report_data["id"])

    context = {
        "Name": report_name,
        "ID": report_data["id"],
        "InstanceID": instance_data["id"],
        "Format": report_format.lower(),
    }
    hr = tableToMarkdown("Report Information", context)

    if download_immediately:
        try:
            # Wait for the report to be completed
            time.sleep(REPORT_DOWNLOAD_WAIT_TIME)  # pylint: disable=E9003

            return download_report_command(
                client=client,
                report_id=report_data["id"],
                instance_id=instance_data["id"],
                name=report_name,
                report_format=report_format,
            )

        except Exception as e:
            # A 404 response could mean that the report generation process has not finished yet.
            # In that case report's information will be returned to the user for them to download it manually.
            if "404" not in str(e):
                raise

    return CommandResults(
        readable_output=hr,
        outputs_prefix="Nexpose.Report",
        outputs=context,
        outputs_key_field=["ID", "InstanceID"],
        raw_response=instance_data,
    )


def find_asset_last_scan_data(asset_data: dict) -> tuple[str, str]:
    """
    Find the date and ID for the last scan of an asset.

    Note:
        `-` is used as a placeholder for missing values instead of `None` because of backwards compatibility.

    Args:
        asset_data (dict): A dictionary representing an asset as received from the API.

    Returns:
        tuple[str, str]: A tuple containing the date (first value) and ID (seconds value) of the last scan of the asset.
    """
    scan_date = '-'
    scan_id = '-'

    if asset_data.get("history"):
        sorted_scans = sorted(asset_data["history"], key=lambda x: convert_datetime_str(x.get("date")), reverse=True)

        if "date" in sorted_scans[0]:
            scan_date = sorted_scans[0]["date"]

        if "scanId" in sorted_scans[0]:
            scan_id = sorted_scans[0]["scanId"]

    return scan_date, scan_id


def find_valid_params(strict_mode: bool = False, **kwargs) -> dict:
    """
    A function for filtering dictionaries (passed as kwargs) to remove keys that have a None value.

    Args:
        strict_mode (bool, optional): If set to true, keys with a False value (e.g. [], {}, '', False)
        will be removed as well.
        kwargs: A collection of keyword args to filter.

    Returns:
        dict: A dictionary containing only keywords with a value that isn't None.
    """
    new_kwargs = {}

    for key, value in kwargs.items():
        if (strict_mode and value) or (not strict_mode and value is not None):
            new_kwargs[key] = value

    return new_kwargs


def get_scan_entry(scan: dict) -> CommandResults:
    """
    Generate entry data from scan data (as received from the API).

    Args:
        scan (dict): Scan data as it was received from the API.

    Returns:
        CommandResults: Scan data in a normalized format that will be displayed in the UI.
    """
    scan_output = normalize_scan_data(scan)

    vulnerability_headers = [
        "Critical",
        "Severe",
        "Moderate",
        "Total",
    ]

    vulnerability_output = generate_new_dict(
        data=scan["vulnerabilities"],
        name_mapping={
            "critical": "Critical",
            "severe": "Severe",
            "moderate": "Moderate",
            "total": "Total",
        },
        include_none=True,
    )

    scan_hr = tableToMarkdown(
        name=f"Nexpose Scan ID {str(scan['id'])}",
        t=scan_output,
        headers=[
            "Id",
            "ScanType",
            "ScanName",
            "StartedBy",
            "Assets",
            "TotalTime",
            "Completed",
            "Status",
            "Message",
        ],
        removeNull=True)

    scan_hr += tableToMarkdown("Vulnerabilities", vulnerability_output, vulnerability_headers, removeNull=True)
    scan_output["Vulnerabilities"] = vulnerability_output

    return CommandResults(
        outputs_prefix="Nexpose.Scan",
        outputs_key_field="Id",
        outputs=scan_output,
        readable_output=scan_hr,
        raw_response=scan,
    )


def generate_duration_time(years: int | None = None, months: int | None = None, weeks: int | None = None,
                           days: int | None = None, hours: int | None = None, minutes: int | None = None,
                           seconds: float | None = None) -> str | None:
    """
    | Generate an ISO 8601 duration string.
    | More info about format's specification can be found on:
        https://en.wikipedia.org/wiki/ISO_8601#Durations
    |
    | If an overflow of a time unit occurs, the next unit will be incremented.
    | For months, 4 weeks are will be added to a month, even though months have variable length.

    Args:
        years (int | None, optional): Duration years.
        months (int | None, optional): Duration months.
        weeks (int | None, optional): Duration weeks.
        days (int | None, optional): Duration days.
        hours (int | None, optional): Duration hours.
        minutes (int | None, optional): Duration minutes.
        seconds (float | None, optional): Duration seconds.

    Returns:
        str: The duration represented in an ISO 8601 duration string.
    """
    if not any((years, months, weeks, days, hours, minutes, seconds)):
        return None

    duration_str = "P"

    if years:
        duration_str += f"{years}Y"

    if months:
        duration_str += f"{months}M"

    if weeks:
        duration_str += f"{weeks}W"

    if days:
        duration_str += f"{days}D"

    if hours or minutes or seconds:
        duration_str += "T"

        if hours:
            duration_str += f"{hours}H"

        if minutes:
            duration_str += f"{minutes}M"

        if seconds:
            duration_str += f"{seconds}S"

    return duration_str


def normalize_scan_data(scan_data: dict) -> dict:
    """
    Normalizes scan data received from the API to a HumanReadable format that will be displayed in the UI.

    Args:
        scan_data (dict): Scan data as it was received from the API.

    Returns:
        dict: Scan data in a normalized format that will be displayed in the UI.
    """
    result = generate_new_dict(
        data=scan_data,
        name_mapping={
            "id": "Id",
            "scanType": "ScanType",
            "scanName": "ScanName",
            "startedBy": "StartedBy",
            "assets": "Assets",
            "endTime": "Completed",
            "status": "Status",
            "message": "Message",
        },
        include_none=True,
    )

    if scan_data.get("duration"):
        result["TotalTime"] = readable_duration_time(scan_data["duration"])

    else:
        result["TotalTime"] = "No duration data was found."

    return result


def readable_duration_time(duration: str) -> str:
    """
    | Convert an ISO 8601 duration string to a human-readable string format.
    | More info about format's specification can be found on:
        https://en.wikipedia.org/wiki/ISO_8601#Durations

    Args:
        duration (str): An ISO 8601 duration string.

    Returns:
        str: The duration represented in a human-readable string format.
    """
    # Assure duration is in a valid format
    if not re.fullmatch(r"P(?:[\d.]+[YMWD]){0,4}T(?:[\d.]+[HMS]){0,3}", duration):
        raise ValueError(f"\"{duration}\" is not a valid ISO 8601 duration string.")

    p_duration, t_duration = duration.replace("T", ",T").split(",")
    p_duration = re.findall(r"([\d.]+[A-Z])", p_duration)
    t_duration = re.findall(r"([\d.]+[A-Z])", t_duration)
    duration_mapping_p = {
        "Y": "years",
        "M": "months",
        "W": "weeks",
        "D": "days",
    }
    duration_mapping_t = {
        "H": "hours",
        "M": "minutes",
        "S": "seconds",
    }
    duration_values: dict = {
        "years": 0,
        "months": 0,
        "weeks": 0,
        "days": 0,
        "hours": 0,
        "minutes": 0,
        "seconds": 0,
    }

    for item in p_duration:
        designator = item[-1]
        number_float = float(item[:-1])

        if number_float.is_integer():
            number_int = int(number_float)

        else:
            number_int = round(number_float)

        duration_values[duration_mapping_p[designator]] = number_int

    for item in t_duration:
        designator = item[-1]
        number_float = float(item[:-1])

        if number_float.is_integer():
            duration_values[duration_mapping_t[designator]] = int(number_float)

        else:
            duration_values[duration_mapping_t[designator]] = number_float

    result = []
    for item in duration_values:
        zero_up_to_now = True

        if duration_values[item] > 0:
            zero_up_to_now = False

        if not zero_up_to_now:
            result += [f"{duration_values[item]} {item}"]

    return ", ".join(result)


@overload
def remove_dict_key(data: dict, key: Any) -> dict:  # pragma: no cover
    pass


@overload
def remove_dict_key(data: list, key: Any) -> list:  # pragma: no cover
    pass


@overload
def remove_dict_key(data: tuple, key: Any) -> tuple:  # pragma: no cover
    pass


def remove_dict_key(data: dict | list | tuple, key: Any) -> dict | list | tuple:
    """
    Recursively remove a dictionary key from an object

    Args:
        data (dict | list | tuple): A dictionary or an iterable to remove keys for dictionaries within it.
        key (Any): Key to remove from dictionaries.

    Returns:
        dict | list | tuple: The data-structure (original or copy) with the specified key name removed
        from all dictionaries within.
    """
    if isinstance(data, dict):
        if key in data:
            del data[key]

        for k in data:
            remove_dict_key(data[k], key)

    if isinstance(data, list | tuple):
        for item in data:
            remove_dict_key(item, key)

    return data


@overload
def generate_new_dict(data: dict, name_mapping: dict[str, str], include_none: bool = False) -> dict:  # pragma: no cover
    pass


@overload
def generate_new_dict(data: list, name_mapping: dict[str, str], include_none: bool = False) -> list:  # pragma: no cover
    pass


def generate_new_dict(data: dict | list, name_mapping: dict[str, str],
                      include_none: bool = False) -> dict | list | tuple:
    """
    Generate a new dictionary from an existing dictionary, with the keys renamed according to `name_mapping`.

    Args:
        data (dict | list): The dictionary to generate a new dictionary from.
            If a list is passed, the function will run recursively on each item in the list.
        name_mapping (dict[str, str]): A mapping between old key names to the new key names
            in a `key-path: new-key` format.
        include_none (bool, optional): Whether to include keys with `None` values in the new dictionary.
    """
    if isinstance(data, dict):
        new_dict = {}

        for key_path, new_key in name_mapping.items():
            value = find_dict_item(data, key_path)

            if include_none or value is not None:
                new_dict[new_key] = value

        return new_dict

    elif isinstance(data, list):
        return [generate_new_dict(item, name_mapping, include_none) for item in data]

    elif isinstance(data, tuple):
        return tuple(generate_new_dict(item, name_mapping, include_none) for item in data)

    else:
        return data


def find_dict_item(data: dict | list | tuple, key_path: str) -> Any:
    """
    Find a dictionary item by its key path.

    Note:
        This code snippet assumes that `data` does not contain None values.
        If it does, None values will be returned both if the value is None, or if the key couldn't be found.

    Args:
        data (dict | list | tuple): A dictionary, a list, or a tuple to search for the key path in.
        key_path (str): The key path to search for. Keys are separated by a dot (.) character.

    Returns:
        Any: The value of the key path if found, None otherwise.
    """
    if isinstance(data, dict):
        key_path_list = key_path.split('.')

        if key_path_list[0] in data:
            if len(key_path_list) == 1:
                return data[key_path_list[0]]

            else:
                return find_dict_item(
                    data=data[key_path_list[0]],
                    key_path=".".join(key_path_list[1:]),
                )

        else:
            return None

    elif isinstance(data, list | tuple):
        result = [find_dict_item(
            data=item,
            key_path=key_path,
        ) for item in data]

        return [item for item in result if item is not None]

    return None


def parse_asset_filters(client, **kwargs):
    """
    Parse and generate a list of asset filters based on provided keyword arguments.

    Args:
        client (Client): Client to use for API requests.
        **kwargs: Arbitrary keyword arguments representing filter criteria.
            - ip_address_is (str): A specific IP address to filter assets by.
            - host_name_is (str): A specific host name to filter assets by.
            - risk_score_higher_than (str): A minimum risk score to filter assets by.
            - vulnerability_title_contains (str): A keyword to filter assets by vulnerability title.
            - query (str): A semicolon-separated list of custom query strings.
            - site_id_in (str): A comma-separated list of site IDs to filter assets by.
            - site_name_in (str): A comma-separated list of site names to filter assets by.


    Returns:
        list[str]: A list of asset filter strings.
    """
    filters_data: list[str] = []

    if kwargs.get("ip_address_is"):
        filters_data.append("ip-address is " + kwargs["ip_address_is"])

    if kwargs.get("host_name_is"):
        filters_data.append("host-name is " + kwargs["host_name_is"])

    if kwargs.get("risk_score_higher_than"):
        filters_data.append("risk-score is-greater-than " + kwargs["risk_score_higher_than"])

    if kwargs.get("vulnerability_title_contains"):
        filters_data.append("vulnerability-title contains " + kwargs["vulnerability_title_contains"])

    if kwargs.get("query"):
        filters_data.extend(kwargs["query"].split(";"))

    sites: list[Site] = []

    for site_id in argToList(kwargs.get("site_id_in")):
        sites.append(Site(site_id=site_id, client=client))

    for site_name in argToList(kwargs.get("site_name_in")):
        sites.append(Site(site_name=site_name, client=client))

    if sites:
        str_site_ids: str = ""

        if isinstance(sites, list):
            str_site_ids = ",".join([site.id for site in sites])

        elif isinstance(sites, Site):
            str_site_ids = sites.id

        filters_data.append("site-id in " + str_site_ids)

    return filters_data


def validate_input(input_value: str | None, valid_options: list[str], arg_name: str, is_required: bool = True):
    """
    Validates the input value against a list of valid options.

    Args:
        input_value (str | None): The input value to validate.
        valid_options (list[str]): The list of valid options.
        parameter_name (str): The name of the parameter being validated (used in the error message).
        is_required (bool): Whether the input value is required. Defaults to True.

    Raises:
        DemistoException: If the input value is invalid or not in the list of valid options.

    Returns:
        bool: True if the input value is valid or not required and None is provided.
    """
    if input_value is None and not is_required:
        return True
    elif not input_value or input_value.lower() not in valid_options:
        raise DemistoException(f"{input_value} is an invalid {arg_name} the only options are: {', '.join(valid_options)}")
    return True


# --- Command Functions --- #
def create_asset_command(client: Client, date: str, site_id: str | None = None, site_name: str | None = None,
                         ip: str | None = None, host_name: str | None = None,
                         host_name_source: str | None = None) -> CommandResults:
    """
    Create a new asset.

    Args:
        client (Client): The client to use.
        date (str): The date the data was collected on the asset.
        site_id (str | None, optional): Name of the site to create the asset in.
        site_name (str | None, optional): Name of the site to create the asset in. Can be used instead of "site_id".
        ip (str | None, optional): The IP address of the asset.
        host_name (str | None, optional): The hostname of the asset.
        host_name_source (str | None, optional): The source of the hostname.
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    response_data = client.create_asset(
        site_id=site.id,
        date=date,
        ip_address=ip,
        hostname=host_name,
        hostname_source=host_name_source,
    )

    return CommandResults(
        readable_output=f"New asset has been created with ID {response_data['id']}.",
        outputs_prefix="Nexpose.Asset",
        outputs_key_field="id",
        outputs={"id": response_data['id']},
        raw_response=response_data,
    )


def create_assets_report_command(client: Client, assets: str, template: str | None = None, name: str | None = None,
                                 report_format: str | None = None,
                                 download_immediately: str | None = None) -> dict | CommandResults:
    """
    Create a report about specific assets.

    Args:
        client (Client): Client to use for API requests.
        assets (str): List of assets to include in the report.
        template (str | None, optional): ID of report template to use.
            Defaults to None (will result in using the first available template)
        name (str | None, optional): Name for the report that will be generated. Uses "report {date}" by default.
        report_format (str | None, optional): Format of the report that will be generated. Defaults to PDF.
        download_immediately: (str | None, optional) = Whether to download the report automatically after creation.
            Defaults to True.
    """
    download_immediately_bool = None

    asset_ids_list: list[str] = argToList(assets)

    if download_immediately is not None:
        download_immediately_bool = argToBoolean(download_immediately)

    scope = {"assets": [int(asset_id) for asset_id in asset_ids_list]}

    return create_report(
        client=client,
        scope=scope,
        template_id=template,
        report_name=name,
        report_format=report_format,
        download_immediately=download_immediately_bool,
    )


def create_scan_report_command(client: Client, scan: str, template: str | None = None, name: str | None = None,
                               report_format: str | None = None,
                               download_immediately: str | None = None) -> dict | CommandResults:
    """
    Create a report about specific sites.

    Args:
        client (Client): Client to use for API requests.
        scan (str): ID of the scan to create a report on.
        template (str | None, optional): ID of report template to use.
            Defaults to None (will result in using the first available template)
        name (str | None, optional): Name for the report that will be generated. Uses "report {date}" by default.
        report_format (str | None, optional): Format of the report that will be generated. Defaults to PDF.
        download_immediately: (str | None, optional) = Whether to download the report automatically after creation.
            Defaults to True.
    """
    download_immediately_bool = None

    if download_immediately is not None:
        download_immediately_bool = argToBoolean(download_immediately)

    scope = {"scan": arg_to_number(scan, required=True)}

    return create_report(
        client=client,
        scope=scope,
        template_id=template,
        report_name=name,
        report_format=report_format,
        download_immediately=download_immediately_bool,
    )


def create_scan_schedule_command(client: Client, on_scan_repeat: str, start: str, site_id: str | None = None,
                                 site_name: str | None = None, excluded_asset_groups: str | None = None,
                                 excluded_targets: str | None = None, included_asset_groups: str | None = None,
                                 included_targets: str | None = None, duration_days: str | None = None,
                                 duration_hours: str | None = None, duration_minutes: str | None = None,
                                 enabled: str | None = None, frequency: str | None = None,
                                 interval_time: str | None = None, scan_name: str | None = None,
                                 date_of_month: int | None = None,
                                 scan_template_id: str | None = None) -> CommandResults:
    """
    Create a new site scan schedule.

    Args:
        client (Client): Client to use for API requests.
        on_scan_repeat (str): The desired behavior of a repeating scheduled scan
            when the previous scan was paused due to reaching its maximum duration.
        start (str): The scheduled start date and time formatted in ISO 8601 format.
        site_id (str | None, optional): ID of the site to create a scheduled scan for.
        site_name (str | None, optional): Name of the site to create a scheduled scan for.
            Can be used instead of "site_id".
        excluded_asset_groups (str | None, optional): Asset groups to exclude from the scan.
        excluded_targets (str | None, optional): Addresses to exclude from the scan. Each address is a string that
            can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
        included_asset_groups (str | None, optional): Asset groups to include in the scan.
        included_targets (str | None, optional): Addresses to include in the scan.  Each address is a string that
            can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
        duration_days (str | None, optional): Maximum duration of the scan in days.
            Can be used along with `duration_hours` and `duration_minutes`.
        duration_hours (str | None, optional): Maximum duration of the scan in hours.
            Can be used along with `duration_days` and `duration_minutes`.
        duration_minutes (str | None, optional): Maximum duration of the scan in minutes.
            Can be used along with `duration_days` and `duration_hours`.
        enabled (str | None, optional): A flag indicating whether the scan schedule is enabled.
           Defaults to None, which results in using True.
        frequency (str | None, optional): Frequency for the schedule to repeat.
            Required if using other repeat settings.
        interval_time (str | None, optional): The interval time the schedule should repeat.
            Required if using other repeat settings.
        date_of_month(str | None, optional): Specifies the schedule repeat day of the interval month.
            Required and used only if frequency is set to `DATE_OF_MONTH`.
        scan_name (str | None, optional): A unique user-defined name for the scan launched by the schedule.
            If not explicitly set in the schedule, the scan name will be generated prior to the scan launching.
        scan_template_id (str | None, optional): ID of the scan template to use.
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    excluded_asset_groups_list = None
    excluded_targets_list = None
    frequency_enum = None
    included_asset_groups_list = None
    included_targets_list = None

    if excluded_asset_groups is not None:
        excluded_asset_groups_list = [int(asset_id) for asset_id in argToList(excluded_asset_groups)]

    if excluded_targets is not None:
        excluded_targets_list = argToList(excluded_targets)

    if frequency is not None:
        frequency_enum = RepeatFrequencyType[frequency]

    if included_asset_groups is not None:
        included_asset_groups_list = [int(asset_id) for asset_id in argToList(included_asset_groups)]

    if included_targets is not None:
        included_targets_list = argToList(included_targets)

    duration_days_int = arg_to_number(duration_days, required=False)
    duration_hours_int = arg_to_number(duration_hours, required=False)
    duration_minutes_int = arg_to_number(duration_minutes, required=False)
    interval_int = arg_to_number(interval_time, required=False)
    date_of_month_int = arg_to_number(date_of_month, required=False)

    if enabled is not None:
        enabled_bool = argToBoolean(enabled)

    else:
        enabled_bool = True

    duration = generate_duration_time(
        days=duration_days_int,
        hours=duration_hours_int,
        minutes=duration_minutes_int,
    )

    response_data = client.create_site_scan_schedule(
        site_id=site.id,
        enabled=enabled_bool,
        repeat_behaviour=on_scan_repeat,
        start_date=start,
        excluded_asset_groups=excluded_asset_groups_list,
        excluded_targets=excluded_targets_list,
        included_asset_groups=included_asset_groups_list,
        included_targets=included_targets_list,
        duration=duration,
        frequency=frequency_enum,
        interval=interval_int,
        date_of_month=date_of_month_int,
        scan_name=scan_name,
        scan_template_id=scan_template_id,
    )

    return CommandResults(
        readable_output=f"New scheduled scan has been created with ID {response_data['id']}.",
        outputs_prefix="Nexpose.ScanSchedule",
        outputs_key_field="id",
        outputs={"id": response_data['id']},
        raw_response=response_data,
    )


def create_shared_credential_command(client: Client, name: str, site_assignment: str, service: str,
                                     database: str | None = None, description: str | None = None,
                                     domain: str | None = None, host_restriction: str | None = None,
                                     http_realm: str | None = None, notes_id_password: str | None = None,
                                     ntlm_hash: str | None = None, oracle_enumerate_sids: str | None = None,
                                     oracle_listener_password: str | None = None, oracle_sid: str | None = None,
                                     password: str | None = None, port_restriction: str | None = None,
                                     sites: str | None = None, authentication_type: str | None = None,
                                     community_name: str | None = None, privacy_password: str | None = None,
                                     privacy_type: str | None = None, ssh_key_pem: str | None = None,
                                     ssh_permission_elevation: str | None = None,
                                     ssh_permission_elevation_password: str | None = None,
                                     ssh_permission_elevation_username: str | None = None,
                                     ssh_private_key_password: str | None = None,
                                     use_windows_authentication: str | None = None,
                                     username: str | None = None) -> CommandResults:
    """
    Create a new shared credential.

    Args:
        client (Client): Client to use for API requests.
        name (str): Name of the credential.
        site_assignment (str): Site assignment configuration for the credential.
        service (str): Credential service type.
        database (str | None, optional): Database name.
        description (str | None, optional): Description for the credential.
        domain (str | None, optional): Domain address.
        host_restriction (str | None, optional): Hostname or IP address to restrict the credentials to.
        http_realm (str | None, optional): HTTP realm.
        notes_id_password (str | None, optional): Password for the notes account that will be used for authenticating.
        ntlm_hash (str | None, optional): NTLM password hash.
        oracle_enumerate_sids (str | None, optional): Whether the scan engine should attempt to enumerate
            SIDs from the environment.
        oracle_listener_password (str | None, optional): The Oracle Net Listener password.
            Used to enumerate SIDs from the environment.
        oracle_sid (str | None, optional): Oracle database name.
        password (str | None, optional): Password for the credential.
        port_restriction (str | None, optional): Further restricts the credential to attempt to authenticate
            on a specific port. Can be used only if `host_restriction` is used.
        sites (str | None, optional): List of site IDs for the shared credential that are explicitly assigned
            access to the shared scan credential, allowing it to use the credential during a scan.
        authentication_type (str | None, optional): SNMPv3 authentication type for the credential.
        community_name (str | None, optional): SNMP community for authentication.
        privacy_password (str | None, optional): SNMPv3 privacy password to use.
        privacy_type (str | None, optional): SNMPv3 Privacy protocol to use.
        ssh_key_pem (str | None, optional): PEM formatted private key.
        ssh_permission_elevation (str | None, optional): Elevation type to use for scans.
        ssh_permission_elevation_password (str | None, optional): Password to use for elevation.
        ssh_permission_elevation_username (str | None, optional): Username to use for elevation.
        ssh_private_key_password (str | None, optional): Password for the private key.
        use_windows_authentication (str | None, optional): Whether to use Windows authentication.
        username (str | None, optional): Username for the credential.
    """
    oracle_enumerate_sids_bool = None
    sites_list = None
    snmpv3_authentication_type_enum = None
    snmpv3_privacy_type_enum = None
    ssh_permission_elevation_enum = None
    use_windows_authentication_bool = None

    if oracle_enumerate_sids is not None:
        oracle_enumerate_sids_bool = argToBoolean(oracle_enumerate_sids)

    if sites is not None:
        sites_list = [int(item) for item in argToList(sites)]

    if authentication_type is not None:
        snmpv3_authentication_type_enum = SNMPv3AuthenticationType[authentication_type]

    if privacy_type is not None:
        snmpv3_privacy_type_enum = SNMPv3PrivacyType[privacy_type]

    if ssh_permission_elevation is not None:
        ssh_permission_elevation_enum = SSHElevationType[ssh_permission_elevation]

    if use_windows_authentication is not None:
        use_windows_authentication_bool = argToBoolean(use_windows_authentication)

    response_data = client.create_shared_credential(
        name=name,
        site_assignment=SharedCredentialSiteAssignment[site_assignment],
        service=CredentialService[service],
        database_name=database,
        description=description,
        domain=domain,
        host_restriction=host_restriction,
        http_realm=http_realm,
        notes_id_password=notes_id_password,
        ntlm_hash=ntlm_hash,
        oracle_enumerate_sids=oracle_enumerate_sids_bool,
        oracle_listener_password=oracle_listener_password,
        oracle_sid=oracle_sid,
        password=password,
        port_restriction=port_restriction,
        sites=sites_list,
        snmp_community_name=community_name,
        snmpv3_authentication_type=snmpv3_authentication_type_enum,
        snmpv3_privacy_password=privacy_password,
        snmpv3_privacy_type=snmpv3_privacy_type_enum,
        ssh_key_pem=ssh_key_pem,
        ssh_permission_elevation=ssh_permission_elevation_enum,
        ssh_permission_elevation_password=ssh_permission_elevation_password,
        ssh_permission_elevation_username=ssh_permission_elevation_username,
        ssh_private_key_password=ssh_private_key_password,
        use_windows_authentication=use_windows_authentication_bool,
        username=username,
    )

    return CommandResults(
        readable_output=f"New shared credential has been created with ID {response_data['id']}.",
        outputs_prefix="Nexpose.SharedCredential",
        outputs_key_field="id",
        outputs={"id": response_data['id']},
        raw_response=response_data,
    )


def create_site_command(client: Client, name: str, description: str | None = None, assets: str | None = None,
                        importance: str | None = None, template_id: str | None = None) -> CommandResults:
    """
    Create a new site.

    Args:
        client (Client): Client to use for API requests.
        name (str): Name of the site. Must be unique.
        description (str | None, optional): Description of the site. Defaults to None.
        assets (str | None, optional): List of asset IDs to be included in site scans. Defaults to None.
        importance (str | None, optional): Importance of the site.
            Defaults to None (results in using API's default - "normal").
        template_id (str | None, optional): The identifier of a scan template.
            Defaults to None (results in using default scan template).
    """
    assets_list = None

    if assets is not None:
        assets_list = argToList(assets)

    response_data = client.create_site(
        name=name,
        description=description,
        assets=assets_list,
        site_importance=importance,
        template_id=template_id
    )

    return CommandResults(
        readable_output=f"New site has been created with ID {response_data['id']}.",
        outputs_prefix="Nexpose.Site",
        outputs_key_field="Id",
        outputs={"Id": response_data['id']},
        raw_response=response_data,
    )


def create_sites_report_command(client: Client, sites: str | None = None, site_names: str | None = None,
                                template: str | None = None, name: str | None = None, report_format: str | None = None,
                                download_immediately: str | None = None) -> dict | CommandResults:
    """
    Create a report about specific sites.

    Args:
        client (Client): Client to use for API requests.
        sites (str | None, optional): List of site IDs to create the report about.
        site_names (str | None, optional): List of site names to create the report about.
        template (str | None, optional): ID of report template to use.
            Defaults to None (will result in using the first available template)
        name (str | None, optional): Name for the report that will be generated. Uses "report {date}" by default.
        report_format (str | None, optional): Format of the report that will be generated. Defaults to PDF.
        download_immediately: (str | None, optional) = Whether to download the report automatically after creation.
            Defaults to True.
    """
    sites_list = [Site(site_id=site_id, client=client) for site_id in argToList(sites)]
    sites_list.extend(
        [Site(site_name=site_name, client=client) for site_name in argToList(site_names)]
    )

    if len(sites_list) == 0:
        raise Exception("At least one site ID or site name must be provided.")

    download_immediately_bool = None

    if download_immediately is not None:
        download_immediately_bool = argToBoolean(download_immediately)

    scope = {"sites": [int(site.id) for site in sites_list]}

    return create_report(
        client=client,
        scope=scope,
        template_id=template,
        report_name=name,
        report_format=report_format,
        download_immediately=download_immediately_bool,
    )


def create_site_scan_credential_command(client: Client, name: str, service: str, site_id: str | None = None,
                                        site_name: str | None = None, authentication_type: str | None = None,
                                        community_name: str | None = None, database: str | None = None,
                                        description: str | None = None, domain: str | None = None,
                                        host_restriction: str | None = None, http_realm: str | None = None,
                                        notes_id_password: str | None = None, ntlm_hash: str | None = None,
                                        oracle_enumerate_sids: str | None = None,
                                        oracle_listener_password: str | None = None, oracle_sid: str | None = None,
                                        password: str | None = None, port_restriction: str | None = None,
                                        privacy_password: str | None = None, privacy_type: str | None = None,
                                        ssh_key_pem: str | None = None, ssh_permission_elevation: str | None = None,
                                        ssh_permission_elevation_password: str | None = None,
                                        ssh_permission_elevation_username: str | None = None,
                                        ssh_private_key_password: str | None = None,
                                        use_windows_authentication: str | None = None,
                                        username: str | None = None) -> CommandResults:
    """
    Create a new site scan credential.

    Args:
        client (Client): Client to use for API requests.
        name (str): Name of the credential.
        service (str): Credential service type.
        site_id (str | None, optional): ID of a site to create the credential for.
        site_name (str | None, optional): Name of a site to create the credential for. Can be used instead of "site_id".
        authentication_type (str): SNMPv3 authentication type for the credential.
        community_name (str | None, optional): SNMP community for authentication.
        database (str | None, optional): Database name.
        description (str | None, optional): Description for the credential.
        domain (str | None, optional): Domain address.
        host_restriction (str | None, optional): Hostname or IP address to restrict the credentials to.
        http_realm (str | None, optional): HTTP realm.
        notes_id_password (str | None, optional): Password for the notes account that will be used for authenticating.
        ntlm_hash (str | None, optional): NTLM password hash.
        oracle_enumerate_sids (str | None, optional): Whether the scan engine should attempt to enumerate
            SIDs from the environment.
        oracle_listener_password (str | None, optional): The Oracle Net Listener password.
            Used to enumerate SIDs from the environment.
        oracle_sid (str | None, optional): Oracle database name.
        password (str | None, optional): Password for the credential.
        port_restriction (str | None, optional): Further restricts the credential to attempt to authenticate
            on a specific port. Can be used only if `host_restriction` is used.
        privacy_password (str | None, optional): SNMPv3 privacy password to use.
        privacy_type (str | None, optional): SNMPv3 Privacy protocol to use.
        ssh_key_pem (str | None, optional): PEM formatted private key.
        ssh_permission_elevation (str | None, optional): Elevation type to use for scans.
        ssh_permission_elevation_password (str | None, optional): Password to use for elevation.
        ssh_permission_elevation_username (str | None, optional): Username to use for elevation.
        ssh_private_key_password (str | None, optional): Password for the private key.
        use_windows_authentication (str | None, optional): Whether to use Windows authentication.
        username (str | None, optional): Username for the credential.
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    oracle_enumerate_sids_bool = None
    snmpv3_authentication_type_enum = None
    snmpv3_privacy_type_enum = None
    ssh_permission_elevation_enum = None
    use_windows_authentication_bool = None

    if oracle_enumerate_sids is not None:
        oracle_enumerate_sids_bool = argToBoolean(oracle_enumerate_sids)

    if authentication_type is not None:
        snmpv3_authentication_type_enum = SNMPv3AuthenticationType[authentication_type]

    if privacy_type is not None:
        snmpv3_privacy_type_enum = SNMPv3PrivacyType[privacy_type]

    if ssh_permission_elevation is not None:
        ssh_permission_elevation_enum = SSHElevationType[ssh_permission_elevation]

    if use_windows_authentication is not None:
        use_windows_authentication_bool = argToBoolean(use_windows_authentication)

    response_data = client.create_site_scan_credential(
        site_id=site.id,
        name=name,
        service=CredentialService[service],
        database_name=database,
        description=description,
        domain=domain,
        host_restriction=host_restriction,
        http_realm=http_realm,
        notes_id_password=notes_id_password,
        ntlm_hash=ntlm_hash,
        oracle_enumerate_sids=oracle_enumerate_sids_bool,
        oracle_listener_password=oracle_listener_password,
        oracle_sid=oracle_sid,
        password=password,
        port_restriction=port_restriction,
        snmp_community_name=community_name,
        snmpv3_authentication_type=snmpv3_authentication_type_enum,
        snmpv3_privacy_password=privacy_password,
        snmpv3_privacy_type=snmpv3_privacy_type_enum,
        ssh_key_pem=ssh_key_pem,
        ssh_permission_elevation=ssh_permission_elevation_enum,
        ssh_permission_elevation_password=ssh_permission_elevation_password,
        ssh_permission_elevation_username=ssh_permission_elevation_username,
        ssh_private_key_password=ssh_private_key_password,
        use_windows_authentication=use_windows_authentication_bool,
        username=username,
    )

    return CommandResults(
        readable_output=f"New site scan credential has been created with ID {response_data['id']}.",
        outputs_prefix="Nexpose.SiteScanCredential",
        outputs_key_field="id",
        outputs={"id": response_data['id']},
        raw_response=response_data,
    )


def create_vulnerability_exception_command(client: Client, vulnerability_id: str,
                                           scope_type: str, state: str, reason: str, scope_id: str | None = None,
                                           expires: str | None = None, comment: str | None = None) -> CommandResults:
    """
    Create a vulnerability exception.

    Args:
        client (Client): Client to use for API requests.
        vulnerability_id (str): ID of the vulnerability to create the exception for.
        scope_type (str): The type of the exception scope.
        state (str): The state of the vulnerability exception.
        reason (str): The reason the vulnerability exception was submitted.
        scope_id (int): ID of the chosen `scope_type` (site ID, asset ID, etc.).
            Required if `scope_type` is anything other than `Global`
        expires (str | None, optional): The date and time the vulnerability exception is set to expire.
        comment (str | None, optional): A comment from the submitter as to why the exception was submitted.
    """
    scope_type_enum = VulnerabilityExceptionScopeType[scope_type]

    if scope_type_enum != VulnerabilityExceptionScopeType.GLOBAL and scope_id is None:
        raise ValueError(f"\"scope_id\" must be set when using scopes different than "
                         f"\"{VulnerabilityExceptionScopeType.GLOBAL.value}\".")

    response_data = client.create_vulnerability_exception(
        vulnerability_id=vulnerability_id,
        scope_type=scope_type_enum,
        state=state,
        reason=reason,
        scope_id=int(scope_id) if scope_id is not None else None,
        expires=expires,
        comment=comment,
    )

    return CommandResults(
        readable_output=f"New vulnerability exception has been created with ID {str(response_data['id'])}.",
        outputs_prefix="Nexpose.VulnerabilityException",
        outputs_key_field="id",
        outputs={"id": response_data["id"]},
        raw_response=response_data,
    )


def delete_asset_command(client: Client, asset_id: str) -> CommandResults:
    """
    Delete an asset.

    Args:
        client (Client): Client to use for API requests.
        asset_id (str): ID of the asset to delete.
    """
    response_data = client.delete_asset(asset_id=asset_id)

    return CommandResults(
        readable_output=f"Asset {asset_id} has been deleted.",
        raw_response=response_data,
    )


def delete_scan_schedule_command(client: Client, schedule_id: str, site_id: str | None = None,
                                 site_name: str | None = None) -> CommandResults:
    """
    Delete a scheduled scan.

    Args:
        client (Client): Client to use for API requests.
        schedule_id (str): ID of the scheduled scan to delete.
        site_id (str | None, optional): ID of the site to delete the scheduled scan from.
        site_name (str | None, optional): Name of the site to delete the scheduled scan from.
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    response_data = client.delete_scan_schedule(
        site_id=site.id,
        scheduled_scan_id=schedule_id,
    )

    return CommandResults(
        readable_output=f"Scheduled scan with ID {schedule_id} has been deleted.",
        raw_response=response_data,
    )


def delete_site_command(client: Client, site_id: str | None = None, site_name: str | None = None) -> CommandResults:
    """
    Delete a site.

    Args:
        client (Client): Client to use for API requests.
        site_id (str | None, optional): ID of a site to delete.
        site_name (str | None, optional): Name of a site to delete. Can be used instead of "site_id".
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    response_data = client.delete_site(site.id)

    return CommandResults(
        readable_output=f"Site ID {site.id} has been deleted.",
        outputs_prefix="Nexpose.Report",
        outputs_key_field=["ID", "InstanceID"],
        raw_response=response_data,
    )


def delete_shared_credential_command(client: Client, shared_credential_id: str) -> CommandResults:
    """
    Delete a shared credential.

    Args:
        client (Client): Client to use for API requests.
        shared_credential_id (str): ID of the shared credential to delete.
    """
    response_data = client.delete_shared_credential(shared_credential_id)

    return CommandResults(
        readable_output=f"Shared credential with ID {shared_credential_id} has been deleted.",
        raw_response=response_data,
    )


def delete_site_scan_credential_command(client: Client, credential_id: str, site_id: str | None = None,
                                        site_name: str | None = None) -> CommandResults:
    """
    Delete a site scan credential.

    Args:
        client (Client): Client to use for API requests.
        credential_id (str): ID of the site scan credential to delete.
        site_id (str | None, optional): ID of the site to delete the site scan credential from.
        site_name (str | None, optional): Name of the site to delete the site scan credential from.
            Can be used instead of "site_id".
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    response_data = client.delete_site_scan_credential(
        site_id=site.id,
        site_credential_id=credential_id,
    )

    return CommandResults(
        readable_output=f"Site scan credential with ID {credential_id} has been deleted.",
        raw_response=response_data,
    )


def delete_vulnerability_exception_command(client: Client, vulnerability_exception_id: str) -> CommandResults:
    """
    Delete a vulnerability exception.

    Args:
        client (Client): Client to use for API requests.
        vulnerability_exception_id (str): ID of the vulnerability exception to delete.
    """
    response_data = client.delete_vulnerability_exception(vulnerability_exception_id)

    return CommandResults(
        readable_output=f"Vulnerability exception with ID {vulnerability_exception_id} has been deleted.",
        raw_response=response_data,
    )


def download_report_command(client: Client, report_id: str, instance_id: str, name: str | None = None,
                            report_format: str | None = None) -> dict:
    """
    Download a report file.

    Note:
        Not sure why there's a report_format parameter, as the format is set when generating the report,
        and all the parameter seems to do here, is just change the file extension
        (which is obviously not how file conversion works).
        This function currently remains as it is, since removing it might break client's using it for some reason.

    Args:
        client (Client): Client to use for API requests.
        report_id (str): ID of the report to download.
        instance_id (str): ID of the report instance.
        name (str | None, optional): Name to give the generated report file.
            Defaults to None (results in using a "report <date>" format as a name).
        report_format (str | None, optional): File format to use for the generated report.
            Defaults to None (results in using PDF).

    Returns:
        dict: A dict generated by `CommonServerPython.fileResult` representing a War Room entry.
    """
    if name is None:
        name = f"report {str(datetime.now())}"

    if not report_format:
        report_format = "pdf"

    report_data = client.download_report(
        report_id=report_id,
        instance_id=instance_id
    )

    return fileResult(
        filename=f"{name}.{report_format.lower()}",
        data=report_data,
        file_type=entryTypes["entryInfoFile"],
    )


def get_asset_tags_command(client: Client, asset_id: str) -> CommandResults | list[CommandResults]:
    """
    Retrieve tags associated to an asset.

    Args:
        client (Client): Client to use for API requests.
        asset_id (str): ID of the asset to retrieve information about.
    """
    tags = []

    try:
        tag_raw_data = client.get_asset_tags(asset_id)

    except DemistoException as e:
        if e.res is not None and e.res.status_code is not None and e.res.status_code == 404:
            return CommandResults(readable_output="Asset not found.")
    for tag in tag_raw_data.get("resources", []):
        tag_output = generate_new_dict(
            data=tag,
            name_mapping={
                "type": "Type",
                "riskModifier": "RiskModifier",
                "name": "Name",
                "created": "CreatedTime",
            },
            include_none=True,
        )
        tags.append(tag_output)

    readable_output = tableToMarkdown(
        name=f"Nexpose Asset Tags for Asset {asset_id}",
        t=tags,
        headers=["Type", "Name", "Risk Modifier", "Created Time"],
    )

    result = CommandResults(
        readable_output=readable_output,
        outputs_prefix="Nexpose.AssetTag",
        outputs=tags,
        outputs_key_field="type",
        raw_response=tag_raw_data,
    )

    return result


def get_asset_command(client: Client, asset_id: str) -> CommandResults | list[CommandResults]:
    """
    Retrieve information about an asset.

    Args:
        client (Client): Client to use for API requests.
        asset_id (str): ID of the asset to retrieve information about.
    """
    hr_asset_headers = [
        "AssetId",
        "Addresses",
        "Hardware",
        "Aliases",
        "HostType",
        "Site",
        "OperatingSystem",
        "CPE",
        "LastScanDate",
        "LastScanId",
        "RiskScore"
    ]

    hr_service_headers = [
        "Name",
        "Port",
        "Product",
        "Protocol",
    ]

    hr_software_headers = [
        "Software",
        "Version",
    ]

    hr_users_headers = [
        "FullName",
        "Name",
        "UserId",
    ]

    hr_vulnerability_headers = [
        "Id",
        "Title",
        "Malware",
        "Exploit",
        "CVSS",
        "Risk",
        "PublishedOn",
        "ModifiedOn",
        "Severity",
        "Instances",
    ]

    try:
        asset_data = client.get_asset(asset_id)

    except DemistoException as e:
        if e.res is not None and e.res.status_code is not None and e.res.status_code == 404:
            return CommandResults(readable_output="Asset not found.")

        raise e

    asset_output = generate_new_dict(
        data=asset_data,
        name_mapping={
            "id": "AssetId",
            "ip": "Address",
            "addresses.ip": "Addresses",
            "addresses.mac": "Hardware",
            "hostNames.name": "Aliases",
            "type": "HostType",
            "Site": "Site",
            "os": "OperatingSystem",
            "vulnerabilities.total": "Vulnerabilities",
            "cpe.v2.3": "CPE",
            "riskScore": "RiskScore",
        },
        include_none=True,
    )

    site = client.find_asset_site(asset_data["id"])

    if site is not None:
        asset_output["Site"] = site.name

    asset_output["LastScanDate"], asset_output["LastScanId"] = find_asset_last_scan_data(asset_data)
    asset_output["Software"] = None
    asset_output["Service"] = None
    asset_output["User"] = None

    if asset_data.get("software"):
        asset_output["Software"] = generate_new_dict(
            data=asset_data["software"],
            name_mapping={
                "description": "Software",
                "version": "Version",
            },
            include_none=True,
        )

    if asset_data.get("services"):
        asset_output["Service"] = generate_new_dict(
            data=asset_data["services"],
            name_mapping={
                "name": "Name",
                "port": "Port",
                "product": "Product",
                "protocol": "Protocol",
            },
            include_none=True,
        )

    if asset_data.get("users"):
        asset_output["User"] = generate_new_dict(
            data=asset_data["users"],
            name_mapping={
                "name": "Name",
                "fullName": "FullName",
                "id": "UserId",
            },
            include_none=True,
        )

    vulnerabilities = client.get_asset_vulnerabilities(asset_id=str(asset_data["id"]))
    asset_output["Vulnerability"] = []
    cve_indicators: list[CommandResults] = []

    for vulnerability in vulnerabilities:
        extra_info = client.get_vulnerability(vulnerability["id"])
        vulnerability_output = {
            "Id": vulnerability["id"],
            "Title": extra_info["title"],
            "Malware": extra_info["malwareKits"],
            "Exploit": extra_info["exploits"],
            "CVSS": extra_info["cvss"]["v2"]["score"],
            "Risk": extra_info["riskScore"],
            "PublishedOn": extra_info["published"],
            "ModifiedOn": extra_info["modified"],
            "Severity": extra_info["severity"],
            "Instances": vulnerability["instances"],
        }

        asset_output["Vulnerability"].append(vulnerability_output)

        if "cves" in extra_info:
            for cve in extra_info["cves"]:
                if "v3" in extra_info["cvss"]:
                    cvss_info = extra_info["cvss"]["v3"]
                    cvss_version = "3"

                else:
                    cvss_info = extra_info["cvss"]["v2"]
                    cvss_version = "2"

                cve_indicators.append(CommandResults(
                    readable_output=tableToMarkdown(cve, vulnerability_output,
                                                    hr_vulnerability_headers, removeNull=True),
                    indicator=Common.CVE(
                        id=cve,
                        cvss=None,  # type: ignore
                        cvss_score=cvss_info.get("score"),
                        cvss_vector=cvss_info.get("vector"),
                        cvss_version=cvss_version,
                        description=extra_info["description"]["text"],
                        modified=extra_info["modified"],
                        published=extra_info["published"],
                    )))

    readable_output = tableToMarkdown(
        name=f"Nexpose Asset {str(asset_data['id'])}",
        t=asset_output,
        headers=hr_asset_headers,
        removeNull=True
    )

    if asset_output.get("Vulnerability"):
        readable_output += tableToMarkdown(
            name="Vulnerabilities",
            t=asset_output["Vulnerability"],
            headers=hr_vulnerability_headers,
            removeNull=True
        )

    if asset_output.get("Software"):
        readable_output += tableToMarkdown(
            name="Software",
            t=asset_output["Software"],
            headers=hr_software_headers,
            removeNull=True
        )

    if asset_output.get("Service"):
        readable_output += tableToMarkdown(
            name="Services",
            t=asset_output["Service"],
            headers=hr_service_headers,
            removeNull=True
        )

    if asset_output.get("User"):
        readable_output += tableToMarkdown(
            name="Users",
            t=asset_output["User"],
            headers=hr_users_headers,
            removeNull=True
        )

    result = CommandResults(
        readable_output=readable_output,
        outputs_prefix="Nexpose.Asset",
        outputs=asset_output,
        outputs_key_field="AssetId",
        indicator=Common.Endpoint(
            id=asset_output.get("AssetId"),
            hostname=asset_output.get("Aliases"),
            ip_address=asset_output.get("Addresses"),
            os=asset_output.get("OperatingSystem"),
            vendor=VENDOR_NAME
        ),
        raw_response=asset_data,
    )

    if cve_indicators:
        return [*cve_indicators, result]

    return result


def get_assets_command(client: Client, page_size: str | None = None, page: str | None = None, sort: str | None = None,
                       limit: str | None = None) -> CommandResults | list[CommandResults]:
    """
    Retrieve a list of all assets.

    Args:
        client (Client): Client to use for API requests.
        page_size (str | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (str | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (str | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    page_size_int = arg_to_number(page_size, required=False)
    page_int = arg_to_number(page, required=False)
    limit_int = arg_to_number(limit, required=False)

    hr_headers = [
        "AssetId",
        "Address",
        "Name",
        "Site",
        "Exploits",
        "Malware",
        "OperatingSystem",
        "Vulnerabilities",
        "RiskScore",
        "Assessed",
        "LastScanDate",
        "LastScanId"
    ]

    assets_data = client.get_assets(
        page_size=page_size_int,
        page=page_int,
        sort=sort,
        limit=limit_int
    )

    if not assets_data:
        return CommandResults(
            readable_output="No assets found",
            raw_response=assets_data
        )

    results = []

    for asset_data in assets_data:
        asset_output = generate_new_dict(
            data=asset_data,
            name_mapping={
                "id": "AssetId",
                "ip": "Address",
                "addresses.ip": "Addresses",
                "hostName": "Name",
                "Site": "Site",
                "vulnerabilities.exploits": "Exploits",
                "vulnerabilities.malwareKits": "Malware",
                "os": "OperatingSystem",
                "vulnerabilities.total": "Vulnerabilities",
                "riskScore": "RiskScore",
                "assessedForVulnerabilities": "Assessed",
            },
            include_none=True,
        )

        site = client.find_asset_site(asset_data["id"])

        if site is not None:
            asset_output["Site"] = site.name

        asset_output["LastScanDate"], asset_output["LastScanId"] = find_asset_last_scan_data(asset_data)

        results.append(
            CommandResults(
                outputs_prefix="Nexpose.Asset",
                outputs_key_field="Id",
                outputs=asset_output,
                readable_output=tableToMarkdown(f"Nexpose Asset {str(asset_data['id'])}", asset_output,
                                                hr_headers, removeNull=True),
                raw_response=asset_data,
                indicator=Common.Endpoint(
                    id=asset_data["id"],
                    hostname=asset_data.get("hostName"),
                    ip_address=asset_data.get("ip"),
                    mac_address=asset_data.get("mac"),
                    os=asset_data.get("os"),
                    vendor=VENDOR_NAME
                )
            ))

    return results


def get_asset_vulnerability_command(client: Client, asset_id: str,
                                    vulnerability_id: str) -> CommandResults | list[CommandResults]:
    """
    Retrieve information about vulnerability findings on an asset.

    Args:
        client (Client): Client to use for API requests.
        asset_id (str): ID of the asset to retrieve information about.
        vulnerability_id (str): ID of the vulnerability to look for
    """
    hr_vulnerability_headers = [
        "Id",
        "Title",
        "Severity",
        "RiskScore",
        "CVSS",
        "CVSSV3",
        "Published",
        "Added",
        "Modified",
        "CVSSScore",
        "CVSSV3Score",
        "Categories",
        "CVES",
    ]

    hr_results_headers = [
        "Port",
        "Protocol",
        "Since",
        "Proof",
        "Status",
    ]

    hr_solutions_headers = [
        "Type",
        "Summary",
        "Steps",
        "Estimate",
        "AdditionalInformation",
    ]

    try:
        vulnerability_data = client.get_asset_vulnerability(
            asset_id=asset_id,
            vulnerability_id=vulnerability_id,
        )

    # A 404 error is returned when the asset or vulnerability could not be found,
    # or if the asset is not vulnerable to this vulnerability.
    # This code section is to separate the different errors and return a different message for each case.
    except DemistoException as e:
        if e.res is not None and e.res.status_code is not None and e.res.status_code == 404:
            try:
                client.get_asset(asset_id)

            except DemistoException as e2:
                if e2.res is not None and e2.res.status_code is not None and e2.res.status_code == 404:
                    raise ValueError("Asset not found.")

            try:
                client.get_vulnerability(vulnerability_id)

            except DemistoException as e2:
                if e2.res is not None and e2.res.status_code is not None and e2.res.status_code == 404:  # type: ignore
                    raise ValueError("Vulnerability not found.")

            return CommandResults(readable_output=f"Asset {asset_id} is not vulnerable to \"{vulnerability_id}\".")

        raise e

    # Add extra info about vulnerability
    vulnerability_extra_data = client.get_vulnerability(vulnerability_id=vulnerability_id)
    vulnerability_data.update(deepcopy(vulnerability_extra_data))

    vulnerability_outputs = generate_new_dict(
        data=vulnerability_extra_data,
        name_mapping={
            "id": "Id",
            "title": "Title",
            "severity": "Severity",
            "riskScore": "RiskScore",
            "cvss.v2.vector": "CVSS",
            "cvss.v3.vector": "CVSSV3",
            "published": "Published",
            "added": "Added",
            "modified": "Modified",
            "cvss.v2.score": "CVSSScore",
            "cvss.v3.score": "CVSSV3Score",
            "categories": "Categories",
            "cves": "CVES",
        },
        include_none=True,
    )

    results_output: list = []

    if vulnerability_data.get("results"):
        results_output = generate_new_dict(
            data=vulnerability_data["results"],
            name_mapping={
                "port": "Port",
                "protocol": "Protocol",
                "since": "Since",
                "proof": "Proof",
                "status": "Status",
            },
            include_none=True,
        )

    # Remove HTML tags
    for result in results_output:
        result["Proof"] = re.sub("<.*?>", "", result["Proof"])

    # Add solutions data
    solutions_output: list = []
    solutions = client.get_asset_vulnerability_solution(asset_id, vulnerability_id)
    vulnerability_data["solutions"] = solutions

    if solutions and solutions.get("resources"):
        solutions_output = generate_new_dict(
            data=solutions["resources"],
            name_mapping={
                "type": "Type",
                "summary.text": "Summary",
                "steps.text": "Steps",
                "estimate": "Estimate",
                "additionalInformation.text": "AdditionalInformation",
            },
            include_none=True,
        )

        for idx, _val in enumerate(solutions_output):
            solutions_output[idx]["Estimate"] = readable_duration_time(solutions_output[idx]["Estimate"])

    vulnerability_outputs["Check"] = results_output
    vulnerability_outputs["Solution"] = solutions_output

    vulnerabilities_md = tableToMarkdown(f"Vulnerability {str(vulnerability_id)}", vulnerability_outputs,
                                         hr_vulnerability_headers, removeNull=True)
    results_md = tableToMarkdown("Checks", results_output, hr_results_headers, removeNull=True) if len(
        results_output) > 0 else ""
    solutions_md = tableToMarkdown("Solutions", solutions_output, hr_solutions_headers,
                                   removeNull=True) if solutions_output is not None else ""

    indicators: list = []

    if vulnerability_data.get("cves"):
        for cve in vulnerability_data["cves"]:
            if "v3" in vulnerability_data["cvss"]:
                cvss_info = vulnerability_data["cvss"]["v3"]
                cvss_version = "3"

            else:
                cvss_info = vulnerability_data["cvss"]["v2"]
                cvss_version = "2"

            indicators.append(
                Common.CVE(
                    id=cve,
                    cvss=None,  # type: ignore
                    cvss_score=cvss_info.get("score"),
                    cvss_vector=cvss_info.get("vector"),
                    cvss_version=cvss_version,
                    description=vulnerability_data["description"]["text"],
                    modified=vulnerability_data["modified"],
                    published=vulnerability_data["published"],
                )
            )

    if len(indicators) == 0:
        indicators = [None]

    results = []

    for indicator in indicators:
        results.append(CommandResults(
            outputs_prefix="Nexpose.Asset",
            outputs_key_field="AssetId",
            outputs={
                "AssetId": asset_id,
                "Vulnerability": [vulnerability_outputs],
            },
            readable_output=vulnerabilities_md + results_md + solutions_md,
            indicator=indicator,
        ))

    return results


def get_generated_report_status_command(client: Client, report_id: str, instance_id: str) -> CommandResults:
    """
    Retrieve information about a generated report's status.

    Args:
        client (Client): Client to use for API requests.
        report_id (str): ID of the report to retrieve information about.
        instance_id (str): ID of the report instance to retrieve information about.
    """
    response = client.get_report_history(report_id, instance_id)

    context = {
        "ID": report_id,
        "InstanceID": instance_id,
        "Status": response.get("status", "unknown"),
    }

    hr = tableToMarkdown("Report Generation Status", context)

    return CommandResults(
        readable_output=hr,
        outputs_prefix="Nexpose.Report",
        outputs=context,
        outputs_key_field=["ID", "InstanceID"],
        raw_response=response,
    )


def get_report_templates_command(client: Client) -> CommandResults:
    """
    Retrieve information about all available report templates.

    Args:
        client (Client): Client to use for API requests.
    """
    hr_headers = [
        "Id",
        "Name",
        "Description",
        "Type"
    ]

    report_templates_data = client.get_report_templates()

    if not report_templates_data.get("resources"):
        return CommandResults(
            readable_output="No templates found",
            raw_response=report_templates_data,
        )

    report_templates_output = generate_new_dict(
        data=report_templates_data["resources"],
        name_mapping={
            "id": "Id",
            "name": "Name",
            "description": "Description",
            "type": "Type",
        },
        include_none=True,
    )

    return CommandResults(
        outputs_prefix="Nexpose.Template",
        outputs_key_field="Id",
        outputs=report_templates_output,
        readable_output=tableToMarkdown("Nexpose Templates", report_templates_output, hr_headers, removeNull=True),
        raw_response=report_templates_data,
    )


def get_scan_command(client: Client, scan_ids: str) -> list[CommandResults]:
    """
    Retrieve information about a specific or multiple scans.

    Args:
        client (Client): Client to use for API requests.
        scan_ids (str | list): ID of the scan to retrieve.
    """
    scan_ids_list = argToList(scan_ids)

    results = []

    for scan_id in scan_ids_list:
        try:
            scan_data = client.get_scan(scan_id)

        except DemistoException as e:
            if e.res is not None and e.res.status_code is not None and e.res.status_code == 404:
                scan_entry = CommandResults(readable_output=f"Scan for ID {scan_id} was not found.")

            else:
                raise e

        else:
            scan_entry = get_scan_entry(scan_data)

        results.append(scan_entry)

    return results


def get_scans_command(client: Client, active: str | None = None, page_size: str | None = None,
                      page: str | None = None, sort: str | None = None, limit: str | None = None) -> CommandResults:
    """
    Retrieve a list of all scans.

    Args:
        client (Client): Client to use for API requests.
        active (str | None, optional): Whether to return active scans or not. Defaults to False.
        page_size (str | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (str | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (str | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    page_size_int = arg_to_number(page_size, required=False)
    page_int = arg_to_number(page, required=False)
    limit_int = arg_to_number(limit, required=False)

    scans_data = client.get_scans(
        active=argToBoolean(active) if active is not None else None,
        page_size=page_size_int,
        page=page_int,
        sort=sort,
        limit=limit_int,
    )

    if not scans_data:
        return CommandResults(
            readable_output="No scans found",
            raw_response=scans_data,
        )

    normalized_scans = [normalize_scan_data(scan) for scan in scans_data]

    scan_hr = tableToMarkdown(
        name="Nexpose Scans",
        t=normalized_scans,
        headers=[
            "Id",
            "ScanType",
            "ScanName",
            "StartedBy",
            "Assets",
            "TotalTime",
            "Completed",
            "Status",
            "Message",
        ],
        removeNull=True)

    return CommandResults(
        outputs_prefix="Nexpose.Scan",
        outputs_key_field="Id",
        outputs=normalized_scans,
        readable_output=scan_hr,
        raw_response=scans_data,
    )


def get_sites_command(client: Client, page_size: str | None = None, page: str | None = None,
                      sort: str | None = None, limit: str | None = None) -> CommandResults:
    """
    Retrieve a list of sites.

    Args:
        client (Client): Client to use for API requests.
        page_size (str | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (str | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (str | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    hr_headers = [
        "Id",
        "Name",
        "Assets",
        "Vulnerabilities",
        "Risk",
        "Type",
        "LastScan"
    ]

    page_size_int = arg_to_number(page_size, required=False)
    page_int = arg_to_number(page, required=False)
    limit_int = arg_to_number(limit, required=False)

    sites_data = client.get_sites(
        page_size=page_size_int,
        page=page_int,
        sort=sort,
        limit=limit_int,
    )

    if not sites_data:
        return CommandResults(
            readable_output="No sites found",
            raw_response=sites_data,
        )

    sites_output = generate_new_dict(
        data=sites_data,
        name_mapping={
            "id": "Id",
            "name": "Name",
            "assets": "Assets",
            "vulnerabilities.total": "Vulnerabilities",
            "riskScore": "Risk",
            "type": "Type",
            "lastScanTime": "LastScan",
        },
        include_none=True,
    )

    return CommandResults(
        outputs_prefix="Nexpose.Site",
        outputs_key_field="Id",
        outputs=sites_output,
        readable_output=tableToMarkdown("Nexpose Sites", sites_output, hr_headers, removeNull=True),
        raw_response=sites_data,
    )


def list_scan_schedule_command(client: Client, site_id: str | None = None, site_name: str | None = None,
                               schedule_id: str | None = None, limit: str | None = None) -> CommandResults:
    """
    Retrieve information about scan schedules for a specific site or a specific scan schedule.

    Args:
        client (Client): Client to use for API requests.
        site_id (str | None, optional): ID of a site to retrieve scan schedules from.
        site_name (str | None, optional): Name of a site to retrieve scan schedules from.
            Can be used instead of "site_id".
        schedule_id (str): ID of a specific scan schedule to retrieve.
            Defaults to None (Results in getting all scan schedules for the site).
        limit (str | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    hr_headers = [
        "Enable",
        "StartDate",
        "Name",
        "MaxDuration",
        "Repeat",
        "NextStart",
    ]

    limit_int = arg_to_number(limit, required=False)

    if not schedule_id:
        scan_schedules_data = client.get_scan_schedules(site_id=site.id)

        if limit_int is not None and limit_int < len(scan_schedules_data):
            scan_schedules_data = scan_schedules_data[:limit_int]

    else:
        scan_schedules_data = [client.get_scan_schedule(
            site_id=site.id,
            schedule_id=schedule_id,
        )]

    if not scan_schedules_data:
        return CommandResults(
            readable_output="No scan schedules were found for the site.",
            raw_response=scan_schedules_data,
        )

    hr_outputs = generate_new_dict(
        data=scan_schedules_data,
        name_mapping={
            "id": "Id",
            "enabled": "Enable",
            "start": "StartDate",
            "scanName": "Name",
            "duration": "MaxDuration",
            "repeat.every": "Repeat",
            "nextRuntimes": "NextStart",
        },
    )

    for scan_schedule in hr_outputs:
        if scan_schedule.get("MaxDuration"):
            scan_schedule["MaxDuration"] = readable_duration_time(scan_schedule["MaxDuration"])
        if scan_schedule.get("Repeat"):
            scan_schedule["Repeat"] = "every " + scan_schedule["Repeat"]

    return CommandResults(
        outputs_prefix="Nexpose.ScanSchedule",
        outputs_key_field="id",
        outputs=scan_schedules_data,
        readable_output=tableToMarkdown("Nexpose Scan Schedules", hr_outputs, hr_headers, removeNull=True),
        raw_response=scan_schedules_data,
    )


def list_shared_credential_command(client: Client, credential_id: str | None = None,
                                   limit: str | None = None) -> CommandResults:
    """
    Retrieve information about all or a specific vulnerability.

    Args:
        client (Client): Client to use for API requests.
        credential_id (str | None, optional): ID of a specific shared credential to retrieve.
            Defaults to None (Results in getting all vulnerabilities).
        limit (str | None, optional): Limit the number of credentials to return. None means to not use a limit.
            Defaults to None.
    """
    hr_headers = [
        "Id",
        "Name",
        "Service",
        "Domain",
        "UserName",
        "AvailableToSites",
    ]

    limit_int = arg_to_number(limit, required=False)

    if not credential_id:
        shared_credentials_data = client.get_shared_credentials()

        if limit_int is not None and limit_int < len(shared_credentials_data):
            shared_credentials_data = shared_credentials_data[:limit_int]

    else:
        shared_credentials_data = [client.get_shared_credential(credential_id)]

    if not shared_credentials_data:
        return CommandResults(
            readable_output="No shared credentials were found.",
            raw_response=shared_credentials_data,
        )

    shared_credentials_hr = generate_new_dict(
        data=shared_credentials_data,
        name_mapping={
            "id": "Id",
            "name": "Name",
            "account.service": "Service",
            "account.domain": "Domain",
            "account.username": "UserName",
        },
    )

    for shared_credential in shared_credentials_hr:
        if shared_credential.get("sites"):
            shared_credential["AvailableToSites"] = len(shared_credential["sites"])

    return CommandResults(
        outputs_prefix="Nexpose.SharedCredential",
        outputs_key_field="id",
        outputs=shared_credentials_data,
        readable_output=tableToMarkdown("Nexpose Shared Credentials", shared_credentials_hr,
                                        hr_headers, removeNull=True),
        raw_response=shared_credentials_data,
    )


def list_assigned_shared_credential_command(client: Client, site_id: str | None = None, site_name: str | None = None,
                                            limit: str | None = None) -> CommandResults:
    """
    Retrieve information about shared credentials for a specific site.

    Args:
        client (Client): Client to use for API requests.
        site_id (str | None, optional): ID of a site to retrieve shared credentials from.
        site_name (str | None, optional): Name of a site to retrieve shared credentials from.
            Can be used instead of "site_id".
        limit (str | None, optional): Limit the number of credentials to return. None means to not use a limit.
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    hr_headers = [
        "Id",
        "Name",
        "Service",
        "Enabled",
    ]

    limit_int = arg_to_number(limit, required=False)

    response_data = client.get_assigned_shared_credentials(site_id=site.id)

    if not response_data:
        site_id = site.name if site.name else site.id

        return CommandResults(
            readable_output=f"No assigned shared credentials were found for site \"{site_id}\".",
            raw_response=response_data,
        )

    if limit_int:
        response_data = response_data[:limit_int]

    assigned_shared_credentials_hr = generate_new_dict(
        data=response_data,
        name_mapping={
            "id": "Id",
            "name": "Name",
            "service": "Service",
            "enabled": "Enabled",
        },
    )

    return CommandResults(
        outputs_prefix="Nexpose.AssignedSharedCredential",
        outputs_key_field="id",
        outputs=response_data,
        readable_output=tableToMarkdown("Nexpose Assigned Shared Credentials",
                                        assigned_shared_credentials_hr, hr_headers, removeNull=True),
        raw_response=response_data,
    )


def list_site_scan_credential_command(client: Client, site_id: str | None = None, site_name: str | None = None,
                                      credential_id: str | None = None, limit: str | None = None) -> CommandResults:
    """
    Retrieve information about all or a specific scan credential.

    Args:
        client (Client): Client to use for API requests.
        site_id (str | None, optional): ID of a site to retrieve scan credentials from.
        site_name (str | None, optional): Name of a site to retrieve scan credentials from.
            Can be used instead of "site_id".
        credential_id (str | None, optional): ID of a specific scan credential to retrieve.
        limit (str | None, optional): Limit the number of credentials to return. None means to not use a limit.
            Defaults to None.
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    hr_headers = [
        "Id",
        "Enabled",
        "Name",
        "Service",
        "UserName",
        "RestrictToHostName",
        "RestrictToPort",
    ]

    limit_int = arg_to_number(limit, required=False)

    if credential_id is not None:
        site_scan_credentials_data = client.get_site_scan_credential(site_id=site.id, credential_id=credential_id)
        site_scan_credentials_data = [site_scan_credentials_data]

    else:
        site_scan_credentials_data = client.get_site_scan_credentials(site_id=site.id)

    if not site_scan_credentials_data:
        site_id = site.name if site.name else site.id
        return CommandResults(
            readable_output=f"No site scan credentials were found for site \"{site_id}\".",
            raw_response=site_scan_credentials_data,
        )

    if limit_int and len(site_scan_credentials_data) > limit_int:
        site_scan_credentials_data = site_scan_credentials_data[:limit_int]

    site_scan_credentials_hr = generate_new_dict(
        data=site_scan_credentials_data,
        name_mapping={
            "id": "Id",
            "enabled": "Enabled",
            "name": "Name",
            "account.service": "Service",
            "account.username": "UserName",
            "hostRestriction": "RestrictToHostName",
            "portRestriction": "RestrictToPort",
        },
    )

    return CommandResults(
        outputs_prefix="Nexpose.SiteScanCredential",
        outputs_key_field="id",
        outputs=site_scan_credentials_data,
        readable_output=tableToMarkdown(
            "Nexpose Site Scan Credentials", site_scan_credentials_hr, hr_headers, removeNull=True),
        raw_response=site_scan_credentials_data,
    )


def list_vulnerability_command(client: Client, vulnerability_id: str | None = None, page_size: str | None = None,
                               page: str | None = None, sort: str | None = None,
                               limit: str | None = None) -> CommandResults:
    """
    Retrieve information about all or a specific vulnerability.

    Args:
        client (Client): Client to use for API requests.
        vulnerability_id (str | None, optional): ID of a specific vulnerability to retrieve.
            Defaults to None (Results in getting all vulnerabilities).
        page_size (str | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (str | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (str | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    hr_headers = [
        "Title",
        "MalwareKits",
        "Exploits",
        "CVSS",
        "CVSSv3",
        "Risk",
        "PublishedOn",
        "ModifiedOn",
        "Severity",
    ]

    page_size_int = arg_to_number(page_size, required=False)
    page_int = arg_to_number(page, required=False)
    limit_int = arg_to_number(limit, required=False)

    if not vulnerability_id:
        vulnerabilities_data = client.get_vulnerabilities(
            page_size=page_size_int,
            page=page_int,
            sort=sort,
            limit=limit_int,
        )

    else:
        vulnerabilities_data = [client.get_vulnerability(vulnerability_id)]

    if not vulnerabilities_data:
        return CommandResults(
            readable_output="No vulnerability exceptions were found.",
            raw_response=vulnerabilities_data,
        )

    vulnerabilities_hr = generate_new_dict(
        data=vulnerabilities_data,
        name_mapping={
            "title": "Title",
            "malwareKits": "MalwareKits",
            "exploits": "Exploits",
            "cvss.v2.score": "CVSS",
            "cvss.v3.score": "CVSSv3",
            "riskScore": "Risk",
            "published": "PublishedOn",
            "modified": "ModifiedOn",
            "severity": "Severity",
        },
    )

    return CommandResults(
        outputs_prefix="Nexpose.Vulnerability",
        outputs_key_field="id",
        outputs=vulnerabilities_data,
        readable_output=tableToMarkdown(
            "Nexpose Vulnerabilities", vulnerabilities_hr, hr_headers, removeNull=True),
        raw_response=vulnerabilities_data,
    )


def list_vulnerability_exceptions_command(client: Client, vulnerability_exception_id: str | None = None,
                                          page_size: str | None = None, page: str | None = None,
                                          sort: str | None = None, limit: str | None = None) -> CommandResults:
    """
    Retrieve information about all or a specific vulnerability exception.

    Args:
        client (Client): Client to use for API requests.
        vulnerability_exception_id (str | None, optional): ID of a specific vulnerability exception to retrieve.
            Defaults to None (Results in getting all vulnerability exceptions).
        page_size (str | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (str | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (str | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    hr_headers = [
        "Id",
        "Vulnerability",
        "ExceptionScope",
        "Reason",
        "ReportedBy",
        "ReportedOn",
        "ReviewStatus",
        "ReviewedOn",
        "ExpiresOn",
    ]

    page_size_int = arg_to_number(page_size, required=False)
    page_int = arg_to_number(page, required=False)
    limit_int = arg_to_number(limit, required=False)

    if not vulnerability_exception_id:
        vulnerability_exceptions_data = client.get_vulnerability_exceptions(
            page_size=page_size_int,
            page=page_int,
            sort=sort,
            limit=limit_int,
        )

    else:
        vulnerability_exceptions_data = [client.get_vulnerability_exception(vulnerability_exception_id)]

    if not vulnerability_exceptions_data:
        return CommandResults(
            readable_output="No vulnerability exceptions were found.",
            raw_response=vulnerability_exceptions_data,
        )

    hr_vulnerability_exceptions_data = generate_new_dict(
        data=vulnerability_exceptions_data,
        name_mapping={
            "id": "Id",
            "scope.vulnerability": "Vulnerability",
            "scope.type": "ExceptionScope",
            "submit.reason": "Reason",
            "submit.name": "ReportedBy",
            "state": "ReviewStatus",
            "review.date": "ReviewedOn",
            "expires": "ExpiresOn",
        },
    )

    return CommandResults(
        outputs_prefix="Nexpose.VulnerabilityException",
        outputs_key_field="id",
        outputs=vulnerability_exceptions_data,
        readable_output=tableToMarkdown(
            "Nexpose Vulnerability Exceptions", hr_vulnerability_exceptions_data, hr_headers, removeNull=True),
        raw_response=vulnerability_exceptions_data,
    )


def search_assets_command(client: Client, query: str | None = None, ip_address_is: str | None = None,
                          host_name_is: str | None = None, risk_score_higher_than: str | None = None,
                          vulnerability_title_contains: str | None = None, site_id_in: str | None = None,
                          site_name_in: str | None = None, match: str | None = None, page_size: str | None = None,
                          page: str | None = None, sort: str | None = None,
                          limit: str | None = None) -> CommandResults | list[CommandResults]:
    """
    Retrieve a list of all assets with access permissions that match the provided search filters.

    Args:
        client (Client): Client to use for API requests.
        query (str | None, optional): String based filters to use separated by ';'. Defaults to None.
        ip_address_is (str | None, optional): IP address(es) to filter for. Defaults to None.
        host_name_is (str | None, optional): Hostname(s) to filter for. Defaults to None.
        risk_score_higher_than (str | None, optional): Filter for risk scores that are higher than the provided value.
            Defaults to None.
        vulnerability_title_contains (str | None, optional): Filter for vulnerability titles that contain the provided value.
            Defaults to None. Defaults to None.
        site_id_in (str | None, optional): Filter for assets that are under a specific site(s).
            Defaults to None.
        site_name_in (str | None, optional): Filter for assets that are under a specific site(s).
            Defaults to None.
        match (str | None, optional): Determine if the filters should match all or any of the filters.
            Can be either "all" or "any". Defaults to None (Results in using MATCH_DEFAULT_VALUE).
        page_size (str | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (str | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (str | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    # sites: list[Site] = []

    hr_headers = [
        "AssetId",
        "Address",
        "Name",
        "Site",
        "Exploits",
        "Malware",
        "OperatingSystem",
        "RiskScore",
        "Assessed",
        "LastScanDate",
        "LastScanId"
    ]

    page_size_int = arg_to_number(page_size, required=False)
    page_int = arg_to_number(page, required=False)
    limit_int = arg_to_number(limit, required=False)

    if not match:
        match = MATCH_DEFAULT_VALUE

    filters_data = parse_asset_filters(
        client=client,
        ip_address_is=ip_address_is,
        host_name_is=host_name_is,
        risk_score_higher_than=risk_score_higher_than,
        vulnerability_title_contains=vulnerability_title_contains,
        site_id_in=site_id_in,
        site_name_in=site_name_in,
        query=query)

    assets = client.search_assets(
        filters=convert_asset_search_filters(filters_data),
        match=match,
        page_size=page_size_int,
        page=page_int,
        sort=sort,
        limit=limit_int,
    )

    if not assets:
        return CommandResults(readable_output="No assets were found")

    results = []

    for asset in assets:
        asset_output = generate_new_dict(
            data=asset,
            name_mapping={
                "id": "AssetId",
                "ip": "Address",
                "addresses.ip": "Addresses",
                "hostName": "Name",
                "Site": "Site",
                "vulnerabilities.exploits": "Exploits",
                "vulnerabilities.malwareKits": "Malware",
                "os": "OperatingSystem",
                "vulnerabilities.total": "Vulnerabilities",
                "riskScore": "RiskScore",
                "assessedForVulnerabilities": "Assessed",
            },
            include_none=True,
        )

        site = client.find_asset_site(asset["id"])

        if site is not None:
            asset_output["Site"] = site.name

        asset_output["LastScanDate"], asset_output["LastScanId"] = find_asset_last_scan_data(asset)

        results.append(
            CommandResults(
                outputs_prefix="Nexpose.Asset",
                outputs_key_field="Id",
                outputs=asset_output,
                readable_output=tableToMarkdown(f"Nexpose Asset {str(asset['id'])}", asset_output,
                                                hr_headers, removeNull=True),
                raw_response=asset,
                indicator=Common.Endpoint(
                    id=asset["id"],
                    hostname=asset.get("hostName"),
                    ip_address=asset.get("ip"),
                    mac_address=asset.get("mac"),
                    os=asset.get("os"),
                    vendor=VENDOR_NAME
                )
            ))

    return results


def set_assigned_shared_credential_status_command(client: Client, credential_id: str, enabled: bool,
                                                  site_id: str | None = None,
                                                  site_name: str | None = None) -> CommandResults:
    """
    Enable or disable a shared credential.

    Args:
        client (Client): Client to use for API requests.
        credential_id (str): ID of the shared credential to enable or disable.
        enabled (bool): Whether to enable or disable the shared credential.
        site_id (Site): ID of a site to use for API requests.
        site_name (Site): Name of a site to use for API requests. Can be used instead of "site_id".

    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    response_data = client.set_assigned_shared_credential_status(
        site_id=site.id,
        shared_credential_id=credential_id,
        enabled=enabled,
    )

    return CommandResults(
        readable_output=f"Shared credential \"{credential_id}\" enablement has been set to \"{str(enabled).lower()}\".",
        raw_response=response_data,
    )


def start_assets_scan_command(client: Client, ip_addresses: str | None = None,
                              hostnames: str | None = None, name: str | None = None) -> CommandResults:
    """
    Start a scan on the provided assets.

    Note:
        Both `ip_addresses` and `hostnames` are optional, but at least one of them must be provided.

    Args:
        client (Client): Client to use for API requests.
        ip_addresses (str | None, optional): IP(s) of assets to scan. Defaults to None
        hostnames (str | None, optional): Hostname(s) of assets to scan. Defaults to None
        name (str | None): Name to set for the new scan.
            Defaults to None (Results in using a "scan <date>" format).
    """
    if ip_addresses is None and hostnames is None:
        raise ValueError("At least one of \"ips\" and \"hostnames\" must be provided.")

    ip_addresses_list = None
    hostnames_list = None
    asset_filter = ""

    if ip_addresses is not None:
        ip_addresses_list = argToList(ip_addresses)
        asset_filter = "ip-address is " + ip_addresses_list[0]

    if hostnames is not None:
        hostnames_list = argToList(hostnames)
        asset_filter = "host-name is " + hostnames_list[0]

    if not name:
        name = f"scan {datetime.now()}"

    asset_data = client.search_assets(filters=convert_asset_search_filters(asset_filter), match="all")

    if not asset_data:
        return CommandResults(
            readable_output="Could not find assets.",
            raw_response=asset_data,
        )

    site = client.find_asset_site(asset_data[0]["id"])

    if site is None:
        return CommandResults(
            readable_output="Could not find site.",
            raw_response=site,
        )

    hosts = []

    if ip_addresses_list:
        hosts.extend(ip_addresses_list)

    if hostnames_list:
        hosts.extend(hostnames_list)

    scan_response = client.start_site_scan(
        site_id=site.id,
        scan_name=name,
        hosts=hosts
    )

    if "id" not in scan_response:
        return CommandResults(
            readable_output="Could not start scan.",
            raw_response=scan_response,
        )

    return get_scan_entry(client.get_scan(scan_response["id"]))


def start_site_scan_command(client: Client, site_id: str | None = None, site_name: str | None = None,
                            hosts: str | None = None, name: str | None = None) -> CommandResults:
    """
    Start a scan for a specific site.

    Args:
        client (Client): Client to use for API requests.
        site_id (str | None, optional): ID of a site to start a scan on.
        site_name (str | None, optional): Name of a site to start a scan on. Can be used instead of "site_id".
        hosts (str | None): Hosts to scan. Defaults to None (Results in scanning all hosts).
        name (str | None): Name to set for the new scan.
            Defaults to None (Results in using a "scan <date>" format).
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    scan_response = client.start_site_scan(
        site_id=site.id,
        scan_name=name if name else f"scan {datetime.now()}",
        hosts=argToList(hosts) if hosts else None,  # type: ignore[arg-type]
    )

    if not scan_response or "id" not in scan_response:
        return CommandResults(
            readable_output="Could not start scan",
            raw_response=scan_response,
        )

    scan_data = client.get_scan(scan_response["id"])
    return get_scan_entry(scan_data)


def update_scan_command(client: Client, scan_id: str, scan_status: ScanStatus) -> CommandResults:
    """
    Update status for a specific scan.

    Args:
        client (Client): Client to use for API requests.
        scan_id (str): ID of the scan to update.
        scan_status (ScanStatus): Status to set the scan to.
    """
    response = client.update_scan_status(scan_id, scan_status)

    return CommandResults(
        readable_output=f"Successfully updated scan status to \"{scan_status.value}\"",
        raw_response=response,
    )


def update_shared_credential_command(client: Client, shared_credential_id: str, name: str, site_assignment: str,
                                     service: str, authentication_type: str | None = None,
                                     community_name: str | None = None, database: str | None = None,
                                     description: str | None = None, domain: str | None = None,
                                     host_restriction: str | None = None, http_realm: str | None = None,
                                     notes_id_password: str | None = None, ntlm_hash: str | None = None,
                                     oracle_enumerate_sids: str | None = None,
                                     oracle_listener_password: str | None = None,
                                     oracle_sid: str | None = None, password: str | None = None,
                                     port_restriction: str | None = None, sites: str | None = None,
                                     privacy_password: str | None = None, privacy_type: str | None = None,
                                     ssh_key_pem: str | None = None, ssh_permission_elevation: str | None = None,
                                     ssh_permission_elevation_password: str | None = None,
                                     ssh_permission_elevation_username: str | None = None,
                                     ssh_private_key_password: str | None = None,
                                     use_windows_authentication: str | None = None,
                                     username: str | None = None) -> CommandResults:
    """
    Update an existing shared credential.

    Args:
        client (Client): Client to use for API requests.
        shared_credential_id (str): ID of the shared credential to update.
        name (str): Name of the credential.
        site_assignment (str): Site assignment configuration for the credential.
        service (str): Credential service type.
        authentication_type (str): SNMPv3 authentication type for the credential.
        community_name (str | None, optional): SNMP community for authentication.
        database (str | None, optional): Database name.
        description (str | None, optional): Description for the credential.
        domain (str | None, optional): Domain address.
        host_restriction (str | None, optional): Hostname or IP address to restrict the credentials to.
        http_realm (str | None, optional): HTTP realm.
        notes_id_password (str | None, optional): Password for the notes account that will be used for authenticating.
        ntlm_hash (str | None, optional): NTLM password hash.
        oracle_enumerate_sids (str | None, optional): Whether the scan engine should attempt to enumerate
            SIDs from the environment.
        oracle_listener_password (str | None, optional): The Oracle Net Listener password.
            Used to enumerate SIDs from the environment.
        oracle_sid (str | None, optional): Oracle database name.
        password (str | None, optional): Password for the credential.
        port_restriction (str | None, optional): Further restricts the credential to attempt to authenticate
            on a specific port. Can be used only if `host_restriction` is used.
        sites (str | None, optional): List of site IDs for the shared credential that are explicitly assigned
            access to the shared scan credential, allowing it to use the credential during a scan.
        privacy_password (str | None, optional): SNMPv3 privacy password to use.
        privacy_type (str | None, optional): SNMPv3 Privacy protocol to use.
        ssh_key_pem (str | None, optional): PEM formatted private key.
        ssh_permission_elevation (str | None, optional): Elevation type to use for scans.
        ssh_permission_elevation_password (str | None, optional): Password to use for elevation.
        ssh_permission_elevation_username (str | None, optional): Username to use for elevation.
        ssh_private_key_password (str | None, optional): Password for the private key.
        use_windows_authentication (str | None, optional): Whether to use Windows authentication.
        username (str | None, optional): Username for the credential.
    """
    oracle_enumerate_sids_list = None
    sites_list = None
    snmpv3_authentication_type_enum = None
    snmpv3_privacy_type_enum = None
    ssh_permission_elevation_enum = None
    use_windows_authentication_bool = None

    if oracle_enumerate_sids is not None:
        oracle_enumerate_sids_list = argToBoolean(oracle_enumerate_sids)

    if sites is not None:
        sites_list = [int(item) for item in argToList(sites)]

    if authentication_type is not None:
        snmpv3_authentication_type_enum = SNMPv3AuthenticationType[authentication_type]

    if privacy_type is not None:
        snmpv3_privacy_type_enum = SNMPv3PrivacyType[privacy_type]

    if ssh_permission_elevation is not None:
        ssh_permission_elevation_enum = SSHElevationType[ssh_permission_elevation]

    if use_windows_authentication is not None:
        use_windows_authentication_bool = argToBoolean(use_windows_authentication)

    response_data = client.update_shared_credential(
        shared_credential_id=shared_credential_id,
        name=name,
        site_assignment=SharedCredentialSiteAssignment[site_assignment],
        service=CredentialService[service],
        database_name=database,
        description=description,
        domain=domain,
        host_restriction=host_restriction,
        http_realm=http_realm,
        notes_id_password=notes_id_password,
        ntlm_hash=ntlm_hash,
        oracle_enumerate_sids=oracle_enumerate_sids_list,
        oracle_listener_password=oracle_listener_password,
        oracle_sid=oracle_sid,
        password=password,
        port_restriction=port_restriction,
        sites=sites_list,
        snmp_community_name=community_name,
        snmpv3_authentication_type=snmpv3_authentication_type_enum,
        snmpv3_privacy_password=privacy_password,
        snmpv3_privacy_type=snmpv3_privacy_type_enum,
        ssh_key_pem=ssh_key_pem,
        ssh_permission_elevation=ssh_permission_elevation_enum,
        ssh_permission_elevation_password=ssh_permission_elevation_password,
        ssh_permission_elevation_username=ssh_permission_elevation_username,
        ssh_private_key_password=ssh_private_key_password,
        use_windows_authentication=use_windows_authentication_bool,
        username=username,
    )

    return CommandResults(
        readable_output=f"Shared credential with ID {shared_credential_id} has been updated.",
        raw_response=response_data
    )


def update_site_scan_credential_command(client: Client, credential_id: str, name: str, service: str,
                                        site_id: str | None = None, site_name: str | None = None,
                                        authentication_type: str | None = None, community_name: str | None = None,
                                        database: str | None = None, description: str | None = None,
                                        domain: str | None = None, host_restriction: str | None = None,
                                        http_realm: str | None = None, notes_id_password: str | None = None,
                                        ntlm_hash: str | None = None, oracle_enumerate_sids: str | None = None,
                                        oracle_listener_password: str | None = None,
                                        oracle_sid: str | None = None, password: str | None = None,
                                        port_restriction: str | None = None, privacy_password: str | None = None,
                                        privacy_type: str | None = None, ssh_key_pem: str | None = None,
                                        ssh_permission_elevation: str | None = None,
                                        ssh_permission_elevation_password: str | None = None,
                                        ssh_permission_elevation_username: str | None = None,
                                        ssh_private_key_password: str | None = None,
                                        use_windows_authentication: str | None = None,
                                        username: str | None = None) -> CommandResults:
    """
    Update an existing site scan credential.

    Args:
        client (Client): Client to use for API requests.
        credential_id (str): ID of the site scan credential to update.
        name (str): Name of the credential.
        service (str): Credential service type.
        site_id (str | None, optional): ID of a site to update the site scan credential for.
        site_name (str | None, optional): Name of a site to update the site scan credential for.
            Can be used instead of "site_id".
        authentication_type (str | None, optional): SNMPv3 authentication type for the credential.
        community_name (str | None, optional): SNMP community for authentication.
        database (str | None, optional): Database name.
        description (str | None, optional): Description for the credential.
        domain (str | None, optional): Domain address.
        host_restriction (str | None, optional): Hostname or IP address to restrict the credentials to.
        http_realm (str | None, optional): HTTP realm.
        notes_id_password (str | None, optional): Password for the notes account that will be used for authenticating.
        ntlm_hash (str | None, optional): NTLM password hash.
        oracle_enumerate_sids (str | None, optional): Whether the scan engine should attempt to enumerate
            SIDs from the environment.
        oracle_listener_password (str | None, optional): The Oracle Net Listener password.
            Used to enumerate SIDs from the environment.
        oracle_sid (str | None, optional): Oracle database name.
        password (str | None, optional): Password for the credential.
        port_restriction (str | None, optional): Further restricts the credential to attempt to authenticate
            on a specific port. Can be used only if `host_restriction` is used.
        privacy_password (str | None, optional): SNMPv3 privacy password to use.
        privacy_type (str | None, optional): SNMPv3 Privacy protocol to use.
        ssh_key_pem (str | None, optional): PEM formatted private key.
        ssh_permission_elevation (str | None, optional): Elevation type to use for scans.
        ssh_permission_elevation_password (str | None, optional): Password to use for elevation.
        ssh_permission_elevation_username (str | None, optional): Username to use for elevation.
        ssh_private_key_password (str | None, optional): Password for the private key.
        use_windows_authentication (str | None, optional): Whether to use Windows authentication.
        username (str | None, optional): Username for the credential.
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    oracle_enumerate_sids_bool = None
    snmpv3_authentication_type_enum = None
    snmpv3_privacy_type_enum = None
    ssh_permission_elevation_enum = None
    use_windows_authentication_bool = None

    if oracle_enumerate_sids is not None:
        oracle_enumerate_sids_bool = argToBoolean(oracle_enumerate_sids)

    if authentication_type is not None:
        snmpv3_authentication_type_enum = SNMPv3AuthenticationType[authentication_type]

    if privacy_type is not None:
        snmpv3_privacy_type_enum = SNMPv3PrivacyType[privacy_type]

    if ssh_permission_elevation is not None:
        ssh_permission_elevation_enum = SSHElevationType[ssh_permission_elevation]

    if use_windows_authentication is not None:
        use_windows_authentication_bool = argToBoolean(use_windows_authentication)

    response_data = client.update_site_scan_credential(
        site_id=site.id,
        credential_id=credential_id,
        name=name,
        service=CredentialService[service],
        database_name=database,
        description=description,
        domain=domain,
        host_restriction=host_restriction,
        http_realm=http_realm,
        notes_id_password=notes_id_password,
        ntlm_hash=ntlm_hash,
        oracle_enumerate_sids=oracle_enumerate_sids_bool,
        oracle_listener_password=oracle_listener_password,
        oracle_sid=oracle_sid,
        password=password,
        port_restriction=port_restriction,
        snmp_community_name=community_name,
        snmpv3_authentication_type=snmpv3_authentication_type_enum,
        snmpv3_privacy_password=privacy_password,
        snmpv3_privacy_type=snmpv3_privacy_type_enum,
        ssh_key_pem=ssh_key_pem,
        ssh_permission_elevation=ssh_permission_elevation_enum,
        ssh_permission_elevation_password=ssh_permission_elevation_password,
        ssh_permission_elevation_username=ssh_permission_elevation_username,
        ssh_private_key_password=ssh_private_key_password,
        use_windows_authentication=use_windows_authentication_bool,
        username=username,
    )

    return CommandResults(
        readable_output=f"Site scan credential with ID {credential_id} has been updated.",
        raw_response=response_data,
    )


def update_scan_schedule_command(client: Client, schedule_id: int, on_scan_repeat: str, start: str,
                                 site_id: str | None = None, site_name: str | None = None,
                                 excluded_asset_groups: str | None = None, excluded_targets: str | None = None,
                                 included_asset_groups: str | None = None, included_targets: str | None = None,
                                 duration_days: str | None = None, duration_hours: str | None = None,
                                 duration_minutes: str | None = None, enabled: str | None = None,
                                 frequency: str | None = None, interval: str | None = None,
                                 scan_name: str | None = None, date_of_month: str | None = None,
                                 scan_template_id: str | None = None) -> CommandResults:
    """
    Update a site scan schedule.

    Args:
        client (Client): Client to use for API requests.
        schedule_id (str): ID of the scan schedule to update.
        on_scan_repeat (str): The desired behavior of a repeating scheduled scan
            when the previous scan was paused due to reaching its maximum duration.
        start (str): The scheduled start date and time formatted in ISO 8601 format.
        site_id (str | None, optional): ID of a site to create a scheduled scan for.
        site_name (str | None, optional): Name of a site to create a scheduled scan for.
            Can be used instead of "site_id".
        excluded_asset_groups (str | None, optional): Asset groups to exclude from the scan.
        excluded_targets (str | None, optional): Addresses to exclude from the scan. Each address is a string that
            can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
        included_asset_groups (str | None, optional): Asset groups to include in the scan.
        included_targets (str | None, optional): Addresses to include in the scan.  Each address is a string that
            can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
        duration_days (str | None, optional): Maximum duration of the scan in days.
            Can be used along with `duration_hours` and `duration_minutes`.
        duration_hours (str | None, optional): Maximum duration of the scan in hours.
            Can be used along with `duration_days` and `duration_minutes`.
        duration_minutes (str | None, optional): Maximum duration of the scan in minutes.
            Can be used along with `duration_days` and `duration_hours`.
        enabled (str | None, optional): A flag indicating whether the scan schedule is enabled.
           Defaults to None, which results in using True.
        frequency (str | None, optional): Frequency for the schedule to repeat.
        interval (str | None, optional): The interval time the schedule should repeat.
            Required if frequency is set to any value other than `DATE_OF_MONTH`.
        date_of_month(str | None, optional): Specifies the schedule repeat day of the interval month.
            Required and used only if frequency is set to `DATE_OF_MONTH`.
        scan_name (str | None, optional): A unique user-defined name for the scan launched by the schedule.
            If not explicitly set in the schedule, the scan name will be generated prior to the scan launching.
        scan_template_id (str | None, optional): ID of the scan template to use.
    """
    site = Site(
        site_id=site_id,
        site_name=site_name,
        client=client,
    )

    excluded_asset_groups_list = None
    excluded_targets_list = None
    frequency_enum = None
    included_asset_groups_list = None
    included_targets_list = None

    if excluded_asset_groups is not None:
        excluded_asset_groups_list = [int(asset_id) for asset_id in argToList(excluded_asset_groups)]

    if excluded_targets is not None:
        excluded_targets_list = argToList(excluded_targets)

    if frequency is not None:
        frequency_enum = RepeatFrequencyType[frequency]

    if included_asset_groups is not None:
        included_asset_groups_list = [int(asset_id) for asset_id in argToList(included_asset_groups)]

    if included_targets is not None:
        included_targets_list = argToList(included_targets)

    duration_days_int = arg_to_number(duration_days, required=False)
    duration_hours_int = arg_to_number(duration_hours, required=False)
    duration_minutes_int = arg_to_number(duration_minutes, required=False)
    interval_int = arg_to_number(interval, required=False)
    date_of_month_int = arg_to_number(date_of_month, required=False)

    if enabled is not None:
        enabled_bool = argToBoolean(enabled)

    else:
        enabled_bool = True

    duration = generate_duration_time(
        days=duration_days_int,
        hours=duration_hours_int,
        minutes=duration_minutes_int,
    )

    response_data = client.update_scan_schedule(
        site_id=site.id,
        scan_schedule_id=schedule_id,
        enabled=enabled_bool,
        repeat_behaviour=on_scan_repeat,
        start_date=start,
        excluded_asset_groups=excluded_asset_groups_list,
        excluded_targets=excluded_targets_list,
        included_asset_groups=included_asset_groups_list,
        included_targets=included_targets_list,
        duration=duration,
        frequency=frequency_enum,
        interval=interval_int,
        date_of_month=date_of_month_int,
        scan_name=scan_name,
        scan_template_id=scan_template_id,
    )

    return CommandResults(
        readable_output=f"Scan schedule {schedule_id} has been updated.",
        raw_response=response_data,
    )


def update_vulnerability_exception_expiration_command(client: Client, vulnerability_exception_id: str,
                                                      expiration: str) -> CommandResults:
    """
    Update the expiration date of a vulnerability exception.

    Args:
        client (Client): Client to use for API requests.
        vulnerability_exception_id (str): ID of the vulnerability exception to update.
        expiration (str): Expiration date to set for the vulnerability exception,
            formatted in ISO 8601 format.
    """
    response = client.update_vulnerability_exception_expiration(
        vulnerability_exception_id=vulnerability_exception_id,
        expiration_date=expiration,
    )

    return CommandResults(
        readable_output=f"Successfully updated expiration date "
                        f"of vulnerability exception {vulnerability_exception_id}.",
        raw_response=response,
    )


def update_vulnerability_exception_status_command(client: Client, vulnerability_exception_id: str,
                                                  status: str) -> CommandResults:
    """
    Update the status of a vulnerability exception.

    Args:
        client (Client): Client to use for API requests.
        vulnerability_exception_id (str): ID of the vulnerability exception to update.
        status (str): Status to set for the vulnerability exception.
    """
    response = client.update_vulnerability_exception_status(
        vulnerability_exception_id=vulnerability_exception_id,
        status=status,
    )

    return CommandResults(
        readable_output=f"Successfully updated status of vulnerability exception {vulnerability_exception_id}.",
        raw_response=response,
    )


def create_tag_command(client: Client, name: str, type: str, color: str, ip_address_is: str | None = None,
                       host_name_is: str | None = None, risk_score_higher_than: str | None = None,
                       vulnerability_title_contains: str | None = None, site_id_in: str | None = None,
                       site_name_in: str | None = None, query: str | None = None, match: str | None = None):
    """
    Create a tag.

    Args:
        client (Client): Client to use for API requests.
        name (str): The tag name.
        type (str): The tag type.
        color (str): The tag color - relevant only for "custom" type.
        ip_address_is (str, optional): A specific IP address to search for.
        host_name_is (str, optional): A specific host name to search for.
        risk_score_higher_than (str, optional): A minimum risk score to use as a filter.
        vulnerability_title_contains (str, optional): A string to search for in vulnerability titles.
        site_id_in (str, optional): Site IDs to filter for. Can be a comma-separated list.
        site_name_in (str, optional): Site names to filter for. Can be a comma-separated list.
        query (str, optional): Additional queries to use as a filter, in the format: {field} {operator} {value}.
                                Multiple queries can be specified, separated by a ";" separator.
        match (str, optional): Operator to determine how to match filters.
                                "All" requires all filters to match, "Any" requires only one filter to match.

    Returns:
        CommandResults: Results of the tag creation.
    """
    validate_input(type, VALID_TAG_TYPES, "type", True)
    validate_input(color, VALID_TAG_COLORS, "color", False)

    if type.lower() != "custom" and color.lower() != "default":
        raise DemistoException("color argument is only relevant for “custom” type.")

    filters_data = parse_asset_filters(
        client=client,
        ip_address_is=ip_address_is,
        host_name_is=host_name_is,
        risk_score_higher_than=risk_score_higher_than,
        site_id_in=site_id_in,
        site_name_in=site_name_in,
        vulnerability_title_contains=vulnerability_title_contains,
        query=query)

    filters = convert_asset_search_filters(filters_data)
    res = client.create_tag(name=name, type=type, color=color, filters=filters, match=match)

    return CommandResults(
        outputs_prefix="Nexpose.Tag",
        outputs_key_field="id",
        outputs=res,
        readable_output=f"A new tag '{name}' created successfully with ID: {res['id']}",
        raw_response=res,
    )


def delete_tag_command(client: Client, id: str):
    """
    Delete a tag by ID.

    Args:
        client (Client): Client to use for API requests.
        id (str): The tag ID.

    Returns:
        CommandResults: Results of the tag deletion.
    """
    id_int = arg_to_number(id, arg_name="id", required=True)
    client.delete_tag(id_int)  # type: ignore[arg-type]
    return CommandResults(readable_output=f"Tag: {id_int} was deleted successfully")


def get_list_tag_command(client: Client, id: str | None = None, name: str | None = None, type: str | None = None,
                         page_size: str | None = None, page: str | None = None, limit: str | None = None):
    """
    Get a list of tags or a tag by ID.

    Args:
        client (Client): Client to use for API requests.
        id (str, optional): Get tag by ID.
        name (str, optional): Filters the returned tags to only those containing the value within their name.
        type (str, optional): Filters the returned tags to only those of this type.
        page_size (str, optional): Number of records to retrieve in each API call when pagination is used.
        page (str, optional): A specific page to retrieve when pagination is used. Page indexing starts at 0.
        limit (str, optional): A number of records to limit the response to.

    Returns:
        CommandResults: Results of the tags retrieval.
    """
    validate_input(type, VALID_TAG_TYPES, "type", False)

    if id_int := arg_to_number(id, required=False):
        tags = client.get_tag_by_id(id=id_int)
    else:
        page_size_int = arg_to_number(page_size, required=False)
        page_int = arg_to_number(page, required=False)
        limit_int = arg_to_number(limit, required=False)
        tags = client.get_tags_list(name=name, type=type, page_size=page_size_int, page=page_int, limit=limit_int)

    headers = ['id', 'color', 'created', 'name', 'riskmodifier', 'source', 'type']
    return CommandResults(
        outputs_prefix="Nexpose.Tag",
        outputs_key_field="id",
        outputs=tags,
        readable_output=tableToMarkdown("Tags list", remove_dict_key(deepcopy(tags), "searchCriteria"), headers=headers,
                                        headerTransform=string_to_table_header),
        raw_response=tags
    )


def update_tag_search_criteria_command(client: Client, tag_id: str, overwrite: str, ip_address_is: str | None = None,
                                       host_name_is: str | None = None, risk_score_higher_than: str | None = None,
                                       vulnerability_title_contains: str | None = None, site_id_in: str | None = None,
                                       site_name_in: str | None = None, query: str | None = None, match: str | None = None):
    """
    Update the search criteria of a tag.

    Args:
        client (Client): Client to use for API requests.
        tag_id (str): The tag ID.
        overwrite (str): Whether to overwrite the original search values or append new conditions to the existing search.
        ip_address_is (str, optional): A specific IP address to search for.
        host_name_is (str, optional): A specific host name to search for.
        risk_score_higher_than (str, optional): A minimum risk score to use as a filter.
        vulnerability_title_contains (str, optional): A string to search for in vulnerability titles.
        site_id_in (str, optional): Site IDs to filter for. Can be a comma-separated list.
        site_name_in (str, optional): Site names to filter for. Can be a comma-separated list.
        query (str, optional): Additional queries to use as a filter, following the Search Criteria API standard.
        match (str, optional): Operator to determine how to match filters.
            "All" requires all filters to match, "Any" requires only one filter to match.

    Returns:
        CommandResults: Results of the search criteria update.
    """
    tag_id_int = arg_to_number(tag_id, arg_name="tag_id", required=True)

    filters_data = parse_asset_filters(
        client=client,
        ip_address_is=ip_address_is,
        host_name_is=host_name_is,
        risk_score_higher_than=risk_score_higher_than,
        site_name_in=site_name_in,
        site_id_in=site_id_in,
        vulnerability_title_contains=vulnerability_title_contains,
        query=query)

    filters = convert_asset_search_filters(filters_data)

    if not argToBoolean(overwrite):
        tag_data = client.get_tag_by_id(tag_id_int)  # type: ignore[arg-type]
        old_filters = tag_data.get("searchCriteria", {}).get("filters", [])
        filters.extend(old_filters)

    client.update_tag_search_criteria(tag_id_int, filters, match)  # type: ignore[arg-type]
    return CommandResults(readable_output=f"Tag {tag_id_int} search criteria were updated successfully")


def get_list_tag_asset_group_command(client: Client, tag_id: str):
    """
    Get a list of asset groups for a tag.

    Args:
        client (Client): Client to use for API requests.
        tag_id (str): The tag ID.

    Returns:
        CommandResults: Results of the asset groups retrieval.
    """
    tag_id_int = arg_to_number(tag_id, arg_name="tag_id", required=True)

    res = client.send_http_request("GET", f"/tags/{tag_id_int}/asset_groups")
    asset_groups_ids = res.get("resources", [])
    return CommandResults(
        outputs_prefix="Nexpose.TagAssetGroup",
        outputs=asset_groups_ids,
        readable_output=tableToMarkdown(f"Tag {tag_id_int} asset groups.", asset_groups_ids, headers=['Asset groups IDs']),
        raw_response=res
    )


def add_tag_asset_group_command(client: Client, tag_id: str, asset_group_ids: str):
    """
    Add existing asset groups to a tag.

    Args:
        client (Client): Client to use for API requests.
        tag_id (str): The tag ID.
        asset_group_ids (str): The asset group IDs to add. Can be a comma-separated list.

    Returns:
        CommandResults: Results of the asset groups addition.
    """
    tag_id_int = arg_to_number(tag_id, arg_name="tag_id", required=True)
    asset_group_ids_list = argToList(asset_group_ids, transform=int)

    old_asset_groups = client.send_http_request("GET", f"/tags/{tag_id_int}/asset_groups")
    all_asset_group = list(set(old_asset_groups.get("resources", []) + asset_group_ids_list))

    client.send_http_request("PUT", f"/tags/{tag_id_int}/asset_groups", all_asset_group)
    return CommandResults(readable_output=f"Asset groups '{asset_group_ids}' were added successfully")


def remove_tag_asset_group_command(client: Client, tag_id: str, asset_group_id: str):
    """
    Remove an asset group from a tag.

    Args:
        client (Client): Client to use for API requests.
        tag_id (str): The tag ID.
        asset_group_id (str): The asset group ID to remove.

    Returns:
        CommandResults: Results of the asset group removal.
    """
    tag_id_int = arg_to_number(tag_id, arg_name="tag_id", required=True)
    asset_group_id_int = arg_to_number(asset_group_id, arg_name="asset_group_id", required=True)

    client.send_http_request("DELETE", f"/tags/{tag_id_int}/asset_groups/{asset_group_id_int}")
    return CommandResults(readable_output=f"Asset group {asset_group_id_int} was removed from tag {tag_id_int} successfully")


def get_list_tag_asset_command(client: Client, tag_id: str):
    """
    Get a list of assets for a tag.

    Args:
        client (Client): Client to use for API requests.
        tag_id (str): The tag ID.

    Returns:
        CommandResults: Results of the assets retrieval.
    """
    tag_id_int = arg_to_number(tag_id, arg_name="tag_id", required=True)

    res = client.send_http_request("GET", f"/tags/{tag_id_int}/assets")
    resources = res.get("resources", [])
    return CommandResults(
        outputs_prefix="Nexpose.TagAsset",
        outputs_key_field="id",
        outputs=resources,
        readable_output=tableToMarkdown(f"Tag {tag_id_int} assets", resources, headerTransform=string_to_table_header),
        raw_response=res
    )


def add_tag_asset_command(client: Client, tag_id: str, asset_id: str):
    """
    Add an existing asset to a tag.

    Args:
        client (Client): Client to use for API requests.
        tag_id (str): The tag ID.
        asset_id (str): The asset ID to add.

    Returns:
        CommandResults: Results of the asset addition.
    """
    tag_id_int = arg_to_number(tag_id, arg_name="tag_id", required=True)
    asset_id_int = arg_to_number(asset_id, arg_name="asset_id", required=True)

    client.send_http_request("PUT", f"/tags/{tag_id_int}/assets/{asset_id_int}")
    return CommandResults(readable_output=f"Asset {asset_id_int} was added in tag {tag_id_int} successfully")


def remove_tag_asset_command(client: Client, tag_id: str, asset_id: str):
    """
    Remove an asset from a tag.

    Args:
        client (Client): Client to use for API requests.
        tag_id (str): The tag ID.
        asset_id (str): The asset ID to remove.

    Returns:
        CommandResults: Results of the asset removal.
    """
    tag_id_int = arg_to_number(tag_id, arg_name="tag_id", required=True)
    asset_id_int = arg_to_number(asset_id, arg_name="asset_id", required=True)

    client.send_http_request("DELETE", f"/tags/{tag_id_int}/assets/{asset_id_int}")
    return CommandResults(readable_output=f"Asset {asset_id_int} was removed from tag {tag_id_int} successfully")


def add_site_asset_command(client: Client, target_type: str, site_id: str, assets: str | None = None,
                           asset_group_ids: str | None = None):
    """
    Add assets or asset groups to a site's included/excluded assets.

    Args:
        client (Client): Client to use for API requests.
        target_type (str): Type of target, either "included" or "excluded".
        site_id (str): The site ID.
        assets (str, optional): The assets to add. Can be a comma-separated list.
        asset_group_ids (str, optional): The asset group IDs to add. Can be a comma-separated list.

    Returns:
        CommandResults: Results of the assets or asset groups addition/exclusion.
    """
    site_id_int = arg_to_number(site_id, arg_name="site_id", required=True)

    if assets_list := argToList(assets):
        client.send_http_request("POST", f"/sites/{site_id_int}/{target_type}_targets", assets_list)
        added_assets = f"assets {', '.join(assets_list)}"

    elif asset_group_ids_list := argToList(asset_group_ids, transform=int):
        client.send_http_request("PUT", f"/sites/{site_id_int}/{target_type}_asset_groups", asset_group_ids_list)
        added_assets = f"asset group IDs {asset_group_ids}"

    else:
        raise DemistoException("Must provide at least one Asset ID or Asset Group ID")

    return CommandResults(readable_output=f"Added assets- {added_assets} to site ID - {site_id_int}.")


def remove_site_asset_command(client: Client, target_type: str, site_id: str, assets: str | None = None,
                              asset_group_ids: str | None = None):
    """
    Remove assets or asset groups from a site's included/excluded assets.

    Args:
        client (Client): Client to use for API requests.
        target_type (str): Type of target, either "included" or "excluded".
        site_id (str): The site ID.
        assets (str, optional): The assets to remove. Can be a comma-separated list.
        asset_group_ids (str, optional): The asset group IDs to remove. Can be a comma-separated list.

    Returns:
        CommandResults: Results of the assets or asset groups removal.
    """
    site_id_int = arg_to_number(site_id, arg_name="site_id", required=True)

    if assets_list := argToList(assets):
        client.send_http_request("DELETE", f"/sites/{site_id_int}/{target_type}_targets", assets_list)
        removed_assets = f"assets {', '.join(assets_list)}"

    elif asset_group_ids_list := argToList(asset_group_ids, transform=int):
        client.send_http_request("DELETE", f"/sites/{site_id_int}/{target_type}_asset_groups", asset_group_ids_list)
        removed_assets = f"asset group IDs {asset_group_ids}"

    else:
        raise DemistoException("Must provide at least one assets or asset_group_ids")

    return CommandResults(readable_output=f"Removed assets-{removed_assets} from site ID {site_id_int}.")


def list_site_assets_command(client: Client, site_id: str, asset_type: str, target_type: str):
    """
    List included or excluded assets or asset groups for a site.

    Args:
        client (Client): Client to use for API requests.
        site_id (str): The site ID.
        asset_type (str): Type of asset, either "assets" or "asset_groups".
        target_type (str): Type of target, either "included" or "excluded".

    Returns:
        CommandResults: Results of the assets or asset groups retrieval.
    """
    site_id_int = arg_to_number(site_id, arg_name="site_id", required=True)

    if asset_type == "assets":
        res = client.send_http_request("GET", f"/sites/{site_id_int}/{target_type}_targets")
        output_prefix = f"Nexpose.{target_type.capitalize()}Asset"
        readable_title = f"{target_type.capitalize()} Asset list for site ID {site_id_int}"
    elif asset_type == "asset_groups":
        res = client.send_http_request("GET", f"/sites/{site_id_int}/{target_type}_asset_groups")
        output_prefix = f"Nexpose.{target_type.capitalize()}AssetGroup"
        readable_title = f"{target_type.capitalize()} Asset group list for site ID {site_id_int}"
    else:
        raise ValueError("Invalid asset_type. Expected 'assets' or 'asset_groups'.")

    outputs = dict(**res, site_id=site_id_int)
    readable_results = res.get("resources") if asset_type == 'asset_groups' else res

    return CommandResults(
        outputs_prefix=output_prefix,
        outputs_key_field="id",
        outputs=outputs,
        readable_output=tableToMarkdown(readable_title, readable_results,
                                        headerTransform=string_to_table_header, removeNull=True),
        raw_response=outputs
    )


def create_asset_group_command(client: Client, name: str, description: str, type: str, match: str | None = None,
                               ip_address_is: str | None = None, host_name_is: str | None = None,
                               risk_score_higher_than: str | None = None, vulnerability_title_contains: str | None = None,
                               site_id_in: str | None = None, site_name_in: str | None = None, query: str | None = None, ):
    """
    Creates a new asset group in Nexpose.

    Args:
        client (Client): Client to use for API requests.
        name (str): The name of the asset group.
        description (str): The description of the asset group.
        type (str): The type of the asset group, valid values: "dynamic" or "static".
        match (str, optional): The match criteria for the asset group.
        ip_address_is (str, optional): Filter by IP address.
        host_name_is (str, optional): Filter by host name.
        risk_score_higher_than (str, optional): Filter by risk score higher than the specified value.
        vulnerability_title_contains (str, optional): Filter by vulnerability title.
        site_id_in (str, optional): Filter by site ID.
        site_name_in (str, optional): Filter by site name.
        query (str, optional): Additional queries to use as a filter, in the format: {field} {operator} {value}.
                                Multiple queries can be specified, separated by a ";" separator.

    Returns:
        CommandResults: The results of the command execution.
    """
    filters_data = parse_asset_filters(
        client=client,
        ip_address_is=ip_address_is,
        host_name_is=host_name_is,
        risk_score_higher_than=risk_score_higher_than,
        site_id_in=site_id_in,
        site_name_in=site_name_in,
        vulnerability_title_contains=vulnerability_title_contains,
        query=query)

    validate_input(type, VALID_ASSET_GROUP_TYPES, "type", False)

    if type == "Dynamic" and not filters_data:
        raise DemistoException("You must add filters to create a Dynamic asset group.")

    filters = convert_asset_search_filters(filters_data)

    res = client.create_asset_group(name=name, description=description, type=type, filters=filters, match=match)

    return CommandResults(
        outputs_prefix="Nexpose.AssetGroup",
        outputs_key_field="id",
        outputs=res,
        readable_output=f"A new asset group {name} created successfully with ID: {res['id']}",
        raw_response=res
    )


def get_list_asset_group_command(client: Client, group_id: str | None = None, group_name: str | None = None,
                                 type: str | None = None, page_size: str | None = None, page: str | None = None,
                                 limit: str | None = None, sort: str | None = None):
    """
    Get a list of asset groups or a asset group by ID.

    Args:
        client (Client): Client to use for API requests.
        id (str, optional): Get asset group by ID.
        name (str, optional): Filters the returned asset groups to only those containing the value within their name.
        type (str, optional): Filters the returned asset groups to only those of this type.
        page_size (str, optional): Number of records to retrieve in each API call when pagination is used.
        page (str, optional): A specific page to retrieve when pagination is used. Page indexing starts at 0.
        limit (str, optional): A number of records to limit the response to.
        sort (str, optional): The sorting criteria for the results.

    Returns:
        CommandResults: Results of the asset groups retrieval.
    """
    validate_input(type, VALID_ASSET_GROUP_TYPES, "type", False)

    if id_int := arg_to_number(group_id, required=False):
        asset_groups = client.get_asset_group_by_id(id=id_int)
    else:
        page_size_int = arg_to_number(page_size, required=False)
        page_int = arg_to_number(page, required=False)
        limit_int = arg_to_number(limit, required=False)

        asset_groups = client.get_asset_groups(
            name=group_name,
            type=type,
            page_size=page_size_int,
            page=page_int,
            limit=limit_int,
            sort=sort
        )

    return CommandResults(
        outputs_prefix="Nexpose.AssetGroup",
        outputs_key_field="id",
        outputs=asset_groups,
        readable_output=tableToMarkdown("Asset groups list", remove_dict_key(deepcopy(asset_groups), "searchCriteria"),
                                        headerTransform=string_to_table_header),
        raw_response=asset_groups
    )


def main():  # pragma: no cover
    try:
        args = demisto.args()
        params = demisto.params()
        command = demisto.command()
        handle_proxy()

        # A workaround for fixing compatibility issues when upgrading existing instances that are < 1.2.0.
        # ('token' field was converted from type 0 to type 9)
        token = None

        if params.get("token"):
            if isinstance(params["token"], str):
                token = params["token"]

            elif params["token"].get("identifier"):
                token = params["token"]["identifier"]

        client = Client(
            url=params["server"],
            username=params["credentials"].get("identifier"),
            password=params["credentials"].get("password"),
            token=token,
            verify=not params.get("unsecure"),
            connection_error_retries=arg_to_number(params.get("connection_error_retries")) or CONNECTION_ERRORS_RETRIES
        )

        results: CommandResults | list[CommandResults] | dict | str

        if command == "test-module":
            client.get_assets(page_size=1, limit=1)
            results = "ok"
        elif command == "nexpose-create-asset":
            results = create_asset_command(client=client, **args)
        elif command == "nexpose-create-assets-report":
            results = create_assets_report_command(client=client, report_format=args.pop("format", None), **args)
        elif command == "nexpose-create-scan-report":
            results = create_scan_report_command(client=client, report_format=args.pop("format", None), **args)
        elif command == "nexpose-create-scan-schedule":
            results = create_scan_schedule_command(client=client, **args)
        elif command == "nexpose-create-shared-credential":
            results = create_shared_credential_command(client=client, **args)
        elif command == "nexpose-create-site":
            results = create_site_command(client=client, template_id=args.pop("scanTemplateId", None), **args)
        elif command == "nexpose-create-sites-report":
            results = create_sites_report_command(client=client, report_format=args.pop("format", None), **args)
        elif command == "nexpose-create-site-scan-credential":
            results = create_site_scan_credential_command(client=client, **args)
        elif command == "nexpose-create-vulnerability-exception":
            results = create_vulnerability_exception_command(client=client, **args)
        elif command == "nexpose-delete-asset":
            results = delete_asset_command(client=client, asset_id=args.pop("id"))
        elif command == "nexpose-delete-scan-schedule":
            results = delete_scan_schedule_command(client=client, **args)
        elif command == "nexpose-delete-shared-credential":
            results = delete_shared_credential_command(client=client, shared_credential_id=args.pop("id"))
        elif command == "nexpose-delete-site-scan-credential":
            results = delete_site_scan_credential_command(client=client, **args)
        elif command == "nexpose-delete-vulnerability-exception":
            results = delete_vulnerability_exception_command(client=client, vulnerability_exception_id=args.pop("id"))
        elif command == "nexpose-delete-site":
            results = delete_site_command(client=client, site_id=args.pop("id", None), **args)
        elif command == "nexpose-disable-shared-credential":
            results = set_assigned_shared_credential_status_command(client=client, enabled=False, **args)
        elif command == "nexpose-download-report":
            results = download_report_command(client=client, report_format=args.pop("format"), **args)
        elif command == "nexpose-enable-shared-credential":
            results = set_assigned_shared_credential_status_command(client=client, enabled=True, **args)
        elif command == "nexpose-get-asset":
            results = get_asset_command(client=client, asset_id=args.pop("id"))
        elif command == "nexpose-get-asset-tags":
            results = get_asset_tags_command(client=client, asset_id=args.pop("asset_id"))
        elif command == "nexpose-get-asset-vulnerability":
            results = get_asset_vulnerability_command(client=client, asset_id=args.pop("id"),
                                                      vulnerability_id=args.pop("vulnerabilityId"))
        elif command == "nexpose-get-assets":
            results = get_assets_command(client=client, **args)
        elif command == "nexpose-get-report-templates":
            results = get_report_templates_command(client=client)
        elif command == "nexpose-get-report-status":
            results = get_generated_report_status_command(client=client, **args)
        elif command == "nexpose-get-scan":
            results = get_scan_command(client=client, scan_ids=args.pop("id"))
        elif command == "nexpose-get-scans":
            results = get_scans_command(client=client, **args)
        elif command == "nexpose-get-sites":
            results = get_sites_command(client=client, **args)
        elif command == "nexpose-list-assigned-shared-credential":
            results = list_assigned_shared_credential_command(client=client, **args)
        elif command == "nexpose-list-site-scan-credential":
            results = list_site_scan_credential_command(client=client, **args)
        elif command == "nexpose-list-vulnerability":
            results = list_vulnerability_command(client=client, vulnerability_id=args.pop("id", None), **args)
        elif command == "nexpose-list-vulnerability-exceptions":
            results = list_vulnerability_exceptions_command(client=client,
                                                            vulnerability_exception_id=args.pop("id", None), **args)
        elif command == "nexpose-list-scan-schedule":
            results = list_scan_schedule_command(client=client, **args)
        elif command == "nexpose-list-shared-credential":
            results = list_shared_credential_command(client=client, credential_id=args.pop("id", None), **args)
        elif command == "nexpose-pause-scan":
            results = update_scan_command(client=client, scan_id=args.pop("id"), scan_status=ScanStatus.PAUSE)
        elif command == "nexpose-resume-scan":
            results = update_scan_command(client=client, scan_id=args.pop("id"), scan_status=ScanStatus.RESUME)
        elif command == "nexpose-update-shared-credential":
            results = update_shared_credential_command(client=client, shared_credential_id=args.pop("id"), **args)
        elif command == "nexpose-update-site-scan-credential":
            results = update_site_scan_credential_command(client=client, **args)
        elif command == "nexpose-update-scan-schedule":
            results = update_scan_schedule_command(client=client, **args)
        elif command == "nexpose-update-vulnerability-exception-expiration":
            results = update_vulnerability_exception_expiration_command(client=client,
                                                                        vulnerability_exception_id=args.pop("id"),
                                                                        **args)
        elif command == "nexpose-update-vulnerability-exception-status":
            results = update_vulnerability_exception_status_command(client=client,
                                                                    vulnerability_exception_id=args.pop("id"), **args)
        elif command == "nexpose-search-assets":
            results = search_assets_command(
                client=client,
                query=args.pop("query", None),
                ip_address_is=args.pop("ipAddressIs", None),
                host_name_is=args.pop("hostNameIs", None),
                risk_score_higher_than=args.pop("riskScoreHigherThan", None),
                vulnerability_title_contains=args.pop("vulnerabilityTitleContains", None),
                site_id_in=args.pop("siteIdIn", None),
                site_name_in=args.pop("siteNameIn", None),
                **args
            )
        elif command == "nexpose-start-assets-scan":
            results = start_assets_scan_command(client=client, ip_addresses=args.pop("IPs", None),
                                                hostnames=args.pop("hostNames", None), **args)
        elif command == "nexpose-start-site-scan":
            results = start_site_scan_command(client=client, site_id=args.pop("site", None), **args)
        elif command == "nexpose-stop-scan":
            results = update_scan_command(client=client, scan_id=args.pop("id"), scan_status=ScanStatus.STOP)
        elif command == "nexpose-create-tag":
            results = create_tag_command(client=client, **args)
        elif command == "nexpose-delete-tag":
            results = delete_tag_command(client=client, **args)
        elif command == "nexpose-list-tag":
            results = get_list_tag_command(client=client, **args)
        elif command == "nexpose-update-tag-search-criteria":
            results = update_tag_search_criteria_command(client=client, **args)
        elif command == "nexpose-list-tag-asset-group":
            results = get_list_tag_asset_group_command(client=client, **args)
        elif command == "nexpose-add-tag-asset-group":
            results = add_tag_asset_group_command(client=client, **args)
        elif command == "nexpose-remove-tag-asset-group":
            results = remove_tag_asset_group_command(client=client, **args)
        elif command == "nexpose-list-tag-asset":
            results = get_list_tag_asset_command(client=client, **args)
        elif command == "nexpose-add-tag-asset":
            results = add_tag_asset_command(client=client, **args)
        elif command == "nexpose-remove-tag-asset":
            results = remove_tag_asset_command(client=client, **args)
        elif command == "nexpose-add-site-included-asset":
            results = add_site_asset_command(client=client, target_type="included", **args)
        elif command == "nexpose-remove-site-included-asset":
            results = remove_site_asset_command(client=client, target_type="included", **args)
        elif command == "nexpose-list-site-included-asset":
            results = list_site_assets_command(client=client, asset_type="assets", target_type="included", **args)
        elif command == "nexpose-list-site-included-asset-group":
            results = list_site_assets_command(client=client, asset_type="asset_groups", target_type="included", **args)
        elif command == "nexpose-add-site-excluded-asset":
            results = add_site_asset_command(client=client, target_type="excluded", **args)
        elif command == "nexpose-remove-site-excluded-asset":
            results = remove_site_asset_command(client=client, target_type="excluded", **args)
        elif command == "nexpose-list-site-excluded-asset":
            results = list_site_assets_command(client=client, asset_type="assets", target_type="excluded", **args)
        elif command == "nexpose-list-site-excluded-asset-group":
            results = list_site_assets_command(client=client, asset_type="asset_groups", target_type="excluded", **args)
        elif command == "nexpose-list-asset-group":
            results = get_list_asset_group_command(client=client, **args)
        elif command == "nexpose-create-asset-group":
            results = create_asset_group_command(client=client, **args)
        else:
            raise NotImplementedError(f"Command {command} not implemented.")

        if isinstance(results, list) and len(results) == 1:
            return_results(results[0])

        else:
            return_results(results)

    except Exception as e:
        return_error(str(e))


if __name__ in ("__main__", "builtin", "builtins"):   # pragma: no cover
    main()

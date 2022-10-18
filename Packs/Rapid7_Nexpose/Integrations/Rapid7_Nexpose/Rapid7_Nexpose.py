import re
import urllib3

import demistomock as demisto

from copy import deepcopy
from datetime import datetime
from enum import Enum, EnumMeta
from time import strptime, struct_time
from typing import Optional, Union
from CommonServerPython import *
from CommonServerUserPython import *


API_DEFAULT_PAGE_SIZE = 10  # Default page size that's set on the API. Used for calculations.
DEFAULT_PAGE_SIZE = 50  # Default page size to use
MATCH_DEFAULT_VALUE = "any"  # Default "match" value to use when using search filters. Can be either "all" or "any".
REPORT_DOWNLOAD_WAIT_TIME = 60  # Time in seconds to wait before downloading a report after starting its generation
VENDOR_NAME = "Rapid7 Nexpose"  # TODO: Check if correct

urllib3.disable_warnings()  # Disable insecure warnings


class ScanStatus(Enum):
    """An Enum of possible scan status values."""
    PAUSE = 1
    RESUME = 2
    STOP = 3


class FlexibleEnum(EnumMeta):
    """A custom EnumMeta to allow easy and flexible conversion to and from strings."""
    def __getitem__(self, item):
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


class ReportFileFormat(Enum, metaclass=FlexibleEnum):
    """An Enum of possible file formats to use for reports."""
    PDF = "pdf"
    RTF = "rtf"
    XML = "xml"
    HTML = "html"
    Text = "text"


class RepeatBehaviour(Enum, metaclass=FlexibleEnum):
    """An Enum of possible repeat behaviours for scheduled scans to use when repeating a scan that was paused
    due to reaching its maximum duration."""
    RESTART_SCAN = "restart-scan"
    RESUME_SCAN = "resume-scan"


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


class SiteImportance(Enum, metaclass=FlexibleEnum):
    """An Enum of possible site importance values."""
    VERY_LOW = "very_low"
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    VERY_HIGH = "very_high"


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


class VulnerabilityExceptionReason(Enum, metaclass=FlexibleEnum):
    """An Enum of possible vulnerability exception reason values."""
    FALSE_POSITIVE = "False Positive"
    COMPENSATING_CONTROL = "Compensating Control"
    ACCEPTED_USE = "Acceptable Use"
    ACCEPTED_RISK = "Acceptable Risk"
    OTHER = "Other"


class VulnerabilityExceptionScopeType(Enum, metaclass=FlexibleEnum):
    """An Enum of possible vulnerability exception scope type values."""
    GLOBAL = "Global"
    SITE = "Site"
    ASSET = "Asset"
    ASSET_GROUP = "Asset Group"
    INSTANCE = "Instance"


class VulnerabilityExceptionState(Enum, metaclass=FlexibleEnum):
    """An Enum of possible vulnerability exception state values."""
    DELETED = "Deleted"
    EXPIRED = "Expired"
    APPROVED = "Approved"
    REJECTED = "Rejected"


class VulnerabilityExceptionStatus(Enum, metaclass=FlexibleEnum):
    """An Enum of possible vulnerability exception status values."""
    RECALL = "recall"
    APPROVE = "approve"
    REJECT = "reject"


class InvalidSiteNameException(DemistoException):
    pass


class Client(BaseClient):
    """Client class for interactions with Rapid7 Nexpose API."""

    def __init__(self, url: str, username: str, password: str, token: Optional[str] = None, verify: bool = True):
        """
        Initialize the client.

        Args:
            url (str): Nexpose server base URL.
            username (str): Username to use for authentication.
            password (str): Password to use for authentication.
            token (str | None, optional): 2FA token to use for authentication.
            verify (bool, optional): Whether to verify SSL certificates. Defaults to True.
        """

        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

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

    def _paged_http_request(self, page_size: Optional[int], page: Optional[int] = None,
                            sort: Optional[str] = None, limit: Optional[int] = None, **kwargs) -> list:
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
            page_size=page_size,
            limit=limit,
        ))

        # If sort is not None, split it into a list and add to kwargs
        if sort:
            kwargs["params"]["sort"] = sort.split(sep=";")

        response: dict = self._http_request(**kwargs)
        result = response.get("resources", [])

        if not result:
            return []

        if not page:
            total_pages = response["page"].get("totalPages", 1)
            page_count = 1

            while page_count < total_pages and (limit is None or len(result) < limit):
                page_count += 1
                kwargs["params"]["page"] = str(page_count)
                response = self._http_request(**kwargs)
                result.extend(response["resources"])

        if limit and limit < len(result):
            return result[:limit]

        return result

    def create_report(self, report_id: str) -> dict:
        """
        | Generates a configured report.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/generateReport

        Args:
            report_id (str): ID of the configured report to generate.

        Returns:
            str: ID of the generated report instance.
        """
        return self._http_request(
            url_suffix=f"/reports/{report_id}/generate",
            method="POST",
            resp_type="json",
        )

    def create_report_config(self, scope: dict[str, Any], template_id: str,
                             report_name: str, report_format: ReportFileFormat) -> dict:
        """
        | Create a new report configuration.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createReport

        Args:
            scope (dict[str, Any]): Scope of the report, see Nexpose's documentation for more details.
            template_id (str): ID of report template to use.
            report_name (str): Name for the report that will be generated.
            report_format (ReportFileFormat): Format of the report that will be generated.

        Returns:
            dict: API response with information about the newly created report configuration.
        """
        post_data = {
            "scope": scope,
            "template": template_id,
            "name": report_name,
            "format": report_format.value,
        }

        return self._http_request(
            url_suffix="/reports",
            method="POST",
            json_data=post_data,
            resp_type="json",
        )

    def create_shared_credential(self, name: str,
                                 site_assignment: SharedCredentialSiteAssignment,
                                 service: CredentialService,
                                 database_name: Optional[str] = None,
                                 description: Optional[str] = None,
                                 domain: Optional[str] = None,
                                 host_restriction: Optional[str] = None,
                                 http_realm: Optional[str] = None,
                                 notes_id_password: Optional[str] = None,
                                 ntlm_hash: Optional[str] = None,
                                 oracle_enumerate_sids: Optional[bool] = None,
                                 oracle_listener_password: Optional[str] = None,
                                 oracle_sid: Optional[str] = None,
                                 password: Optional[str] = None,
                                 port_restriction: Optional[str] = None,
                                 sites: Optional[List[int]] = None,
                                 snmp_community_name: Optional[str] = None,
                                 snmpv3_authentication_type: Optional[SNMPv3AuthenticationType] = None,
                                 snmpv3_privacy_password: Optional[str] = None,
                                 snmpv3_privacy_type: Optional[SNMPv3PrivacyType] = None,
                                 ssh_key_pem: Optional[str] = None,
                                 ssh_permission_elevation: Optional[SSHElevationType] = None,
                                 ssh_permission_elevation_password: Optional[str] = None,
                                 ssh_permission_elevation_username: Optional[str] = None,
                                 ssh_private_key_password: Optional[str] = None,
                                 use_windows_authentication: Optional[bool] = None,
                                 username: Optional[str] = None) -> dict:
        """
        | Create a new shared credential.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSharedCredential

        Args:
            name (str): Name of the credential.
            site_assignment (SharedCredentialSiteAssignment): Site assignment configuration for the credential.
                Assign the shared scan credential either to be available to all sites, or a specific list of sites.
            service (CredentialService): Credential service type.
            database_name (str, optional): Database name.
            description (str, optional): Description for the credential.
            domain (str, optional): Domain address.
            host_restriction (str, optional): Hostname or IP address to restrict the credentials to.
            http_realm (str, optional): HTTP realm.
            notes_id_password (str, optional): Password for the notes account that will be used for authenticating.
            ntlm_hash (str, optional): NTLM password hash.
            oracle_enumerate_sids (bool, optional): Whether the scan engine should attempt to enumerate
                SIDs from the environment.
            oracle_listener_password (str, optional): The Oracle Net Listener password.
                Used to enumerate SIDs from the environment.
            oracle_sid (str, optional): Oracle database name.
            password (str, optional): Password for the credential.
            port_restriction (str, optional): Further restricts the credential to attempt to authenticate
                on a specific port. Can be used only if `host_restriction` is used.
            sites (List[int], optional): List of site IDs for the shared credential that are explicitly assigned
                access to the shared scan credential, allowing it to use the credential during a scan.
            snmp_community_name (str, optional): SNMP community for authentication.
            snmpv3_authentication_type (SNMPv3AuthenticationType): SNMPv3 authentication type for the credential.
            snmpv3_privacy_password (str, optional): SNMPv3 privacy password to use.
            snmpv3_privacy_type (SNMPv3PrivacyType, optional): SNMPv3 Privacy protocol to use.
            ssh_key_pem (str, optional): PEM formatted private key.
            ssh_permission_elevation (SSHElevationType, optional): Elevation type to use for scans.
            ssh_permission_elevation_password (str, optional): Password to use for elevation.
            ssh_permission_elevation_username (str, optional): Username to use for elevation.
            ssh_private_key_password (str, optional): Password for the private key.
            use_windows_authentication (bool, optional): Whether to use Windows authentication.
            username (str, optional): Username for the credential.

        Returns:
            dict: API response with information about the newly created shared credential.
        """
        account_data = {}

        with CredentialService as S:  # type: CredentialService
            # Services where "username" field is required
            if service in (S.AS400, S.CIFS, S.CIFSHASH, S.CVS, S.DB2, S.FTP, S.HTTP, S.MS_SQL, S.MYSQL, S.ORACLE,
                           S.POP, S.POSTGRESQL, S.REMOTE_EXEC, S.SNMPV3, S.SSH, S.SSH_KEY, S.SYBASE, S.TELNET):
                if username is None:
                    raise ValueError(f"Username is required for \"{service.value}\" services.")

                account_data["username"] = username

            # Services where "password" field is required
            if service in (S.AS400, S.CIFS, S.CIFSHASH, S.CVS, S.DB2, S.FTP, S.HTTP, S.MS_SQL, S.MYSQL,
                           S.ORACLE, S.POP, S.POSTGRESQL, S.REMOTE_EXEC, S.SSH, S.SYBASE, S.TELNET):
                if password is None:
                    raise ValueError(f"Password is required for \"{service.value}\" services.")

                account_data["password"] = password

            # Services with optional "useWindowsAuthentication" field.
            if service in (S.MS_SQL, S.SYBASE) and use_windows_authentication is not None:
                account_data["useWindowsAuthentication"] = use_windows_authentication

            # Services with optional "domain" field.
            if service in (S.AS400, S.CIFS, S.CIFSHASH, S.CVS, S.MS_SQL, S.SYBASE) and domain is not None:
                if service in (S.MS_SQL, S.SYBASE):
                    if use_windows_authentication:
                        account_data["domain"] = domain

                else:
                    account_data["domain"] = domain

            # Services with optional "database" field.
            if service in (S.DB2, S.MS_SQL, S.MYSQL, S.POSTGRESQL, S.SYBASE) and database_name is not None:
                account_data["database"] = database_name

            if service == S.CIFSHASH:
                if ntlm_hash is None:
                    raise ValueError(f"NTLM hash is required for \"{service.value}\" services.")

                account_data["ntlmHash"] = ntlm_hash

            if service == S.HTTP and http_realm is not None:
                account_data["realm"] = http_realm

            if service == S.NOTES and notes_id_password is not None:
                account_data["notesIDPassword"] = notes_id_password

            if service == S.ORACLE:
                if oracle_sid is not None:
                    account_data["sid"] = oracle_sid

                if oracle_enumerate_sids is not None:
                    account_data["enumerateSids"] = oracle_enumerate_sids

                    if oracle_enumerate_sids and oracle_listener_password is None:
                        raise ValueError("Oracle listener password is required when enumerating SIDs.")

                    account_data["oracleListenerPassword"] = oracle_listener_password

            if service == S.SNMP:
                if snmp_community_name is None:
                    raise ValueError(f"Community name is required for \"{service.value}\" services.")

                account_data["community"] = snmp_community_name

            if service == S.SNMPV3:
                if snmpv3_authentication_type is None:
                    raise ValueError(f"Authentication type is required for \"{service.value}\" services.")

                account_data["authenticationType"] = snmpv3_authentication_type.value

                if snmpv3_authentication_type != SNMPv3AuthenticationType.NO_AUTHENTICATION:
                    if password is None:
                        raise ValueError(f"Password is required for \"{service.value}\" services when authentication "
                                         f"is md5 to anything other than \"no-authentication\".")

                    account_data["password"] = password

                if snmpv3_privacy_type is not None:  # TODO: Should privacy_type be required?
                    account_data["privacyType"] = snmpv3_privacy_type.value

                    if snmpv3_privacy_type != SNMPv3PrivacyType.NO_PRIVACY and snmpv3_privacy_password is None:
                        raise ValueError(f"Privacy password is required for \"{service.value}\" services when the "
                                         f"authentication type is set to a value other than \"no-authentication\", "
                                         f"and privacy type is set to a value other than \"no-privacy\".")

                    account_data["privacyPassword"] = snmpv3_privacy_password

            if service in (S.SSH, S.SSH_KEY):
                if ssh_permission_elevation:
                    account_data["permissionElevation"] = ssh_permission_elevation

                if ssh_permission_elevation not in (SSHElevationType.NONE, SSHElevationType.PBRUN):
                    if None in (ssh_permission_elevation_username, ssh_permission_elevation_password):
                        raise ValueError(f"Elevation username and password are required for \"{service.value}\" "
                                         f"services when permission elevation is not \"none\" or \"pbrun\".")

                    account_data["permissionElevationUsername"] = ssh_permission_elevation_username
                    account_data["permissionElevationPassword"] = ssh_permission_elevation_password

            if service == S.SSH_KEY:
                if ssh_key_pem is None:
                    raise ValueError(f"SSH private key password is required for \"{service.value}\" services.")

                account_data["pemKey"] = ssh_key_pem

                if ssh_private_key_password is None:  # TODO: Check if actually required
                    raise ValueError(f"SSH private key password is required for \"{service.value}\" services.")

                account_data["privateKeyPassword"] = ssh_private_key_password

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
            url_suffix=f"/shared_credentials",
            json_data=post_data,
            resp_type="json",
        )

    def create_site_scan_schedule(self, site_id: str, start_date: str,
                                  excluded_asset_groups: Optional[list[int]] = None,
                                  excluded_targets: Optional[list[str]] = None,
                                  included_asset_groups: Optional[list[int]] = None,
                                  included_targets: Optional[list[str]] = None,
                                  duration: Optional[str] = None, enabled: bool = None,
                                  repeat_behaviour: Optional[RepeatBehaviour] = None,
                                  frequency: Optional[RepeatFrequencyType] = None,
                                  interval: Optional[int] = None, date_of_month: Optional[int] = None,
                                  scan_name: Optional[str] = None, scan_template_id: Optional[str] = None) -> dict:
        """
        | Create a new site scan schedule.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSiteScanSchedule

        Args:
            site_id (str): ID of the site to create a new scheduled scan for.
            start_date (str): The scheduled start date and time formatted in ISO 8601 format.
            excluded_asset_groups (list[int], optional): Asset groups to exclude from the scan.
            excluded_targets (list[str], optional): Addresses to exclude from the scan. Each address is a string that
                can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
            included_asset_groups (list[int], optional): Asset groups to include in the scan.
            included_targets (list[str], optional): Addresses to include in the scan.  Each address is a string that
                can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
            duration (str, optional): An ISO 8601 formatted duration string that Specifies the maximum duration
                the scheduled scan is allowed to run.
            enabled (bool): A flag indicating whether the scan schedule is enabled.
            repeat_behaviour (RepeatBehaviour, optional): The desired behavior of a repeating scheduled scan
                when the previous scan was paused due to reaching its maximum duration.
            frequency (RepeatFrequencyType, optional): Frequency for the schedule to repeat.
                Required if using other repeat settings.
            interval (int, optional): The interval time the schedule should repeat.
                Required if using other repeat settings.
            date_of_month(int, optional): Specifies the schedule repeat day of the interval month.
                Required and used only if frequency is set to "DATE_OF_MONTH".
            scan_name (str, optional): A unique user-defined name for the scan launched by the schedule.
                If not explicitly set in the schedule, the scan name will be generated prior to the scan launching.
            scan_template_id (str, optional): ID of the scan template to use.

        Returns:
            dict: API response with information about the newly created scan schedule.
        """
        assets = {}
        repeat = {}

        if excluded_asset_groups:
            assets["excludedAssetGroups"] = {"assetGroupIDs": excluded_asset_groups}

        if excluded_targets:
            assets["excludedTargets"] = {"addresses": excluded_targets}

        if included_asset_groups:
            assets["includedAssetGroups"] = {"assetGroupIDs": included_asset_groups}

        if included_targets:
            assets["includedTargets"] = {"addresses": included_targets}

            if interval is None:
                raise ValueError("'interval' parameter must be set if frequency is used.")

            if frequency == RepeatFrequencyType.DATE_OF_MONTH and not date_of_month:
                raise ValueError("'date_of_month' parameter must be set if frequency is set to 'Date of month'.")

            repeat = find_valid_params(
                every=frequency.value,
                interval=interval,
                dateOfMonth=date_of_month,
            )

        post_data = find_valid_params(
            assets=assets,
            duration=duration,
            enabled=enabled,
            onScanRepeat=repeat_behaviour.value,
            repeat=repeat,
            scanName=scan_name,
            scanTemplateId=scan_template_id,
            start=start_date,
        )

        return self._http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules",
            method="POST",
            json_data=post_data,
            resp_type="json",
        )

    def create_site(self, name: str, description: Optional[str] = None, assets: Optional[list[str]] = None,
                    site_importance: Optional[SiteImportance] = None, template_id: Optional[str] = None) -> dict:
        """
        | Create a new site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSite

        Args:
            name (str): Name of the site. Must be unique.
            description (str | None, optional): Description of the site. Defaults to None.
            assets (list[str] | None, optional): List of asset IDs to be included in site scans. Defaults to None.
            site_importance (SiteImportance | None, optional): Importance of the site.
                Defaults to None (results in using API's default - "normal").
            template_id (str | None, optional): The identifier of a scan template.
                Defaults to None (results in using default scan template).

        Returns:
            dict: API response with information about the newly created site.
        """
        importance: Optional[str] = site_importance.value if site_importance else None

        post_data = find_valid_params(
            name=name,
            description=description,
            importance=importance,
            template_id=template_id,
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

    def create_vulnerability_exception(self, vulnerability_id: str, scope_type: VulnerabilityExceptionScopeType,
                                       state: VulnerabilityExceptionState, reason: VulnerabilityExceptionReason,
                                       expires: Optional[str] = None, comment: Optional[str] = None):
        """
        | Create a new vulnerability exception.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createVulnerabilityException

        Args:
            vulnerability_id (str): ID of the vulnerability to create an exception for.
            scope_type (VulnerabilityExceptionScopeType): The type of the exception scope.
            state (VulnerabilityExceptionState): The state of the vulnerability exception.
            reason (VulnerabilityExceptionReason): The reason the vulnerability exception was submitted.
                Can be one of: "False Positive", "Compensating Control", "Acceptable Use",
                "Acceptable Risk", and "Other".
            expires (str | None, optional): The date and time the vulnerability exception is set to expire.
            comment (str | None, optional): A comment from the submitter as to why the exception was submitted.

        Returns:
            dict: API response with information about the newly created vulnerability exception.
        """
        scope_obj = find_valid_params(
            id=vulnerability_id,
            type=scope_type.value,
        )

        submit_obj = find_valid_params(
            reason=reason.name.value,
            comment=comment,
        )

        # Change to None if empty dict (no parameters used).
        submit_obj = submit_obj if submit_obj else None
        scope_obj = scope_obj if scope_obj else None

        post_data = find_valid_params(
            expires=expires,
            scope=scope_obj,
            state=state.value,
            submit=submit_obj,
        )

        return self._http_request(
            url_suffix="/vulnerability_exceptions",
            method="POST",
            json_data=post_data,
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
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/updateSharedCredential
        """
        return self._http_request(
            url_suffix=f"/shared_credentials/{shared_credential_id}",
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
            url_suffix=f"reports/{report_id}/history/{instance_id}/output",
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
            url_suffix=f"assets/{asset_id}/vulnerabilities/{vulnerability_id}",
            method="GET",
            resp_type="json",
        )

    def get_asset_vulnerabilities(self, asset_id: str, page_size: Optional[int] = DEFAULT_PAGE_SIZE,
                                  page: Optional[int] = None, sort: Optional[str] = None,
                                  limit: Optional[int] = None) -> list[dict]:
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

    def get_assets(self, page_size: Optional[int] = DEFAULT_PAGE_SIZE, page: Optional[int] = None,
                   sort: Optional[str] = None, limit: Optional[int] = None) -> list[dict]:
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
            url_suffix=f"/scan/{scan_id}",
            method="GET",
            resp_type="json",
        )

    def get_scans(self, active: Optional[bool] = False,
                  page_size: Optional[int] = DEFAULT_PAGE_SIZE, page: Optional[int] = None,
                  sort: Optional[str] = None, limit: Optional[int] = None) -> list[dict]:
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
        params = {"active": active}

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

    def get_shared_credentials(self, page_size: Optional[int] = DEFAULT_PAGE_SIZE, page: Optional[int] = None,
                               limit: Optional[int] = None) -> list[dict]:
        """
        | Retrieve information about all shared credentials.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSharedCredentials

        Args:
            page_size (int | None, optional): Number of assets to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            limit (int | None, optional): Limit the number of sites to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list with all shared credentials.
        """
        return self._paged_http_request(
            url_suffix="shared_credentials",
            method="GET",
            page_size=page_size,
            page=page,
            limit=limit,
            resp_type="json",
        )

    def get_site_assets(self, site_id: str, page_size: Optional[int] = DEFAULT_PAGE_SIZE,
                        page: Optional[int] = None, sort: Optional[str] = None,
                        limit: Optional[int] = None) -> list[dict]:
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

    def get_site_scans(self, site_id: str, page_size: Optional[int] = DEFAULT_PAGE_SIZE,
                       page: Optional[int] = None, sort: Optional[str] = None,
                       limit: Optional[int] = None) -> list[dict]:
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

    def get_site_scan_schedule(self, site_id: str, schedule_id: str) -> dict:
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
            url_suffix=f"/https://help.rapid7.com/api/3/sites/{site_id}/scan_schedules/{schedule_id}",
            method="GET",
            resp_type="json",
        )

    def get_site_scan_schedules(self, site_id: str, page_size: Optional[int] = None,
                                page: Optional[int] = None, sort: Optional[str] = None,
                                limit: Optional[int] = None) -> list[dict]:
        """
        | Retrieve information about scan schedules for a specific site.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteScanSchedules

        Args:
            site_id (str): ID of the site to retrieve scan schedules from.
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
                Defaults to None.
        """
        return self._paged_http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules",
            method="GET",
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_sites(self, page_size: Optional[int] = DEFAULT_PAGE_SIZE, page: Optional[int] = None,
                  sort: Optional[str] = None, limit: Optional[int] = None) -> list[dict]:
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

    def get_vulnerabilities(self, page_size: Optional[int] = DEFAULT_PAGE_SIZE, page: Optional[int] = None,
                            sort: Optional[str] = None, limit: Optional[int] = None) -> list[dict]:
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
            url_suffix=f"/vulnerabilities/{vulnerability_exception_id}",
            method="GET",
            resp_type="json",
        )

    def get_vulnerability_exceptions(self, page_size: Optional[int] = DEFAULT_PAGE_SIZE, page: Optional[int] = None,
                                     sort: Optional[str] = None, limit: Optional[int] = None) -> list[dict]:
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

    def search_assets(self, filters: Optional[list[dict]], match: str,
                      page_size: Optional[int] = DEFAULT_PAGE_SIZE, page: Optional[int] = None,
                      sort: Optional[str] = None, limit: Optional[int] = None) -> list[dict]:
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
            url_suffix=f"/sites/{site_id}/shared_credentials/{shared_credential_id}",
            method="PUT",
            data=str(enabled).lower(),  # type: ignore
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
        post_data = {
            "name": scan_name,
            "hosts": hosts
        }

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
                                 site_assignment: SharedCredentialSiteAssignment,
                                 service: CredentialService,
                                 database_name: Optional[str] = None,
                                 description: Optional[str] = None,
                                 domain: Optional[str] = None,
                                 host_restriction: Optional[str] = None,
                                 http_realm: Optional[str] = None,
                                 notes_id_password: Optional[str] = None,
                                 ntlm_hash: Optional[str] = None,
                                 oracle_enumerate_sids: Optional[bool] = None,
                                 oracle_listener_password: Optional[str] = None,
                                 oracle_sid: Optional[str] = None,
                                 password: Optional[str] = None,
                                 port_restriction: Optional[str] = None,
                                 sites: Optional[List[int]] = None,
                                 snmp_community_name: Optional[str] = None,
                                 snmpv3_authentication_type: Optional[SNMPv3AuthenticationType] = None,
                                 snmpv3_privacy_password: Optional[str] = None,
                                 snmpv3_privacy_type: Optional[SNMPv3PrivacyType] = None,
                                 ssh_key_pem: Optional[str] = None,
                                 ssh_permission_elevation: Optional[SSHElevationType] = None,
                                 ssh_permission_elevation_password: Optional[str] = None,
                                 ssh_permission_elevation_username: Optional[str] = None,
                                 ssh_private_key_password: Optional[str] = None,
                                 use_windows_authentication: Optional[bool] = None,
                                 username: Optional[str] = None) -> dict:
        """
        | Update an existing new shared credential.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/updateSharedCredential

        Args:
            shared_credential_id (str): ID of the shared credential to update.
            name (str): Name of the credential.
            site_assignment (SharedCredentialSiteAssignment): Site assignment configuration for the credential.
                Assign the shared scan credential either to be available to all sites, or a specific list of sites.
            service (CredentialService): Credential service type.
            database_name (str, optional): Database name.
            description (str, optional): Description for the credential.
            domain (str, optional): Domain address.
            host_restriction (str, optional): Hostname or IP address to restrict the credentials to.
            http_realm (str, optional): HTTP realm.
            notes_id_password (str, optional): Password for the notes account that will be used for authenticating.
            ntlm_hash (str, optional): NTLM password hash.
            oracle_enumerate_sids (bool, optional): Whether the scan engine should attempt to enumerate
                SIDs from the environment.
            oracle_listener_password (str, optional): The Oracle Net Listener password.
                Used to enumerate SIDs from the environment.
            oracle_sid (str, optional): Oracle database name.
            password (str, optional): Password for the credential.
            port_restriction (str, optional): Further restricts the credential to attempt to authenticate
                on a specific port. Can be used only if `host_restriction` is used.
            sites (List[int], optional): List of site IDs for the shared credential that are explicitly assigned
                access to the shared scan credential, allowing it to use the credential during a scan.
            snmp_community_name (str, optional): SNMP community for authentication.
            snmpv3_authentication_type (SNMPv3AuthenticationType): SNMPv3 authentication type for the credential.
            snmpv3_privacy_password (str, optional): SNMPv3 privacy password to use.
            snmpv3_privacy_type (SNMPv3PrivacyType, optional): SNMPv3 Privacy protocol to use.
            ssh_key_pem (str, optional): PEM formatted private key.
            ssh_permission_elevation (SSHElevationType, optional): Elevation type to use for scans.
            ssh_permission_elevation_password (str, optional): Password to use for elevation.
            ssh_permission_elevation_username (str, optional): Username to use for elevation.
            ssh_private_key_password (str, optional): Password for the private key.
            use_windows_authentication (bool, optional): Whether to use Windows authentication.
            username (str, optional): Username for the credential.

        Returns:
            dict: API response with information about the newly created shared credential.
        """
        account_data = {}

        with CredentialService as S:  # type: CredentialService
            # Services where "username" field is required
            if service in (S.AS400, S.CIFS, S.CIFSHASH, S.CVS, S.DB2, S.FTP, S.HTTP, S.MS_SQL, S.MYSQL, S.ORACLE,
                           S.POP, S.POSTGRESQL, S.REMOTE_EXEC, S.SNMPV3, S.SSH, S.SSH_KEY, S.SYBASE, S.TELNET):
                if username is None:
                    raise ValueError(f"Username is required for \"{service.value}\" services.")

                account_data["username"] = username

            # Services where "password" field is required
            if service in (S.AS400, S.CIFS, S.CIFSHASH, S.CVS, S.DB2, S.FTP, S.HTTP, S.MS_SQL, S.MYSQL,
                           S.ORACLE, S.POP, S.POSTGRESQL, S.REMOTE_EXEC, S.SSH, S.SYBASE, S.TELNET):
                if password is None:
                    raise ValueError(f"Password is required for \"{service.value}\" services.")

                account_data["password"] = password

            # Services with optional "useWindowsAuthentication" field.
            if service in (S.MS_SQL, S.SYBASE) and use_windows_authentication is not None:
                account_data["useWindowsAuthentication"] = use_windows_authentication

            # Services with optional "domain" field.
            if service in (S.AS400, S.CIFS, S.CIFSHASH, S.CVS, S.MS_SQL, S.SYBASE) and domain is not None:
                if service in (S.MS_SQL, S.SYBASE):
                    if use_windows_authentication:
                        account_data["domain"] = domain

                else:
                    account_data["domain"] = domain

            # Services with optional "database" field.
            if service in (S.DB2, S.MS_SQL, S.MYSQL, S.POSTGRESQL, S.SYBASE) and database_name is not None:
                account_data["database"] = database_name

            if service == S.CIFSHASH:
                if ntlm_hash is None:
                    raise ValueError(f"NTLM hash is required for \"{service.value}\" services.")

                account_data["ntlmHash"] = ntlm_hash

            if service == S.HTTP and http_realm is not None:
                account_data["realm"] = http_realm

            if service == S.NOTES and notes_id_password is not None:
                account_data["notesIDPassword"] = notes_id_password

            if service == S.ORACLE:
                if oracle_sid is not None:
                    account_data["sid"] = oracle_sid

                if oracle_enumerate_sids is not None:
                    account_data["enumerateSids"] = oracle_enumerate_sids

                    if oracle_enumerate_sids and oracle_listener_password is None:
                        raise ValueError("Oracle listener password is required when enumerating SIDs.")

                    account_data["oracleListenerPassword"] = oracle_listener_password

            if service == S.SNMP:
                if snmp_community_name is None:
                    raise ValueError(f"Community name is required for \"{service.value}\" services.")

                account_data["community"] = snmp_community_name

            if service == S.SNMPV3:
                if snmpv3_authentication_type is None:
                    raise ValueError(f"Authentication type is required for \"{service.value}\" services.")

                account_data["authenticationType"] = snmpv3_authentication_type.value

                if snmpv3_authentication_type != SNMPv3AuthenticationType.NO_AUTHENTICATION:
                    if password is None:
                        raise ValueError(f"Password is required for \"{service.value}\" services when authentication "
                                         f"is md5 to anything other than \"no-authentication\".")

                    account_data["password"] = password

                if snmpv3_privacy_type is not None:  # TODO: Should privacy_type be required?
                    account_data["privacyType"] = snmpv3_privacy_type.value

                    if snmpv3_privacy_type != SNMPv3PrivacyType.NO_PRIVACY and snmpv3_privacy_password is None:
                        raise ValueError(f"Privacy password is required for \"{service.value}\" services when the "
                                         f"authentication type is set to a value other than \"no-authentication\", "
                                         f"and privacy type is set to a value other than \"no-privacy\".")

                    account_data["privacyPassword"] = snmpv3_privacy_password

            if service in (S.SSH, S.SSH_KEY):
                if ssh_permission_elevation:
                    account_data["permissionElevation"] = ssh_permission_elevation

                if ssh_permission_elevation not in (SSHElevationType.NONE, SSHElevationType.PBRUN):
                    if None in (ssh_permission_elevation_username, ssh_permission_elevation_password):
                        raise ValueError(f"Elevation username and password are required for \"{service.value}\" "
                                         f"services when permission elevation is not \"none\" or \"pbrun\".")

                    account_data["permissionElevationUsername"] = ssh_permission_elevation_username
                    account_data["permissionElevationPassword"] = ssh_permission_elevation_password

            if service == S.SSH_KEY:
                if ssh_key_pem is None:
                    raise ValueError(f"SSH private key password is required for \"{service.value}\" services.")

                account_data["pemKey"] = ssh_key_pem

                if ssh_private_key_password is None:  # TODO: Check if actually required
                    raise ValueError(f"SSH private key password is required for \"{service.value}\" services.")

                account_data["privateKeyPassword"] = ssh_private_key_password

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

    def update_site_scan_schedule(self, site_id: str, scan_schedule_id: int, start_date: str,
                                  excluded_asset_groups: Optional[list[int]] = None,
                                  excluded_targets: Optional[list[str]] = None,
                                  included_asset_groups: Optional[list[int]] = None,
                                  included_targets: Optional[list[str]] = None,
                                  duration: Optional[str] = None, enabled: bool = None,
                                  repeat_behaviour: Optional[RepeatBehaviour] = None,
                                  frequency: Optional[RepeatFrequencyType] = None,
                                  interval: Optional[int] = None, date_of_month: Optional[int] = None,
                                  scan_name: Optional[str] = None, scan_template_id: Optional[str] = None) -> dict:
        """
        | Update a site scan schedule.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/updateSiteScanSchedule

        Args:
            site_id (str): ID of the site to create a new scheduled scan for.
            scan_schedule_id (int): ID of the scan schedule to update.
            start_date (str): The scheduled start date and time formatted in ISO 8601 format.
            excluded_asset_groups (list[int], optional): Asset groups to exclude from the scan.
            excluded_targets (list[str], optional): Addresses to exclude from the scan. Each address is a string that
                can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
            included_asset_groups (list[int], optional): Asset groups to include in the scan.
            included_targets (list[str], optional): Addresses to include in the scan.  Each address is a string that
                can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
            duration (str, optional): An ISO 8601 formatted duration string that Specifies the maximum duration
                the scheduled scan is allowed to run.
            enabled (bool): A flag indicating whether the scan schedule is enabled.
            repeat_behaviour (RepeatBehaviour, optional): The desired behavior of a repeating scheduled scan
                when the previous scan was paused due to reaching its maximum duration.
            frequency (RepeatFrequencyType, optional): Frequency for the schedule to repeat.
                Required if using other repeat settings.
            interval (int, optional): The interval time the schedule should repeat.
                Required if using other repeat settings.
            date_of_month(int, optional): Specifies the schedule repeat day of the interval month.
                Required and used only if frequency is set to `DATE_OF_MONTH`.
            scan_name (str, optional): A unique user-defined name for the scan launched by the schedule.
                If not explicitly set in the schedule, the scan name will be generated prior to the scan launching.
            scan_template_id (str, optional): ID of the scan template to use.

        Returns:
            str: ID of the newly created scan schedule.
        """
        assets = {}
        repeat = {}

        if excluded_asset_groups:
            assets["excludedAssetGroups"] = {"assetGroupIDs": excluded_asset_groups}

        if excluded_targets:
            assets["excludedTargets"] = {"addresses": excluded_targets}

        if included_asset_groups:
            assets["includedAssetGroups"] = {"assetGroupIDs": included_asset_groups}

        if included_targets:
            assets["includedTargets"] = {"addresses": included_targets}

            if not interval:
                raise ValueError("'interval' parameter must be set if frequency is used.")

            if frequency == RepeatFrequencyType.DATE_OF_MONTH and not date_of_month:
                raise ValueError("'date-of-month' parameter must be set if frequency is set to 'Date of month'.")

            repeat = find_valid_params(
                every=frequency.value,
                interval=interval,
                dateOfMonth=date_of_month,
            )

        post_data = find_valid_params(
            assets=assets,
            duration=duration,
            enabled=enabled,
            onScanRepeat=repeat_behaviour.value,
            repeat=repeat,
            scanName=scan_name,
            scanTemplateId=scan_template_id,
            start=start_date,
        )

        return self._http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules/{scan_schedule_id}",
            method="PUT",
            json_data=post_data,
            resp_type="json",
        )

    def update_vulnerability_exception_status(self, vulnerability_exception_id: str,
                                              status: VulnerabilityExceptionStatus) -> dict:
        """
        | Update the status of a vulnerability exception.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/updateVulnerabilityExceptionStatus

        Args:
            vulnerability_exception_id (str): ID of the vulnerability exception to update.
            status (VulnerabilityExceptionStatus): Status to set the vulnerability exception to.

        Returns:
            dict: API response with information about the updated vulnerability exception.
        """
        return self._http_request(
            url_suffix=f"/vulnerability_exceptions/{vulnerability_exception_id}/{status.value}",
            method="POST",
            resp_type="json",
        )

    def update_vulnerability_exception_expiration(self, vulnerability_exception_id: str, expiration_date: str) -> dict:
        """
        | Update the expiration date for a vulnerability exception.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerabilityExceptionExpiration

        Args:
            vulnerability_exception_id (str): ID of the vulnerability exception to update.
            expiration_date (str): The new expiration date for the vulnerability exception.

        Returns:
            dict: API response with information about the updated vulnerability exception.
        """
        headers = self._headers.copy()
        headers.update({"Content-Type": "text/plain"})

        return self._http_request(
            url_suffix=f"/vulnerability_exceptions/{vulnerability_exception_id}/expires",
            method="PUT",
            headers=headers,
            data=expiration_date.encode("utf-8"),  # type: ignore
            resp_type="json",
        )

    def find_site_id(self, name: str) -> Optional[str]:
        """
        Find a site ID by its name.

        Returns:
            str | None: Site ID corresponding to the passed name. None if no match was found.
        """
        for site in self.get_sites():
            if site["name"] == name:
                return str(site["id"])

        return None


class Site:
    """A class representing a site, which can be identified by ID or name."""

    def __init__(self, site_id: Optional[str] = None,
                 site_name: Optional[str] = None, client: Optional[Client] = None) -> None:
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
        self.name: Optional[str] = None

        if site_id:
            self.id = site_id

        elif site_name:
            self.name = site_name

            if client:
                site_id = client.find_site_id(site_name)

                if not site_id:
                    raise InvalidSiteNameException(f"No site with name `{site_name}` was found.")

                self.id = site_id

            else:
                raise ValueError("Can't fetch site ID as no Client was provided.")

        else:
            raise ValueError("Either a site ID or a site name must be passed.")

        self.name = site_name
        self._client = client


def convert_asset_search_filters(search_filters: Union[str, list[str]]) -> list[dict]:
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
    if isinstance(search_filters, str):
        search_filters = [search_filters]

    range_operators = ["in-range", "is-between", "not-in-range"]
    normalized_filters = []

    for search_filter in search_filters:
        # Example: risk-score is-between 5,10
        #   _field = risk-score
        #   _operator = is-greater-than
        #   _value = 5,10
        _field, _operator, _value = search_filter.split(" ")
        values = argToList(_value)

        # Convert numbers to floats if values are numbers
        # TODO: Check if float conversion has any meaning, remove if not
        for i, value in enumerate(values):
            try:
                values[i] = float(value)

            except Exception:
                pass

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
        else:
            filter_dict["value"] = values[0]

        normalized_filters.append(filter_dict)

    return normalized_filters


def convert_datetime_str(time_str: str) -> struct_time:
    """
    Convert a time string formatted in one of the time formats used by Nexpose's API
        for scans to a `struct_time` object.

    Args:
        time_str (str): A time string formatted in one of the time formats used by Nexpose's API for scans.

    Returns:
        struct_time: The datetime represented in a `struct_time` object.
    """
    try:
        return strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")

    except ValueError:
        return strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")


def create_report(client: Client, scope: dict[str, Any], template_id: Optional[str] = None,
                  report_name: Optional[str] = None, report_format: Optional[ReportFileFormat] = None,
                  download_immediately: Optional[bool] = None) -> Union[dict, CommandResults]:
    """
    Create a report and optionally download it.

    Args:
        client (Client): Client to use for API requests.
        scope (dict[str, Any]): Scope of the report, see Nexpose's documentation for more details.
        template_id (str | None, optional): ID of report template to use.
            Defaults to None (will result in using the first available template)
        report_name (str, optional): Name for the report that will be generated. Uses "report {date}" by default.
        report_format (ReportFileFormat, optional): Format of the report that will be generated. Defaults to PDF.
        download_immediately: (bool | None, optional) = Whether to download the report automatically after creation.
            Defaults to True.
    """
    if not template_id:
        templates = client.get_report_templates()

        if not templates.get("resources"):
            return CommandResults(readable_output="Error: No available templates were found.")

        template_id = templates["resources"][0]["id"]

    if not report_name:
        report_name = "report " + str(datetime.now())

    if not report_format:
        report_format = ReportFileFormat.PDF

    if download_immediately is None:
        download_immediately = True

    report_id = client.create_report_config(
        scope=scope,
        template_id=template_id,
        report_name=report_name,
        report_format=report_format,
    )["id"]

    instance_id = client.create_report(report_id)["id"]

    context = {
        "Name": report_name,
        "ID": report_id,
        "InstanceID": instance_id,
        "Format": report_format.value,
    }
    hr = tableToMarkdown("Report Information", context)

    if download_immediately:
        try:
            # Wait for the report to be completed
            time.sleep(REPORT_DOWNLOAD_WAIT_TIME)

            return download_report_command(
                client=client,
                report_id=report_id,
                instance_id=instance_id,
                report_name=report_name,
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
    )


def dq(obj, path):
    """
    return a value in an object path. in case of multiple objects in path, searches them all.
    @param obj - dictionary tree to search in
    @param path (list) - a path of the desired value in the object. for example ['root', 'key', 'subkey']
    """
    # TODO: Remove or rewrite this function
    if len(path) == 0:
        return obj

    if isinstance(obj, dict):
        if path[0] in obj:
            return dq(obj[path[0]], path[1:])
    elif isinstance(obj, list):
        # in case current obj has multiple objects, search them all.
        line = [dq(o, path) for o in obj]
        return [k for k in line if k is not None]

    # in case of error in the path
    return None


def enrich_asset_data(asset: dict) -> dict:
    """
    Enrich asset data with additional information.

    Args:
        asset (dict): A dictionary representing an asset as received from the API.

    Returns:
        dict: The enriched asset data.
    """
    last_scan = find_asset_last_change(asset)
    asset["LastScanDate"] = last_scan["date"]
    asset["LastScanId"] = last_scan["id"]
    site = find_site_from_asset(asset["id"])

    if site:
        asset["Site"] = site["name"]

    return asset


def find_asset_last_change(asset_data: dict) -> dict:
    """
    Retrieve the last change (usually a scan) from an asset's history.

    Args:
        asset_data (dict): The asset data as it was retrieved from the API.

    Returns:
        dict: A dictionary containing data about the latest change in asset's history.
    """
    if not asset_data.get("history"):
        return {
            "date": "-",
            "id": "-"
        }

    sorted_scans = sorted(asset_data["history"], key=lambda x: convert_datetime_str(x.get("date")), reverse=True)

    return {
        "date": sorted_scans[0]["date"] if "date" in sorted_scans[0] else "-",
        "id": sorted_scans[0]["scanId"] if "scanId" in sorted_scans[0] else "-"
    }


def find_valid_params(**kwargs):
    """
    A function for filtering kwargs to remove keys with a None value.

    Args:
        kwargs: A collection of keyword args to filter.

    Returns:
        dict: A dictionary containing only keywords with a value that isn't None.
    """
    new_kwargs = {}

    for key, value in kwargs.items():
        if value:
            new_kwargs[key] = value

    return new_kwargs


def get_scan_entry(scan: dict) -> CommandResults:
    """
    Generate entry data from scan data (as received from the API).
    NOTE: This function alters scan data for HR, and returns that way in ContextData as well.
          For example, if "id" turns to "ID" in HR, the change also applies for ContextData.

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

    vulnerability_output = replace_key_names(
        data=scan["vulnerabilities"],
        name_mapping={
            "critical": "Critical",
            "severe": "Severe",
            "moderate": "Moderate",
            "total": "Total",
        },
        recursive=True,
        no_copy=True,
    )

    scan_hr = tableToMarkdown(
        name="Nexpose scan " + str(scan["id"]),
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


def get_session():
    # TODO: Remove alongside get_site once get_site is removed
    url = demisto.params()["server"].rstrip("/") + "/data/user/login"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }

    if demisto.params().get("token"):
        headers["token"] = demisto.params().get("token")

    body = {
        "nexposeccusername": demisto.params()["credentials"]["identifier"],
        "nexposeccpassword": demisto.params()["credentials"]["password"]
    }

    res = requests.post(url, headers=headers, data=body, verify=not demisto.params().get("unsecure", False))
    if res.status_code < 200 or res.status_code >= 300:
        return ""
    body = res.json()
    if "sessionID" not in body:
        return ""

    return body["sessionID"]


def find_site_from_asset(asset_id: str):
    # TODO: Remove demisto.params() and improve code,
    #       Check why this function uses a non-API endpoint, and adjust this function accordingly.
    url = demisto.params()["server"].rstrip("/") + "/data/assets/" + str(asset_id) + "/scans"
    username = demisto.params()["credentials"]["identifier"]
    password = demisto.params()["credentials"]["password"]
    token = demisto.params().get("token")
    verify = not demisto.params().get("unsecure", False)
    session = get_session()

    headers = {"Content-Type": "application/json"}

    if token:
        headers["token"] = token

    headers["Cookie"] = "nexposeCCSessionID=" + session
    headers["nexposeCCSessionID"] = session

    res = requests.post(url, headers=headers, auth=(username, password), verify=verify)

    if res.status_code < 200 or res.status_code >= 300:
        return ""

    response = res.json()
    if response is None or response["records"] is None or len(response["records"]) == 0:
        return ""

    return {
        "id": response["records"][0]["siteID"],
        "name": response["records"][0]["siteName"],
        "ip": response["records"][0]["ipAddress"]
    }


def generate_duration_time(years: Optional[int] = None, months: Optional[int] = None,
                           weeks: Optional[int] = None, days: Optional[int] = None,
                           hours: Optional[int] = None, minutes: Optional[int] = None,
                           seconds: Optional[float] = None) -> Optional[str]:
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


def normalize_scan_data(scan: dict) -> dict:
    """
    Normalizes scan data received from the API to a HumanReadable format that will be displayed in the UI.
    NOTE: This function alters the original data that's passed under the `scan` parameter, and does not create a copy.

    Args:
        scan (dict): Scan data as it was received from the API.

    Returns:
        dict: Scan data in a normalized format that will be displayed in the UI.
    """
    scan_output = replace_key_names(
        data=scan,
        name_mapping={
            "id": "Id",
            "scanType": "ScanType",
            "scanName": "ScanName",
            "startedBy": "StartedBy",
            "assets": "Assets",
            "duration": "TotalTime",
            "endTime": "Completed",
            "status": "Status",
            "message": "Message",
        },
        recursive=False,
        no_copy=True,
    )

    scan_output["TotalTime"] = readable_duration_time(scan_output["TotalTime"])

    return scan_output


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
        "P": "years",
        "M": "months",
        "W": "weeks",
        "D": "days",
    }
    duration_mapping_t = {
        "H": "hours",
        "M": "minutes",
        "S": "seconds",
    }
    duration_values = {
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
        number = float(item[:-1])

        if number.is_integer():
            number = int(number)

        else:
            number = round(number)

        duration_values[duration_mapping_p[designator]] = number

    for item in t_duration:
        designator = item[-1]
        number = float(item[:-1])

        if number.is_integer():
            number = int(number)

        duration_values[duration_mapping_t[designator]] = number

    result = []
    for item in duration_values:
        zero_up_to_now = True

        if duration_values[item] > 0:
            zero_up_to_now = False

        if not zero_up_to_now:
            result += [f"{duration_values[item]} {item}"]

    return ", ".join(result)


# TODO: Disable "recursive" if it's not actually needed.
def replace_key_names(data: Union[dict, list, tuple], name_mapping: dict[str, str],
                      recursive: bool = False, no_copy: bool = False) -> Union[dict, list, tuple, set]:
    """
    Replace key names in a dictionary.

    Args:
        data (dict | list | tuple): An iterable to replace key names for dictionaries within it.
        name_mapping (dict): A dictionary in a `from (key): to (value)` mapping format
                             of which key names to replace with what.
                             The value of the keys can represent nested dict items in a "parent.child" format.
        recursive (bool, optional): Whether to replace key names in all sub-dictionaries. Defaults to False.
        no_copy (bool, optional): If set to true, the function will replace the keys in the original dictionary
                                  and return it, instead of creating, applying changes, and returning a new copy.

    Returns:
        Union[dict, list, tuple]: The data-structure (original or copy)
                                  with key names of dicts replaced according to mapping.
    """
    # TODO: Fix issue when nested key is inside a list

    if not no_copy:
        data = deepcopy(data)

    if isinstance(data, Union[list, tuple]):
        return [replace_key_names(
            data=data[i],
            name_mapping=name_mapping,
            recursive=recursive,
            no_copy=True,
        ) for i in range(len(data))]

    elif isinstance(data, dict):
        for key, value in name_mapping.items():
            nested_keys = key.split(".")
            data_iterator = data

            while nested_keys:
                current_key = nested_keys.pop()

                if data.get(current_key):
                    if len(nested_keys) == 0:
                        data[value] = data.pop(current_key)
                        break

                    else:
                        data_iterator = data_iterator[current_key]

                else:
                    break

        if recursive:
            for item in data:
                if isinstance(data[item], Union[dict, list, tuple]):
                    data[item] = replace_key_names(
                        data=data[item],
                        name_mapping=name_mapping,
                        recursive=recursive,
                        no_copy=True,
                    )

    return data


# --- Command Functions --- #
def create_assets_report_command(client: Client, asset_ids: list[str], template_id: Optional[str] = None,
                                 report_name: Optional[str] = None,
                                 report_format: Optional[ReportFileFormat] = None,
                                 download_immediately: Optional[bool] = None) -> Union[dict, CommandResults]:
    """
    Create a report about specific assets.

    Args:
        client (Client): Client to use for API requests.
        asset_ids (list[str]): List of assets to include in the report.
        template_id (str | None, optional): ID of report template to use.
            Defaults to None (will result in using the first available template)
        report_name (str, optional): Name for the report that will be generated. Uses "report {date}" by default.
        report_format (ReportFileFormat, optional): Format of the report that will be generated. Defaults to PDF.
        download_immediately: (bool | None, optional) = Whether to download the report automatically after creation.
            Defaults to True.
    """
    scope = {"assets": [int(asset_id) for asset_id in asset_ids]}

    return create_report(
        client=client,
        scope=scope,
        template_id=template_id,
        report_name=report_name,
        report_format=report_format,
        download_immediately=download_immediately,
    )


def create_scan_report_command(client: Client, scan_id: str, template_id: Optional[str] = None,
                               report_name: Optional[str] = None, report_format: Optional[ReportFileFormat] = None,
                               download_immediately: Optional[bool] = None) -> Union[dict, CommandResults]:
    """
    Create a report about specific sites.

    Args:
        client (Client): Client to use for API requests.
        scan_id (scan): ID of the scan to create a report on.
        template_id (str | None, optional): ID of report template to use.
            Defaults to None (will result in using the first available template)
        report_name (str, optional): Name for the report that will be generated. Uses "report {date}" by default.
        report_format (ReportFileFormat, optional): Format of the report that will be generated. Defaults to PDF.
        download_immediately: (bool | None, optional) = Whether to download the report automatically after creation.
            Defaults to True.
    """
    scope = {"scan": scan_id}

    if report_format is not None:
        report_format = report_format.value

    return create_report(
        client=client,
        scope=scope,
        template_id=template_id,
        report_name=report_name,
        report_format=report_format,
        download_immediately=download_immediately,
    )


def create_scan_schedule_command(client: Client, site: Site, enabled: bool, repeat_behaviour: RepeatBehaviour,
                                 start_date: str, excluded_asset_groups: Optional[list[int]] = None,
                                 excluded_targets: Optional[list[str]] = None,
                                 included_asset_groups: Optional[list[int]] = None,
                                 included_targets: Optional[list[str]] = None, duration_days: Optional[int] = None,
                                 duration_hours: Optional[int] = None, duration_minutes: Optional[int] = None,
                                 frequency: Optional[RepeatFrequencyType] = None, interval: Optional[int] = None,
                                 scan_name: Optional[str] = None, date_of_month: Optional[int] = None,
                                 scan_template_id: Optional[str] = None) -> CommandResults:
    """
    Create a new site scan schedule.

    Args:
        client (Client): Client to use for API requests.
        site (Site): Site to create a scheduled scan for.
        enabled (bool, optional): A flag indicating whether the scan schedule is enabled.
           Defaults to None, which results in using True.
        repeat_behaviour (RepeatBehaviour): The desired behavior of a repeating scheduled scan
            when the previous scan was paused due to reaching its maximum duration.
        start_date (str): The scheduled start date and time formatted in ISO 8601 format.
        excluded_asset_groups (list[int], optional): Asset groups to exclude from the scan.
        excluded_targets (list[str], optional): Addresses to exclude from the scan. Each address is a string that
            can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
        included_asset_groups (list[int], optional): Asset groups to include in the scan.
        included_targets (list[str], optional): Addresses to include in the scan.  Each address is a string that
            can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
        duration_days (int, optional): Maximum duration of the scan in days.
            Can be used along with `duration_hours` and `duration_minutes`.
        duration_hours (int, optional): Maximum duration of the scan in hours.
            Can be used along with `duration_days` and `duration_minutes`.
        duration_minutes (int, optional): Maximum duration of the scan in minutes.
            Can be used along with `duration_days` and `duration_hours`.
        frequency (RepeatFrequencyType, optional): Frequency for the schedule to repeat.
            Required if using other repeat settings.
        interval (int, optional): The interval time the schedule should repeat.
            Required if using other repeat settings.
        date_of_month(int, optional): Specifies the schedule repeat day of the interval month.
            Required and used only if frequency is set to `DATE_OF_MONTH`.
        scan_name (str, optional): A unique user-defined name for the scan launched by the schedule.
            If not explicitly set in the schedule, the scan name will be generated prior to the scan launching.
        scan_template_id (str, optional): ID of the scan template to use.
    """
    duration = generate_duration_time(
        days=duration_days,
        hours=duration_hours,
        minutes=duration_minutes)

    response_data = client.create_site_scan_schedule(
        site_id=site.id,
        enabled=enabled,
        repeat_behaviour=repeat_behaviour,
        start_date=start_date,
        excluded_asset_groups=excluded_asset_groups,
        excluded_targets=excluded_targets,
        included_asset_groups=included_asset_groups,
        included_targets=included_targets,
        duration=duration,
        frequency=frequency,
        interval=interval,
        date_of_month=date_of_month,
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


def create_shared_credential_command(client: Client, name: str,
                                     site_assignment: SharedCredentialSiteAssignment,
                                     service: CredentialService,
                                     database_name: Optional[str] = None,
                                     description: Optional[str] = None,
                                     domain: Optional[str] = None,
                                     host_restriction: Optional[str] = None,
                                     http_realm: Optional[str] = None,
                                     notes_id_password: Optional[str] = None,
                                     ntlm_hash: Optional[str] = None,
                                     oracle_enumerate_sids: Optional[bool] = None,
                                     oracle_listener_password: Optional[str] = None,
                                     oracle_sid: Optional[str] = None,
                                     password: Optional[str] = None,
                                     port_restriction: Optional[str] = None,
                                     sites: Optional[List[int]] = None,
                                     snmp_community_name: Optional[str] = None,
                                     snmpv3_authentication_type: Optional[SNMPv3AuthenticationType] = None,
                                     snmpv3_privacy_password: Optional[str] = None,
                                     snmpv3_privacy_type: Optional[SNMPv3PrivacyType] = None,
                                     ssh_key_pem: Optional[str] = None,
                                     ssh_permission_elevation: Optional[SSHElevationType] = None,
                                     ssh_permission_elevation_password: Optional[str] = None,
                                     ssh_permission_elevation_username: Optional[str] = None,
                                     ssh_private_key_password: Optional[str] = None,
                                     use_windows_authentication: Optional[bool] = None,
                                     username: Optional[str] = None) -> CommandResults:
    """
    Create a new shared credential.

    Args:
        client (Client): Client to use for API requests.
        name (str): Name of the credential.
        site_assignment (SharedCredentialSiteAssignment): Site assignment configuration for the credential.
            Assign the shared scan credential either to be available to all sites, or a specific list of sites.
        service (CredentialService): Credential service type.
        database_name (str, optional): Database name.
        description (str, optional): Description for the credential.
        domain (str, optional): Domain address.
        host_restriction (str, optional): Hostname or IP address to restrict the credentials to.
        http_realm (str, optional): HTTP realm.
        notes_id_password (str, optional): Password for the notes account that will be used for authenticating.
        ntlm_hash (str, optional): NTLM password hash.
        oracle_enumerate_sids (bool, optional): Whether the scan engine should attempt to enumerate
            SIDs from the environment.
        oracle_listener_password (str, optional): The Oracle Net Listener password.
            Used to enumerate SIDs from the environment.
        oracle_sid (str, optional): Oracle database name.
        password (str, optional): Password for the credential.
        port_restriction (str, optional): Further restricts the credential to attempt to authenticate
            on a specific port. Can be used only if `host_restriction` is used.
        sites (List[int], optional): List of site IDs for the shared credential that are explicitly assigned
            access to the shared scan credential, allowing it to use the credential during a scan.
        snmp_community_name (str, optional): SNMP community for authentication.
        snmpv3_authentication_type (SNMPv3AuthenticationType): SNMPv3 authentication type for the credential.
        snmpv3_privacy_password (str, optional): SNMPv3 privacy password to use.
        snmpv3_privacy_type (SNMPv3PrivacyType, optional): SNMPv3 Privacy protocol to use.
        ssh_key_pem (str, optional): PEM formatted private key.
        ssh_permission_elevation (SSHElevationType, optional): Elevation type to use for scans.
        ssh_permission_elevation_password (str, optional): Password to use for elevation.
        ssh_permission_elevation_username (str, optional): Username to use for elevation.
        ssh_private_key_password (str, optional): Password for the private key.
        use_windows_authentication (bool, optional): Whether to use Windows authentication.
        username (str, optional): Username for the credential.
    """
    response_data = client.create_shared_credential(
            name=name,
            site_assignment=site_assignment,
            service=service,
            database_name=database_name,
            description=description,
            domain=domain,
            host_restriction=host_restriction,
            http_realm=http_realm,
            notes_id_password=notes_id_password,
            ntlm_hash=ntlm_hash,
            oracle_enumerate_sids=oracle_enumerate_sids,
            oracle_listener_password=oracle_listener_password,
            oracle_sid=oracle_sid,
            password=password,
            port_restriction=port_restriction,
            sites=sites,
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

    return CommandResults(
        readable_output=f"New shared credential has been created with ID {response_data['id']}.",
        outputs_prefix="Nexpose.SharedCredential",
        outputs_key_field="id",
        outputs={"id": response_data['id']},
        raw_response=response_data,
    )


def create_site_command(client: Client, name: str, description: Optional[str] = None,
                        assets: Optional[list[str]] = None, site_importance: Optional[SiteImportance] = None,
                        template_id: Optional[str] = None) -> CommandResults:
    """
    Create a new site.

    Args:
        client (Client): Client to use for API requests.
        name (str): Name of the site. Must be unique.
        description (str | None, optional): Description of the site. Defaults to None.
        assets (list[str] | None, optional): List of asset IDs to be included in site scans. Defaults to None.
        site_importance (SiteImportance | None, optional): Importance of the site.
            Defaults to None (results in using API's default - "normal").
        template_id (str | None, optional): The identifier of a scan template.
            Defaults to None (results in using default scan template).
    """
    response_data = client.create_site(
        name=name,
        description=description,
        assets=assets,
        site_importance=site_importance,
        template_id=template_id)

    return CommandResults(
        readable_output=f"New site has been created with ID {response_data['id']}.",
        outputs_prefix="Nexpose.Site",
        outputs_key_field="Id",
        outputs={"Id": response_data['id']},
        raw_response=response_data,
    )


def create_sites_report_command(client: Client, sites: list[Site],
                                template_id: Optional[str] = None, report_name: Optional[str] = None,
                                report_format: Optional[ReportFileFormat] = None,
                                download_immediately: Optional[bool] = None) -> Union[dict, CommandResults]:
    """
    Create a report about specific sites.

    Args:
        client (Client): Client to use for API requests.
        sites (list[Site]): List of sites to create the report about.
        template_id (str | None, optional): ID of report template to use.
            Defaults to None (will result in using the first available template)
        report_name (str, optional): Name for the report that will be generated. Uses "report {date}" by default.
        report_format (ReportFileFormat, optional): Format of the report that will be generated. Defaults to PDF.
        download_immediately: (bool | None, optional) = Whether to download the report automatically after creation.
            Defaults to True.
    """
    scope = {"sites": sites}

    if report_format is not None:
        report_format = report_format.value

    return create_report(
        client=client,
        scope=scope,
        template_id=template_id,
        report_name=report_name,
        report_format=report_format,
        download_immediately=download_immediately,
    )


def create_vulnerability_exception_command(client: Client, vulnerability_id: str,
                                           scope_type: VulnerabilityExceptionScopeType,
                                           state: VulnerabilityExceptionState, reason: VulnerabilityExceptionReason,
                                           expires: Optional[str] = None,
                                           comment: Optional[str] = None) -> CommandResults:
    """
    Create a vulnerability exception.

    Args:
        client (Client): Client to use for API requests.
        vulnerability_id (str): ID of the vulnerability to create the exception for.
        scope_type (VulnerabilityExceptionScopeType): The type of the exception scope.
        state (VulnerabilityExceptionState): The state of the vulnerability exception.
        reason (VulnerabilityExceptionReason): The reason the vulnerability exception was submitted.
        expires (str | None, optional): The date and time the vulnerability exception is set to expire.
        comment (str | None, optional): A comment from the submitter as to why the exception was submitted.
    """
    response_data = client.create_vulnerability_exception(
        vulnerability_id=vulnerability_id,
        scope_type=scope_type,
        state=state,
        reason=reason,
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


def delete_scheduled_scan_command(client: Client, site: Site, scheduled_scan_id: str) -> CommandResults:
    """
    Delete a scheduled scan.

    Args:
        client (Client): Client to use for API requests.
        site (Site): Site to delete the scheduled scan from.
        scheduled_scan_id (str): ID of the scheduled scan to delete.

    Returns:
        dict: API response.
    """
    client.delete_scan_schedule(
        site_id=site.id,
        scheduled_scan_id=scheduled_scan_id,
    )

    return CommandResults(readable_output=f"Scheduled scan with ID {scheduled_scan_id} has been deleted.")


def delete_site_command(client: Client, site: Site) -> CommandResults:
    """
    Delete a site.

    Args:
        client (Client): Client to use for API requests.
        site (Site): Site to delete.
    """
    client.delete_site(site.id)

    return CommandResults(
        readable_output=f"Site ID {site.id} has been deleted.",
        outputs_prefix="Nexpose.Report",
        outputs_key_field=["ID", "InstanceID"],
    )


def delete_shared_credential_command(client: Client, shared_credential_id: str) -> CommandResults:
    """
    Delete a shared credential.

    Args:
        client (Client): Client to use for API requests.
        shared_credential_id (str): ID of the shared credential to delete.
    """
    client.delete_shared_credential(shared_credential_id)
    return CommandResults(readable_output=f"Shared credential with ID {shared_credential_id} has been deleted.")


def delete_vulnerability_exception_command(client: Client, vulnerability_exception_id: str) -> CommandResults:
    """
    Delete a vulnerability exception.

    Args:
        client (Client): Client to use for API requests.
        vulnerability_exception_id (str): ID of the vulnerability exception to delete.
    """
    client.delete_vulnerability_exception(vulnerability_exception_id)

    return CommandResults(
        readable_output=f"Vulnerability exception with ID {vulnerability_exception_id} has been deleted.")


def download_report_command(client: Client, report_id: str, instance_id: str,
                            report_format: ReportFileFormat, report_name: Optional[str] = None) -> dict:
    """
    Download a report file.

    Args:
        client (Client): Client to use for API requests.
        report_id (str): ID of the report to download.
        instance_id (str): ID of the report instance.
        report_format (ReportFileFormat): File format to use for the generated report.
        report_name (str | None, optional): Name to give the generated report file.
            Defaults to None (results in using a "report <date>" format as a name).

    Returns:
        dict: A dict generated by `CommonServerPython.fileResult` representing a War Room entry.
    """
    # TODO: Check if format can actually be changed from the default PDF received from Nexpose. Delete if not?

    if not report_name:
        report_name = f"report {str(datetime.now())}"

    report_data = client.download_report(
        report_id=report_id,
        instance_id=instance_id
    )

    return fileResult(
        filename=f"{report_name}.{report_format.value}",
        data=report_data,
        file_type=entryTypes["entryInfoFile"],
    )


def get_asset_command(client: Client, asset_id: str) -> CommandResults:
    """
    Retrieve information about an asset.

    Args:
        client (Client): Client to use for API requests.
        asset_id (str): ID of the asset to retrieve information about.
    """
    asset = client.get_asset(asset_id)

    if asset.get("status") == "404":
        return CommandResults(readable_output="Asset not found")

    last_scan = find_asset_last_change(asset)
    asset["LastScanDate"] = last_scan["date"]
    asset["LastScanId"] = last_scan["id"]
    asset["Site"] = find_site_from_asset(asset["id"])["name"]

    asset_headers = [
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

    asset_output = replace_key_names(
        data=asset,
        name_mapping={
            "id": "AssetId",
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
        recursive=True,
        no_copy=True,
    )

    # Set all vars to None
    software_headers = software_output = service_headers = services_output = users_headers = users_output = None

    if "software" in asset and len(asset["software"]) > 0:
        software_headers = [
            "Software",
            "Version",
        ]

        software_output = replace_key_names(
            data=asset["software"],
            name_mapping={
                "description": "Software",
                "version": "Version",
            },
            recursive=True,
            no_copy=True,
        )

    if "services" in asset and len(asset["services"]) > 0:
        service_headers = [
            "Name",
            "Port",
            "Product",
            "Protocol",
        ]

        services_output = replace_key_names(
            data=asset["services"],
            name_mapping={
                "name": "Name",
                "port": "Port",
                "product": "Product",
                "protocol": "Protocol",
            },
            recursive=True,
            no_copy=True,
        )

    if "users" in asset and len(asset["users"]) > 0:
        users_headers = [
            "FullName",
            "Name",
            "UserId",
        ]

        users_output = replace_key_names(
            data=asset["users"],
            name_mapping={
                "name": "Name",
                "fullName": "FullName",
                "id": "UserId",
            },
            recursive=True,
            no_copy=True,
        )

    vulnerability_headers = [
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

    vulnerabilities = client.get_vulnerabilities(asset["id"])
    asset["vulnerabilities"] = vulnerabilities

    vulnerabilities_output = []
    cves_output = []

    for idx, vulnerability in enumerate(asset["vulnerabilities"]):
        extra_info = client.get_vulnerability(vulnerability["id"])
        asset["vulnerabilities"][idx].update(extra_info)

        cvss = dq(extra_info["cvss"], ["v2", "score"])  # TODO: Find a more intuitive way to do this without dq

        if "cves" in extra_info:
            cves_output.extend(
                [{"ID": cve} for cve in extra_info["cves"]]
            )

        output_vulnerability = {
            "Id": vulnerability["id"],
            "Title": extra_info["title"],
            "Malware": extra_info["malwareKits"],
            "Exploit": extra_info["exploits"],
            "CVSS": cvss,
            "Risk": extra_info["riskScore"],
            "PublishedOn": extra_info["published"],
            "ModifiedOn": extra_info["modified"],
            "Severity": extra_info["severity"],
            "Instances": vulnerability["instances"],
        }

        vulnerabilities_output.append(output_vulnerability)

    asset_md = tableToMarkdown("Nexpose asset " + str(asset["id"]), asset_output, asset_headers, removeNull=True)
    vulnerabilities_md = tableToMarkdown("Vulnerabilities", vulnerabilities_output, vulnerability_headers,
                                         removeNull=True) if len(vulnerabilities_output) > 0 else ""
    software_md = tableToMarkdown("Software", software_output, software_headers,
                                  removeNull=True) if software_output is not None else ""
    services_md = tableToMarkdown("Services", services_output, service_headers,
                                  removeNull=True) if services_output is not None else ""
    users_md = tableToMarkdown("Users", users_output, users_headers,
                               removeNull=True) if users_output is not None else ""

    md = asset_md + vulnerabilities_md + software_md + services_md + users_md

    asset_output["Vulnerability"] = vulnerabilities_output
    asset_output["Software"] = software_output
    asset_output["Service"] = services_output
    asset_output["User"] = users_output

    endpoint = {
        "IP": asset_output["Addresses"],
        "MAC": asset_output["Hardware"],
        "HostName": asset_output["Aliases"],
        "OS": asset_output["OperatingSystem"]
    }

    context = {
        "Nexpose.Asset(val.AssetId==obj.AssetId)": asset_output,
        "Endpoint(val.IP==obj.IP)": endpoint
    }

    if cves_output:
        context["CVE(val.ID==obj.ID)"] = cves_output

    # TODO: Switch to CommandResults
    return {
        "Type": entryTypes["note"],
        "Contents": asset,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": context
    }


def get_assets_command(client: Client, page_size: Optional[int] = None,
                       page: Optional[int] = None, sort: Optional[str] = None,
                       limit: Optional[int] = None) -> Union[CommandResults, list[CommandResults]]:
    """
    Retrieve a list of all assets.

    Args:
        client (Client): Client to use for API requests.
        page_size (int | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    assets = client.get_assets(
        page_size=page_size,
        page=page,
        sort=sort,
        limit=limit
    )

    if not assets:
        return CommandResults(readable_output="No assets found")

    for asset in assets:
        enrich_asset_data(asset)

    headers = [
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

    replace_key_names(
        data=assets,
        name_mapping={
            "id": "AssetId",
            "ip": "Address",
            "hostName": "Name",
            "Site": "Site",
            "vulnerabilities.exploits": "Exploits",
            "vulnerabilities.malwareKits": "Malware",
            "os": "OperatingSystem",
            "vulnerabilities.total": "Vulnerabilities",
            "riskScore": "RiskScore",
            "assessedForVulnerabilities": "Assessed",
        },
        recursive=True,
        no_copy=True,
    )

    result = []

    for asset in assets:
        result.append(
            CommandResults(
                outputs_prefix="Nexpose.Asset",
                outputs_key_field="Id",
                outputs=asset,
                readable_output=tableToMarkdown("Nexpose Asset", asset, headers, removeNull=True),
                raw_response=asset,
                indicator=Common.Endpoint(
                    id=asset["AssetId"],
                    hostname=asset.get("Name"),
                    ip_address=asset.get("Address"),
                    os=asset.get("OperatingSystem"),
                    vendor=VENDOR_NAME
                )
            ))

    return result


def get_asset_vulnerability_command(client: Client, asset_id: str, vulnerability_id: str) -> CommandResults:
    """
    Retrieve information about vulnerability findings on an asset.

    Args:
        client (Client): Client to use for API requests.
        asset_id (str): ID of the asset to retrieve information about.
        vulnerability_id (str): ID of the vulnerability to look for
    """
    vulnerability_data = client.get_asset_vulnerability(
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
    )

    # TODO: If 404 is received, check that asset_id and vulnerability_id are valid and return error message accordingly.
    # If they are, print a message saying that the asset is not vulnerable.
    # Otherwise print an error saying which parameter is invalid.

    if vulnerability_data is None:
        return CommandResults(readable_output="Vulnerability not found")

    vulnerability_headers = [
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
        "CVES"
    ]

    # Add extra info about vulnerability
    vulnerability_extra_data = client.get_vulnerability(asset_id)
    vulnerability_data.update(vulnerability_extra_data)

    vulnerability_outputs = replace_key_names(
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
        recursive=True,
        no_copy=True,
    )

    results_headers = [
        "Port",
        "Protocol",
        "Since",
        "Proof",
        "Status"
    ]

    results_output = []

    if vulnerability_data.get("results"):
        results_output = replace_key_names(
            data=vulnerability_data["results"],
            name_mapping={
                "port": "Port",
                "protocol": "Protocol",
                "since": "Since",
                "proof": "Proof",
                "status": "Status",
            },
            recursive=True,
            no_copy=True,
        )

    # Remove HTML tags
    for result in results_output:
        result["Proof"] = re.sub("<.*?>", "", result["Proof"])

    solutions_headers = [
        "Type",
        "Summary",
        "Steps",
        "Estimate",
        "AdditionalInformation"
    ]

    # Add solutions data
    solutions_output = None
    solutions = client.get_asset_vulnerability_solution(asset_id, vulnerability_id)
    vulnerability_data["solutions"] = solutions

    if solutions and solutions.get("resources"):
        solutions_output = replace_key_names(
            data=solutions["resources"],
            name_mapping={
                "type": "Type",
                "summary.text": "Summary",
                "steps.text": "Steps",
                "estimate": "Estimate",
                "additionalInformation.text": "AdditionalInformation",
            },
            recursive=True,
            no_copy=True,
        )

        for i, val in enumerate(solutions_output):
            solutions_output[i]["Estimate"] = readable_duration_time(solutions_output[i]["Estimate"])

    vulnerabilities_md = tableToMarkdown("Vulnerability " + vulnerability_id, vulnerability_outputs,
                                         vulnerability_headers, removeNull=True)
    results_md = tableToMarkdown("Checks", results_output, results_headers, removeNull=True) if len(
        results_output) > 0 else ""
    solutions_md = tableToMarkdown("Solutions", solutions_output, solutions_headers,
                                   removeNull=True) if solutions_output is not None else ""
    md = vulnerabilities_md + results_md + solutions_md

    cves = []

    if vulnerability_outputs["CVES"] is not None and len(vulnerability_outputs["CVES"]) > 0:
        cves = [{
            "ID": cve
        } for cve in vulnerability_outputs["CVES"]]

    vulnerability_outputs["Check"] = results_output
    vulnerability_outputs["Solution"] = solutions_output

    asset = {
        "AssetId": asset_id,
        "Vulnerability": [vulnerability_outputs]
    }

    context = {
        "Nexpose.Asset(val.AssetId==obj.AssetId)": asset,
    }

    if len(cves) > 0:
        context["CVE(val.ID==obj.ID)"] = cves

    return {
        "Type": entryTypes["note"],
        "Contents": vulnerability_data,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": context
    }


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
    response_data = client.get_report_templates()

    if not response_data.get("resources"):
        return CommandResults(readable_output="No templates found")

    headers = [
        "Id",
        "Name",
        "Description",
        "Type"
    ]

    outputs = replace_key_names(
        data=response_data["resources"],
        name_mapping={
            "id": "Id",
            "name": "Name",
            "description": "Description",
            "type": "Type",
        },
        recursive=True,
        no_copy=True,
    )

    return CommandResults(
        outputs_prefix="Nexpose.Template",
        outputs_key_field="Id",
        outputs=outputs,
        readable_output=tableToMarkdown("Nexpose templates", outputs, headers, removeNull=True),
        raw_response=response_data,
    )


def get_scan_command(client: Client, scan_ids: Union[str, list[str]]) -> Union[CommandResults, list[CommandResults]]:
    """
    Retrieve information about a specific or multiple scans.

    Args:
        client (Client): Client to use for API requests.
        scan_ids (str | list): ID of the scan to retrieve.
    """
    if isinstance(scan_ids, str):
        scan_ids = [scan_ids]

    scans = []

    for scan_id in scan_ids:
        scan = client.get_scan(scan_id)

        if not scan:
            return CommandResults(readable_output="Scan not found")

        scan_entry = get_scan_entry(scan)
        scans.append(scan_entry)

    if len(scans) == 1:
        return scans[0]

    return scans


def get_scans_command(client: Client, active: Optional[bool] = None, page_size: Optional[int] = None,
                      page: Optional[int] = None, sort: Optional[str] = None,
                      limit: Optional[int] = None) -> CommandResults:
    """
    Retrieve a list of all scans.

    Args:
        client (Client): Client to use for API requests.
        active (bool | None, optional): Whether to return active scans or not. Defaults to False.
        page_size (int | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    scans: list = client.get_scans(
        active=active,
        page_size=page_size,
        page=page,
        sort=sort,
        limit=limit,
    )

    if not scans:
        return CommandResults(readable_output="No scans found")

    normalized_scans = [normalize_scan_data(scan) for scan in scans]  # TODO: Use get_scan_entry function and modify it to make vulnerability optional

    scan_hr = tableToMarkdown(
        name="Nexpose scans",
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
        raw_response=scans,
    )


def get_sites_command(client: Client, page_size: Optional[int] = None, page: Optional[int] = None,
                      sort: Optional[str] = None, limit: Optional[int] = None) -> CommandResults:
    """
    Retrieve a list of sites.

    Args:
        client (Client): Client to use for API requests.
        page_size (int | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    sites = client.get_sites(
        page_size=page_size,
        page=page,
        sort=sort,
        limit=limit
    )

    if not sites:
        return CommandResults(readable_output="No sites found")

    headers = [
        "Id",
        "Name",
        "Assets",
        "Vulnerabilities",
        "Risk",
        "Type",
        "LastScan"
    ]

    outputs = replace_key_names(
        data=sites,
        name_mapping={
            "id": "Id",
            "name": "Name",
            "assets": "Assets",
            "vulnerabilities.total": "Vulnerabilities",
            "riskScore": "Risk",
            "type": "Type",
            "lastScanTime": "LastScan",
        },
        recursive=True,
    )

    return CommandResults(
        outputs_prefix="Nexpose.Site",
        outputs_key_field="Id",
        outputs=outputs,
        readable_output=tableToMarkdown("Nexpose sites", outputs, headers, removeNull=True),
        raw_response=sites,
    )


def list_scan_schedule_command(client: Client, site: Site, schedule_id: Optional[str] = None,
                               page_size: Optional[int] = None, page: Optional[int] = None,
                               limit: Optional[int] = None) -> CommandResults:
    """
    Retrieve information about scan schedules for a specific site or a specific scan schedule.

    Args:
        client (Client): Client to use for API requests.
        site (Site): Site to retrieve scan schedules from.
        schedule_id (str): ID of a specific scan schedule to retrieve.
            Defaults to None (Results in getting all scan schedules for the site).
        page_size (int | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    if not schedule_id:
        scan_schedules = client.get_site_scan_schedules(
            site_id=site.id,
            page_size=page_size,
            page=page,
            limit=limit,
        )

    else:
        scan_schedules = client.get_site_scan_schedule(
            site_id=site.id,
            schedule_id=schedule_id,
        )

        scan_schedules = [scan_schedules]

    if not scan_schedules:
        return CommandResults(readable_output="No scan schedules were found for the site.")

    hr_outputs = replace_key_names(
        data=scan_schedules,
        name_mapping={
            "id": "Id",
            "enabled": "Enable",
            "start": "StartDate",
            "scanName": "Name",
            "duration": "MaxDuration",
            "repeat.every": "Repeat",
            "nextRuntimes": "NextStart",
        },
        recursive=True,
    )

    for scan_schedule in hr_outputs:
        if scan_schedule.get("MaxDuration"):
            scan_schedule["MaxDuration"] = readable_duration_time(scan_schedule["MaxDuration"])
        if scan_schedule.get("Repeat"):
            scan_schedule["Repeat"] = "every " + scan_schedule["Repeat"]

    headers = [
        "Enable",
        "StartDate",
        "Name",
        "MaxDuration",
        "Repeat",
        "NextStart",
    ]

    return CommandResults(
        outputs_prefix="Nexpose.ScanSchedule",
        outputs_key_field="id",
        outputs=scan_schedules,
        readable_output=tableToMarkdown("Nexpose scan schedules", hr_outputs, headers, removeNull=True),
        raw_response=scan_schedules,
    )


def list_shared_credential_command(client: Client, credential_id: Optional[str], page_size: Optional[int] = None,
                                   page: Optional[int] = None, limit: Optional[int] = None) -> CommandResults:
    """
    Retrieve information about all or a specific vulnerability.

    Args:
        client (Client): Client to use for API requests.
        credential_id (str | None, optional): ID of a specific shared credential to retrieve.
            Defaults to None (Results in getting all vulnerabilities).
        page_size (int | None, optional): Number of credentials to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        limit (int | None, optional): Limit the number of credentials to return. None means to not use a limit.
            Defaults to None.
    """
    if not credential_id:
        shared_credentials = client.get_shared_credentials(
            page_size=page_size,
            page=page,
            limit=limit,
        )

    else:
        shared_credentials = client.get_shared_credential(credential_id)

        shared_credentials = [shared_credentials]

    if not shared_credentials:
        return CommandResults(readable_output="No shared credentials were found.")

    headers = [
        "Id",
        "Name",
        "Service",
        "Domain",
        "UserName",
        "AvailableToSites",
    ]

    shared_credentials_hr = replace_key_names(
        data=shared_credentials,
        name_mapping={
            "id": "Id",
            "name": "Name",
            "account.service": "Service",
            "account.domain": "Domain",
            "account.username": "UserName",
        },
        recursive=True,
    )

    for shared_credential in shared_credentials_hr:
        if shared_credential.get("sites"):
            shared_credential["AvailableToSites"] = len(shared_credential["sites"])

    return CommandResults(
        outputs_prefix="Nexpose.SharedCredential",
        outputs_key_field="id",
        outputs=shared_credentials,
        readable_output=tableToMarkdown("Nexpose Shared Credentials", shared_credentials_hr, headers, removeNull=True),
        raw_response=shared_credentials,
    )


def list_assigned_shared_credential_command(client: Client, site: Site) -> CommandResults:
    """
    Retrieve information about shared credentials for a specific site.

    Args:
        client (Client): Client to use for API requests.
        site (Site): Site to retrieve shared credentials from.
    """
    response_data = client.get_assigned_shared_credentials(site_id=site.id)

    if not response_data:
        site_id = site.name if site.name else site.id
        return CommandResults(readable_output=f"No assigned shared credentials were found for site \"{site_id}\".")

    headers = [
        "Id",
        "Name",
        "Service",
        "Enabled",
    ]

    assigned_shared_credentials_hr = replace_key_names(
        data=response_data,
        name_mapping={
            "id": "Id",
            "name": "Name",
            "service": "Service",
            "enabled": "Domain",
        },
        recursive=True,
    )

    return CommandResults(
        outputs_prefix="Nexpose.AssignedSharedCredential",
        outputs_key_field="id",
        outputs=response_data,
        readable_output=tableToMarkdown("Nexpose Assigned Shared Credentials", assigned_shared_credentials_hr, headers, removeNull=True),
        raw_response=response_data,
    )


def list_vulnerability_command(client: Client, vulnerability_id: Optional[str], page_size: Optional[int] = None,
                               page: Optional[int] = None, sort: Optional[str] = None,
                               limit: Optional[int] = None) -> CommandResults:
    """
    Retrieve information about all or a specific vulnerability.

    Args:
        client (Client): Client to use for API requests.
        vulnerability_id (str | None, optional): ID of a specific vulnerability to retrieve.
            Defaults to None (Results in getting all vulnerabilities).
        page_size (int | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    if not vulnerability_id:
        vulnerabilities = client.get_vulnerabilities(
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
        )

    else:
        vulnerabilities = client.get_vulnerability(
            vulnerability_id=vulnerability_id,
        )

        vulnerabilities = [vulnerabilities]

    if not vulnerabilities:
        return CommandResults(readable_output="No vulnerability exceptions were found.")

    headers = [
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

    vulnerabilities_hr = replace_key_names(
        data=vulnerabilities,
        name_mapping={
            "title": "Title",
            "malwareKits": "MalwareKits",
            "exploits": "Exploits",
            "CVSS.v2.score": "CVSS",
            "CVSS.v3.score": "CVSSv3",
            "riskScore": "Risk",
            "published": "PublishedOn",
            "modified": "ModifiedOn",
            "severity": "Severity",
        },
        recursive=True,
    )

    return CommandResults(
        outputs_prefix="Nexpose.Vulnerability",
        outputs_key_field="id",
        outputs=vulnerabilities,
        readable_output=tableToMarkdown(
            "Nexpose Vulnerabilities", vulnerabilities_hr, headers, removeNull=True),
        raw_response=vulnerabilities,
    )


def list_vulnerability_exceptions_command(client: Client, vulnerability_exception_id: Optional[str] = None,
                                          page_size: Optional[int] = None, page: Optional[int] = None,
                                          sort: Optional[str] = None, limit: Optional[int] = None) -> CommandResults:
    """
    Retrieve information about all or a specific vulnerability exception.

    Args:
        client (Client): Client to use for API requests.
        vulnerability_exception_id (str | None, optional): ID of a specific vulnerability exception to retrieve.
            Defaults to None (Results in getting all vulnerability exceptions).
        page_size (int | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    if not vulnerability_exception_id:
        vulnerability_exceptions = client.get_vulnerability_exceptions(
            page_size=page_size,
            page=page,
            sort=sort,
            limit=limit,
        )

    else:
        vulnerability_exceptions = client.get_vulnerability_exception(
            vulnerability_exception_id=vulnerability_exception_id,
        )

        vulnerability_exceptions = [vulnerability_exceptions]

    if not vulnerability_exceptions:
        return CommandResults(readable_output="No vulnerability exceptions were found.")

    headers = [
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

    hr_outputs = replace_key_names(
        data=vulnerability_exceptions,
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
        recursive=True,
    )

    return CommandResults(
        outputs_prefix="Nexpose.VulnerabilityException",
        outputs_key_field="id",
        outputs=vulnerability_exceptions,
        readable_output=tableToMarkdown(
            "Nexpose Vulnerability Exceptions", hr_outputs, headers, removeNull=True),
        raw_response=vulnerability_exceptions,
    )


def search_assets_command(client: Client, filter_query: Optional[str] = None, ip_addresses: Optional[str] = None,
                          hostnames: Optional[str] = None, risk_score: Optional[str] = None,
                          vulnerability_title: Optional[str] = None, sites: Union[Site, list[Site], None] = None,
                          match: Optional[str] = None, page_size: Optional[int] = None,
                          page: Optional[int] = None, sort: Optional[str] = None,
                          limit: Optional[int] = None) -> Union[CommandResults, list[CommandResults]]:
    """
    Retrieve a list of all assets with access permissions that match the provided search filters.

    Args:
        client (Client): Client to use for API requests.
        filter_query (str | None, optional): String based filters to use separated by ';'. Defaults to None.
        ip_addresses (str | None, optional): IP address(es) to filter for separated by ','. Defaults to None.
        hostnames (str | None, optional): Hostname(s) to filter for separated by ','. Defaults to None.
        risk_score (str | None, optional): Filter for risk scores that are higher than the provided value.
            Defaults to None.
        vulnerability_title (str | None, optional): Filter for vulnerability titles that contain the provided value.
            Defaults to None. Defaults to None.
        sites (Site | list[Site] | None, optional): Filter for assets that are under a specific site(s).
            Defaults to None.
        match (str | None, optional): Determine if the filters should match all or any of the filters.
            Can be either "all" or "any". Defaults to None (Results in using MATCH_DEFAULT_VALUE).
        page_size (int | None, optional): Number of scans to return per page when using pagination.
            Defaults to DEFAULT_PAGE_SIZE.
        page (int | None, optional): Specific pagination page to retrieve. Defaults to None.
            Defaults to None.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    if not match:
        match = MATCH_DEFAULT_VALUE

    filters_data: list[Union[list[str], str]] = []

    if filter_query:
        filters_data.append(filter_query.split(";"))

    if risk_score:
        filters_data.append("risk-score is-greater-than " + risk_score)

    if vulnerability_title:
        filters_data.append("vulnerability-title contains " + vulnerability_title)

    if sites:
        str_site_ids: str

        if isinstance(sites, list):
            str_site_ids = ",".join([site.id for site in sites])

        else:  # elif isinstance(sites, Site):
            str_site_ids = sites.id

        filters_data.append("site-id in " + str_site_ids)

    if ip_addresses:
        ips = argToList(ip_addresses)

        for ip in ips:
            filters_data.append("ip-address is " + ip)  # TODO: Change to `in <list of comma separated ip addresses>` instead of multiple filters?

    if hostnames:
        hostnames = argToList(hostnames)

        for hostname in hostnames:
            filters_data.append("host-name is " + hostname)  # TODO: Change to `in <list of comma separated hostnames>` instead if multiple filters?

    assets = []

    for filter_data in filters_data:
        assets.extend(
            client.search_assets(
                filters=convert_asset_search_filters(filter_data),
                match=match,
                page_size=page_size,
                page=page,
                sort=sort,
                limit=limit,
            )
        )

    if not assets:
        return CommandResults(readable_output="No assets were found")

    for asset in assets:
        enrich_asset_data(asset)

    headers = [
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

    replace_key_names(
        data=assets,
        name_mapping={
            "id": "AssetId",
            "ip": "Address",
            "hostName": "Name",
            "vulnerabilities.exploits": "Exploits",
            "vulnerabilities.malwareKits": "Malware",
            "os": "OperatingSystem",
            "vulnerabilities.total": "Vulnerabilities",
            "riskScore": "RiskScore",
            "assessedForVulnerabilities": "Assessed",
        },
        recursive=True,
        no_copy=True,
    )

    result = []

    for asset in assets:
        result.append(
            CommandResults(
                outputs_prefix="Nexpose.Asset",
                outputs_key_field="Id",
                outputs=asset,
                readable_output=tableToMarkdown("Nexpose Asset", asset, headers, removeNull=True),
                raw_response=asset,
                indicator=Common.Endpoint(
                    id=asset["AssetId"],
                    hostname=asset.get("Name"),
                    ip_address=asset.get("Address"),
                    os=asset.get("OperatingSystem"),
                    vendor=VENDOR_NAME
                )
            ))

    return result


def set_assigned_shared_credential_status_command(client: Client, site: Site,
                                                  shared_credential_id: str, enabled: bool) -> CommandResults:
    """
    Enable or disable a shared credential.

    Args:
        client (Client): Client to use for API requests.
        site (Site): Site to use for API requests.
        shared_credential_id (str): ID of the shared credential to enable or disable.
        enabled (bool): Whether to enable or disable the shared credential.
    """

    response_data = client.set_assigned_shared_credential_status(
        site_id=site.id,
        shared_credential_id=shared_credential_id,
        enabled=enabled,
    )

    return CommandResults(
        readable_output=f"Shared credential \"{shared_credential_id}\" enablement \
                          has been set to \"{str(enabled).lower()}\".",
        raw_response=response_data,
    )


def start_assets_scan_command(client: Client, ips: Union[str, list, None] = None,
                              hostnames: Union[str, list, None] = None,
                              scan_name: Optional[str] = None) -> CommandResults:  # TODO: Add pagination args?
    """
    | Start a scan on the provided assets.
    |
    | Note: Both `ips` and `hostnames` are optional, but at least one of them must be provided.

    Args:
        client (Client): Client to use for API requests.
        ips (str | list | None, optional): IP(s) of assets to scan. Defaults to None
        hostnames (str | list | None, optional): Hostname(s) of assets to scan. Defaults to None
        scan_name (str | None): Name to set for the new scan.
            Defaults to None (Results in using a "scan <date>" format).
    """
    if not (ips or hostnames):
        raise ValueError("At least one of `ips` and `hostnames` must be provided")

    if not scan_name:
        scan_name = f"scan {datetime.now()}"

    if isinstance(ips, str):
        ips = [ips]

    if isinstance(hostnames, str):
        hostnames = [hostnames]

    if ips:
        asset_filter = "ip-address is " + ips[0]

    else:  # elif hostnames
        asset_filter = "host-name is " + hostnames[0]

    asset = client.search_assets(filters=convert_asset_search_filters(asset_filter), match="all")

    if not asset:
        return CommandResults(readable_output="Could not find assets")

    site = find_site_from_asset(asset[0]["id"])

    if site is None or "id" not in site:  # TODO: Check if `site` can actually be None
        return CommandResults(readable_output="Could not find site")

    hosts = []

    if ips:
        hosts.extend(ips)

    if hostnames:
        hosts.extend(hostnames)

    scan_response = client.start_site_scan(
        site_id=site["id"],
        scan_name=scan_name,
        hosts=hosts
    )

    if "id" not in scan_response:
        return CommandResults(readable_output="Could not start scan")

    return get_scan_entry(client.get_scan(scan_response["id"]))


def start_site_scan_command(client: Client, site: Site,
                            scan_name: Optional[str], hosts: Optional[list[str]]) -> CommandResults:  # TODO: Add pagination args?
    """
    Start a scan for a specific site.

    Args:
        client (Client): Client to use for API requests.
        site (Site): Site to start a scan on.
        scan_name (str | None): Name to set for the new scan.
            Defaults to None (Results in using a "scan <date>" format).
        hosts (list[str] | None): Hosts to scan. Defaults to None (Results in scanning all hosts).
    """
    if not scan_name:
        scan_name = f"scan {datetime.now()}"

    if not hosts:
        assets = client.get_site_assets(site.id)
        hosts = [asset["ip"] for asset in assets]

    scan_response = client.start_site_scan(
        site_id=site.id,
        scan_name=scan_name,
        hosts=hosts
    )

    if not scan_response or "id" not in scan_response:
        return CommandResults(readable_output="Could not start scan")

    scan_data = client.get_scan(scan_response.get("id"))
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


def update_shared_credential_command(
        client: Client, shared_credential_id: str, name: str,
        site_assignment: SharedCredentialSiteAssignment,
        service: CredentialService,
        database_name: Optional[str] = None,
        description: Optional[str] = None,
        domain: Optional[str] = None,
        host_restriction: Optional[str] = None,
        http_realm: Optional[str] = None,
        notes_id_password: Optional[str] = None,
        ntlm_hash: Optional[str] = None,
        oracle_enumerate_sids: Optional[bool] = None,
        oracle_listener_password: Optional[str] = None,
        oracle_sid: Optional[str] = None,
        password: Optional[str] = None,
        port_restriction: Optional[str] = None,
        sites: Optional[List[int]] = None,
        snmp_community_name: Optional[str] = None,
        snmpv3_authentication_type: Optional[SNMPv3AuthenticationType] = None,
        snmpv3_privacy_password: Optional[str] = None,
        snmpv3_privacy_type: Optional[SNMPv3PrivacyType] = None,
        ssh_key_pem: Optional[str] = None,
        ssh_permission_elevation: Optional[SSHElevationType] = None,
        ssh_permission_elevation_password: Optional[str] = None,
        ssh_permission_elevation_username: Optional[str] = None,
        ssh_private_key_password: Optional[str] = None,
        use_windows_authentication: Optional[bool] = None,
        username: Optional[str] = None) -> CommandResults:
    """
    Update an existing shared credential.

    Args:
        client (Client): Client to use for API requests.
        shared_credential_id (str): ID of the shared credential to update.
        name (str): Name of the credential.
        site_assignment (SharedCredentialSiteAssignment): Site assignment configuration for the credential.
            Assign the shared scan credential either to be available to all sites, or a specific list of sites.
        service (CredentialService): Credential service type.
        database_name (str, optional): Database name.
        description (str, optional): Description for the credential.
        domain (str, optional): Domain address.
        host_restriction (str, optional): Hostname or IP address to restrict the credentials to.
        http_realm (str, optional): HTTP realm.
        notes_id_password (str, optional): Password for the notes account that will be used for authenticating.
        ntlm_hash (str, optional): NTLM password hash.
        oracle_enumerate_sids (bool, optional): Whether the scan engine should attempt to enumerate
            SIDs from the environment.
        oracle_listener_password (str, optional): The Oracle Net Listener password.
            Used to enumerate SIDs from the environment.
        oracle_sid (str, optional): Oracle database name.
        password (str, optional): Password for the credential.
        port_restriction (str, optional): Further restricts the credential to attempt to authenticate
            on a specific port. Can be used only if `host_restriction` is used.
        sites (List[int], optional): List of site IDs for the shared credential that are explicitly assigned
            access to the shared scan credential, allowing it to use the credential during a scan.
        snmp_community_name (str, optional): SNMP community for authentication.
        snmpv3_authentication_type (SNMPv3AuthenticationType): SNMPv3 authentication type for the credential.
        snmpv3_privacy_password (str, optional): SNMPv3 privacy password to use.
        snmpv3_privacy_type (SNMPv3PrivacyType, optional): SNMPv3 Privacy protocol to use.
        ssh_key_pem (str, optional): PEM formatted private key.
        ssh_permission_elevation (SSHElevationType, optional): Elevation type to use for scans.
        ssh_permission_elevation_password (str, optional): Password to use for elevation.
        ssh_permission_elevation_username (str, optional): Username to use for elevation.
        ssh_private_key_password (str, optional): Password for the private key.
        use_windows_authentication (bool, optional): Whether to use Windows authentication.
        username (str, optional): Username for the credential.
    """
    response_data = client.update_shared_credential(
        shared_credential_id=shared_credential_id,
        name=name,
        site_assignment=site_assignment,
        service=service,
        database_name=database_name,
        description=description,
        domain=domain,
        host_restriction=host_restriction,
        http_realm=http_realm,
        notes_id_password=notes_id_password,
        ntlm_hash=ntlm_hash,
        oracle_enumerate_sids=oracle_enumerate_sids,
        oracle_listener_password=oracle_listener_password,
        oracle_sid=oracle_sid,
        password=password,
        port_restriction=port_restriction,
        sites=sites,
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

    return CommandResults(
        readable_output=f"Shared Credential with ID {shared_credential_id} has been updated.",
        raw_response=response_data
    )


def update_scan_schedule_command(client: Client, site: Site, scan_schedule_id: int,
                                 enabled: bool, repeat_behaviour: RepeatBehaviour, start_date: str,
                                 excluded_asset_groups: Optional[list[int]] = None,
                                 excluded_targets: Optional[list[str]] = None,
                                 included_asset_groups: Optional[list[int]] = None,
                                 included_targets: Optional[list[str]] = None, duration_days: Optional[int] = None,
                                 duration_hours: Optional[int] = None, duration_minutes: Optional[int] = None,
                                 frequency: Optional[RepeatFrequencyType] = None, interval: Optional[int] = None,
                                 scan_name: Optional[str] = None, date_of_month: Optional[int] = None,
                                 scan_template_id: Optional[str] = None) -> CommandResults:
    """
    Update a site scan schedule.

    Args:
        client (Client): Client to use for API requests.
        site (Site): Site to create a scheduled scan for.
        scan_schedule_id (int): ID of the scan schedule to update.
        enabled (bool, optional): A flag indicating whether the scan schedule is enabled.
           Defaults to None, which results in using True.
        repeat_behaviour (RepeatBehaviour): The desired behavior of a repeating scheduled scan
            when the previous scan was paused due to reaching its maximum duration.
        start_date (str): The scheduled start date and time formatted in ISO 8601 format.
        excluded_asset_groups (list[int], optional): Asset groups to exclude from the scan.
        excluded_targets (list[str], optional): Addresses to exclude from the scan. Each address is a string that
            can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
        included_asset_groups (list[int], optional): Asset groups to include in the scan.
        included_targets (list[str], optional): Addresses to include in the scan.  Each address is a string that
            can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.
        duration_days (int, optional): Maximum duration of the scan in days.
            Can be used along with `duration_hours` and `duration_minutes`.
        duration_hours (int, optional): Maximum duration of the scan in hours.
            Can be used along with `duration_days` and `duration_minutes`.
        duration_minutes (int, optional): Maximum duration of the scan in minutes.
            Can be used along with `duration_days` and `duration_hours`.
        frequency (RepeatFrequencyType, optional): Frequency for the schedule to repeat.
        interval (int, optional): The interval time the schedule should repeat.
            Required if frequency is set to any value other than `DATE_OF_MONTH`.
        date_of_month(int, optional): Specifies the schedule repeat day of the interval month.
            Required and used only if frequency is set to `DATE_OF_MONTH`.
        scan_name (str, optional): A unique user-defined name for the scan launched by the schedule.
            If not explicitly set in the schedule, the scan name will be generated prior to the scan launching.
        scan_template_id (str, optional): ID of the scan template to use.
    """
    duration = generate_duration_time(
        days=duration_days,
        hours=duration_hours,
        minutes=duration_minutes)

    client.update_site_scan_schedule(
        site_id=site.id,
        scan_schedule_id=scan_schedule_id,
        enabled=enabled,
        repeat_behaviour=repeat_behaviour,
        start_date=start_date,
        excluded_asset_groups=excluded_asset_groups,
        excluded_targets=excluded_targets,
        included_asset_groups=included_asset_groups,
        included_targets=included_targets,
        duration=duration,
        frequency=frequency,
        interval=interval,
        date_of_month=date_of_month,
        scan_name=scan_name,
        scan_template_id=scan_template_id,
    )

    return CommandResults(readable_output=f"Scan schedule {scan_schedule_id} has been updated.")


def update_vulnerability_exception_command(client: Client, vulnerability_exception_id: str,
                                           expiration_date: Optional[str] = None,
                                           status: Optional[VulnerabilityExceptionStatus] = None) -> CommandResults:
    """
    Update a vulnerability exception.

    Args:
        client (Client): Client to use for API requests.
        vulnerability_exception_id (str): ID of the vulnerability exception to update.
        expiration_date (str, optional): Expiration date to set for the vulnerability exception,
            formatted in ISO 8601 format.
        status (VulnerabilityExceptionStatus, optional): Status to set for the vulnerability exception.
    """
    if not expiration_date and not status:
        raise ValueError("Either expiration or status must be set.")

    responses = []
    if expiration_date:
        responses.append(
            client.update_vulnerability_exception_expiration(
                vulnerability_exception_id=vulnerability_exception_id,
                expiration_date=expiration_date
            )
        )

    if status:
        responses.append(
            client.update_vulnerability_exception_status(
                vulnerability_exception_id=vulnerability_exception_id,
                status=status
            )
        )

    if len(responses) == 1:
        responses = responses[0]

    return CommandResults(
        readable_output=f"Successfully updated vulnerability exception {vulnerability_exception_id}.",
        raw_response=responses)


def main():
    try:
        args = demisto.args()
        params = demisto.params()
        command = demisto.command()
        handle_proxy()

        client = Client(
            url=params["server"],
            username=params["credentials"].get("identifier"),
            password=params["credentials"].get("password"),
            token=params.get("token"),
            verify=not params.get("unsecure")
        )

        if command == "test-module":
            client.get_assets(page_size=1, limit=1)
            results = "ok"
        elif command == "nexpose-create-assets-report":
            report_format = None

            if args.get("format"):
                report_format = ReportFileFormat[args["format"]]

            results = create_assets_report_command(
                client=client,
                asset_ids=argToList(args.get("assets")),
                template_id=args.get("template"),
                report_name=args.get("name"),
                report_format=report_format,
                download_immediately=argToBoolean(args.get("download_immediately"))
            )
        elif command == "nexpose-create-scan-report":
            report_format = None

            if args.get("format"):
                report_format = ReportFileFormat[args["format"]]

            results = create_scan_report_command(
                client=client,
                scan_id=args["scans"],
                template_id=args.get("template"),
                report_name=args.get("name"),
                report_format=report_format,
                download_immediately=argToBoolean(args.get("download_immediately")),
            )
        elif command == "nexpose-create-scan-schedule":
            repeat_behaviour = RepeatBehaviour[args["on_scan_repeat"]]
            frequency = None

            if args.get("frequency"):
                frequency = RepeatFrequencyType[args.get("frequency")]

            results = create_scan_schedule_command(
                client=client,
                site=Site(
                    site_id=args.get("site_id"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
                enabled=args.get("enabled"),
                repeat_behaviour=repeat_behaviour,
                start_date=args["start"],
                excluded_asset_groups=[int(asset_id) for asset_id in argToList(args.get("excluded_asset_group_ids"))],
                excluded_targets=argToList(args.get("excluded_addresses")),
                included_asset_groups=[int(asset_id) for asset_id in argToList(args.get("included_asset_group_ids"))],
                included_targets=argToList(args.get("included_addresses")),
                duration_days=arg_to_number(args.get("duration_days")),
                duration_hours=arg_to_number(args.get("duration_hours")),
                duration_minutes=arg_to_number(args.get("duration_minutes")),
                frequency=frequency,
                interval=arg_to_number(args.get("interval_time")),
                date_of_month=arg_to_number(args.get("date_of_month")),
                scan_name=args.get("scan_name"),
                scan_template_id=args.get("scan_template_id"))
        elif command == "nexpose-create-shared-credential":
            snmpv3_privacy_type = None
            ssh_permission_elevation = None

            if args.get("snmpv3_privacy_type") is not None:
                snmpv3_privacy_type = SNMPv3PrivacyType[args["snmpv3_privacy_type"]]

            if args.get("ssh_permission_elevation") is not None:
                ssh_permission_elevation = SSHElevationType[args["ssh_permission_elevation"]]

            results = create_shared_credential_command(
                client=client,
                name=args["name"],
                site_assignment=SharedCredentialSiteAssignment[args["site_assignment"]],
                service=CredentialService[args["service"]],
                database_name=args.get("database"),
                description=args.get("description"),
                domain=args.get("domain"),
                host_restriction=args.get("host_restriction"),
                http_realm=args.get("http_realm"),
                notes_id_password=args.get("notes_id_password"),
                ntlm_hash=args.get("ntlm_hash"),
                oracle_enumerate_sids=argToBoolean(args.get("oracle_enumerate_sids")),
                oracle_listener_password=args.get("oracle_listener_password"),
                oracle_sid=args.get("oracle_sid"),
                password=args.get("password"),
                port_restriction=args.get("port_restriction"),
                sites=[int(item) for item in argToList(args.get("sites"))],
                snmp_community_name=args.get("community_name"),
                snmpv3_authentication_type=args.get("authentication_type"),
                snmpv3_privacy_password=args.get("privacy_password"),
                snmpv3_privacy_type=snmpv3_privacy_type,
                ssh_key_pem=args.get("ssh_key_pem"),
                ssh_permission_elevation=ssh_permission_elevation,
                ssh_permission_elevation_password=args.get("ssh_permission_elevation_password"),
                ssh_permission_elevation_username=args.get("ssh_permission_elevation_username"),
                ssh_private_key_password=args.get("ssh_private_key_password"),
                use_windows_authentication=argToBoolean(args.get("use_windows_authentication")),
                username=args.get("username"),
            )
        elif command == "nexpose-create-site":
            site_importance = None

            if args.get("importance"):
                site_importance = SiteImportance[args["importance"]]

            results = create_site_command(
                client=client,
                name=args["name"],
                description=args.get("description"),
                assets=argToList(args.get("assets")),
                site_importance=site_importance,
                template_id=args.get("scanTemplateId"),
            )
        elif command == "nexpose-create-sites-report":
            sites_list = [Site(site_id=site_id, client=client) for site_id in argToList(args.get("sites"))]
            sites_list.extend(
                [Site(site_name=site_name, client=client) for site_name in argToList(args.get("site_names"))]
            )

            report_format = None

            if args.get("format"):
                report_format = ReportFileFormat[args["format"]]

            results = create_sites_report_command(
                client=client,
                sites=sites_list,
                template_id=args.get("template"),
                report_name=args.get("name"),
                report_format=report_format,
                download_immediately=argToBoolean(args.get("download_immediately")),
            )
        elif command == "nexpose-create-vulnerability-exception":
            scope_type = VulnerabilityExceptionScopeType[args["scope_type"]]
            state = VulnerabilityExceptionState[args["state"]]
            reason = VulnerabilityExceptionReason[args["reason"]]

            results = create_vulnerability_exception_command(
                client=client,
                vulnerability_id=args["vulnerability_id"],
                scope_type=scope_type,
                state=state,
                reason=reason,
                expires=args.get("expires"),
                comment=args.get("comment"),

            )
        elif command == "nexpose-delete-scan-schedule":
            results = delete_scheduled_scan_command(
                client=client,
                site=Site(
                    site_id=args.get("site_id"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
                scheduled_scan_id=args["schedule_id"],
            )
        elif command == "nexpose-delete-shared-credential":
            results = delete_shared_credential_command(
                client=client,
                shared_credential_id=args["id"],
            )
        elif command == "nexpose-delete-vulnerability-exception":
            results = delete_vulnerability_exception_command(
                client=client,
                vulnerability_exception_id=args["id"],
            )
        elif command == "nexpose-delete-site":
            results = delete_site_command(
                client=client,
                site=Site(
                    site_id=args.get("id"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
            )
        elif command == "nexpose-disable-shared-credential":
            results = set_assigned_shared_credential_status_command(
                client=client,
                site=Site(
                    site_id=args.get("site_id"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
                shared_credential_id=args["credential_id"],
                enabled=False,
            )
        elif command == "nexpose-download-report":
            report_format = None

            if args.get("format"):
                report_format = ReportFileFormat[args["format"]]

            results = download_report_command(
                client=client,
                report_id=args["report_id"],
                instance_id=args["instance_id"],
                report_name=args.get("name"),
                report_format=report_format,
            )
        elif command == "nexpose-enable-shared-credential":
            results = set_assigned_shared_credential_status_command(
                client=client,
                site=Site(
                    site_id=args.get("site_id"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
                shared_credential_id=args["credential_id"],
                enabled=True,
            )
        elif command == "nexpose-get-asset":
            results = get_asset_command(
                client=client,
                asset_id=args["id"]
            )
        elif command == "nexpose-get-asset-vulnerability":
            results = get_asset_vulnerability_command(
                client=client,
                asset_id=args["id"],
                vulnerability_id=args["vulnerabilityId"],
            )
        elif command == "nexpose-get-assets":
            results = get_assets_command(
                client=client,
                page=arg_to_number(args.get("page")),
                page_size=arg_to_number(args.get("page_size")),
                sort=args.get("sort"),
                limit=arg_to_number(args.get("limit"))
            )
        elif command == "nexpose-get-report-templates":
            results = get_report_templates_command(
                client=client,
            )
        elif command == "nexpose-get-report-status":
            results = get_generated_report_status_command(
                client=client,
                report_id=args["report_id"],
                instance_id=args["instance_id"]
            )
        elif command == "nexpose-get-scan":
            results = get_scan_command(
                client=client,
                scan_ids=argToList(str(args.get(id))),
            )
        elif command == "nexpose-get-scans":
            results = get_scans_command(
                client=client,
                active=args.get("active"),
                page_size=arg_to_number(args.get("page_size")),
                page=arg_to_number(args.get("page")),
                sort=args.get("sort"),
                limit=arg_to_number(args.get("limit")),
            )
        elif command == "nexpose-get-sites":
            results = get_sites_command(
                client=client,
                page_size=arg_to_number(args.get("page_size")),
                page=arg_to_number(args.get("page")),
                sort=args.get("sort"),
                limit=arg_to_number(args.get("limit")),
            )
        elif command == "nexpose-list-assigned-shared-credential":
            results = list_assigned_shared_credential_command(
                client=client,
                site=Site(
                    site_id=args.get("site_id"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
            )
        elif command == "nexpose-list-vulnerability":
            results = list_vulnerability_command(
                client=client,
                vulnerability_id=args.get("id"),
                page_size=arg_to_number(args.get("page_size")),
                page=arg_to_number(args.get("page")),
                limit=arg_to_number(args.get("limit")),
            )
        elif command == "nexpose-list-vulnerability-exceptions":
            results = list_vulnerability_exceptions_command(
                client=client,
                vulnerability_exception_id=args.get("id"),
                page_size=arg_to_number(args.get("page_size")),
                page=arg_to_number(args.get("page")),
                limit=arg_to_number(args.get("limit")),
            )
        elif command == "nexpose-list-scan-schedule":
            results = list_scan_schedule_command(
                client=client,
                site=Site(
                    site_id=args.get("site_id"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
                schedule_id=args.get("schedule_id"),
                page_size=arg_to_number(args.get("page_size")),
                page=arg_to_number(args.get("page")),
                limit=arg_to_number(args.get("limit")),
            )
        elif command == "nexpose-list-shared-credential":
            results = list_shared_credential_command(
                client=client,
                credential_id=args.get("id"),
                page_size=arg_to_number(args.get("page_size")),
                page=arg_to_number(args.get("page")),
                limit=arg_to_number(args.get("limit")),
            )
        elif command == "nexpose-pause-scan":
            results = update_scan_command(
                client=client,
                scan_id=args["id"],
                scan_status=ScanStatus.PAUSE,
            )
        elif command == "nexpose-resume-scan":
            results = update_scan_command(
                client=client,
                scan_id=args["id"],
                scan_status=ScanStatus.RESUME,
            )
        elif command == "nexpose-update-shared-credential":
            snmpv3_privacy_type = None
            ssh_permission_elevation = None

            if args.get("snmpv3_privacy_type") is not None:
                snmpv3_privacy_type = SNMPv3PrivacyType[args["snmpv3_privacy_type"]]

            if args.get("ssh_permission_elevation") is not None:
                ssh_permission_elevation = SSHElevationType[args["ssh_permission_elevation"]]

            results = update_shared_credential_command(
                client=client,
                shared_credential_id=args["id"],
                name=args["name"],
                site_assignment=SharedCredentialSiteAssignment[args["site_assignment"]],
                service=CredentialService[args["service"]],
                database_name=args.get("database"),
                description=args.get("description"),
                domain=args.get("domain"),
                host_restriction=args.get("host_restriction"),
                http_realm=args.get("http_realm"),
                notes_id_password=args.get("notes_id_password"),
                ntlm_hash=args.get("ntlm_hash"),
                oracle_enumerate_sids=argToBoolean(args.get("oracle_enumerate_sids")),
                oracle_listener_password=args.get("oracle_listener_password"),
                oracle_sid=args.get("oracle_sid"),
                password=args.get("password"),
                port_restriction=args.get("port_restriction"),
                sites=[int(item) for item in argToList(args.get("sites"))],
                snmp_community_name=args.get("community_name"),
                snmpv3_authentication_type=args.get("authentication_type"),
                snmpv3_privacy_password=args.get("privacy_password"),
                snmpv3_privacy_type=snmpv3_privacy_type,
                ssh_key_pem=args.get("ssh_key_pem"),
                ssh_permission_elevation=ssh_permission_elevation,
                ssh_permission_elevation_password=args.get("ssh_permission_elevation_password"),
                ssh_permission_elevation_username=args.get("ssh_permission_elevation_username"),
                ssh_private_key_password=args.get("ssh_private_key_password"),
                use_windows_authentication=argToBoolean(args.get("use_windows_authentication")),
                username=args.get("username"),
            )
        elif command == "nexpose-update-scan-schedule":
            repeat_behaviour = RepeatBehaviour[args["on_scan_repeat"]]
            frequency = None

            if args.get("frequency"):
                frequency = RepeatFrequencyType[args.get("frequency")]

            results = update_scan_schedule_command(
                client=client,
                site=Site(
                    site_id=args.get("site_id"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
                scan_schedule_id=args["schedule_id"],
                enabled=args.get("enabled"),
                repeat_behaviour=repeat_behaviour,
                start_date=args["start"],
                excluded_asset_groups=[int(asset_id) for asset_id in argToList(args.get("excluded_asset_group_ids"))],
                excluded_targets=argToList(args.get("excluded_addresses")),
                included_asset_groups=[int(asset_id) for asset_id in argToList(args.get("included_asset_group_ids"))],
                included_targets=argToList(args.get("included_addresses")),
                duration_days=arg_to_number(args.get("duration_days")),
                duration_hours=arg_to_number(args.get("duration_hours")),
                duration_minutes=arg_to_number(args.get("duration_minutes")),
                frequency=frequency,
                interval=arg_to_number(args.get("interval_time")),
                date_of_month=arg_to_number(args.get("date_of_month")),
                scan_name=args.get("scan_name"),
                scan_template_id=args.get("scan_template_id"))
        elif command == "nexpose-update-vulnerability-exception":
            status = None

            if args.get("status"):
                status = VulnerabilityExceptionStatus[args.get("status")]

            results = update_vulnerability_exception_command(
                client=client,
                vulnerability_exception_id=args["id"],
                expiration_date=args.get("expiration"),
                status=status,
            )
        elif command == "nexpose-search-assets":
            sites: list[Site] = []

            for site_id in argToList(args.get("siteIdIn")):
                sites.append(Site(site_id=site_id, client=client))

            for site_name in argToList(args.get("siteNameIn")):
                sites.append(Site(site_name=site_name, client=client))

            results = search_assets_command(
                client=client,
                filter_query=args.get("query"),
                ip_addresses=args.get("ipAddressIs"),
                hostnames=args.get("hostNameIs"),
                risk_score=args.get("riskScoreHigherThan"),
                vulnerability_title=args.get("vulnerabilityTitleContains"),
                sites=sites,
                match=args.get("match"),
                page_size=arg_to_number(args.get("page_size")),
                page=arg_to_number(args.get("page")),
                sort=args.get("sort"),
                limit=arg_to_number(args.get("limit")),
            )
        elif command == "nexpose-start-assets-scan":
            results = start_assets_scan_command(
                client=client,
                ips=argToList(args.get("IPs")),
                hostnames=argToList(args.get("hostNames")),
                scan_name=args.get("name"),
            )
        elif command == "nexpose-start-site-scan":
            results = start_site_scan_command(
                client=client,
                site=Site(
                    site_id=args.get("site"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
                scan_name=args.get("name"),
                hosts=argToList(args.get("hosts")),
            )
        elif command == "nexpose-stop-scan":
            results = update_scan_command(
                client=client,
                scan_id=args["id"],
                scan_status=ScanStatus.STOP,
            )
        else:
            raise NotImplementedError(f"Command {command} not implemented")

        return_results(results)

    except Exception as e:
        LOG(e)
        LOG.print_log(False)
        return_error(str(e))


if __name__ in ("__main__", "builtin", "builtins"):
    main()

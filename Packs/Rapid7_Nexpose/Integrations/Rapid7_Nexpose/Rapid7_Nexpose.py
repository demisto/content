import datetime
import re

import urllib3

import demistomock as demisto

from enum import Enum
from time import strptime, struct_time

from CommonServerPython import *
from CommonServerUserPython import *


API_DEFAULT_PAGE_SIZE = 10  # Default page size that's set on the API. Used for calculations.
DEFAULT_PAGE_SIZE = 50  # Default page size to use
MATCH_DEFAULT_VALUE = "any"  # Default "match" value to use when using search filters. Can be either "all" or "any".
REPORT_DOWNLOAD_WAIT_TIME = 60  # Time in seconds to wait before downloading a report after starting its generation
VENDOR_NAME = "Rapid7 Nexpose"  # TODO: Check if correct

urllib3.disable_warnings()  # Disable insecure warnings


class ReportFileFormat(Enum):
    """An Enum of possible file formats to use for reports."""
    PDF = 1
    RTF = 2
    XML = 3
    HTML = 4
    Text = 5


class ScanStatus(Enum):
    """An Enum of possible scan status values."""
    PAUSE = 1
    RESUME = 2
    STOP = 3


class SiteImportance(Enum):
    """An Enum of possible site importance values."""
    VERY_LOW = 1
    LOW = 2
    NORMAL = 3
    HIGH = 4
    VERY_HIGH = 5


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

        # If sort is not None, split it into a list
        if sort:
            sort = sort.split(sep=";")

        kwargs["params"].update(find_valid_params(
            page_size=page_size,
            sort=sort,
            limit=limit,
        ))

        response: dict = self._http_request(**kwargs)
        result = response.get("resources", [])

        if not result:
            return []

        if not page:
            # If page_size is not set, the size that will be used is API's default.
            _page_size = page_size if page_size else API_DEFAULT_PAGE_SIZE

            total_pages = response["page"].get("totalPages", 1)
            page_count = 1

            while page_count < total_pages and (limit is None or len(result) < limit):
                page_count += 1
                kwargs["params"]["page"] = str(page_count)
                response = self._http_request(**kwargs)
                result.extend(response.get("resources"))

        if limit and limit < len(result):
            return result[:limit]

        return result

    def create_report(self, report_id: str) -> str:
        """
        | Generates a configured report.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/generateReport

        Args:
            report_id (str): ID of the configured report to generate.

        Returns:
            str: ID of the generated report instance.
        """
        return str(self._http_request(
            url_suffix=f"/reports/{report_id}/generate",
            method="POST",
            resp_type="json",
        ).get("id"))

    def create_report_config(self, scope: dict[str, Any], template_id: str,
                             report_name: str, report_format: str) -> str:
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
            str: ID of the created report configuration.
        """
        post_data = {
            "scope": scope,
            "template": template_id,
            "name": report_name,
            "format": report_format
        }

        return str(self._http_request(
            url_suffix=f"/reports",
            method="POST",
            json_data=post_data,
            resp_type="json",
        ).get("id"))

    def create_site(self, name: str, description: Optional[str] = None, assets: Optional[list[str]] = None,
                    site_importance: Optional[str] = None, template_id: Optional[str] = None) -> dict:
        """
        | Create a new site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSite

        Args:
            name (str): Name of the site. Must be unique.
            description (str | None, optional): Description of the site. Defaults to None.
            assets (list[str] | None, optional): List of asset IDs to be included in site scans. Defaults to None.
            site_importance (str | None, optional): Importance of the site. Can be either:
                "very_low", "low", "normal", "high" or "very_high".
                Defaults to None (results in using API's default - "normal").
            template_id (str | None, optional): The identifier of a scan template.
                Defaults to None (results in using default scan template).

        Returns:
            dict: API response with information about the newly created site.
        """
        post_data = find_valid_params(
            name=name,
            description=description,
            importance=site_importance,
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
            url_suffix=f"/sites",
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
        )

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

    def get_scan_schedule(self, site_id: str, schedule_id: str) -> dict:
        """
        | Retrieve information about a specific scheduled scan from a specific site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteScanSchedule

        Args:
            site_id (str): ID of the site to retrieve scheduled scan from.
            schedule_id (str): ID of the scheduled scan to retrieve.

        Returns:
            dict: API response with information about a specific scheduled scans from the specific site.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules/{schedule_id}",
            method="GET",
            resp_type="json",
        )

    def get_scan_schedules(self, site_id: str) -> dict:
        """
        | Retrieve information about all scheduled scans from a specific site.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteScanSchedules

        Args:
            site_id (str): ID of the site to retrieve scheduled scans from.

        Returns:
            dict: API response with information about all scheduled scans from the specific site.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules",
            method="GET",
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

    def get_shared_credentials(self) -> dict:
        """
        | Retrieve information about all shared credentials.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSharedCredentials

        Returns:
            dict: API response with all shared credentials and their information.
        """
        return self._http_request(
            url_suffix=f"/shared_credentials",
            method="GET",
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

    def update_scan_status(self, scan_id: str, status: str) -> dict:
        """
        | Update status for a specific scan.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/setScanStatus

        Args:
            scan_id (str): ID of the scan to update.
            status (str): Status to set the scan to. Can be either "pause", "stop", or "resume".
        """
        return self._http_request(
            url_suffix=f"/scans/{scan_id}/{status}",
            method="POST",
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
        if site_id:
            self.id = site_id

        elif site_name:
            if not client:
                raise ValueError("Can't fetch site ID as no Client was provided.")

            self.id = client.find_site_id(site_name)

            if not self.id:
                raise InvalidSiteNameException(f"No site with name `{site_name}` was found.")

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
            current_value = None

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
    Convert a time string formatted in one of the time formats used by Nexpose's API for scans to a `struct_time` object.

    Args:
        time_str (str): A time string formatted in one of the time formats used by Nexpose's API for scans.

    Returns:
        struct_time: The datetime represented in a `struct_time` object.
    """
    try:
        return strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")

    except ValueError:
        return strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")


def convert_duration_time(duration: str) -> str:
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
        report_format=report_format.name.lower(),
    )

    instance_id = client.create_report(report_id)

    context = {
        "Name": report_name,
        "ID": report_id,
        "InstanceID": instance_id,
        "Format": report_format.name.lower(),
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


def normalize_scan_data(scan: dict) -> dict:
    """
    Normalizes scan data received from the API to a format that will be displayed in the UI.

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
    )

    scan_output["TotalTime"] = convert_duration_time(scan_output["TotalTime"])

    return scan_output


# TODO: Disable "recursive" if it's not actually needed.
def replace_key_names(data: Union[dict, list, tuple], name_mapping: dict[str, str],
                      recursive: bool = False) -> Union[dict, list, tuple, set]:
    """
    Replace key names in a dictionary.

    Args:
        data (dict | list | tuple): An iterable to replace key names for dictionaries within it.
        name_mapping (dict): A dictionary in a `from: to` mapping format of which key names to replace with what.
            the value of the keys ("from") can represent nested dict items in a "parent.child" format.
        recursive (bool, optional): Whether to replace key names in all sub-dictionaries. Defaults to False.

    Returns:
        Union[dict, list, tuple]: The same data-structure with key names of dicts replaced according to mapping.
    """
    # TODO: Fix issue when nested key is inside a list
    if isinstance(data, Union[list, tuple]):
        return [replace_key_names(
            data=data[i],
            name_mapping=name_mapping,
            recursive=recursive,
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
                    data[item] = replace_key_names(data[item], name_mapping, recursive)

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

    return create_report(
        client=client,
        scope=scope,
        template_id=template_id,
        report_name=report_name,
        report_format=report_format,
        download_immediately=download_immediately,
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
    response = client.create_site(name, description, assets, site_importance.name.lower(), template_id)

    output = {
        "Id": response["id"]
    }

    return CommandResults(
        readable_output=tableToMarkdown("New site created", output),
        outputs_prefix="Nexpose.Site",
        outputs_key_field="Id",
        outputs=output,
        raw_response=response,
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

    return create_report(
        client=client,
        scope=scope,
        template_id=template_id,
        report_name=report_name,
        report_format=report_format,
        download_immediately=download_immediately,
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


def download_report_command(client: Client, report_id: str, instance_id: str,
                            report_name: Union[str, None], report_format: ReportFileFormat) -> dict:
    """
    Download a report file.

    Args:
        client (Client): Client to use for API requests.
        report_id (str): ID of the report to download.
        instance_id (str): ID of the report instance.
        report_name (str | None, optional): Name to give the generated report file.
            Defaults to None (results in using a "report <date>" format as a name).
        report_format (ReportFileFormat): File format to use for the generated report.

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
        filename=f"{report_name}.{report_format.name.lower()}",
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

    if solutions:
        solutions_output = replace_key_names(
            data=solutions.get("resources"),
            name_mapping={
                "type": "Type",
                "summary.text": "Summary",
                "steps.text": "Steps",
                "estimate": "Estimate",
                "additionalInformation.text": "AdditionalInformation",
            },
            recursive=True,
        )

        for i, val in enumerate(solutions_output):
            solutions_output[i]["Estimate"] = convert_duration_time(solutions_output[i]["Estimate"])

    vulnerabilities_md = tableToMarkdown("Vulnerability " + vulnerability_id, vulnerability_outputs,
                                         vulnerability_headers, removeNull=True)
    results_md = tableToMarkdown("Checks", results_output, results_headers, removeNull=True) if len(
        results_output) > 0 else ""
    solutions_md = tableToMarkdown("Solutions", solutions_output, solutions_headers,
                                   removeNull=True) if solutions_output is not None else ""

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

    for scan_schedule in scan_schedules:
        if scan_schedule.get("duration"):
            scan_schedule["duration"] = convert_duration_time(scan_schedule["duration"])
        if scan_schedule.get("repeat") and scan_schedule["repeat"].get("every"):
            scan_schedule["repeat"]["every"] = "every " + scan_schedule["repeat"]["every"]

    headers = [
        "Enable",
        "StartDate",
        "Name",
        "MaxDuration",
        "Repeat",
        "NextStart",
    ]

    outputs = replace_key_names(
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

    return CommandResults(
        outputs_prefix="Nexpose.ScanSchedule",
        outputs_key_field="Id",
        outputs=outputs,
        readable_output=tableToMarkdown("Nexpose scan schedules", outputs, headers, removeNull=True),
        raw_response=scan_schedules,
    )


def search_assets_command(client: Client, filter_query: Optional[str] = None, ip_addresses: Optional[str] = None,
                          hostnames: Optional[str] = None, risk_score: Optional[str] = None,
                          vulnerability_title: Optional[str] = None, sites: Optional[Site, list[Site]] = None,
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
    )
    endpoints = [{"IP": asset["Address"], "HostName": asset["Name"], "OS": asset["OperatingSystem"]}
                 for asset in outputs]

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


def start_assets_scan_command(client: Client, ips: Optional[str, list] = None,
                              hostnames: Optional[str, list] = None,
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
    response = client.update_scan_status(scan_id, scan_status.name.lower())

    return CommandResults(
        readable_output=f"Successfully updated scan status to \"{scan_status.name.lower()}\"",
        raw_response=response,
    )


def main():
    try:
        args = demisto.args()
        params = demisto.params()
        command = demisto.command()
        handle_proxy()

        client = Client(
            url=params.get("server"),
            username=params["credentials"].get("identifier"),
            password=params["credentials"].get("password"),
            token=params.get("token"),
            verify=not params.get("unsecure")
        )

        if command == "test-module":
            client.get_assets(page_size=1, limit=1)
            results = "ok"
        elif command == "nexpose-create-assets-report":
            results = create_assets_report_command(
                client=client,
                asset_ids=argToList(args.get("assets")),
                template_id=args.get("template"),
                report_name=args.get("name"),
                report_format=ReportFileFormat(args.get("format").upper()),
                download_immediately=argToBoolean(args.get("download_immediately"))
            )
        elif command == "nexpose-create-scan-report":
            results = create_scan_report_command(
                client=client,
                scan_id=args.get("scans"),
                template_id=args.get("template"),
                report_name=args.get("name"),
                report_format=ReportFileFormat(args.get("format").upper()),
                download_immediately=argToBoolean(args.get("download_immediately")),
            )
        elif command == "nexpose-create-site":
            results = create_site_command(
                client=client,
                name=args.get("name"),
                description=args.get("description"),
                assets=argToList(args.get("assets")),
                site_importance=SiteImportance(args.get("importance").upper()),
                template_id=args.get("scanTemplateId"),
            )
        elif command == "nexpose-create-sites-report":
            sites_list = [Site(site_id=site_id, client=client) for site_id in argToList(args.get("sites"))]
            sites_list.extend(
                [Site(site_name=site_name, client=client) for site_name in argToList(args.get("site_names"))]
            )

            results = create_sites_report_command(
                client=client,
                sites=sites_list,
                template_id=args.get("template"),
                report_name=args.get("name"),
                report_format=ReportFileFormat(args.get("format").upper()),
                download_immediately=argToBoolean(args.get("download_immediately")),
            )
        elif command == "nexpose-delete-scan-schedule":
            results = delete_scheduled_scan_command(
                client=client,
                site=Site(
                    site_id=args.get("site_id"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
                scheduled_scan_id=args.get("schedule_id"),
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
        elif command == "nexpose-download-report":
            results = download_report_command(
                client=client,
                report_id=args.get("report_id"),
                instance_id=args.get("instance_id"),
                report_name=args.get("name"),
                report_format=ReportFileFormat(args.get("format", "pdf").upper()),
            )
        elif command == "nexpose-get-asset":
            results = get_asset_command(
                client=client,
                asset_id=args.get("id")
            )
        elif command == "nexpose-get-asset-vulnerability":
            results = get_asset_vulnerability_command(
                client=client,
                asset_id=args.get("id"),
                vulnerability_id=args.get("vulnerabilityId"),
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
                report_id=args.get("report_id"),
                instance_id=args.get("instance_id")
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
        elif command == "nexpose-pause-scan":
            results = update_scan_command(
                client=client,
                scan_id=args.get("id"),
                scan_status=ScanStatus.PAUSE,
            )
        elif command == "nexpose-resume-scan":
            results = update_scan_command(
                client=client,
                scan_id=args.get("id"),
                scan_status=ScanStatus.RESUME,
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
                scan_id=args.get("id"),
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

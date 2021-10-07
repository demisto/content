"""Main integration script."""
import dateparser
from typing import Dict, Tuple
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
COMMON_BASE_URL = "https://api.central.sophos.com"


class Client(BaseClient):
    """Client class, communicates with Sophos Central."""

    def __init__(
        self,
        client_id,
        client_secret,
        verify,
        proxy,
        bearer_token,
        integration_context,
        tenant_id="",
    ):
        """
        Set headers, client_id and client_secret.

        Args:
            client_id (str): Sophos Central client id.
            client_secret (str): Sophos Central client secret.
            verify (bool): takes bool value.
            proxy (bool): takes boolean value.
            bearer_token (str): A JWT token.
        """
        headers, base_url = self.get_client_data(tenant_id, bearer_token)
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
        self.headers = headers
        self.bearer_token = bearer_token
        self.client_id = client_id
        self.client_secret = client_secret
        self.integration_context = integration_context

    @staticmethod
    def _cache_exists() -> bool:
        """
        Check if the cache exists with base URL and tenant ID.

        Returns:
            _cache_exists (bool): True, if cache has base URL and tenant ID as keys, False otherwise.
        """
        context = get_integration_context()
        return "base_url" in context and "tenant_id" in context

    @staticmethod
    def _whoami(bearer_token: str) -> dict:
        """
        Get the "whoami" API response.

        Args:
            bearer_token (str): JWT token for authentication

        Returns:
            response (dict): whoami API response
        """
        headers = {"Authorization": f"Bearer {bearer_token}"}
        try:
            response = requests.get(f"{COMMON_BASE_URL}/whoami/v1", headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as err:
            raise DemistoException(
                f"An HTTP error occurred while validating the given tenant ID: {str(err)}"
            )
        except requests.exceptions.SSLError as err:
            raise DemistoException(f"SSL Certificate Verification Failed: {str(err)}")
        except requests.exceptions.ProxyError as err:
            err_msg = (
                "Proxy Error - if the 'Use system proxy' checkbox in the integration configuration is"
                " selected, try clearing the checkbox."
            )
            raise DemistoException(err_msg, err)
        except requests.exceptions.ConnectionError as err:
            raise DemistoException(
                f"Connection error occurred while validating the given tenant ID: {str(err)}"
            )
        except requests.exceptions.Timeout as err:
            raise DemistoException(
                f"Request timed out while validating the given tenant ID: {str(err)}"
            )
        except requests.exceptions.RequestException as err:
            raise DemistoException(
                f"An error occurred while making REST API call to validate the given tenant ID: {str(err)}"
            )
        except Exception as err:
            raise DemistoException(
                f"An error occurred while processing the API response: {str(err)}"
            )

    @staticmethod
    def _get_tenant_base_url(
        bearer_token: str, entity_id: str, tenant_id: str, creds_type: str
    ) -> str:
        """
        Fetch the tenant base URL.

        Args:
            bearer_token (str): JWT token for authentication
            entity_id (str): Partner or organization ID
            tenant_id (str): Tenant ID for which the base URL is to be fetched
            creds_type (str): Credential type (partner/organization)

        Returns:
            base_url (str): The base URL of given tenant in given partner/organization
        """
        url_suffix = f"{creds_type}/v1/tenants/{tenant_id}"
        headers = {
            f"X-{creds_type.title()}-ID": entity_id,
            "Authorization": f"Bearer {bearer_token}",
        }

        try:
            response = requests.get(f"{COMMON_BASE_URL}/{url_suffix}", headers=headers)

            if response.status_code == 200:
                return response.json().get("apiHost", "")
            elif response.status_code == 404:
                return ""
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            raise DemistoException(
                f"An HTTP error occurred while validating the given tenant ID: {str(err)}"
            )
        except requests.exceptions.SSLError as err:
            raise DemistoException(f"SSL Certificate Verification Failed: {str(err)}")
        except requests.exceptions.ProxyError as err:
            err_msg = (
                "Proxy Error - if the 'Use system proxy' checkbox in the integration configuration is"
                " selected, try clearing the checkbox."
            )
            raise DemistoException(err_msg, err)
        except requests.exceptions.ConnectionError as err:
            raise DemistoException(
                f"Connection error occurred while validating the given tenant ID: {str(err)}"
            )
        except requests.exceptions.Timeout as err:
            raise DemistoException(
                f"Request timed out while validating the given tenant ID: {str(err)}"
            )
        except requests.exceptions.RequestException as err:
            raise DemistoException(
                f"An error occurred while making REST API call to validate the given tenant ID: {str(err)}"
            )
        except Exception as err:
            raise DemistoException(
                f"An error occurred while processing the API response: {str(err)}"
            )
        return ""

    @staticmethod
    def _update_integration_context(new_context: dict):
        """
        Update the integration context by the new values.

        Args:
            new_context (dict): The new context values to be added to existing context.
        """
        context = get_integration_context()
        context.update(new_context)
        set_integration_context(context)

    @staticmethod
    def get_client_data(tenant_id: str, bearer_token: str) -> Tuple[dict, str]:
        """
        Validate the given tenant ID.

        Args:
            tenant_id (str): Tenant ID entered by the user
            bearer_token (str): JWT token for authentication

        Returns:
            headers (dict): Headers object with tenant ID and bearer token.
            base_url (str): Tenant specific regional base URL.
        """
        headers = {"Authorization": f"Bearer {bearer_token}"}

        # compare tenant id with cache
        if Client._cache_exists():
            context = get_integration_context()
            if tenant_id == context.get("tenant_id") or context.get(
                "is_tenant_level", False
            ):
                # this means tenant ID hasn't changed. So use the cache
                headers.update({"X-Tenant-ID": context.get("tenant_id")})
                return headers, context.get("base_url")
            else:
                # this means tenant ID changed, update the cache.
                context.pop("base_url")
                context.pop("tenant_id")
                set_integration_context(context)
                return Client.get_client_data(tenant_id, bearer_token)
        else:
            whoami = Client._whoami(bearer_token)
            creds_type, entity_id, base_url = (
                str(whoami.get("idType")).lower(),
                whoami.get("id", ""),
                whoami.get("apiHosts", {}).get("dataRegion"),
            )
            # if tenant ID is provided even with tenant level credentials and it's different from
            # actual tenant ID, raise error without making API call to validate it.
            if tenant_id and creds_type == "tenant" and tenant_id != entity_id:
                raise DemistoException(
                    "Value provided in tenant ID field is not same as configured tenant whose credentials are entered."
                )
            if tenant_id and creds_type != "tenant":
                # validate the given tenant id for partner or organization entity and get corresponding base url
                base_url = Client._get_tenant_base_url(
                    bearer_token, entity_id, tenant_id, creds_type
                )
                if base_url:
                    base_url = f"{base_url}/"
                    headers.update({"X-Tenant-ID": tenant_id})
                    # update the cache
                    Client._update_integration_context(
                        {"base_url": base_url, "tenant_id": tenant_id}
                    )
                    return headers, base_url
                raise DemistoException(
                    f"Value provided in tenant ID is not from managed tenants of "
                    f"configured {creds_type} whose credentials are entered."
                )
            else:
                # validate that the credentials are of tenant level and get the corresponding tenant id.
                if creds_type != "tenant":
                    raise DemistoException(
                        f"Tenant ID field is mandatory to configure {creds_type} user's credential."
                    )

                headers.update({"X-Tenant-ID": entity_id})
                if not base_url:
                    raise DemistoException("Error finding data region.")

                base_url = f"{base_url}/"
                # updatet the cache
                Client._update_integration_context(
                    {
                        "base_url": base_url,
                        "tenant_id": entity_id,
                        "is_tenant_level": True,
                    }
                )
                return headers, base_url

    @staticmethod
    def get_jwt_token_from_api(client_id: str, client_secret: str) -> dict:
        """
        Send an auth request to Sophos Central and receive an access token.

        Args:
            client_id (str): Sophos Central client id.
            client_secret (str): Sophos Central client secret.

        Returns:
            response.json (dict): API response from Sophos.
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "token",
        }
        response = requests.post(
            headers=headers, data=body, url="https://id.sophos.com/api/v2/oauth2/token"
        )
        if not response.ok:
            raise DemistoException(response.text)
        return response.json()

    def convert_id_to_name(
        self, object_mapping_name: str, object_id: str, url_suffix: str, field_key: str
    ) -> str:
        """
        Converts an object id to its name using API.
        Notes:
        * as a performance enhacement, will use integration context as a cache to avoid multiple API calls.
        * Follows the best-effort approach. in case of an error, it will log the error and return an empty string.
        Args:
            object_mapping_name (str): the name of the object mapping.
            object_id (str): the object ID to convert.
            url_suffix (str): the URL endpoint for getting the object info.
            field_key (str): the field key of the name in the API response.
        Returns:
            object name (str): the object name if successful, empty string otherwise.
        """
        try:
            object_mapping = self.integration_context.setdefault(
                object_mapping_name, {}
            )
            if object_mapping.get(object_id):
                return object_mapping.get(object_id)

            demisto.debug(
                f"did not find object id in {object_mapping_name} cache, retreiving from API"
            )
            response = self._http_request(
                method="GET",
                url_suffix=url_suffix,
                headers=self.headers,
            )
            object_mapping[object_id] = response.get(field_key, "")
            return object_mapping[object_id]
        except Exception as exc:
            demisto.debug(
                f"failed to convert the {object_mapping_name} id, Error: {exc}\n{traceback.format_exc()}"
            )
            return ""

    def get_person_name(self, person_id: str) -> str:
        return self.convert_id_to_name(
            "person_mapping",
            person_id,
            f"common/v1/directory/users/{person_id}",
            "name",
        )

    def get_managed_agent_name(self, managed_agent_id: str) -> str:
        return self.convert_id_to_name(
            "managed_agent_mapping",
            managed_agent_id,
            f"endpoint/v1/endpoints/{managed_agent_id}",
            "hostname",
        )

    def list_alert(self, limit: Optional[int]) -> Dict:
        """
        List all alerts connected to a tenant.

        Args:
            limit (int): Max number of alerts to return.

        Returns:
            response (Response): API response from Sophos.
        """
        params = remove_empty_elements({"pageSize": limit})
        url_suffix = "common/v1/alerts"
        return self._http_request(
            method="GET", url_suffix=url_suffix, headers=self.headers, params=params
        )

    def get_alert(self, alert_id: str) -> Dict:
        """
        Get a single alert based on ID.

        Args:
            alert_id (str): ID of the alert to get.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = f"common/v1/alerts/{alert_id}"
        return self._http_request(
            method="GET", url_suffix=url_suffix, headers=self.headers
        )

    def action_alert(
        self,
        alert_id: str,
        action: str,
        message: Optional[str],
    ) -> Dict:
        """
        Take action against one alert.

        Args:
            alert_id (str): Alert ID to take action against
            action (str): Name of the action to take.
            message (str): Optional message for the action.

        Returns:
            response (Response): API response from Sophos.
        """
        body = remove_empty_elements({"action": action, "message": message})
        url_suffix = f"common/v1/alerts/{alert_id}/actions"
        return self._http_request(
            method="POST",
            headers=self.headers,
            json_data=body,
            url_suffix=url_suffix,
        )

    def search_alert(
        self,
        start: Optional[str],
        end: Optional[str],
        product: Optional[List[str]],
        category: Optional[List[str]],
        group_key: Optional[str],
        severity: Optional[List[str]],
        ids: Optional[List[str]],
        limit: Optional[int],
    ) -> Dict:
        """
        Search alerts based on parameters.

        Args:
            start (str): Find alerts that were raised on or after this time - Use ISO time format.
            end (str): Find alerts that were raised on or before this time - Use ISO time format.
            product (str): Alerts for a product.
            category (str): Alert category.
            group_key (str): Alerts for a specific severity level.
            severity (str): Alerts for a specific severity level.
            ids (list(str)): List of IDs.
            limit (int): Max number of alerts to return.

        Returns:
            response (Response): API response from Sophos.
        """
        body = {
            "from": start,
            "to": end,
            "product": product,
            "category": category,
            "groupKey": group_key,
            "severity": severity,
            "ids": ids,
            "pageSize": limit,
        }
        body = remove_empty_elements(body)
        url_suffix = "common/v1/alerts/search"
        return self._http_request(
            method="POST",
            headers=self.headers,
            json_data=body,
            url_suffix=url_suffix,
        )

    def list_endpoint(
        self,
        health_status: Optional[List[str]],
        endpoint_type: Optional[List[str]],
        tamper_protection_enabled: Optional[bool],
        lockdown_status: Optional[List[str]],
        last_seen_before: Optional[str],
        last_seen_after: Optional[str],
        ids: Optional[List[str]],
        view: Optional[str],
        limit: Optional[int],
    ) -> Dict:
        """
        List all endpoints for a tenant.

        Args:
            health_status (list(str)): Endpoints that have any of the specified health status.
            endpoint_type (list(str)): Endpoints that have any of the specified endpoint type.
            tamper_protection_enabled (bool): Tamper protection status.
            lockdown_status (list(str)): Endpoints that have any of the specified lockdown status.
            last_seen_before (str): Last seen before date and time (UTC) or duration exclusive.
            last_seen_after (str): Last seen after date and time (UTC) or duration inclusive.
            ids (list(str)): List of IDs.
            view (str): Type of view to be returned in the response.
            limit (int): Max number of endpoints to return.

        Returns:
            response (Response): API response from Sophos.
        """
        params = {
            "healthStatus": health_status,
            "type": endpoint_type,
            "tamperProtectionEnabled": tamper_protection_enabled,
            "lockdownStatus": lockdown_status,
            "lastSeenBefore": last_seen_before,
            "lastSeenAfter": last_seen_after,
            "ids": ids,
            "view": view,
            "pageSize": limit,
        }
        params = remove_empty_elements(params)
        url_suffix = "endpoint/v1/endpoints"
        return self._http_request(
            method="GET", headers=self.headers, params=params, url_suffix=url_suffix
        )

    def scan_endpoint(self, endpoint_id: str) -> Dict:
        """
        Initiate a scan on an endpoint.

        Args:
            endpoint_id (str): ID of the endpoint to scan.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = f"endpoint/v1/endpoints/{endpoint_id}/scans"
        return self._http_request(
            method="POST", headers=self.headers, json_data={}, url_suffix=url_suffix
        )

    def get_tamper(self, endpoint_id: str) -> Dict:
        """
        Get tamper protection of an endpoint.

        Args:
            endpoint_id (str): ID of the endpoint to get protection of.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = f"endpoint/v1/endpoints/{endpoint_id}/tamper-protection"
        return self._http_request(
            method="GET", headers=self.headers, url_suffix=url_suffix
        )

    def update_tamper(self, endpoint_id: str, enabled: bool) -> Dict:
        """
        Get tamper protection of an endpoin.

        Args:
            endpoint_id (str): ID of the endpoint to update protection of.
            enabled(bool): Should the protection be updated to enabled or disabled.

        Returns:
            response (Response): API response from Sophos.
        """
        body = {"enabled": enabled}
        url_suffix = f"endpoint/v1/endpoints/{endpoint_id}/tamper-protection"
        return self._http_request(
            method="POST",
            headers=self.headers,
            json_data=body,
            url_suffix=url_suffix,
        )

    def list_allowed_item(
        self,
        page_size: Optional[int],
        page: Optional[int],
    ) -> Dict:
        """
        List all allowed items for a tenant.

        Args:
            page_size (int): Max number of results per page.
            page (int): Page number to return.

        Returns:
            response (Response): API response from Sophos.
        """
        params = remove_empty_elements({"pageSize": page_size, "page": page})
        url_suffix = "endpoint/v1/settings/allowed-items"
        return self._http_request(
            method="GET", headers=self.headers, params=params, url_suffix=url_suffix
        )

    def get_allowed_item(self, allowed_item_id: str) -> Dict:
        """
        Get a single allowed item.

        Args:
            allowed_item_id (str): Allowed item ID.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = f"endpoint/v1/settings/allowed-items/{allowed_item_id}"
        return self._http_request(
            method="GET", headers=self.headers, url_suffix=url_suffix
        )

    def add_allowed_item(
        self,
        item_type: str,
        comment: str,
        certificate_signer: Optional[str],
        file_name: Optional[str],
        path: Optional[str],
        sha256: Optional[str],
        origin_endpoint_id: Optional[str],
    ) -> Dict:
        """
        Add a new allowed item.

        Args:
            comment (str): Comment indicating why the item should be allowed.
            certificate_signer (str): Certificate signer.
            file_name (str): File name to allow.
            path (str): Path of file to allow.
            sha256 (str) SHA256 value for the file.
            item_type (str): type of the item.
            origin_endpoint_id (str): Endpoint ID where the item was last seen.

        Returns:
            response (Response): API response from Sophos.
        """
        body = {
            "comment": comment,
            "originEndpointId": origin_endpoint_id,
            "type": item_type,
            "properties": {
                "fileName": file_name,
                "path": path,
                "sha256": sha256,
                "certificateSigner": certificate_signer,
            },
        }
        body = remove_empty_elements(body)
        url_suffix = "endpoint/v1/settings/allowed-items"
        return self._http_request(
            method="POST",
            headers=self.headers,
            json_data=body,
            url_suffix=url_suffix,
        )

    def update_allowed_item(self, allowed_item_id: str, comment: str) -> Dict:
        """
        Update an existing allowed item.

        Args:
            allowed_item_id (str): ID of the allowed item to update.
            comment (str): Comment indicating why the item should be allowed.

        Returns:
            response (Response): API response from Sophos.
        """
        body = {"comment": comment}
        url_suffix = f"endpoint/v1/settings/allowed-items/{allowed_item_id}"
        return self._http_request(
            method="PATCH",
            headers=self.headers,
            json_data=body,
            url_suffix=url_suffix,
        )

    def delete_allowed_item(self, allowed_item_id: str) -> Dict:
        """
        Delete an existing allowed item.

        Args:
            allowed_item_id (str): ID of the allowed item to update.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = f"endpoint/v1/settings/allowed-items/{allowed_item_id}"
        return self._http_request(
            method="DELETE", headers=self.headers, url_suffix=url_suffix
        )

    def list_blocked_item(
        self,
        page_size: Optional[int],
        page: Optional[int],
    ) -> Dict:
        """
        List all blocked items for a tenant.

        Args:
            page_size (int): Max number of results per page.
            page (int): Page number to return.

        Returns:
            response (Response): API response from Sophos.
        """
        params = remove_empty_elements({"pageSize": page_size, "page": page})
        url_suffix = "endpoint/v1/settings/blocked-items"
        return self._http_request(
            method="GET", headers=self.headers, params=params, url_suffix=url_suffix
        )

    def get_blocked_item(self, allowed_item_id: str) -> Dict:
        """
        Get a single blocked item.

        Args:
            allowed_item_id (str): Allowed item ID.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = f"endpoint/v1/settings/blocked-items/{allowed_item_id}"
        return self._http_request(
            method="GET", headers=self.headers, url_suffix=url_suffix
        )

    def add_blocked_item(
        self,
        item_type: str,
        comment: str,
        certificate_signer: Optional[str],
        file_name: Optional[str],
        path: Optional[str],
        sha256: Optional[str],
        origin_endpoint_id: Optional[str],
    ) -> Dict:
        """
        Add a new blocked item.

        Args:
            comment (str): Comment indicating why the item should be allowed.
            certificate_signer (str): Certificate signer.
            file_name (str): File name to allow.
            path (str): Path of file to allow.
            sha256 (str) SHA256 value for the file.
            item_type (str): type of the item.
            origin_endpoint_id (str): Endpoint ID where the item was last seen.

        Returns:
            response (Response): API response from Sophos.
        """
        body = {
            "comment": comment,
            "originEndpointId": origin_endpoint_id,
            "type": item_type,
            "properties": {
                "fileName": file_name,
                "path": path,
                "sha256": sha256,
                "certificateSigner": certificate_signer,
            },
        }
        body = remove_empty_elements(body)
        url_suffix = "endpoint/v1/settings/blocked-items"
        return self._http_request(
            method="POST",
            headers=self.headers,
            json_data=body,
            url_suffix=url_suffix,
        )

    def delete_blocked_item(self, allowed_item_id: str) -> Dict:
        """
        Delete an existing blocked item.

        Args:
            allowed_item_id (str): ID of the allowed item to update.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = f"endpoint/v1/settings/blocked-items/{allowed_item_id}"
        return self._http_request(
            method="DELETE", headers=self.headers, url_suffix=url_suffix
        )

    def list_scan_exclusion(
        self,
        exclusion_type: Optional[str],
        page_size: Optional[int],
        page: Optional[int],
    ) -> Dict:
        """
        List all scan exclusions.

        Args:
            exclusion_type (str): Type of scanning exclusions to list.
            page_size (int): Size of the page requested.
            page (int): Number of page to return.

        Returns:
            response (Response): API response from Sophos.
        """
        params = remove_empty_elements(
            {"type": exclusion_type, "pageSize": page_size, "page": page}
        )
        url_suffix = "endpoint/v1/settings/exclusions/scanning"
        return self._http_request(
            method="GET", headers=self.headers, params=params, url_suffix=url_suffix
        )

    def get_scan_exclusion(self, exclusion_id: str) -> Dict:
        """
        Get a single scan exclusion.

        Args:
            exclusion_id (str): ID of the scan exclusion.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = f"endpoint/v1/settings/exclusions/scanning/{exclusion_id}"
        return self._http_request(
            method="GET", headers=self.headers, url_suffix=url_suffix
        )

    def add_scan_exclusion(
        self,
        comment: Optional[str],
        scan_mode: Optional[str],
        exclusion_type: str,
        value: str,
    ) -> Dict:
        """
        Add a new scan exclusion.

        Args:
            comment (str): Comment indicating why the exclusion was created.
            scan_mode (str): Scan mode to exclude.
            exclusion_type (str): Type of the scanning exclusion.
            value (str): Exclusion value.

        Returns:
            response (Response): API response from Sophos.
        """
        body = remove_empty_elements(
            {
                "comment": comment,
                "scanMode": scan_mode,
                "type": exclusion_type,
                "value": value,
            }
        )
        url_suffix = "endpoint/v1/settings/exclusions/scanning"
        return self._http_request(
            method="POST",
            headers=self.headers,
            json_data=body,
            url_suffix=url_suffix,
        )

    def update_scan_exclusion(
        self,
        comment: Optional[str],
        scan_mode: Optional[str],
        exclusion_id: str,
        value: Optional[str],
    ) -> Dict:
        """
        Update an existing scan exclusion.

        Args:
            comment (str): Comment indicating why the exclusion was created.
            scan_mode (str): Scan mode to exclude.
            exclusion_id (str): ID of the exclusion to update.
            value (str): Exclusion value.

        Returns:
            response (Response): API response from Sophos.
        """
        body = remove_empty_elements(
            {"comment": comment, "scanMode": scan_mode, "value": value}
        )
        url_suffix = f"endpoint/v1/settings/exclusions/scanning/{exclusion_id}"
        return self._http_request(
            method="PATCH",
            headers=self.headers,
            json_data=body,
            url_suffix=url_suffix,
        )

    def delete_scan_exclusion(self, exclusion_id: str) -> Dict:
        """
        Delete an existing scan exclusion.

        Args:
            exclusion_id (str): ID of the exclusion to delete.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = f"endpoint/v1/settings/exclusions/scanning/{exclusion_id}"
        return self._http_request(
            method="DELETE", headers=self.headers, url_suffix=url_suffix
        )

    def list_exploit_mitigation(
        self,
        mitigation_type: Optional[str],
        page_size: Optional[int],
        page: Optional[int],
        modified: Optional[bool],
    ) -> Dict:
        """
        List all exploit mitigations.

        Args:
            mitigation_type (str): Exploit mitigation type.
            page_size (int): Size of the page requested.
            page (int): Number of page to return.
            modified (bool): Whether or not the exploit mitigation was customized.

        Returns:
            response (Response): API response from Sophos.
        """
        params = remove_empty_elements(
            {
                "page": page,
                "pageSize": page_size,
                "type": mitigation_type,
                "modified": modified,
            }
        )
        url_suffix = "endpoint/v1/settings/exploit-mitigation/applications"
        return self._http_request(
            method="GET", headers=self.headers, params=params, url_suffix=url_suffix
        )

    def get_exploit_mitigation(self, mitigation_id: str) -> Dict:
        """
        Get a single exploit mitigation.

        Args:
            mitigation_id (str): Exploit mitigation type.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = (
            f"endpoint/v1/settings/exploit-mitigation/applications/{mitigation_id}"
        )
        return self._http_request(
            method="GET", headers=self.headers, url_suffix=url_suffix
        )

    def add_exploit_mitigation(self, path: str) -> Dict:
        """
        Add a new exploit mitigation.

        Args:
            path (str): An absolute path to exclude.

        Returns:
            response (Response): API response from Sophos.
        """
        body = {"paths": [path]}
        url_suffix = "endpoint/v1/settings/exploit-mitigation/applications"
        return self._http_request(
            method="POST",
            headers=self.headers,
            json_data=body,
            url_suffix=url_suffix,
        )

    def update_exploit_mitigation(
        self, mitigation_id: str, path: Optional[str]
    ) -> Dict:
        """
        Update an existing exploit mitigation.

        Args:
            mitigation_id (str): ID of the mitigation to update.
            path (str): An absolute path to exclude.

        Returns:
            response (Response): API response from Sophos.
        """
        body = remove_empty_elements({"paths": [path]})
        url_suffix = (
            f"endpoint/v1/settings/exploit-mitigation/applications/{mitigation_id}"
        )
        return self._http_request(
            method="PATCH",
            headers=self.headers,
            json_data=body,
            url_suffix=url_suffix,
        )

    def delete_exploit_mitigation(self, mitigation_id: str) -> Dict:
        """
        Update an existing exploit mitigation.

        Args:
            mitigation_id (str): ID of the mitigation to update.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = (
            f"endpoint/v1/settings/exploit-mitigation/applications/{mitigation_id}"
        )
        return self._http_request(
            method="DELETE", headers=self.headers, url_suffix=url_suffix
        )

    def list_detected_exploit(
        self,
        page_size: Optional[int],
        page: Optional[int],
        thumbprint_not_in: Optional[str],
    ) -> Dict:
        """
        List all detected exploits.

        Args:
            page_size (int): Size of the page requested.
            page (int): Number of page to return.
            thumbprint_not_in (str): Filter out detected exploits with these thumbprints.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = "endpoint/v1/settings/exploit-mitigation/detected-exploits"
        params = {
            "pageSize": page_size,
            "page": page,
            "thumbprintNotIn": thumbprint_not_in,
        }
        return self._http_request(
            method="GET", headers=self.headers, params=params, url_suffix=url_suffix
        )

    def get_detected_exploit(self, detected_exploit_id: str) -> Dict:
        """
        Get a single detected exploit.

        Args:
            detected_exploit_id (str): ID of the exploit to return.

        Returns:
            response (Response): API response from Sophos.
        """
        url_suffix = (
            "endpoint/v1/settings/exploit-mitigation"
            f"/detected-exploits/{detected_exploit_id}"
        )
        return self._http_request(
            method="GET", headers=self.headers, url_suffix=url_suffix
        )

    def isolate_endpoint(self, endpoint_id: List[str], comment: Optional[str]) -> Dict:
        """
        Initiate isolation request on the given endpoint(s).

        Args:
            endpoint_id: Endpoint ID(s) to be isolated.
            comment: Reason for isolation.

        Returns:
            response (Response): API response from Sophos.
        """
        body = {"enabled": True, "ids": endpoint_id, "comment": comment}
        return self._http_request(
            method="POST",
            headers=self.headers,
            url_suffix="endpoint/v1/endpoints/isolation",
            json_data=body,
        )

    def deisolate_endpoint(
        self, endpoint_id: List[str], comment: Optional[str]
    ) -> Dict:
        """
        Initiate de-isolation request on the given endpoint(s).

        Args:
            endpoint_id: Endpoint ID(s) to be de-isolated.
            comment: Reason for de-isolation.

        Returns:
            response (Response): API response from Sophos.
        """
        body = {"enabled": False, "ids": endpoint_id, "comment": comment}
        return self._http_request(
            method="POST",
            headers=self.headers,
            url_suffix="endpoint/v1/endpoints/isolation",
            json_data=body,
        )


def flip_chars(id_to_flip: str) -> str:
    """
    Reverse every couple of adjacent digits in the ID.
    can be used to construct Sophos URLs.
    For example:
        badc-fehgji-xwzy -> abcd-efghij-wxyz
    Args:
        id_to_flip (str): A UID
    Returns:
        id (str): A UID with the every two digits flipped.
    """
    return "-".join(
        "".join(pair[::-1] for pair in re.split(r"(.{2})", uid_part))
        for uid_part in id_to_flip.split("-")
    )


def create_alert_output(
    client: Client, item: Dict, table_headers: List[str]
) -> Dict[str, Optional[Any]]:
    """
    Create the complete output dictionary for an alert.

    Args:
        item (dict): A source dictionary from the API response.
        table_headers (list(str)): The table headers to be used when creating initial data.

    Returns:
        object_data (dict(str)): The output dictionary.
    """
    alert_data = {
        field: item.get(field) for field in table_headers + ["groupKey", "product"]
    }
    managed_agent = item.get("managedAgent")
    if managed_agent:
        managed_agent_id = managed_agent.get("id", "")
        alert_data["managedAgentId"] = managed_agent_id
        alert_data["managedAgentIdMorphed"] = flip_chars(managed_agent_id)
        alert_data["managedAgentName"] = client.get_managed_agent_name(managed_agent_id)
        alert_data["managedAgentType"] = managed_agent.get("type")
    tenant = item.get("tenant")
    if tenant:
        alert_data["tenantId"] = tenant.get("id")
        alert_data["tenantIdMorphed"] = flip_chars(tenant.get("id", ""))
        alert_data["tenantName"] = tenant.get("name")
    person = item.get("person")
    if person:
        person_id = person.get("id", "")
        alert_data["person"] = person_id
        alert_data["personIdMorphed"] = flip_chars(person_id)
        alert_data["personName"] = client.get_person_name(person_id)

    return alert_data


def sophos_central_alert_list_command(
    client: Client, args: Dict[str, str]
) -> CommandResults:
    """
    List all alerts.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    results = client.list_alert(min(int(args.get("limit", "")), 100))
    items = results.get("items")
    table_headers = [
        "id",
        "description",
        "severity",
        "raisedAt",
        "allowedActions",
        "managedAgentId",
        "managedAgentName",
        "personName",
        "category",
        "type",
    ]
    outputs = []
    if items:
        for item in items:
            outputs.append(create_alert_output(client, item, table_headers))

    readable_output = tableToMarkdown(
        name=f"Listed {len(outputs)} Alerts:",
        t=outputs,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.Alert",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def sophos_central_alert_get_command(client: Client, args: dict) -> CommandResults:
    """
    Get a specific alert by ID.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args.get("alert_id", "")
    try:
        result = client.get_alert(alert_id)
        table_headers = [
            "id",
            "description",
            "severity",
            "raisedAt",
            "allowedActions",
            "managedAgentId",
            "managedAgentName",
            "personName",
            "category",
            "type",
        ]
        object_data = create_alert_output(client, result, table_headers)
        readable_output = tableToMarkdown(
            name="Found Alert:", t=object_data, headers=table_headers, removeNull=True
        )
        return CommandResults(
            outputs_key_field="id",
            outputs_prefix="SophosCentral.Alert",
            raw_response=result,
            outputs=object_data,
            readable_output=readable_output,
        )
    except DemistoException:
        return CommandResults(
            readable_output=f"Unable to find the following alert: {alert_id}"
        )


def sophos_central_alert_action_command(client: Client, args: dict) -> CommandResults:
    """
    Take an action against a specific alert or alerts.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    outputs = []
    table_headers = [
        "id",
        "action",
        "completedAt",
        "alertId",
        "result",
        "requestedAt",
        "startedAt",
        "status",
    ]
    alert_ids = argToList(args.get("alert_id"))
    failed_alerts = []
    results = []
    for alert_id in alert_ids:
        try:
            result = client.action_alert(
                alert_id,
                args.get("action", ""),
                args.get("message", ""),
            )
            results.append(result)
            object_data = {field: result.get(field) for field in table_headers}
            outputs.append(object_data)
        except DemistoException:
            failed_alerts.append(alert_id)
    readable_output = tableToMarkdown(
        name="Alerts Acted Against:", t=outputs, headers=table_headers, removeNull=True
    )
    if failed_alerts:
        readable_output += f'\nAlerts not acted against: {",".join(failed_alerts)}'
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.AlertAction",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def sophos_central_alert_search_command(client: Client, args: dict) -> CommandResults:
    """
    Search for alerts based on query parameters.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    start_date = args.get("start")
    end_date = args.get("end")
    date_range = args.get("date_range")
    if date_range:
        start_date, end_date = parse_date_range(date_range=date_range)
        start_date = start_date.isoformat(timespec="milliseconds")
        end_date = end_date.isoformat(timespec="milliseconds")

    results = client.search_alert(
        start_date,
        end_date,
        argToList(args.get("product")),
        argToList(args.get("category")),
        args.get("group_key"),
        argToList(args.get("severity")),
        argToList(args.get("ids")),
        min(int(args.get("limit", "")), 100),
    )

    items = results.get("items")
    table_headers = [
        "id",
        "description",
        "severity",
        "raisedAt",
        "allowedActions",
        "managedAgentId",
        "managedAgentName",
        "personName",
        "category",
        "type",
    ]
    outputs = []
    if items:
        for item in items:
            outputs.append(create_alert_output(client, item, table_headers))

    readable_output = tableToMarkdown(
        name=f"Found {len(outputs)} Alerts:",
        t=outputs,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.Alert",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def sophos_central_endpoint_list_command(client: Client, args: dict) -> CommandResults:
    """
    List all endpoints.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    results = client.list_endpoint(
        argToList(args.get("health_status")),
        argToList(args.get("endpoint_type")),
        args.get("tamper_protection_enabled") == "true",
        argToList(args.get("lockdown_status")),
        args.get("last_seen_before"),
        args.get("last_seen_after"),
        args.get("ids"),
        args.get("view"),
        min(int(args.get("limit", "")), 100),
    )
    items = results.get("items")
    table_headers = [
        "id",
        "hostname",
        "ipv4Addresses",
        "ipv6Addresses",
        "macAddresses",
        "type",
        "online",
        "tamperProtectionEnabled",
    ]
    outputs = []
    if items:
        for item in items:
            object_data = {field: item.get(field) for field in table_headers}
            assigned_products = item.get("assignedProducts")
            if assigned_products:
                object_data["assignedProductCodes"] = [
                    product.get("code")
                    for product in assigned_products
                    if product.get("code")
                ]
            associated_person = item.get("associatedPerson")
            if associated_person:
                object_data["associatedPersonId"] = associated_person.get("id")
                object_data["associatedPersonName"] = associated_person.get("name")
                object_data["associatedPersonViaLogin"] = associated_person.get(
                    "viaLogin"
                )
            group = item.get("group")
            if group:
                object_data["groupId"] = group.get("id")
                object_data["groupName"] = group.get("name")
            endpoint_os = item.get("os")
            if endpoint_os:
                object_data["osBuild"] = endpoint_os.get("build")
                object_data["osIsServer"] = endpoint_os.get("isServer")
                object_data["osName"] = endpoint_os.get("name")
                object_data["osPlatform"] = endpoint_os.get("platform")
            health = item.get("health")
            if health:
                object_data["health"] = health.get("overall")
            outputs.append(object_data)
    readable_output = tableToMarkdown(
        name=f"Listed {len(outputs)} Endpoints:",
        t=outputs,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.Endpoint",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def sophos_central_endpoint_scan_command(client: Client, args: dict) -> CommandResults:
    """
    Initiate a scan on an endpoint.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    table_headers = ["id", "status", "requestedAt"]
    failed_endpoints = []
    outputs = []
    results = []
    for endpoint in argToList(args.get("endpoint_id")):
        try:
            result = client.scan_endpoint(endpoint)
            if result:
                results.append(result)
                object_data = {field: result.get(field) for field in table_headers}
                outputs.append(object_data)
        except DemistoException:
            failed_endpoints.append(endpoint)
    readable_output = tableToMarkdown(
        name="Scanning Endpoints:", t=outputs, headers=table_headers, removeNull=True
    )
    if failed_endpoints:
        readable_output += f'\nEndpoints not scanned: {",".join(failed_endpoints)}'
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.EndpointScan",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def sophos_central_endpoint_tamper_get_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Get tamper protection info on one or more endpoints.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    table_headers = ["endpointId", "enabled", "password"]
    failed_endpoints = []
    outputs = []
    results = []
    for endpoint in argToList(args.get("endpoint_id")):
        try:
            result = client.get_tamper(endpoint)
            if result:
                object_data = {
                    "enabled": result.get("enabled"),
                    "endpointId": endpoint,
                    "password": result.get("password"),
                }
                if not argToBoolean(args.get("get_password")):
                    object_data["password"] = None
                    result["password"] = result["previousPasswords"] = None
                results.append(result)
                outputs.append(object_data)
        except DemistoException:
            failed_endpoints.append(endpoint)
    readable_output = tableToMarkdown(
        name="Listed Endpoints Tamper Protection:",
        t=outputs,
        headers=table_headers,
        removeNull=True,
    )
    if failed_endpoints:
        readable_output += f'\nEndpoints not found: {",".join(failed_endpoints)}'
    return CommandResults(
        outputs_key_field="endpointId",
        outputs_prefix="SophosCentral.EndpointTamper",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def sophos_central_endpoint_tamper_update_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Update tamper protection info on one or more endpoints.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    table_headers = ["endpointId", "enabled", "password"]
    failed_endpoints = []
    outputs = []
    results = []
    for endpoint in argToList(args.get("endpoint_id")):
        try:
            result = client.update_tamper(endpoint, args.get("enabled") == "true")
            if result:
                object_data = {
                    "enabled": result.get("enabled"),
                    "endpointId": endpoint,
                    "password": result.get("password"),
                }
                if not argToBoolean(args.get("get_password")):
                    object_data["password"] = None
                    result["password"] = result["previousPasswords"] = None
                results.append(result)
                outputs.append(object_data)
        except DemistoException:
            failed_endpoints.append(endpoint)
    readable_output = tableToMarkdown(
        name="Updated Endpoints Tamper Protection:",
        t=outputs,
        headers=table_headers,
        removeNull=True,
    )
    if failed_endpoints:
        readable_output += f'\nEndpoints not found: {",".join(failed_endpoints)}'
    return CommandResults(
        outputs_key_field="endpointId",
        outputs_prefix="SophosCentral.EndpointTamper",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def create_item_output(item: Dict) -> Dict:
    """
    Create the complete output dictionary for an allowed / blocked item.

    Args:
        item (dict(str)): A source dictionary from the API response.

    Returns:
        item_data (dict(str)): The output dictionary.
    """
    data_fields = ["id", "comment", "type", "updatedAt", "createdAt"]
    item_data = {field: item.get(field) for field in data_fields}
    properties = item.get("properties")
    if properties:
        item_data["fileName"] = properties.get("fileName")
        item_data["path"] = properties.get("path")
        item_data["sha256"] = properties.get("sha256")
        item_data["certificateSigner"] = properties.get("certificateSigner")

    created_by = item.get("createdBy")
    if created_by:
        item_data["createdById"] = created_by.get("id")
        item_data["createdByName"] = created_by.get("name")

    origin_endpoint = item.get("originEndpoint")
    if origin_endpoint:
        item_data["originEndpointId"] = origin_endpoint.get("endpointId")

    origin_person = item.get("originPerson")
    if origin_person:
        item_data["originPersonId"] = origin_person.get("id")
        item_data["originPersonName"] = origin_person.get("name")

    return item_data


def validate_item_fields(args: Dict[str, str]):
    """
    Validate parameters exist before they are sent to the API.

    Args:
        args (dict): XSOAR arguments for the command.

    Raises:
        DemistoException: If a required field is missing.
    """
    item_types = ["path", "certificateSigner", "sha256"]
    for item_type in item_types:
        if args.get("item_type") == item_type and not args.get(
            camel_case_to_underscore(item_type)
        ):
            raise DemistoException(
                f"{item_type} item requires a value "
                f"in the {camel_case_to_underscore(item_type)} argument."
            )


def sophos_central_allowed_item_list_command(
    client: Client, args: dict
) -> CommandResults:
    """
    List all allowed items for a tenant.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    results = client.list_allowed_item(
        min(int(args.get("page_size", "")), 100), args.get("page")
    )
    items = results.get("items")
    table_headers = [
        "id",
        "comment",
        "fileName",
        "sha256",
        "path",
        "certificateSigner",
        "createdAt",
        "createdByName",
        "type",
        "updatedAt",
    ]
    outputs = []
    if items:
        for item in items:
            outputs.append(create_item_output(item))
    readable_output = f'### Current page: {int(args.get("page", ""))}\n'
    readable_output += tableToMarkdown(
        name=f"Listed {len(outputs)} Allowed Items:",
        t=outputs,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.AllowedItem",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def sophos_central_allowed_item_get_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Get a single allowed item for a tenant.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    allowed_item_id = args.get("allowed_item_id", "")
    try:
        result = client.get_allowed_item(allowed_item_id)
        table_headers = [
            "id",
            "comment",
            "fileName",
            "sha256",
            "path",
            "certificateSigner",
            "createdAt",
            "createdByName",
            "type",
            "updatedAt",
        ]
        object_data = {}
        if result:
            object_data = create_item_output(result)

        readable_output = tableToMarkdown(
            name="Found Allowed Item:",
            t=object_data,
            headers=table_headers,
            removeNull=True,
        )
        return CommandResults(
            outputs_key_field="id",
            outputs_prefix="SophosCentral.AllowedItem",
            raw_response=result,
            outputs=object_data,
            readable_output=readable_output,
        )
    except DemistoException:
        return CommandResults(readable_output=f"Unable to find item: {allowed_item_id}")


def sophos_central_allowed_item_add_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Add a new allowed item.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    validate_item_fields(args)
    result = client.add_allowed_item(
        args.get("item_type", ""),
        args.get("comment", ""),
        args.get("certificate_signer"),
        args.get("file_name"),
        args.get("path"),
        args.get("sha256"),
        args.get("origin_endpoint_id"),
    )
    table_headers = [
        "id",
        "comment",
        "fileName",
        "sha256",
        "path",
        "certificateSigner",
        "createdAt",
        "createdByName",
        "type",
        "updatedAt",
    ]
    object_data = {}
    if result:
        object_data = create_item_output(result)

    readable_output = tableToMarkdown(
        name="Added Allowed Item:",
        t=object_data,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.AllowedItem",
        raw_response=result,
        outputs=object_data,
        readable_output=readable_output,
    )


def sophos_central_allowed_item_update_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Update an existing allowed item.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    allowed_item_id = args.get("allowed_item_id", "")
    try:
        result = client.update_allowed_item(allowed_item_id, args.get("comment", ""))
        table_headers = [
            "id",
            "comment",
            "fileName",
            "sha256",
            "path",
            "certificateSigner",
            "createdAt",
            "createdByName",
            "type",
            "updatedAt",
        ]
        object_data = {}
        if result:
            object_data = create_item_output(result)

        readable_output = tableToMarkdown(
            name="Updated Allowed Item:",
            t=object_data,
            headers=table_headers,
            removeNull=True,
        )
        return CommandResults(
            outputs_key_field="id",
            outputs_prefix="SophosCentral.AllowedItem",
            raw_response=result,
            outputs=object_data,
            readable_output=readable_output,
        )
    except DemistoException:
        return CommandResults(
            readable_output=f"Unable to update item: {allowed_item_id}"
        )


def sophos_central_allowed_item_delete_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Delete an existing allowed item.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    result = client.delete_allowed_item(args.get("allowed_item_id", ""))
    readable_output = (
        f'Success deleting allowed item: {args.get("allowed_item_id", "")}'
    )
    outputs = {"deletedItemId": args.get("allowed_item_id", "")}
    if not result or not result.get("deleted"):
        readable_output = (
            f'Failed deleting allowed item: {args.get("allowed_item_id", "")}'
        )
        outputs = {}
    return CommandResults(
        raw_response=result,
        readable_output=readable_output,
        outputs=outputs,
        outputs_prefix="SophosCentral.DeletedAllowedItem",
    )


def sophos_central_blocked_item_list_command(
    client: Client, args: dict
) -> CommandResults:
    """
    List all blocked items for a tenant.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    results = client.list_blocked_item(
        min(int(args.get("page_size", "")), 100),
        args.get("page"),
    )
    items = results.get("items")
    table_headers = [
        "id",
        "comment",
        "fileName",
        "sha256",
        "path",
        "certificateSigner",
        "createdAt",
        "createdByName",
        "type",
        "updatedAt",
    ]
    outputs = []
    if items:
        for item in items:
            outputs.append(create_item_output(item))

    readable_output = f'### Current page: {int(args.get("page", ""))}\n'
    readable_output += tableToMarkdown(
        name=f"Listed {len(outputs)} Blocked Items:",
        t=outputs,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.BlockedItem",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def sophos_central_blocked_item_get_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Get a single blocked item for a tenant.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    blocked_item_id = args.get("blocked_item_id", "")
    try:
        result = client.get_blocked_item(blocked_item_id)
        table_headers = [
            "id",
            "comment",
            "fileName",
            "sha256",
            "path",
            "certificateSigner",
            "createdAt",
            "createdByName",
            "type",
            "updatedAt",
        ]
        object_data = {}
        if result:
            object_data = create_item_output(result)

        readable_output = tableToMarkdown(
            name="Found Blocked Item:",
            t=object_data,
            headers=table_headers,
            removeNull=True,
        )
        return CommandResults(
            outputs_key_field="id",
            outputs_prefix="SophosCentral.BlockedItem",
            raw_response=result,
            outputs=object_data,
            readable_output=readable_output,
        )
    except DemistoException:
        return CommandResults(readable_output=f"Unable to find item: {blocked_item_id}")


def sophos_central_blocked_item_add_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Add a new blocked item.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    validate_item_fields(args)
    result = client.add_blocked_item(
        args.get("item_type", ""),
        args.get("comment", ""),
        args.get("certificate_signer"),
        args.get("file_name"),
        args.get("path"),
        args.get("sha256"),
        args.get("origin_endpoint_id"),
    )
    table_headers = [
        "id",
        "comment",
        "fileName",
        "sha256",
        "path",
        "certificateSigner",
        "createdAt",
        "createdByName",
        "type",
        "updatedAt",
    ]
    object_data = {}
    if result:
        object_data = create_item_output(result)

    readable_output = tableToMarkdown(
        name="Added Blocked Item:",
        t=object_data,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.BlockedItem",
        raw_response=result,
        outputs=object_data,
        readable_output=readable_output,
    )


def sophos_central_blocked_item_delete_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Delete an existing blocked item.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    result = client.delete_blocked_item(args.get("blocked_item_id", ""))
    readable_output = (
        f'Success deleting blocked item: {args.get("blocked_item_id", "")}'
    )
    outputs = {"deletedItemId": args.get("blocked_item_id", "")}
    if not result or not result.get("deleted"):
        readable_output = (
            f'Failed deleting blocked item: {args.get("blocked_item_id", "")}'
        )
        outputs = {}
    return CommandResults(
        raw_response=result,
        readable_output=readable_output,
        outputs=outputs,
        outputs_prefix="SophosCentral.DeletedBlockedItem",
    )


def sophos_central_scan_exclusion_list_command(
    client: Client, args: dict
) -> CommandResults:
    """
    List all scan exclusions.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    results = client.list_scan_exclusion(
        args.get("exclusion_type"),
        min(int(args.get("page_size", "")), 100),
        args.get("page"),
    )
    items = results.get("items")
    table_headers = ["id", "value", "type", "description", "comment", "scanMode"]
    outputs = []
    if items:
        for item in items:
            current_object_data = {field: item.get(field) for field in table_headers}
            outputs.append(current_object_data)

    readable_output = f'### Current page: {int(args.get("page", ""))}\n'
    readable_output += tableToMarkdown(
        name=f"Listed {len(outputs)} Scan Exclusions:",
        t=outputs,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.ScanExclusion",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def sophos_central_scan_exclusion_get_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Get a single scan exclusion.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    exclusion_id = args.get("exclusion_id", "")
    try:
        result = client.get_scan_exclusion(exclusion_id)
        table_headers = ["id", "value", "type", "description", "comment", "scanMode"]
        object_data = {}
        if result:
            object_data = {field: result.get(field) for field in table_headers}

        readable_output = tableToMarkdown(
            name="Found Scan Exclusion:",
            t=object_data,
            headers=table_headers,
            removeNull=True,
        )
        return CommandResults(
            outputs_key_field="id",
            outputs_prefix="SophosCentral.ScanExclusion",
            raw_response=result,
            outputs=object_data,
            readable_output=readable_output,
        )
    except DemistoException:
        return CommandResults(f"Unable to find exclusion: {exclusion_id}")


def sophos_central_scan_exclusion_add_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Get a single scan exclusion.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    result = client.add_scan_exclusion(
        args.get("comment"),
        args.get("scan_mode"),
        args.get("exclusion_type", ""),
        args.get("value", ""),
    )
    table_headers = ["id", "value", "type", "description", "comment", "scanMode"]
    object_data = {}
    if result:
        object_data = {field: result.get(field) for field in table_headers}

    readable_output = tableToMarkdown(
        name="Added Scan Exclusion:",
        t=object_data,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.ScanExclusion",
        raw_response=result,
        outputs=object_data,
        readable_output=readable_output,
    )


def sophos_central_scan_exclusion_update_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Update an existing. scan exclusion.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    exclusion_id = args.get("exclusion_id", "")
    try:
        result = client.update_scan_exclusion(
            args.get("comment"),
            args.get("scan_mode"),
            exclusion_id,
            args.get("value", ""),
        )
        table_headers = ["id", "value", "type", "description", "comment", "scanMode"]
        object_data = {}
        if result:
            object_data = {field: result.get(field) for field in table_headers}

        readable_output = tableToMarkdown(
            name="Updated Scan Exclusion:",
            t=object_data,
            headers=table_headers,
            removeNull=True,
        )
        return CommandResults(
            outputs_key_field="id",
            outputs_prefix="SophosCentral.ScanExclusion",
            raw_response=result,
            outputs=object_data,
            readable_output=readable_output,
        )
    except DemistoException:
        return CommandResults(f"Unable to update exclusion: {exclusion_id}")


def sophos_central_scan_exclusion_delete_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Delete an existing scan exclusion.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    result = client.delete_scan_exclusion(args.get("exclusion_id", ""))
    readable_output = f'Success deleting scan exclusion: {args.get("exclusion_id", "")}'
    outputs = {"deletedExclusionId": args.get("exclusion_id", "")}
    if not result or not result.get("deleted"):
        readable_output = (
            f'Failed deleting scan exclusion: {args.get("exclusion_id", "")}'
        )
        outputs = {}
    return CommandResults(
        raw_response=result,
        readable_output=readable_output,
        outputs=outputs,
        outputs_prefix="SophosCentral.DeletedScanExclusion",
    )


def sophos_central_exploit_mitigation_list_command(
    client: Client, args: dict
) -> CommandResults:
    """
    List all exploit mitigations.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    results = client.list_exploit_mitigation(
        args.get("mitigation_type"),
        min(int(args.get("page_size", "")), 100),
        args.get("page"),
        args.get("modified"),
    )
    items = results.get("items")
    table_headers = ["id", "name", "type", "category", "paths"]
    outputs = []
    if items:
        for item in items:
            current_object_data = {field: item.get(field) for field in table_headers}
            outputs.append(current_object_data)
    readable_output = f'### Current page: {int(args.get("page", ""))}\n'
    readable_output += tableToMarkdown(
        name=f"Listed {len(outputs)} Exploit Mitigations:",
        t=outputs,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.ExploitMitigation",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def sophos_central_exploit_mitigation_get_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Get a single scan exclusion.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    mitigation_id = args.get("mitigation_id", "")
    try:
        result = client.get_exploit_mitigation(mitigation_id)
        table_headers = ["id", "name", "type", "category", "paths"]
        object_data = {}
        if result:
            object_data = {field: result.get(field) for field in table_headers}

        readable_output = tableToMarkdown(
            name="Found Exploit Mitigation:",
            t=object_data,
            headers=table_headers,
            removeNull=True,
        )
        return CommandResults(
            outputs_key_field="id",
            outputs_prefix="SophosCentral.ExploitMitigation",
            raw_response=result,
            outputs=object_data,
            readable_output=readable_output,
        )
    except DemistoException:
        return CommandResults(f"Unable to find mitigation: {mitigation_id}")


def sophos_central_exploit_mitigation_add_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Add a new scan exclusion.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    result = client.add_exploit_mitigation(args.get("path", ""))
    table_headers = ["id", "name", "type", "category", "paths"]
    object_data = {}
    if result:
        object_data = {field: result.get(field) for field in table_headers}

    readable_output = tableToMarkdown(
        name="Added Exploit Mitigation:",
        t=object_data,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.ExploitMitigation",
        raw_response=result,
        outputs=object_data,
        readable_output=readable_output,
    )


def sophos_central_exploit_mitigation_update_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Add a new scan exclusion.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    mitigation_id = args.get("mitigation_id", "")
    try:
        result = client.update_exploit_mitigation(mitigation_id, args.get("path"))
        table_headers = ["id", "name", "type", "category", "paths"]
        object_data = {}
        if result:
            object_data = {field: result.get(field) for field in table_headers}

        readable_output = tableToMarkdown(
            name="Updated Exploit Mitigation:",
            t=object_data,
            headers=table_headers,
            removeNull=True,
        )
        return CommandResults(
            outputs_key_field="id",
            outputs_prefix="SophosCentral.ExploitMitigation",
            raw_response=result,
            outputs=object_data,
            readable_output=readable_output,
        )
    except DemistoException:
        return CommandResults(f"Unable to update mitigation: {mitigation_id}")


def sophos_central_exploit_mitigation_delete_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Delete an existing exploit mitigation.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    result = client.delete_exploit_mitigation(args.get("mitigation_id", ""))
    readable_output = (
        f'Success deleting exploit mitigation: {args.get("mitigation_id", "")}'
    )
    outputs = {"deletedMitigationId": args.get("mitigation_id", "")}
    if not result or not result.get("deleted"):
        readable_output = (
            f'Failed deleting exploit mitigation: {args.get("mitigation_id", "")}'
        )
        outputs = {}
    return CommandResults(
        raw_response=result,
        readable_output=readable_output,
        outputs=outputs,
        outputs_prefix="SophosCentral.DeletedExploitMitigation",
    )


def create_detected_exploit_output(item: Dict) -> Dict:
    """
    Create the complete output dictionary for a detected exploit.

    Args:
        item (dict(str)): A source dictionary from the API response.

    Returns:
        object_data (dict(str)): The output dictionary.
    """
    data_fields = [
        "id",
        "thumbprint",
        "count",
        "description",
        "firstSeenAt",
        "lastSeenAt",
    ]
    outputs = {field: item.get(field) for field in data_fields}

    last_user = item.get("lastUser")
    if last_user:
        outputs["lastUserName"] = last_user.get("name")
        outputs["lastUserId"] = last_user.get("id")

    last_endpoint = item.get("lastEndpoint")
    if last_endpoint:
        outputs["lastEndpointHostname"] = last_endpoint.get("hostname")
        outputs["lastEndpointId"] = last_endpoint.get("id")

    return outputs


def sophos_central_detected_exploit_list_command(
    client: Client, args: dict
) -> CommandResults:
    """
    List all detected exploits.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    results = client.list_detected_exploit(
        min(int(args.get("page_size", "")), 100),
        args.get("page"),
        args.get("thumbprint_not_in"),
    )
    items = results.get("items")
    table_headers = [
        "id",
        "description",
        "thumbprint",
        "count",
        "firstSeenAt",
        "lastSeenAt",
    ]
    outputs = []
    if items:
        for item in items:
            current_object_data = create_detected_exploit_output(item)
            outputs.append(current_object_data)
    readable_output = f'### Current page: {int(args.get("page", ""))}\n'
    readable_output += tableToMarkdown(
        name=f"Listed {len(outputs)} Detected Exploits:",
        t=outputs,
        headers=table_headers,
        removeNull=True,
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.DetectedExploit",
        raw_response=results,
        outputs=outputs,
        readable_output=readable_output,
    )


def sophos_central_detected_exploit_get_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Get a single detected exploit.

    Args:
        client (Client): Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    detected_exploit_id = args.get("detected_exploit_id", "")
    try:
        result = client.get_detected_exploit(detected_exploit_id)
        table_headers = [
            "id",
            "description",
            "thumbprint",
            "count",
            "firstSeenAt",
            "lastSeenAt",
        ]
        object_data = {}
        if result:
            object_data = create_detected_exploit_output(result)

        readable_output = tableToMarkdown(
            name="Found Detected Exploit:",
            t=object_data,
            headers=table_headers,
            removeNull=True,
        )
        return CommandResults(
            outputs_key_field="id",
            outputs_prefix="SophosCentral.DetectedExploit",
            raw_response=result,
            outputs=object_data,
            readable_output=readable_output,
        )
    except DemistoException:
        return CommandResults(f"Unable to find exploit: {detected_exploit_id}")


def sophos_central_isolate_endpoint_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Initiate isolation request on the given endpoint(s).

    Args:
        client (Client):  Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    result = client.isolate_endpoint(
        argToList(args.get("endpoint_id")), args.get("comment", "")
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.EndpointIsolation",
        readable_output="Endpoint(s) isolated successfully.",
        outputs=result,
        raw_response=result,
    )


def sophos_central_deisolate_endpoint_command(
    client: Client, args: dict
) -> CommandResults:
    """
    Initiate de-isolation request on the given endpoint(s).

    Args:
        client (Client):  Sophos Central API client.
        args (dict): All command arguments

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    result = client.deisolate_endpoint(
        argToList(args.get("endpoint_id")), args.get("comment", "")
    )
    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="SophosCentral.EndpointIsolation",
        readable_output="Endpoint(s) de-isolated successfully.",
        outputs=result,
        raw_response=result,
    )


def fetch_incidents(
    client: Client,
    last_run: Dict[str, int],
    first_fetch_time: str,
    fetch_severity: Optional[List[str]],
    fetch_category: Optional[List[str]],
    max_fetch: Optional[int],
) -> Tuple[Dict[str, int], List[dict]]:
    """
    Fetch incidents (alerts) each minute (by default).

    Args:
        client (Client): Sophos Central Client.
        last_run (dict): Dict with last_fetch object,
                                  saving the last fetch time(in millisecond timestamp).
        first_fetch_time (dict): Dict with first fetch time in str (ex: 3 days ago).
        fetch_severity (list(str)): Severity to fetch.
        fetch_category (list(str)): Category(s) to fetch.
        max_fetch (int): Max number of alerts to fetch.
    Returns:
        Tuple of next_run (millisecond timestamp) and the incidents list
    """
    last_fetch_timestamp = last_run.get("last_fetch", None)

    if last_fetch_timestamp:
        last_fetch_date = datetime.fromtimestamp(last_fetch_timestamp / 1000)
        last_fetch = last_fetch_date
    else:
        first_fetch_date = dateparser.parse(first_fetch_time).replace(tzinfo=None)
        last_fetch = first_fetch_date
    incidents = []
    next_run = last_fetch
    alerts = client.search_alert(
        last_fetch.isoformat(timespec="milliseconds"),
        None,
        None,
        fetch_category,
        None,
        fetch_severity,
        None,
        max_fetch,
    )
    data_fields = [
        "id",
        "description",
        "severity",
        "raisedAt",
        "allowedActions",
        "managedAgentId",
        "category",
        "type",
    ]
    for alert in alerts.get("items", []):
        alert = create_alert_output(client, alert, data_fields)
        alert_created_time = alert.get("raisedAt")
        alert_id = alert.get("id")
        incident = {
            "name": f"Sophos Central Alert {alert_id}",
            "occurred": alert_created_time,
            "rawJSON": json.dumps(alert),
        }
        incidents.append(incident)
    if incidents:
        last_incident_time = incidents[-1].get("occurred", "")
        next_run = datetime.strptime(last_incident_time, DATE_FORMAT)
    next_run += timedelta(milliseconds=1)
    next_run_timestamp = int(datetime.timestamp(next_run) * 1000)
    return {"last_fetch": next_run_timestamp}, incidents


def test_module(client: Client) -> str:
    """
    Test the validity of the connection and the.

    Args:
        client (Client): Sophos Central client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.list_alert(1)
        return "ok"
    except DemistoException as exception:
        if "Name does not resolve" in str(exception):
            return "Wrong API server region found."
        raise DemistoException(exception)


def retrieve_jwt_token(
    client_id: str, client_secret: str, integration_context: Dict
) -> str:
    """
    Get the JWT token from the integration context or create a new one.

    Args:
        client_id (str): Sophos Central client ID.
        client_secret (str): Sophoes Central client secret.
        integration_context (dict): Integration context from Demisto.

    Returns:
        bearer_token (str): JWT token for required commands.
    """
    bearer_token = integration_context.get("bearer_token", "")
    valid_until = integration_context.get("valid_until", "")
    time_now = int(time.time())
    if bearer_token and valid_until:
        if time_now < int(valid_until):
            return bearer_token
    bearer_token_dict = Client.get_jwt_token_from_api(client_id, client_secret)
    if bearer_token_dict:
        bearer_token = str(bearer_token_dict.get("access_token", ""))
    Client._update_integration_context(
        {"bearer_token": bearer_token, "valid_until": time_now + 600}
    )
    return bearer_token


def creds_changed(context: dict, client_id: str) -> bool:
    """
    Check whether the credentials were changed by the user.

    Args:
        context (dict): Integration context from Demisto.
        client_id (str): Sophos Central client ID.

    Returns:
        creds_changed (bool): True if credentials were changed, False otherwise.
    """
    return context.get("client_id", "") != client_id


def invalidate_context(client_id: str) -> None:
    """
    Invalidate the Demisto integration context and set new client id.

    Args:
        client_id (str): Newly provided Sophos Central client ID.
    """
    set_integration_context({"client_id": client_id})


def main():
    """Parse and validate integration params."""
    params = demisto.params()
    sophos_id = params.get("credentials", {}).get("identifier", "")
    sophos_secret = params.get("credentials", {}).get("password", "")

    # if credentials were changed by the user, stored cache/context should be invalidated
    # and new client ID should be stored in context.
    if creds_changed(get_integration_context(), sophos_id):
        invalidate_context(sophos_id)

    fetch_severity = params.get("fetch_severity", [])
    fetch_category = params.get("fetch_category", [])
    max_fetch = int(params.get("max_fetch", "50"))
    first_fetch_time = params.get("first_fetch", "3 days").strip()
    proxy = params.get("proxy", False)
    tenant_id = params.get("tenant_id", "")
    command = demisto.command()
    demisto.info(f"Command being called is {command}")
    client: Optional[Client] = None
    commands = {
        "sophos-central-alert-list": sophos_central_alert_list_command,
        "sophos-central-alert-get": sophos_central_alert_get_command,
        "sophos-central-alert-action": sophos_central_alert_action_command,
        "sophos-central-alert-search": sophos_central_alert_search_command,
        "sophos-central-endpoint-list": sophos_central_endpoint_list_command,
        "sophos-central-endpoint-scan": sophos_central_endpoint_scan_command,
        "sophos-central-endpoint-tamper-get": sophos_central_endpoint_tamper_get_command,
        "sophos-central-endpoint-tamper-update": sophos_central_endpoint_tamper_update_command,
        "sophos-central-allowed-item-list": sophos_central_allowed_item_list_command,
        "sophos-central-allowed-item-get": sophos_central_allowed_item_get_command,
        "sophos-central-allowed-item-add": sophos_central_allowed_item_add_command,
        "sophos-central-allowed-item-update": sophos_central_allowed_item_update_command,
        "sophos-central-allowed-item-delete": sophos_central_allowed_item_delete_command,
        "sophos-central-blocked-item-list": sophos_central_blocked_item_list_command,
        "sophos-central-blocked-item-get": sophos_central_blocked_item_get_command,
        "sophos-central-blocked-item-add": sophos_central_blocked_item_add_command,
        "sophos-central-blocked-item-delete": sophos_central_blocked_item_delete_command,
        "sophos-central-scan-exclusion-list": sophos_central_scan_exclusion_list_command,
        "sophos-central-scan-exclusion-get": sophos_central_scan_exclusion_get_command,
        "sophos-central-scan-exclusion-add": sophos_central_scan_exclusion_add_command,
        "sophos-central-scan-exclusion-update": sophos_central_scan_exclusion_update_command,
        "sophos-central-scan-exclusion-delete": sophos_central_scan_exclusion_delete_command,
        "sophos-central-exploit-mitigation-list": sophos_central_exploit_mitigation_list_command,
        "sophos-central-exploit-mitigation-get": sophos_central_exploit_mitigation_get_command,
        "sophos-central-exploit-mitigation-add": sophos_central_exploit_mitigation_add_command,
        "sophos-central-exploit-mitigation-update": sophos_central_exploit_mitigation_update_command,
        "sophos-central-exploit-mitigation-delete": sophos_central_exploit_mitigation_delete_command,
        "sophos-central-detected-exploit-list": sophos_central_detected_exploit_list_command,
        "sophos-central-detected-exploit-get": sophos_central_detected_exploit_get_command,
        "sophos-central-isolate-endpoint": sophos_central_isolate_endpoint_command,
        "sophos-central-deisolate-endpoint": sophos_central_deisolate_endpoint_command,
    }
    try:
        bearer_token = retrieve_jwt_token(
            sophos_id, sophos_secret, get_integration_context()
        )
        client = Client(
            bearer_token=bearer_token,
            verify=True,
            client_id=sophos_id,
            client_secret=sophos_secret,
            proxy=proxy,
            integration_context=get_integration_context(),
            tenant_id=tenant_id,
        )
        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                fetch_severity=fetch_severity,
                fetch_category=fetch_category,
                max_fetch=max_fetch,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands:
            return_results(commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'The "{command}" command was not implemented.')

    except Exception as e:
        if "Error parsing the query params or request body" in str(e):
            error_string = "Make sure the arguments are correctly formatted."
        elif "Unauthorized" in str(e):
            error_string = "Wrong credentials (ID and / or secret) given."
        elif "SSL Certificate Verification Failed" in str(e):
            error_string = (
                "SSL Certificate Verification Failed: Make sure that "
                "Sophos Central API servers have valid SSL certificate."
            )
        else:
            error_string = str(e)
        return_error(f"Failed to execute {command} command. Error: {error_string}")
    finally:
        if client:
            client._update_integration_context(client.integration_context)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

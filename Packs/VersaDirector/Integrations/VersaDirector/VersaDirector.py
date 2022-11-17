import demistomock as demisto
from CommonServerPython import *  # noqa #! pylint: disable=unused-wildcard-import
from typing import Dict, Any, Optional
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

PORT_CREDENTIALS = "9182"
PORT_AUTH = "9183"
DEFAULT_TIMEOUT = 600
DEFAULT_INTERVAL = 10
OAUTH_CLIENT = "XSOAR-OAuth-client"
VENDOR_NAME = "VersaDirector"
ALREADY_EXISTS_MSG = "Object already exists."

# The credentials below are public therefore they are not a secret
CLIENT_ID = "voae_rest"
CLIENT_CREDENTIALS = "asrevnet_123"


# Error messages:
AUTH_EXISTING_TOKEN = "Auth process failed. Existing Token found with the matching name."
AUTH_EXCEEDED_MAXIMUM = "Auth process failed. Possibly exceeded maximum number of allowed tokens."
AUTH_INVALID_CREDENTIALS = "Auth process failed. invalid credentials returned from api."
BASIC_CREDENTIALS_COULD_NOT_START = (
    "Auth process could not start. To run vd-auth-start command,"
    + " please enter Username and password parameters in instance configuration."
)
CLIENT_CREDENTIALS_COULD_NOT_START = (
    "Auth process could not start, missing client_id and client_secret command arguments or integration parameters."
)
AUTH_INVALID_ACCESS_TOKEN = (
    "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method"
)
AUTH_BAD_CREDENTIALS = "Auth process failed. Please check client_id and client_secret validity."

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(
        self,
        server_url,
        verify,
        proxy,
        headers,
        auth,
        organization_params,
        client_id_param,
        client_secret_param,
    ):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)
        self.organization_params = organization_params
        self.client_id_param = client_id_param
        self.client_secret_param = client_secret_param

    # HEADING: """ REQUEST FUNCTIONS """

    def test_organization_name_request(self, organization_name: str):
        try:
            self._http_request(
                "GET",
                url_suffix=f"nextgen/deviceGroup?organization={organization_name}",
                headers=self._headers,
            )
        except DemistoException as e:
            raise DemistoException("Organization Name parameter OR arguments is invalid.", exception=e.exception)

    def access_token_request(self, username: str, password: str, client_id: str, client_secret: str):
        request_body = {
            "client_id": f"{client_id}",
            "client_secret": f"{client_secret}",
            "username": f"{username}",
            "password": f"{password}",
            "grant_type": "password",
        }

        response = self._http_request(
            "POST",
            url_suffix="auth/token",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201),
        )
        return response

    def refresh_token_request(self, client_id: str, client_secret: str, refresh_token: str):
        request_body = {
            "client_id": f"{client_id}",
            "client_secret": f"{client_secret}",
            "grant_type": "refresh_token",
            "refresh_token": f"{refresh_token}",
        }

        response = self._http_request(
            "POST",
            url_suffix="auth/refresh",
            headers=self._headers,
            json_data=request_body,
        )

        return response

    def auth_credentials_request(self, access_token: str, token_name: str, token_description: str):
        request_body = {
            "name": token_name,
            "description": token_description,
            "expires_at": "",
            "client_secret_expires_at": "",
            "max_access_tokens": 10,
            "max_access_tokens_per_user": 99,
            "access_token_validity": 900,
            "refresh_token_validity": 86400,
            "allowed_grant_types": ["password", "refresh_token", "client_credentials"],
            "allowed_source_client_address": {
                "source_type": "ANYWHERE",
                "ip_address_list": [],
            },
            "enabled": "true",
            "software_id": "",
            "software_version": "",
            "contacts": [],
            "redirect_uris": [],
        }
        self._headers = {"Authorization": f"Bearer {access_token}"}
        self._auth = None
        response = self._http_request(
            "POST",
            url_suffix="auth/admin/clients",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201),
        )

        return response

    def appliance_list_request(self, offset: Optional[int] = None, limit: Optional[int] = None):
        params = assign_params(offset=offset, limit=limit)

        response = self._http_request(
            "GET",
            url_suffix="vnms/cloud/systems/getAllAppliancesBasicDetails",
            params=params,
            headers=self._headers,
        )

        return response

    def organization_list_request(self, offset: Optional[int] = None, limit: Optional[int] = None):
        params = assign_params(limit=limit, offset=offset)

        response = self._http_request(
            "GET",
            url_suffix="nextgen/organization",
            params=params,
            headers=self._headers,
        )

        return response

    def appliances_list_by_organization_request(
        self, organization: str, offset: Optional[int] = None, limit: Optional[int] = None
    ):
        params = assign_params(offset=offset, limit=limit)

        response = self._http_request(
            "GET",
            url_suffix=f"vnms/appliance/filter/{organization}",
            params=params,
            headers=self._headers,
        )

        return response

    def appliances_group_list_by_organization_request(
        self, organization: str, offset: Optional[int] = None, limit: Optional[int] = None
    ):
        params = assign_params(organization_name=organization, offset=offset, limit=limit)
        response = self._http_request(
            "GET",
            url_suffix="nextgen/deviceGroup",
            params=params,
            headers=self._headers,
        )

        return response

    def appliances_list_by_device_group_request(
        self,
        device_group: str,
        template_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)

        response = self._http_request(
            "GET",
            url_suffix=f"nextgen/deviceGroup/{device_group}/template/{template_name}",
            params=params,
            headers=self._headers,
        )

        return response

    def template_list_by_organization_request(
        self,
        organization: Optional[str] = None,
        type: Optional[list] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(organization=organization, type=type, offset=offset, limit=limit)

        response = self._http_request(
            "GET",
            url_suffix="vnms/template/metadata",
            params=params,
            headers=self._headers,
        )

        return response

    def template_list_by_datastore_request(self, organization: str, offset: Optional[int] = None, limit: Optional[int] = None):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/template/{organization}-DataStore/config/orgs/org",
            params=params,
            headers=headers,
            resp_type="xml",
        )

        return response

    def application_service_template_list_request(
        self,
        organization: Optional[str] = None,
        keyword: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(organization=organization, searchKeyword=keyword, offset=offset, limit=limit)
        response = self._http_request(
            "GET",
            url_suffix="/nextgen/applicationServiceTemplate",
            params=params,
            headers=self._headers,
        )

        return response

    def template_change_commit_request(self, template_name: str, appliances: list, mode: str, reboot: str):
        request_body = {
            "versanms.templateRequest": {
                "device-list": appliances,
                "mode": f"{mode}",
                "reboot": f"{reboot}",
            }
        }

        response = self._http_request(
            "POST",
            url_suffix=f"vnms/template/applyTemplate/{template_name}/devices",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(
                200,
            ),  # ok_codes default value is insufficient because this http request should only accept status code 200.
            resp_type="response",
        )
        return response

    def template_change_commit_polling_request(self, task_id: str):
        response = self._http_request(
            "GET",
            url_suffix=f"/vnms/tasks/task/{task_id}",
            headers=self._headers,
        )
        return response

    def template_custom_url_category_list_request(
        self,
        organization: str,
        template_name: str,
        url_category_name: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(url_category_name=url_category_name, offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"/api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + "/url-filtering/user-defined-url-categories/url-category",
            params=params,
            headers=headers,
            resp_type="xml",
        )

        return response

    def template_custom_url_category_create_request(
        self,
        organization: str,
        template_name: str,
        url_category_name: str,
        description: str,
        confidence: str,
        urls: list,
        url_reputation: list,
        patterns: list,
        pattern_reputation: list,
    ):

        request_body = create_custom_url_category_request_body(
            url_category_name,
            description,
            confidence,
            urls,
            url_reputation,
            patterns,
            pattern_reputation,
        )

        response = self._http_request(
            "POST",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/"
            + f"{organization}/url-filtering/user-defined-url-categories",
            headers=self._headers,
            json_data=request_body,
            resp_type="response",
            ok_codes=(200, 201),
        )

        return response

    def template_custom_url_category_edit_request(
        self,
        organization: str,
        template_name: str,
        url_category_name: str,
        description: str,
        confidence: str,
        urls: list,
        url_reputation: list,
        patterns: list,
        pattern_reputation: list,
    ):
        request_body = create_custom_url_category_request_body(
            url_category_name,
            description,
            confidence,
            urls,
            url_reputation,
            patterns,
            pattern_reputation,
        )

        response = self._http_request(
            "PUT",
            url_suffix=f"/api/config/devices/template/{template_name}/config/orgs/org-services/"
            + f"{organization}/url-filtering/user-defined-url-categories/url-category/{url_category_name}",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201, 204),
            return_empty_response=True,
        )

        return response, request_body

    def template_custom_url_category_delete_request(self, organization: str, template_name: str, url_category_name: str):
        response = self._http_request(
            "DELETE",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/"
            + f"{organization}/url-filtering/user-defined-url-categories/url-category/{url_category_name}",
            headers=self._headers,
            ok_codes=(200, 201, 204),
            return_empty_response=True,
        )

        return response

    def appliance_custom_url_category_list_request(
        self,
        organization: str,
        appliance_name: str,
        url_category_name: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)

        suffix = (
            f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + "/url-filtering/user-defined-url-categories/url-category"
        )
        if url_category_name:
            suffix += f"/{url_category_name}"

        headers = self._headers
        headers["Content-Type"] = "application/xml"

        response = self._http_request("GET", url_suffix=suffix, params=params, headers=headers, resp_type="xml")
        return response

    def appliance_custom_url_category_create_request(
        self,
        organization: str,
        appliance_name: str,
        url_category_name: str,
        description: str,
        confidence: str,
        urls: list,
        url_reputation: list,
        patterns: list,
        pattern_reputation: list,
    ):
        request_body = create_custom_url_category_request_body(
            url_category_name,
            description,
            confidence,
            urls,
            url_reputation,
            patterns,
            pattern_reputation,
        )

        response = self._http_request(
            "POST",
            url_suffix=f"/api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + "/url-filtering/user-defined-url-categories",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201, 204),
            resp_type="response",
        )

        return response, request_body

    def appliance_custom_url_category_edit_request(
        self,
        organization: str,
        appliance_name: str,
        url_category_name: str,
        description: str,
        confidence: str,
        urls: list,
        url_reputation: list,
        patterns: list,
        pattern_reputation: list,
    ):
        request_body = create_custom_url_category_request_body(
            url_category_name,
            description,
            confidence,
            urls,
            url_reputation,
            patterns,
            pattern_reputation,
        )

        response = self._http_request(
            "PUT",
            url_suffix=f"/api/config/devices/template/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/url-filtering/user-defined-url-categories/url-category/{url_category_name}",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 204),
            return_empty_response=True,
        )

        return response, request_body

    def appliance_custom_url_category_delete_request(self, organization: str, appliance_name: str, url_category_name: str):
        response = self._http_request(
            "DELETE",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/url-filtering/user-defined-url-categories/url-category/{url_category_name}",
            headers=self._headers,
            ok_codes=(200, 204),
            return_empty_response=True,
        )

        return response

    def template_access_policy_list_request(
        self,
        organization: str,
        template_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + "/security/access-policies/access-policy-group",
            params=params,
            headers=headers,
            resp_type="xml",
        )
        return response

    def template_access_policy_rule_list_request(
        self,
        organization: str,
        template_name: str,
        access_policy_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + f"/security/access-policies/access-policy-group/{access_policy_name}/rules/access-policy",
            params=params,
            headers=headers,
            resp_type="xml",
        )
        return response

    def template_access_policy_rule_create_request(
        self,
        organization: str,
        template_name: str,
        access_policy_name: str,
        rule_name: str,
        description: str,
        tags: list,
        source_address_objects: list,
        destination_address_objects: list,
        url_reputation: list,
        predefined_application: list,
        user_defined_application: list,
        custom_url_categories: list,
    ):

        request_body = create_access_policy_rule_request_body(
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            predefined_application,
            user_defined_application,
            custom_url_categories,
        )

        response = self._http_request(
            "POST",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + f"/security/access-policies/access-policy-group/{access_policy_name}/rules",
            headers=self._headers,
            json_data=request_body,
            resp_type="response",
            ok_codes=(200, 201, 204),
        )

        return response, request_body

    def template_access_policy_rule_edit_request(
        self,
        organization: str,
        template_name: str,
        access_policy_name: str,
        rule_name: str,
        description: str,
        tags: list,
        source_address_objects: list,
        destination_address_objects: list,
        url_reputation: list,
        predefined_application: list,
        user_defined_application: list,
        custom_url_categories: list,
    ):

        request_body = create_access_policy_rule_request_body(
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            predefined_application,
            user_defined_application,
            custom_url_categories,
        )

        response = self._http_request(
            "PUT",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + f"/security/access-policies/access-policy-group/{access_policy_name}/rules/access-policy/{rule_name}",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201, 204),
            return_empty_response=True,
        )
        return response, request_body

    def template_access_policy_rule_delete_request(
        self,
        organization: str,
        template_name: str,
        access_policy_name: str,
        rule_name: str,
    ):
        response = self._http_request(
            "DELETE",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + f"/security/access-policies/access-policy-group/{access_policy_name}/rules/access-policy/{rule_name}",
            headers=self._headers,
            ok_codes=(200, 201, 204),
            return_empty_response=True,
        )
        return response

    def appliance_access_policy_list_request(
        self,
        organization: str,
        appliance_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + "/security/access-policies/access-policy-group",
            params=params,
            headers=headers,
            ok_codes=(200, 201),
            resp_type="xml",
        )
        return response

    def appliance_access_policy_rule_list_request(
        self,
        organization: str,
        appliance_name: str,
        access_policy_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/security/access-policies/access-policy-group/{access_policy_name}/rules/access-policy",
            params=params,
            headers=headers,
            resp_type="xml",
        )
        return response

    def appliance_access_policy_rule_create_request(
        self,
        organization: str,
        appliance_name: str,
        access_policy_name: str,
        rule_name: str,
        description: str,
        tags: list,
        source_address_objects: list,
        destination_address_objects: list,
        url_reputation: list,
        predefined_application: list,
        user_defined_application: list,
        custom_url_categories: list,
    ):

        request_body = create_access_policy_rule_request_body(
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            predefined_application,
            user_defined_application,
            custom_url_categories,
        )

        response = self._http_request(
            "POST",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/security/access-policies/access-policy-group/{access_policy_name}/rules",
            headers=self._headers,
            json_data=request_body,
            resp_type="response",
            ok_codes=(200, 201, 204),
        )

        return response, request_body

    def appliance_access_policy_rule_edit_request(
        self,
        organization: str,
        appliance_name: str,
        access_policy_name: str,
        rule_name: str,
        description: str,
        tags: list,
        source_address_objects: list,
        destination_address_objects: list,
        url_reputation: list,
        predefined_application: list,
        user_defined_application: list,
        custom_url_categories: list,
    ):

        request_body = create_access_policy_rule_request_body(
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            predefined_application,
            user_defined_application,
            custom_url_categories,
        )

        response = self._http_request(
            "PUT",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/security/access-policies/access-policy-group/{access_policy_name}/rules/access-policy/{rule_name}",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201, 204),
            return_empty_response=True,
        )
        return response, request_body

    def appliance_access_policy_rule_delete_request(
        self,
        organization: str,
        appliance_name: str,
        access_policy_name: str,
        rule_name: str,
    ):
        response = self._http_request(
            "DELETE",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/security/access-policies/access-policy-group/{access_policy_name}/rules/access-policy/{rule_name}",
            headers=self._headers,
            ok_codes=(200, 201, 204),
            return_empty_response=True,
        )
        return response

    def template_sdwan_policy_list_request(
        self,
        organization: str,
        template_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + "/sd-wan/policies/sdwan-policy-group",
            params=params,
            headers=headers,
            resp_type="xml",
        )
        return response

    def template_sdwan_policy_rule_request(
        self,
        organization: str,
        template_name: str,
        sdwan_policy_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + f"/sd-wan/policies/sdwan-policy-group/{sdwan_policy_name}/rules/rule",
            params=params,
            headers=headers,
            resp_type="xml",
        )
        return response

    def template_sdwan_policy_rule_create_request(
        self,
        organization: str,
        template_name: str,
        sdwan_policy_name: str,
        rule_name: str,
        description: str,
        tags: list,
        source_address_objects: list,
        destination_address_objects: list,
        url_reputation: list,
        custom_url_categories: list,
        forwarding_action: str,
        nexthop_ip: str,
        routing_instance: str,
        forwarding_profile: str,
        predefined_application: list,
        user_defined_application: list,
    ):

        request_body = create_sdwan_policy_rule_request_body(
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            custom_url_categories,
            forwarding_action,
            nexthop_ip,
            routing_instance,
            forwarding_profile,
            predefined_application,
            user_defined_application,
        )

        response = self._http_request(
            "POST",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + f"/sd-wan/policies/sdwan-policy-group/{sdwan_policy_name}/rules",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201),
            resp_type="response",
        )

        return response, request_body

    def template_sdwan_policy_rule_edit_request(
        self,
        organization: str,
        template_name: str,
        sdwan_policy_name: str,
        rule_name: str,
        description: str,
        tags: list,
        rule_disable: str,
        source_address_objects: list,
        destination_address_objects: list,
        url_reputation: list,
        custom_url_categories: list,
        forwarding_action: str,
        nexthop_ip: str,
        routing_instance: str,
        forwarding_profile: str,
        predefined_application: list,
        user_defined_application: list,
    ):

        request_body = create_sdwan_policy_rule_request_body(
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            custom_url_categories,
            forwarding_action,
            nexthop_ip,
            routing_instance,
            forwarding_profile,
            predefined_application,
            user_defined_application,
            rule_disable,
        )

        response = self._http_request(
            "PUT",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + f"/sd-wan/policies/sdwan-policy-group/{sdwan_policy_name}/rules/rule/{rule_name}",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201, 204),
            return_empty_response=True,
        )

        return response, request_body

    def template_sdwan_policy_rule_delete_request(
        self,
        organization: str,
        template_name: str,
        sdwan_policy_name: str,
        rule_name: str,
    ):
        response = self._http_request(
            "DELETE",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + f"/sd-wan/policies/sdwan-policy-group/{sdwan_policy_name}/rules/rule/{rule_name}",
            headers=self._headers,
            ok_codes=(200, 201, 204),
            return_empty_response=True,
        )
        return response

    def appliance_sdwan_policy_list_request(
        self,
        organization: str,
        appliance_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + "/sd-wan/policies/sdwan-policy-group",
            params=params,
            headers=headers,
            resp_type="xml",
        )
        return response

    def appliance_sdwan_policy_rule_list_request(
        self,
        organization: str,
        appliance_name: str,
        sdwan_policy_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/sd-wan/policies/sdwan-policy-group/{sdwan_policy_name}/rules/rule",
            params=params,
            headers=headers,
            resp_type="xml",
        )
        return response

    def appliance_sdwan_policy_rule_create_request(
        self,
        organization: str,
        appliance_name: str,
        sdwan_policy_name: str,
        rule_name: str,
        description: str,
        tags: list,
        source_address_objects: list,
        destination_address_objects: list,
        url_reputation: list,
        custom_url_categories: list,
        forwarding_action: str,
        nexthop_ip: str,
        routing_instance: str,
        forwarding_profile: str,
        predefined_application: list,
        user_defined_application: list,
    ):

        request_body = create_sdwan_policy_rule_request_body(
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            custom_url_categories,
            forwarding_action,
            nexthop_ip,
            routing_instance,
            forwarding_profile,
            predefined_application,
            user_defined_application,
        )

        response = self._http_request(
            "POST",
            url_suffix=f"/api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/sd-wan/policies/sdwan-policy-group/{sdwan_policy_name}/rules",
            headers=self._headers,
            resp_type="response",
            json_data=request_body,
            ok_codes=(200, 201),
        )
        return response, request_body

    def appliance_sdwan_policy_rule_edit_request(
        self,
        organization: str,
        appliance_name: str,
        sdwan_policy_name: str,
        rule_name: str,
        description: str,
        tags: list,
        rule_disable: str,
        source_address_objects: list,
        destination_address_objects: list,
        url_reputation: list,
        custom_url_categories: list,
        forwarding_action: str,
        nexthop_ip: str,
        routing_instance: str,
        forwarding_profile: str,
        predefined_application: list,
        user_defined_application: list,
    ):

        request_body = create_sdwan_policy_rule_request_body(
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            custom_url_categories,
            forwarding_action,
            nexthop_ip,
            routing_instance,
            forwarding_profile,
            predefined_application,
            user_defined_application,
            rule_disable,
        )

        response = self._http_request(
            "PUT",
            url_suffix=f"/api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/sd-wan/policies/sdwan-policy-group/{sdwan_policy_name}/rules/{rule_name}",
            headers=self._headers,
            resp_type="response",
            json_data=request_body,
            ok_codes=(200, 201),
        )
        return response, request_body

    def appliance_sdwan_policy_rule_delete_request(
        self,
        organization: str,
        appliance_name: str,
        sdwan_policy_name: str,
        rule_name: str,
    ):
        response = self._http_request(
            "DELETE",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/sd-wan/policies/sdwan-policy-group/{sdwan_policy_name}/rules/rule/{rule_name}",
            headers=self._headers,
            resp_type="response",
            ok_codes=(200, 204),
            return_empty_response=True,
        )
        return response

    def template_address_object_list_request(
        self,
        organization: str,
        template_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/"
            + f"{organization}/objects/addresses/address",
            params=params,
            headers=headers,
            resp_type="xml",
        )
        return response

    def template_address_object_create_request(
        self,
        organization: str,
        template_name: str,
        object_name: str,
        description: str,
        tags: list,
        address_object_type: str,
        object_value: str,
    ):
        request_body = create_address_object_request_body(object_name, description, tags, address_object_type, object_value)

        response = self._http_request(
            "POST",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}/objects/addresses",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201),
            resp_type="response",
        )

        return response, request_body

    def template_address_object_edit_request(
        self,
        organization: str,
        template_name: str,
        object_name: str,
        description: str,
        tags: list,
        address_object_type: str,
        object_value: str,
    ):

        request_body = create_address_object_request_body(object_name, description, tags, address_object_type, object_value)

        response = self._http_request(
            "PUT",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + f"/objects/addresses/address/{object_name}",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201, 204),
            resp_type="response",
            return_empty_response=True,
        )

        return response, request_body

    def template_address_object_delete_request(self, organization: str, template_name: str, object_name: str):
        response = self._http_request(
            "DELETE",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + f"/objects/addresses/address/{object_name}",
            headers=self._headers,
            ok_codes=(200, 201, 204),
            resp_type="response",
            return_empty_response=True,
        )

        return response

    def appliance_address_object_list_request(
        self,
        organization: str,
        appliance_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + "/objects/addresses/address",
            params=params,
            headers=headers,
            resp_type="xml",
        )
        return response

    def appliance_address_object_create_request(
        self,
        organization: str,
        appliance_name: str,
        object_name: str,
        description: str,
        tags: list,
        address_object_type: str,
        object_value: str,
    ):
        request_body = create_address_object_request_body(object_name, description, tags, address_object_type, object_value)

        response = self._http_request(
            "POST",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}/objects/addresses",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201),
            resp_type="response",
        )

        return response, request_body

    def appliance_address_object_edit_request(
        self,
        organization: str,
        appliance_name: str,
        object_name: str,
        description: str,
        tags: list,
        address_object_type: str,
        object_value: str,
    ):

        request_body = create_address_object_request_body(object_name, description, tags, address_object_type, object_value)

        response = self._http_request(
            "PUT",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/objects/addresses/address/{object_name}",
            headers=self._headers,
            json_data=request_body,
            ok_codes=(200, 201, 204),
            resp_type="response",
            return_empty_response=True,
        )

        return response, request_body

    def appliance_address_object_delete_request(self, organization: str, appliance_name: str, object_name: str):
        response = self._http_request(
            "DELETE",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + f"/objects/addresses/address/{object_name}",
            headers=self._headers,
            ok_codes=(200, 201, 204),
            resp_type="response",
            return_empty_response=True,
        )

        return response

    def template_user_defined_application_list_request(
        self,
        organization: str,
        template_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + "/application-identification/user-defined-applications/user-defined-application",
            params=params,
            headers=headers,
            resp_type="xml",
            ok_codes=(200, 201, 204),
        )
        return response

    def appliance_user_defined_application_list_request(
        self,
        organization: str,
        appliance_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + "/application-identification/user-defined-applications/user-defined-application",
            params=params,
            headers=headers,
            resp_type="xml",
            ok_codes=(200, 201),
        )
        return response

    def template_user_modified_application_list_request(
        self,
        organization: str,
        template_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/template/{template_name}/config/orgs/org-services/{organization}"
            + "/application-identification/application-specific-options/app-specific-option-list",
            params=params,
            headers=headers,
            resp_type="xml",
            ok_codes=(200, 201),
        )
        return response

    def appliance_user_modified_application_list_request(
        self,
        organization: str,
        appliance_name: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers
        headers["Content-Type"] = "application/xml"
        response = self._http_request(
            "GET",
            url_suffix=f"api/config/devices/device/{appliance_name}/config/orgs/org-services/{organization}"
            + "/application-identification/application-specific-options/app-specific-option-list",
            params=params,
            headers=headers,
            resp_type="xml",
            ok_codes=(200, 201),
        )
        return response

    def predefined_application_list_request(
        self,
        family: Optional[str] = None,
        risk: Optional[int] = None,
        tags: Optional[list] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        params = assign_params(family=family, risk=risk, tags=tags, offset=offset, limit=limit)
        response = self._http_request(
            "GET",
            url_suffix="vnms/spack/predefined?xPath=/predefined/config/predefined-applications"
            + "/application-identification/applications/application",
            params=params,
            headers=self._headers,
            resp_type="json",
            ok_codes=(200, 201, 204),
        )
        return response


# HEADING: """ HELPER FUNCTIONS """


def set_offset(page: Optional[int], page_size: Optional[int]):
    """Determine offset according to 'page' and 'page_size' arguments

    :type page: ``Optional[int]``
    :param page: start index of page

    :type page_size: ``Optional[int]``
    :param ip: size of page

    :return: offset
    :rtype: Optional[int]
    """
    if not page:
        return page_size
    elif (isinstance(page, int) and isinstance(page_size, int)) and (page >= 0 and page_size >= 0):
        return page * page_size
    else:
        raise DemistoException(message="'page' or 'page_size' arguments are invalid.")


def check_limit(limit: Optional[int]):
    """given 'limit' as an argument, check its validity

    :type limit: ``int``

    :return: None
    :rtype: None
    """
    if isinstance(limit, int) and limit <= 0:
        raise DemistoException("Please provide a positive value for 'limit' argument.")


def set_organization(organization_args: Optional[str], organization_params: Optional[str]):
    """given two choices for default organization name (arguments or parameters), check if organization name exists.

    :type organization_args: ``str``
    :param organization_args: organization name from arguments

    :type organization_params: ``str``
    :param organization_params: organization name from parameters

    :return: organization
    :rtype: string
    """
    organization = organization_args or organization_params

    if not organization:
        raise DemistoException("Please provide 'Organization Name' via integration configuration or command argument.")

    return organization


def check_and_update_token(client: Client, client_id: str, client_secret: str, current_context: dict[str, Any]):
    """
    Checks if current auth token is valid.
    If needed - updates auth token using available refresh token.
    Updates new auth token in integration context.

    :type organization_args: ``Client``
    :param client: Client object

    :type client_id: ``str``
    :param client_id: client id parameter

    :type client_secret: ``str``
    :param client_id: client secret parameter

    :type current_context: ``dict[str, any]``
    :param current_context: current integration context

    :rtype: Tuple(boolean,str)
    """

    try:
        test_connectivity(client)  # send HTTP request to check if token is valid
    except DemistoException as e:
        if e.res.status_code == 401 or "invalid_token" in str(e.message):
            if current_context:
                # obtain refresh token and send it using client.access_token_request function
                refresh_token = current_context.get("refresh_token", "")

                client._headers = None

                # response contains updated auth_token to be used as Bearer token
                response = client.refresh_token_request(client_id, client_secret, refresh_token)
                auth_token = response.get("access_token")

                # integration context is updated with new access token and refresh token
                response["client_id"] = client_id
                response["client_secret"] = client_secret
                update_integration_auth_context(response)

                return auth_token
            else:
                raise DemistoException(
                    "Auth Token Expired, Refresh Token is not found."
                    + "Please create a new Auth Token using 'vd-auth-start' command."
                )

    return None


def create_client_header(
    use_token: bool,
    username: str,
    password: str,
    client_id: str,
    client_secret: str,
    access_token: str,
):
    """
    Creates Auth and Header arguments for the Client object based on the authentication
    method selected in the integration instance configuration.

    :type use_token: ``bool``
    :param use_token: boolean argument indicating which type of authentication will be used.

    :type username: ``str``
    :param username: Username parameter from instance configuration.

    :type password: ``str``
    :param password: Password parameter from instance configuration.

    :type client_id: ``str``
    :param client_id: Client ID parameter from instance configuration.

    :type client_secret: ``str``
    :param client_secret: Client Secret parameter from instance configuration.

    :type access_token: ``str``
    :param access_token: Access Token parameter from instance configuration.

    :rtype: Tuple(Optional[None,str],dict[str,str])
    returns (auth, header) tuple
    """
    # Basic authentication
    if (not use_token) and username and password:
        credentials = f"{username}:{password}"
        auth_header = f"Basic {b64_encode(credentials)}"
        return (username, password), {"Authorization": auth_header}
    # Auth Token authentication
    elif use_token and all([client_id, client_secret, access_token]):
        return None, {"Authorization": f"Bearer {access_token}"}
    else:
        raise DemistoException(message="Not all fields for the selected authenticating are set, therefore it cannot be executed.")


def create_custom_url_category_request_body(
    url_category_name: str,
    description: str,
    confidence: str,
    urls: list,
    url_reputation: list,
    patterns: list,
    pattern_reputation: list,
):

    urls_dict: dict[str, list] = {
        "strings": [],
        "patterns": [],
    }

    if urls:
        _strings = urls_dict.get("strings", [])
        for value in urls:
            _strings.append({"string-value": value})

        if url_reputation:
            for i in range(len(url_reputation)):
                _strings[i]["reputation"] = url_reputation[i]

    if patterns:
        _patterns = urls_dict.get("patterns", [])
        for value in patterns:
            _patterns.append({"pattern-value": value})

        if pattern_reputation:
            for i in range(len(pattern_reputation)):
                _patterns[i]["reputation"] = pattern_reputation[i]

    request_body = {
        "url-category": {
            "category-name": url_category_name,
            "category-description": description,
            "confidence": confidence,
            "urls": urls_dict,
        }
    }

    return request_body


def create_access_policy_rule_request_body(
    rule_name: str,
    description: str,
    tags: list,
    source_address_objects: list,
    destination_address_objects: list,
    url_reputation: list,
    predefined_application: list,
    user_defined_application: list,
    custom_url_categories: list,
):

    request_body = {
        "access-policy": {
            "name": rule_name,
            "description": description,
            "rule-disable": "false",
            "tag": tags,
            "match": {
                "source": {
                    "zone": {},
                    "address": {
                        "address-list": source_address_objects,
                        "negate": "",
                    },
                    "site-name": [],
                    "user": {
                        "user-type": "any",
                        "local-database": {"status": "disabled"},
                        "external-database": {"status": "disabled"},
                    },
                },
                "destination": {
                    "zone": {},
                    "address": {
                        "address-list": destination_address_objects,
                        "negate": "",
                    },
                    "site-name": [],
                },
                "application": {
                    "predefined-application-list": predefined_application,
                    "user-defined-application-list": user_defined_application,
                },
                "url-category": {"user-defined": custom_url_categories},
                "url-reputation": {"predefined": url_reputation},
                "ttl": {},
            },
            "set": {
                "lef": {
                    "event": "never",
                    "options": {"send-pcap-data": {"enable": False}},
                },
                "action": "deny",
                "tcp-session-keepalive": "disabled",
            },
        }
    }

    return request_body


def create_address_object_request_body(
    object_name: str, description: str, tags: list, address_object_type: str, object_value: str
):

    request_body = {
        "address": {
            "name": object_name,
            "description": description,
            "tag": tags,
            address_object_type: object_value,
        }
    }

    return request_body


def create_sdwan_policy_rule_request_body(
    rule_name: str,
    description: str,
    tags: list,
    source_address_objects: list,
    destination_address_objects: list,
    url_reputation: list,
    custom_url_categories: list,
    forwarding_action: str,
    nexthop_ip: str,
    routing_instance: str,
    forwarding_profile: str,
    predefined_application: list,
    user_defined_application: list,
    rule_disable: str = "false",
):

    request_body: dict[str, dict] = {
        "rule": {
            "name": rule_name,
            "description": description,
            "tag": tags,
            "rule-disable": rule_disable,
            "match": {
                "source": {
                    "zone": {},
                    "address": {"address-list": source_address_objects},
                    "user": {
                        "user-type": "any",
                        "local-database": {"status": "disabled"},
                        "external-database": {"status": "disabled"},
                    },
                },
                "destination": {
                    "zone": {},
                    "address": {"address-list": destination_address_objects},
                },
                "application": {
                    "predefined-application-list": predefined_application,
                    "user-defined-application-list": user_defined_application,
                },
                "url-category": {"user-defined": custom_url_categories},
                "url-reputation": {"predefined": url_reputation},
                "ttl": {},
            },
            "set": {
                "lef": {
                    "event": "never",
                    "profile-default": "true",
                    "rate-limit": "10",
                },
                "action": forwarding_action,
                "tcp-optimization": {},
            },
            "monitor": {},
        }
    }

    for key, value in {
        "forwarding-profile": forwarding_profile,
        "nexthop-address": nexthop_ip,
        "routing-instance": routing_instance,
    }.items():
        if value:
            request_body.get("rule", {}).get("set", {}).update({key: value})

    return request_body


def update_integration_auth_context(obj: dict[Any, Any]) -> None:
    # TODO: add docstring
    temp_context = get_integration_context()
    if temp_context.get("context"):
        temp_context = temp_context.get("context")
    temp_context.update(obj)
    set_integration_context({"context": temp_context})


# HEADING: """ COMMAND FUNCTIONS """


def handle_auth_token_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Creates Auth Clients and Auth tokens.

    The function will first determine whether Client ID and Client Secret were passed as parameters (default) or arguments,
    indicating an existing Auth Client.
    If not, it will use the VOEA REST API (from the product's official API documentation) to create a new Auth Client.

    When an Auth Client exists, the function will send a request to generate a new Auth Token.
    If successful, All of the Token's relevant information will be saved in the
    Integration Context for Later Use and Refresh Token requests.

    Args:
        client (Client): Client object
        args (Dict[str, Any]): command arguments

    Raises:
        DemistoException: raises DemistoException errors related to bad arguments/parameters or
                            failure in a specific step of the authentication process

    Returns:
        CommandResults: returns message in the War room if authentication process was successful
    """

    if not client._auth:
        raise DemistoException(message=BASIC_CREDENTIALS_COULD_NOT_START)
    username, password = client._auth
    token_name = args.get("token_name", OAUTH_CLIENT)
    token_description = args.get("description", OAUTH_CLIENT + " for Versa Director Integration")
    client_id = None
    client_secret = None
    _outputs = None
    oauth_client_created_msg = ""

    # check if Client ID and Client Secret were passed as parameters
    if client.client_id_param and client.client_secret_param:
        client_id = client.client_id_param
        client_secret = client.client_secret_param

    # check if Client ID and Client Secret were passed as arguments
    elif args.get("client_id") and args.get("client_secret"):
        client_id = args.get("client_id")
        client_secret = args.get("client_secret")

    # if Client ID and Client Secret are not passed, create new Client ID and Client Secret (New Auth Client)
    else:
        client_id = CLIENT_ID
        client_secret = CLIENT_CREDENTIALS

        if client._base_url.endswith(PORT_CREDENTIALS):
            client._base_url = client._base_url.replace(PORT_CREDENTIALS, PORT_AUTH)
        try:
            # stage 1: Obtain Access token from voae_rest client
            token_response = client.access_token_request(username, password, client_id, client_secret)
            access_token = token_response.get("access_token", "")

            # stage 2: If successful, use the “Access_token” from the response as a “Bearer token”
            # authorization to created the desired "Auth Client"
            response = client.auth_credentials_request(access_token, token_name, token_description)

        except DemistoException as e:
            if e.res.status_code == 500:
                raise DemistoException(message=AUTH_EXISTING_TOKEN, exception=e)
            elif e.res.status_code == 400:
                raise DemistoException(message=AUTH_EXCEEDED_MAXIMUM, exception=e)
            else:
                raise DemistoException(message="Auth process failed.", exception=e)

        # if "Auth Client" created successfully, Client ID and Client Secret would return
        # in the response and saved in the Integration Context
        client_id = response.get("client_id")
        client_secret = response.get("client_secret")

        if not client_id or not client_secret:
            raise DemistoException(message=AUTH_INVALID_CREDENTIALS)

        _outputs = {"client_id": client_id, "client_name": token_name}
        update_integration_auth_context(response)

        oauth_client_created_msg = (
            f"Auth Client Created Successfully.\nClient ID: {client_id}, Auth Client Name: {token_name}.\n\n"
        )

    # stage 3: create an Auth Token using the Auth Client
    try:
        response = client.access_token_request(username, password, client_id, client_secret)
    except DemistoException as e:
        if e.res.status_code == 401:
            raise DemistoException(message=AUTH_INVALID_ACCESS_TOKEN)
        else:
            raise DemistoException(message=AUTH_BAD_CREDENTIALS)

    # save response with generated Auth Token, Refresh Token, Expiration Information and User Information
    # in Integration Context (among other information).
    response.update({"client_id": client_id, "client_secret": client_secret})
    update_integration_auth_context(response)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".AuthClient",
        outputs=_outputs if _outputs else {"client_id": client_id},
        raw_response=_outputs if _outputs else {"client_id": client_id},
        readable_output=oauth_client_created_msg
        + "Authentication request was successful, Auth Token was created and saved in the Integration Context.\n"
        + "Please check the 'Use Auth Token' in the configuration screen.\n"
        + "To ensure the authentication is valid, run the 'vd-auth-test' command.",
    )

    return command_results


def auth_test_command(client: Client, args: Dict[str, Any]):
    # test organization name if provided
    organization_name = client.organization_params or args.get("organization")
    if organization_name:
        client.test_organization_name_request(organization_name)
    # test connectivity with chosen authentication method
    message = test_connectivity(client)
    if message == "ok":
        if headers := client._headers:
            if "Bearer" in headers.get("Authorization"):
                message = "Auth Token "
            else:
                message = "Basic "

    return CommandResults(readable_output=message + "Authentication method connectivity verified.")


def appliance_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit", 25))
    offset = set_offset(page, page_size)

    check_limit(limit)

    response = client.appliance_list_request(offset, limit)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".Appliance",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name="Appliances",
            t=response.get("appliance-list"),
            headers=["name", "uuid", "ipAddress", "appType", "branchId"],
            headerTransform=pascalToSpace,
        ),
    )
    return command_results


def organization_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    response = client.organization_list_request(offset, limit)

    # extract 'applianceuuid' list from 'appliances' dictionary
    appliances = []
    if response:
        for appliance in response[0].get("appliances", []):
            appliances.append(appliance.get("applianceuuid"))
        response[0]["appliances"] = appliances

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".Organization",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name="Organization List",
            headerTransform=pascalToSpace,
            t=response,
            headers=["name", "id", "parent", "appliances", "cpeDeploymentType", "uuid"],
        ),
    )

    return command_results


def appliances_list_by_organization_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization", None)
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 50))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.appliances_list_by_organization_request(organization, offset, limit)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".Appliance",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name="Organization List",
            headers=["name", "ipAddress", "type", "softwareVersion", "ownerOrg"],
            t=response.get("appliances", {}),
            headerTransform=pascalToSpace,
        ),
    )

    return command_results


def appliances_group_list_by_organization_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization", None)
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.appliances_group_list_by_organization_request(organization, offset, limit)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".DeviceGroup",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Appliance groups associated with {organization}",
            t=response.get("device-group", {}),
            headerTransform=pascalToSpace,
            headers=[
                "name",
                "organization",
                "createDate",
                "inventory-name",
                "poststaging-template",
            ],
        ),
    )
    return command_results


def appliances_list_by_device_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    device_group = args.get("device_group", "")
    template_name = args.get("template_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    response = client.appliances_list_by_device_group_request(device_group, template_name, offset, limit)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".DeviceGroup",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name="Appliances",
            t=response,
            headerTransform=pascalToSpace,
            headers=[
                "name",
                "organization",
                "createDate",
                "inventory-name",
                "poststaging-template",
                "template-association",
            ],
            json_transform_mapping={
                "template-association": JsonTransformer(
                    keys=["name"],
                ),
            },
            removeNull=True,
        ),
    )
    return command_results


def template_list_by_organization_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    type = args.get("type", "MAIN")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.template_list_by_organization_request(organization, type, offset, limit)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".Template",
        outputs=response.get("versanms.templates", {}).get("template", {}),
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Templates associated with {organization}",
            t=response.get("versanms.templates", {}).get("template", {}),
            headerTransform=pascalToSpace,
            headers=[
                "name",
                "organization",
                "lockDetails",
                "templateType",
                "isPrimary",
                "isStaging",
            ],
        ),
    )
    return command_results


def template_list_by_datastore_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.template_list_by_datastore_request(organization, offset, limit)
    response = json.loads(xml2json((response.content)))

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".DataStoreTemplate",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Templates associated with {organization} Data-Store",
            t=response.get("collection", {}).get("org", {}),
            headerTransform=pascalToSpace,
            removeNull=True,
            headers=[
                "name",
                "appliance-owner",
                "available-routing-instances",
                "owned-routing-instances",
                "available-networks",
            ],
        ),
    )
    return command_results


def application_service_template_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    keyword = args.get("keyword")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.application_service_template_list_request(organization, keyword, offset, limit)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplicationServiceTemplate",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Application Service Templates associated with {organization}",
            t=response.get("content", {}),
            headerTransform=pascalToSpace,
            headers=[
                "createDate",
                "modifyDate",
                "lastUpdatedBy",
                "name",
                "organization",
                "status",
            ],
        ),
    )
    return command_results


@polling_function(
    name="vd-template-change-commit",
    interval=DEFAULT_INTERVAL,
    timeout=DEFAULT_TIMEOUT,
    requires_polling_arg=False,
)
def template_change_commit_command(args: Dict[str, Any], client: Client) -> PollResult:
    template_name = args.get("template_name", "")
    appliances = argToList(args.get("appliances"))
    mode = args.get("mode", "")
    reboot = args.get("reboot", "false")
    task_id = args.get("task_id")
    if not task_id:
        response = client.template_change_commit_request(template_name, appliances, mode, reboot)
        response = json.loads((response.content).decode("utf-8"))
        template_response = response.get("versanms.templateResponse", {})
        task_id = template_response.get("taskId")
        args["task_id"] = task_id

    response = client.template_change_commit_polling_request(task_id)
    percentage_completion = response.get("versa-tasks.task", {}).get("versa-tasks.percentage-completion")

    if percentage_completion == 100:
        return PollResult(
            response=CommandResults(
                outputs_prefix=VENDOR_NAME + ".Commit",
                raw_response=response.get("versa-tasks.task", {}),
                readable_output=tableToMarkdown(
                    name="Template change committed",
                    t=response.get("versa-tasks.task", {}),
                    headerTransform=pascalToSpace,
                    headers=[
                        "versa-tasks.id",
                        "versa-tasks.task-description",
                        "versa-tasks.user",
                        "versa-tasks.task-status",
                        "versa-tasks.progressmessages",
                    ],
                    is_auto_json_transform=True,
                ),
            ),
            continue_to_poll=False,
        )
    else:
        results = CommandResults(readable_output="Polling job failed.")
        return PollResult(
            continue_to_poll=True,
            args_for_next_run={"task_id": task_id, **args},
            response=results,
        )


def template_custom_url_category_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    url_category_name = args.get("url_category_name")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.template_custom_url_category_list_request(organization, template_name, url_category_name, offset, limit)
    response = json.loads(xml2json((response.content)))

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateCustomUrlCategory",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Application Service Templates associated with {organization}",
            t=response.get("collection", {}).get("url-category", {}),
            headerTransform=pascalToSpace,
            headers=["category-name", "category-description", "confidence", "urls"],
            is_auto_json_transform=True,
        ),
    )
    return command_results


def template_custom_url_category_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization", "")
    template_name = args.get("template_name", "")
    url_category_name = args.get("url_category_name", "")
    description = args.get("description", "")
    confidence = args.get("confidence", "")
    urls = argToList(args.get("urls"))
    url_reputation = argToList(args.get("url_reputation"))
    patterns = argToList(args.get("patterns"))
    pattern_reputation = argToList(args.get("pattern_reputation"))
    message = "Object created successfully."

    organization = set_organization(organization_args, client.organization_params)
    try:
        client.template_custom_url_category_create_request(
            organization,
            template_name,
            url_category_name,
            description,
            confidence,
            urls,
            url_reputation,
            patterns,
            pattern_reputation,
        )
    except DemistoException as e:
        if e.res.status_code == 409:
            message = ALREADY_EXISTS_MSG
        else:
            raise e

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateCustomUrlCategory",
        readable_output=message,
    )
    return command_results


def template_custom_url_category_edit_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    url_category_name = args.get("url_category_name", "")
    description = args.get("description", "")
    confidence = args.get("confidence", "")
    urls = argToList(args.get("urls"))
    url_reputation = argToList(args.get("url_reputation"))
    patterns = argToList(args.get("patterns"))
    pattern_reputation = argToList(args.get("pattern_reputation"))

    organization = set_organization(organization_args, client.organization_params)

    response, request_body = client.template_custom_url_category_edit_request(
        organization,
        template_name,
        url_category_name,
        description,
        confidence,
        urls,
        url_reputation,
        patterns,
        pattern_reputation,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateCustomUrlCategory",
        readable_output=f"Command run successfully.\nRequest Body:\n\n{request_body}",
    )
    return command_results


def template_custom_url_category_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    url_category_name = args.get("url_category_name", "")

    organization = set_organization(organization_args, client.organization_params)

    client.template_custom_url_category_delete_request(
        organization=organization,
        template_name=template_name,
        url_category_name=url_category_name,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateCustomUrlCategory",
        readable_output="Command run successfully.",
    )
    return command_results


def appliance_custom_url_category_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    url_category_name = args.get("url_category_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.appliance_custom_url_category_list_request(organization, appliance_name, url_category_name, offset, limit)
    response = json.loads(xml2json((response.content)))

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceCustomUrlCategory",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Application Service Appliances associated with {organization}",
            t=response.get("collection", {}).get("url-category", {}),
            headerTransform=pascalToSpace,
            headers=["category-name", "category-description", "confidence", "urls"],
            is_auto_json_transform=True,
            removeNull=True,
        ),
    )
    return command_results


def appliance_custom_url_category_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    url_category_name = args.get("url_category_name", "")
    description = args.get("description", "")
    confidence = args.get("confidence", "")
    urls = argToList(args.get("urls"))
    url_reputation = argToList(args.get("url_reputation"))
    patterns = argToList(args.get("patterns"))
    pattern_reputation = argToList(args.get("pattern_reputation"))

    message = "Command run successfully."

    organization = set_organization(organization_args, client.organization_params)

    try:
        response, request_body = client.appliance_custom_url_category_create_request(
            organization,
            appliance_name,
            url_category_name,
            description,
            confidence,
            urls,
            url_reputation,
            patterns,
            pattern_reputation,
        )
    except DemistoException as e:
        if e.res.status_code == 409:
            message = ALREADY_EXISTS_MSG
            request_body = None, "Not available."

        else:
            raise e

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceCustomUrlCategory",
        readable_output=message + f"\nRequest Body:\n\n{request_body}",
    )
    return command_results


def appliance_custom_url_category_edit_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    url_category_name = args.get("url_category_name", "")
    description = args.get("description", "")
    confidence = args.get("confidence", "")
    urls = argToList(args.get("urls"))
    url_reputation = argToList(args.get("url_reputation"))
    patterns = argToList(args.get("patterns"))
    pattern_reputation = argToList(args.get("pattern_reputation"))

    organization = set_organization(organization_args, client.organization_params)

    response, request_body = client.appliance_custom_url_category_edit_request(
        organization,
        appliance_name,
        url_category_name,
        description,
        confidence,
        urls,
        url_reputation,
        patterns,
        pattern_reputation,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceCustomUrlCategory",
        readable_output="Command run successfully.\nRequest Body:\n\n" + str(request_body),
    )
    return command_results


def appliance_custom_url_category_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    url_category_name = args.get("url_category_name", "")

    organization = set_organization(organization_args, client.organization_params)

    client.appliance_custom_url_category_delete_request(
        organization=organization,
        appliance_name=appliance_name,
        url_category_name=url_category_name,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceCustomUrlCategory",
        readable_output="Command run successfully.",
    )
    return command_results


def template_access_policy_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.template_access_policy_list_request(organization, template_name, offset, limit)
    response = json.loads(xml2json((response.content)))

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateAccessPolicy",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Access policies associated with {organization}",
            t=response.get("collection", {}).get("access-policy-group", {}),
            headerTransform=pascalToSpace,
            headers=["name", "rules"],
            is_auto_json_transform=True,
        ),
    )
    return command_results


def template_access_policy_rule_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    access_policy_name = args.get("access_policy_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.template_access_policy_rule_list_request(organization, template_name, access_policy_name, offset, limit)
    response = json.loads(xml2json((response.content)))

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateAccessPolicyRule",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Access policies associated with {organization}",
            t=response.get("collection", {}).get("access-policy", {}),
            headerTransform=pascalToSpace,
            headers=["name", "description", "tag", "rule-disable"],
            is_auto_json_transform=True,
        ),
    )
    return command_results


def template_access_policy_rule_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization", "")
    template_name = args.get("template_name", "")
    access_policy_name = args.get("access_policy_name", "")
    if custom_rule_json := args.get("custom_rule_json"):
        access_policy = custom_rule_json.get("access-policy", "")
        rule_name = access_policy.get("name", "")
        description = access_policy.get("description", "")
        tags = argToList(access_policy.get("tag"))
        source_address_objects = argToList(access_policy.get("match", {}).get("source", {}).get("address"))
        destination_address_objects = argToList(access_policy.get("match", {}).get("destination", {}).get("address"))
        url_reputation = argToList(access_policy.get("match", {}).get("url-reputation", {}).get("predefined"))
        predefined_application = argToList(
            access_policy.get("match", {}).get("application", {}).get("predefined-application-list")
        )

        user_defined_application = argToList(
            access_policy.get("match", {}).get("application", {}).get("user-defined-application-list")
        )
        custom_url_categories = []
    else:
        rule_name = args.get("rule_name", "")
        description = args.get("description", "")
        tags = argToList(args.get("tags"))
        source_address_objects = argToList(args.get("source_address_objects"))
        destination_address_objects = argToList(args.get("destination_address_objects"))
        url_reputation = argToList(args.get("url_reputation"))
        predefined_application = argToList(args.get("predefined_application"))
        user_defined_application = argToList(args.get("user_defined_application"))
        custom_url_categories = argToList(args.get("custom_url_categories"))

    organization = set_organization(organization_args, client.organization_params)

    message = "Command run successfully."

    try:
        response, request_body = client.template_access_policy_rule_create_request(
            organization,
            template_name,
            access_policy_name,
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            predefined_application,
            user_defined_application,
            custom_url_categories,
        )
    except DemistoException as e:
        if e.res.status_code == 409:
            message = ALREADY_EXISTS_MSG
            request_body = None, "Not available."

        else:
            raise e

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateAccessPolicyRule",
        readable_output=message + f"\nRequest Body:\n\n{request_body}",
    )
    return command_results


def template_access_policy_rule_edit_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization", "")
    template_name = args.get("template_name", "")
    access_policy_name = args.get("access_policy_name", "")
    if custom_rule_json := args.get("custom_rule_json"):
        access_policy = custom_rule_json.get("access-policy", "")
        rule_name = access_policy.get("name", "")
        description = access_policy.get("description", "")
        tags = argToList(access_policy.get("tag"))
        source_address_objects = argToList(access_policy.get("match", {}).get("source", {}).get("address"))
        destination_address_objects = argToList(access_policy.get("match", {}).get("destination", {}).get("address"))
        url_reputation = argToList(access_policy.get("match", {}).get("url-reputation", {}).get("predefined"))
        predefined_application = argToList(
            access_policy.get("match", {}).get("application", {}).get("predefined-application-list")
        )

        user_defined_application = argToList(
            access_policy.get("match", {}).get("application", {}).get("user-defined-application-list")
        )
        custom_url_categories = []
    else:
        rule_name = args.get("rule_name", "")
        description = args.get("description", "")
        tags = argToList(args.get("tags"))
        source_address_objects = argToList(args.get("source_address_objects"))
        destination_address_objects = argToList(args.get("destination_address_objects"))
        url_reputation = argToList(args.get("url_reputation", ""))
        predefined_application = argToList(args.get("predefined_application"))
        user_defined_application = argToList(args.get("user_defined_application"))
        custom_url_categories = argToList(args.get("custom_url_categories"))

    organization = set_organization(organization_args, client.organization_params)

    response, request_body = client.template_access_policy_rule_edit_request(
        organization,
        template_name,
        access_policy_name,
        rule_name,
        description,
        tags,
        source_address_objects,
        destination_address_objects,
        url_reputation,
        predefined_application,
        user_defined_application,
        custom_url_categories,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateAccessPolicyRule",
        readable_output="Command run successfully.\nRequest Body:\n\n" + str(request_body),
    )
    return command_results


def template_access_policy_rule_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    access_policy_name = args.get("access_policy_name", "")
    rule_name = args.get("rule_name", "")

    organization = set_organization(organization_args, client.organization_params)

    client.template_access_policy_rule_delete_request(organization, template_name, access_policy_name, rule_name)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateAccessPolicyRule",
        readable_output="Command run successfully.",
    )
    return command_results


def appliance_access_policy_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.appliance_access_policy_list_request(organization, appliance_name, offset, limit)
    response = json.loads(xml2json((response.content)))

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceAccessPolicy",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Access policies associated with {organization}",
            t=response.get("collection", {}).get("access-policy-group", {}),
            headerTransform=pascalToSpace,
            headers=["name", "rules"],
            is_auto_json_transform=True,
        ),
    )
    return command_results


def appliance_access_policy_rule_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    access_policy_name = args.get("access_policy_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.appliance_access_policy_rule_list_request(organization, appliance_name, access_policy_name, offset, limit)
    response = json.loads(xml2json((response.content)))

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceAccessPolicyRule",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Access policies associated with {organization}",
            t=response.get("collection", {}).get("access-policy", {}),
            headerTransform=pascalToSpace,
            headers=["name", "description", "tag", "rule-disable"],
            is_auto_json_transform=True,
        ),
    )
    return command_results


def appliance_access_policy_rule_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization", "")
    appliance_name = args.get("appliance_name", "")
    access_policy_name = args.get("access_policy_name", "")
    if custom_rule_json := args.get("custom_rule_json"):
        access_policy = custom_rule_json.get("access-policy", "")
        rule_name = access_policy.get("name", "")
        description = access_policy.get("description", "")
        tags = argToList(access_policy.get("tag"))
        source_address_objects = argToList(access_policy.get("match", {}).get("source", {}).get("address"))
        destination_address_objects = argToList(access_policy.get("match", {}).get("destination", {}).get("address"))
        url_reputation = argToList(access_policy.get("match", {}).get("url-reputation", {}).get("predefined"))
        predefined_application = argToList(
            access_policy.get("match", {}).get("application", {}).get("predefined-application-list")
        )

        user_defined_application = argToList(
            access_policy.get("match", {}).get("application", {}).get("user-defined-application-list")
        )
        custom_url_categories = []
    else:
        rule_name = args.get("rule_name", "")
        description = args.get("description", "")
        tags = argToList(args.get("tags"))
        source_address_objects = argToList(args.get("source_address_objects"))
        destination_address_objects = argToList(args.get("destination_address_objects"))
        url_reputation = argToList(args.get("url_reputation", ""))
        predefined_application = argToList(args.get("predefined_application"))
        user_defined_application = argToList(args.get("user_defined_application"))
        custom_url_categories = argToList(args.get("custom_url_categories"))

    organization = set_organization(organization_args, client.organization_params)

    message = "Command run successfully."

    try:
        response, request_body = client.appliance_access_policy_rule_create_request(
            organization,
            appliance_name,
            access_policy_name,
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            predefined_application,
            user_defined_application,
            custom_url_categories,
        )
    except DemistoException as e:
        if e.res.status_code == 409:
            message = ALREADY_EXISTS_MSG
            request_body = None, "Not available."

        else:
            raise e

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceAccessPolicyRule",
        readable_output=message + f"\nRequest Body:\n\n{request_body}",
    )
    return command_results


def appliance_access_policy_rule_edit_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization", "")
    appliance_name = args.get("appliance_name", "")
    access_policy_name = args.get("access_policy_name", "")
    if custom_rule_json := args.get("custom_rule_json"):
        access_policy = custom_rule_json.get("access-policy", "")
        rule_name = access_policy.get("name", "")
        description = access_policy.get("description", "")
        tags = argToList(access_policy.get("tag"))
        source_address_objects = argToList(access_policy.get("match", {}).get("source", {}).get("address"))
        destination_address_objects = argToList(access_policy.get("match", {}).get("destination", {}).get("address"))
        url_reputation = argToList(access_policy.get("match", {}).get("url-reputation", {}).get("predefined"))
        predefined_application = argToList(
            access_policy.get("match", {}).get("application", {}).get("predefined-application-list")
        )

        user_defined_application = argToList(
            access_policy.get("match", {}).get("application", {}).get("user-defined-application-list")
        )
        custom_url_categories = []
    else:
        rule_name = args.get("rule_name", "")
        description = args.get("description", "")
        tags = argToList(args.get("tags"))
        source_address_objects = argToList(args.get("source_address_objects"))
        destination_address_objects = argToList(args.get("destination_address_objects"))
        url_reputation = argToList(args.get("url_reputation", ""))
        predefined_application = argToList(args.get("predefined_application"))
        user_defined_application = argToList(args.get("user_defined_application"))
        custom_url_categories = argToList(args.get("custom_url_categories"))

    organization = set_organization(organization_args, client.organization_params)

    response, request_body = client.appliance_access_policy_rule_edit_request(
        organization,
        appliance_name,
        access_policy_name,
        rule_name,
        description,
        tags,
        source_address_objects,
        destination_address_objects,
        url_reputation,
        predefined_application,
        user_defined_application,
        custom_url_categories,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceAccessPolicyRule",
        readable_output="Command run successfully.\nRequest Body:\n\n" + str(request_body),
    )
    return command_results


def appliance_access_policy_rule_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    access_policy_name = args.get("access_policy_name", "")
    rule_name = args.get("rule_name", "")

    organization = set_organization(organization_args, client.organization_params)

    client.appliance_access_policy_rule_delete_request(organization, appliance_name, access_policy_name, rule_name)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceAccessPolicyRule",
        readable_output="Command run successfully.",
    )
    return command_results


def template_sdwan_policy_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.template_sdwan_policy_list_request(organization, template_name, offset, limit)
    response = json.loads(xml2json((response.content)))

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateSdwanPolicy",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"SD-WAN policies associated with {organization}",
            t=response.get("collection", {}).get("sdwan-policy-group", {}),
            headerTransform=pascalToSpace,
            headers=["name", "rules"],
            is_auto_json_transform=True,
        ),
    )
    return command_results


def template_sdwan_policy_rule_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    sdwan_policy_name = args.get("sdwan_policy_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.template_sdwan_policy_rule_request(organization, template_name, sdwan_policy_name, offset, limit)
    response = json.loads(xml2json((response.content))).get("collection").get("rule")

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateSdwanPolicyRule",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"SD-WAN policy rules associated with {organization}",
            t=response,
            headerTransform=string_to_table_header,
            headers=["name", "match", "set"],
            is_auto_json_transform=True,
            removeNull=True,
        ),
    )
    return command_results


def template_sdwan_policy_rule_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    sdwan_policy_name = args.get("sdwan_policy_name", "")

    organization = set_organization(organization_args, client.organization_params)

    if custom_rule_json := args.get("custom_rule_json"):
        rule = custom_rule_json.get("rule", "")
        rule_name = rule.get("name", "")
        description = rule.get("description", "")
        tags = argToList(rule.get("tag"))
        source_address_objects = rule.get("match").get("source").get("address").get("address-list")
        destination_address_objects = rule.get("match").get("destination").get("address").get("address-list")
        url_reputation = rule.get("match").get("url-reputation").get("predefined")
        custom_url_categories = rule.get("match").get("url-category").get("user-defined")
        forwarding_action = rule.get("match").get("forwarding-class")
        nexthop_ip = rule.get("set").get("nexthop-address")
        routing_instance = rule.get("set").get("routing-instance")
        forwarding_profile = rule.get("set").get("forwarding-profile")
        predefined_application = rule.get("match").get("application").get("predefined-application-list")
        user_defined_application = rule.get("match").get("application").get("user-defined-application-list")
    else:
        rule_name = args.get("rule_name", "")
        description = args.get("description", "")
        tags = argToList(args.get("tags"))
        source_address_objects = argToList(args.get("source_address_objects"))
        destination_address_objects = argToList(args.get("destination_address_objects"))
        url_reputation = argToList(args.get("url_reputation"))
        custom_url_categories = argToList(args.get("custom_url_categories"))
        forwarding_action = args.get("forwarding_action", "")
        nexthop_ip = args.get("nexthop_ip", "")
        routing_instance = args.get("routing_instance", "")
        forwarding_profile = args.get("forwarding_profile", "")
        predefined_application = argToList(args.get("predefined_application"))
        user_defined_application = argToList(args.get("user_defined_application"))

    message = "Command run successfully."

    try:
        response, request_body = client.template_sdwan_policy_rule_create_request(
            organization,
            template_name,
            sdwan_policy_name,
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            custom_url_categories,
            forwarding_action,
            nexthop_ip,
            routing_instance,
            forwarding_profile,
            predefined_application,
            user_defined_application,
        )
    except DemistoException as e:
        if e.res.status_code == 409:
            message = ALREADY_EXISTS_MSG
            request_body = None, "Not available."

        else:
            raise e

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateSdwanPolicyRule",
        readable_output=message + f"\nRequest Body:\n\n{request_body}",
    )
    return command_results


def template_sdwan_policy_rule_edit_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    sdwan_policy_name = args.get("sdwan_policy_name", "")

    organization = set_organization(organization_args, client.organization_params)

    if custom_rule_json := args.get("custom_rule_json"):
        rule = custom_rule_json.get("rule", "")
        rule_name = rule.get("name", "")
        description = rule.get("description", "")
        tags = argToList(rule.get("tag"))
        source_address_objects = rule.get("match").get("source").get("address").get("address-list")
        destination_address_objects = rule.get("match").get("destination").get("address").get("address-list")
        url_reputation = rule.get("match").get("url-reputation").get("predefined")
        custom_url_categories = rule.get("match").get("url-category").get("user-defined")
        forwarding_action = rule.get("match").get("forwarding-class")
        nexthop_ip = rule.get("set").get("nexthop-address")
        routing_instance = rule.get("set").get("routing-instance")
        forwarding_profile = rule.get("set").get("forwarding-profile")
        predefined_application = rule.get("match").get("application").get("predefined-application-list")
        user_defined_application = rule.get("match").get("application").get("user-defined-application-list")
        rule_disable = args.get("rule_disable", "false")

    else:
        rule_name = args.get("rule_name", "")
        description = args.get("description", "")
        tags = argToList(args.get("tags"))
        source_address_objects = argToList(args.get("source_address_objects"))
        destination_address_objects = argToList(args.get("destination_address_objects"))
        url_reputation = argToList(args.get("url_reputation"))
        custom_url_categories = argToList(args.get("custom_url_categories"))
        forwarding_action = args.get("forwarding_action", "")
        nexthop_ip = args.get("nexthop_ip", "")
        routing_instance = args.get("routing_instance", "")
        forwarding_profile = args.get("forwarding_profile", "")
        predefined_application = argToList(args.get("predefined_application"))
        user_defined_application = argToList(args.get("user_defined_application"))
        rule_disable = args.get("rule_disable", "false")

    response, request_body = client.template_sdwan_policy_rule_edit_request(
        organization,
        template_name,
        sdwan_policy_name,
        rule_name,
        description,
        tags,
        rule_disable,
        source_address_objects,
        destination_address_objects,
        url_reputation,
        custom_url_categories,
        forwarding_action,
        nexthop_ip,
        routing_instance,
        forwarding_profile,
        predefined_application,
        user_defined_application,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateSdwanPolicyRule",
        readable_output="Command run successfully.\nRequest Body:\n\n" + str(request_body),
    )
    return command_results


def template_sdwan_policy_rule_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    sdwan_policy_name = args.get("sdwan_policy_name", "")
    rule_name = args.get("rule_name", "")

    organization = set_organization(organization_args, client.organization_params)

    client.template_sdwan_policy_rule_delete_request(
        organization,
        template_name,
        sdwan_policy_name,
        rule_name,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateSdwanPolicyRule",
        readable_output="Command run successfully.",
    )
    return command_results


def appliance_sdwan_policy_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.appliance_sdwan_policy_list_request(organization, appliance_name, offset, limit)
    response = json.loads(xml2json((response.content))).get("collection", {}).get("sdwan-policy-group")

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceSdwanPolicy",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"SD-WAN policies associated with {organization}",
            t=response,
            headerTransform=pascalToSpace,
            headers=["name", "rules"],
            is_auto_json_transform=True,
        ),
    )
    return command_results


def appliance_sdwan_policy_rule_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    sdwan_policy_name = args.get("sdwan_policy_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.appliance_sdwan_policy_rule_list_request(organization, appliance_name, sdwan_policy_name, offset, limit)
    response = json.loads(xml2json((response.content))).get("collection", {}).get("rule", {})
    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceSdwanPolicyRule",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"SD-WAN policy rules associated with {organization}",
            t=response,
            headerTransform=pascalToSpace,
            headers=["name", "description", "rule-disable", "action"],
            is_auto_json_transform=True,
            removeNull=True,
        ),
    )
    return command_results


def appliance_sdwan_policy_rule_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    sdwan_policy_name = args.get("sdwan_policy_name", "")
    organization = set_organization(organization_args, client.organization_params)

    if custom_rule_json := args.get("custom_rule_json"):
        rule = custom_rule_json.get("rule", {})
        rule_name = rule.get("name", "")
        description = rule.get("description", "")
        tags = argToList(rule.get("tag"))
        source_address_objects = rule.get("source", {}).get("address", {}).get("address-list", [])
        destination_address_objects = rule.get("destination", {}).get("address", {}).get("address-list", [])
        url_reputation = rule.get("match", {}).get("source", {}).get("url-reputation", [])
        custom_url_categories = rule.get("match", {}).get("url-category", {}).get("predefined", {}).get("user-defined", [])
        forwarding_action = rule.get("set", {}).get("action", {}).get("action", "")
        nexthop_ip = rule.get("set", {}).get("nexthop-address	", {})
        routing_instance = rule.get("match", {}).get("routing-instance", "")
        forwarding_profile = rule.get("set", {}).get("forwarding-profile", "")
        predefined_application = rule.get("match", {}).get("application", {}).get("predefined-application-list", [])
        user_defined_application = rule.get("match", {}).get("application", {}).get("user-defined-application-list", [])
    else:
        rule_name = args.get("rule_name", "")
        description = args.get("description", "")
        tags = argToList(args.get("tag"))
        source_address_objects = argToList(args.get("source_address_objects"))
        destination_address_objects = argToList(args.get("destination_address_objects"))
        url_reputation = argToList(args.get("url_reputation"))
        custom_url_categories = argToList(args.get("custom_url_categories"))
        forwarding_action = args.get("forwarding_action", "")
        nexthop_ip = args.get("nexthop_ip", "")
        routing_instance = args.get("routing_instance", "")
        forwarding_profile = args.get("forwarding_profile", "")
        predefined_application = argToList(args.get("predefined_application"))
        user_defined_application = argToList(args.get("user_defined_application"))

    message = "Command run successfully."

    try:
        response, request_body = client.appliance_sdwan_policy_rule_create_request(
            organization,
            appliance_name,
            sdwan_policy_name,
            rule_name,
            description,
            tags,
            source_address_objects,
            destination_address_objects,
            url_reputation,
            custom_url_categories,
            forwarding_action,
            nexthop_ip,
            routing_instance,
            forwarding_profile,
            predefined_application,
            user_defined_application,
        )
    except DemistoException as e:
        if e.res.status_code == 409:
            message = ALREADY_EXISTS_MSG
            request_body = None, "Not available."

        else:
            raise e

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceSdwanPolicyRule",
        readable_output=message + f"\nRequest Body:\n\n{request_body}",
    )
    return command_results


def appliance_sdwan_policy_rule_edit_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    sdwan_policy_name = args.get("sdwan_policy_name", "")
    organization = set_organization(organization_args, client.organization_params)

    if custom_rule_json := args.get("custom_rule_json"):
        rule = custom_rule_json.get("rule", {})
        rule_name = rule.get("name", "")
        description = rule.get("description", "")
        tags = argToList(rule.get("tag"))
        source_address_objects = rule.get("source", {}).get("address", {}).get("address-list", [])
        destination_address_objects = rule.get("destination", {}).get("address", {}).get("address-list", [])
        url_reputation = rule.get("match", {}).get("source", {}).get("url-reputation", [])
        custom_url_categories = rule.get("match", {}).get("url-category", {}).get("predefined", {}).get("user-defined", [])
        forwarding_action = rule.get("set", {}).get("action", {}).get("action", "")
        nexthop_ip = rule.get("set", {}).get("nexthop-address	", {})
        routing_instance = rule.get("match", {}).get("routing-instance", "")
        forwarding_profile = rule.get("set", {}).get("forwarding-profile", "")
        predefined_application = rule.get("match", {}).get("application", {}).get("predefined-application-list", [])
        user_defined_application = rule.get("match", {}).get("application", {}).get("user-defined-application-list", [])
        rule_disable = args.get("rule_disable", "false")
    else:
        rule_name = args.get("rule_name", "")
        description = args.get("description", "")
        tags = argToList(args.get("tag"))
        source_address_objects = argToList(args.get("source_address_objects"))
        destination_address_objects = argToList(args.get("destination_address_objects"))
        url_reputation = argToList(args.get("url_reputation"))
        custom_url_categories = argToList(args.get("custom_url_categories"))
        forwarding_action = args.get("forwarding_action", "")
        nexthop_ip = args.get("nexthop_ip", "")
        routing_instance = args.get("routing_instance", "")
        forwarding_profile = args.get("forwarding_profile", "")
        predefined_application = argToList(args.get("predefined_application"))
        user_defined_application = argToList(args.get("user_defined_application"))
        rule_disable = args.get("rule_disable", "false")

    response, request_body = client.appliance_sdwan_policy_rule_edit_request(
        organization,
        appliance_name,
        sdwan_policy_name,
        rule_name,
        description,
        tags,
        rule_disable,
        source_address_objects,
        destination_address_objects,
        url_reputation,
        custom_url_categories,
        forwarding_action,
        nexthop_ip,
        routing_instance,
        forwarding_profile,
        predefined_application,
        user_defined_application,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceSdwanPolicyRule",
        readable_output=f"Command run successfully.\nRequest Body:\n\n{request_body}",
    )
    return command_results


def appliance_sdwan_policy_rule_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    sdwan_policy_name = args.get("sdwan_policy_name", "")
    rule_name = args.get("rule_name", "")
    organization = set_organization(organization_args, client.organization_params)

    client.appliance_sdwan_policy_rule_delete_request(organization, appliance_name, sdwan_policy_name, rule_name)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceSdwanPolicyRule",
        readable_output="Command run successfully.",
    )
    return command_results


def template_address_object_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.template_address_object_list_request(organization, template_name, offset, limit)
    response = json.loads(xml2json((response.content))).get("collection", {}).get("address", {})
    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateAddressObject",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Address objects associated with {organization}",
            t=response,
            headerTransform=pascalToSpace,
            headers=[
                "name",
                "description",
                "tag",
                "ipv4-prefix",
                "fqdn",
                "ipv4-range",
                "ipv4-wildcard-mask",
                "ipv6-prefix",
                "dynamic-address",
            ],
            is_auto_json_transform=True,
            removeNull=True,
        ),
    )
    return command_results


def template_address_object_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    object_name = args.get("object_name", "")
    description = args.get("description", "")
    tags = argToList(args.get("tags"))
    address_object_type = args.get("address_object_type", "")
    object_value = args.get("object_value", "")

    organization = set_organization(organization_args, client.organization_params)

    message = "Command run successfully."

    try:
        response, request_body = client.template_address_object_create_request(
            organization,
            template_name,
            object_name,
            description,
            tags,
            address_object_type,
            object_value,
        )
    except DemistoException as e:
        if e.res.status_code == 409:
            message = ALREADY_EXISTS_MSG
            request_body = None, "Not available."

        else:
            raise e

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateAddressObject",
        readable_output=message + f"\nRequest Body:\n\n{request_body}",
    )
    return command_results


def template_address_object_edit_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    object_name = args.get("object_name", "")
    description = args.get("description", "")
    tags = argToList(args.get("tags"))
    address_object_type = args.get("address_object_type", "")
    object_value = args.get("object_value", "")

    organization = set_organization(organization_args, client.organization_params)

    response, request_body = client.template_address_object_edit_request(
        organization,
        template_name,
        object_name,
        description,
        tags,
        address_object_type,
        object_value,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateAddressObject",
        readable_output="Command run successfully.\nRequest Body:\n\n" + str(request_body),
    )
    return command_results


def template_address_object_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    object_name = args.get("object_name", "")

    organization = set_organization(organization_args, client.organization_params)

    client.template_address_object_delete_request(
        organization,
        template_name,
        object_name,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateAddressObject",
        readable_output="Command run successfully.",
    )
    return command_results


def appliance_address_object_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.appliance_address_object_list_request(organization, appliance_name, offset, limit)
    response = json.loads(xml2json((response.content))).get("collection", {}).get("address", {})
    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceAddressObject",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"Address objects associated with {organization}",
            t=response,
            headerTransform=pascalToSpace,
            headers=[
                "name",
                "description",
                "tag",
                "ipv4-prefix",
                "fqdn",
                "ipv4-range",
                "ipv4-wildcard-mask",
                "ipv6-prefix",
                "dynamic-address",
            ],
            is_auto_json_transform=True,
            removeNull=True,
        ),
    )
    return command_results


def appliance_address_object_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    object_name = args.get("object_name", "")
    description = args.get("description", "")
    tags = argToList(args.get("tags"))
    address_object_type = args.get("address_object_type", "")
    object_value = args.get("object_value", "")

    organization = set_organization(organization_args, client.organization_params)

    message = "Command run successfully."

    try:
        response, request_body = client.appliance_address_object_create_request(
            organization,
            appliance_name,
            object_name,
            description,
            tags,
            address_object_type,
            object_value,
        )
    except DemistoException as e:
        if e.res.status_code == 409:
            message = ALREADY_EXISTS_MSG
            request_body = None, "Not available."

        else:
            raise e

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceAddressObject",
        readable_output=message + f"\nRequest Body:\n\n{request_body}",
    )
    return command_results


def appliance_address_object_edit_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    object_name = args.get("object_name", "")
    description = args.get("description", "")
    tags = argToList(args.get("tags"))
    address_object_type = args.get("address_object_type", "")
    object_value = args.get("object_value", "")

    organization = set_organization(organization_args, client.organization_params)

    response, request_body = client.appliance_address_object_edit_request(
        organization,
        appliance_name,
        object_name,
        description,
        tags,
        address_object_type,
        object_value,
    )

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceAddressObject",
        readable_output="Command run successfully.\nRequest Body:\n\n" + str(request_body),
    )
    return command_results


def appliance_address_object_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    object_name = args.get("object_name", "")

    organization = set_organization(organization_args, client.organization_params)

    client.appliance_address_object_delete_request(organization, appliance_name, object_name)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceAddressObject",
        readable_output="Command run successfully.",
    )
    return command_results


def template_user_defined_application_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.template_user_defined_application_list_request(organization, template_name, offset, limit)
    response = json.loads(xml2json((response.content))).get("collection", {}).get("user-defined-application", {})
    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateUserDefinedApplication",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"User defined application objects associated with {organization}",
            t=response,
            headerTransform=pascalToSpace,
            headers=["app-name", "description", "precedence", "tag", "risk", "family"],
            is_auto_json_transform=True,
            removeNull=True,
        ),
    )
    return command_results


def appliance_user_defined_application_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.appliance_user_defined_application_list_request(organization, appliance_name, offset, limit)

    response = json.loads(xml2json((response.content))).get("collection", {}).get("user-defined-application", {})
    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceUserDefinedApplication",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"User defined application objects associated with {organization}",
            t=response,
            headerTransform=pascalToSpace,
            headers=["app-name", "description", "precedence", "tag", "risk", "family"],
            is_auto_json_transform=True,
            removeNull=True,
        ),
    )
    return command_results


def template_user_modified_application_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    template_name = args.get("template_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.template_user_modified_application_list_request(organization, template_name, offset, limit)
    response = json.loads(xml2json((response.content))).get("collection", {}).get("app-specific-option-list", {})
    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".TemplateUserModifiedApplication",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"User modified predefined application objects associated with {organization}",
            t=response,
            headerTransform=pascalToSpace,
            headers=[
                "app-name",
                "app-risk",
                "app-productivity",
                "app-timeout",
                "app-final-with-endpoint",
            ],
            is_auto_json_transform=True,
            removeNull=True,
        ),
    )
    return command_results


def appliance_user_modified_application_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_args = args.get("organization")
    appliance_name = args.get("appliance_name", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    organization = set_organization(organization_args, client.organization_params)

    response = client.appliance_user_modified_application_list_request(organization, appliance_name, offset, limit)

    response = json.loads(xml2json((response.content))).get("collection", {}).get("app-specific-option-list", {})
    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".ApplianceUserModifiedApplication",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name=f"User modified predefined application objects associated with {organization}",
            t=response,
            headerTransform=pascalToSpace,
            headers=[
                "app-name",
                "app-risk",
                "app-productivity",
                "app-timeout",
                "app-final-with-endpoint",
            ],
            is_auto_json_transform=True,
            removeNull=True,
        ),
    )
    return command_results


def predefined_application_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    family = args.get("family")
    risks = arg_to_number(args.get("risks"))
    tags = argToList(args.get("tags"))
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    offset = set_offset(page, page_size)

    check_limit(limit)

    response = client.predefined_application_list_request(family, risks, tags, offset, limit)

    command_results = CommandResults(
        outputs_prefix=VENDOR_NAME + ".PredefinedApplication",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name="User predefined application objects.",
            t=response,
            headerTransform=pascalToSpace,
            headers=[
                "name",
                "family",
                "subfamily",
                "description",
                "risk",
                "productivity",
                "tag",
            ],
            is_auto_json_transform=True,
            removeNull=True,
        ),
    )
    return command_results


def test_connectivity(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        client._http_request(
            method="GET",
            url_suffix="vnms/alarm/notification",
            params={"limit": 3, "offset": 0},
        )
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = "Authorization Error: make sure authentication parameters/arguments are correctly set."
        else:
            raise e
    return message


def test_module(use_token: bool):
    """
    Performs basic GET request to check if the API is reachable and authentication is successful.
    Returns ok if successful.
    """
    if use_token:
        raise Exception(
            "When using Auth Token authentication method, "
            "Please input Auth Token Parameters OR run '!vd-auth-start' command with the necessary arguments.\n"
            "Then run '!vd-auth-test' command to check valid connectivity using Auth Token authentication."
        )
    else:
        raise Exception(
            "When using Basic authentication method, "
            "Please make sure Username and Password are passed as parameters.\n"
            "Then run '!vd-auth-test' command to check valid connectivity using Basic authentication."
        )


# HEADING: """ MAIN FUNCTION """


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    use_token = params.get("use_token", False)
    port = PORT_AUTH if use_token else PORT_CREDENTIALS
    url = params.get("url", "")
    url = url[:-1] + f":{port}" if url.endswith("/") else url + f":{port}"
    context = get_integration_context()
    if context.get("context"):
        context = context.get("context")
    username = params.get("credentials", {}).get("identifier", "")
    password = params.get("credentials", {}).get("password", "")
    client_id = params.get("client_id") or context.get("client_id")
    client_secret = params.get("client_secret") or context.get("client_secret")
    access_token = params.get("access_token") or context.get("access_token")
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        # test from instance configuration is disabled. test_module will print a message according to the
        # authentication method chosen by the user and direct him to run the necessary commands/actions.
        if command == "test-module":
            return_results(test_module(use_token))

        auth, headers = create_client_header(use_token, username, password, client_id, client_secret, access_token)

        client = Client(
            server_url=url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            auth=auth,
            organization_params=params.get("organization"),
            client_id_param=params.get("client_id"),
            client_secret_param=params.get("access_token"),
        )

        # check auth token validity and if a refresh token is needed to obtain new auth token
        if use_token:
            if new_token := check_and_update_token(client, client_id, client_secret, context):
                client._headers = {"Authorization": f"Bearer {new_token}"}

        commands = {
            "vd-auth-start": handle_auth_token_command,
            "vd-auth-test": auth_test_command,
            "vd-appliance-list": appliance_list_command,
            "vd-organization-list": organization_list_command,
            "vd-organization-appliance-list": appliances_list_by_organization_command,
            "vd-appliance-group-list": appliances_group_list_by_organization_command,
            "vd-appliance-group-template-appliance-list": appliances_list_by_device_group_command,
            "vd-template-list": template_list_by_organization_command,
            "vd-datastore-template-list": template_list_by_datastore_command,
            "vd-application-service-template-list": application_service_template_list_command,
            "vd-template-change-commit": template_change_commit_command,
            "vd-template-custom-url-category-list": template_custom_url_category_list_command,
            "vd-template-custom-url-category-create": template_custom_url_category_create_command,
            "vd-template-custom-url-category-edit": template_custom_url_category_edit_command,
            "vd-template-custom-url-category-delete": template_custom_url_category_delete_command,
            "vd-appliance-custom-url-category-list": appliance_custom_url_category_list_command,
            "vd-appliance-custom-url-category-create": appliance_custom_url_category_create_command,
            "vd-appliance-custom-url-category-edit": appliance_custom_url_category_edit_command,
            "vd-appliance-custom-url-category-delete": appliance_custom_url_category_delete_command,
            "vd-template-access-policy-list": template_access_policy_list_command,
            "vd-template-access-policy-rule-list": template_access_policy_rule_list_command,
            "vd-template-access-policy-rule-create": template_access_policy_rule_create_command,
            "vd-template-access-policy-rule-edit": template_access_policy_rule_edit_command,
            "vd-template-access-policy-rule-delete": template_access_policy_rule_delete_command,
            "vd-appliance-access-policy-list": appliance_access_policy_list_command,
            "vd-appliance-access-policy-rule-list": appliance_access_policy_rule_list_command,
            "vd-appliance-access-policy-rule-create": appliance_access_policy_rule_create_command,
            "vd-appliance-access-policy-rule-edit": appliance_access_policy_rule_edit_command,
            "vd-appliance-access-policy-rule-delete": appliance_access_policy_rule_delete_command,
            "vd-template-sdwan-policy-list": template_sdwan_policy_list_command,
            "vd-template-sdwan-policy-rule-list": template_sdwan_policy_rule_list_command,
            "vd-template-sdwan-policy-rule-create": template_sdwan_policy_rule_create_command,
            "vd-template-sdwan-policy-rule-edit": template_sdwan_policy_rule_edit_command,
            "vd-template-sdwan-policy-rule-delete": template_sdwan_policy_rule_delete_command,
            "vd-appliance-sdwan-policy-list": appliance_sdwan_policy_list_command,
            "vd-appliance-sdwan-policy-rule-list": appliance_sdwan_policy_rule_list_command,
            "vd-appliance-sdwan-policy-rule-create": appliance_sdwan_policy_rule_create_command,
            "vd-appliance-sdwan-policy-rule-edit": appliance_sdwan_policy_rule_edit_command,
            "vd-appliance-sdwan-policy-rule-delete": appliance_sdwan_policy_rule_delete_command,
            "vd-template-address-object-list": template_address_object_list_command,
            "vd-template-address-object-create": template_address_object_create_command,
            "vd-template-address-object-edit": template_address_object_edit_command,
            "vd-template-address-object-delete": template_address_object_delete_command,
            "vd-appliance-address-object-list": appliance_address_object_list_command,
            "vd-appliance-address-object-create": appliance_address_object_create_command,
            "vd-appliance-address-object-edit": appliance_address_object_edit_command,
            "vd-appliance-address-object-delete": appliance_address_object_delete_command,
            "vd-template-user-defined-application-list": template_user_defined_application_list_command,
            "vd-appliance-user-defined-application-list": appliance_user_defined_application_list_command,
            "vd-template-user-modified-application-list": template_user_modified_application_list_command,
            "vd-appliance-user-modified-application-list": appliance_user_modified_application_list_command,
            "vd-predefined-application-list": predefined_application_list_command,
        }
        if command == "vd-template-change-commit":
            return_results(commands[command](args, client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")
    except DemistoException as e:
        if e.res and e.res.status_code == 204:
            return_results(f"Empty response has returned from {demisto.command()} command.\nMessage:\n{str(e)}")
        else:
            raise e
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

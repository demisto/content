import demistomock as demisto
from CommonServerPython import *
import time
from requests import Response

import urllib3
from urllib3 import exceptions as urllib3_exceptions


class AuthError(Exception):
    pass


Null = object()


def str_arg(args: Dict[str, Any], name: str, nullable=False):
    arg = args.get(name, "")
    if arg == "":
        return None
    if nullable and arg == "null":
        return Null
    return str(arg)


def int_arg(args: Dict[str, Any], name: str, nullable=False):
    arg = args.get(name, "")
    if arg == "":
        return None
    if nullable and arg == "null":
        return Null
    return arg_to_number(arg, arg_name=name)


def bool_arg(args: Dict[str, Any], name: str, nullable=False):
    arg = args.get(name, "")
    if arg == "":
        return None
    if nullable and arg == "null":
        return Null
    return argToBoolean(arg)


def list_arg(args: Dict[str, Any], name: str, nullable=False):
    arg = args.get(name, "")
    if arg == "":
        return None
    if nullable and arg == "null":
        return Null
    return argToList(arg)


def json_arg(args: Dict[str, Any], name: str, nullable=False):
    arg = args.get(name, "")
    if arg == "":
        return None
    if nullable and arg == "null":
        return Null
    return json.loads(arg)


def add_key_to_outputs(outputs: dict, key_name: str, key_val):
    if type(outputs) is dict and key_name not in outputs:
        outputs[key_name] = str(key_val)


def to_markdown(name: str, t):
    try:
        return tableToMarkdown(name, t)
    except Exception as e:
        return "Success (failed to format output: %s)" % str(e)


class Client(BaseClient):
    def __init__(self, auth_key, auth_user, is_password, server_url, verify, proxy, timeout):
        self._auth_key = auth_key
        self._auth_user = auth_user
        self._is_password = is_password

        timeout = timeout or BaseClient.REQUESTS_TIMEOUT

        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers={}, auth=None, timeout=timeout)

    def _raise_client_exc(self, res: Response):
        if res.status_code == 401:
            raise AuthError
        self.client_error_handler(res)

    def _convert_nulls(self, json_payload: dict):
        for key, value in json_payload.items():
            if value is Null:
                json_payload[key] = None

    def _http_request(self, *args, **kwargs):
        headers: dict = kwargs.get("headers", {})
        kwargs["headers"] = headers

        data = kwargs.get("json_data")
        if data:
            self._convert_nulls(data)

        first_auth = True
        token = get_session_token()
        if token:
            headers["Cookies"] = token
            first_auth = False
        else:
            if self._is_password:
                kwargs["auth"] = (self._auth_user, self._auth_key)
            else:
                headers["X-Auth-Key"] = self._auth_key
                headers["X-Auth-User"] = self._auth_user

        client_err_handler = None if first_auth else self._raise_client_exc  # no AuthError if first_auth is True

        try:
            resp: Response = super()._http_request(
                *args, **kwargs, resp_type="response", error_handler=client_err_handler  # type: ignore
            )
        except AuthError:  # AuthError is only raised when first_auth is False
            update_session_token(None)

            first_auth = True
            if self._is_password:
                kwargs["auth"] = (self._auth_user, self._auth_key)
            else:
                headers["X-Auth-Key"] = self._auth_key
                headers["X-Auth-User"] = self._auth_user

            # retry
            resp = super()._http_request(*args, **kwargs, resp_type="response")  # type: ignore

        if first_auth:
            token = resp.headers.get("Set-Cookie")

        update_session_token(token)

        if resp.status_code == 204:
            obj_id = resp.headers.get("x-object-id")
            if obj_id:
                return {"id": obj_id}
            return {}

        return resp.json()

    def add_session_target_to_target_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        account = str_arg(args, "account")
        domain = str_arg(args, "domain")
        domain_type = str_arg(args, "domain_type")
        device = str_arg(args, "device")
        service = str_arg(args, "service")
        application = str_arg(args, "application")
        session_account_type = str_arg(args, "session_account_type")

        data = assign_params(
            values_to_ignore=(None,),
            account=account,
            domain=domain,
            domain_type=domain_type,
            device=device,
            service=service,
            application=application,
        )
        key = {
            "account": "accounts",
            "account_mapping": "account_mappings",
            "interactive_login": "interactive_logins",
            "scenario_account": "scenario_accounts",
        }.get(session_account_type)
        if not key:
            raise DemistoException("unknown session_account_type: " + session_account_type)

        data = {"session": {key: [data]}}

        response = self._http_request("put", f"/targetgroups/{group_id}", json_data=data)

        return CommandResults(
            readable_output="Success!",
            raw_response=response,
        )

    def add_password_target_to_target_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        account = str_arg(args, "account")
        domain = str_arg(args, "domain")
        domain_type = str_arg(args, "domain_type")
        device = str_arg(args, "device")
        application = str_arg(args, "application")

        data = assign_params(
            values_to_ignore=(None,),
            account=account,
            domain=domain,
            domain_type=domain_type,
            device=device,
            application=application,
        )

        data = {"password_retrieval": {"accounts": [data]}}

        response = self._http_request("put", f"/targetgroups/{group_id}", json_data=data)

        return CommandResults(
            readable_output="Success!",
            raw_response=response,
        )

    def add_restriction_to_target_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        action = str_arg(args, "action")
        rules = str_arg(args, "rules")
        subprotocol = str_arg(args, "subprotocol")

        body = assign_params(
            values_to_ignore=(None,),
            action=action,
            rules=rules,
            subprotocol=subprotocol,
        )

        response = self._http_request("post", f"/targetgroups/{group_id}/restrictions", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_restriction_to_target_group",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-restriction-to-target-group", response),
            raw_response=response,
        )

    def add_timeframe_period(self, args: Dict[str, Any]):
        timeframe_id = str_arg(args, "timeframe_id")
        start_date = str_arg(args, "start_date")
        end_date = str_arg(args, "end_date")
        start_time = str_arg(args, "start_time")
        end_time = str_arg(args, "end_time")
        week_days = list_arg(args, "week_days")

        body = {
            "periods": [
                assign_params(
                    values_to_ignore=(None,),
                    start_date=start_date,
                    end_date=end_date,
                    start_time=start_time,
                    end_time=end_time,
                    week_days=week_days,
                )
            ]
        }

        response = self._http_request("put", f"/timeframes/{timeframe_id}", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def add_global_domain(self, args: Dict[str, Any]):
        domain_post_domain_name = str_arg(args, "domain_post_domain_name")
        domain_post_domain_real_name = str_arg(args, "domain_post_domain_real_name")
        domain_post_description = str_arg(args, "domain_post_description")
        domain_post_enable_password_change = bool_arg(args, "domain_post_enable_password_change")
        domain_post_kerberos_kdc = str_arg(args, "domain_post_kerberos_kdc")
        domain_post_kerberos_realm = str_arg(args, "domain_post_kerberos_realm")
        domain_post_kerberos_port = int_arg(args, "domain_post_kerberos_port")
        domain_post_password_change_policy = str_arg(args, "domain_post_password_change_policy", nullable=True)
        domain_post_password_change_plugin = str_arg(args, "domain_post_password_change_plugin", nullable=True)
        domain_post_password_change_plugin_parameters = json_arg(
            args, "domain_post_password_change_plugin_parameters", nullable=True
        )
        domain_post_ca_private_key = str_arg(args, "domain_post_ca_private_key")
        domain_post_passphrase = str_arg(args, "domain_post_passphrase")
        domain_post_vault_plugin = str_arg(args, "domain_post_vault_plugin", nullable=True)
        domain_post_vault_plugin_parameters = json_arg(args, "domain_post_vault_plugin_parameters", nullable=True)

        kerberos = assign_params(kdc=domain_post_kerberos_kdc, realm=domain_post_kerberos_realm, port=domain_post_kerberos_port)

        body = assign_params(
            values_to_ignore=(None,),
            domain_name=domain_post_domain_name,
            domain_real_name=domain_post_domain_real_name,
            description=domain_post_description,
            enable_password_change=domain_post_enable_password_change,
            kerberos=kerberos or None,
            password_change_policy=domain_post_password_change_policy,
            password_change_plugin=domain_post_password_change_plugin,
            password_change_plugin_parameters=domain_post_password_change_plugin_parameters,
            ca_private_key=domain_post_ca_private_key,
            passphrase=domain_post_passphrase,
            vault_plugin=domain_post_vault_plugin,
            vault_plugin_parameters=domain_post_vault_plugin_parameters,
        )
        response = self._http_request("post", "/domains", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_global_domain",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-global-domain", response),
            raw_response=response,
        )

    def get_account_references(self, args: Dict[str, Any]):
        account_id = str_arg(args, "account_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/accounts/{account_id}/references", params=params)

        return CommandResults(
            outputs_prefix="WAB.account_reference_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-account-references", response),
            raw_response=response,
        )

    def get_account_reference(self, args: Dict[str, Any]):
        account_id = str_arg(args, "account_id")
        reference_id = str_arg(args, "reference_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/accounts/{account_id}/references/{reference_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.account_reference_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-account-reference", response),
            raw_response=response,
        )

    def change_password_or_ssh_key_of_account(self, args: Dict[str, Any]):
        account_id = str_arg(args, "account_id")
        credential_type = str_arg(args, "credential_type")
        changePasswordOrSshKeyOfAccount_password = str_arg(args, "changePasswordOrSshKeyOfAccount_password")
        changePasswordOrSshKeyOfAccount_private_key = str_arg(args, "changePasswordOrSshKeyOfAccount_private_key")
        changePasswordOrSshKeyOfAccount_passphrase = str_arg(args, "changePasswordOrSshKeyOfAccount_passphrase")

        body = assign_params(
            values_to_ignore=(None,),
            password=changePasswordOrSshKeyOfAccount_password,
            private_key=changePasswordOrSshKeyOfAccount_private_key,
            passphrase=changePasswordOrSshKeyOfAccount_passphrase,
        )
        response = self._http_request("put", f"/accountchangepassword/{account_id}/{credential_type}", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_all_accounts(self, args: Dict[str, Any]):
        account_type = str_arg(args, "account_type")
        application = str_arg(args, "application")
        device = str_arg(args, "device")
        passwords = bool_arg(args, "passwords")
        key_format = str_arg(args, "key_format")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,),
            account_type=account_type,
            application=application,
            device=device,
            passwords=passwords,
            key_format=key_format,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        response = self._http_request("get", "/accounts", params=params)

        return CommandResults(
            outputs_prefix="WAB.account_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-all-accounts", response),
            raw_response=response,
        )

    def get_one_account(self, args: Dict[str, Any]):
        account_id = str_arg(args, "account_id")
        account_type = str_arg(args, "account_type")
        application = str_arg(args, "application")
        device = str_arg(args, "device")
        passwords = bool_arg(args, "passwords")
        key_format = str_arg(args, "key_format")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,),
            account_type=account_type,
            application=application,
            device=device,
            passwords=passwords,
            key_format=key_format,
            fields=fields,
        )
        response = self._http_request("get", f"/accounts/{account_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.account_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-one-account", response),
            raw_response=response,
        )

    def delete_account(self, args: Dict[str, Any]):
        account_id = str_arg(args, "account_id")

        response = self._http_request("delete", f"/accounts/{account_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_application_account_credentials(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request(
            "get", f"/applications/{application_id}/localdomains/{domain_id}/accounts/{account_id}/credentials", params=params
        )

        return CommandResults(
            outputs_prefix="WAB.app_account_credential_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-application-account-credentials", response),
            raw_response=response,
        )

    def add_credential_to_application_account(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        app_account_credential_post_password = str_arg(args, "app_account_credential_post_password")
        app_account_credential_post_type = "password"

        body = assign_params(
            values_to_ignore=(None,), type=app_account_credential_post_type, password=app_account_credential_post_password
        )
        response = self._http_request(
            "post", f"/applications/{application_id}/localdomains/{domain_id}/accounts/{account_id}/credentials", json_data=body
        )

        return CommandResults(
            outputs_prefix="WAB.add_credential_to_application_account",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-credential-to-application-account", response),
            raw_response=response,
        )

    def get_application_account_credential(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        credential_id = str_arg(args, "credential_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request(
            "get",
            f"/applications/{application_id}/localdomains/{domain_id}/accounts/{account_id}/credentials/{credential_id}",
            params=params,
        )

        return CommandResults(
            outputs_prefix="WAB.app_account_credential_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-application-account-credential", response),
            raw_response=response,
        )

    def edit_credential_of_application_account(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        credential_id = str_arg(args, "credential_id")
        app_account_credential_put_password = str_arg(args, "app_account_credential_put_password")
        app_account_credential_put_type = "password"

        body = assign_params(
            values_to_ignore=(None,), type=app_account_credential_put_type, password=app_account_credential_put_password
        )
        response = self._http_request(
            "put",
            f"/applications/{application_id}/localdomains/{domain_id}/accounts/{account_id}/credentials/{credential_id}",
            json_data=body,
        )

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_application_accounts(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        domain_id = str_arg(args, "domain_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/applications/{application_id}/localdomains/{domain_id}/accounts", params=params)

        return CommandResults(
            outputs_prefix="WAB.app_account_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-application-accounts", response),
            raw_response=response,
        )

    def add_account_to_local_domain_of_application(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        domain_id = str_arg(args, "domain_id")
        app_account_post_account_name = str_arg(args, "app_account_post_account_name")
        app_account_post_account_login = str_arg(args, "app_account_post_account_login")
        app_account_post_description = str_arg(args, "app_account_post_description")
        app_account_post_auto_change_password = bool_arg(args, "app_account_post_auto_change_password")
        app_account_post_checkout_policy = str_arg(args, "app_account_post_checkout_policy")
        app_account_post_certificate_validity = str_arg(args, "app_account_post_certificate_validity")
        app_account_post_can_edit_certificate_validity = bool_arg(args, "app_account_post_can_edit_certificate_validity")

        body = assign_params(
            values_to_ignore=(None,),
            account_name=app_account_post_account_name,
            account_login=app_account_post_account_login,
            description=app_account_post_description,
            auto_change_password=app_account_post_auto_change_password,
            checkout_policy=app_account_post_checkout_policy,
            certificate_validity=app_account_post_certificate_validity,
            can_edit_certificate_validity=app_account_post_can_edit_certificate_validity,
        )
        response = self._http_request("post", f"/applications/{application_id}/localdomains/{domain_id}/accounts", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_account_to_local_domain_of_application",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-account-to-local-domain-of-application", response),
            raw_response=response,
        )

    def get_application_account(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request(
            "get", f"/applications/{application_id}/localdomains/{domain_id}/accounts/{account_id}", params=params
        )

        return CommandResults(
            outputs_prefix="WAB.app_account_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-application-account", response),
            raw_response=response,
        )

    def edit_account_on_local_domain_of_application(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        force = bool_arg(args, "force")
        app_account_put_account_name = str_arg(args, "app_account_put_account_name")
        app_account_put_account_login = str_arg(args, "app_account_put_account_login")
        app_account_put_description = str_arg(args, "app_account_put_description")
        app_account_put_auto_change_password = bool_arg(args, "app_account_put_auto_change_password")
        app_account_put_checkout_policy = str_arg(args, "app_account_put_checkout_policy")
        app_account_put_certificate_validity = str_arg(args, "app_account_put_certificate_validity")
        app_account_put_can_edit_certificate_validity = bool_arg(args, "app_account_put_can_edit_certificate_validity")
        app_account_put_onboard_status = str_arg(args, "app_account_put_onboard_status")

        params = assign_params(values_to_ignore=(None,), force=force)
        body = assign_params(
            values_to_ignore=(None,),
            account_name=app_account_put_account_name,
            account_login=app_account_put_account_login,
            description=app_account_put_description,
            auto_change_password=app_account_put_auto_change_password,
            checkout_policy=app_account_put_checkout_policy,
            certificate_validity=app_account_put_certificate_validity,
            can_edit_certificate_validity=app_account_put_can_edit_certificate_validity,
            onboard_status=app_account_put_onboard_status,
        )
        response = self._http_request(
            "put", f"/applications/{application_id}/localdomains/{domain_id}/accounts/{account_id}", params=params, json_data=body
        )

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_account_from_local_domain_of_application(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")

        response = self._http_request("delete", f"/applications/{application_id}/localdomains/{domain_id}/accounts/{account_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_local_domains_data_for_application(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/applications/{application_id}/localdomains", params=params)

        return CommandResults(
            outputs_prefix="WAB.localdomain_app_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-local-domains-data-for-application", response),
            raw_response=response,
        )

    def add_local_domain_in_application(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        localdomain_app_post_domain_name = str_arg(args, "localdomain_app_post_domain_name")
        localdomain_app_post_description = str_arg(args, "localdomain_app_post_description")
        localdomain_app_post_enable_password_change = bool_arg(args, "localdomain_app_post_enable_password_change")
        localdomain_app_post_password_change_policy = str_arg(args, "localdomain_app_post_password_change_policy", nullable=True)
        localdomain_app_post_password_change_plugin = str_arg(args, "localdomain_app_post_password_change_plugin", nullable=True)
        password_change_plugin_parameters = json_arg(args, "password_change_plugin_parameters")

        body = assign_params(
            values_to_ignore=(None,),
            domain_name=localdomain_app_post_domain_name,
            description=localdomain_app_post_description,
            enable_password_change=localdomain_app_post_enable_password_change,
            password_change_policy=localdomain_app_post_password_change_policy,
            password_change_plugin=localdomain_app_post_password_change_plugin,
            password_change_plugin_parameters=password_change_plugin_parameters,
        )
        response = self._http_request("post", f"/applications/{application_id}/localdomains", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_local_domain_in_application",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-local-domain-in-application", response),
            raw_response=response,
        )

    def get_local_domain_data_for_application(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        domain_id = str_arg(args, "domain_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/applications/{application_id}/localdomains/{domain_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.localdomain_app_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-local-domain-data-for-application", response),
            raw_response=response,
        )

    def delete_local_domain_from_application(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        domain_id = str_arg(args, "domain_id")

        response = self._http_request("delete", f"/applications/{application_id}/localdomains/{domain_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_applications(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/applications", params=params)

        return CommandResults(
            outputs_prefix="WAB.application_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-applications", response),
            raw_response=response,
        )

    def get_application(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/applications/{application_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.application_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-application", response),
            raw_response=response,
        )

    def edit_application(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")
        force = bool_arg(args, "force")
        application_put_application_name = str_arg(args, "application_put_application_name")
        application_put_description = str_arg(args, "application_put_description")
        application_put_parameters = str_arg(args, "application_put_parameters")
        application_put_global_domains = list_arg(args, "application_put_global_domains")
        application_put_connection_policy = str_arg(args, "application_put_connection_policy")

        params = assign_params(values_to_ignore=(None,), force=force)
        body = assign_params(
            values_to_ignore=(None,),
            application_name=application_put_application_name,
            description=application_put_description,
            parameters=application_put_parameters,
            global_domains=application_put_global_domains,
            connection_policy=application_put_connection_policy,
        )
        response = self._http_request("put", f"/applications/{application_id}", params=params, json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_application(self, args: Dict[str, Any]):
        application_id = str_arg(args, "application_id")

        response = self._http_request("delete", f"/applications/{application_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_approvals(self, args: Dict[str, Any]):
        approval_id = str_arg(args, "approval_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,), approval_id=approval_id, q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        response = self._http_request("get", "/approvals", params=params)

        return CommandResults(
            outputs_prefix="WAB.approval_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-approvals", response),
            raw_response=response,
        )

    def get_approvals_for_all_approvers(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/approvals/assignments", params=params)

        return CommandResults(
            outputs_prefix="WAB.approval_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-approvals-for-all-approvers", response),
            raw_response=response,
        )

    def reply_to_approval_request(self, args: Dict[str, Any]):
        approval_assignment_post_id = str_arg(args, "approval_assignment_post_id")
        approval_assignment_post_comment = str_arg(args, "approval_assignment_post_comment")
        approval_assignment_post_duration = int_arg(args, "approval_assignment_post_duration")
        approval_assignment_post_timeout = int_arg(args, "approval_assignment_post_timeout")
        approval_assignment_post_approved = bool_arg(args, "approval_assignment_post_approved")
        approval_assignment_post_is_active = bool_arg(args, "approval_assignment_post_is_active")
        approval_assignment_post_status = str_arg(args, "approval_assignment_post_status")

        body = assign_params(
            values_to_ignore=(None,),
            id=approval_assignment_post_id,
            comment=approval_assignment_post_comment,
            duration=approval_assignment_post_duration,
            timeout=approval_assignment_post_timeout,
            approved=approval_assignment_post_approved,
            is_active=approval_assignment_post_is_active,
            status=approval_assignment_post_status,
        )
        response = self._http_request("post", "/approvals/assignments", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.reply_to_approval_request",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-reply-to-approval-request", response),
            raw_response=response,
        )

    def get_approvals_for_approver(self, args: Dict[str, Any]):
        user_name = str_arg(args, "user_name")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/approvals/assignments/{user_name}", params=params)

        return CommandResults(
            outputs_prefix="WAB.approval_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-approvals-for-approver", response),
            raw_response=response,
        )

    def cancel_accepted_approval(self, args: Dict[str, Any]):
        approval_assignment_cancel_post_id = str_arg(args, "approval_assignment_cancel_post_id")
        approval_assignment_cancel_post_comment = str_arg(args, "approval_assignment_cancel_post_comment")

        body = assign_params(
            values_to_ignore=(None,), id=approval_assignment_cancel_post_id, comment=approval_assignment_cancel_post_comment
        )
        response = self._http_request("post", "/approvals/assignments/cancel", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.cancel_accepted_approval",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-cancel-accepted-approval", response),
            raw_response=response,
        )

    def notify_approvers_linked_to_approval_assignment(self, args: Dict[str, Any]):
        approval_assignment_notify_post_id = str_arg(args, "approval_assignment_notify_post_id")

        body = assign_params(values_to_ignore=(None,), id=approval_assignment_notify_post_id)
        response = self._http_request("post", "/approvals/assignments/notify", json_data=body)

        add_key_to_outputs(response, "approval_assignment_notify_post_id", approval_assignment_notify_post_id)

        return CommandResults(
            outputs_prefix="WAB.approval_assignment_notify_post_response",
            outputs_key_field="approval_assignment_notify_post_id",
            outputs=response,
            readable_output=to_markdown("wab-notify-approvers-linked-to-approval-assignment", response),
            raw_response=response,
        )

    def get_approval_request_pending_for_user(self, args: Dict[str, Any]):
        user = str_arg(args, "user")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")
        approval_id = str_arg(args, "approval_id")

        params = assign_params(
            values_to_ignore=(None,),
            user=user,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
            approval_id=approval_id,
        )
        response = self._http_request("get", "/approvals/requests", params=params)

        return CommandResults(
            outputs_prefix="WAB.approval_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-approval-request-pending-for-user", response),
            raw_response=response,
        )

    def make_new_approval_request_to_access_target(self, args: Dict[str, Any]):
        approval_request_post_target_name = str_arg(args, "approval_request_post_target_name")
        approval_request_post_authorization = str_arg(args, "approval_request_post_authorization")
        approval_request_post_account = str_arg(args, "approval_request_post_account")
        approval_request_post_domain = str_arg(args, "approval_request_post_domain")
        approval_request_post_device = str_arg(args, "approval_request_post_device")
        approval_request_post_application = str_arg(args, "approval_request_post_application")
        approval_request_post_service = str_arg(args, "approval_request_post_service")
        approval_request_post_ticket = str_arg(args, "approval_request_post_ticket")
        approval_request_post_comment = str_arg(args, "approval_request_post_comment")
        approval_request_post_begin = str_arg(args, "approval_request_post_begin")
        approval_request_post_duration = int_arg(args, "approval_request_post_duration")

        body = assign_params(
            values_to_ignore=(None,),
            target_name=approval_request_post_target_name,
            authorization=approval_request_post_authorization,
            account=approval_request_post_account,
            domain=approval_request_post_domain,
            device=approval_request_post_device,
            application=approval_request_post_application,
            service=approval_request_post_service,
            ticket=approval_request_post_ticket,
            comment=approval_request_post_comment,
            begin=approval_request_post_begin,
            duration=approval_request_post_duration,
        )
        response = self._http_request("post", "/approvals/requests", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.approval_request_post_response_ok",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-make-new-approval-request-to-access-target", response),
            raw_response=response,
        )

    def cancel_approval_request(self, args: Dict[str, Any]):
        approval_request_cancel_post_id = str_arg(args, "approval_request_cancel_post_id")

        body = assign_params(values_to_ignore=(None,), id=approval_request_cancel_post_id)
        response = self._http_request("post", "/approvals/requests/cancel", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.cancel_approval_request",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-cancel-approval-request", response),
            raw_response=response,
        )

    def notify_approvers_linked_to_approval_request(self, args: Dict[str, Any]):
        approval_request_notify_post_id = str_arg(args, "approval_request_notify_post_id")

        body = assign_params(values_to_ignore=(None,), id=approval_request_notify_post_id)
        response = self._http_request("post", "/approvals/requests/notify", json_data=body)

        add_key_to_outputs(response, "approval_request_notify_post_id", approval_request_notify_post_id)

        return CommandResults(
            outputs_prefix="WAB.approval_request_notify_post_response",
            outputs_key_field="approval_request_notify_post_id",
            outputs=response,
            readable_output=to_markdown("wab-notify-approvers-linked-to-approval-request", response),
            raw_response=response,
        )

    def check_if_approval_is_required_for_target(self, args: Dict[str, Any]):
        target_name = str_arg(args, "target_name")
        authorization = str_arg(args, "authorization")
        begin = str_arg(args, "begin")

        params = assign_params(values_to_ignore=(None,), authorization=authorization, begin=begin)
        response = self._http_request("get", f"/approvals/requests/target/{target_name}", params=params)

        return CommandResults(
            outputs_prefix="WAB.approval_request_target_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-check-if-approval-is-required-for-target", response),
            raw_response=response,
        )

    def get_mappings_of_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/authdomains/{domain_id}/mappings", params=params)

        return CommandResults(
            outputs_prefix="WAB.authdomain_mapping_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-mappings-of-domain", response),
            raw_response=response,
        )

    def add_mapping_in_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        authdomain_mapping_post_domain = str_arg(args, "authdomain_mapping_post_domain")
        authdomain_mapping_post_user_group = str_arg(args, "authdomain_mapping_post_user_group")
        authdomain_mapping_post_external_group = str_arg(args, "authdomain_mapping_post_external_group")

        body = assign_params(
            values_to_ignore=(None,),
            domain=authdomain_mapping_post_domain,
            user_group=authdomain_mapping_post_user_group,
            external_group=authdomain_mapping_post_external_group,
        )
        response = self._http_request("post", f"/authdomains/{domain_id}/mappings", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_mapping_in_domain",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-mapping-in-domain", response),
            raw_response=response,
        )

    def edit_mappings_of_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        authdomain_mapping_put_domain = str_arg(args, "authdomain_mapping_put_domain")
        authdomain_mapping_put_user_group = str_arg(args, "authdomain_mapping_put_user_group")
        authdomain_mapping_put_external_group = str_arg(args, "authdomain_mapping_put_external_group")

        body = assign_params(
            values_to_ignore=(None,),
            domain=authdomain_mapping_put_domain,
            user_group=authdomain_mapping_put_user_group,
            external_group=authdomain_mapping_put_external_group,
        )
        response = self._http_request("put", f"/authdomains/{domain_id}/mappings", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_mapping_of_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        mapping_id = str_arg(args, "mapping_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/authdomains/{domain_id}/mappings/{mapping_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.authdomain_mapping_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-mapping-of-domain", response),
            raw_response=response,
        )

    def edit_mapping_of_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        mapping_id = str_arg(args, "mapping_id")
        authdomain_mapping_put_domain = str_arg(args, "authdomain_mapping_put_domain")
        authdomain_mapping_put_user_group = str_arg(args, "authdomain_mapping_put_user_group")
        authdomain_mapping_put_external_group = str_arg(args, "authdomain_mapping_put_external_group")

        body = assign_params(
            values_to_ignore=(None,),
            domain=authdomain_mapping_put_domain,
            user_group=authdomain_mapping_put_user_group,
            external_group=authdomain_mapping_put_external_group,
        )
        response = self._http_request("put", f"/authdomains/{domain_id}/mappings/{mapping_id}", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_mapping_of_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        mapping_id = str_arg(args, "mapping_id")

        response = self._http_request("delete", f"/authdomains/{domain_id}/mappings/{mapping_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_auth_domains(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/authdomains", params=params)

        return CommandResults(
            outputs_prefix="WAB.auth_domain_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-auth-domains", response),
            raw_response=response,
        )

    def get_auth_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/authdomains/{domain_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.auth_domain_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-auth-domain", response),
            raw_response=response,
        )

    def get_authentications(self, args: Dict[str, Any]):
        from_date = str_arg(args, "from_date")
        to_date = str_arg(args, "to_date")
        date_field = str_arg(args, "date_field")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,),
            from_date=from_date,
            to_date=to_date,
            date_field=date_field,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        response = self._http_request("get", "/authentications", params=params)

        return CommandResults(
            outputs_prefix="WAB.authentication_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-authentications", response),
            raw_response=response,
        )

    def get_authentication(self, args: Dict[str, Any]):
        auth_id = str_arg(args, "auth_id")
        from_date = str_arg(args, "from_date")
        to_date = str_arg(args, "to_date")
        date_field = str_arg(args, "date_field")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,), from_date=from_date, to_date=to_date, date_field=date_field, fields=fields
        )
        response = self._http_request("get", f"/authentications/{auth_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.authentication_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-authentication", response),
            raw_response=response,
        )

    def get_authorizations(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/authorizations", params=params)

        return CommandResults(
            outputs_prefix="WAB.authorization_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-authorizations", response),
            raw_response=response,
        )

    def add_authorization(self, args: Dict[str, Any]):
        authorization_post_user_group = str_arg(args, "authorization_post_user_group")
        authorization_post_target_group = str_arg(args, "authorization_post_target_group")
        authorization_post_authorization_name = str_arg(args, "authorization_post_authorization_name")
        authorization_post_description = str_arg(args, "authorization_post_description")
        authorization_post_subprotocols = list_arg(args, "authorization_post_subprotocols")
        authorization_post_is_critical = bool_arg(args, "authorization_post_is_critical")
        authorization_post_is_recorded = bool_arg(args, "authorization_post_is_recorded")
        authorization_post_authorize_password_retrieval = bool_arg(args, "authorization_post_authorize_password_retrieval")
        authorization_post_authorize_sessions = bool_arg(args, "authorization_post_authorize_sessions")
        authorization_post_approval_required = bool_arg(args, "authorization_post_approval_required")
        authorization_post_has_comment = bool_arg(args, "authorization_post_has_comment")
        authorization_post_mandatory_comment = bool_arg(args, "authorization_post_mandatory_comment")
        authorization_post_has_ticket = bool_arg(args, "authorization_post_has_ticket")
        authorization_post_mandatory_ticket = bool_arg(args, "authorization_post_mandatory_ticket")
        authorization_post_approvers = list_arg(args, "authorization_post_approvers")
        authorization_post_active_quorum = int_arg(args, "authorization_post_active_quorum")
        authorization_post_inactive_quorum = int_arg(args, "authorization_post_inactive_quorum")
        authorization_post_single_connection = bool_arg(args, "authorization_post_single_connection")
        authorization_post_approval_timeout = int_arg(args, "authorization_post_approval_timeout")
        authorization_post_authorize_session_sharing = bool_arg(args, "authorization_post_authorize_session_sharing")
        authorization_post_session_sharing_mode = str_arg(args, "authorization_post_session_sharing_mode")

        body = assign_params(
            values_to_ignore=(None,),
            user_group=authorization_post_user_group,
            target_group=authorization_post_target_group,
            authorization_name=authorization_post_authorization_name,
            description=authorization_post_description,
            subprotocols=authorization_post_subprotocols,
            is_critical=authorization_post_is_critical,
            is_recorded=authorization_post_is_recorded,
            authorize_password_retrieval=authorization_post_authorize_password_retrieval,
            authorize_sessions=authorization_post_authorize_sessions,
            approval_required=authorization_post_approval_required,
            has_comment=authorization_post_has_comment,
            mandatory_comment=authorization_post_mandatory_comment,
            has_ticket=authorization_post_has_ticket,
            mandatory_ticket=authorization_post_mandatory_ticket,
            approvers=authorization_post_approvers,
            active_quorum=authorization_post_active_quorum,
            inactive_quorum=authorization_post_inactive_quorum,
            single_connection=authorization_post_single_connection,
            approval_timeout=authorization_post_approval_timeout,
            authorize_session_sharing=authorization_post_authorize_session_sharing,
            session_sharing_mode=authorization_post_session_sharing_mode,
        )
        response = self._http_request("post", "/authorizations", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_authorization",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-authorization", response),
            raw_response=response,
        )

    def get_authorization(self, args: Dict[str, Any]):
        authorization_id = str_arg(args, "authorization_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/authorizations/{authorization_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.authorization_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-authorization", response),
            raw_response=response,
        )

    def edit_authorization(self, args: Dict[str, Any]):
        authorization_id = str_arg(args, "authorization_id")
        force = bool_arg(args, "force")
        authorization_put_authorization_name = str_arg(args, "authorization_put_authorization_name")
        authorization_put_description = str_arg(args, "authorization_put_description")
        authorization_put_subprotocols = list_arg(args, "authorization_put_subprotocols")
        authorization_put_is_critical = bool_arg(args, "authorization_put_is_critical")
        authorization_put_is_recorded = bool_arg(args, "authorization_put_is_recorded")
        authorization_put_authorize_password_retrieval = bool_arg(args, "authorization_put_authorize_password_retrieval")
        authorization_put_authorize_sessions = bool_arg(args, "authorization_put_authorize_sessions")
        authorization_put_approval_required = bool_arg(args, "authorization_put_approval_required")
        authorization_put_has_comment = bool_arg(args, "authorization_put_has_comment")
        authorization_put_mandatory_comment = bool_arg(args, "authorization_put_mandatory_comment")
        authorization_put_has_ticket = bool_arg(args, "authorization_put_has_ticket")
        authorization_put_mandatory_ticket = bool_arg(args, "authorization_put_mandatory_ticket")
        authorization_put_approvers = list_arg(args, "authorization_put_approvers")
        authorization_put_active_quorum = int_arg(args, "authorization_put_active_quorum")
        authorization_put_inactive_quorum = int_arg(args, "authorization_put_inactive_quorum")
        authorization_put_single_connection = bool_arg(args, "authorization_put_single_connection")
        authorization_put_approval_timeout = int_arg(args, "authorization_put_approval_timeout")
        authorization_put_authorize_session_sharing = bool_arg(args, "authorization_put_authorize_session_sharing")
        authorization_put_session_sharing_mode = str_arg(args, "authorization_put_session_sharing_mode")

        params = assign_params(values_to_ignore=(None,), force=force)
        body = assign_params(
            values_to_ignore=(None,),
            authorization_name=authorization_put_authorization_name,
            description=authorization_put_description,
            subprotocols=authorization_put_subprotocols,
            is_critical=authorization_put_is_critical,
            is_recorded=authorization_put_is_recorded,
            authorize_password_retrieval=authorization_put_authorize_password_retrieval,
            authorize_sessions=authorization_put_authorize_sessions,
            approval_required=authorization_put_approval_required,
            has_comment=authorization_put_has_comment,
            mandatory_comment=authorization_put_mandatory_comment,
            has_ticket=authorization_put_has_ticket,
            mandatory_ticket=authorization_put_mandatory_ticket,
            approvers=authorization_put_approvers,
            active_quorum=authorization_put_active_quorum,
            inactive_quorum=authorization_put_inactive_quorum,
            single_connection=authorization_put_single_connection,
            approval_timeout=authorization_put_approval_timeout,
            authorize_session_sharing=authorization_put_authorize_session_sharing,
            session_sharing_mode=authorization_put_session_sharing_mode,
        )
        response = self._http_request("put", f"/authorizations/{authorization_id}", params=params, json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_authorization(self, args: Dict[str, Any]):
        authorization_id = str_arg(args, "authorization_id")

        response = self._http_request("delete", f"/authorizations/{authorization_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_checkout_policies(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/checkoutpolicies", params=params)

        return CommandResults(
            outputs_prefix="WAB.checkoutpolicy_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-checkout-policies", response),
            raw_response=response,
        )

    def get_checkout_policy(self, args: Dict[str, Any]):
        checkout_policy_id = str_arg(args, "checkout_policy_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/checkoutpolicies/{checkout_policy_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.checkoutpolicy_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-checkout-policy", response),
            raw_response=response,
        )

    def get_clusters(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/clusters", params=params)

        return CommandResults(
            outputs_prefix="WAB.cluster_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-clusters", response),
            raw_response=response,
        )

    def get_cluster(self, args: Dict[str, Any]):
        cluster_id = str_arg(args, "cluster_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/clusters/{cluster_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.cluster_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-cluster", response),
            raw_response=response,
        )

    def getx509_configuration_infos(self, args: Dict[str, Any]):

        response = self._http_request("get", "/config/x509")

        return CommandResults(
            outputs_prefix="WAB.config_x509_get",
            outputs=response,
            readable_output=to_markdown("wab-getx509-configuration-infos", response),
            raw_response=response,
        )

    def uploadx509_configuration(self, args: Dict[str, Any]):
        config_x509_post_ca_certificate = str_arg(args, "config_x509_post_ca_certificate")
        config_x509_post_server_public_key = str_arg(args, "config_x509_post_server_public_key")
        config_x509_post_server_private_key = str_arg(args, "config_x509_post_server_private_key")
        config_x509_post_enable = bool_arg(args, "config_x509_post_enable")

        body = assign_params(
            values_to_ignore=(None,),
            ca_certificate=config_x509_post_ca_certificate,
            server_public_key=config_x509_post_server_public_key,
            server_private_key=config_x509_post_server_private_key,
            enable=config_x509_post_enable,
        )
        response = self._http_request("post", "/config/x509", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.uploadx509_configuration",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-uploadx509-configuration", response),
            raw_response=response,
        )

    def updatex509_configuration(self, args: Dict[str, Any]):
        config_x509_put_ca_certificate = str_arg(args, "config_x509_put_ca_certificate")
        config_x509_put_server_public_key = str_arg(args, "config_x509_put_server_public_key")
        config_x509_put_server_private_key = str_arg(args, "config_x509_put_server_private_key")
        config_x509_put_enable = bool_arg(args, "config_x509_put_enable")

        body = assign_params(
            values_to_ignore=(None,),
            ca_certificate=config_x509_put_ca_certificate,
            server_public_key=config_x509_put_server_public_key,
            server_private_key=config_x509_put_server_private_key,
            enable=config_x509_put_enable,
        )
        response = self._http_request("put", "/config/x509", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def resetx509_configuration(self, args: Dict[str, Any]):

        response = self._http_request("delete", "/config/x509")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_current_serial_configuration_number_of_bastion(self, args: Dict[str, Any]):

        response = self._http_request("get", "/confignumber")

        return CommandResults(
            outputs_prefix="WAB.confignumber_get",
            outputs=response,
            readable_output=to_markdown("wab-get-current-serial-configuration-number-of-bastion", response),
            raw_response=response,
        )

    def get_connection_policies(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/connectionpolicies", params=params)

        return CommandResults(
            outputs_prefix="WAB.connectionpolicy_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-connection-policies", response),
            raw_response=response,
        )

    def add_connection_policy(self, args: Dict[str, Any]):
        connectionpolicy_post_connection_policy_name = str_arg(args, "connectionpolicy_post_connection_policy_name")
        connectionpolicy_post_type = str_arg(args, "connectionpolicy_post_type")
        connectionpolicy_post_description = str_arg(args, "connectionpolicy_post_description")
        connectionpolicy_post_protocol = str_arg(args, "connectionpolicy_post_protocol")
        connectionpolicy_post_authentication_methods = list_arg(args, "connectionpolicy_post_authentication_methods")
        options = json_arg(args, "options")

        body = assign_params(
            values_to_ignore=(None,),
            connection_policy_name=connectionpolicy_post_connection_policy_name,
            type=connectionpolicy_post_type,
            description=connectionpolicy_post_description,
            protocol=connectionpolicy_post_protocol,
            authentication_methods=connectionpolicy_post_authentication_methods,
            options=options,
        )
        response = self._http_request("post", "/connectionpolicies", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_connection_policy",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-connection-policy", response),
            raw_response=response,
        )

    def get_connection_policy(self, args: Dict[str, Any]):
        connection_policy_id = str_arg(args, "connection_policy_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/connectionpolicies/{connection_policy_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.connectionpolicy_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-connection-policy", response),
            raw_response=response,
        )

    def edit_connection_policy(self, args: Dict[str, Any]):
        connection_policy_id = str_arg(args, "connection_policy_id")
        force = bool_arg(args, "force")
        connectionpolicy_put_connection_policy_name = str_arg(args, "connectionpolicy_put_connection_policy_name")
        connectionpolicy_put_description = str_arg(args, "connectionpolicy_put_description")
        connectionpolicy_put_authentication_methods = list_arg(args, "connectionpolicy_put_authentication_methods")
        options = json_arg(args, "options")

        params = assign_params(values_to_ignore=(None,), force=force)
        body = assign_params(
            values_to_ignore=(None,),
            connection_policy_name=connectionpolicy_put_connection_policy_name,
            description=connectionpolicy_put_description,
            authentication_methods=connectionpolicy_put_authentication_methods,
            options=options,
        )
        response = self._http_request("put", f"/connectionpolicies/{connection_policy_id}", params=params, json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_connection_policy(self, args: Dict[str, Any]):
        connection_policy_id = str_arg(args, "connection_policy_id")

        response = self._http_request("delete", f"/connectionpolicies/{connection_policy_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_device_account_credentials(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        key_format = str_arg(args, "key_format")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,), key_format=key_format, q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        response = self._http_request(
            "get", f"/devices/{device_id}/localdomains/{domain_id}/accounts/{account_id}/credentials", params=params
        )

        return CommandResults(
            outputs_prefix="WAB.credential_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-device-account-credentials", response),
            raw_response=response,
        )

    def add_credential_to_device_account(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        credential_post_type = str_arg(args, "credential_post_type")
        credential_post_password = str_arg(args, "credential_post_password")
        credential_post_private_key = str_arg(args, "credential_post_private_key")
        credential_post_passphrase = str_arg(args, "credential_post_passphrase")

        body = assign_params(
            values_to_ignore=(None,),
            type=credential_post_type,
            password=credential_post_password,
            private_key=credential_post_private_key,
            passphrase=credential_post_passphrase,
        )
        response = self._http_request(
            "post", f"/devices/{device_id}/localdomains/{domain_id}/accounts/{account_id}/credentials", json_data=body
        )

        return CommandResults(
            outputs_prefix="WAB.add_credential_to_device_account",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-credential-to-device-account", response),
            raw_response=response,
        )

    def get_device_account_credential(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        credential_id = str_arg(args, "credential_id")
        key_format = str_arg(args, "key_format")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), key_format=key_format, fields=fields)
        response = self._http_request(
            "get",
            f"/devices/{device_id}/localdomains/{domain_id}/accounts/{account_id}/credentials/{credential_id}",
            params=params,
        )

        return CommandResults(
            outputs_prefix="WAB.credential_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-device-account-credential", response),
            raw_response=response,
        )

    def edit_credential_of_device_account(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        credential_id = str_arg(args, "credential_id")
        credential_put_type = str_arg(args, "credential_put_type")
        credential_put_password = str_arg(args, "credential_put_password")
        credential_put_private_key = str_arg(args, "credential_put_private_key")
        credential_put_passphrase = str_arg(args, "credential_put_passphrase")

        body = assign_params(
            values_to_ignore=(None,),
            type=credential_put_type,
            password=credential_put_password,
            private_key=credential_put_private_key,
            passphrase=credential_put_passphrase,
        )
        response = self._http_request(
            "put",
            f"/devices/{device_id}/localdomains/{domain_id}/accounts/{account_id}/credentials/{credential_id}",
            json_data=body,
        )

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_all_accounts_on_device_local_domain(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        domain_id = str_arg(args, "domain_id")
        key_format = str_arg(args, "key_format")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,), key_format=key_format, q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        response = self._http_request("get", f"/devices/{device_id}/localdomains/{domain_id}/accounts", params=params)

        return CommandResults(
            outputs_prefix="WAB.device_account_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-all-accounts-on-device-local-domain", response),
            raw_response=response,
        )

    def add_account_to_local_domain_on_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        domain_id = str_arg(args, "domain_id")
        device_account_post_account_name = str_arg(args, "device_account_post_account_name")
        device_account_post_account_login = str_arg(args, "device_account_post_account_login")
        device_account_post_description = str_arg(args, "device_account_post_description")
        device_account_post_auto_change_password = bool_arg(args, "device_account_post_auto_change_password")
        device_account_post_auto_change_ssh_key = bool_arg(args, "device_account_post_auto_change_ssh_key")
        device_account_post_checkout_policy = str_arg(args, "device_account_post_checkout_policy")
        device_account_post_certificate_validity = str_arg(args, "device_account_post_certificate_validity")
        device_account_post_can_edit_certificate_validity = bool_arg(args, "device_account_post_can_edit_certificate_validity")
        device_account_post_services = list_arg(args, "device_account_post_services")

        body = assign_params(
            values_to_ignore=(None,),
            account_name=device_account_post_account_name,
            account_login=device_account_post_account_login,
            description=device_account_post_description,
            auto_change_password=device_account_post_auto_change_password,
            auto_change_ssh_key=device_account_post_auto_change_ssh_key,
            checkout_policy=device_account_post_checkout_policy,
            certificate_validity=device_account_post_certificate_validity,
            can_edit_certificate_validity=device_account_post_can_edit_certificate_validity,
            services=device_account_post_services,
        )
        response = self._http_request("post", f"/devices/{device_id}/localdomains/{domain_id}/accounts", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_account_to_local_domain_on_device",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-account-to-local-domain-on-device", response),
            raw_response=response,
        )

    def get_one_account_on_device_local_domain(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        key_format = str_arg(args, "key_format")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), key_format=key_format, fields=fields)
        response = self._http_request(
            "get", f"/devices/{device_id}/localdomains/{domain_id}/accounts/{account_id}", params=params
        )

        return CommandResults(
            outputs_prefix="WAB.device_account_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-one-account-on-device-local-domain", response),
            raw_response=response,
        )

    def edit_account_on_local_domain_of_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        force = bool_arg(args, "force")
        device_account_put_account_name = str_arg(args, "device_account_put_account_name")
        device_account_put_account_login = str_arg(args, "device_account_put_account_login")
        device_account_put_description = str_arg(args, "device_account_put_description")
        device_account_put_auto_change_password = bool_arg(args, "device_account_put_auto_change_password")
        device_account_put_auto_change_ssh_key = bool_arg(args, "device_account_put_auto_change_ssh_key")
        device_account_put_checkout_policy = str_arg(args, "device_account_put_checkout_policy")
        device_account_put_certificate_validity = str_arg(args, "device_account_put_certificate_validity")
        device_account_put_can_edit_certificate_validity = bool_arg(args, "device_account_put_can_edit_certificate_validity")
        device_account_put_onboard_status = str_arg(args, "device_account_put_onboard_status")
        device_account_put_services = list_arg(args, "device_account_put_services")

        params = assign_params(values_to_ignore=(None,), force=force)
        body = assign_params(
            values_to_ignore=(None,),
            account_name=device_account_put_account_name,
            account_login=device_account_put_account_login,
            description=device_account_put_description,
            auto_change_password=device_account_put_auto_change_password,
            auto_change_ssh_key=device_account_put_auto_change_ssh_key,
            checkout_policy=device_account_put_checkout_policy,
            certificate_validity=device_account_put_certificate_validity,
            can_edit_certificate_validity=device_account_put_can_edit_certificate_validity,
            onboard_status=device_account_put_onboard_status,
            services=device_account_put_services,
        )
        response = self._http_request(
            "put", f"/devices/{device_id}/localdomains/{domain_id}/accounts/{account_id}", params=params, json_data=body
        )

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_account_from_local_domain_of_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")

        response = self._http_request("delete", f"/devices/{device_id}/localdomains/{domain_id}/accounts/{account_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_certificates_on_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/devices/{device_id}/certificates", params=params)

        return CommandResults(
            outputs_prefix="WAB.device_certificates_get",
            outputs=response,
            readable_output=to_markdown("wab-get-certificates-on-device", response),
            raw_response=response,
        )

    def get_certificate_on_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        cert_type = str_arg(args, "cert_type")
        address = str_arg(args, "address")
        port = int_arg(args, "port")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/devices/{device_id}/certificates/{cert_type}/{address}/{port}", params=params)

        return CommandResults(
            outputs_prefix="WAB.device_certificates_get",
            outputs=response,
            readable_output=to_markdown("wab-get-certificate-on-device", response),
            raw_response=response,
        )

    def revoke_certificate_of_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        cert_type = str_arg(args, "cert_type")
        address = str_arg(args, "address")
        port = int_arg(args, "port")

        response = self._http_request("delete", f"/devices/{device_id}/certificates/{cert_type}/{address}/{port}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_local_domains_of_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/devices/{device_id}/localdomains", params=params)

        return CommandResults(
            outputs_prefix="WAB.localdomain_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-local-domains-of-device", response),
            raw_response=response,
        )

    def add_local_domain_in_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        localdomain_post_domain_name = str_arg(args, "localdomain_post_domain_name")
        localdomain_post_description = str_arg(args, "localdomain_post_description")
        localdomain_post_enable_password_change = bool_arg(args, "localdomain_post_enable_password_change")
        localdomain_post_password_change_policy = str_arg(args, "localdomain_post_password_change_policy", nullable=True)
        localdomain_post_password_change_plugin = str_arg(args, "localdomain_post_password_change_plugin", nullable=True)
        localdomain_post_ca_private_key = str_arg(args, "localdomain_post_ca_private_key")
        localdomain_post_passphrase = str_arg(args, "localdomain_post_passphrase")
        password_change_plugin_parameters = json_arg(args, "password_change_plugin_parameters")

        body = assign_params(
            values_to_ignore=(None,),
            domain_name=localdomain_post_domain_name,
            description=localdomain_post_description,
            enable_password_change=localdomain_post_enable_password_change,
            password_change_policy=localdomain_post_password_change_policy,
            password_change_plugin=localdomain_post_password_change_plugin,
            ca_private_key=localdomain_post_ca_private_key,
            passphrase=localdomain_post_passphrase,
            password_change_plugin_parameters=password_change_plugin_parameters,
        )
        response = self._http_request("post", f"/devices/{device_id}/localdomains", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_local_domain_in_device",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-local-domain-in-device", response),
            raw_response=response,
        )

    def get_local_domain_of_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        domain_id = str_arg(args, "domain_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/devices/{device_id}/localdomains/{domain_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.localdomain_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-local-domain-of-device", response),
            raw_response=response,
        )

    def delete_local_domain_from_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        domain_id = str_arg(args, "domain_id")

        response = self._http_request("delete", f"/devices/{device_id}/localdomains/{domain_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_services_of_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/devices/{device_id}/services", params=params)

        return CommandResults(
            outputs_prefix="WAB.service_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-services-of-device", response),
            raw_response=response,
        )

    def add_service_in_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        service_post_id = str_arg(args, "service_post_id")
        service_post_service_name = str_arg(args, "service_post_service_name")
        service_post_protocol = str_arg(args, "service_post_protocol")
        service_post_port = int_arg(args, "service_post_port")
        service_post_subprotocols = list_arg(args, "service_post_subprotocols")
        service_post_connection_policy = str_arg(args, "service_post_connection_policy")
        service_post_global_domains = list_arg(args, "service_post_global_domains")
        service_post_seamless_connection = bool_arg(args, "service_post_seamless_connection")

        body = assign_params(
            values_to_ignore=(None,),
            id=service_post_id,
            service_name=service_post_service_name,
            protocol=service_post_protocol,
            port=service_post_port,
            subprotocols=service_post_subprotocols,
            connection_policy=service_post_connection_policy,
            global_domains=service_post_global_domains,
            seamless_connection=service_post_seamless_connection,
        )
        response = self._http_request("post", f"/devices/{device_id}/services", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_service_in_device",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-service-in-device", response),
            raw_response=response,
        )

    def get_service_of_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        service_id = str_arg(args, "service_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/devices/{device_id}/services/{service_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.service_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-service-of-device", response),
            raw_response=response,
        )

    def edit_service_of_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        service_id = str_arg(args, "service_id")
        force = bool_arg(args, "force")
        service_put_port = int_arg(args, "service_put_port")
        service_put_subprotocols = list_arg(args, "service_put_subprotocols")
        service_put_connection_policy = str_arg(args, "service_put_connection_policy")
        service_put_global_domains = list_arg(args, "service_put_global_domains")
        service_put_seamless_connection = bool_arg(args, "service_put_seamless_connection")

        params = assign_params(values_to_ignore=(None,), force=force)
        body = assign_params(
            values_to_ignore=(None,),
            port=service_put_port,
            subprotocols=service_put_subprotocols,
            connection_policy=service_put_connection_policy,
            global_domains=service_put_global_domains,
            seamless_connection=service_put_seamless_connection,
        )
        response = self._http_request("put", f"/devices/{device_id}/services/{service_id}", params=params, json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_service_from_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        service_id = str_arg(args, "service_id")

        response = self._http_request("delete", f"/devices/{device_id}/services/{service_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_devices(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/devices", params=params)

        return CommandResults(
            outputs_prefix="WAB.device_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-devices", response),
            raw_response=response,
        )

    def add_device(self, args: Dict[str, Any]):
        device_post_device_name = str_arg(args, "device_post_device_name")
        device_post_description = str_arg(args, "device_post_description")
        device_post_alias = str_arg(args, "device_post_alias")
        device_post_host = str_arg(args, "device_post_host")

        body = assign_params(
            values_to_ignore=(None,),
            device_name=device_post_device_name,
            description=device_post_description,
            alias=device_post_alias,
            host=device_post_host,
        )
        response = self._http_request("post", "/devices", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_device",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-device", response),
            raw_response=response,
        )

    def get_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/devices/{device_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.device_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-device", response),
            raw_response=response,
        )

    def edit_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")
        force = bool_arg(args, "force")
        device_put_device_name = str_arg(args, "device_put_device_name")
        device_put_description = str_arg(args, "device_put_description")
        device_put_alias = str_arg(args, "device_put_alias")
        device_put_host = str_arg(args, "device_put_host")
        device_put_onboard_status = str_arg(args, "device_put_onboard_status")

        params = assign_params(values_to_ignore=(None,), force=force)
        body = assign_params(
            values_to_ignore=(None,),
            device_name=device_put_device_name,
            description=device_put_description,
            alias=device_put_alias,
            host=device_put_host,
            onboard_status=device_put_onboard_status,
        )
        response = self._http_request("put", f"/devices/{device_id}", params=params, json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_device(self, args: Dict[str, Any]):
        device_id = str_arg(args, "device_id")

        response = self._http_request("delete", f"/devices/{device_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_global_domain_account_credentials(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/domains/{domain_id}/accounts/{account_id}/credentials", params=params)

        return CommandResults(
            outputs_prefix="WAB.credential_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-global-domain-account-credentials", response),
            raw_response=response,
        )

    def get_global_domain_account_credential(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        credential_id = str_arg(args, "credential_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request(
            "get", f"/domains/{domain_id}/accounts/{account_id}/credentials/{credential_id}", params=params
        )

        return CommandResults(
            outputs_prefix="WAB.credential_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-global-domain-account-credential", response),
            raw_response=response,
        )

    def edit_credential_of_global_domain_account(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        credential_id = str_arg(args, "credential_id")
        credential_put_type = str_arg(args, "credential_put_type")
        credential_put_password = str_arg(args, "credential_put_password")
        credential_put_private_key = str_arg(args, "credential_put_private_key")
        credential_put_passphrase = str_arg(args, "credential_put_passphrase")

        body = assign_params(
            values_to_ignore=(None,),
            type=credential_put_type,
            password=credential_put_password,
            private_key=credential_put_private_key,
            passphrase=credential_put_passphrase,
        )
        response = self._http_request(
            "put", f"/domains/{domain_id}/accounts/{account_id}/credentials/{credential_id}", json_data=body
        )

        return CommandResults(readable_output="Success!", raw_response=response)

    def add_credential_to_global_domain_account(self, args: Dict[str, Any]):
        domain_name = str_arg(args, "domain_name")
        account_id = str_arg(args, "account_id")
        credential_post_type = str_arg(args, "credential_post_type")
        credential_post_password = str_arg(args, "credential_post_password")
        credential_post_private_key = str_arg(args, "credential_post_private_key")
        credential_post_passphrase = str_arg(args, "credential_post_passphrase")

        body = assign_params(
            values_to_ignore=(None,),
            type=credential_post_type,
            password=credential_post_password,
            private_key=credential_post_private_key,
            passphrase=credential_post_passphrase,
        )
        response = self._http_request("post", f"/domains/{domain_name}/accounts/{account_id}/credentials", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_credential_to_global_domain_account",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-credential-to-global-domain-account", response),
            raw_response=response,
        )

    def get_accounts_of_global_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        q = str_arg(args, "q")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/domains/{domain_id}/accounts", params=params)

        return CommandResults(
            outputs_prefix="WAB.domain_account_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-accounts-of-global-domain", response),
            raw_response=response,
        )

    def add_account_in_global_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        domain_account_post_account_name = str_arg(args, "domain_account_post_account_name")
        domain_account_post_account_login = str_arg(args, "domain_account_post_account_login")
        domain_account_post_description = str_arg(args, "domain_account_post_description")
        domain_account_post_auto_change_password = bool_arg(args, "domain_account_post_auto_change_password")
        domain_account_post_auto_change_ssh_key = bool_arg(args, "domain_account_post_auto_change_ssh_key")
        domain_account_post_checkout_policy = str_arg(args, "domain_account_post_checkout_policy")
        domain_account_post_certificate_validity = str_arg(args, "domain_account_post_certificate_validity")
        domain_account_post_can_edit_certificate_validity = bool_arg(args, "domain_account_post_can_edit_certificate_validity")
        domain_account_post_resources = list_arg(args, "domain_account_post_resources")

        body = assign_params(
            values_to_ignore=(None,),
            account_name=domain_account_post_account_name,
            account_login=domain_account_post_account_login,
            description=domain_account_post_description,
            auto_change_password=domain_account_post_auto_change_password,
            auto_change_ssh_key=domain_account_post_auto_change_ssh_key,
            checkout_policy=domain_account_post_checkout_policy,
            certificate_validity=domain_account_post_certificate_validity,
            can_edit_certificate_validity=domain_account_post_can_edit_certificate_validity,
            resources=domain_account_post_resources,
        )
        response = self._http_request("post", f"/domains/{domain_id}/accounts", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_account_in_global_domain",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-account-in-global-domain", response),
            raw_response=response,
        )

    def get_account_of_global_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/domains/{domain_id}/accounts/{account_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.domain_account_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-account-of-global-domain", response),
            raw_response=response,
        )

    def edit_account_in_global_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        force = bool_arg(args, "force")
        domain_account_put_account_name = str_arg(args, "domain_account_put_account_name")
        domain_account_put_account_login = str_arg(args, "domain_account_put_account_login")
        domain_account_put_description = str_arg(args, "domain_account_put_description")
        domain_account_put_auto_change_password = bool_arg(args, "domain_account_put_auto_change_password")
        domain_account_put_auto_change_ssh_key = bool_arg(args, "domain_account_put_auto_change_ssh_key")
        domain_account_put_checkout_policy = str_arg(args, "domain_account_put_checkout_policy")
        domain_account_put_certificate_validity = str_arg(args, "domain_account_put_certificate_validity")
        domain_account_put_can_edit_certificate_validity = bool_arg(args, "domain_account_put_can_edit_certificate_validity")
        domain_account_put_onboard_status = str_arg(args, "domain_account_put_onboard_status")
        domain_account_put_resources = list_arg(args, "domain_account_put_resources")

        params = assign_params(values_to_ignore=(None,), force=force)
        body = assign_params(
            values_to_ignore=(None,),
            account_name=domain_account_put_account_name,
            account_login=domain_account_put_account_login,
            description=domain_account_put_description,
            auto_change_password=domain_account_put_auto_change_password,
            auto_change_ssh_key=domain_account_put_auto_change_ssh_key,
            checkout_policy=domain_account_put_checkout_policy,
            certificate_validity=domain_account_put_certificate_validity,
            can_edit_certificate_validity=domain_account_put_can_edit_certificate_validity,
            onboard_status=domain_account_put_onboard_status,
            resources=domain_account_put_resources,
        )
        response = self._http_request("put", f"/domains/{domain_id}/accounts/{account_id}", params=params, json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_account_from_global_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")

        response = self._http_request("delete", f"/domains/{domain_id}/accounts/{account_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_resource_from_global_domain_account(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        account_id = str_arg(args, "account_id")
        resource_name = str_arg(args, "resource_name")

        response = self._http_request("delete", f"/domains/{domain_id}/accounts/{account_id}/resource/{resource_name}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_global_domains(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/domains", params=params)

        return CommandResults(
            outputs_prefix="WAB.domain_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-global-domains", response),
            raw_response=response,
        )

    def get_global_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/domains/{domain_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.domain_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-global-domain", response),
            raw_response=response,
        )

    def delete_global_domain(self, args: Dict[str, Any]):
        domain_id = str_arg(args, "domain_id")

        response = self._http_request("delete", f"/domains/{domain_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_external_authentications(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/externalauths", params=params)

        return CommandResults(
            outputs_prefix="WAB.externalauth_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-external-authentications", response),
            raw_response=response,
        )

    def get_external_authentication(self, args: Dict[str, Any]):
        authentication_id = str_arg(args, "authentication_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/externalauths/{authentication_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.externalauth_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-external-authentication", response),
            raw_response=response,
        )

    def get_external_authentication_group_mappings(self, args: Dict[str, Any]):
        group_by = str_arg(args, "group_by")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,), group_by=group_by, q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        response = self._http_request("get", "/authmappings", params=params)

        return CommandResults(
            outputs_prefix="WAB.authmappings_get",
            outputs=response,
            readable_output=to_markdown("wab-get-external-authentication-group-mappings", response),
            raw_response=response,
        )

    def get_ldap_users_of_domain(self, args: Dict[str, Any]):
        domain = str_arg(args, "domain")
        last_connection = bool_arg(args, "last_connection")
        q = str_arg(args, "q")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,), last_connection=last_connection, q=q, offset=offset, limit=limit, fields=fields
        )
        response = self._http_request("get", f"/ldapusers/{domain}", params=params)

        return CommandResults(
            outputs_prefix="WAB.ldapuser_get",
            outputs_key_field=["domain", "user_name"],
            outputs=response,
            readable_output=to_markdown("wab-get-ldap-users-of-domain", response),
            raw_response=response,
        )

    def get_ldap_user_of_domain(self, args: Dict[str, Any]):
        domain = str_arg(args, "domain")
        user_name = str_arg(args, "user_name")
        last_connection = bool_arg(args, "last_connection")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), last_connection=last_connection, fields=fields)
        response = self._http_request("get", f"/ldapusers/{domain}/{user_name}", params=params)

        return CommandResults(
            outputs_prefix="WAB.ldapuser_get",
            outputs_key_field=["domain", "user_name"],
            outputs=response,
            readable_output=to_markdown("wab-get-ldap-user-of-domain", response),
            raw_response=response,
        )

    def get_information_about_wallix_bastion_license(self, args: Dict[str, Any]):

        response = self._http_request("get", "/licenseinfo")

        return CommandResults(
            outputs_prefix="WAB.licenseinfo_get",
            outputs=response,
            readable_output=to_markdown("wab-get-information-about-wallix-bastion-license", response),
            raw_response=response,
        )

    def post_logsiem(self, args: Dict[str, Any]):
        logsiem_post_application = str_arg(args, "logsiem_post_application")
        logsiem_post_message = str_arg(args, "logsiem_post_message")

        body = assign_params(values_to_ignore=(None,), application=logsiem_post_application, message=logsiem_post_message)
        response = self._http_request("post", "/logsiem", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.post_logsiem",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-post-logsiem", response),
            raw_response=response,
        )

    def get_notifications(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit)
        response = self._http_request("get", "/notifications", params=params)

        return CommandResults(
            outputs_prefix="WAB.notification_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-notifications", response),
            raw_response=response,
        )

    def add_notification(self, args: Dict[str, Any]):
        notification_post_notification_name = str_arg(args, "notification_post_notification_name")
        notification_post_description = str_arg(args, "notification_post_description")
        notification_post_enabled = bool_arg(args, "notification_post_enabled")
        notification_post_destination = str_arg(args, "notification_post_destination")
        notification_post_language = str_arg(args, "notification_post_language")
        notification_post_events = list_arg(args, "notification_post_events")
        notification_post_type = "email"

        body = assign_params(
            values_to_ignore=(None,),
            notification_name=notification_post_notification_name,
            description=notification_post_description,
            enabled=notification_post_enabled,
            type=notification_post_type,
            destination=notification_post_destination,
            language=notification_post_language,
            events=notification_post_events,
        )
        response = self._http_request("post", "/notifications", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_notification",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-notification", response),
            raw_response=response,
        )

    def get_notification(self, args: Dict[str, Any]):
        notification_id = str_arg(args, "notification_id")

        response = self._http_request("get", f"/notifications/{notification_id}")

        return CommandResults(
            outputs_prefix="WAB.notification_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-notification", response),
            raw_response=response,
        )

    def edit_notification(self, args: Dict[str, Any]):
        notification_id = str_arg(args, "notification_id")
        force = bool_arg(args, "force")
        notification_put_notification_name = str_arg(args, "notification_put_notification_name")
        notification_put_description = str_arg(args, "notification_put_description")
        notification_put_enabled = bool_arg(args, "notification_put_enabled")
        notification_put_destination = str_arg(args, "notification_put_destination")
        notification_put_language = str_arg(args, "notification_put_language")
        notification_put_events = list_arg(args, "notification_put_events")
        notification_put_type = "email"

        params = assign_params(values_to_ignore=(None,), force=force)
        body = assign_params(
            values_to_ignore=(None,),
            notification_name=notification_put_notification_name,
            description=notification_put_description,
            enabled=notification_put_enabled,
            type=notification_put_type,
            destination=notification_put_destination,
            language=notification_put_language,
            events=notification_put_events,
        )
        response = self._http_request("put", f"/notifications/{notification_id}", params=params, json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_notification(self, args: Dict[str, Any]):
        notification_id = str_arg(args, "notification_id")

        response = self._http_request("delete", f"/notifications/{notification_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_object_to_onboard(self, args: Dict[str, Any]):
        object_type = str_arg(args, "object_type")
        object_status = str_arg(args, "object_status")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,),
            object_type=object_type,
            object_status=object_status,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        response = self._http_request("get", "/onboarding_objects", params=params)

        return CommandResults(
            outputs_prefix="WAB.onboarding_objects_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-object-to-onboard", response),
            raw_response=response,
        )

    def get_password_change_policies(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit)
        response = self._http_request("get", "/passwordchangepolicies", params=params)

        return CommandResults(
            outputs_prefix="WAB.passwordchangepolicy_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-password-change-policies", response),
            raw_response=response,
        )

    def add_password_change_policy(self, args: Dict[str, Any]):
        passwordchangepolicy_post_password_change_policy_name = str_arg(
            args, "passwordchangepolicy_post_password_change_policy_name"
        )
        passwordchangepolicy_post_description = str_arg(args, "passwordchangepolicy_post_description")
        passwordchangepolicy_post_password_length = int_arg(args, "passwordchangepolicy_post_password_length", nullable=True)
        passwordchangepolicy_post_special_chars = int_arg(args, "passwordchangepolicy_post_special_chars", nullable=True)
        passwordchangepolicy_post_lower_chars = int_arg(args, "passwordchangepolicy_post_lower_chars", nullable=True)
        passwordchangepolicy_post_upper_chars = int_arg(args, "passwordchangepolicy_post_upper_chars", nullable=True)
        passwordchangepolicy_post_digit_chars = int_arg(args, "passwordchangepolicy_post_digit_chars", nullable=True)
        passwordchangepolicy_post_exclude_chars = str_arg(args, "passwordchangepolicy_post_exclude_chars", nullable=True)
        passwordchangepolicy_post_ssh_key_type = str_arg(args, "passwordchangepolicy_post_ssh_key_type", nullable=True)
        passwordchangepolicy_post_ssh_key_size = int_arg(args, "passwordchangepolicy_post_ssh_key_size", nullable=True)
        passwordchangepolicy_post_change_period = str_arg(args, "passwordchangepolicy_post_change_period", nullable=True)

        body = assign_params(
            values_to_ignore=(None,),
            password_change_policy_name=passwordchangepolicy_post_password_change_policy_name,
            description=passwordchangepolicy_post_description,
            password_length=passwordchangepolicy_post_password_length,
            special_chars=passwordchangepolicy_post_special_chars,
            lower_chars=passwordchangepolicy_post_lower_chars,
            upper_chars=passwordchangepolicy_post_upper_chars,
            digit_chars=passwordchangepolicy_post_digit_chars,
            exclude_chars=passwordchangepolicy_post_exclude_chars,
            ssh_key_type=passwordchangepolicy_post_ssh_key_type,
            ssh_key_size=passwordchangepolicy_post_ssh_key_size,
            change_period=passwordchangepolicy_post_change_period,
        )
        response = self._http_request("post", "/passwordchangepolicies", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_password_change_policy",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-password-change-policy", response),
            raw_response=response,
        )

    def get_password_change_policy(self, args: Dict[str, Any]):
        policy_id = str_arg(args, "policy_id")

        response = self._http_request("get", f"/passwordchangepolicies/{policy_id}")

        return CommandResults(
            outputs_prefix="WAB.passwordchangepolicy_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-password-change-policy", response),
            raw_response=response,
        )

    def edit_password_change_policy(self, args: Dict[str, Any]):
        policy_id = str_arg(args, "policy_id")
        passwordchangepolicy_put_password_change_policy_name = str_arg(
            args, "passwordchangepolicy_put_password_change_policy_name"
        )
        passwordchangepolicy_put_description = str_arg(args, "passwordchangepolicy_put_description")
        passwordchangepolicy_put_password_length = int_arg(args, "passwordchangepolicy_put_password_length", nullable=True)
        passwordchangepolicy_put_special_chars = int_arg(args, "passwordchangepolicy_put_special_chars", nullable=True)
        passwordchangepolicy_put_lower_chars = int_arg(args, "passwordchangepolicy_put_lower_chars", nullable=True)
        passwordchangepolicy_put_upper_chars = int_arg(args, "passwordchangepolicy_put_upper_chars", nullable=True)
        passwordchangepolicy_put_digit_chars = int_arg(args, "passwordchangepolicy_put_digit_chars", nullable=True)
        passwordchangepolicy_put_exclude_chars = str_arg(args, "passwordchangepolicy_put_exclude_chars", nullable=True)
        passwordchangepolicy_put_ssh_key_type = str_arg(args, "passwordchangepolicy_put_ssh_key_type", nullable=True)
        passwordchangepolicy_put_ssh_key_size = int_arg(args, "passwordchangepolicy_put_ssh_key_size", nullable=True)
        passwordchangepolicy_put_change_period = str_arg(args, "passwordchangepolicy_put_change_period", nullable=True)

        body = assign_params(
            values_to_ignore=(None,),
            password_change_policy_name=passwordchangepolicy_put_password_change_policy_name,
            description=passwordchangepolicy_put_description,
            password_length=passwordchangepolicy_put_password_length,
            special_chars=passwordchangepolicy_put_special_chars,
            lower_chars=passwordchangepolicy_put_lower_chars,
            upper_chars=passwordchangepolicy_put_upper_chars,
            digit_chars=passwordchangepolicy_put_digit_chars,
            exclude_chars=passwordchangepolicy_put_exclude_chars,
            ssh_key_type=passwordchangepolicy_put_ssh_key_type,
            ssh_key_size=passwordchangepolicy_put_ssh_key_size,
            change_period=passwordchangepolicy_put_change_period,
        )
        response = self._http_request("put", f"/passwordchangepolicies/{policy_id}", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_password_change_policy(self, args: Dict[str, Any]):
        policy_id = str_arg(args, "policy_id")

        response = self._http_request("delete", f"/passwordchangepolicies/{policy_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_passwordrights(self, args: Dict[str, Any]):
        count = bool_arg(args, "count")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), count=count, q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/passwordrights", params=params)

        return CommandResults(
            outputs_prefix="WAB.passwordrights_get",
            outputs=response,
            readable_output=to_markdown("wab-get-passwordrights", response),
            raw_response=response,
        )

    def get_passwordrights_user_name(self, args: Dict[str, Any]):
        user_name = str_arg(args, "user_name")
        count = bool_arg(args, "count")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), count=count, fields=fields)
        response = self._http_request("get", f"/passwordrights/{user_name}", params=params)

        add_key_to_outputs(response, "user_name", user_name)

        return CommandResults(
            outputs_prefix="WAB.passwordrights_get",
            outputs_key_field="user_name",
            outputs=response,
            readable_output=to_markdown("wab-get-passwordrights-user-name", response),
            raw_response=response,
        )

    def get_profiles(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/profiles", params=params)

        return CommandResults(
            outputs_prefix="WAB.profile_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-profiles", response),
            raw_response=response,
        )

    def get_profile(self, args: Dict[str, Any]):
        profile_id = str_arg(args, "profile_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/profiles/{profile_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.profile_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-profile", response),
            raw_response=response,
        )

    def get_scanjobs(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/scanjobs", params=params)

        return CommandResults(
            outputs_prefix="WAB.scanjob_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-scanjobs", response),
            raw_response=response,
        )

    def start_scan_job_manually(self, args: Dict[str, Any]):
        scanjob_post_scan_id = str_arg(args, "scanjob_post_scan_id")

        body = assign_params(values_to_ignore=(None,), scan_id=scanjob_post_scan_id)
        response = self._http_request("post", "/scanjobs", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.start_scan_job_manually",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-start-scan-job-manually", response),
            raw_response=response,
        )

    def get_scanjob(self, args: Dict[str, Any]):
        scanjob_id = str_arg(args, "scanjob_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/scanjobs/{scanjob_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.scanjob_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-scanjob", response),
            raw_response=response,
        )

    def cancel_scan_job(self, args: Dict[str, Any]):
        scanjob_id = str_arg(args, "scanjob_id")

        response = self._http_request("put", f"/scanjobs/{scanjob_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_scans(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/scans", params=params)

        return CommandResults(
            outputs_prefix="WAB.scan_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-scans", response),
            raw_response=response,
        )

    def get_scan(self, args: Dict[str, Any]):
        scan_id = str_arg(args, "scan_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/scans/{scan_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.scan_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-scan", response),
            raw_response=response,
        )

    def edit_scan(self, args: Dict[str, Any]):
        scan_id = str_arg(args, "scan_id")
        scan_put_name = str_arg(args, "scan_put_name")
        scan_put_active = bool_arg(args, "scan_put_active")
        scan_put_periodicity = str_arg(args, "scan_put_periodicity")
        scan_put_description = str_arg(args, "scan_put_description")
        scan_put_emails = list_arg(args, "scan_put_emails")
        scan_put_subnets = list_arg(args, "scan_put_subnets")
        scan_put_banner_regex = list_arg(args, "scan_put_banner_regex")
        scan_put_scan_for_accounts = bool_arg(args, "scan_put_scan_for_accounts")
        scan_put_master_accounts = list_arg(args, "scan_put_master_accounts")
        scan_put_search_filter = str_arg(args, "scan_put_search_filter")
        scan_put_dn_list = list_arg(args, "scan_put_dn_list")
        scan_put_devices = list_arg(args, "scan_put_devices")

        body = assign_params(
            values_to_ignore=(None,),
            name=scan_put_name,
            active=scan_put_active,
            periodicity=scan_put_periodicity,
            description=scan_put_description,
            emails=scan_put_emails,
            subnets=scan_put_subnets,
            banner_regex=scan_put_banner_regex,
            scan_for_accounts=scan_put_scan_for_accounts,
            master_accounts=scan_put_master_accounts,
            search_filter=scan_put_search_filter,
            dn_list=scan_put_dn_list,
            devices=scan_put_devices,
        )
        response = self._http_request("put", f"/scans/{scan_id}", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_scan(self, args: Dict[str, Any]):
        scan_id = str_arg(args, "scan_id")

        response = self._http_request("delete", f"/scans/{scan_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_sessionrights(self, args: Dict[str, Any]):
        count = bool_arg(args, "count")
        last_connection = bool_arg(args, "last_connection")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,),
            count=count,
            last_connection=last_connection,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        response = self._http_request("get", "/sessionrights", params=params)

        return CommandResults(
            outputs_prefix="WAB.sessionrights_get",
            outputs=response,
            readable_output=to_markdown("wab-get-sessionrights", response),
            raw_response=response,
        )

    def get_sessionrights_user_name(self, args: Dict[str, Any]):
        user_name = str_arg(args, "user_name")
        count = bool_arg(args, "count")
        last_connection = bool_arg(args, "last_connection")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), count=count, last_connection=last_connection, fields=fields)
        response = self._http_request("get", f"/sessionrights/{user_name}", params=params)

        add_key_to_outputs(response, "user_name", user_name)

        return CommandResults(
            outputs_prefix="WAB.sessionrights_get",
            outputs_key_field="user_name",
            outputs=response,
            readable_output=to_markdown("wab-get-sessionrights-user-name", response),
            raw_response=response,
        )

    def get_sessions(self, args: Dict[str, Any]):
        session_id = str_arg(args, "session_id")
        otp = str_arg(args, "otp")
        status = str_arg(args, "status")
        from_date = str_arg(args, "from_date")
        to_date = str_arg(args, "to_date")
        date_field = str_arg(args, "date_field")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,),
            session_id=session_id,
            otp=otp,
            status=status,
            from_date=from_date,
            to_date=to_date,
            date_field=date_field,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        response = self._http_request("get", "/sessions", params=params)

        return CommandResults(
            outputs_prefix="WAB.session_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-sessions", response),
            raw_response=response,
        )

    def edit_session(self, args: Dict[str, Any]):
        session_id = str_arg(args, "session_id")
        action = str_arg(args, "action")
        session_put_edit_description = str_arg(args, "session_put_edit_description")

        params = assign_params(values_to_ignore=(None,), session_id=session_id, action=action)
        body = assign_params(values_to_ignore=(None,), description=session_put_edit_description)
        response = self._http_request("put", "/sessions", params=params, json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_session_metadata(self, args: Dict[str, Any]):
        session_ids = str_arg(args, "session_ids")
        download = bool_arg(args, "download")

        params = assign_params(values_to_ignore=(None,), session_ids=session_ids, download=download)
        response = self._http_request("get", "/sessions/metadata", params=params)

        return CommandResults(
            outputs_prefix="WAB.session_metadata_get",
            outputs=response,
            readable_output=to_markdown("wab-get-session-metadata", response),
            raw_response=response,
        )

    def get_session_sharing_requests(self, args: Dict[str, Any]):
        request_id = str_arg(args, "request_id")
        session_id = str_arg(args, "session_id")

        params = assign_params(values_to_ignore=(None,), request_id=request_id, session_id=session_id)
        response = self._http_request("get", "/sessions/requests", params=params)

        return CommandResults(
            outputs_prefix="WAB.session_request_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-session-sharing-requests", response),
            raw_response=response,
        )

    def create_session_request(self, args: Dict[str, Any]):
        session_request_post_session_id = str_arg(args, "session_request_post_session_id")
        session_request_post_mode = str_arg(args, "session_request_post_mode")

        body = assign_params(values_to_ignore=(None,), session_id=session_request_post_session_id, mode=session_request_post_mode)
        response = self._http_request("post", "/sessions/requests", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_pending_or_live_session_request(self, args: Dict[str, Any]):
        request_id = str_arg(args, "request_id")

        response = self._http_request("delete", f"/sessions/requests/{request_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_latest_snapshot_of_running_session(self, args: Dict[str, Any]):
        session_id = str_arg(args, "session_id")

        response = self._http_request("get", f"/sessions/snapshots/{session_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_status_of_trace_generation(self, args: Dict[str, Any]):
        session_id = str_arg(args, "session_id")
        date = str_arg(args, "date")
        duration = int_arg(args, "duration")
        download = bool_arg(args, "download")

        params = assign_params(values_to_ignore=(None,), date=date, duration=duration, download=download)
        response = self._http_request("get", f"/sessions/traces/{session_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.session_trace_get",
            outputs_key_field="session_id",
            outputs=response,
            readable_output=to_markdown("wab-get-status-of-trace-generation", response),
            raw_response=response,
        )

    def generate_trace_for_session(self, args: Dict[str, Any]):
        session_trace_post_session_id = str_arg(args, "session_trace_post_session_id")
        session_trace_post_date = str_arg(args, "session_trace_post_date")
        session_trace_post_duration = int_arg(args, "session_trace_post_duration")

        body = assign_params(
            values_to_ignore=(None,),
            session_id=session_trace_post_session_id,
            date=session_trace_post_date,
            duration=session_trace_post_duration,
        )
        response = self._http_request("post", "/sessions/traces", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.generate_trace_for_session",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-generate-trace-for-session", response),
            raw_response=response,
        )

    def get_wallix_bastion_usage_statistics(self, args: Dict[str, Any]):
        from_date = str_arg(args, "from_date")
        to_date = str_arg(args, "to_date")

        params = assign_params(values_to_ignore=(None,), from_date=from_date, to_date=to_date)
        response = self._http_request("get", "/statistics", params=params)

        return CommandResults(
            outputs_prefix="WAB.statistics_get",
            outputs=response,
            readable_output=to_markdown("wab-get-wallix-bastion-usage-statistics", response),
            raw_response=response,
        )

    def get_target_groups(self, args: Dict[str, Any]):
        device = str_arg(args, "device")
        application = str_arg(args, "application")
        domain = str_arg(args, "domain")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,),
            device=device,
            application=application,
            domain=domain,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        response = self._http_request("get", "/targetgroups", params=params)

        return CommandResults(
            outputs_prefix="WAB.targetgroups_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-target-groups", response),
            raw_response=response,
        )

    def add_target_group(self, args: Dict[str, Any]):
        targetgroups_post_group_name = str_arg(args, "targetgroups_post_group_name")
        targetgroups_post_description = str_arg(args, "targetgroups_post_description")

        body = assign_params(
            values_to_ignore=(None,), group_name=targetgroups_post_group_name, description=targetgroups_post_description
        )
        response = self._http_request("post", "/targetgroups", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_target_group",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-target-group", response),
            raw_response=response,
        )

    def get_target_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        device = str_arg(args, "device")
        application = str_arg(args, "application")
        domain = str_arg(args, "domain")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), device=device, application=application, domain=domain, fields=fields)
        response = self._http_request("get", f"/targetgroups/{group_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.targetgroups_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-target-group", response),
            raw_response=response,
        )

    def edit_target_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        force = bool_arg(args, "force")
        targetgroups_put_group_name = str_arg(args, "targetgroups_put_group_name")
        targetgroups_put_description = str_arg(args, "targetgroups_put_description")

        params = assign_params(values_to_ignore=(None,), force=force)
        body = assign_params(
            values_to_ignore=(None,), group_name=targetgroups_put_group_name, description=targetgroups_put_description
        )
        response = self._http_request("put", f"/targetgroups/{group_id}", params=params, json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_target_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")

        response = self._http_request("delete", f"/targetgroups/{group_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_target_from_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        target_type = str_arg(args, "target_type")
        target_id = str_arg(args, "target_id")

        response = self._http_request("delete", f"/targetgroups/{group_id}/{target_type}/{target_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_timeframes(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/timeframes", params=params)

        return CommandResults(
            outputs_prefix="WAB.timeframe_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-timeframes", response),
            raw_response=response,
        )

    def add_timeframe(self, args: Dict[str, Any]):
        timeframe_post_timeframe_name = str_arg(args, "timeframe_post_timeframe_name")
        timeframe_post_description = str_arg(args, "timeframe_post_description")
        timeframe_post_is_overtimable = bool_arg(args, "timeframe_post_is_overtimable")

        body = assign_params(
            values_to_ignore=(None,),
            timeframe_name=timeframe_post_timeframe_name,
            description=timeframe_post_description,
            is_overtimable=timeframe_post_is_overtimable,
        )
        response = self._http_request("post", "/timeframes", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_timeframe",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-timeframe", response),
            raw_response=response,
        )

    def get_timeframe(self, args: Dict[str, Any]):
        timeframe_id = str_arg(args, "timeframe_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/timeframes/{timeframe_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.timeframe_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-timeframe", response),
            raw_response=response,
        )

    def edit_timeframe(self, args: Dict[str, Any]):
        timeframe_id = str_arg(args, "timeframe_id")
        timeframe_put_timeframe_name = str_arg(args, "timeframe_put_timeframe_name")
        timeframe_put_description = str_arg(args, "timeframe_put_description")
        timeframe_put_is_overtimable = bool_arg(args, "timeframe_put_is_overtimable")

        body = assign_params(
            values_to_ignore=(None,),
            timeframe_name=timeframe_put_timeframe_name,
            description=timeframe_put_description,
            is_overtimable=timeframe_put_is_overtimable,
        )
        response = self._http_request("put", f"/timeframes/{timeframe_id}", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_timeframe(self, args: Dict[str, Any]):
        timeframe_id = str_arg(args, "timeframe_id")

        response = self._http_request("delete", f"/timeframes/{timeframe_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_user_groups(self, args: Dict[str, Any]):
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", "/usergroups", params=params)

        return CommandResults(
            outputs_prefix="WAB.usergroups_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-user-groups", response),
            raw_response=response,
        )

    def add_user_group(self, args: Dict[str, Any]):
        usergroups_post_group_name = str_arg(args, "usergroups_post_group_name")
        usergroups_post_profile = str_arg(args, "usergroups_post_profile", nullable=True)
        usergroups_post_description = str_arg(args, "usergroups_post_description")
        usergroups_post_timeframes = list_arg(args, "usergroups_post_timeframes")
        usergroups_post_users = list_arg(args, "usergroups_post_users")
        usergroups_post_language = str_arg(args, "usergroups_post_language")
        usergroups_post_email_list = str_arg(args, "usergroups_post_email_list")

        body = assign_params(
            values_to_ignore=(None,),
            group_name=usergroups_post_group_name,
            profile=usergroups_post_profile,
            description=usergroups_post_description,
            timeframes=usergroups_post_timeframes,
            users=usergroups_post_users,
            language=usergroups_post_language,
            email_list=usergroups_post_email_list,
        )
        response = self._http_request("post", "/usergroups", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_user_group",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-user-group", response),
            raw_response=response,
        )

    def get_user_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/usergroups/{group_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.usergroups_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-user-group", response),
            raw_response=response,
        )

    def edit_user_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        force = bool_arg(args, "force")
        usergroups_put_group_name = str_arg(args, "usergroups_put_group_name")
        usergroups_put_profile = str_arg(args, "usergroups_put_profile", nullable=True)
        usergroups_put_description = str_arg(args, "usergroups_put_description")
        usergroups_put_timeframes = list_arg(args, "usergroups_put_timeframes")
        usergroups_put_users = list_arg(args, "usergroups_put_users")
        usergroups_put_language = str_arg(args, "usergroups_put_language")
        usergroups_put_email_list = str_arg(args, "usergroups_put_email_list")

        params = assign_params(values_to_ignore=(None,), force=force)
        body = assign_params(
            values_to_ignore=(None,),
            group_name=usergroups_put_group_name,
            profile=usergroups_put_profile,
            description=usergroups_put_description,
            timeframes=usergroups_put_timeframes,
            users=usergroups_put_users,
            language=usergroups_put_language,
            email_list=usergroups_put_email_list,
        )
        response = self._http_request("put", f"/usergroups/{group_id}", params=params, json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_user_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")

        response = self._http_request("delete", f"/usergroups/{group_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_users(self, args: Dict[str, Any]):
        password_hash = bool_arg(args, "password_hash")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,), password_hash=password_hash, q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        response = self._http_request("get", "/users", params=params)

        return CommandResults(
            outputs_prefix="WAB.user_get",
            outputs_key_field="user_name",
            outputs=response,
            readable_output=to_markdown("wab-get-users", response),
            raw_response=response,
        )

    def add_user(self, args: Dict[str, Any]):
        password_hash = bool_arg(args, "password_hash")
        user_post_user_name = str_arg(args, "user_post_user_name")
        user_post_display_name = str_arg(args, "user_post_display_name")
        user_post_email = str_arg(args, "user_post_email")
        user_post_ip_source = str_arg(args, "user_post_ip_source")
        user_post_preferred_language = str_arg(args, "user_post_preferred_language")
        user_post_profile = str_arg(args, "user_post_profile")
        user_post_groups = list_arg(args, "user_post_groups")
        user_post_user_auths = list_arg(args, "user_post_user_auths")
        user_post_password = str_arg(args, "user_post_password")
        user_post_force_change_pwd = bool_arg(args, "user_post_force_change_pwd")
        user_post_ssh_public_key = str_arg(args, "user_post_ssh_public_key")
        user_post_certificate_dn = str_arg(args, "user_post_certificate_dn")
        user_post_last_connection = str_arg(args, "user_post_last_connection", nullable=True)
        user_post_expiration_date = str_arg(args, "user_post_expiration_date")
        user_post_is_disabled = bool_arg(args, "user_post_is_disabled")
        user_post_gpg_public_key = str_arg(args, "user_post_gpg_public_key")

        params = assign_params(values_to_ignore=(None,), password_hash=password_hash)
        body = assign_params(
            values_to_ignore=(None,),
            user_name=user_post_user_name,
            display_name=user_post_display_name,
            email=user_post_email,
            ip_source=user_post_ip_source,
            preferred_language=user_post_preferred_language,
            profile=user_post_profile,
            groups=user_post_groups,
            user_auths=user_post_user_auths,
            password=user_post_password,
            force_change_pwd=user_post_force_change_pwd,
            ssh_public_key=user_post_ssh_public_key,
            certificate_dn=user_post_certificate_dn,
            last_connection=user_post_last_connection,
            expiration_date=user_post_expiration_date,
            is_disabled=user_post_is_disabled,
            gpg_public_key=user_post_gpg_public_key,
        )
        response = self._http_request("post", "/users", params=params, json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_user",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-user", response),
            raw_response=response,
        )

    def get_user(self, args: Dict[str, Any]):
        name = str_arg(args, "name")
        password_hash = bool_arg(args, "password_hash")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), password_hash=password_hash, fields=fields)
        response = self._http_request("get", f"/users/{name}", params=params)

        return CommandResults(
            outputs_prefix="WAB.user_get",
            outputs_key_field="user_name",
            outputs=response,
            readable_output=to_markdown("wab-get-user", response),
            raw_response=response,
        )

    def edit_user(self, args: Dict[str, Any]):
        name = str_arg(args, "name")
        force = bool_arg(args, "force")
        password_hash = bool_arg(args, "password_hash")
        user_put_user_name = str_arg(args, "user_put_user_name")
        user_put_display_name = str_arg(args, "user_put_display_name")
        user_put_email = str_arg(args, "user_put_email")
        user_put_ip_source = str_arg(args, "user_put_ip_source")
        user_put_preferred_language = str_arg(args, "user_put_preferred_language")
        user_put_profile = str_arg(args, "user_put_profile")
        user_put_groups = list_arg(args, "user_put_groups")
        user_put_user_auths = list_arg(args, "user_put_user_auths")
        user_put_password = str_arg(args, "user_put_password")
        user_put_force_change_pwd = bool_arg(args, "user_put_force_change_pwd")
        user_put_ssh_public_key = str_arg(args, "user_put_ssh_public_key")
        user_put_certificate_dn = str_arg(args, "user_put_certificate_dn")
        user_put_last_connection = str_arg(args, "user_put_last_connection", nullable=True)
        user_put_expiration_date = str_arg(args, "user_put_expiration_date")
        user_put_is_disabled = bool_arg(args, "user_put_is_disabled")
        user_put_gpg_public_key = str_arg(args, "user_put_gpg_public_key")

        params = assign_params(values_to_ignore=(None,), force=force, password_hash=password_hash)
        body = assign_params(
            values_to_ignore=(None,),
            user_name=user_put_user_name,
            display_name=user_put_display_name,
            email=user_put_email,
            ip_source=user_put_ip_source,
            preferred_language=user_put_preferred_language,
            profile=user_put_profile,
            groups=user_put_groups,
            user_auths=user_put_user_auths,
            password=user_put_password,
            force_change_pwd=user_put_force_change_pwd,
            ssh_public_key=user_put_ssh_public_key,
            certificate_dn=user_put_certificate_dn,
            last_connection=user_put_last_connection,
            expiration_date=user_put_expiration_date,
            is_disabled=user_put_is_disabled,
            gpg_public_key=user_put_gpg_public_key,
        )
        response = self._http_request("put", f"/users/{name}", params=params, json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_target_group_restrictions(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/targetgroups/{group_id}/restrictions", params=params)

        return CommandResults(
            outputs_prefix="WAB.restriction_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-target-group-restrictions", response),
            raw_response=response,
        )

    def get_target_group_restriction(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        restriction_id = str_arg(args, "restriction_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/targetgroups/{group_id}/restrictions/{restriction_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.restriction_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-target-group-restriction", response),
            raw_response=response,
        )

    def edit_restriction_from_targetgroup(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        restriction_id = str_arg(args, "restriction_id")
        restriction_put_action = str_arg(args, "restriction_put_action")
        restriction_put_rules = str_arg(args, "restriction_put_rules")
        restriction_put_subprotocol = str_arg(args, "restriction_put_subprotocol")

        body = assign_params(
            values_to_ignore=(None,),
            action=restriction_put_action,
            rules=restriction_put_rules,
            subprotocol=restriction_put_subprotocol,
        )
        response = self._http_request("put", f"/targetgroups/{group_id}/restrictions/{restriction_id}", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_restriction_from_targetgroup(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        restriction_id = str_arg(args, "restriction_id")

        response = self._http_request("delete", f"/targetgroups/{group_id}/restrictions/{restriction_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_password_for_target(self, args: Dict[str, Any]):
        account_name = str_arg(args, "account_name")
        key_format = str_arg(args, "key_format")
        cert_format = str_arg(args, "cert_format")
        authorization = str_arg(args, "authorization")
        duration = int_arg(args, "duration")

        params = assign_params(
            values_to_ignore=(None,),
            key_format=key_format,
            cert_format=cert_format,
            authorization=authorization,
            duration=duration,
        )
        response = self._http_request("get", f"/targetpasswords/checkout/{account_name}", params=params)

        add_key_to_outputs(response, "account_name", account_name)

        return CommandResults(
            outputs_prefix="WAB.targetpasswords_get_checkout",
            outputs_key_field="account_name",
            outputs=response,
            readable_output=to_markdown("wab-get-password-for-target", response),
            raw_response=response,
        )

    def extend_duration_time_to_get_passwords_for_target(self, args: Dict[str, Any]):
        account_name = str_arg(args, "account_name")
        authorization = str_arg(args, "authorization")

        params = assign_params(values_to_ignore=(None,), authorization=authorization)
        response = self._http_request("get", f"/targetpasswords/extendcheckout/{account_name}", params=params)

        return CommandResults(readable_output="Success!", raw_response=response)

    def release_passwords_for_target(self, args: Dict[str, Any]):
        account_name = str_arg(args, "account_name")
        authorization = str_arg(args, "authorization")
        force = bool_arg(args, "force")
        comment = str_arg(args, "comment")

        params = assign_params(values_to_ignore=(None,), authorization=authorization, force=force, comment=comment)
        response = self._http_request("get", f"/targetpasswords/checkin/{account_name}", params=params)

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_target_by_type(self, args: Dict[str, Any]):
        target_type = str_arg(args, "target_type")
        group = str_arg(args, "group")
        group_id = str_arg(args, "group_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(
            values_to_ignore=(None,), group=group, group_id=group_id, q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        response = self._http_request("get", f"/targets/{target_type}", params=params)

        return CommandResults(
            outputs_prefix="WAB.getTargetByType",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-target-by-type", response),
            raw_response=response,
        )

    def get_mappings_of_user_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/usergroups/{group_id}/mappings", params=params)

        return CommandResults(
            outputs_prefix="WAB.authdomain_mapping_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-mappings-of-user-group", response),
            raw_response=response,
        )

    def add_mapping_in_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        usergroup_mapping_post_domain = str_arg(args, "usergroup_mapping_post_domain")
        usergroup_mapping_post_external_group = str_arg(args, "usergroup_mapping_post_external_group")
        usergroup_mapping_post_profile = str_arg(args, "usergroup_mapping_post_profile")

        body = assign_params(
            values_to_ignore=(None,),
            domain=usergroup_mapping_post_domain,
            external_group=usergroup_mapping_post_external_group,
            profile=usergroup_mapping_post_profile,
        )
        response = self._http_request("post", f"/usergroups/{group_id}/mappings", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_mapping_in_group",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-mapping-in-group", response),
            raw_response=response,
        )

    def get_mapping_of_user_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        mapping_id = str_arg(args, "mapping_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/usergroups/{group_id}/mappings/{mapping_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.authdomain_mapping_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-mapping-of-user-group", response),
            raw_response=response,
        )

    def edit_mapping_of_user_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        mapping_id = str_arg(args, "mapping_id")
        usergroup_mapping_post_domain = str_arg(args, "usergroup_mapping_post_domain")
        usergroup_mapping_post_external_group = str_arg(args, "usergroup_mapping_post_external_group")
        usergroup_mapping_post_profile = str_arg(args, "usergroup_mapping_post_profile")

        body = assign_params(
            values_to_ignore=(None,),
            domain=usergroup_mapping_post_domain,
            external_group=usergroup_mapping_post_external_group,
            profile=usergroup_mapping_post_profile,
        )
        response = self._http_request("put", f"/usergroups/{group_id}/mappings/{mapping_id}", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_mapping_of_user_group(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        mapping_id = str_arg(args, "mapping_id")

        response = self._http_request("delete", f"/usergroups/{group_id}/mappings/{mapping_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_user_group_restrictions(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        q = str_arg(args, "q")
        sort = str_arg(args, "sort")
        offset = int_arg(args, "offset")
        limit = int_arg(args, "limit")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), q=q, sort=sort, offset=offset, limit=limit, fields=fields)
        response = self._http_request("get", f"/usergroups/{group_id}/restrictions", params=params)

        return CommandResults(
            outputs_prefix="WAB.restriction_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-user-group-restrictions", response),
            raw_response=response,
        )

    def add_restriction_to_usergroup(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        restriction_post_action = str_arg(args, "restriction_post_action")
        restriction_post_rules = str_arg(args, "restriction_post_rules")
        restriction_post_subprotocol = str_arg(args, "restriction_post_subprotocol")

        body = assign_params(
            values_to_ignore=(None,),
            action=restriction_post_action,
            rules=restriction_post_rules,
            subprotocol=restriction_post_subprotocol,
        )
        response = self._http_request("post", f"/usergroups/{group_id}/restrictions", json_data=body)

        return CommandResults(
            outputs_prefix="WAB.add_restriction_to_usergroup",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-add-restriction-to-usergroup", response),
            raw_response=response,
        )

    def get_user_group_restriction(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        restriction_id = str_arg(args, "restriction_id")
        fields = str_arg(args, "fields")

        params = assign_params(values_to_ignore=(None,), fields=fields)
        response = self._http_request("get", f"/usergroups/{group_id}/restrictions/{restriction_id}", params=params)

        return CommandResults(
            outputs_prefix="WAB.restriction_get",
            outputs_key_field="id",
            outputs=response,
            readable_output=to_markdown("wab-get-user-group-restriction", response),
            raw_response=response,
        )

    def edit_restriction_from_usergroup(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        restriction_id = str_arg(args, "restriction_id")
        restriction_put_action = str_arg(args, "restriction_put_action")
        restriction_put_rules = str_arg(args, "restriction_put_rules")
        restriction_put_subprotocol = str_arg(args, "restriction_put_subprotocol")

        body = assign_params(
            values_to_ignore=(None,),
            action=restriction_put_action,
            rules=restriction_put_rules,
            subprotocol=restriction_put_subprotocol,
        )
        response = self._http_request("put", f"/usergroups/{group_id}/restrictions/{restriction_id}", json_data=body)

        return CommandResults(readable_output="Success!", raw_response=response)

    def delete_restriction_from_usergroup(self, args: Dict[str, Any]):
        group_id = str_arg(args, "group_id")
        restriction_id = str_arg(args, "restriction_id")

        response = self._http_request("delete", f"/usergroups/{group_id}/restrictions/{restriction_id}")

        return CommandResults(readable_output="Success!", raw_response=response)

    def get_version(self, args: Dict[str, Any]):

        response = self._http_request("get", "/version")

        return CommandResults(
            outputs_prefix="WAB.version_get",
            outputs=response,
            readable_output=to_markdown("wab-get-version", response),
            raw_response=response,
        )


def test_module(client: Client):
    """
    Tests API connectivity and authentication
    Returning 'ok' indicates that connection to the Bastion appliance is successful.
    Raises exceptions if something goes wrong.
    """

    try:
        client._http_request("get", "", headers={})
        demisto.results("ok")
    except DemistoException as e:
        if e.res:
            raise Exception(f"{e.res.status_code}: {e.res.text}")

        raise e


def validate_api_version(v: str):
    v = v.removeprefix("v")

    vs = v.split(".")
    if len(vs) != 2:
        raise Exception("invalid version format")
    try:
        int(vs[0])
        int(vs[1])
    except ValueError:
        raise Exception("invalid version format") from None

    return v


def get_session_token():
    integration_context: dict = get_integration_context()
    token = integration_context.get("session_token")
    last_request_at = integration_context.get("last_request_at")
    time_now = int(time.time())
    if token and last_request_at and time_now - last_request_at < 100:
        return token
    return None


def update_session_token(token: str | None):
    if token is None:
        set_integration_context({})
    else:
        time_now = int(time.time())

        integration_context = {
            "session_token": token,
            "last_request_at": time_now,
        }
        set_integration_context(integration_context)


def raise_deprecated(old_command, new_command):
    raise DemistoException(f"{old_command} is deprecated. Use {new_command} instead")


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get("url")
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    timeout = params.get("timeout", False)

    if timeout:
        try:
            timeout = int(timeout)
        except ValueError:
            raise ValueError("timeout must be a positive integer, got " + str(timeout))
        if timeout <= 0:
            raise ValueError("timeout must be a positive integer, got " + str(timeout))

    base_path = "/api"

    apiv: str = params.get("api_version", "")

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        if not verify_certificate:
            urllib3.disable_warnings(category=urllib3_exceptions.InsecureRequestWarning)

        if apiv:
            apiv = validate_api_version(apiv)
            base_path += "/v" + apiv

        client: Client = Client(
            params["auth_key"],
            params["auth_user"],
            params.get("is_password", False),
            urljoin(url, base_path),
            verify_certificate,
            proxy,
            timeout,
        )

        commands: Dict[str, Any] = {
            "wab-add-session-target-to-target-group": client.add_session_target_to_target_group,
            "wab-add-password-target-to-target-group": client.add_password_target_to_target_group,
            "wab-add-restriction-to-target-group": client.add_restriction_to_target_group,
            "wab-add-timeframe-period": client.add_timeframe_period,
            "wab-add-global-domain": client.add_global_domain,
            "wab-get-account-references": client.get_account_references,
            "wab-get-account-reference": client.get_account_reference,
            "wab-change-password-or-ssh-key-of-account": client.change_password_or_ssh_key_of_account,
            "wab-get-all-accounts": client.get_all_accounts,
            "wab-get-one-account": client.get_one_account,
            "wab-delete-account": client.delete_account,
            "wab-get-application-account-credentials": client.get_application_account_credentials,
            "wab-add-credential-to-application-account": client.add_credential_to_application_account,
            "wab-get-application-account-credential": client.get_application_account_credential,
            "wab-edit-credential-of-application-account": client.edit_credential_of_application_account,
            "wab-get-application-accounts": client.get_application_accounts,
            "wab-add-account-to-local-domain-of-application": client.add_account_to_local_domain_of_application,
            "wab-get-application-account": client.get_application_account,
            "wab-edit-account-on-local-domain-of-application": client.edit_account_on_local_domain_of_application,
            "wab-delete-account-from-local-domain-of-application": client.delete_account_from_local_domain_of_application,
            "wab-get-local-domains-data-for-application": client.get_local_domains_data_for_application,
            "wab-add-local-domain-in-application": client.add_local_domain_in_application,
            "wab-get-local-domain-data-for-application": client.get_local_domain_data_for_application,
            "wab-delete-local-domain-from-application": client.delete_local_domain_from_application,
            "wab-get-applications": client.get_applications,
            "wab-get-application": client.get_application,
            "wab-edit-application": client.edit_application,
            "wab-delete-application": client.delete_application,
            "wab-get-approvals": client.get_approvals,
            "wab-get-approvals-for-all-approvers": client.get_approvals_for_all_approvers,
            "wab-reply-to-approval-request": client.reply_to_approval_request,
            "wab-get-approvals-for-approver": client.get_approvals_for_approver,
            "wab-cancel-accepted-approval": client.cancel_accepted_approval,
            "wab-notify-approvers-linked-to-approval-assignment": client.notify_approvers_linked_to_approval_assignment,
            "wab-get-approval-request-pending-for-user": client.get_approval_request_pending_for_user,
            "wab-make-new-approval-request-to-access-target": client.make_new_approval_request_to_access_target,
            "wab-cancel-approval-request": client.cancel_approval_request,
            "wab-notify-approvers-linked-to-approval-request": client.notify_approvers_linked_to_approval_request,
            "wab-check-if-approval-is-required-for-target": client.check_if_approval_is_required_for_target,
            "wab-get-mappings-of-domain": client.get_mappings_of_domain,
            "wab-add-mapping-in-domain": client.add_mapping_in_domain,
            "wab-edit-mappings-of-domain": client.edit_mappings_of_domain,
            "wab-get-mapping-of-domain": client.get_mapping_of_domain,
            "wab-edit-mapping-of-domain": client.edit_mapping_of_domain,
            "wab-delete-mapping-of-domain": client.delete_mapping_of_domain,
            "wab-get-auth-domains": client.get_auth_domains,
            "wab-get-auth-domain": client.get_auth_domain,
            "wab-get-authentications": client.get_authentications,
            "wab-get-authentication": client.get_authentication,
            "wab-get-authorizations": client.get_authorizations,
            "wab-add-authorization": client.add_authorization,
            "wab-get-authorization": client.get_authorization,
            "wab-edit-authorization": client.edit_authorization,
            "wab-delete-authorization": client.delete_authorization,
            "wab-get-checkout-policies": client.get_checkout_policies,
            "wab-get-checkout-policy": client.get_checkout_policy,
            "wab-get-clusters": client.get_clusters,
            "wab-get-cluster": client.get_cluster,
            "wab-getx509-configuration-infos": client.getx509_configuration_infos,
            "wab-uploadx509-configuration": client.uploadx509_configuration,
            "wab-updatex509-configuration": client.updatex509_configuration,
            "wab-resetx509-configuration": client.resetx509_configuration,
            "wab-get-current-serial-configuration-number-of-bastion": client.get_current_serial_configuration_number_of_bastion,
            "wab-get-connection-policies": client.get_connection_policies,
            "wab-add-connection-policy": client.add_connection_policy,
            "wab-get-connection-policy": client.get_connection_policy,
            "wab-edit-connection-policy": client.edit_connection_policy,
            "wab-delete-connection-policy": client.delete_connection_policy,
            "wab-get-device-account-credentials": client.get_device_account_credentials,
            "wab-add-credential-to-device-account": client.add_credential_to_device_account,
            "wab-get-device-account-credential": client.get_device_account_credential,
            "wab-edit-credential-of-device-account": client.edit_credential_of_device_account,
            "wab-get-all-accounts-on-device-local-domain": client.get_all_accounts_on_device_local_domain,
            "wab-add-account-to-local-domain-on-device": client.add_account_to_local_domain_on_device,
            "wab-get-one-account-on-device-local-domain": client.get_one_account_on_device_local_domain,
            "wab-edit-account-on-local-domain-of-device": client.edit_account_on_local_domain_of_device,
            "wab-delete-account-from-local-domain-of-device": client.delete_account_from_local_domain_of_device,
            "wab-get-certificates-on-device": client.get_certificates_on_device,
            "wab-get-certificate-on-device": client.get_certificate_on_device,
            "wab-revoke-certificate-of-device": client.revoke_certificate_of_device,
            "wab-get-local-domains-of-device": client.get_local_domains_of_device,
            "wab-add-local-domain-in-device": client.add_local_domain_in_device,
            "wab-get-local-domain-of-device": client.get_local_domain_of_device,
            "wab-delete-local-domain-from-device": client.delete_local_domain_from_device,
            "wab-get-services-of-device": client.get_services_of_device,
            "wab-add-service-in-device": client.add_service_in_device,
            "wab-get-service-of-device": client.get_service_of_device,
            "wab-edit-service-of-device": client.edit_service_of_device,
            "wab-delete-service-from-device": client.delete_service_from_device,
            "wab-get-devices": client.get_devices,
            "wab-add-device": client.add_device,
            "wab-get-device": client.get_device,
            "wab-edit-device": client.edit_device,
            "wab-delete-device": client.delete_device,
            "wab-get-global-domain-account-credentials": client.get_global_domain_account_credentials,
            "wab-get-global-domain-account-credential": client.get_global_domain_account_credential,
            "wab-edit-credential-of-global-domain-account": client.edit_credential_of_global_domain_account,
            "wab-add-credential-to-global-domain-account": client.add_credential_to_global_domain_account,
            "wab-get-accounts-of-global-domain": client.get_accounts_of_global_domain,
            "wab-add-account-in-global-domain": client.add_account_in_global_domain,
            "wab-get-account-of-global-domain": client.get_account_of_global_domain,
            "wab-edit-account-in-global-domain": client.edit_account_in_global_domain,
            "wab-delete-account-from-global-domain": client.delete_account_from_global_domain,
            "wab-delete-resource-from-global-domain-account": client.delete_resource_from_global_domain_account,
            "wab-get-global-domains": client.get_global_domains,
            "wab-get-global-domain": client.get_global_domain,
            "wab-delete-global-domain": client.delete_global_domain,
            "wab-get-external-authentications": client.get_external_authentications,
            "wab-get-external-authentication": client.get_external_authentication,
            "wab-get-external-authentication-group-mappings": client.get_external_authentication_group_mappings,
            "wab-get-ldap-users-of-domain": client.get_ldap_users_of_domain,
            "wab-get-ldap-user-of-domain": client.get_ldap_user_of_domain,
            "wab-get-information-about-wallix-bastion-license": client.get_information_about_wallix_bastion_license,
            "wab-post-logsiem": client.post_logsiem,
            "wab-get-notifications": client.get_notifications,
            "wab-add-notification": client.add_notification,
            "wab-get-notification": client.get_notification,
            "wab-edit-notification": client.edit_notification,
            "wab-delete-notification": client.delete_notification,
            "wab-get-object-to-onboard": client.get_object_to_onboard,
            "wab-get-password-change-policies": client.get_password_change_policies,
            "wab-add-password-change-policy": client.add_password_change_policy,
            "wab-get-password-change-policy": client.get_password_change_policy,
            "wab-edit-password-change-policy": client.edit_password_change_policy,
            "wab-delete-password-change-policy": client.delete_password_change_policy,
            "wab-get-passwordrights": client.get_passwordrights,
            "wab-get-passwordrights-user-name": client.get_passwordrights_user_name,
            "wab-get-profiles": client.get_profiles,
            "wab-get-profile": client.get_profile,
            "wab-get-scanjobs": client.get_scanjobs,
            "wab-start-scan-job-manually": client.start_scan_job_manually,
            "wab-get-scanjob": client.get_scanjob,
            "wab-cancel-scan-job": client.cancel_scan_job,
            "wab-get-scans": client.get_scans,
            "wab-get-scan": client.get_scan,
            "wab-edit-scan": client.edit_scan,
            "wab-delete-scan": client.delete_scan,
            "wab-get-sessionrights": client.get_sessionrights,
            "wab-get-sessionrights-user-name": client.get_sessionrights_user_name,
            "wab-get-sessions": client.get_sessions,
            "wab-edit-session": client.edit_session,
            "wab-get-session-metadata": client.get_session_metadata,
            "wab-get-session-sharing-requests": client.get_session_sharing_requests,
            "wab-create-session-request": client.create_session_request,
            "wab-delete-pending-or-live-session-request": client.delete_pending_or_live_session_request,
            "wab-get-latest-snapshot-of-running-session": client.get_latest_snapshot_of_running_session,
            "wab-get-status-of-trace-generation": client.get_status_of_trace_generation,
            "wab-generate-trace-for-session": client.generate_trace_for_session,
            "wab-get-wallix-bastion-usage-statistics": client.get_wallix_bastion_usage_statistics,
            "wab-get-target-groups": client.get_target_groups,
            "wab-add-target-group": client.add_target_group,
            "wab-get-target-group": client.get_target_group,
            "wab-edit-target-group": client.edit_target_group,
            "wab-delete-target-group": client.delete_target_group,
            "wab-delete-target-from-group": client.delete_target_from_group,
            "wab-get-timeframes": client.get_timeframes,
            "wab-add-timeframe": client.add_timeframe,
            "wab-get-timeframe": client.get_timeframe,
            "wab-edit-timeframe": client.edit_timeframe,
            "wab-delete-timeframe": client.delete_timeframe,
            "wab-get-user-groups": client.get_user_groups,
            "wab-add-user-group": client.add_user_group,
            "wab-get-user-group": client.get_user_group,
            "wab-edit-user-group": client.edit_user_group,
            "wab-delete-user-group": client.delete_user_group,
            "wab-get-users": client.get_users,
            "wab-add-user": client.add_user,
            "wab-get-user": client.get_user,
            "wab-edit-user": client.edit_user,
            "wab-get-target-group-restrictions": client.get_target_group_restrictions,
            "wab-get-target-group-restriction": client.get_target_group_restriction,
            "wab-edit-restriction-from-targetgroup": client.edit_restriction_from_targetgroup,
            "wab-delete-restriction-from-targetgroup": client.delete_restriction_from_targetgroup,
            "wab-get-password-for-target": client.get_password_for_target,
            "wab-extend-duration-time-to-get-passwords-for-target": client.extend_duration_time_to_get_passwords_for_target,
            "wab-release-passwords-for-target": client.release_passwords_for_target,
            "wab-get-target-by-type": client.get_target_by_type,
            "wab-get-mappings-of-user-group": client.get_mappings_of_user_group,
            "wab-add-mapping-in-group": client.add_mapping_in_group,
            "wab-get-mapping-of-user-group": client.get_mapping_of_user_group,
            "wab-edit-mapping-of-user-group": client.edit_mapping_of_user_group,
            "wab-delete-mapping-of-user-group": client.delete_mapping_of_user_group,
            "wab-get-user-group-restrictions": client.get_user_group_restrictions,
            "wab-add-restriction-to-usergroup": client.add_restriction_to_usergroup,
            "wab-get-user-group-restriction": client.get_user_group_restriction,
            "wab-edit-restriction-from-usergroup": client.edit_restriction_from_usergroup,
            "wab-delete-restriction-from-usergroup": client.delete_restriction_from_usergroup,
            "wab-get-version": client.get_version,
        }

        if command == "test-module":
            test_module(client)
        elif command in commands:
            return_results(commands[command](args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()

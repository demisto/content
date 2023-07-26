import demistomock as demisto
from CommonServerPython import *
import time
import requests
from requests import Response


class AuthError(Exception):
    pass


class Client(BaseClient):
    def __init__(self, auth_key, auth_user, server_url, verify, proxy):
        self._auth_key = auth_key
        self._auth_user = auth_user

        super().__init__(
            base_url=server_url, verify=verify, proxy=proxy, headers={}, auth=None
        )

    def _raise_client_exc(self, res: Response):
        if res.status_code == 401:
            raise AuthError()
        self.client_error_handler(res)

    def _http_request(self, *args, **kwargs):
        headers: dict = kwargs["headers"]

        first_auth = True
        token = get_session_token()
        if token:
            headers["Cookies"] = token
            first_auth = False
        else:
            headers["X-Auth-Key"] = self._auth_key
            headers["X-Auth-User"] = self._auth_user

        client_err_handler = (
            None if first_auth else self._raise_client_exc
        )  # no AuthError if first_auth is True

        try:
            resp: Response = super()._http_request(
                *args, **kwargs, resp_type="response", error_handler=client_err_handler  # type: ignore
            )
        except AuthError:  # AuthError is only raised when first_auth is False
            update_session_token(None)

            first_auth = True
            headers["X-Auth-Key"] = self._auth_key
            headers["X-Auth-User"] = self._auth_user

            # retry
            resp = super()._http_request(
                *args, **kwargs, resp_type="response"  # type: ignore
            )

        if first_auth:
            token = resp.headers.get("Set-Cookie")

        update_session_token(token)

        if resp.status_code == 204:
            return {}

        return resp.json()

    def add_account_in_global_domain_request(
        self,
        domain_id,
        domain_account_post_account_login,
        domain_account_post_account_name,
        domain_account_post_auto_change_password,
        domain_account_post_auto_change_ssh_key,
        domain_account_post_can_edit_certificate_validity,
        domain_account_post_certificate_validity,
        domain_account_post_checkout_policy,
        domain_account_post_description,
        domain_account_post_resources,
    ):
        data = assign_params(
            account_login=domain_account_post_account_login,
            account_name=domain_account_post_account_name,
            auto_change_password=domain_account_post_auto_change_password,
            auto_change_ssh_key=domain_account_post_auto_change_ssh_key,
            can_edit_certificate_validity=domain_account_post_can_edit_certificate_validity,
            certificate_validity=domain_account_post_certificate_validity,
            checkout_policy=domain_account_post_checkout_policy,
            description=domain_account_post_description,
            resources=domain_account_post_resources,
        )
        headers = self._headers

        response = self._http_request(
            "post", f"domains/{domain_id}/accounts", json_data=data, headers=headers
        )

        return response

    def add_account_to_local_domain_of_application_request(
        self,
        application_id,
        domain_id,
        app_account_post_account_login,
        app_account_post_account_name,
        app_account_post_auto_change_password,
        app_account_post_can_edit_certificate_validity,
        app_account_post_certificate_validity,
        app_account_post_checkout_policy,
        app_account_post_description,
    ):
        data = assign_params(
            account_login=app_account_post_account_login,
            account_name=app_account_post_account_name,
            auto_change_password=app_account_post_auto_change_password,
            can_edit_certificate_validity=app_account_post_can_edit_certificate_validity,
            certificate_validity=app_account_post_certificate_validity,
            checkout_policy=app_account_post_checkout_policy,
            description=app_account_post_description,
        )
        headers = self._headers

        response = self._http_request(
            "post",
            f"applications/{application_id}/localdomains/{domain_id}/accounts",
            json_data=data,
            headers=headers,
        )

        return response

    def add_account_to_local_domain_on_device_request(
        self,
        device_id,
        domain_id,
        device_account_post_account_login,
        device_account_post_account_name,
        device_account_post_auto_change_password,
        device_account_post_auto_change_ssh_key,
        device_account_post_can_edit_certificate_validity,
        device_account_post_certificate_validity,
        device_account_post_checkout_policy,
        device_account_post_description,
        device_account_post_services,
    ):
        data = assign_params(
            account_login=device_account_post_account_login,
            account_name=device_account_post_account_name,
            auto_change_password=device_account_post_auto_change_password,
            auto_change_ssh_key=device_account_post_auto_change_ssh_key,
            can_edit_certificate_validity=device_account_post_can_edit_certificate_validity,
            certificate_validity=device_account_post_certificate_validity,
            checkout_policy=device_account_post_checkout_policy,
            description=device_account_post_description,
            services=device_account_post_services,
        )
        headers = self._headers

        response = self._http_request(
            "post",
            f"devices/{device_id}/localdomains/{domain_id}/accounts",
            json_data=data,
            headers=headers,
        )

        return response

    def add_authorization_request(
        self,
        authorization_post_active_quorum,
        authorization_post_approval_required,
        authorization_post_approval_timeout,
        authorization_post_approvers,
        authorization_post_authorization_name,
        authorization_post_authorize_password_retrieval,
        authorization_post_authorize_session_sharing,
        authorization_post_authorize_sessions,
        authorization_post_description,
        authorization_post_has_comment,
        authorization_post_has_ticket,
        authorization_post_inactive_quorum,
        authorization_post_is_critical,
        authorization_post_is_recorded,
        authorization_post_mandatory_comment,
        authorization_post_mandatory_ticket,
        authorization_post_session_sharing_mode,
        authorization_post_single_connection,
        authorization_post_subprotocols,
        authorization_post_target_group,
        authorization_post_user_group,
    ):
        data = assign_params(
            active_quorum=authorization_post_active_quorum,
            approval_required=authorization_post_approval_required,
            approval_timeout=authorization_post_approval_timeout,
            approvers=authorization_post_approvers,
            authorization_name=authorization_post_authorization_name,
            authorize_password_retrieval=authorization_post_authorize_password_retrieval,
            authorize_session_sharing=authorization_post_authorize_session_sharing,
            authorize_sessions=authorization_post_authorize_sessions,
            description=authorization_post_description,
            has_comment=authorization_post_has_comment,
            has_ticket=authorization_post_has_ticket,
            inactive_quorum=authorization_post_inactive_quorum,
            is_critical=authorization_post_is_critical,
            is_recorded=authorization_post_is_recorded,
            mandatory_comment=authorization_post_mandatory_comment,
            mandatory_ticket=authorization_post_mandatory_ticket,
            session_sharing_mode=authorization_post_session_sharing_mode,
            single_connection=authorization_post_single_connection,
            subprotocols=authorization_post_subprotocols,
            target_group=authorization_post_target_group,
            user_group=authorization_post_user_group,
        )
        headers = self._headers

        response = self._http_request(
            "post", "authorizations", json_data=data, headers=headers
        )

        return response

    def add_device_request(
        self,
        device_post_host,
        device_post_alias,
        device_post_description,
        device_post_device_name,
    ):
        data = assign_params(
            host=device_post_host,
            alias=device_post_alias,
            description=device_post_description,
            device_name=device_post_device_name,
        )
        headers = self._headers

        response = self._http_request(
            "post", "devices", json_data=data, headers=headers
        )

        return response

    def add_notification_request(
        self,
        notification_post_description,
        notification_post_destination,
        notification_post_enabled,
        notification_post_events,
        notification_post_language,
        notification_post_notification_name,
        notification_post_type,
    ):
        data = assign_params(
            description=notification_post_description,
            destination=notification_post_destination,
            enabled=notification_post_enabled,
            events=notification_post_events,
            language=notification_post_language,
            notification_name=notification_post_notification_name,
            type=notification_post_type,
        )
        headers = self._headers

        response = self._http_request(
            "post", "notifications", json_data=data, headers=headers
        )

        return response

    def add_user_request(
        self,
        password_hash,
        user_post_certificate_dn,
        user_post_display_name,
        user_post_email,
        user_post_expiration_date,
        user_post_force_change_pwd,
        user_post_gpg_public_key,
        user_post_groups,
        user_post_ip_source,
        user_post_is_disabled,
        user_post_last_connection,
        user_post_password,
        user_post_preferred_language,
        user_post_profile,
        user_post_ssh_public_key,
        user_post_user_auths,
        user_post_user_name,
    ):
        params = assign_params(password_hash=password_hash)
        data = assign_params(
            certificate_dn=user_post_certificate_dn,
            display_name=user_post_display_name,
            email=user_post_email,
            expiration_date=user_post_expiration_date,
            force_change_pwd=user_post_force_change_pwd,
            gpg_public_key=user_post_gpg_public_key,
            groups=user_post_groups,
            ip_source=user_post_ip_source,
            is_disabled=user_post_is_disabled,
            last_connection=user_post_last_connection,
            password=user_post_password,
            preferred_language=user_post_preferred_language,
            profile=user_post_profile,
            ssh_public_key=user_post_ssh_public_key,
            user_auths=user_post_user_auths,
            user_name=user_post_user_name,
        )
        headers = self._headers

        response = self._http_request(
            "post", "users", params=params, json_data=data, headers=headers
        )

        return response

    def cancel_accepted_approval_request(
        self,
        approval_assignment_cancel_post_comment,
        approval_assignment_cancel_post_id,
    ):
        data = assign_params(
            comment=approval_assignment_cancel_post_comment,
            id=approval_assignment_cancel_post_id,
        )
        headers = self._headers

        response = self._http_request(
            "post", "approvals/assignments/cancel", json_data=data, headers=headers
        )

        return response

    def cancel_approval_request_request(self, approval_request_cancel_post_id):
        data = assign_params(id=approval_request_cancel_post_id)
        headers = self._headers

        response = self._http_request(
            "post", "approvals/requests/cancel", json_data=data, headers=headers
        )

        return response

    def cancel_scan_job_request(self, scanjob_id):
        headers = self._headers

        response = self._http_request("put", f"scanjobs/{scanjob_id}", headers=headers)

        return response

    def check_if_approval_is_required_for_target_request(
        self, target_name, authorization, begin
    ):
        params = assign_params(authorization=authorization, begin=begin)
        headers = self._headers

        response = self._http_request(
            "get",
            f"approvals/requests/target/{target_name}",
            params=params,
            headers=headers,
        )

        return response

    def create_session_request_request(
        self, session_request_post_mode, session_request_post_session_id
    ):
        data = assign_params(
            mode=session_request_post_mode, session_id=session_request_post_session_id
        )
        headers = self._headers

        response = self._http_request(
            "post", "sessions/requests", json_data=data, headers=headers
        )

        return response

    def delete_account_request(self, account_id):
        headers = self._headers

        response = self._http_request(
            "delete", f"accounts/{account_id}", headers=headers
        )

        return response

    def delete_account_from_global_domain_request(self, domain_id, account_id):
        headers = self._headers

        response = self._http_request(
            "delete", f"domains/{domain_id}/accounts/{account_id}", headers=headers
        )

        return response

    def delete_account_from_local_domain_of_application_request(
        self, application_id, domain_id, account_id
    ):
        headers = self._headers

        response = self._http_request(
            "delete",
            f"applications/{application_id}/localdomains/{domain_id}/accounts/{account_id}",
            headers=headers,
        )

        return response

    def delete_account_from_local_domain_of_device_request(
        self, device_id, domain_id, account_id
    ):
        headers = self._headers

        response = self._http_request(
            "delete",
            f"devices/{device_id}/localdomains/{domain_id}/accounts/{account_id}",
            headers=headers,
        )

        return response

    def delete_application_request(self, application_id):
        headers = self._headers

        response = self._http_request(
            "delete", f"applications/{application_id}", headers=headers
        )

        return response

    def delete_authorization_request(self, authorization_id):
        headers = self._headers

        response = self._http_request(
            "delete", f"authorizations/{authorization_id}", headers=headers
        )

        return response

    def delete_device_request(self, device_id):
        headers = self._headers

        response = self._http_request("delete", f"devices/{device_id}", headers=headers)

        return response

    def delete_notification_request(self, notification_id):
        headers = self._headers

        response = self._http_request(
            "delete", f"notifications/{notification_id}", headers=headers
        )

        return response

    def delete_pending_or_live_session_request_request(self, request_id):
        headers = self._headers

        response = self._http_request(
            "delete", f"sessions/requests/{request_id}", headers=headers
        )

        return response

    def delete_resource_from_global_domain_account_request(
        self, domain_id, account_id, resource_name
    ):
        headers = self._headers

        response = self._http_request(
            "delete",
            f"domains/{domain_id}/accounts/{account_id}/resource/{resource_name}",
            headers=headers,
        )

        return response

    def delete_service_from_device_request(self, device_id, service_id):
        headers = self._headers

        response = self._http_request(
            "delete", f"devices/{device_id}/services/{service_id}", headers=headers
        )

        return response

    def edit_account_in_global_domain_request(
        self,
        domain_id,
        account_id,
        force,
        domain_account_put_account_login,
        domain_account_put_account_name,
        domain_account_put_auto_change_password,
        domain_account_put_auto_change_ssh_key,
        domain_account_put_can_edit_certificate_validity,
        domain_account_put_certificate_validity,
        domain_account_put_checkout_policy,
        domain_account_put_description,
        domain_account_put_onboard_status,
        domain_account_put_resources,
    ):
        params = assign_params(force=force)
        data = assign_params(
            account_login=domain_account_put_account_login,
            account_name=domain_account_put_account_name,
            auto_change_password=domain_account_put_auto_change_password,
            auto_change_ssh_key=domain_account_put_auto_change_ssh_key,
            can_edit_certificate_validity=domain_account_put_can_edit_certificate_validity,
            certificate_validity=domain_account_put_certificate_validity,
            checkout_policy=domain_account_put_checkout_policy,
            description=domain_account_put_description,
            onboard_status=domain_account_put_onboard_status,
            resources=domain_account_put_resources,
        )
        headers = self._headers

        response = self._http_request(
            "put",
            f"domains/{domain_id}/accounts/{account_id}",
            params=params,
            json_data=data,
            headers=headers,
        )

        return response

    def edit_account_on_local_domain_of_application_request(
        self,
        application_id,
        domain_id,
        account_id,
        force,
        app_account_put_account_login,
        app_account_put_account_name,
        app_account_put_auto_change_password,
        app_account_put_can_edit_certificate_validity,
        app_account_put_certificate_validity,
        app_account_put_checkout_policy,
        app_account_put_description,
        app_account_put_onboard_status,
    ):
        params = assign_params(force=force)
        data = assign_params(
            account_login=app_account_put_account_login,
            account_name=app_account_put_account_name,
            auto_change_password=app_account_put_auto_change_password,
            can_edit_certificate_validity=app_account_put_can_edit_certificate_validity,
            certificate_validity=app_account_put_certificate_validity,
            checkout_policy=app_account_put_checkout_policy,
            description=app_account_put_description,
            onboard_status=app_account_put_onboard_status,
        )
        headers = self._headers

        response = self._http_request(
            "put",
            f"applications/{application_id}/localdomains/{domain_id}/accounts/{account_id}",
            params=params,
            json_data=data,
            headers=headers,
        )

        return response

    def edit_account_on_local_domain_of_device_request(
        self,
        device_id,
        domain_id,
        account_id,
        force,
        device_account_put_account_login,
        device_account_put_account_name,
        device_account_put_auto_change_password,
        device_account_put_auto_change_ssh_key,
        device_account_put_can_edit_certificate_validity,
        device_account_put_certificate_validity,
        device_account_put_checkout_policy,
        device_account_put_description,
        device_account_put_onboard_status,
        device_account_put_services,
    ):
        params = assign_params(force=force)
        data = assign_params(
            account_login=device_account_put_account_login,
            account_name=device_account_put_account_name,
            auto_change_password=device_account_put_auto_change_password,
            auto_change_ssh_key=device_account_put_auto_change_ssh_key,
            can_edit_certificate_validity=device_account_put_can_edit_certificate_validity,
            certificate_validity=device_account_put_certificate_validity,
            checkout_policy=device_account_put_checkout_policy,
            description=device_account_put_description,
            onboard_status=device_account_put_onboard_status,
            services=device_account_put_services,
        )
        headers = self._headers

        response = self._http_request(
            "put",
            f"devices/{device_id}/localdomains/{domain_id}/accounts/{account_id}",
            params=params,
            json_data=data,
            headers=headers,
        )

        return response

    def edit_application_request(
        self,
        application_id,
        force,
        application_put__meters,
        application_put_application_name,
        application_put_connection_policy,
        application_put_description,
    ):
        params = assign_params(force=force)
        data = assign_params(
            _meters=application_put__meters,
            application_name=application_put_application_name,
            connection_policy=application_put_connection_policy,
            description=application_put_description,
        )
        headers = self._headers

        response = self._http_request(
            "put",
            f"applications/{application_id}",
            params=params,
            json_data=data,
            headers=headers,
        )

        return response

    def edit_authorization_request(
        self,
        authorization_id,
        force,
        authorization_put_active_quorum,
        authorization_put_approval_required,
        authorization_put_approval_timeout,
        authorization_put_approvers,
        authorization_put_authorization_name,
        authorization_put_authorize_password_retrieval,
        authorization_put_authorize_session_sharing,
        authorization_put_authorize_sessions,
        authorization_put_description,
        authorization_put_has_comment,
        authorization_put_has_ticket,
        authorization_put_inactive_quorum,
        authorization_put_is_critical,
        authorization_put_is_recorded,
        authorization_put_mandatory_comment,
        authorization_put_mandatory_ticket,
        authorization_put_session_sharing_mode,
        authorization_put_single_connection,
        authorization_put_subprotocols,
    ):
        params = assign_params(force=force)
        data = assign_params(
            active_quorum=authorization_put_active_quorum,
            approval_required=authorization_put_approval_required,
            approval_timeout=authorization_put_approval_timeout,
            approvers=authorization_put_approvers,
            authorization_name=authorization_put_authorization_name,
            authorize_password_retrieval=authorization_put_authorize_password_retrieval,
            authorize_session_sharing=authorization_put_authorize_session_sharing,
            authorize_sessions=authorization_put_authorize_sessions,
            description=authorization_put_description,
            has_comment=authorization_put_has_comment,
            has_ticket=authorization_put_has_ticket,
            inactive_quorum=authorization_put_inactive_quorum,
            is_critical=authorization_put_is_critical,
            is_recorded=authorization_put_is_recorded,
            mandatory_comment=authorization_put_mandatory_comment,
            mandatory_ticket=authorization_put_mandatory_ticket,
            session_sharing_mode=authorization_put_session_sharing_mode,
            single_connection=authorization_put_single_connection,
            subprotocols=authorization_put_subprotocols,
        )
        headers = self._headers

        response = self._http_request(
            "put",
            f"authorizations/{authorization_id}",
            params=params,
            json_data=data,
            headers=headers,
        )

        return response

    def edit_device_request(
        self,
        device_id,
        force,
        device_put_host,
        device_put_alias,
        device_put_description,
        device_put_device_name,
        device_put_onboard_status,
    ):
        params = assign_params(force=force)
        data = assign_params(
            host=device_put_host,
            alias=device_put_alias,
            description=device_put_description,
            device_name=device_put_device_name,
            onboard_status=device_put_onboard_status,
        )
        headers = self._headers

        response = self._http_request(
            "put",
            f"devices/{device_id}",
            params=params,
            json_data=data,
            headers=headers,
        )

        return response

    def edit_notification_request(
        self,
        notification_id,
        force,
        notification_put_description,
        notification_put_destination,
        notification_put_enabled,
        notification_put_events,
        notification_put_language,
        notification_put_notification_name,
        notification_put_type,
    ):
        params = assign_params(force=force)
        data = assign_params(
            description=notification_put_description,
            destination=notification_put_destination,
            enabled=notification_put_enabled,
            events=notification_put_events,
            language=notification_put_language,
            notification_name=notification_put_notification_name,
            type=notification_put_type,
        )
        headers = self._headers

        response = self._http_request(
            "put",
            f"notifications/{notification_id}",
            params=params,
            json_data=data,
            headers=headers,
        )

        return response

    def edit_service_of_device_request(
        self,
        device_id,
        service_id,
        force,
        service_put_connection_policy,
        service_put_global_domains,
        service_put_port,
    ):
        params = assign_params(force=force)
        data = assign_params(
            connection_policy=service_put_connection_policy,
            global_domains=service_put_global_domains,
            port=service_put_port,
        )
        headers = self._headers

        response = self._http_request(
            "put",
            f"devices/{device_id}/services/{service_id}",
            params=params,
            json_data=data,
            headers=headers,
        )

        return response

    def edit_session_request(self, session_id, action, session_put_edit_description):
        params = assign_params(session_id=session_id, action=action)
        data = assign_params(description=session_put_edit_description)
        headers = self._headers

        response = self._http_request(
            "put", "sessions", params=params, json_data=data, headers=headers
        )

        return response

    def extend_duration_time_to_get_passwords_for_target_request(
        self, account_name, authorization
    ):
        params = assign_params(authorization=authorization)
        headers = self._headers

        response = self._http_request(
            "get",
            f"targetpasswords/extendcheckout/{account_name}",
            params=params,
            headers=headers,
        )

        return response

    def generate_trace_for_session_request(
        self,
        session_trace_post_date,
        session_trace_post_duration,
        session_trace_post_session_id,
    ):
        data = assign_params(
            date=session_trace_post_date,
            duration=session_trace_post_duration,
            session_id=session_trace_post_session_id,
        )
        headers = self._headers

        response = self._http_request(
            "post", "sessions/traces", json_data=data, headers=headers
        )

        return response

    def get_account_of_global_domain_request(self, domain_id, account_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get",
            f"domains/{domain_id}/accounts/{account_id}",
            params=params,
            headers=headers,
        )

        return response

    def get_account_reference_request(self, account_id, reference_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get",
            f"accounts/{account_id}/references/{reference_id}",
            params=params,
            headers=headers,
        )

        return response

    def get_account_references_request(
        self, account_id, q, sort, offset, limit, fields
    ):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", f"accounts/{account_id}/references", params=params, headers=headers
        )

        return response

    def get_accounts_of_global_domain_request(
        self, domain_id, q, offset, limit, fields
    ):
        params = assign_params(q=q, offset=offset, limit=limit, fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"domains/{domain_id}/accounts", params=params, headers=headers
        )

        return response

    def get_all_accounts_request(
        self,
        account_type,
        application,
        device,
        passwords,
        key_format,
        q,
        sort,
        offset,
        limit,
        fields,
    ):
        params = assign_params(
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
        headers = self._headers

        response = self._http_request("get", "accounts", params=params, headers=headers)

        return response

    def get_all_accounts_on_device_local_domain_request(
        self, device_id, domain_id, key_format, q, sort, offset, limit, fields
    ):
        params = assign_params(
            key_format=key_format,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        headers = self._headers

        response = self._http_request(
            "get",
            f"devices/{device_id}/localdomains/{domain_id}/accounts",
            params=params,
            headers=headers,
        )

        return response

    def get_application_request(self, application_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"applications/{application_id}", params=params, headers=headers
        )

        return response

    def get_application_account_request(
        self, application_id, domain_id, account_id, fields
    ):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get",
            f"applications/{application_id}/localdomains/{domain_id}/accounts/{account_id}",
            params=params,
            headers=headers,
        )

        return response

    def get_application_accounts_request(
        self, application_id, domain_id, q, sort, offset, limit, fields
    ):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get",
            f"applications/{application_id}/localdomains/{domain_id}/accounts",
            params=params,
            headers=headers,
        )

        return response

    def get_applications_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", "applications", params=params, headers=headers
        )

        return response

    def get_approval_request_pending_for_user_request(
        self, user, q, sort, offset, limit, fields, approval_id
    ):
        params = assign_params(
            user=user,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
            approval_id=approval_id,
        )
        headers = self._headers

        response = self._http_request(
            "get", "approvals/requests", params=params, headers=headers
        )

        return response

    def get_approvals_request(self, approval_id, q, sort, offset, limit, fields):
        params = assign_params(
            approval_id=approval_id,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        headers = self._headers

        response = self._http_request(
            "get", "approvals", params=params, headers=headers
        )

        return response

    def get_approvals_for_all_approvers_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", "approvals/assignments", params=params, headers=headers
        )

        return response

    def get_approvals_for_approver_request(
        self, user_name, q, sort, offset, limit, fields
    ):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", f"approvals/assignments/{user_name}", params=params, headers=headers
        )

        return response

    def get_auth_domain_request(self, domain_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"authdomains/{domain_id}", params=params, headers=headers
        )

        return response

    def get_auth_domains_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", "authdomains", params=params, headers=headers
        )

        return response

    def get_authentication_request(
        self, auth_id, from_date, to_date, date_field, fields
    ):
        params = assign_params(
            from_date=from_date, to_date=to_date, date_field=date_field, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", f"authentications/{auth_id}", params=params, headers=headers
        )

        return response

    def get_authentications_request(
        self, from_date, to_date, date_field, q, sort, offset, limit, fields
    ):
        params = assign_params(
            from_date=from_date,
            to_date=to_date,
            date_field=date_field,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        headers = self._headers

        response = self._http_request(
            "get", "authentications", params=params, headers=headers
        )

        return response

    def get_authorization_request(self, authorization_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"authorizations/{authorization_id}", params=params, headers=headers
        )

        return response

    def get_authorizations_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", "authorizations", params=params, headers=headers
        )

        return response

    def get_certificate_on_device_request(
        self, device_id, cert_type, address, port, q, sort, offset, limit, fields
    ):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get",
            f"devices/{device_id}/certificates/{cert_type}/{address}/{port}",
            params=params,
            headers=headers,
        )

        return response

    def get_certificates_on_device_request(
        self, device_id, q, sort, offset, limit, fields
    ):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", f"devices/{device_id}/certificates", params=params, headers=headers
        )

        return response

    def get_checkout_policies_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", "checkoutpolicies", params=params, headers=headers
        )

        return response

    def get_checkout_policy_request(self, checkout_policy_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get",
            f"checkoutpolicies/{checkout_policy_id}",
            params=params,
            headers=headers,
        )

        return response

    def get_device_request(self, device_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"devices/{device_id}", params=params, headers=headers
        )

        return response

    def get_devices_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request("get", "devices", params=params, headers=headers)

        return response

    def get_global_domain_request(self, domain_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"domains/{domain_id}", params=params, headers=headers
        )

        return response

    def get_global_domains_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request("get", "domains", params=params, headers=headers)

        return response

    def get_information_about_wallix_bastion_license_request(self):
        headers = self._headers

        response = self._http_request("get", "licenseinfo", headers=headers)

        return response

    def get_latest_snapshot_of_running_session_request(self, session_id):
        headers = self._headers

        response = self._http_request(
            "get", f"sessions/snapshots/{session_id}", headers=headers
        )

        return response

    def get_ldap_user_of_domain_request(
        self, domain, user_name, last_connection, fields
    ):
        params = assign_params(last_connection=last_connection, fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"ldapusers/{domain}/{user_name}", params=params, headers=headers
        )

        return response

    def get_ldap_users_of_domain_request(
        self, domain, last_connection, q, offset, limit, fields
    ):
        params = assign_params(
            last_connection=last_connection,
            q=q,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        headers = self._headers

        response = self._http_request(
            "get", f"ldapusers/{domain}", params=params, headers=headers
        )

        return response

    def get_metadata_of_one_or_multiple_sessions_request(self, session_ids, download):
        params = assign_params(session_ids=session_ids, download=download)
        headers = self._headers

        response = self._http_request(
            "get", "sessions/metadata", params=params, headers=headers
        )

        return response

    def get_notification_request(self, notification_id):
        headers = self._headers

        response = self._http_request(
            "get", f"notifications/{notification_id}", headers=headers
        )

        return response

    def get_notifications_request(self, q, sort, offset, limit):
        params = assign_params(q=q, sort=sort, offset=offset, limit=limit)
        headers = self._headers

        response = self._http_request(
            "get", "notifications", params=params, headers=headers
        )

        return response

    def get_object_to_onboard_request(
        self, object_type, object_status, q, sort, offset, limit, fields
    ):
        params = assign_params(
            object_type=object_type,
            object_status=object_status,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        headers = self._headers

        response = self._http_request(
            "get", "onboarding_objects", params=params, headers=headers
        )

        return response

    def get_one_account_request(
        self,
        account_id,
        account_type,
        application,
        device,
        passwords,
        key_format,
        fields,
    ):
        params = assign_params(
            account_type=account_type,
            application=application,
            device=device,
            passwords=passwords,
            key_format=key_format,
            fields=fields,
        )
        headers = self._headers

        response = self._http_request(
            "get", f"accounts/{account_id}", params=params, headers=headers
        )

        return response

    def get_one_account_on_device_local_domain_request(
        self, device_id, domain_id, account_id, key_format, fields
    ):
        params = assign_params(key_format=key_format, fields=fields)
        headers = self._headers

        response = self._http_request(
            "get",
            f"devices/{device_id}/localdomains/{domain_id}/accounts/{account_id}",
            params=params,
            headers=headers,
        )

        return response

    def get_profile_request(self, profile_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"profiles/{profile_id}", params=params, headers=headers
        )

        return response

    def get_profiles_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request("get", "profiles", params=params, headers=headers)

        return response

    def get_scan_request(self, scan_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"scans/{scan_id}", params=params, headers=headers
        )

        return response

    def get_scanjob_request(self, scanjob_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"scanjobs/{scanjob_id}", params=params, headers=headers
        )

        return response

    def get_scanjobs_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request("get", "scanjobs", params=params, headers=headers)

        return response

    def get_scans_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request("get", "scans", params=params, headers=headers)

        return response

    def get_service_of_device_request(self, device_id, service_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get",
            f"devices/{device_id}/services/{service_id}",
            params=params,
            headers=headers,
        )

        return response

    def get_services_of_device_request(self, device_id, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", f"devices/{device_id}/services", params=params, headers=headers
        )

        return response

    def get_session_sharing_requests_request(self, request_id, session_id):
        params = assign_params(request_id=request_id, session_id=session_id)
        headers = self._headers

        response = self._http_request(
            "get", "sessions/requests", params=params, headers=headers
        )

        return response

    def get_sessionrights_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", "sessionrights", params=params, headers=headers
        )

        return response

    def get_sessionrights_user_name_request(self, user_name, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"sessionrights/{user_name}", params=params, headers=headers
        )

        return response

    def get_sessions_request(
        self,
        session_id,
        otp,
        status,
        from_date,
        to_date,
        date_field,
        q,
        sort,
        offset,
        limit,
        fields,
    ):
        params = assign_params(
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
        headers = self._headers

        response = self._http_request("get", "sessions", params=params, headers=headers)

        return response

    def get_status_of_trace_generation_request(
        self, session_id, date, duration, download
    ):
        params = assign_params(date=date, duration=duration, download=download)
        headers = self._headers

        response = self._http_request(
            "get", f"sessions/traces/{session_id}", params=params, headers=headers
        )

        return response

    def get_target_by_type_request(
        self, target_type, group, group_id, q, sort, offset, limit, fields
    ):
        params = assign_params(
            group=group,
            group_id=group_id,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        headers = self._headers

        response = self._http_request(
            "get", f"targets/{target_type}", params=params, headers=headers
        )

        return response

    def get_target_group_request(self, group_id, device, application, domain, fields):
        params = assign_params(
            device=device, application=application, domain=domain, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", f"targetgroups/{group_id}", params=params, headers=headers
        )

        return response

    def get_target_groups_request(
        self, device, application, domain, q, sort, offset, limit, fields
    ):
        params = assign_params(
            device=device,
            application=application,
            domain=domain,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        headers = self._headers

        response = self._http_request(
            "get", "targetgroups", params=params, headers=headers
        )

        return response

    def get_user_request(self, name, password_hash, fields):
        params = assign_params(password_hash=password_hash, fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"users/{name}", params=params, headers=headers
        )

        return response

    def get_user_group_request(self, group_id, fields):
        params = assign_params(fields=fields)
        headers = self._headers

        response = self._http_request(
            "get", f"usergroups/{group_id}", params=params, headers=headers
        )

        return response

    def get_user_groups_request(self, q, sort, offset, limit, fields):
        params = assign_params(
            q=q, sort=sort, offset=offset, limit=limit, fields=fields
        )
        headers = self._headers

        response = self._http_request(
            "get", "usergroups", params=params, headers=headers
        )

        return response

    def get_users_request(self, password_hash, q, sort, offset, limit, fields):
        params = assign_params(
            password_hash=password_hash,
            q=q,
            sort=sort,
            offset=offset,
            limit=limit,
            fields=fields,
        )
        headers = self._headers

        response = self._http_request("get", "users", params=params, headers=headers)

        return response

    def get_wallix_bastion_usage_statistics_request(self, from_date, to_date):
        params = assign_params(from_date=from_date, to_date=to_date)
        headers = self._headers

        response = self._http_request(
            "get", "statistics", params=params, headers=headers
        )

        return response

    def make_new_approval_request_to_access_target_request(
        self,
        approval_request_post_authorization,
        approval_request_post_begin,
        approval_request_post_comment,
        approval_request_post_duration,
        approval_request_post_target_name,
        approval_request_post_ticket,
    ):
        data = assign_params(
            authorization=approval_request_post_authorization,
            begin=approval_request_post_begin,
            comment=approval_request_post_comment,
            duration=approval_request_post_duration,
            target_name=approval_request_post_target_name,
            ticket=approval_request_post_ticket,
        )
        headers = self._headers

        response = self._http_request(
            "post", "approvals/requests", json_data=data, headers=headers
        )

        return response

    def release_passwords_for_target_request(
        self, account_name, authorization, force, comment
    ):
        params = assign_params(
            authorization=authorization, force=force, comment=comment
        )
        headers = self._headers

        response = self._http_request(
            "get",
            f"targetpasswords/checkin/{account_name}",
            params=params,
            headers=headers,
        )

        return response

    def reply_to_approval_request_request(
        self,
        approval_assignment_post_approved,
        approval_assignment_post_comment,
        approval_assignment_post_duration,
        approval_assignment_post_id,
        approval_assignment_post_timeout,
    ):
        data = assign_params(
            approved=approval_assignment_post_approved,
            comment=approval_assignment_post_comment,
            duration=approval_assignment_post_duration,
            id=approval_assignment_post_id,
            timeout=approval_assignment_post_timeout,
        )
        headers = self._headers

        response = self._http_request(
            "post", "approvals/assignments", json_data=data, headers=headers
        )

        return response

    def revoke_certificate_of_device_request(self, device_id, cert_type, address, port):
        headers = self._headers

        response = self._http_request(
            "delete",
            f"devices/{device_id}/certificates/{cert_type}/{address}/{port}",
            headers=headers,
        )

        return response

    def start_scan_job_manually_request(self, scanjob_post_scan_id):
        data = assign_params(scan_id=scanjob_post_scan_id)
        headers = self._headers

        response = self._http_request(
            "post", "scanjobs", json_data=data, headers=headers
        )

        return response


def add_account_in_global_domain_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    domain_id = str(args.get("domain_id", ""))
    domain_account_post_account_login = str(
        args.get("domain_account_post_account_login", "")
    )
    domain_account_post_account_name = str(
        args.get("domain_account_post_account_name", "")
    )
    domain_account_post_auto_change_password = argToBoolean(
        args.get("domain_account_post_auto_change_password", False)
    )
    domain_account_post_auto_change_ssh_key = argToBoolean(
        args.get("domain_account_post_auto_change_ssh_key", False)
    )
    domain_account_post_can_edit_certificate_validity = argToBoolean(
        args.get("domain_account_post_can_edit_certificate_validity", False)
    )
    domain_account_post_certificate_validity = str(
        args.get("domain_account_post_certificate_validity", "")
    )
    domain_account_post_checkout_policy = str(
        args.get("domain_account_post_checkout_policy", "")
    )
    domain_account_post_description = str(
        args.get("domain_account_post_description", "")
    )
    domain_account_post_resources = argToList(
        args.get("domain_account_post_resources", [])
    )

    response = client.add_account_in_global_domain_request(
        domain_id,
        domain_account_post_account_login,
        domain_account_post_account_name,
        domain_account_post_auto_change_password,
        domain_account_post_auto_change_ssh_key,
        domain_account_post_can_edit_certificate_validity,
        domain_account_post_certificate_validity,
        domain_account_post_checkout_policy,
        domain_account_post_description,
        domain_account_post_resources,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def add_account_to_local_domain_of_application_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    application_id = str(args.get("application_id", ""))
    domain_id = str(args.get("domain_id", ""))
    app_account_post_account_login = str(args.get("app_account_post_account_login", ""))
    app_account_post_account_name = str(args.get("app_account_post_account_name", ""))
    app_account_post_auto_change_password = argToBoolean(
        args.get("app_account_post_auto_change_password", False)
    )
    app_account_post_can_edit_certificate_validity = argToBoolean(
        args.get("app_account_post_can_edit_certificate_validity", False)
    )
    app_account_post_certificate_validity = str(
        args.get("app_account_post_certificate_validity", "")
    )
    app_account_post_checkout_policy = str(
        args.get("app_account_post_checkout_policy", "")
    )
    app_account_post_description = str(args.get("app_account_post_description", ""))

    response = client.add_account_to_local_domain_of_application_request(
        application_id,
        domain_id,
        app_account_post_account_login,
        app_account_post_account_name,
        app_account_post_auto_change_password,
        app_account_post_can_edit_certificate_validity,
        app_account_post_certificate_validity,
        app_account_post_checkout_policy,
        app_account_post_description,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def add_account_to_local_domain_on_device_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    domain_id = str(args.get("domain_id", ""))
    device_account_post_account_login = str(
        args.get("device_account_post_account_login", "")
    )
    device_account_post_account_name = str(
        args.get("device_account_post_account_name", "")
    )
    device_account_post_auto_change_password = argToBoolean(
        args.get("device_account_post_auto_change_password", False)
    )
    device_account_post_auto_change_ssh_key = argToBoolean(
        args.get("device_account_post_auto_change_ssh_key", False)
    )
    device_account_post_can_edit_certificate_validity = argToBoolean(
        args.get("device_account_post_can_edit_certificate_validity", False)
    )
    device_account_post_certificate_validity = str(
        args.get("device_account_post_certificate_validity", "")
    )
    device_account_post_checkout_policy = str(
        args.get("device_account_post_checkout_policy", "")
    )
    device_account_post_description = str(
        args.get("device_account_post_description", "")
    )
    device_account_post_services = argToList(
        args.get("device_account_post_services", [])
    )

    response = client.add_account_to_local_domain_on_device_request(
        device_id,
        domain_id,
        device_account_post_account_login,
        device_account_post_account_name,
        device_account_post_auto_change_password,
        device_account_post_auto_change_ssh_key,
        device_account_post_can_edit_certificate_validity,
        device_account_post_certificate_validity,
        device_account_post_checkout_policy,
        device_account_post_description,
        device_account_post_services,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def add_authorization_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    authorization_post_active_quorum = args.get(
        "authorization_post_active_quorum", None
    )
    authorization_post_approval_required = argToBoolean(
        args.get("authorization_post_approval_required", False)
    )
    authorization_post_approval_timeout = args.get(
        "authorization_post_approval_timeout", None
    )
    authorization_post_approvers = argToList(
        args.get("authorization_post_approvers", [])
    )
    authorization_post_authorization_name = str(
        args.get("authorization_post_authorization_name", "")
    )
    authorization_post_authorize_password_retrieval = argToBoolean(
        args.get("authorization_post_authorize_password_retrieval", False)
    )
    authorization_post_authorize_session_sharing = argToBoolean(
        args.get("authorization_post_authorize_session_sharing", False)
    )
    authorization_post_authorize_sessions = argToBoolean(
        args.get("authorization_post_authorize_sessions", False)
    )
    authorization_post_description = str(args.get("authorization_post_description", ""))
    authorization_post_has_comment = argToBoolean(
        args.get("authorization_post_has_comment", False)
    )
    authorization_post_has_ticket = argToBoolean(
        args.get("authorization_post_has_ticket", False)
    )
    authorization_post_inactive_quorum = args.get(
        "authorization_post_inactive_quorum", None
    )
    authorization_post_is_critical = argToBoolean(
        args.get("authorization_post_is_critical", False)
    )
    authorization_post_is_recorded = argToBoolean(
        args.get("authorization_post_is_recorded", False)
    )
    authorization_post_mandatory_comment = argToBoolean(
        args.get("authorization_post_mandatory_comment", False)
    )
    authorization_post_mandatory_ticket = argToBoolean(
        args.get("authorization_post_mandatory_ticket", False)
    )
    authorization_post_session_sharing_mode = str(
        args.get("authorization_post_session_sharing_mode", "")
    )
    authorization_post_single_connection = argToBoolean(
        args.get("authorization_post_single_connection", False)
    )
    authorization_post_subprotocols = argToList(
        args.get("authorization_post_subprotocols", [])
    )
    authorization_post_target_group = str(
        args.get("authorization_post_target_group", "")
    )
    authorization_post_user_group = str(args.get("authorization_post_user_group", ""))

    response = client.add_authorization_request(
        authorization_post_active_quorum,
        authorization_post_approval_required,
        authorization_post_approval_timeout,
        authorization_post_approvers,
        authorization_post_authorization_name,
        authorization_post_authorize_password_retrieval,
        authorization_post_authorize_session_sharing,
        authorization_post_authorize_sessions,
        authorization_post_description,
        authorization_post_has_comment,
        authorization_post_has_ticket,
        authorization_post_inactive_quorum,
        authorization_post_is_critical,
        authorization_post_is_recorded,
        authorization_post_mandatory_comment,
        authorization_post_mandatory_ticket,
        authorization_post_session_sharing_mode,
        authorization_post_single_connection,
        authorization_post_subprotocols,
        authorization_post_target_group,
        authorization_post_user_group,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def add_device_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    device_post_host = str(args.get("device_post_host", ""))
    device_post_alias = str(args.get("device_post_alias", ""))
    device_post_description = str(args.get("device_post_description", ""))
    device_post_device_name = str(args.get("device_post_device_name", ""))

    response = client.add_device_request(
        device_post_host,
        device_post_alias,
        device_post_description,
        device_post_device_name,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def add_notification_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    notification_post_description = str(args.get("notification_post_description", ""))
    notification_post_destination = str(args.get("notification_post_destination", ""))
    notification_post_enabled = argToBoolean(
        args.get("notification_post_enabled", False)
    )
    notification_post_events = argToList(args.get("notification_post_events", []))
    notification_post_language = str(args.get("notification_post_language", ""))
    notification_post_notification_name = str(
        args.get("notification_post_notification_name", "")
    )
    notification_post_type = str(args.get("notification_post_type", ""))

    response = client.add_notification_request(
        notification_post_description,
        notification_post_destination,
        notification_post_enabled,
        notification_post_events,
        notification_post_language,
        notification_post_notification_name,
        notification_post_type,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def add_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    password_hash = argToBoolean(args.get("password_hash", False))
    user_post_certificate_dn = str(args.get("user_post_certificate_dn", ""))
    user_post_display_name = str(args.get("user_post_display_name", ""))
    user_post_email = str(args.get("user_post_email", ""))
    user_post_expiration_date = str(args.get("user_post_expiration_date", ""))
    user_post_force_change_pwd = argToBoolean(
        args.get("user_post_force_change_pwd", False)
    )
    user_post_gpg_public_key = str(args.get("user_post_gpg_public_key", ""))
    user_post_groups = argToList(args.get("user_post_groups", []))
    user_post_ip_source = str(args.get("user_post_ip_source", ""))
    user_post_is_disabled = argToBoolean(args.get("user_post_is_disabled", False))
    user_post_last_connection = str(args.get("user_post_last_connection", ""))
    user_post_password = str(args.get("user_post_password", ""))
    user_post_preferred_language = str(args.get("user_post_preferred_language", ""))
    user_post_profile = str(args.get("user_post_profile", ""))
    user_post_ssh_public_key = str(args.get("user_post_ssh_public_key", ""))
    user_post_user_auths = argToList(args.get("user_post_user_auths", []))
    user_post_user_name = str(args.get("user_post_user_name", ""))

    response = client.add_user_request(
        password_hash,
        user_post_certificate_dn,
        user_post_display_name,
        user_post_email,
        user_post_expiration_date,
        user_post_force_change_pwd,
        user_post_gpg_public_key,
        user_post_groups,
        user_post_ip_source,
        user_post_is_disabled,
        user_post_last_connection,
        user_post_password,
        user_post_preferred_language,
        user_post_profile,
        user_post_ssh_public_key,
        user_post_user_auths,
        user_post_user_name,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def cancel_accepted_approval_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    approval_assignment_cancel_post_comment = str(
        args.get("approval_assignment_cancel_post_comment", "")
    )
    approval_assignment_cancel_post_id = str(
        args.get("approval_assignment_cancel_post_id", "")
    )

    response = client.cancel_accepted_approval_request(
        approval_assignment_cancel_post_comment, approval_assignment_cancel_post_id
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def cancel_approval_request_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    approval_request_cancel_post_id = str(
        args.get("approval_request_cancel_post_id", "")
    )

    response = client.cancel_approval_request_request(approval_request_cancel_post_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def cancel_scan_job_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    scanjob_id = str(args.get("scanjob_id", ""))

    response = client.cancel_scan_job_request(scanjob_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def check_if_approval_is_required_for_target_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    target_name = str(args.get("target_name", ""))
    authorization = str(args.get("authorization", ""))
    begin = str(args.get("begin", ""))

    response = client.check_if_approval_is_required_for_target_request(
        target_name, authorization, begin
    )
    command_results = CommandResults(
        outputs_prefix="WAB.approval_request_target_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def create_session_request_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    session_request_post_mode = str(args.get("session_request_post_mode", ""))
    session_request_post_session_id = str(
        args.get("session_request_post_session_id", "")
    )

    response = client.create_session_request_request(
        session_request_post_mode, session_request_post_session_id
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def delete_account_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    account_id = str(args.get("account_id", ""))

    response = client.delete_account_request(account_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def delete_account_from_global_domain_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    domain_id = str(args.get("domain_id", ""))
    account_id = str(args.get("account_id", ""))

    response = client.delete_account_from_global_domain_request(domain_id, account_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def delete_account_from_local_domain_of_application_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    application_id = str(args.get("application_id", ""))
    domain_id = str(args.get("domain_id", ""))
    account_id = str(args.get("account_id", ""))

    response = client.delete_account_from_local_domain_of_application_request(
        application_id, domain_id, account_id
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def delete_account_from_local_domain_of_device_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    domain_id = str(args.get("domain_id", ""))
    account_id = str(args.get("account_id", ""))

    response = client.delete_account_from_local_domain_of_device_request(
        device_id, domain_id, account_id
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def delete_application_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    application_id = str(args.get("application_id", ""))

    response = client.delete_application_request(application_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def delete_authorization_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    authorization_id = str(args.get("authorization_id", ""))

    response = client.delete_authorization_request(authorization_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def delete_device_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    device_id = str(args.get("device_id", ""))

    response = client.delete_device_request(device_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def delete_notification_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    notification_id = str(args.get("notification_id", ""))

    response = client.delete_notification_request(notification_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def delete_pending_or_live_session_request_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    request_id = str(args.get("request_id", ""))

    response = client.delete_pending_or_live_session_request_request(request_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def delete_resource_from_global_domain_account_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    domain_id = str(args.get("domain_id", ""))
    account_id = str(args.get("account_id", ""))
    resource_name = str(args.get("resource_name", ""))

    response = client.delete_resource_from_global_domain_account_request(
        domain_id, account_id, resource_name
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def delete_service_from_device_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    service_id = str(args.get("service_id", ""))

    response = client.delete_service_from_device_request(device_id, service_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def edit_account_in_global_domain_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    domain_id = str(args.get("domain_id", ""))
    account_id = str(args.get("account_id", ""))
    force = argToBoolean(args.get("force", False))
    domain_account_put_account_login = str(
        args.get("domain_account_put_account_login", "")
    )
    domain_account_put_account_name = str(
        args.get("domain_account_put_account_name", "")
    )
    domain_account_put_auto_change_password = argToBoolean(
        args.get("domain_account_put_auto_change_password", False)
    )
    domain_account_put_auto_change_ssh_key = argToBoolean(
        args.get("domain_account_put_auto_change_ssh_key", False)
    )
    domain_account_put_can_edit_certificate_validity = argToBoolean(
        args.get("domain_account_put_can_edit_certificate_validity", False)
    )
    domain_account_put_certificate_validity = str(
        args.get("domain_account_put_certificate_validity", "")
    )
    domain_account_put_checkout_policy = str(
        args.get("domain_account_put_checkout_policy", "")
    )
    domain_account_put_description = str(args.get("domain_account_put_description", ""))
    domain_account_put_onboard_status = str(
        args.get("domain_account_put_onboard_status", "")
    )
    domain_account_put_resources = argToList(
        args.get("domain_account_put_resources", [])
    )

    response = client.edit_account_in_global_domain_request(
        domain_id,
        account_id,
        force,
        domain_account_put_account_login,
        domain_account_put_account_name,
        domain_account_put_auto_change_password,
        domain_account_put_auto_change_ssh_key,
        domain_account_put_can_edit_certificate_validity,
        domain_account_put_certificate_validity,
        domain_account_put_checkout_policy,
        domain_account_put_description,
        domain_account_put_onboard_status,
        domain_account_put_resources,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def edit_account_on_local_domain_of_application_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    application_id = str(args.get("application_id", ""))
    domain_id = str(args.get("domain_id", ""))
    account_id = str(args.get("account_id", ""))
    force = argToBoolean(args.get("force", False))
    app_account_put_account_login = str(args.get("app_account_put_account_login", ""))
    app_account_put_account_name = str(args.get("app_account_put_account_name", ""))
    app_account_put_auto_change_password = argToBoolean(
        args.get("app_account_put_auto_change_password", False)
    )
    app_account_put_can_edit_certificate_validity = argToBoolean(
        args.get("app_account_put_can_edit_certificate_validity", False)
    )
    app_account_put_certificate_validity = str(
        args.get("app_account_put_certificate_validity", "")
    )
    app_account_put_checkout_policy = str(
        args.get("app_account_put_checkout_policy", "")
    )
    app_account_put_description = str(args.get("app_account_put_description", ""))
    app_account_put_onboard_status = str(args.get("app_account_put_onboard_status", ""))

    response = client.edit_account_on_local_domain_of_application_request(
        application_id,
        domain_id,
        account_id,
        force,
        app_account_put_account_login,
        app_account_put_account_name,
        app_account_put_auto_change_password,
        app_account_put_can_edit_certificate_validity,
        app_account_put_certificate_validity,
        app_account_put_checkout_policy,
        app_account_put_description,
        app_account_put_onboard_status,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def edit_account_on_local_domain_of_device_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    domain_id = str(args.get("domain_id", ""))
    account_id = str(args.get("account_id", ""))
    force = argToBoolean(args.get("force", False))
    device_account_put_account_login = str(
        args.get("device_account_put_account_login", "")
    )
    device_account_put_account_name = str(
        args.get("device_account_put_account_name", "")
    )
    device_account_put_auto_change_password = argToBoolean(
        args.get("device_account_put_auto_change_password", False)
    )
    device_account_put_auto_change_ssh_key = argToBoolean(
        args.get("device_account_put_auto_change_ssh_key", False)
    )
    device_account_put_can_edit_certificate_validity = argToBoolean(
        args.get("device_account_put_can_edit_certificate_validity", False)
    )
    device_account_put_certificate_validity = str(
        args.get("device_account_put_certificate_validity", "")
    )
    device_account_put_checkout_policy = str(
        args.get("device_account_put_checkout_policy", "")
    )
    device_account_put_description = str(args.get("device_account_put_description", ""))
    device_account_put_onboard_status = str(
        args.get("device_account_put_onboard_status", "")
    )
    device_account_put_services = argToList(args.get("device_account_put_services", []))

    response = client.edit_account_on_local_domain_of_device_request(
        device_id,
        domain_id,
        account_id,
        force,
        device_account_put_account_login,
        device_account_put_account_name,
        device_account_put_auto_change_password,
        device_account_put_auto_change_ssh_key,
        device_account_put_can_edit_certificate_validity,
        device_account_put_certificate_validity,
        device_account_put_checkout_policy,
        device_account_put_description,
        device_account_put_onboard_status,
        device_account_put_services,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def edit_application_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    application_id = str(args.get("application_id", ""))
    force = argToBoolean(args.get("force", False))
    application_put__meters = str(args.get("application_put__meters", ""))
    application_put_application_name = str(
        args.get("application_put_application_name", "")
    )
    application_put_connection_policy = str(
        args.get("application_put_connection_policy", "")
    )
    application_put_description = str(args.get("application_put_description", ""))

    response = client.edit_application_request(
        application_id,
        force,
        application_put__meters,
        application_put_application_name,
        application_put_connection_policy,
        application_put_description,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def edit_authorization_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    authorization_id = str(args.get("authorization_id", ""))
    force = argToBoolean(args.get("force", False))
    authorization_put_active_quorum = args.get("authorization_put_active_quorum", None)
    authorization_put_approval_required = argToBoolean(
        args.get("authorization_put_approval_required", False)
    )
    authorization_put_approval_timeout = args.get(
        "authorization_put_approval_timeout", None
    )
    authorization_put_approvers = argToList(args.get("authorization_put_approvers", []))
    authorization_put_authorization_name = str(
        args.get("authorization_put_authorization_name", "")
    )
    authorization_put_authorize_password_retrieval = argToBoolean(
        args.get("authorization_put_authorize_password_retrieval", False)
    )
    authorization_put_authorize_session_sharing = argToBoolean(
        args.get("authorization_put_authorize_session_sharing", False)
    )
    authorization_put_authorize_sessions = argToBoolean(
        args.get("authorization_put_authorize_sessions", False)
    )
    authorization_put_description = str(args.get("authorization_put_description", ""))
    authorization_put_has_comment = argToBoolean(
        args.get("authorization_put_has_comment", False)
    )
    authorization_put_has_ticket = argToBoolean(
        args.get("authorization_put_has_ticket", False)
    )
    authorization_put_inactive_quorum = args.get(
        "authorization_put_inactive_quorum", None
    )
    authorization_put_is_critical = argToBoolean(
        args.get("authorization_put_is_critical", False)
    )
    authorization_put_is_recorded = argToBoolean(
        args.get("authorization_put_is_recorded", False)
    )
    authorization_put_mandatory_comment = argToBoolean(
        args.get("authorization_put_mandatory_comment", False)
    )
    authorization_put_mandatory_ticket = argToBoolean(
        args.get("authorization_put_mandatory_ticket", False)
    )
    authorization_put_session_sharing_mode = str(
        args.get("authorization_put_session_sharing_mode", "")
    )
    authorization_put_single_connection = argToBoolean(
        args.get("authorization_put_single_connection", False)
    )
    authorization_put_subprotocols = argToList(
        args.get("authorization_put_subprotocols", [])
    )

    response = client.edit_authorization_request(
        authorization_id,
        force,
        authorization_put_active_quorum,
        authorization_put_approval_required,
        authorization_put_approval_timeout,
        authorization_put_approvers,
        authorization_put_authorization_name,
        authorization_put_authorize_password_retrieval,
        authorization_put_authorize_session_sharing,
        authorization_put_authorize_sessions,
        authorization_put_description,
        authorization_put_has_comment,
        authorization_put_has_ticket,
        authorization_put_inactive_quorum,
        authorization_put_is_critical,
        authorization_put_is_recorded,
        authorization_put_mandatory_comment,
        authorization_put_mandatory_ticket,
        authorization_put_session_sharing_mode,
        authorization_put_single_connection,
        authorization_put_subprotocols,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def edit_device_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    force = argToBoolean(args.get("force", False))
    device_put_host = str(args.get("device_put_host", ""))
    device_put_alias = str(args.get("device_put_alias", ""))
    device_put_description = str(args.get("device_put_description", ""))
    device_put_device_name = str(args.get("device_put_device_name", ""))
    device_put_onboard_status = str(args.get("device_put_onboard_status", ""))

    response = client.edit_device_request(
        device_id,
        force,
        device_put_host,
        device_put_alias,
        device_put_description,
        device_put_device_name,
        device_put_onboard_status,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def edit_notification_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    notification_id = str(args.get("notification_id", ""))
    force = argToBoolean(args.get("force", False))
    notification_put_description = str(args.get("notification_put_description", ""))
    notification_put_destination = str(args.get("notification_put_destination", ""))
    notification_put_enabled = argToBoolean(args.get("notification_put_enabled", False))
    notification_put_events = argToList(args.get("notification_put_events", []))
    notification_put_language = str(args.get("notification_put_language", ""))
    notification_put_notification_name = str(
        args.get("notification_put_notification_name", "")
    )
    notification_put_type = str(args.get("notification_put_type", ""))

    response = client.edit_notification_request(
        notification_id,
        force,
        notification_put_description,
        notification_put_destination,
        notification_put_enabled,
        notification_put_events,
        notification_put_language,
        notification_put_notification_name,
        notification_put_type,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def edit_service_of_device_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    service_id = str(args.get("service_id", ""))
    force = argToBoolean(args.get("force", False))
    service_put_connection_policy = str(args.get("service_put_connection_policy", ""))
    service_put_global_domains = argToList(args.get("service_put_global_domains", []))
    service_put_port = args.get("service_put_port", None)

    response = client.edit_service_of_device_request(
        device_id,
        service_id,
        force,
        service_put_connection_policy,
        service_put_global_domains,
        service_put_port,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def edit_session_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    session_id = str(args.get("session_id", ""))
    action = str(args.get("action", ""))
    session_put_edit_description = str(args.get("session_put_edit_description", ""))

    response = client.edit_session_request(
        session_id, action, session_put_edit_description
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def extend_duration_time_to_get_passwords_for_target_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    account_name = str(args.get("account_name", ""))
    authorization = str(args.get("authorization", ""))

    response = client.extend_duration_time_to_get_passwords_for_target_request(
        account_name, authorization
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def generate_trace_for_session_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    session_trace_post_date = str(args.get("session_trace_post_date", ""))
    session_trace_post_duration = args.get("session_trace_post_duration", None)
    session_trace_post_session_id = str(args.get("session_trace_post_session_id", ""))

    response = client.generate_trace_for_session_request(
        session_trace_post_date,
        session_trace_post_duration,
        session_trace_post_session_id,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_account_of_global_domain_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    domain_id = str(args.get("domain_id", ""))
    account_id = str(args.get("account_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_account_of_global_domain_request(
        domain_id, account_id, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.domain_account_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_account_reference_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    account_id = str(args.get("account_id", ""))
    reference_id = str(args.get("reference_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_account_reference_request(account_id, reference_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.account_reference_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_account_references_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    account_id = str(args.get("account_id", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_account_references_request(
        account_id, q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.account_reference_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_accounts_of_global_domain_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    domain_id = str(args.get("domain_id", ""))
    q = str(args.get("q", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_accounts_of_global_domain_request(
        domain_id, q, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.domain_account_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_all_accounts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    account_type = str(args.get("account_type", ""))
    application = str(args.get("application", ""))
    device = str(args.get("device", ""))
    passwords = argToBoolean(args.get("passwords", False))
    key_format = str(args.get("key_format", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_all_accounts_request(
        account_type,
        application,
        device,
        passwords,
        key_format,
        q,
        sort,
        offset,
        limit,
        fields,
    )
    command_results = CommandResults(
        outputs_prefix="WAB.account_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_all_accounts_on_device_local_domain_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    domain_id = str(args.get("domain_id", ""))
    key_format = str(args.get("key_format", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_all_accounts_on_device_local_domain_request(
        device_id, domain_id, key_format, q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.device_account_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_application_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    application_id = str(args.get("application_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_application_request(application_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.application_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_application_account_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    application_id = str(args.get("application_id", ""))
    domain_id = str(args.get("domain_id", ""))
    account_id = str(args.get("account_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_application_account_request(
        application_id, domain_id, account_id, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.app_account_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_application_accounts_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    application_id = str(args.get("application_id", ""))
    domain_id = str(args.get("domain_id", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_application_accounts_request(
        application_id, domain_id, q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.app_account_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_applications_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_applications_request(q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.application_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_approval_request_pending_for_user_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    user = str(args.get("user", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))
    approval_id = str(args.get("approval_id", ""))

    response = client.get_approval_request_pending_for_user_request(
        user, q, sort, offset, limit, fields, approval_id
    )
    command_results = CommandResults(
        outputs_prefix="WAB.approval_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_approvals_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    approval_id = str(args.get("approval_id", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_approvals_request(approval_id, q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.approval_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_approvals_for_all_approvers_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_approvals_for_all_approvers_request(
        q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.approval_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_approvals_for_approver_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    user_name = str(args.get("user_name", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_approvals_for_approver_request(
        user_name, q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.approval_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_auth_domain_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    domain_id = str(args.get("domain_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_auth_domain_request(domain_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.auth_domain_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_auth_domains_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_auth_domains_request(q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.auth_domain_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_authentication_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    auth_id = str(args.get("auth_id", ""))
    from_date = str(args.get("from_date", ""))
    to_date = str(args.get("to_date", ""))
    date_field = str(args.get("date_field", ""))
    fields = str(args.get("fields", ""))

    response = client.get_authentication_request(
        auth_id, from_date, to_date, date_field, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.authentication_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_authentications_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    from_date = str(args.get("from_date", ""))
    to_date = str(args.get("to_date", ""))
    date_field = str(args.get("date_field", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_authentications_request(
        from_date, to_date, date_field, q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.authentication_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_authorization_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    authorization_id = str(args.get("authorization_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_authorization_request(authorization_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.authorization_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_authorizations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_authorizations_request(q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.authorization_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_certificate_on_device_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    cert_type = str(args.get("cert_type", ""))
    address = str(args.get("address", ""))
    port = args.get("port", None)
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_certificate_on_device_request(
        device_id, cert_type, address, port, q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.device_certificates_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_certificates_on_device_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_certificates_on_device_request(
        device_id, q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.device_certificates_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_checkout_policies_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_checkout_policies_request(q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.checkoutpolicy_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_checkout_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    checkout_policy_id = str(args.get("checkout_policy_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_checkout_policy_request(checkout_policy_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.checkoutpolicy_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_device_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_device_request(device_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.device_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_devices_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_devices_request(q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.device_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_global_domain_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    domain_id = str(args.get("domain_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_global_domain_request(domain_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.domain_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_global_domains_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_global_domains_request(q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.domain_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_information_about_wallix_bastion_license_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    response = client.get_information_about_wallix_bastion_license_request()
    command_results = CommandResults(
        outputs_prefix="WAB.licenseinfo_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_latest_snapshot_of_running_session_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    session_id = str(args.get("session_id", ""))

    response = client.get_latest_snapshot_of_running_session_request(session_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_ldap_user_of_domain_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    domain = str(args.get("domain", ""))
    user_name = str(args.get("user_name", ""))
    last_connection = argToBoolean(args.get("last_connection", False))
    fields = str(args.get("fields", ""))

    response = client.get_ldap_user_of_domain_request(
        domain, user_name, last_connection, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.ldapuser_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_ldap_users_of_domain_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    domain = str(args.get("domain", ""))
    last_connection = argToBoolean(args.get("last_connection", False))
    q = str(args.get("q", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_ldap_users_of_domain_request(
        domain, last_connection, q, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.ldapuser_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_metadata_of_one_or_multiple_sessions_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    session_ids = str(args.get("session_ids", ""))
    download = argToBoolean(args.get("download", False))

    response = client.get_metadata_of_one_or_multiple_sessions_request(
        session_ids, download
    )
    command_results = CommandResults(
        outputs_prefix="WAB.session_metadata_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_notification_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    notification_id = str(args.get("notification_id", ""))

    response = client.get_notification_request(notification_id)
    command_results = CommandResults(
        outputs_prefix="WAB.notification_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_notifications_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)

    response = client.get_notifications_request(q, sort, offset, limit)
    command_results = CommandResults(
        outputs_prefix="WAB.notification_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_object_to_onboard_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    object_type = str(args.get("object_type", ""))
    object_status = str(args.get("object_status", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_object_to_onboard_request(
        object_type, object_status, q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.onboarding_objects_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_one_account_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    account_id = str(args.get("account_id", ""))
    account_type = str(args.get("account_type", ""))
    application = str(args.get("application", ""))
    device = str(args.get("device", ""))
    passwords = argToBoolean(args.get("passwords", False))
    key_format = str(args.get("key_format", ""))
    fields = str(args.get("fields", ""))

    response = client.get_one_account_request(
        account_id, account_type, application, device, passwords, key_format, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.account_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_one_account_on_device_local_domain_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    domain_id = str(args.get("domain_id", ""))
    account_id = str(args.get("account_id", ""))
    key_format = str(args.get("key_format", ""))
    fields = str(args.get("fields", ""))

    response = client.get_one_account_on_device_local_domain_request(
        device_id, domain_id, account_id, key_format, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.device_account_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_profile_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    profile_id = str(args.get("profile_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_profile_request(profile_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.profile_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_profiles_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_profiles_request(q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.profile_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_scan_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    scan_id = str(args.get("scan_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_scan_request(scan_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.scan_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_scanjob_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    scanjob_id = str(args.get("scanjob_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_scanjob_request(scanjob_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.scanjob_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_scanjobs_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_scanjobs_request(q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.scanjob_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_scans_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_scans_request(q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.scan_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_service_of_device_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    service_id = str(args.get("service_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_service_of_device_request(device_id, service_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.service_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_services_of_device_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_services_of_device_request(
        device_id, q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.service_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_session_sharing_requests_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    request_id = str(args.get("request_id", ""))
    session_id = str(args.get("session_id", ""))

    response = client.get_session_sharing_requests_request(request_id, session_id)
    command_results = CommandResults(
        outputs_prefix="WAB.session_request_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_sessionrights_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_sessionrights_request(q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.sessionrights_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_sessionrights_user_name_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    user_name = str(args.get("user_name", ""))
    fields = str(args.get("fields", ""))

    response = client.get_sessionrights_user_name_request(user_name, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.sessionrights_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_sessions_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    session_id = str(args.get("session_id", ""))
    otp = str(args.get("otp", ""))
    status = str(args.get("status", ""))
    from_date = str(args.get("from_date", ""))
    to_date = str(args.get("to_date", ""))
    date_field = str(args.get("date_field", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_sessions_request(
        session_id,
        otp,
        status,
        from_date,
        to_date,
        date_field,
        q,
        sort,
        offset,
        limit,
        fields,
    )
    command_results = CommandResults(
        outputs_prefix="WAB.session_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_status_of_trace_generation_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    session_id = str(args.get("session_id", ""))
    date = str(args.get("date", ""))
    duration = args.get("duration", None)
    download = argToBoolean(args.get("download", False))

    response = client.get_status_of_trace_generation_request(
        session_id, date, duration, download
    )
    command_results = CommandResults(
        outputs_prefix="WAB.session_trace_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_target_by_type_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    target_type = str(args.get("target_type", ""))
    group = str(args.get("group", ""))
    group_id = str(args.get("group_id", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_target_by_type_request(
        target_type, group, group_id, q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.getTargetByType",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_target_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    group_id = str(args.get("group_id", ""))
    device = str(args.get("device", ""))
    application = str(args.get("application", ""))
    domain = str(args.get("domain", ""))
    fields = str(args.get("fields", ""))

    response = client.get_target_group_request(
        group_id, device, application, domain, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.targetgroups_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_target_groups_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    device = str(args.get("device", ""))
    application = str(args.get("application", ""))
    domain = str(args.get("domain", ""))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_target_groups_request(
        device, application, domain, q, sort, offset, limit, fields
    )
    command_results = CommandResults(
        outputs_prefix="WAB.targetgroups_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = str(args.get("name", ""))
    password_hash = argToBoolean(args.get("password_hash", False))
    fields = str(args.get("fields", ""))

    response = client.get_user_request(name, password_hash, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.user_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_user_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    group_id = str(args.get("group_id", ""))
    fields = str(args.get("fields", ""))

    response = client.get_user_group_request(group_id, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.usergroups_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_user_groups_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_user_groups_request(q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.usergroups_get",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_users_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    password_hash = argToBoolean(args.get("password_hash", False))
    q = str(args.get("q", ""))
    sort = str(args.get("sort", ""))
    offset = args.get("offset", None)
    limit = args.get("limit", None)
    fields = str(args.get("fields", ""))

    response = client.get_users_request(password_hash, q, sort, offset, limit, fields)
    command_results = CommandResults(
        outputs_prefix="WAB.user_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_wallix_bastion_usage_statistics_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    from_date = str(args.get("from_date", ""))
    to_date = str(args.get("to_date", ""))

    response = client.get_wallix_bastion_usage_statistics_request(from_date, to_date)
    command_results = CommandResults(
        outputs_prefix="WAB.statistics_get",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def make_new_approval_request_to_access_target_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    approval_request_post_authorization = str(
        args.get("approval_request_post_authorization", "")
    )
    approval_request_post_begin = str(args.get("approval_request_post_begin", ""))
    approval_request_post_comment = str(args.get("approval_request_post_comment", ""))
    approval_request_post_duration = args.get("approval_request_post_duration", None)
    approval_request_post_target_name = str(
        args.get("approval_request_post_target_name", "")
    )
    approval_request_post_ticket = str(args.get("approval_request_post_ticket", ""))

    response = client.make_new_approval_request_to_access_target_request(
        approval_request_post_authorization,
        approval_request_post_begin,
        approval_request_post_comment,
        approval_request_post_duration,
        approval_request_post_target_name,
        approval_request_post_ticket,
    )
    command_results = CommandResults(
        outputs_prefix="WAB.approval_request_post_response_ok",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def release_passwords_for_target_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    account_name = str(args.get("account_name", ""))
    authorization = str(args.get("authorization", ""))
    force = argToBoolean(args.get("force", False))
    comment = str(args.get("comment", ""))

    response = client.release_passwords_for_target_request(
        account_name, authorization, force, comment
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def reply_to_approval_request_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    approval_assignment_post_approved = argToBoolean(
        args.get("approval_assignment_post_approved", False)
    )
    approval_assignment_post_comment = str(
        args.get("approval_assignment_post_comment", "")
    )
    approval_assignment_post_duration = args.get(
        "approval_assignment_post_duration", None
    )
    approval_assignment_post_id = str(args.get("approval_assignment_post_id", ""))
    approval_assignment_post_timeout = args.get(
        "approval_assignment_post_timeout", None
    )

    response = client.reply_to_approval_request_request(
        approval_assignment_post_approved,
        approval_assignment_post_comment,
        approval_assignment_post_duration,
        approval_assignment_post_id,
        approval_assignment_post_timeout,
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def revoke_certificate_of_device_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    device_id = str(args.get("device_id", ""))
    cert_type = str(args.get("cert_type", ""))
    address = str(args.get("address", ""))
    port = args.get("port", None)

    response = client.revoke_certificate_of_device_request(
        device_id, cert_type, address, port
    )
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def start_scan_job_manually_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    scanjob_post_scan_id = str(args.get("scanjob_post_scan_id", ""))

    response = client.start_scan_job_manually_request(scanjob_post_scan_id)
    command_results = CommandResults(
        outputs_prefix="WAB",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


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
    if token and last_request_at:
        if time_now - last_request_at < 100:
            return token
    return None


def update_session_token(token: str | None):
    if token is None:
        set_integration_context({})

    time_now = int(time.time())

    integration_context = {
        "session_token": token,
        "last_request_at": time_now,
    }
    set_integration_context(integration_context)


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get("url")
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    base_path = "/api"

    apiv: str = params.get("api_version", "")

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        requests.packages.urllib3.disable_warnings()  # type: ignore

        if apiv:
            apiv = validate_api_version(apiv)
            base_path += "/v" + apiv

        client: Client = Client(
            params["auth_key"],
            params["auth_user"],
            urljoin(url, base_path),
            verify_certificate,
            proxy,
        )

        commands = {
            "wab-add-account-in-global-domain": add_account_in_global_domain_command,
            "wab-add-account-to-local-domain-of-application": add_account_to_local_domain_of_application_command,
            "wab-add-account-to-local-domain-on-device": add_account_to_local_domain_on_device_command,
            "wab-add-authorization": add_authorization_command,
            "wab-add-device": add_device_command,
            "wab-add-notification": add_notification_command,
            "wab-add-user": add_user_command,
            "wab-cancel-accepted-approval": cancel_accepted_approval_command,
            "wab-cancel-approval-request": cancel_approval_request_command,
            "wab-cancel-scan-job": cancel_scan_job_command,
            "wab-check-if-approval-is-required-for-target": check_if_approval_is_required_for_target_command,
            "wab-create-session-request": create_session_request_command,
            "wab-delete-account": delete_account_command,
            "wab-delete-account-from-global-domain": delete_account_from_global_domain_command,
            "wab-delete-account-from-local-domain-of-application": delete_account_from_local_domain_of_application_command,
            "wab-delete-account-from-local-domain-of-device": delete_account_from_local_domain_of_device_command,
            "wab-delete-application": delete_application_command,
            "wab-delete-authorization": delete_authorization_command,
            "wab-delete-device": delete_device_command,
            "wab-delete-notification": delete_notification_command,
            "wab-delete-pending-or-live-session-request": delete_pending_or_live_session_request_command,
            "wab-delete-resource-from-global-domain-account": delete_resource_from_global_domain_account_command,
            "wab-delete-service-from-device": delete_service_from_device_command,
            "wab-edit-account-in-global-domain": edit_account_in_global_domain_command,
            "wab-edit-account-on-local-domain-of-application": edit_account_on_local_domain_of_application_command,
            "wab-edit-account-on-local-domain-of-device": edit_account_on_local_domain_of_device_command,
            "wab-edit-application": edit_application_command,
            "wab-edit-authorization": edit_authorization_command,
            "wab-edit-device": edit_device_command,
            "wab-edit-notification": edit_notification_command,
            "wab-edit-service-of-device": edit_service_of_device_command,
            "wab-edit-session": edit_session_command,
            "wab-extend-duration-time-to-get-passwords-for-target": extend_duration_time_to_get_passwords_for_target_command,
            "wab-generate-trace-for-session": generate_trace_for_session_command,
            "wab-get-account-of-global-domain": get_account_of_global_domain_command,
            "wab-get-account-reference": get_account_reference_command,
            "wab-get-account-references": get_account_references_command,
            "wab-get-accounts-of-global-domain": get_accounts_of_global_domain_command,
            "wab-get-all-accounts": get_all_accounts_command,
            "wab-get-all-accounts-on-device-local-domain": get_all_accounts_on_device_local_domain_command,
            "wab-get-application": get_application_command,
            "wab-get-application-account": get_application_account_command,
            "wab-get-application-accounts": get_application_accounts_command,
            "wab-get-applications": get_applications_command,
            "wab-get-approval-request-pending-for-user": get_approval_request_pending_for_user_command,
            "wab-get-approvals": get_approvals_command,
            "wab-get-approvals-for-all-approvers": get_approvals_for_all_approvers_command,
            "wab-get-approvals-for-approver": get_approvals_for_approver_command,
            "wab-get-auth-domain": get_auth_domain_command,
            "wab-get-auth-domains": get_auth_domains_command,
            "wab-get-authentication": get_authentication_command,
            "wab-get-authentications": get_authentications_command,
            "wab-get-authorization": get_authorization_command,
            "wab-get-authorizations": get_authorizations_command,
            "wab-get-certificate-on-device": get_certificate_on_device_command,
            "wab-get-certificates-on-device": get_certificates_on_device_command,
            "wab-get-checkout-policies": get_checkout_policies_command,
            "wab-get-checkout-policy": get_checkout_policy_command,
            "wab-get-device": get_device_command,
            "wab-get-devices": get_devices_command,
            "wab-get-global-domain": get_global_domain_command,
            "wab-get-global-domains": get_global_domains_command,
            "wab-get-information-about-wallix-bastion-license": get_information_about_wallix_bastion_license_command,
            "wab-get-latest-snapshot-of-running-session": get_latest_snapshot_of_running_session_command,
            "wab-get-ldap-user-of-domain": get_ldap_user_of_domain_command,
            "wab-get-ldap-users-of-domain": get_ldap_users_of_domain_command,
            "wab-get-metadata-of-one-or-multiple-sessions": get_metadata_of_one_or_multiple_sessions_command,
            "wab-get-notification": get_notification_command,
            "wab-get-notifications": get_notifications_command,
            "wab-get-object-to-onboard": get_object_to_onboard_command,
            "wab-get-one-account": get_one_account_command,
            "wab-get-one-account-on-device-local-domain": get_one_account_on_device_local_domain_command,
            "wab-get-profile": get_profile_command,
            "wab-get-profiles": get_profiles_command,
            "wab-get-scan": get_scan_command,
            "wab-get-scanjob": get_scanjob_command,
            "wab-get-scanjobs": get_scanjobs_command,
            "wab-get-scans": get_scans_command,
            "wab-get-service-of-device": get_service_of_device_command,
            "wab-get-services-of-device": get_services_of_device_command,
            "wab-get-session-sharing-requests": get_session_sharing_requests_command,
            "wab-get-sessionrights": get_sessionrights_command,
            "wab-get-sessionrights-user-name": get_sessionrights_user_name_command,
            "wab-get-sessions": get_sessions_command,
            "wab-get-status-of-trace-generation": get_status_of_trace_generation_command,
            "wab-get-target-by-type": get_target_by_type_command,
            "wab-get-target-group": get_target_group_command,
            "wab-get-target-groups": get_target_groups_command,
            "wab-get-user": get_user_command,
            "wab-get-user-group": get_user_group_command,
            "wab-get-user-groups": get_user_groups_command,
            "wab-get-users": get_users_command,
            "wab-get-wallix-bastion-usage-statistics": get_wallix_bastion_usage_statistics_command,
            "wab-make-new-approval-request-to-access-target": make_new_approval_request_to_access_target_command,
            "wab-release-passwords-for-target": release_passwords_for_target_command,
            "wab-reply-to-approval-request": reply_to_approval_request_command,
            "wab-revoke-certificate-of-device": revoke_certificate_of_device_command,
            "wab-start-scan-job-manually": start_scan_job_manually_command,
        }

        if command == "test-module":
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()

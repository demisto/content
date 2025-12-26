import time

import jwt
import urllib3
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
UPDATE_REQ_RESPONSE = {"result": "updated successfully!"}


def get_jwt_token(app_user_id: str, app_user_secret: str, current_time=None, expire_time_sec: int = 60):
    if current_time is None:
        current_time = int(time.time())
    payload = {
        "iss": app_user_id,
        "iat": current_time,
        "exp": current_time + expire_time_sec,
    }
    token = jwt.encode(payload, app_user_secret, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


class Client(BaseClient):
    def __init__(self, app_user_id, app_user_secret, operational_user_id, operational_user_secret, external_api_key,
                 *args, **kwargs):
        self.app_user_id = app_user_id
        self.app_user_secret = app_user_secret
        self.operational_user_id = operational_user_id
        self.operational_user_secret = operational_user_secret
        self.external_api_key = external_api_key
        super().__init__(*args, **kwargs)

    def build_headers(self):
        headers = {
            "Authorization": f"Bearer {get_jwt_token(self.app_user_id, self.app_user_secret)}"
        }
        if self.external_api_key:
            headers["X-Console-API-Key"] = self.external_api_key
        return headers

    def build_operational_headers(self):
        """Build headers using operational API key for getUPN endpoint"""
        if self.operational_user_id and self.operational_user_secret:
            headers = {
                "Authorization": f"Bearer {get_jwt_token(self.operational_user_id, self.operational_user_secret)}"
            }
        else:
            # Fall back to main credentials if operational key not provided
            headers = {
                "Authorization": f"Bearer {get_jwt_token(self.app_user_id, self.app_user_secret)}"
            }
        if self.external_api_key:
            headers["X-Console-API-Key"] = self.external_api_key
        return headers

    def get_status_http_request(self):
        """
        initiates an http request to get the service status
        """
        response = self._http_request(
            method="GET",
            url_suffix="getBootStatus",
            headers=self.build_headers(),
        )
        return response

    def get_upn_by_email_or_sam_account_http_request(self, domain=None, email=None, sam_account=None):
        """
        initiates an http request to get the upn by email or sam account
        """
        params = {"domain": domain}
        if email:
            params["email"] = email
        else:
            params["sam_account"] = sam_account

        response = self._http_request(
            method="GET",
            url_suffix="getUPN",
            params=params,
            headers=self.build_operational_headers(),
        )
        return response["user_principal_name"]

    def get_user_entity_risk_http_request(self, upn):
        """
        initiates an http request to get the user entity's risk from Silverfort DB
        """
        response = self._http_request(
            method="GET",
            url_suffix="getEntityRisk",
            params={"user_principal_name": upn},
            headers=self.build_headers(),
        )
        return response

    def get_resource_entity_risk_http_request(self, resource_name, domain_name):
        """
        initiates an http request to get the resource entity's risk from Silverfort DB
        """
        response = self._http_request(
            method="GET",
            url_suffix="getEntityRisk",
            params={"resource_name": resource_name, "domain_name": domain_name},
            headers=self.build_headers(),
        )
        return response

    def update_user_entity_risk_http_request(self, upn, risks):
        """
        initiates an http request to update the user entity's risk in Silverfort DB
        """
        response = self._http_request(
            method="POST",
            url_suffix="updateEntityRisk",
            headers=self.build_headers(),
            json_data={"user_principal_name": upn, "risks": risks},
        )
        return response

    def update_resource_entity_risk_http_request(self, resource_name, domain_name, risks):
        """
        initiates an http request to update resource entity's risk in Silverfort DB
        """
        response = self._http_request(
            method="POST",
            url_suffix="updateEntityRisk",
            json_data={"resource_name": resource_name, "domain_name": domain_name, "risks": risks},
            headers=self.build_headers(),
        )
        return response


def create_risk_json(args):
    try:
        valid_for = args.get("valid_for")
        valid_for = int(valid_for)
    except Exception:
        raise Exception("valid_for must be a positive number greater than 1")
    risk_name = args.get("risk_name")
    severity = args.get("severity")
    description = args.get("description")
    return {risk_name: {"severity": severity, "valid_for": valid_for, "description": description}}


def get_upn(client, args):
    email = args.get("email")
    sam_account = args.get("sam_account")
    domain = args.get("domain")
    return client.get_upn_by_email_or_sam_account_http_request(domain, email, sam_account)


def test_module(client):
    """
    Use getEntityRisk to validate credentials.
    Return 'ok' on 200, 400 or 404 (endpoint reached + auth ok).
    Fail on 401/403 and any unexpected error.
    """
    test_upn = "sfuser"  # any UPN is fine; 400/404 is acceptable for a creds-only test
    try:
        client._http_request(
            method="GET",
            url_suffix="getEntityRisk",
            params={"user_principal_name": test_upn},
            headers=client.build_headers(),
            ok_codes=(200, 400, 404),
        )
        return "ok"

    except Exception as e:
        # Try to extract an HTTP status (when available)
        status = None
        try:
            # DemistoException often carries the original Response in e.res
            status = getattr(getattr(e, "res", None), "status_code", None)
        except Exception:
            pass

        if status in (401, 403):
            return_error(f"Authentication failed (HTTP {status}). "
                         "Check the App User ID:Secret, server URL, JWT clock skew, and permissions.")
        elif status:
            return_error(f"Unexpected response from getEntityRisk (HTTP {status}): {str(e)}")
        else:
            # No HTTP status available; surface the error
            return_error(f"Failed to call getEntityRisk: {str(e)}")


def get_user_entity_risk_command(client, args):
    upn = args.get("upn")
    if not upn:
        upn = get_upn(client, args)
    result = client.get_user_entity_risk_http_request(upn)

    outputs = {"UPN": upn, "Risk": result.get("risk"), "Reasons": result.get("reasons")}
    name = "Silverfort User Risk"
    headers = ["UPN", "Risk", "Reasons"]
    readable_output = tableToMarkdown(name, outputs, headers)

    return (
        readable_output,
        {"Silverfort.UserRisk(val.UPN && val.UPN == obj.UPN)": outputs},
        result,  # raw response - the original response
    )


def get_resource_entity_risk_command(client, args):
    resource_name = args.get("resource_name")
    domain_name = args.get("domain_name")
    result = client.get_resource_entity_risk_http_request(resource_name, domain_name)

    outputs = {"ResourceName": resource_name, "Risk": result.get("risk"), "Reasons": result.get("reasons")}
    name = "Silverfort Resource Risk"
    headers = ["ResourceName", "Risk", "Reasons"]
    readable_output = tableToMarkdown(name, outputs, headers)

    return (
        readable_output,
        {"Silverfort.ResourceRisk(val.ResourceName && val.ResourceName == obj.ResourceName)": outputs},
        result,  # raw response - the original response
    )


def update_user_entity_risk_command(client, args):
    upn = args.get("upn")
    if not upn:
        upn = get_upn(client, args)
    risks = create_risk_json(args)
    result = client.update_user_entity_risk_http_request(upn, risks)

    if result == UPDATE_REQ_RESPONSE:
        return "updated successfully!"
    else:
        return "Couldn't update the user entity's risk"


def update_resource_entity_risk_command(client, args):
    resource_name = args.get("resource_name")
    domain_name = args.get("domain_name")
    risks = create_risk_json(args)
    result = client.update_resource_entity_risk_http_request(resource_name, domain_name, risks)

    if result == UPDATE_REQ_RESPONSE:
        return "updated successfully!"
    else:
        return "Couldn't update the resource entity's risk"


def main():  # pragma: no cover
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    base_url = urljoin(demisto.params().get("url"), "/v1/public")
    verify_certificate = not demisto.params().get("insecure", False)

    api_key = demisto.params().get("apikey")
    app_user_id, app_user_secret = api_key.split(":")

    operational_api_key = demisto.params().get("operationalApiKey")
    operational_user_id = None
    operational_user_secret = None
    if operational_api_key:
        operational_user_id, operational_user_secret = operational_api_key.split(":")

    external_api_key = demisto.params().get("externalApiKey")
    if not app_user_id or not app_user_secret:
        return_error("Verify the API KEY parameter is correct")

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        client = Client(app_user_id=app_user_id,
                        app_user_secret=app_user_secret,
                        operational_user_id=operational_user_id,
                        operational_user_secret=operational_user_secret,
                        base_url=base_url, verify=verify_certificate,
                        external_api_key=external_api_key)

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == "silverfort-get-user-risk":
            return_outputs(*get_user_entity_risk_command(client, demisto.args()))

        elif demisto.command() == "silverfort-get-resource-risk":
            return_outputs(*get_resource_entity_risk_command(client, demisto.args()))

        elif demisto.command() == "silverfort-update-user-risk":
            result = update_user_entity_risk_command(client, demisto.args())
            demisto.results(result)

        elif demisto.command() == "silverfort-update-resource-risk":
            result = update_resource_entity_risk_command(client, demisto.args())
            demisto.results(result)
    # Log exceptions
    except Exception as e:
        error_message = f"Failed to execute {demisto.command()} command. Error: "
        if "Failed to parse" in e.args[0]:
            return_error(message=error_message + "Verify the URL parameter is correct")
        elif "riskapi" not in e.args[0]:
            return_error(message=error_message + str(e.args[0]))
        else:
            return_error(error_message + "Something went wrong")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

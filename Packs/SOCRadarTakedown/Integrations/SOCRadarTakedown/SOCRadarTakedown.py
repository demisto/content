import urllib3
import re
from typing import Any

# Import XSOAR common functions
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

SOCRADAR_API_ENDPOINT = "https://platform.socradar.com/api"
MESSAGES = {
    "BAD_REQUEST_ERROR": "An error occurred while fetching the data.",
    "AUTHORIZATION_ERROR": "Authorization Error: make sure API Key is correctly set.",
    "RATE_LIMIT_EXCEED_ERROR": "Rate limit has been exceeded. Please make sure your API key's rate limit is adequate.",
}

""" CLIENT CLASS """


class Client:
    """
    Client class to interact with the SOCRadar Takedown API
    """

    def __init__(self, base_url: str, api_key: str, company_id: str, verify: bool, proxy: bool):
        self.base_url = base_url
        self.api_key = api_key
        self.company_id = company_id
        self.headers = {"API-KEY": self.api_key}
        self.verify = verify
        self.proxy = proxy

    def check_auth(self) -> dict[str, Any]:
        """Checks if the API key is valid"""
        url = f"{self.base_url}/get/company/{self.company_id}/takedown/requests"

        try:
            response = requests.get(url, headers=self.headers, verify=self.verify)

            if response.status_code == 401:
                raise Exception("Authorization Error: Invalid API Key")
            elif response.status_code == 429:
                raise Exception("Rate limit exceeded")
            elif response.status_code >= 500:
                raise Exception(f"Server Error: {response.status_code}")
            elif response.status_code >= 400:
                raise Exception(f"API Error: {response.status_code}")

            return {"is_success": True}

        except requests.exceptions.RequestException as e:
            raise Exception(f"Connection error: {str(e)}")

    def submit_phishing_domain_takedown(
        self, domain: str, abuse_type: str, domain_type: str, notes: str = "", send_alarm: bool = True, email: str = ""
    ) -> dict[str, Any]:
        """Submit phishing domain takedown request"""
        url = f"{self.base_url}/add/company/{self.company_id}/takedown/request"
        data = {
            "abuse_type": abuse_type,
            "entity": domain,
            "type": domain_type,
            "notes": notes,
            "send_alarm": send_alarm,
            "email": email,
        }

        response = requests.post(url, json=data, headers=self.headers, verify=self.verify)

        if response.status_code >= 400:
            raise Exception(f"API Error: {response.status_code} - {response.text}")

        return response.json()

    def submit_social_media_impersonation_takedown(
        self, username: str, full_name: str, account_type: str, notes: str = "", send_alarm: bool = True, email: str = ""
    ) -> dict[str, Any]:
        """Submit social media impersonation takedown request"""
        url = f"{self.base_url}/add/company/{self.company_id}/takedown/request/social_media_risks"
        data = {
            "impersonating_account": {"username": username, "full_name": full_name, "account_type": account_type},
            "notes": notes,
            "send_alarm": send_alarm,
            "email": email,
        }

        response = requests.post(url, json=data, headers=self.headers, verify=self.verify)

        if response.status_code >= 400:
            raise Exception(f"API Error: {response.status_code} - {response.text}")

        return response.json()

    def submit_source_code_leak_takedown(self, leak_id: int, notes: str = "", email: str = "") -> dict[str, Any]:
        """Submit source code leak takedown request"""
        url = f"{self.base_url}/add/company/{self.company_id}/takedown/request/source_code_leaks"
        data = {
            "id": leak_id,
            "notes": notes,
            "email": email,
        }

        response = requests.post(url, json=data, headers=self.headers, verify=self.verify)

        if response.status_code >= 400:
            raise Exception(f"API Error: {response.status_code} - {response.text}")

        return response.json()

    def submit_rogue_app_takedown(self, app_id: int, notes: str = "", email: str = "") -> dict[str, Any]:
        """Submit rogue mobile app takedown request"""
        url = f"{self.base_url}/add/company/{self.company_id}/takedown/request/rogue_mobile_apps"
        data = {
            "id": app_id,
            "notes": notes,
            "email": email,
        }

        response = requests.post(url, json=data, headers=self.headers, verify=self.verify)

        if response.status_code >= 400:
            raise Exception(f"API Error: {response.status_code} - {response.text}")

        return response.json()


""" HELPER FUNCTIONS """


class Validator:
    @staticmethod
    def validate_domain(domain_to_validate: str) -> bool:
        if not isinstance(domain_to_validate, str) or len(domain_to_validate) > 255:
            return False
        if domain_to_validate.endswith("."):
            domain_to_validate = domain_to_validate[:-1]
        domain_regex = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(domain_regex.match(x) for x in domain_to_validate.split("."))

    @staticmethod
    def raise_if_domain_not_valid(domain: str):
        if not Validator.validate_domain(domain):
            raise ValueError(f'Domain "{domain}" is not a valid domain address')

    @staticmethod
    def validate_url(url: str) -> bool:
        """Basic URL validation"""
        url_pattern = re.compile(
            r"^https?://"  # http:// or https://
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain...
            r"localhost|"  # localhost...
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
            r"(?::\d+)?"  # optional port
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )
        return url_pattern.match(url) is not None

    @staticmethod
    def raise_if_url_not_valid(url: str):
        if not Validator.validate_url(url):
            raise ValueError(f'URL "{url}" is not a valid URL')


def get_client_from_params() -> Client:
    """Initialize client from demisto params"""
    params = demisto.params()
    api_key = params.get("credentials", {}).get("password", "").strip()
    company_id = params.get("credentials", {}).get("identifier", "").strip()
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    if not api_key:
        raise ValueError("API Key is required")
    if not company_id:
        raise ValueError("Company ID is required")

    return Client(base_url=SOCRADAR_API_ENDPOINT, api_key=api_key, company_id=company_id, verify=verify_certificate, proxy=proxy)


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication"""
    try:
        client.check_auth()
        return "ok"
    except Exception as e:
        return f"Test failed: {str(e)}"


def submit_phishing_domain_takedown_command(client: Client) -> CommandResults:
    """Submits a takedown request for a phishing domain or URL"""
    args = demisto.args()
    domain = args.get("domain", "")
    abuse_type = args.get("abuse_type", "potential_phishing")
    domain_type = args.get("type", "phishing_domain")
    notes = args.get("notes", "")
    send_alarm = args.get("send_alarm", "true").lower() == "true"
    email = args.get("email", "")

    # Validate based on type
    if domain_type == "phishing_url":
        Validator.raise_if_url_not_valid(domain)
    else:  # phishing_domain
        Validator.raise_if_domain_not_valid(domain)

    # Submit request
    raw_response = client.submit_phishing_domain_takedown(
        domain=domain, abuse_type=abuse_type, domain_type=domain_type, notes=notes, send_alarm=send_alarm, email=email
    )

    # Prepare output
    readable_output = "### Phishing Domain Takedown Request\n"
    readable_output += f"**Domain**: {domain}\n"
    readable_output += f"**Status**: {'Success' if raw_response.get('is_success', False) else 'Failed'}\n"

    if raw_response.get("message"):
        readable_output += f"**Message**: {raw_response.get('message')}\n"

    outputs = {
        "Domain": domain,
        "AbuseType": abuse_type,
        "Status": "Success" if raw_response.get("is_success", False) else "Failed",
        "Message": raw_response.get("message", ""),
        "SendAlarm": send_alarm,
        "Notes": notes,
    }

    return CommandResults(
        outputs_prefix="SOCRadarTakedown.PhishingDomain",
        outputs_key_field="Domain",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def submit_social_media_impersonation_takedown_command(client: Client) -> CommandResults:
    """Submits a takedown request for social media impersonation"""
    args = demisto.args()
    username = args.get("username", "")
    full_name = args.get("full_name", "")
    account_type = args.get("account_type", "")
    notes = args.get("notes", "")
    send_alarm = args.get("send_alarm", "true").lower() == "true"
    email = args.get("email", "")

    # Submit request
    raw_response = client.submit_social_media_impersonation_takedown(
        username=username,
        full_name=full_name,
        account_type=account_type,
        notes=notes,
        send_alarm=send_alarm,
        email=email,
    )

    # Prepare output
    readable_output = "### Social Media Impersonation Takedown Request\n"
    readable_output += f"**Username**: {username}\n"
    readable_output += f"**Full Name**: {full_name}\n"
    readable_output += f"**Account Type**: {account_type}\n"
    readable_output += f"**Status**: {'Success' if raw_response.get('is_success', False) else 'Failed'}\n"

    if raw_response.get("message"):
        readable_output += f"**Message**: {raw_response.get('message')}\n"

    outputs = {
        "Username": username,
        "FullName": full_name,
        "AccountType": account_type,
        "AbuseType": "impersonating_accounts",
        "Status": "Success" if raw_response.get("is_success", False) else "Failed",
        "Message": raw_response.get("message", ""),
        "SendAlarm": send_alarm,
        "Notes": notes,
    }

    return CommandResults(
        outputs_prefix="SOCRadarTakedown.SocialMediaImpersonation",
        outputs_key_field="Username",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def submit_source_code_leak_takedown_command(client: Client) -> CommandResults:
    """Submits a takedown request for leaked source code"""
    args = demisto.args()
    leak_id = int(args.get("id", "0"))
    notes = args.get("notes", "")
    email = args.get("email", "")

    # Submit request
    raw_response = client.submit_source_code_leak_takedown(leak_id=leak_id, notes=notes, email=email)

    # Prepare output
    readable_output = "### Source Code Leak Takedown Request\n"
    readable_output += f"**Leak ID**: {leak_id}\n"
    readable_output += f"**Status**: {'Success' if raw_response.get('is_success', False) else 'Failed'}\n"

    if raw_response.get("message"):
        readable_output += f"**Message**: {raw_response.get('message')}\n"

    outputs = {
        "LeakID": leak_id,
        "AbuseType": "source_code_leak",
        "Status": "Success" if raw_response.get("is_success", False) else "Failed",
        "Message": raw_response.get("message", ""),
        "Notes": notes,
        "Email": email,
    }

    return CommandResults(
        outputs_prefix="SOCRadarTakedown.SourceCodeLeak",
        outputs_key_field="LeakID",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def submit_rogue_app_takedown_command(client: Client) -> CommandResults:
    """Submits a takedown request for a rogue mobile app"""
    args = demisto.args()
    app_id = int(args.get("id", "0"))
    notes = args.get("notes", "")
    send_alarm = args.get("send_alarm", "true").lower() == "true"
    email = args.get("email", "")

    # Submit request
    raw_response = client.submit_rogue_app_takedown(app_id=app_id, notes=notes, email=email)

    # Prepare output
    readable_output = "### Rogue App Takedown Request\n"
    readable_output += f"**App ID**: {app_id}\n"
    readable_output += f"**Status**: {'Success' if raw_response.get('is_success', False) else 'Failed'}\n"

    if raw_response.get("message"):
        readable_output += f"**Message**: {raw_response.get('message')}\n"

    outputs = {
        "AppID": str(app_id),
        "AbuseType": "rogue_mobile_app",
        "Status": "Success" if raw_response.get("is_success", False) else "Failed",
        "Message": raw_response.get("message", ""),
        "SendAlarm": send_alarm,
        "Notes": notes,
        "Email": email,
    }

    return CommandResults(
        outputs_prefix="SOCRadarTakedown.RogueApp",
        outputs_key_field="AppID",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


""" MAIN FUNCTION """


def main():
    """Main function, parses params and runs command functions"""
    try:
        command = demisto.command()

        if command == "test-module":
            client = get_client_from_params()
            result = test_module(client)
            return_results(result)
        else:
            client = get_client_from_params()

            if command == "socradar-submit-phishing-domain":
                return_results(submit_phishing_domain_takedown_command(client))
            elif command == "socradar-submit-social-media-impersonation":
                return_results(submit_social_media_impersonation_takedown_command(client))
            elif command == "socradar-submit-source-code-leak":
                return_results(submit_source_code_leak_takedown_command(client))
            elif command == "socradar-submit-rogue-app":
                return_results(submit_rogue_app_takedown_command(client))
            else:
                raise NotImplementedError(f"Unknown command {command}")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
import traceback
import re
from typing import Any, Dict, List, Optional, Union
from json.decoder import JSONDecodeError

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

    def __init__(self, base_url, api_key, company_id, verify, proxy):
        self.base_url = base_url
        self.api_key = api_key
        self.company_id = company_id
        self.headers = {"API-KEY": self.api_key}
        self.verify = verify
        self.proxy = proxy

    def check_auth(self):
        """Checks if the API key is valid"""
        import requests

        url = f"{self.base_url}/get/company/{self.company_id}/takedown/progress"
        params = {"asset_id": "test", "type": "impersonating_accounts"}

        try:
            response = requests.get(
                url,
                params=params,
                headers=self.headers,
                verify=self.verify
            )

            if response.status_code == 401:
                raise Exception("Authorization Error: Invalid API Key")
            elif response.status_code == 429:
                raise Exception("Rate limit exceeded")
            elif response.status_code >= 400:
                raise Exception(f"API Error: {response.status_code}")

            return {"is_success": True}

        except requests.exceptions.RequestException as e:
            raise Exception(f"Connection error: {str(e)}")

    def submit_phishing_domain_takedown(self, domain, abuse_type="potential_phishing", notes="",
                                        domain_type="phishing_domain", send_alarm=True, email=""):
        """Submits a takedown request for a phishing domain"""
        import requests

        url = f"{self.base_url}/add/company/{self.company_id}/takedown/request"
        data = {
            "abuse_type": abuse_type,
            "entity": domain,
            "type": domain_type,
            "notes": notes,
            "send_alarm": send_alarm,
            "email": email
        }

        response = requests.post(
            url,
            json=data,
            headers=self.headers,
            verify=self.verify
        )

        if response.status_code >= 400:
            raise Exception(f"API Error: {response.status_code} - {response.text}")

        return response.json()

    def submit_social_media_impersonation_takedown(self, url_link, abuse_type="impersonating_accounts",
                                                   notes="", send_alarm=True, email=""):
        """Submits a takedown request for social media impersonation"""
        import requests

        api_url = f"{self.base_url}/add/company/{self.company_id}/takedown/request"
        data = {
            "abuse_type": abuse_type,
            "entity": url_link,
            "type": "impersonating_accounts",
            "notes": notes,
            "send_alarm": send_alarm,
            "email": email
        }

        response = requests.post(
            api_url,
            json=data,
            headers=self.headers,
            verify=self.verify
        )

        if response.status_code >= 400:
            raise Exception(f"API Error: {response.status_code} - {response.text}")

        return response.json()

    def get_takedown_progress(self, asset_id, takedown_type):
        """Gets the progress of a takedown request"""
        import requests

        url = f"{self.base_url}/get/company/{self.company_id}/takedown/progress"
        params = {
            "asset_id": asset_id,
            "type": takedown_type
        }

        try:
            response = requests.get(
                url,
                params=params,
                headers=self.headers,
                verify=self.verify
            )

            if response.status_code == 401:
                raise Exception("Authorization Error: Invalid API Key")
            elif response.status_code == 429:
                raise Exception("Rate limit exceeded")
            elif response.status_code >= 400:
                raise Exception(f"API Error: {response.status_code} - {response.text}")

            return response.json()

        except requests.exceptions.RequestException as e:
            raise Exception(f"Connection error: {str(e)}")

    def submit_source_code_leak_takedown(self, url_link, abuse_type="source_code_leak",
                                         notes="", send_alarm=True, email=""):
        """Submits a takedown request for leaked source code"""
        import requests

        api_url = f"{self.base_url}/add/company/{self.company_id}/takedown/request"
        data = {
            "abuse_type": abuse_type,
            "entity": url_link,
            "type": "source_code_leak",
            "notes": notes,
            "send_alarm": send_alarm,
            "email": email
        }

        response = requests.post(
            api_url,
            json=data,
            headers=self.headers,
            verify=self.verify
        )

        if response.status_code >= 400:
            raise Exception(f"API Error: {response.status_code} - {response.text}")

        return response.json()

    def submit_rogue_app_takedown(self, app_info, abuse_type="rogue_mobile_app",
                                  notes="", send_alarm=True, email=""):
        """Submits a takedown request for a rogue mobile app"""
        import requests

        api_url = f"{self.base_url}/add/company/{self.company_id}/takedown/request"
        data = {
            "abuse_type": abuse_type,
            "entity": app_info,
            "type": "rogue_mobile_app",
            "notes": notes,
            "send_alarm": send_alarm,
            "email": email
        }

        response = requests.post(
            api_url,
            json=data,
            headers=self.headers,
            verify=self.verify
        )

        if response.status_code >= 400:
            raise Exception(f"API Error: {response.status_code} - {response.text}")

        return response.json()


""" HELPER FUNCTIONS """


class Validator:
    @staticmethod
    def validate_domain(domain_to_validate):
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
    def validate_url(url: str):
        """Basic URL validation"""
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return url_pattern.match(url) is not None

    @staticmethod
    def raise_if_url_not_valid(url: str):
        if not Validator.validate_url(url):
            raise ValueError(f'URL "{url}" is not a valid URL')


""" COMMAND FUNCTIONS """


def test_module():
    """Tests API connectivity and authentication"""
    try:
        # Get parameters
        api_key = demisto.params().get("apikey", "")
        company_id = demisto.params().get("company_id", "")
        verify_certificate = not demisto.params().get("insecure", False)
        proxy = demisto.params().get("proxy", False)

        if not api_key:
            return "API Key is required"
        if not company_id:
            return "Company ID is required"

        # Create client and test
        client = Client(
            base_url=SOCRADAR_API_ENDPOINT,
            api_key=api_key,
            company_id=company_id,
            verify=verify_certificate,
            proxy=proxy
        )

        client.check_auth()
        return "ok"

    except Exception as e:
        return f"Test failed: {str(e)}"


def submit_phishing_domain_takedown_command():
    """Submits a takedown request for a phishing domain"""
    try:
        # Get parameters
        api_key = demisto.params().get("apikey", "")
        company_id = demisto.params().get("company_id", "")
        verify_certificate = not demisto.params().get("insecure", False)
        proxy = demisto.params().get("proxy", False)

        # Get arguments
        domain = demisto.args().get("domain", "")
        abuse_type = demisto.args().get("abuse_type", "potential_phishing")
        domain_type = demisto.args().get("type", "phishing_domain")
        notes = demisto.args().get("notes", "")
        send_alarm = demisto.args().get("send_alarm", "true").lower() == "true"
        email = demisto.args().get("email", "")

        # Validate required fields
        if not domain:
            raise ValueError("Domain is required")
        if not email:
            raise ValueError("Email is required")

        # Validate domain
        Validator.raise_if_domain_not_valid(domain)

        # Create client
        client = Client(
            base_url=SOCRADAR_API_ENDPOINT,
            api_key=api_key,
            company_id=company_id,
            verify=verify_certificate,
            proxy=proxy
        )

        # Submit request
        raw_response = client.submit_phishing_domain_takedown(
            domain, abuse_type, notes, domain_type, send_alarm, email
        )

        # Prepare output
        readable_output = f"### Phishing Domain Takedown Request\n"
        readable_output += f"**Domain**: {domain}\n"
        readable_output += f"**Status**: {'Success' if raw_response.get('is_success', False) else 'Failed'}\n"

        if raw_response.get("message"):
            readable_output += f"**Message**: {raw_response.get('message')}\n"

        outputs = {
            "SOCRadarTakedown.PhishingDomain(val.Domain == obj.Domain)": {
                "Domain": domain,
                "AbuseType": abuse_type,
                "Status": "Success" if raw_response.get('is_success', False) else "Failed",
                "Message": raw_response.get("message", ""),
                "SendAlarm": send_alarm,
                "Notes": notes
            }
        }

        demisto.results({
            "Type": entryTypes["note"],
            "Contents": raw_response,
            "ContentsFormat": formats["json"],
            "HumanReadable": readable_output,
            "EntryContext": outputs
        })

    except Exception as e:
        demisto.results({
            "Type": entryTypes["error"],
            "Contents": str(e),
            "ContentsFormat": formats["text"]
        })


def submit_social_media_impersonation_takedown_command():
    """Submits a takedown request for social media impersonation"""
    try:
        # Get parameters
        api_key = demisto.params().get("apikey", "")
        company_id = demisto.params().get("company_id", "")
        verify_certificate = not demisto.params().get("insecure", False)
        proxy = demisto.params().get("proxy", False)

        # Get arguments
        url_link = demisto.args().get("url", "")
        abuse_type = demisto.args().get("abuse_type", "impersonating_accounts")
        notes = demisto.args().get("notes", "")
        send_alarm = demisto.args().get("send_alarm", "true").lower() == "true"
        email = demisto.args().get("email", "")

        # Validate required fields
        if not url_link:
            raise ValueError("URL is required")
        if not email:
            raise ValueError("Email is required")

        # Validate URL
        Validator.raise_if_url_not_valid(url_link)

        # Create client
        client = Client(
            base_url=SOCRADAR_API_ENDPOINT,
            api_key=api_key,
            company_id=company_id,
            verify=verify_certificate,
            proxy=proxy
        )

        # Submit request
        raw_response = client.submit_social_media_impersonation_takedown(
            url_link, abuse_type, notes, send_alarm, email
        )

        # Prepare output
        readable_output = f"### Social Media Impersonation Takedown Request\n"
        readable_output += f"**URL**: {url_link}\n"
        readable_output += f"**Status**: {'Success' if raw_response.get('is_success', False) else 'Failed'}\n"

        if raw_response.get("message"):
            readable_output += f"**Message**: {raw_response.get('message')}\n"

        outputs = {
            "SOCRadarTakedown.SocialMediaImpersonation(val.URL == obj.URL)": {
                "URL": url_link,
                "AbuseType": abuse_type,
                "Status": "Success" if raw_response.get('is_success', False) else "Failed",
                "Message": raw_response.get("message", ""),
                "SendAlarm": send_alarm,
                "Notes": notes
            }
        }

        demisto.results({
            "Type": entryTypes["note"],
            "Contents": raw_response,
            "ContentsFormat": formats["json"],
            "HumanReadable": readable_output,
            "EntryContext": outputs
        })

    except Exception as e:
        demisto.results({
            "Type": entryTypes["error"],
            "Contents": str(e),
            "ContentsFormat": formats["text"]
        })


def get_takedown_progress_command():
    """Gets the progress of a takedown request"""
    try:
        # Get parameters
        api_key = demisto.params().get("apikey", "")
        company_id = demisto.params().get("company_id", "")
        verify_certificate = not demisto.params().get("insecure", False)
        proxy = demisto.params().get("proxy", False)

        # Get arguments
        asset_id = demisto.args().get("asset_id", "")
        takedown_type = demisto.args().get("type", "")

        # Validate required fields
        if not asset_id:
            raise ValueError("Asset ID is required")
        if not takedown_type:
            raise ValueError("Type is required")

        # Create client
        client = Client(
            base_url=SOCRADAR_API_ENDPOINT,
            api_key=api_key,
            company_id=company_id,
            verify=verify_certificate,
            proxy=proxy
        )

        # Get progress
        raw_response = client.get_takedown_progress(asset_id, takedown_type)

        # Prepare output
        readable_output = f"### Takedown Progress\n"
        readable_output += f"**Asset ID**: {asset_id}\n"
        readable_output += f"**Type**: {takedown_type}\n"

        if raw_response.get("status"):
            readable_output += f"**Status**: {raw_response.get('status')}\n"
        if raw_response.get("progress"):
            readable_output += f"**Progress**: {raw_response.get('progress')}\n"
        if raw_response.get("message"):
            readable_output += f"**Message**: {raw_response.get('message')}\n"

        outputs = {
            "SOCRadarTakedown.Progress(val.AssetId == obj.AssetId)": {
                "AssetId": asset_id,
                "Type": takedown_type,
                "Status": raw_response.get("status", ""),
                "Progress": raw_response.get("progress", ""),
                "Message": raw_response.get("message", ""),
                "RawResponse": raw_response
            }
        }

        demisto.results({
            "Type": entryTypes["note"],
            "Contents": raw_response,
            "ContentsFormat": formats["json"],
            "HumanReadable": readable_output,
            "EntryContext": outputs
        })

    except Exception as e:
        demisto.results({
            "Type": entryTypes["error"],
            "Contents": str(e),
            "ContentsFormat": formats["text"]
        })


def submit_source_code_leak_takedown_command():
    """Submits a takedown request for leaked source code"""
    try:
        # Get parameters
        api_key = demisto.params().get("apikey", "")
        company_id = demisto.params().get("company_id", "")
        verify_certificate = not demisto.params().get("insecure", False)
        proxy = demisto.params().get("proxy", False)

        # Get arguments
        url_link = demisto.args().get("url", "")
        abuse_type = demisto.args().get("abuse_type", "source_code_leak")
        notes = demisto.args().get("notes", "")
        send_alarm = demisto.args().get("send_alarm", "true").lower() == "true"
        email = demisto.args().get("email", "")

        # Validate required fields
        if not url_link:
            raise ValueError("URL is required")
        if not email:
            raise ValueError("Email is required")

        # Validate URL
        Validator.raise_if_url_not_valid(url_link)

        # Create client
        client = Client(
            base_url=SOCRADAR_API_ENDPOINT,
            api_key=api_key,
            company_id=company_id,
            verify=verify_certificate,
            proxy=proxy
        )

        # Submit request
        raw_response = client.submit_source_code_leak_takedown(
            url_link, abuse_type, notes, send_alarm, email
        )

        # Prepare output
        readable_output = f"### Source Code Leak Takedown Request\n"
        readable_output += f"**URL**: {url_link}\n"
        readable_output += f"**Status**: {'Success' if raw_response.get('is_success', False) else 'Failed'}\n"

        if raw_response.get("message"):
            readable_output += f"**Message**: {raw_response.get('message')}\n"

        outputs = {
            "SOCRadarTakedown.SourceCodeLeak(val.URL == obj.URL)": {
                "URL": url_link,
                "AbuseType": abuse_type,
                "Status": "Success" if raw_response.get('is_success', False) else "Failed",
                "Message": raw_response.get("message", ""),
                "SendAlarm": send_alarm,
                "Notes": notes
            }
        }

        demisto.results({
            "Type": entryTypes["note"],
            "Contents": raw_response,
            "ContentsFormat": formats["json"],
            "HumanReadable": readable_output,
            "EntryContext": outputs
        })

    except Exception as e:
        demisto.results({
            "Type": entryTypes["error"],
            "Contents": str(e),
            "ContentsFormat": formats["text"]
        })


def submit_rogue_app_takedown_command():
    """Submits a takedown request for a rogue mobile app"""
    try:
        # Get parameters
        api_key = demisto.params().get("apikey", "")
        company_id = demisto.params().get("company_id", "")
        verify_certificate = not demisto.params().get("insecure", False)
        proxy = demisto.params().get("proxy", False)

        # Get arguments
        app_info = demisto.args().get("app_info", "")
        abuse_type = demisto.args().get("abuse_type", "rogue_mobile_app")
        notes = demisto.args().get("notes", "")
        send_alarm = demisto.args().get("send_alarm", "true").lower() == "true"
        email = demisto.args().get("email", "")

        # Validate required fields
        if not app_info:
            raise ValueError("App info is required")
        if not email:
            raise ValueError("Email is required")

        # Create client
        client = Client(
            base_url=SOCRADAR_API_ENDPOINT,
            api_key=api_key,
            company_id=company_id,
            verify=verify_certificate,
            proxy=proxy
        )

        # Submit request
        raw_response = client.submit_rogue_app_takedown(
            app_info, abuse_type, notes, send_alarm, email
        )

        # Prepare output
        readable_output = f"### Rogue App Takedown Request\n"
        readable_output += f"**App Info**: {app_info}\n"
        readable_output += f"**Status**: {'Success' if raw_response.get('is_success', False) else 'Failed'}\n"

        if raw_response.get("message"):
            readable_output += f"**Message**: {raw_response.get('message')}\n"

        outputs = {
            "SOCRadarTakedown.RogueApp(val.AppInfo == obj.AppInfo)": {
                "AppInfo": app_info,
                "AbuseType": abuse_type,
                "Status": "Success" if raw_response.get('is_success', False) else "Failed",
                "Message": raw_response.get("message", ""),
                "SendAlarm": send_alarm,
                "Notes": notes
            }
        }

        demisto.results({
            "Type": entryTypes["note"],
            "Contents": raw_response,
            "ContentsFormat": formats["json"],
            "HumanReadable": readable_output,
            "EntryContext": outputs
        })

    except Exception as e:
        demisto.results({
            "Type": entryTypes["error"],
            "Contents": str(e),
            "ContentsFormat": formats["text"]
        })


""" MAIN FUNCTION """


def main():
    """Main function, parses params and runs command functions"""
    try:
        command = demisto.command()

        if command == "test-module":
            result = test_module()
            demisto.results(result)

        elif command == "socradar-submit-phishing-domain":
            submit_phishing_domain_takedown_command()

        elif command == "socradar-submit-social-media-impersonation":
            submit_social_media_impersonation_takedown_command()

        elif command == "socradar-get-takedown-progress":
            get_takedown_progress_command()

        elif command == "socradar-submit-source-code-leak":
            submit_source_code_leak_takedown_command()

        elif command == "socradar-submit-rogue-app":
            submit_rogue_app_takedown_command()

        else:
            demisto.results({
                "Type": entryTypes["error"],
                "Contents": f"Unknown command: {command}",
                "ContentsFormat": formats["text"]
            })

    except Exception as e:
        demisto.results({
            "Type": entryTypes["error"],
            "Contents": f"Failed to execute {demisto.command()} command. Error: {str(e)}",
            "ContentsFormat": formats["text"]
        })


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

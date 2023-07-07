import demistomock as demisto
from CommonServerPython import *


""" IMPORTS  """
from dateparser import parse as parse_date
from typing import Dict, List, Callable
from requests import Response

""" GLOBALS / PARAMS  """
FETCH_TIME_DEFAULT = "3 days"
CLOSED_ALERT_STATUS = ["Closed", "Deleted"]


""" CLIENT """


class ZFClient(BaseClient):
    def __init__(self, username, password, fetch_limit, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.credentials = {
            "username": username,
            "password": password
        }
        self.fetch_limit = fetch_limit

    def api_request(
        self,
        method: str,
        url_suffix: str,
        headers_builder_type: str | None = 'api',
        params: Dict | None = None,
        data: Dict | None = None,
        prefix: str | None = "1.0",
        empty_response: bool = False,
        error_handler: Callable[[Any], Any] | None = None,
    ):
        """
        :param method: HTTP request type
        :param url_suffix: The suffix of the URL
        :param headers_builder_type: It can be `api` or `cti`. It selects
        the function to build the headers required
        for each case
        :param params: The request's query parameters
        :param data: The request's body parameters
        :param version: api prefix to consider, default is to use version '1.0'
        :param res_type: Selects the decoder of the response. It can be
        `json` (default), `xml`, `text`, `content`, `response`
        :param empty_response: Indicates if the response data is empty or not
        :param error_handler: Function that receives the response and manage
        the error
        :return: Returns the content of the response received from the API.
        """
        pref_string = f"/{prefix}" if prefix else ""

        if headers_builder_type is None:
            headers = {}
        else:
            if headers_builder_type not in ("api", "cti"):
                raise ValueError(
                    "`headers_builder_type` should be 'api' or 'cti'"
                )
            header_builder = dict(
                api=self.get_api_request_header,
                cti=self.get_cti_request_header
            ).get(headers_builder_type)
            if header_builder is None:
                raise ValueError(
                    "`headers_builder_type` should be 'api' or 'cti'"
                )
            headers = header_builder()

        return self._http_request(
            method=method,
            url_suffix=urljoin(pref_string, url_suffix),
            headers=headers,
            params=params,
            data=data,
            empty_valid_codes=(200, 201),
            return_empty_response=empty_response,
            error_handler=error_handler,
        )

    def handle_auth_error(self, raw_response: Response):
        response = raw_response.json()
        if "res_content" in response:
            raise Exception("Failure resolving URL.")
        error_msg_list: List = response.get("non_field_errors", [])
        if not error_msg_list:
            raise Exception("Unable to log in with provided credentials.")
        else:
            raise Exception(error_msg_list[0])

    def get_authorization_token(self) -> str:
        """
        :return: Returns the authorization token
        """
        integration_context: Dict = demisto.getIntegrationContext()
        token: str = integration_context.get("token", "")
        if token:
            return token
        url_suffix: str = "/1.0/api-token-auth/"
        response_content: Dict = self.api_request(
            "POST",
            url_suffix,
            data=self.credentials,
            error_handler=self.handle_auth_error,
            headers_builder_type=None,
            prefix=None,
        )
        token = response_content.get("token", "")
        demisto.setIntegrationContext({"token": token})
        return token

    def _is_cti_token_valid(self, token: str):
        """
        :param token: Token string to verify if it is still valid
        """
        url_suffix: str = "/auth/token/verify/"
        data_for_request: Dict = {"token": token}
        response: Dict = self.api_request(
            "POST",
            url_suffix,
            data=data_for_request,
            empty_response=True,
            headers_builder_type=None,
            prefix=None,
        )
        return bool(response)

    def _get_new_access_token(self):
        url_suffix: str = "/auth/token/"
        response_content: Dict = self.api_request(
            "POST",
            url_suffix,
            data=self.credentials,
            headers_builder_type=None,
            prefix=None,
        )
        return response_content.get("access", "")

    def get_cti_authorization_token(self) -> str:
        """
        :return: returns the authorization token for the CTI feed
        """
        integration_context: Dict = demisto.getIntegrationContext()
        token: str = integration_context.get("cti_token", "")
        if token and self._is_cti_token_valid(token):
            return token
        token = self._get_new_access_token()
        if not token:
            raise Exception("Unable to retrieve token.")
        demisto.setIntegrationContext({"cti_token": token})
        return token

    def get_api_request_header(self):
        token: str = self.get_authorization_token()
        return {
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def get_cti_request_header(self):
        token: str = self.get_cti_authorization_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def get_policy_types(self) -> Dict:
        """
        :return: HTTP request content.
        """
        url_suffix: str = "/policies/"
        response_content: Dict = self.api_request("GET", url_suffix)
        return response_content

    def list_alerts(self, params: Dict) -> Dict:
        """
        :param params: The request's body parameters.
        :return: HTTP request content.
        """
        url_suffix: str = "/alerts/"
        if not params.get("limit"):
            params['limit'] = self.fetch_limit
        response_content: Dict = self.api_request(
            "GET",
            url_suffix,
            params=params
        )
        return response_content

    def get_alert(self, alert_id: int) -> Dict:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        url_suffix: str = f"/alerts/{alert_id}/"
        response_content: Dict = self.api_request("GET", url_suffix)
        return response_content

    def alert_user_assignment(self, alert_id: int, username: str) -> Dict:
        """
        :param alert_id: The ID of the alert.
        :param username: The username we want to assign to the alert.
        :return: HTTP request content.
        """
        url_suffix: str = f"/alerts/{alert_id}/assign/"
        request_body = {"subject": username}
        response_content: Dict = self.api_request(
            "POST",
            url_suffix,
            data=request_body,
            empty_response=True,
        )
        return response_content

    def close_alert(self, alert_id: int) -> Dict:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        url_suffix: str = f"/alerts/{alert_id}/close/"
        response_content: Dict = self.api_request(
            "POST",
            url_suffix,
            empty_response=True,
        )
        return response_content

    def open_alert(self, alert_id: int) -> Dict:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        url_suffix: str = f"/alerts/{alert_id}/open/"
        response_content: Dict = self.api_request(
            "POST",
            url_suffix,
            empty_response=True,
        )
        return response_content

    def alert_request_takedown(self, alert_id: int) -> Dict:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        url_suffix: str = f"/alerts/{alert_id}/request_takedown/"
        response_content: Dict = self.api_request(
            "POST",
            url_suffix,
            empty_response=True,
        )
        return response_content

    def alert_cancel_takedown(self, alert_id: int) -> Dict:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        url_suffix: str = f"/alerts/{alert_id}/cancel_takedown/"
        response_content: Dict = self.api_request(
            "POST",
            url_suffix,
            empty_response=True,
        )
        return response_content

    def modify_alert_tags(
        self,
        alert_id: int,
        action: str,
        tags_list: List[str]
    ) -> Dict:
        """
        :param alert_id: The ID of the alert.
        :param action: action can be 'added' or 'removed'. It indicates
        what action we want to do i.e add/remove tags/
        :param tags_list_string: A string representation of the tags,
        separated by a comma ','
        :return: HTTP request content.
        """
        url_suffix: str = "/alerttagchangeset/"
        request_body: Dict = {
            "changes": [
                {
                    f"{action}": tags_list,
                    "alert": alert_id,
                },
            ],
        }
        response_content: Dict = self.api_request(
            "POST", url_suffix, data=request_body,
        )
        return response_content

    def create_entity(
        self,
        name: str,
        strict_name_matching: bool | None = None,
        tags: list | None = None,
        policy: int | None = None,
        organization: str | None = None,
    ) -> Dict:
        """
        :param name: Name of the entity (may be non-unique).
        :param strict_name_matching: Indicating type of string matching for
        comparing name to impersonators.
        :param tags: List of string tags for tagging the entity. Separated
        by a comma ','.
        :param policy: The ID of the policy to assign to the new entity.
        :param organization: Organization name associated with entity.
        :return: HTTP request content.
        """
        url_suffix: str = "/entities/"
        request_body: Dict = {
            "name": name,
            "strict_name_matching": strict_name_matching,
            "labels": tags,
            "policy": policy,
            "policy_id": policy,
            "organization": organization,
        }
        request_body = remove_none_dict(request_body)
        response_content: Dict = self.api_request(
            "POST", url_suffix, data=request_body,
        )
        return response_content

    def list_entities(self, params: Dict) -> Dict:
        """
        :param params: The request's body parameters.
        :return: HTTP request content.
        """
        url_suffix: str = "/entities/"
        response_content: Dict = self.api_request(
            "GET",
            url_suffix,
            params=params,
        )
        return response_content

    def get_entity_types(self) -> Dict:
        """
        :return: HTTP request content.
        """
        url_suffix: str = "/entities/types/"
        response_content: Dict = self.api_request("GET", url_suffix)
        return response_content

    def modify_alert_notes(self, alert_id: int, notes: str) -> Dict:
        """
        :param alert_id: The ID of the alert.
        :param notes: The notes for the alert.
        :return: HTTP request content.
        """
        url_suffix: str = f"/alerts/{alert_id}/"
        request_body: Dict = {"notes": notes}
        response_content: Dict = self.api_request(
            "POST",
            url_suffix,
            data=request_body,
            empty_response=True,
        )
        return response_content

    def submit_threat(
        self,
        source: str,
        alert_type: str,
        violation: str,
        entity_id: str
    ):
        """
        :param alert_id: The ID of the alert.
        :param notes: The notes for the alert.
        :return: HTTP request content.
        """
        url_suffix: str = "/threat_submit/"
        request_body: Dict = {
            "source": source,
            "alert_type": alert_type,
            "violation": violation,
            "entity_id": entity_id,
        }
        request_body = remove_none_dict(request_body)
        response_content: Dict = self.api_request(
            "POST",
            url_suffix,
            data=request_body,
            prefix="2.0",
        )
        return response_content

    def get_cti_c2_domains(self, domain: str):
        """
        :param domain: The domain to lookup in c2-domains CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/c2-domains/"
        params = {"domain": domain}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_phishing(self, domain: str | None = None, ip: str | None = None):
        """
        :param domain: The domain to lookup in phishing CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/phishing/"
        params = remove_none_dict({"domain": domain, "host_ip": ip})
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_email_addresses(self, email: str):
        """
        :param email: The email to lookup in email-addresses CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/email-addresses/"
        params = {"email": email}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_compromised_credentials(self, email: str):
        """
        :param email: The email to lookup in compromised-credentials CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/compromised-credentials/"
        params = {"email": email}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_botnet_compromised_credentials(self, email: str):
        """
        :param email: The email to lookup in botnet-compromised-credentials
        CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/botnet-compromised-credentials/"
        params = {"email": email}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_botnet(self, ip: str):
        """
        :param ip: The ip to lookup in botnet CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/botnet/"
        params = {"ip": ip}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_malware(self, hash_type: str, hash: str):
        """
        :param hash_type: The hash type to lookup in malware CTI Feed
        :param hash: The hash to lookup in malware CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/malware/"
        params = {hash_type: hash}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_exploits(self, since: str):
        """
        :param since: since date to query exploits
        :return: HTTP request content.
        """
        url_suffix = "/exploits/"
        params = {"created_after": since}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content


""" HELPERS """


def alert_to_incident(alert: Dict) -> Dict:
    """
    transforms an alert to incident convention
    :param alert: alert is a dictionary
    :return: Incident - dictionary
    """
    alert_id: str = str(alert.get("id", ""))
    incident: Dict = {
        "rawJSON": json.dumps(alert),
        "name": f"ZeroFox Alert {alert_id}",
        "occurred": alert.get("timestamp", ""),
    }
    return incident


def dict_value_to_integer(params: Dict, key: str):
    """
    :param params: A dictionary which has the key param
    :param key: The key that we need to convert it's value to integer
    :return: The integer representation of the key's value in the dict params
    """
    try:
        if params:
            value: str = params.get(key, "")
            if value:
                params[key] = int(value)
                return params[key]
    except ValueError:
        raise Exception(f"This value for {key} must be an integer.")


def severity_num_to_string(severity_num: int) -> str:
    """
    transforms severity number to string representation
    :param severity_num: Severity score as Integer
    :return: Returns the String representation of the severity score
    """
    severity_map = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
    return severity_map.get(severity_num, "")


def severity_string_to_num(severity_str: str) -> int:
    """
    :param severity_str: Severity score as String
    :return: Returns the Integer representation of the severity score
    """
    severity_map = {"Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
    return severity_map.get(severity_str, -1)


def get_nested_key(obj: Dict, path: List[str], default_value: Any | None = None):
    for key in path[:-1]:
        obj = obj.get(key, {})
        if not isinstance(obj, dict):
            return default_value
    return obj.get(path[-1])


def get_alert_contents(alert: Dict) -> Dict:
    """
    :param alert: Alert is a dictionary
    :return: A dict representing the alert contents
    """
    return {
        "AlertType": alert.get("alert_type"),
        "OffendingContentURL": alert.get("offending_content_url"),
        "Assignee": alert.get("assignee"),
        "EntityID": get_nested_key(alert, ["entity", "id"]),
        "EntityName": get_nested_key(alert, ["entity", "name"]),
        "EntityImage": get_nested_key(alert, ["entity", "image"]),
        "EntityTermID": get_nested_key(alert, ["entity_term", "id"]),
        "EntityTermName": get_nested_key(alert, ["entity_term", "name"]),
        "EntityTermDeleted": get_nested_key(alert, ["entity_term", "deleted"]),
        "ContentCreatedAt": alert.get("content_created_at"),
        "ID": alert.get("id"),
        "ProtectedAccount": alert.get("protected_account"),
        "RiskRating": severity_num_to_string(int(alert.get("severity", ""))),
        "PerpetratorName": get_nested_key(alert, ["perpetrator", "name"]),
        "PerpetratorUrl": get_nested_key(alert, ["perpetrator", "url"]),
        "PerpetratorTimeStamp": get_nested_key(
            alert, ["perpetrator", "timestamp"],
        ),
        "PerpetratorType": get_nested_key(alert, ["perpetrator", "type"]),
        "PerpetratorID": get_nested_key(alert, ["perpetrator", "id"]),
        "PerpetratorNetwork": get_nested_key(
            alert, ["perpetrator", "network"],
        ),
        "RuleGroupID": alert.get("rule_group_id"),
        "Status": alert.get("status"),
        "Timestamp": alert.get("timestamp"),
        "RuleName": alert.get("rule_name"),
        "LastModified": alert.get("last_modified"),
        "ProtectedLocations": alert.get("protected_locations"),
        "DarkwebTerm": alert.get("darkweb_term"),
        "Reviewed": alert.get("reviewed"),
        "Escalated": alert.get("escalated"),
        "Network": alert.get("network"),
        "ProtectedSocialObject": alert.get("protected_social_object"),
        "Notes": alert.get("notes"),
        "RuleID": alert.get("rule_id"),
        "EntityAccount": alert.get("entity_account"),
        "Tags": alert.get("tags"),
    }


def transform_alert_human_readable_values(
    alert: Dict,
    title_keys: List[str] = []
):
    transformed_alert = alert.copy()
    for key in title_keys:
        transformed_alert[key] = transformed_alert.get(key, "").title()
    return transformed_alert


def transform_alerts_human_readable_values(
    alerts: Union[Dict, List],
    title_keys: List[str] = []
):
    if isinstance(alerts, list):
        return [
            transform_alert_human_readable_values(
                alert,
                title_keys=title_keys,
            )
            for alert in alerts
        ]
    elif isinstance(alerts, dict):
        return transform_alert_human_readable_values(
            alerts,
            title_keys=title_keys,
        )


def transform_alert_human_readable_header(header: str):
    transformations = {
        "EntityName": "Protected Entity",
        "AlertType": "Content Type",
        "Timestamp": "Alert Date",
        "Network": "Source",
        "RuleName": "Rule",
        "RiskRating": "Risk Rating",
        "OffendingContentURL": "Offending Content",
    }
    return transformations.get(header, header)


def get_human_readable_alerts(alerts: Union[Dict, List]):
    visible_keys: List = [
        "ID",
        "EntityName",
        "AlertType",
        "Timestamp",
        "Status",
        "OffendingContentURL",
        "Network",
        "RuleName",
        "RiskRating",
        "Notes",
        "Tags",
    ]
    title_keys = ["AlertType", "RuleName", "Network", "EntityName"]
    transformed_alerts = transform_alerts_human_readable_values(
        alerts, title_keys=title_keys
    )
    readable_output: str = tableToMarkdown(
        "ZeroFox Alerts",
        transformed_alerts,
        headers=visible_keys,
        date_fields=["Timestamp"],
        headerTransform=transform_alert_human_readable_header,
        removeNull=True,
    )
    return readable_output


def remove_none_dict(input_dict: Dict) -> Dict:
    """
    removes all none values from a dict
    :param input_dict: any dictionary in the world is OK
    :return: same dictionary but without None values
    """
    return {
        key: value for key, value in input_dict.items()
        if value is not None
    }


def get_entity_contents(entity: Dict) -> Dict:
    """
    :param entity: Entity is a dictionary
    :return: A dict representation of the contents of entity
    """
    return {
        "ID": entity.get("id"),
        "Name": entity.get("name"),
        "EmailAddress": entity.get("email_address"),
        "Organization": entity.get("organization"),
        "Tags": entity.get("labels"),
        "StrictNameMatching": entity.get("strict_name_matching"),
        "PolicyID": entity.get("policy_id"),
        "Profile": entity.get("profile"),
        "EntityGroupID": get_nested_key(entity, ["entity_group", "id"]),
        "EntityGroupName": get_nested_key(entity, ["entity_group", "name"]),
        "TypeID": get_nested_key(entity, ["type", "id"]),
        "TypeName": get_nested_key(entity, ["type", "name"]),
    }


def get_entity_human_readable_outputs(contents: Dict) -> Dict:
    """
    returns the convention for the war room
    :param contents: Contents is a dictionary
    :return: A dict representation of the war room contents displayed to the user
    """
    return {
        "Name": contents.get("Name"),
        "Type": contents.get("TypeName"),
        "Policy": contents.get("PolicyID"),
        "Email": contents.get("EmailAddress"),
        "Tags": contents.get("Tags"),
        "ID": contents.get("ID"),
    }


def get_c2_domain_content(c2_domain_record: Dict):
    return {
        "Domain": c2_domain_record.get("domain", ""),
        "LastModified": c2_domain_record.get("created_at", ""),
        "IPs": ", ".join(c2_domain_record.get("ip_addresses", []))
    }


def get_phishing_content(phishing_record: Dict):
    return {
        "Domain": phishing_record.get("domain", ""),
        "LastModified": phishing_record.get("scanned", ""),
        "IPs": get_nested_key(phishing_record, ["host", "ip"], "")
    }


def get_compromised_domain_content(
    c2_domain_response: Dict,
    phishing_response: Dict
):
    compromised_domain_content = []

    c2_domains_results = c2_domain_response.get("results", [])
    compromised_domain_content += [
        get_c2_domain_content(record) for record in c2_domains_results
    ]

    phishing_results = phishing_response.get("results", [])
    compromised_domain_content += [
        get_phishing_content(record) for record in phishing_results
    ]

    return compromised_domain_content


def get_email_address_content(email_address_record: Dict):
    return {
        "Domain": email_address_record.get("domain", ""),
        "Email": email_address_record.get("email", ""),
        "CreatedAt": email_address_record.get("created_at", ""),
    }


def get_credentials_content(credentials_record: Dict):
    return {
        "Domain": credentials_record.get("domain", ""),
        "Email": credentials_record.get("email", ""),
        "CreatedAt": credentials_record.get("created_at", ""),
    }


def get_botnet_credentials_content(botnet_credentials_record: Dict):
    return {
        "Domain": botnet_credentials_record.get("domain", ""),
        "Email": botnet_credentials_record.get("email", ""),
        "CreatedAt": botnet_credentials_record.get("created_at", ""),
    }


def get_compromised_email_content(
    email_addressed_response: Dict,
    credentials_response: Dict,
    botnet_credentials_response: Dict,
):
    compromised_email_content = []

    email_addresses_results = email_addressed_response.get("results", [])
    compromised_email_content += [
        get_email_address_content(record)
        for record in email_addresses_results
    ]

    credentials_results = credentials_response.get("results", [])
    compromised_email_content += [
        get_credentials_content(record)
        for record in credentials_results
    ]

    botnet_credentials_results = botnet_credentials_response.get("results", [])
    compromised_email_content += [
        get_botnet_credentials_content(record)
        for record in botnet_credentials_results
    ]

    return compromised_email_content


def get_botnet_ip_content(botnet_result: Dict):
    return {
        "CreatedAt": botnet_result.get("acquired_at", ""),
        "IPAddress": botnet_result.get("ip_address", ""),
        "Domain": botnet_result.get("c2_domain", ""),
    }


def get_phishing_ip_content(botnet_result: Dict):
    return {
        "CreatedAt": botnet_result.get("scanned", ""),
        "IPAddress": get_nested_key(botnet_result, ["host", "ip"]),
        "Domain": botnet_result.get("domain", ""),
    }


def get_malicious_ip_content(botnet_response: Dict, phishing_response: Dict):
    malicious_ip_content = []

    botnet_results = botnet_response.get("results", [])
    malicious_ip_content += [
        get_botnet_ip_content(record)
        for record in botnet_results
    ]

    phishing_results = phishing_response.get("results", [])
    malicious_ip_content += [
        get_phishing_ip_content(record)
        for record in phishing_results
    ]

    return malicious_ip_content


def get_malicious_hash_type_content(
    malicious_hash_result: Dict,
    hash_type: str
):
    family_content = malicious_hash_result.get("family", [])
    if not family_content:
        family_content = []
    return {
        "CreatedAt": malicious_hash_result.get("created_at", ""),
        "Family": ", ".join(family_content),
        "MD5": malicious_hash_result.get("md5", ""),
        "SHA1": malicious_hash_result.get("sha1", ""),
        "SHA256": malicious_hash_result.get("sha256", ""),
        "SHA512": malicious_hash_result.get("sha512", ""),
        "FoundHash": hash_type,
    }


def get_malicious_hash_content(hash_type: str, malicious_hash_response: Dict):
    malicious_hash_content = []

    malicious_hash_results = malicious_hash_response.get("results", [])
    malicious_hash_content += [
        get_malicious_hash_type_content(record, hash_type)
        for record in malicious_hash_results
    ]

    return malicious_hash_content


def get_exploit_content(exploit_result: Dict):
    return {
        "CreatedAt": exploit_result.get("created_at", ""),
        "CVECode": exploit_result.get("cve", ""),
        "URLs": ", ".join(exploit_result.get("urls", [])),
    }


def get_exploits_content(exploits_response: Dict):
    exploits_content = []

    exploits_results = exploits_response.get("results", [])
    exploits_content += [
        get_exploit_content(record)
        for record in exploits_results
    ]

    return exploits_content


""" COMMANDS """


def test_module(client: ZFClient):
    """
    Performs basic get request to get item samples
    """
    client.get_policy_types()
    return "ok"


def fetch_incidents(
    client: ZFClient,
    last_run: Dict[str, str],
    first_fetch_time: str
):
    date_format = "%Y-%m-%dT%H:%M:%S"
    last_fetched = last_run.get("last_fetched")
    if last_fetched is None:
        last_fetched = first_fetch_time
    last_fetched = parse_date(last_fetched, date_formats=(date_format,))
    if last_fetched is None:
        raise ValueError("last_fetched param is invalid")

    response_content = client.list_alerts(
        {"sort_direction": "asc", "min_timestamp": last_fetched}
    )
    alerts: List = response_content.get("alerts", [])

    next_run = {"last_fetched": last_fetched.strftime(date_format)}
    incidents = []
    if alerts:
        integration_instance = demisto.integrationInstance()
        for alert in alerts:
            # Fields for mirroring alert
            alert["mirror_direction"] = "In"
            alert["mirror_instance"] = integration_instance

            incident = alert_to_incident(alert)
            incidents.append(incident)

        # max_update_time is the timestamp of the last alert in alerts
        # (alerts is a sorted list)
        last_alert_timestamp: str = str(alerts[-1].get("timestamp", ""))
        # add 1 second to last alert timestamp,
        # in order to prevent duplicated alerts
        parsed_last_alert_timestamp = parse_date(
            last_alert_timestamp,
            date_formats=(date_format,),
        )
        if parsed_last_alert_timestamp is None:
            raise ValueError("Incorrect timestamp in last alert of"
                             " fetch-incidents")
        max_update_time = (
            parsed_last_alert_timestamp + timedelta(seconds=1)
        ).strftime(date_format)
        next_run["last_fetched"] = max_update_time

    return next_run, incidents


def get_modified_remote_data_command(client: ZFClient, args: Dict):
    args = GetModifiedRemoteDataArgs(args)
    last_update = args.last_update

    # Get alerts created before `last_update` and modified after `last_update`
    list_alert_params = {
        "last_modified_min_date": str(last_update),
        "max_timestamp": str(last_update),
    }

    try:
        response_content = client.list_alerts(list_alert_params)
    except Exception as e:
        raise Exception(f"There was an error {e}, skip update")

    modified_alerts = response_content.get("alerts", [])
    demisto.debug(f"Fetched {len(modified_alerts)} alerts with "
                  f"the following params: {str(list_alert_params)}")
    modified_alert_ids = [str(alert.get("id")) for alert in modified_alerts]

    return GetModifiedRemoteDataResponse(
        modified_incident_ids=modified_alert_ids,
    )


def get_remote_data_command(client: ZFClient, args: Dict):
    args = GetRemoteDataArgs(args)
    alert_id = args.remote_incident_id

    response_content = client.get_alert(alert_id)
    alert = response_content.get("alert", {})
    demisto.debug(f"Alert fetched with id {alert.get('id')}")

    entries = []
    if alert.get("status") in CLOSED_ALERT_STATUS:
        demisto.debug("Incident associated with "
                      "alert_id={alert_id} is being closed")
        entries.append({
            "Contents": {
                "dbotIncidentClose": True,
                "closeReason": "Other",
                "closeNotes": "Closed in ZeroFox"
            },
        })

    return GetRemoteDataResponse(mirrored_object=alert, entries=entries)


def get_alert_command(client: ZFClient, args: Dict):
    alert_id: int = dict_value_to_integer(args, "alert_id")
    response_content: Dict = client.get_alert(alert_id)
    alert: Dict = response_content.get("alert", {})
    if not alert or not isinstance(alert, Dict):
        raise Exception(f"Alert with ID {alert_id} does not exist")
    output: Dict = get_alert_contents(alert)
    readable_output: str = get_human_readable_alerts(output)
    return CommandResults(
        outputs=output,
        outputs_prefix="ZeroFox.Alert",
        readable_output=readable_output,
    )


def alert_user_assignment_command(client: ZFClient, args: Dict):
    alert_id: int = dict_value_to_integer(args, "alert_id")
    username: str = args.get("username", "")
    client.alert_user_assignment(alert_id, username)
    response_content: Dict = client.get_alert(alert_id)
    alert = response_content.get("alert", {})
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output="Successful assignment "
                        f"of {username} to alert {alert_id}.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
    )


def close_alert_command(client: ZFClient, args: Dict):
    alert_id: int = dict_value_to_integer(args, "alert_id")
    client.close_alert(alert_id)
    response_content: Dict = client.get_alert(alert_id)
    alert = response_content.get("alert", {})
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output=f"Successfully closed Alert {alert_id}.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
    )


def open_alert_command(client: ZFClient, args: Dict):
    alert_id: int = dict_value_to_integer(args, "alert_id")
    client.open_alert(alert_id)
    response_content: Dict = client.get_alert(alert_id)
    alert = response_content.get("alert", {})
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output=f"Successfully opened Alert {alert_id}.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
    )


def alert_request_takedown_command(client: ZFClient, args: Dict):
    alert_id: int = dict_value_to_integer(args, "alert_id")
    client.alert_request_takedown(alert_id)
    response_content: Dict = client.get_alert(alert_id)
    alert = response_content.get("alert", {})
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output=f"Request to successfully take down Alert {alert_id}.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
    )


def alert_cancel_takedown_command(client: ZFClient, args: Dict):
    alert_id: int = dict_value_to_integer(args, "alert_id")
    client.alert_cancel_takedown(alert_id)
    response_content: Dict = client.get_alert(alert_id)
    alert = response_content.get("alert", {})
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output=f"Successful cancelled takedown of Alert {alert_id}.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
    )


def modify_alert_tags_command(client: ZFClient, args: Dict):
    alert_id: int = dict_value_to_integer(args, "alert_id")
    action_string: str = args.get("action", "")
    action: str = "added" if action_string == "add" else "removed"
    tags_list_string: str = args.get("tags", "")
    tags_list: list = argToList(tags_list_string, separator=",")
    response_content: Dict = client.modify_alert_tags(
        alert_id,
        action,
        tags_list,
    )
    if not response_content.get("changes"):
        raise Exception(f"Alert with ID {alert_id} does not exist")
    response_content: Dict = client.get_alert(alert_id)
    alert = response_content.get("alert", {})
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output="Successful modification of tags.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
    )


def create_entity_command(client: ZFClient, args: Dict):
    name: str = args.get("name", "")
    raw_strict_name_matching = args.get("strict_name_matching", "")
    strict_name_matching: bool = raw_strict_name_matching == "true"
    tags: str = args.get("tags", "")
    tags: List = argToList(tags, ",")
    policy_id: int = dict_value_to_integer(args, "policy_id")
    organization: str = args.get("organization", "")
    response_content: Dict = client.create_entity(
        name, strict_name_matching, tags, policy_id, organization,
    )
    entity_id: int = response_content.get("id", "")

    return CommandResults(
        readable_output=f"Successful creation of entity. ID: {entity_id}.",
        outputs={
            "ID": entity_id,
            "StrictNameMatching": strict_name_matching,
            "Name": name,
            "Tags": tags,
            "PolicyID": policy_id,
            "Organization": organization,
        },
        outputs_prefix="ZeroFox.Entity",
    )


def list_alerts_command(client: ZFClient, args: Dict):
    params: Dict = remove_none_dict(args)
    # handle all integer query params
    for key in [
        "entity",
        "entity_term",
        "last_modified",
        "offset",
        "page_id",
        "rule_id",
    ]:
        dict_value_to_integer(params, key)
    # handle severity/risk_rating parameter - special case
    risk_rating_string: str = params.get("risk_rating", "")
    if risk_rating_string:
        del params["risk_rating"]
        params["severity"] = severity_string_to_num(risk_rating_string)
    # handle limit parameter - special case
    limit_str = params.get("limit")
    if limit_str:
        limit: int = dict_value_to_integer(params, "limit")
        if limit < 0 or limit > 100:
            raise Exception("Incorrect limit. Limit should be 0 <= x <= 100.")
    response_content: Dict = client.list_alerts(params)
    if not response_content:
        return CommandResults(readable_output="No alerts found.", outputs=[])
    elif isinstance(response_content, Dict):
        alerts: List = response_content.get("alerts", [])
        if not alerts:
            return CommandResults(
                readable_output="No alerts found.",
                outputs=[],
                outputs_prefix="ZeroFox.Alert",
            )
        else:
            output: List = [get_alert_contents(alert) for alert in alerts]
            readable_output: str = get_human_readable_alerts(output)
            return CommandResults(
                outputs=output,
                readable_output=readable_output,
                outputs_prefix="ZeroFox.Alert",
            )
    else:
        return CommandResults(
            readable_output="No alerts found.",
            outputs=[],
            outputs_prefix="ZeroFox.Alert",
        )


def list_entities_command(client: ZFClient, args: Dict):
    params: Dict = remove_none_dict(args)
    # handle all integer query params
    for key in ["group", "label", "network", "page", "policy", "type"]:
        dict_value_to_integer(params, key)
    response_content: Dict = client.list_entities(params)
    if not response_content:
        return CommandResults(
            readable_output="No entities found.",
            outputs=[],
            outputs_prefix="ZeroFox.Entity",
        )
    elif isinstance(response_content, Dict):
        entities: List = response_content.get("entities", [])
        if not entities:
            return CommandResults(
                readable_output="No entities found.",
                outputs=entities,
                outputs_prefix="ZeroFox.Entity",
            )
        else:
            contents = [get_entity_contents(entity) for entity in entities]
            human_readable = [
                get_entity_human_readable_outputs(content)
                for content in contents
            ]
            headers: List = ["Name", "Type", "Policy", "Email", "Tags", "ID"]
            return CommandResults(
                readable_output=tableToMarkdown(
                    "ZeroFox Entities",
                    human_readable,
                    headers=headers,
                    removeNull=True,
                ),
                raw_response=response_content,
                outputs=contents,
                outputs_prefix="ZeroFox.Entity",
            )

    else:
        return CommandResults(
            readable_output="No entities found.",
            outputs=[],
            outputs_prefix="ZeroFox.Entities",
        )


def get_entity_types_command(client: ZFClient, args: Dict):
    response_content: Dict = client.get_entity_types()
    entity_types: List = response_content.get("results", [])
    human_readable = []
    for entity_type in entity_types:
        type_name: str = entity_type.get("name", "")
        type_id: int = entity_type.get("id", "")
        human_readable.append({"Name": type_name, "ID": type_id})
    headers = ["Name", "ID"]
    return CommandResults(
        outputs=entity_types,
        readable_output=tableToMarkdown(
            "ZeroFox Entity Types",
            human_readable,
            headers=headers,
            removeNull=True,
        ),
        outputs_prefix="ZeroFox.EntityTypes",
    )


def get_policy_types_command(client: ZFClient, args: Dict):
    response_content: Dict = client.get_policy_types()
    policy_types: List = response_content.get("policies", [])
    human_readable = []
    for policy_type in policy_types:
        type_name: str = policy_type.get("name", "")
        type_id: int = policy_type.get("id", "")
        human_readable.append({"Name": type_name, "ID": type_id})
    headers = ["Name", "ID"]

    return CommandResults(
        outputs=policy_types,
        readable_output=tableToMarkdown(
            "ZeroFox Policy Types",
            human_readable,
            headers=headers,
            removeNull=True,
        ),
        outputs_prefix="ZeroFox.PolicyTypes",
        raw_response=response_content,
    )


def modify_alert_notes_command(client: ZFClient, args: Dict):
    alert_id: int = dict_value_to_integer(args, "alert_id")
    alert_notes: str = args.get("notes", "")
    client.modify_alert_notes(alert_id, alert_notes)
    response_content: Dict = client.get_alert(alert_id)
    alert = response_content.get("alert", {})
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output="Successful note modification of alert "
                        f"with ID: {alert_id}",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
    )


def submit_threat_command(client: ZFClient, args: Dict):
    source: str = args.get("source", "")
    alert_type: str = args.get("alert_type", "")
    violation: str = args.get("violation", "")
    entity_id: str = args.get("entity_id", "")
    response_content: Dict = client.submit_threat(
        source,
        alert_type,
        violation,
        entity_id,
    )
    alert_id = response_content.get("alert_id")
    output = f"Successful submission of threat. ID: {alert_id}."
    return CommandResults(
        readable_output=output,
        raw_response=response_content,
        outputs={"ID": alert_id},
        outputs_prefix="ZeroFox.Alert",
    )


def compromised_domain_command(client: ZFClient, args: Dict):
    domain: str = args.get("domain", "")

    c2_domains_response = client.get_cti_c2_domains(domain)
    phishing_response = client.get_cti_phishing(domain=domain)
    outputs = get_compromised_domain_content(
        c2_domains_response,
        phishing_response,
    )

    if len(outputs) == 0:
        return CommandResults(
            readable_output="No compromised domains were found",
            outputs=outputs,
            outputs_prefix="ZeroFox.CompromisedDomains",
        )
    return CommandResults(
        readable_output=tableToMarkdown("Compromised domain Summary", outputs),
        outputs=outputs,
        outputs_prefix="ZeroFox.CompromisedDomains",
    )


def compromised_email_command(client: ZFClient, args: Dict):
    email: str = args.get("email", "")

    email_addresses_response = client.get_cti_email_addresses(email)
    credentials_response = client.get_cti_compromised_credentials(email)
    botnet_credentials_response = client\
        .get_cti_botnet_compromised_credentials(email)

    outputs = get_compromised_email_content(
        email_addresses_response,
        credentials_response,
        botnet_credentials_response,
    )

    if len(outputs) == 0:
        return CommandResults(
            outputs=outputs,
            readable_output="No compromised emails were found",
            outputs_prefix="ZeroFox.CompromisedEmails",
        )
    return CommandResults(
        outputs=outputs,
        readable_output=tableToMarkdown(
            "Compromised email Summary",
            outputs,
        ),
        outputs_prefix="ZeroFox.CompromisedEmails",
    )


def malicious_ip_command(client: ZFClient, args: Dict):
    ip: str = args.get("ip", "")

    botnet_response = client.get_cti_botnet(ip)
    phishing_response = client.get_cti_phishing(ip=ip)

    outputs = get_malicious_ip_content(
        botnet_response,
        phishing_response,
    )

    if len(outputs) == 0:
        return CommandResults(
            readable_output="No malicious ips were found",
            outputs=outputs,
            outputs_prefix="ZeroFox.MaliciousIPs",
        )
    return CommandResults(
        outputs=outputs,
        readable_output=tableToMarkdown("Malicious ip Summary", outputs),
        outputs_prefix="ZeroFox.MaliciousIPs",
    )


def malicious_hash_command(client: ZFClient, args: Dict):
    hash: str = args.get("hash", "")

    outputs = []
    for hash_type in ["md5", "sha1", "sha256", "sha512"]:
        hash_type_response = client.get_cti_malware(hash_type, hash)
        outputs += get_malicious_hash_content(hash_type, hash_type_response)

    if len(outputs) == 0:
        return CommandResults(
            readable_output="No malicious hashes were found",
            outputs=outputs,
            outputs_prefix="ZeroFox.MaliciousHashes",
        )
    return CommandResults(
        outputs=outputs,
        readable_output=tableToMarkdown("Malicious hash Summary", outputs),
        outputs_prefix="ZeroFox.MaliciousHashes",
    )


def search_exploits_command(client: ZFClient, args: Dict):
    since: str = args.get("since", "")

    exploits_response = client.get_cti_exploits(since)

    outputs = get_exploits_content(exploits_response)

    if len(outputs) == 0:
        return CommandResults(
            outputs=outputs,
            readable_output="No exploits were found",
            outputs_prefix="ZeroFox.Exploits",
        )
    return CommandResults(
        outputs=outputs,
        readable_output=tableToMarkdown("Exploit Search Summary", outputs),
        outputs_prefix="ZeroFox.Exploits",
    )


""" COMMANDS MANAGER / SWITCH PANEL """


def main():
    USERNAME: str = demisto.params().get("credentials", {}).get("identifier")
    PASSWORD: str = demisto.params().get("credentials", {}).get("password")
    BASE_URL: str = (
        demisto.params()["url"][:-1]
        if demisto.params()["url"].endswith("/")
        else demisto.params()["url"]
    )
    FETCH_TIME: str = demisto.params().get(
        "fetch_time", FETCH_TIME_DEFAULT,
    ).strip()
    FETCH_LIMIT: int = int(demisto.params().get("fetch_limit", "100"))

    commands = {
        "get-modified-remote-data": get_modified_remote_data_command,
        "get-remote-data": get_remote_data_command,
        "zerofox-get-alert": get_alert_command,
        "zerofox-alert-user-assignment": alert_user_assignment_command,
        "zerofox-close-alert": close_alert_command,
        "zerofox-open-alert": open_alert_command,
        "zerofox-alert-request-takedown": alert_request_takedown_command,
        "zerofox-alert-cancel-takedown": alert_cancel_takedown_command,
        "zerofox-modify-alert-tags": modify_alert_tags_command,
        "zerofox-create-entity": create_entity_command,
        "zerofox-list-alerts": list_alerts_command,
        "zerofox-list-entities": list_entities_command,
        "zerofox-get-entity-types": get_entity_types_command,
        "zerofox-get-policy-types": get_policy_types_command,
        "zerofox-modify-alert-notes": modify_alert_notes_command,
        "zerofox-submit-threat": submit_threat_command,
        "zerofox-search-compromised-domain": compromised_domain_command,
        "zerofox-search-compromised-email": compromised_email_command,
        "zerofox-search-malicious-ip": malicious_ip_command,
        "zerofox-search-malicious-hash": malicious_hash_command,
        "zerofox-search-exploits": search_exploits_command,
    }
    try:
        client = ZFClient(
            base_url=BASE_URL,
            ok_codes={200, 201},
            username=USERNAME,
            password=PASSWORD,
            fetch_limit=FETCH_LIMIT,
        )

        handle_proxy()
        command = demisto.command()

        if command == 'test-module':
            results = test_module(client)
            return_results(results)
        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client,
                last_run=demisto.getLastRun(),
                first_fetch_time=FETCH_TIME,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        else:
            command_handler = commands[command]
            results = command_handler(client, demisto.args())
            return_results(results)

    # Log exceptions
    except Exception as e:
        error_msg: str = str(e)
        if demisto.command() == "fetch-incidents":
            LOG(error_msg)
            LOG.print_log()
            raise
        else:
            return_error(error_msg)


if __name__ == "builtins":
    main()

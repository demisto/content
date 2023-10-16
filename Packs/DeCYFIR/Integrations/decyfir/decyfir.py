import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Any

''' IMPORTS '''

import urllib3
import json
import dateparser

# Disable insecure warnings
# requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

MAX_INCIDENTS_TO_FETCH = 500
DEFAULT_INDICATORS_THRESHOLD = 65

API_PATH_SUFFIX: str = '/core/api-ua/v2/alerts'

LABEL_DECYFIR = "DeCYFIR"
LABEL_ATTACK_SURFACE = "Attack Surface"
LABEL_DIGITAL_RISK = "Digital Risk"
LABEL_DIGITAL_RISK_IM_IN = "Impersonation & Infringement"
LABEL_DIGITAL_RISK_DB_WM = "Data Breach & Web Monitoring"
LABEL_DIGITAL_RISK_S_PE = "Social & Public Exposure"

LABEL_OPEN_PORTS = "Open Ports"
LABEL_IP_VULNERABILITY = "IP Vulnerability"
LABEL_CONFIGURATION = "Configuration"
LABEL_CLOUD_WEAKNESS = "Cloud Weakness"
LABEL_IP_REPUTATION = "IP Reputation"
LABEL_CERTIFICATES = "Certificates"

LABEL_DOMAIN_IT_ASSET = "Domain IT Asset"
LABEL_EXECUTIVE_PEOPLE = "Executive People"
LABEL_PRODUCT_SOLUTION = "Product Solution"
LABEL_SOCIAL_HANDLERS = "Social Handlers"

LABEL_PHISHING = "Phishing"
LABEL_RANSOMWARE = "Ransomware"
LABEL_DARK_WEB = "Dark web"

LABEL_SOURCE_CODE = "Source Code"
LABEL_MALICIOUS_MOBILE_APPS = "Malicious Mobile Apps"
LABEL_CONFIDENTIAL_FILES = "Confidential Files"
LABEL_DUMPS_PII_CII = "Dumps PII-CII"
LABEL_SOCIAL_THREAT = "Social Threat"

LABELS_LIST: list = [LABEL_OPEN_PORTS, LABEL_IP_VULNERABILITY, LABEL_CONFIGURATION, LABEL_CLOUD_WEAKNESS,
                     LABEL_IP_REPUTATION, LABEL_CERTIFICATES,
                     LABEL_DOMAIN_IT_ASSET, LABEL_EXECUTIVE_PEOPLE, LABEL_PRODUCT_SOLUTION, LABEL_SOCIAL_HANDLERS,
                     LABEL_PHISHING, LABEL_RANSOMWARE, LABEL_DARK_WEB,
                     LABEL_SOURCE_CODE, LABEL_MALICIOUS_MOBILE_APPS, LABEL_CONFIDENTIAL_FILES, LABEL_DUMPS_PII_CII,
                     LABEL_SOCIAL_THREAT]

VAR_ATTACK_SURFACE = "attack-surface"
VAR_IMPERSONATION_AND_INFRINGEMENT = "impersonation-and-infringement"
VAR_DATA_BREACH_AND_WEB_MONITORING = "data-breach-and-web-monitoring"
VAR_SOCIAL_AND_PUBLIC_EXPOSURE = "social-and-public-exposure"

# ATTACK SURFACE
VAR_OPEN_PORTS = "open-ports"
VAR_IP_VULNERABILITY = "ip-vulnerability"
VAR_CONFIGURATION = "configuration"
VAR_CLOUD_WEAKNESS = "cloud-weakness"
VAR_IP_REPUTATION = "ip-reputation"
VAR_CERTIFICATES = "certificates"

VAR_ATTACK_SURFACES_SUB_TYPES: list = [VAR_OPEN_PORTS, VAR_IP_VULNERABILITY, VAR_CONFIGURATION, VAR_CLOUD_WEAKNESS,
                                       VAR_IP_REPUTATION, VAR_CERTIFICATES]

# IMPERSONATION & INFRINGEMENT
VAR_DOMAIN_IT_ASSET = "domain-it-asset"
VAR_EXECUTIVE_PEOPLE = "executive-people"
VAR_PRODUCT_SOLUTION = "product-solution"
VAR_SOCIAL_HANDLERS = "social-handlers"

VAR_IMPERSONATION_AND_INFRINGEMENT_SUB_TYPE: list = [VAR_DOMAIN_IT_ASSET, VAR_EXECUTIVE_PEOPLE, VAR_PRODUCT_SOLUTION,
                                                     VAR_SOCIAL_HANDLERS]

# DATA BREACH AND WEB MONITORING
VAR_PHISHING = "phishing"
VAR_RANSOMWARE = "ransomware"
VAR_DARK_WEB = "dark-web"

VAR_DATA_BREACH_AND_WEB_MONITORING_SUB_TYPES: list = [VAR_PHISHING, VAR_RANSOMWARE, VAR_DARK_WEB]

# SOCIAL AND PUBLIC EXPOSURE
VAR_SOURCE_CODE = "source-code"
VAR_MALICIOUS_MOBILE_APPS = "malicious-mobile-apps"
VAR_CONFIDENTIAL_FILES = "confidential-files"
VAR_DUMPS_PII_CII = "dumps-pii-cii"
VAR_SOCIAL_THREAT = "social-threat"

VAR_SOCIAL_AND_PUBLIC_EXPOSURE_SUB_TYPES: list = [VAR_SOURCE_CODE, VAR_MALICIOUS_MOBILE_APPS, VAR_CONFIDENTIAL_FILES,
                                                  VAR_DUMPS_PII_CII, VAR_SOCIAL_THREAT]


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_severity(self, risk_score: int):
        if risk_score > 8:
            return IncidentSeverity.CRITICAL
        elif risk_score > 5:
            return IncidentSeverity.HIGH
        elif risk_score >= 3:
            return IncidentSeverity.MEDIUM
        elif risk_score >= 1:
            return IncidentSeverity.LOW
        else:
            return IncidentSeverity.UNKNOWN

    def request_decyfir_api(self, category, category_type, api_param_query) -> list[dict]:
        response = self._http_request(
            url_suffix=f"{API_PATH_SUFFIX}" + f"/{category}?" + f"type={category_type}" + api_param_query,
            resp_type='response',
            method='GET')

        if response.status_code == 200 and response.content:
            return response.json()

        return []

    def get_decyfir_data(self, after_val: int, decyfir_api_key: str, incident_type: str, max_fetch):

        size = max_fetch if max_fetch else MAX_INCIDENTS_TO_FETCH

        api_param_query = "&" + f"key={decyfir_api_key}&" + f"size={size}&" + f"after={after_val}"

        return_data = {}
        incident_types = []
        if incident_type:
            incident_types.append(incident_type)
        else:
            incident_types.append(LABEL_ATTACK_SURFACE)
            incident_types.append(LABEL_DIGITAL_RISK_IM_IN)
            incident_types.append(LABEL_DIGITAL_RISK_S_PE)
            incident_types.append(LABEL_DIGITAL_RISK_DB_WM)

        if incident_types:
            for type_ in incident_types:
                if type_ == LABEL_ATTACK_SURFACE:
                    for cat_type in VAR_ATTACK_SURFACES_SUB_TYPES:
                        return_data[cat_type] = self.request_decyfir_api(VAR_ATTACK_SURFACE, cat_type, api_param_query)

                if type_ == LABEL_DIGITAL_RISK_IM_IN:
                    for cat_type in VAR_IMPERSONATION_AND_INFRINGEMENT_SUB_TYPE:
                        return_data[cat_type] = self.request_decyfir_api(VAR_IMPERSONATION_AND_INFRINGEMENT, cat_type,
                                                                         api_param_query)

                if type_ == LABEL_DIGITAL_RISK_DB_WM:
                    for cat_type in VAR_DATA_BREACH_AND_WEB_MONITORING_SUB_TYPES:
                        return_data[cat_type] = self.request_decyfir_api(VAR_DATA_BREACH_AND_WEB_MONITORING, cat_type,
                                                                         api_param_query)

                if type_ == LABEL_DIGITAL_RISK_S_PE:
                    for cat_type in VAR_SOCIAL_AND_PUBLIC_EXPOSURE_SUB_TYPES:
                        return_data[cat_type] = self.request_decyfir_api(VAR_SOCIAL_AND_PUBLIC_EXPOSURE, cat_type,
                                                                         api_param_query)

        return return_data

    def prepare_incident_json(self, alert_type: str, alert_subtype: str, name: str, date_val: str,
                              severity: int, details: dict, record_id: str) -> dict[str, Any]:

        occurred_date = dateparser.parse(date_val)
        occurred = occurred_date.strftime(DATE_FORMAT) if isinstance(occurred_date, datetime) else None

        decyfir_data_details = []

        for key, value in details.items():
            if key != 'uid' and value is not None and value != 'null':
                key = str(key).replace("_", " ").capitalize()
                decyfir_data_details.append({"fields": key, "values": value})

        return_data = {
            "type": f"{alert_type}",
            "name": name,
            "occurred": occurred,
            "severity": severity,
            "rawJSON": str(json.dumps(details)),
            "category": alert_type,
            "subcategory": alert_subtype,
            "dbotMirrorId": record_id,
            "sourceBrand": LABEL_DECYFIR,
            "labels": [
                {
                    "type": "Description",
                    "value": details.get('description')
                }
            ],
            "customFields": {
                "decyfirdatadetails": decyfir_data_details
            }
        }

        return return_data

    def prepare_incidents_for_attack_surface(self, json_data, alert_type: str, alert_subtype: str) -> list[dict]:
        try:
            incidents_json = []
            for json_ in json_data:
                severity = self.get_severity(json_.get("risk_score"))
                ip = json_.get("ip")
                details = dict(json_)
                date_val = json_.get("alert_created_date")
                uid = json_.get("uid")

                domain: str = ""
                if json_.get("sub_domain"):
                    domain = json_.get("sub_domain")
                domain = domain + ", " + json_.get("top_domain") if domain else json_.get("top_domain")

                name = f"DOMAIN : {domain}" if domain else ""

                if ip:
                    name = name + f"\n IP: {ip}" if name else f"IP: {ip}"

                if not name:
                    name = "Asset: {}".format(json_.get("asset_name")) if json_.get("asset_name") else ""

                incident_json = self.prepare_incident_json(alert_type, alert_subtype,
                                                           name, date_val, severity, details, uid)
                incidents_json.append(incident_json)

            return incidents_json
        except Exception as e:
            raise DemistoException(str(e))

    def prepare_incidents_for_digital_risk(self, json_data, alert_type: str, alert_subtype: str) -> list:
        try:
            incidents_json = []
            for json_ in json_data:
                severity = self.get_severity(json_.get("risk_score"))
                date_val = json_.get("alert_created_date")
                details = dict(json_)
                name: str = json_.get("title")
                uid = json_.get("uid")

                incident_json = self.prepare_incident_json(alert_type, alert_subtype,
                                                           name, date_val, severity, details, uid)
                incidents_json.append(incident_json)

            return incidents_json
        except Exception as e:
            raise DemistoException(str(e))

    def convert_decyfir_data_to_incidents_format(self, decyfir_alerts_incidents):
        try:
            return_data: list[dict] = []

            # Attack Surface
            # Open Ports
            if json_data := decyfir_alerts_incidents.get(VAR_OPEN_PORTS):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_OPEN_PORTS)
                return_data = return_data + incidents_json_data

            # IP Vulnerability
            if json_data := decyfir_alerts_incidents.get(VAR_IP_VULNERABILITY):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_IP_VULNERABILITY)
                return_data = return_data + incidents_json_data

            # "Configuration"
            if json_data := decyfir_alerts_incidents.get(VAR_CONFIGURATION):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_CONFIGURATION)
                return_data = return_data + incidents_json_data

            # Cloud Weakness
            if json_data := decyfir_alerts_incidents.get(VAR_CLOUD_WEAKNESS):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_CLOUD_WEAKNESS)
                return_data = return_data + incidents_json_data

            # IP Reputation
            if json_data := decyfir_alerts_incidents.get(VAR_IP_REPUTATION):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_IP_REPUTATION)
                return_data = return_data + incidents_json_data

            # Certificates
            if json_data := decyfir_alerts_incidents.get(VAR_CERTIFICATES):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_CERTIFICATES)
                return_data = return_data + incidents_json_data

            # Digital Risk
            # impersonation & infringement
            if json_data := decyfir_alerts_incidents.get(VAR_DOMAIN_IT_ASSET):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_IM_IN,
                                                                              LABEL_DOMAIN_IT_ASSET)
                return_data = return_data + incidents_json_data

            # Executive People
            if json_data := decyfir_alerts_incidents.get(VAR_EXECUTIVE_PEOPLE):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_IM_IN,
                                                                              LABEL_EXECUTIVE_PEOPLE)
                return_data = return_data + incidents_json_data

            # Product Solution
            if json_data := decyfir_alerts_incidents.get(VAR_PRODUCT_SOLUTION):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_IM_IN,
                                                                              LABEL_PRODUCT_SOLUTION)
                return_data = return_data + incidents_json_data

            # Social Handlers
            if json_data := decyfir_alerts_incidents.get(VAR_SOCIAL_HANDLERS):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_IM_IN,
                                                                              LABEL_SOCIAL_HANDLERS)
                return_data = return_data + incidents_json_data

            # PHISHING
            if json_data := decyfir_alerts_incidents.get(VAR_PHISHING):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_DB_WM,
                                                                              LABEL_PHISHING)
                return_data = return_data + incidents_json_data

            # ransomware
            if json_data := decyfir_alerts_incidents.get(VAR_RANSOMWARE):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_DB_WM,
                                                                              LABEL_RANSOMWARE)
                return_data = return_data + incidents_json_data

                # Dark web
            if json_data := decyfir_alerts_incidents.get(VAR_DARK_WEB):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_DB_WM,
                                                                              LABEL_DARK_WEB)
                return_data = return_data + incidents_json_data

            # Source Code
            if json_data := decyfir_alerts_incidents.get(VAR_SOURCE_CODE):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_S_PE,
                                                                              LABEL_SOURCE_CODE)
                return_data = return_data + incidents_json_data

            # malicious-mobile-apps
            if json_data := decyfir_alerts_incidents.get(VAR_MALICIOUS_MOBILE_APPS):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_S_PE,
                                                                              LABEL_MALICIOUS_MOBILE_APPS)
                return_data = return_data + incidents_json_data

            # confidential-files
            if json_data := decyfir_alerts_incidents.get(VAR_CONFIDENTIAL_FILES):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_S_PE,
                                                                              LABEL_CONFIDENTIAL_FILES)
                return_data = return_data + incidents_json_data

            # dumps-pii-cii
            if json_data := decyfir_alerts_incidents.get(VAR_DUMPS_PII_CII):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_S_PE,
                                                                              LABEL_DUMPS_PII_CII)
                return_data = return_data + incidents_json_data

            return return_data
        except Exception as e:
            raise DemistoException(str(e))


# commands
# This is the call made when pressing the integration Test button.
def test_module(client, decyfir_api_key):  # pragma: no cover
    url = f"{API_PATH_SUFFIX}" + f"/{VAR_ATTACK_SURFACE}?" + f"type={VAR_OPEN_PORTS}" \
          + "&size=1" + "&key=" + f"{decyfir_api_key}"

    response = client._http_request(url_suffix=url, method='GET', resp_type='response')

    if response.status_code == 200:
        return 'ok'
    elif response.status_code == 401 or response.status_code == 403:
        return 'Not Authorized'
    else:
        return f"Error_code: {response.status_code}, Please contact the DeCYFIR team to assist you further on this."


def fetch_incidents(client, last_run, first_fetch, decyfir_api_key, incident_type, max_fetch):
    try:
        start_fetch = dateparser.parse(last_run.get("last_fetch")) if last_run else dateparser.parse(first_fetch)
        start_fetch_timestamp_val: float = start_fetch.timestamp() if isinstance(start_fetch, datetime) else 0.0

        start_fetch_timestamp: int = int(start_fetch_timestamp_val * 1000)

        # To get the DeCYFIR data in JSON format
        json_decyfir_data = client.get_decyfir_data(after_val=start_fetch_timestamp,
                                                    decyfir_api_key=decyfir_api_key,
                                                    incident_type=incident_type, max_fetch=max_fetch)

        decyfir_incidents = client.convert_decyfir_data_to_incidents_format(json_decyfir_data)

        # Assigning the current date time value to last_fetch for next run
        last_fetch_time = datetime.now().strftime(DATE_FORMAT)
        last_fetch = {"last_fetch": last_fetch_time}

        return last_fetch, decyfir_incidents
    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e


def main():  # pragma: no cover

    params = demisto.params()
    decyfir_url = params['url'].rstrip('/')
    decyfir_api_key = params.get('api_key').get("password")
    incident_type: str = params.get('incidentType')
    max_fetch: str = params.get('max_fetch')
    verify_certificate = not params.get('insecure', False)
    # How much time before the first fetch to retrieve incidents
    first_fetch = params.get('first_fetch', '30 days').strip()
    proxy = params.get('proxy', False)

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=decyfir_url,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client, decyfir_api_key)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch=first_fetch,
                decyfir_api_key=decyfir_api_key,
                incident_type=incident_type,
                max_fetch=max_fetch
            )
            # Pushing Incidents data to XSOAR
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError('DeCYFIR error: ' + f'command {demisto.command()} is not implemented')

    # Log exceptions
    except Exception as e:
        err = f'Failed to execute {demisto.command()} command. DeCYFIR error: {str(e)}'
        return_error(err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

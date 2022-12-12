import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Any, Dict, List

''' IMPORTS '''

import urllib3
import json
import requests
import dateparser

# Disable insecure warnings
# requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

MAX_INCIDENTS_TO_FETCH = 500
DEFAULT_INDICATORS_THRESHOLD = 65

QA_API_PATH: str = 'https://qadecyfir.cyfirma.com/core/api-ua/v2/alerts'
PROD_API_PATH: str = 'https://decyfir.cyfirma.com/core/api-ua/v2/alerts'

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

    def say_hello(self, name):
        return f'Hello {name}'

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

    def request_decyfir_api(self, endpoint) -> str:
        response = requests.get(f"{endpoint}")
        if response.status_code == 200:
            if len(response.text) > 0:
                return json.dumps(response.json())
        else:
            print(f"Error: =>  {response.status_code} error with API request")
            return ""

    def get_decyfir_data(self, after_val: int, is_first_fetch: bool, org_api_key: str, incident_type: str) -> str:
        endpoint_env = f"{QA_API_PATH}"

        size: int = MAX_INCIDENTS_TO_FETCH
        if is_first_fetch:
            size = 1000

        api_query = "&" + f"key={org_api_key}&" + f"size={size}&" + f"after={after_val}"

        return_data: json = {}
        for cat_type in VAR_ATTACK_SURFACES_SUB_TYPES:
            endpoint = f"{endpoint_env}" + f"/{VAR_ATTACK_SURFACE}?" + f"type={cat_type}" + api_query
            data = self.request_decyfir_api(endpoint)
            return_data[cat_type] = data

        for cat_type in VAR_IMPERSONATION_AND_INFRINGEMENT_SUB_TYPE:
            endpoint = f"{endpoint_env}" + f"/{VAR_IMPERSONATION_AND_INFRINGEMENT}?" + f"type={cat_type}" + api_query
            data = self.request_decyfir_api(endpoint)
            return_data[cat_type] = data

        for cat_type in VAR_DATA_BREACH_AND_WEB_MONITORING_SUB_TYPES:
            endpoint = f"{endpoint_env}" + f"/{VAR_DATA_BREACH_AND_WEB_MONITORING}?" + f"type={cat_type}" + api_query
            data = self.request_decyfir_api(endpoint)
            return_data[cat_type] = data

        for cat_type in VAR_SOCIAL_AND_PUBLIC_EXPOSURE_SUB_TYPES:
            endpoint = f"{endpoint_env}" + f"/{VAR_SOCIAL_AND_PUBLIC_EXPOSURE}?" + f"type={cat_type}" + api_query
            data = self.request_decyfir_api(endpoint)
            return_data[cat_type] = data

        return json.dumps(return_data)

    def prepare_incident_json(self, source_brand: str, alert_type: str, alert_subtype: str, name: str, date_val: str,
                              severity: int, details: str, record_id: str) -> Dict[str, Any]:

        incident_owner = "Administrator"
        return_data = {
            "type": "" + f"{alert_type}",
            "name": name,
            "occurred": dateparser.parse(date_val).strftime(DATE_FORMAT),
            "owner": incident_owner,
            "severity": severity,
            "details": details,
            "rawJSON": details,
            "decyfirsubcategory": alert_subtype,
            "decyfircategory": alert_type,
            "category": alert_type,
            "dbotMirrorId": record_id,
            "sourceBrand": LABEL_DECYFIR,
            "labels": [
                {
                    "type": "decyfircategory",
                    "value": alert_type
                },
                {
                    "type": "decyfirsubcategory",
                    "value": alert_subtype
                },
                {
                    "type": "incident_source_from",
                    "value": source_brand
                }
            ]
        }

        return return_data

    def prepare_incidents_for_attack_surface(self, json_data, alert_type: str, alert_subtype: str) -> List:
        try:
            incidents_json = []
            for json_ in json.loads(json_data):
                severity = self.get_severity(json_.get("risk_score"))
                ip = json_.get("ip")
                details = str(json.dumps(json_))
                date_val = json_.get("alert_created_date")
                uid = json_.get("uid")

                domain: str = ""
                if json_.get("sub_domain"):
                    domain = json_.get("sub_domain")
                if json_.get("top_domain"):
                    if domain.__eq__("") or domain == "":
                        domain = json_.get("top_domain")
                    else:
                        domain = domain + ", " + json_.get("top_domain")

                name = "DOMAIN : {}".format(domain) if domain else ""

                if ip:
                    name = name + "\n IP: {}".format(ip) if name else "IP: {}".format(ip)


                incident_json = self.prepare_incident_json(LABEL_DECYFIR, alert_type, alert_subtype,
                                                           name, date_val, severity, details, uid)
                incidents_json.append(incident_json)

            return incidents_json

        except Exception as e:
            print("Exception when calling prepare_incidents_for_attack_surface=> : %s\n" % e)
            return_error(str(e))

    def prepare_incidents_for_digital_risk(self, json_data, alert_type: str, alert_subtype: str) -> List:
        try:
            incidents_json = []
            for json_ in json.loads(json_data):
                severity = self.get_severity(json_.get("risk_score"))
                date_val = json_.get("alert_created_date")
                details = str(json.dumps(json_))
                name: str = json_.get("title")
                uid = json_.get("uid")

                incident_json = self.prepare_incident_json(LABEL_DECYFIR, alert_type, alert_subtype,
                                                           name, date_val, severity, details, uid)
                incidents_json.append(incident_json)

            return incidents_json
        except Exception as e:
            print("Exception when calling prepare_incidents_for_digital_risk=> : %s\n" % e)
            return_error(str(e))

    def convert_decyfir_data_to_incidents_format(self, decyfir_alerts_incidents: json):
        try:
            json_val = json.loads(decyfir_alerts_incidents)
            return_data = []

            # Attack Surface
            # Open Ports
            if json_data := json_val.get(VAR_OPEN_PORTS):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_OPEN_PORTS)
                return_data = return_data + incidents_json_data

            # IP Vulnerability
            if json_data := json_val.get(VAR_IP_VULNERABILITY):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_IP_VULNERABILITY)
                return_data = return_data + incidents_json_data

            # "Configuration"
            if json_data := json_val.get(VAR_CONFIGURATION):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_CONFIGURATION)
                return_data = return_data + incidents_json_data

            # Cloud Weakness
            if json_data := json_val.get(VAR_CLOUD_WEAKNESS):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_CLOUD_WEAKNESS)
                return_data = return_data + incidents_json_data

            # IP Reputation
            if json_data := json_val.get(VAR_IP_REPUTATION):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_IP_REPUTATION)
                return_data = return_data + incidents_json_data

            # Certificates
            if json_data:= json_val.get(VAR_CERTIFICATES):
                incidents_json_data = self.prepare_incidents_for_attack_surface(json_data, LABEL_ATTACK_SURFACE,
                                                                                LABEL_CERTIFICATES)
                return_data = return_data + incidents_json_data

            # Digital Risk
            # impersonation & infringement
            if json_data := json_val.get(VAR_DOMAIN_IT_ASSET):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_IM_IN,
                                                                              LABEL_DOMAIN_IT_ASSET)
                return_data = return_data + incidents_json_data

            # Executive People
            if json_data := json_val.get(VAR_EXECUTIVE_PEOPLE):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_IM_IN,
                                                                              LABEL_EXECUTIVE_PEOPLE)
                return_data = return_data + incidents_json_data

            # Product Solution
            if json_data := json_val.get(VAR_PRODUCT_SOLUTION):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_IM_IN,
                                                                              LABEL_PRODUCT_SOLUTION)
                return_data = return_data + incidents_json_data

            # Social Handlers
            if json_data := json_val.get(VAR_SOCIAL_HANDLERS):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_IM_IN,
                                                                              LABEL_SOCIAL_HANDLERS)
                return_data = return_data + incidents_json_data

            # PHISHING
            if json_data := json_val.get(VAR_PHISHING):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_DB_WM,
                                                                              LABEL_PHISHING)
                return_data = return_data + incidents_json_data

            # ransomware
            if json_data := json_val.get(VAR_RANSOMWARE):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_DB_WM,
                                                                              LABEL_RANSOMWARE)
                return_data = return_data + incidents_json_data

                # Dark web
            if json_data := json_val.get(VAR_DARK_WEB):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_DB_WM,
                                                                              LABEL_DARK_WEB)
                return_data = return_data + incidents_json_data

            # Source Code
            if json_data := json_val.get(VAR_SOURCE_CODE):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_S_PE,
                                                                              LABEL_SOURCE_CODE)
                return_data = return_data + incidents_json_data

            # malicious-mobile-apps
            if json_data := json_val.get(VAR_MALICIOUS_MOBILE_APPS):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_S_PE,
                                                                              LABEL_MALICIOUS_MOBILE_APPS)
                return_data = return_data + incidents_json_data

            # confidential-files
            if json_data := json_val.get(VAR_CONFIDENTIAL_FILES):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_S_PE,
                                                                              LABEL_CONFIDENTIAL_FILES)
                return_data = return_data + incidents_json_data

            # dumps-pii-cii
            if json_data := json_val.get(VAR_DUMPS_PII_CII):
                incidents_json_data = self.prepare_incidents_for_digital_risk(json_data, LABEL_DIGITAL_RISK_S_PE,
                                                                              LABEL_DUMPS_PII_CII)
                return_data = return_data + incidents_json_data

            return return_data
        except Exception as e:
            demisto.error(traceback.format_exc())
            print("Exception when calling convert_decyfir_data_to_incidents_format => : %s\n" % e)
            return_error(str(e))


# commands
# This is the call made when pressing the integration Test button.
def test_module(client):
    result = client.say_hello('DBot')
    if 'Hello DBot' == result:
        return 'ok'
    else:
        return 'Test failed because ......'


def fetch_incidents(client, last_run, first_fetch_time):
    try:
        org_api_key: str = demisto.params().get('decyfir_api_key')
        # incident_type: str = demisto.params().get('incidentType')
        is_first_fetch = True

        fetch_from = dateparser.parse(last_run.get("last_fetch")) if last_run else dateparser.parse(first_fetch_time)

        after_val: int = int(fetch_from.timestamp() * 1000)

        # To get the DeCYFIR data in JSON format
        json_decyfir_data = client.get_decyfir_data(after_val=after_val, is_first_fetch=is_first_fetch,
                                                    org_api_key=org_api_key, incident_type=None)

        decyfir_incidents = client.convert_decyfir_data_to_incidents_format(json_decyfir_data)

        # Pushing Incidents data to XSOAR
        demisto.incidents(decyfir_incidents)

        # Assigning the current date time value to last_fetch for next run
        fetch_time = datetime.now().strftime(DATE_FORMAT)
        fetch_timings_data = {"last_fetch": fetch_time}

        return fetch_timings_data
    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            print("Exception when calling command=> fetch_incidents: {}".format(e))
            raise e


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1/suffix')

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('first_fetch_time', '30 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            next_run = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)
            demisto.setLastRun(next_run)
        else:
            raise NotImplementedError(f'DeCYFIR error: '
                                      f'command {command} is not implemented')

    # Log exceptions
    except Exception as e:
        err = f'Failed to execute {demisto.command()} command. Error: {str(e)}'
        return_error(err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

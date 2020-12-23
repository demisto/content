import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

# type: ignore
# flake8: noqa
# mypy: ignore-errors


# Imports

from enum import Enum

from typing import Dict


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

headers = {}
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class MitigationsState(Enum):
    open = "open"
    archive = "archive"
    all = "all"


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def api_test(self):
        """
        Sends a test api call to the management server.
        """
        results = self._http_request(
            method='GET',
            url_suffix='test'
        )

        return results

    def get_mitigations(self, timeout=60, mitigations_state=MitigationsState.open.value):
        data = {mitigations_state: mitigations_state.lower()}

        if mitigations_state == MitigationsState.all.value:
            data.pop(mitigations_state)

        return self._http_request(
            method='GET',
            url_suffix="mitigations",
            data=data,
            timeout=timeout

        )

    def get_mitigation_by_id(self, mitigation_id, timeout=60):
        return self._http_request(
            method='GET',
            url_suffix="mitigations/mitigation",
            params={"id": str(mitigation_id)},
            timeout=timeout
        )

    def get_mitigations_subtechnique_procedure_by_id(self, sub_tech_proc_id, timeout=60):
        return self._http_request(
            method='GET',
            url_suffix=f"mitigations/subtechnique-procedures/{str(sub_tech_proc_id)}",
            timeout=timeout
        )


def api_test(client: Client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to and the Connection to the service is successful.
    :param client: Cymptom client
    """
    try:
        results = client.api_test()
        if results and results.get("status") == "ok":
            return return_results('ok')
        else:
            return return_error(f"There was an error: {results.get('status', 'Failure')} - {results.get('error')}")
    except Exception as e:
        return_error(
            f"There was an error in testing connection to URL: {client._base_url}, API Key: {client._headers['Authorization'].split()[-1]}. "
            f"Please make sure that the API key is valid and has the right permissions, and that the URL is in the correct form. Error: {str(e)}")


def get_mitigations(client: Client) -> CommandResults:
    """
    This function uses a client argument
    """
    args = demisto.args()
    timeout = args.get("timeout", 60)
    state = args.get("state", MitigationsState.open.value)
    limit = args.get("limit", None)
    timeout = int(timeout)

    # mitigations_results = client.get_mitigations(timeout=timeout, mitigations_state=state)
    mitigations_results = {'totalVectors': 399,
                                     'severitySummary': {'critical': 1, 'low': 12, 'medium': 1, 'high': 1},
                                     'mitigations': [
                                         {'id': 3824, 'name': 'Brute Force',
                                          'severity': {'name': 'high', 'percentage': 11.78, 'value': 188},
                                          'tactics': ['Credential Access'], 'vectorCount': 188,
                                          'procedures': [
                                              {'name': 'Password Guessing-5766', 'state': 'open'},
                                              {'name': 'Password Spraying-5766', 'state': 'open'},
                                              {'name': 'Password Spraying-5772', 'state': 'open'},
                                              {'name': 'Password Spraying-5689', 'state': 'open'}],
                                          'mitigations': ['User Account Management',
                                                          'Multi-factor Authentication',
                                                          'Account Use Policies', 'Password Policies']}]}
    mitigations_formatted = []
    table_headers = ["ID", "Name", "Severity Type", "Attack Vectors Use Percentage", "Attack Vectors Count",
                     "Procedures", "Techniques", "Sub Techniques", "References"]

    for mitigation in mitigations_results.get("mitigations", {}):
        # extended_info = client.get_mitigation_by_id(mitigation["id"])
        extended_info = {'id': 3824, 'name': 'Brute Force', 'references': [
    {'source_name': 'mitre-attack', 'external_id': 'T1110', 'url': 'https://attack.mitre.org/techniques/T1110'},
    {'external_id': 'CAPEC-49', 'source_name': 'capec', 'url': 'https://capec.mitre.org/data/definitions/49.html'}],
                                          'severity': {'name': 'high', 'percentage': 11.78, 'value': 188},
                                          'subtechniques': [{'id': 356, 'name': 'Password Guessing', 'details': {
                                              'description': 'Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target\'s policies on password complexity or use policies that may lock accounts out after a number of failed attempts.\n\nGuessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization\'s login failure policies. (Citation: Cylance Cleaver)\n\nTypically, management services over commonly used ports are used when guessing passwords. Commonly targeted services include the following:\n\n* SSH (22/TCP)\n* Telnet (23/TCP)\n* FTP (21/TCP)\n* NetBIOS / SMB / Samba (139/TCP & 445/TCP)\n* LDAP (389/TCP)\n* Kerberos (88/TCP)\n* RDP / Terminal Services (3389/TCP)\n* HTTP/HTTP Management Services (80/TCP & 443/TCP)\n* MSSQL (1433/TCP)\n* Oracle (1521/TCP)\n* MySQL (3306/TCP)\n* VNC (5900/TCP)\n\nIn addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)\n\nIn default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.',
                                              'metadata': {'tactics': ['Credential Access'], 'technique': 'Brute Force',
                                                           'malwares': ['China Chopper', 'Pony', 'SpeakUp', 'Emotet',
                                                                        'Xbash'], 'tools': [],
                                                           'platforms': ['Linux', 'macOS', 'Windows', 'Office 365',
                                                                         'GCP', 'Azure AD', 'AWS', 'Azure', 'SaaS'],
                                                           'references': [{'source_name': 'mitre-attack',
                                                                           'external_id': 'T1110.001',
                                                                           'url': 'https://attack.mitre.org/techniques/T1110/001'},
                                                                          {
                                                                              'url': 'https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf',
                                                                              'description': 'Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.',
                                                                              'source_name': 'Cylance Cleaver'},
                                                                          {'source_name': 'US-CERT TA18-068A 2018',
                                                                           'url': 'https://www.us-cert.gov/ncas/alerts/TA18-086A',
                                                                           'description': 'US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.'}],
                                                           'permissionsRequired': ['User'],
                                                           'dataSources': ['Authentication logs',
                                                                           'Office 365 account logs']}},
                                                             'state': 'open',
                                                             'detection': 'Monitor authentication logs for system and application login failures of [Valid Accounts](https://attack.mitre.org/techniques/T1078). If authentication failures are high, then there may be a brute force attempt to gain access to a system using legitimate credentials.',
                                                             'evidence': [
                                                                 "<sources>'s and <targets>'s passwords were cracked using dictionaries of common passwords"],
                                                             'vectorCount': 33, 'procedures': [{'vectorCount': 33,
                                                                                                'severity': {
                                                                                                    'name': 'medium',
                                                                                                    'percentage': 8.27,
                                                                                                    'value': 33}}],
                                                             'recommendations': [
                                                                 {'id': 1187, 'name': 'Password Policies',
                                                                  'description': 'Refer to NIST guidelines when creating password policies. (Citation: NIST 800-63-3)'},
                                                                 {'id': 1185, 'name': 'Account Use Policies',
                                                                  'description': 'Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed. Too strict a policy may create a denial of service condition and render environments un-usable, with all accounts used in the brute force being locked-out.'},
                                                                 {'id': 1186, 'name': 'Multi-factor Authentication',
                                                                  'description': 'Use multi-factor authentication. Where possible, also enable multi-factor authentication on externally facing services.'}]},
                                                            {'id': 357, 'name': 'Password Spraying', 'details': {
                                                                'description': 'Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. \'Password01\'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)\n\nTypically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:\n\n* SSH (22/TCP)\n* Telnet (23/TCP)\n* FTP (21/TCP)\n* NetBIOS / SMB / Samba (139/TCP & 445/TCP)\n* LDAP (389/TCP)\n* Kerberos (88/TCP)\n* RDP / Terminal Services (3389/TCP)\n* HTTP/HTTP Management Services (80/TCP & 443/TCP)\n* MSSQL (1433/TCP)\n* Oracle (1521/TCP)\n* MySQL (3306/TCP)\n* VNC (5900/TCP)\n\nIn addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)\n\nIn default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.',
                                                                'metadata': {'tactics': ['Credential Access'],
                                                                             'technique': 'Brute Force',
                                                                             'malwares': ['Linux Rabbit'],
                                                                             'tools': ['MailSniper'],
                                                                             'platforms': ['Linux', 'macOS', 'Windows',
                                                                                           'AWS', 'GCP', 'Azure',
                                                                                           'Office 365', 'Azure AD',
                                                                                           'SaaS'], 'references': [
                                                                        {'source_name': 'mitre-attack',
                                                                         'external_id': 'T1110.003',
                                                                         'url': 'https://attack.mitre.org/techniques/T1110/003'},
                                                                        {
                                                                            'url': 'http://www.blackhillsinfosec.com/?p=4645',
                                                                            'description': 'Thyer, J. (2015, October 30). Password Spraying & Other Fun with RPCCLIENT. Retrieved April 25, 2017.',
                                                                            'source_name': 'BlackHillsInfosec Password Spraying'},
                                                                        {'source_name': 'US-CERT TA18-068A 2018',
                                                                         'url': 'https://www.us-cert.gov/ncas/alerts/TA18-086A',
                                                                         'description': 'US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.'},
                                                                        {
                                                                            'source_name': 'Trimarc Detecting Password Spraying',
                                                                            'url': 'https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing',
                                                                            'description': 'Metcalf, S. (2018, May 6). Trimarc Research: Detecting Password Spraying with Security Event Auditing. Retrieved January 16, 2019.'}],
                                                                             'permissionsRequired': ['User'],
                                                                             'dataSources': ['Authentication logs',
                                                                                             'Office 365 account logs']}},
                                                             'state': 'open',
                                                             'detection': 'Monitor authentication logs for system and application login failures of [Valid Accounts](https://attack.mitre.org/techniques/T1078). Specifically, monitor for many failed authentication attempts across various accounts that may result from password spraying attempts.\n\nConsider the following event IDs:(Citation: Trimarc Detecting Password Spraying)\n\n* Domain Controllers: "Audit Logon" (Success & Failure) for event ID 4625.\n* Domain Controllers: "Audit Kerberos Authentication Service" (Success & Failure) for event ID 4771.\n* All systems: "Audit Logon" (Success & Failure) for event ID 4648.',
                                                             'evidence': [
                                                                 "<sources> and <targets>'s password hashes were found identical"],
                                                             'vectorCount': 155, 'procedures': [{'vectorCount': 11,
                                                                                                 'severity': {
                                                                                                     'name': 'low',
                                                                                                     'percentage': 2.76,
                                                                                                     'value': 11}}],
                                                             'recommendations': [
                                                                 {'id': 1190, 'name': 'Account Use Policies',
                                                                  'description': 'Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed. Too strict a policy may create a denial of service condition and render environments un-usable, with all accounts used in the brute force being locked-out.'},
                                                                 {'id': 1191, 'name': 'Multi-factor Authentication',
                                                                  'description': 'Use multi-factor authentication. Where possible, also enable multi-factor authentication on externally facing services.'},
                                                                 {'id': 1192, 'name': 'Password Policies',
                                                                  'description': 'Refer to NIST guidelines when creating password policies. (Citation: NIST 800-63-3)'}]},
                                                            {'id': 357, 'name': 'Password Spraying', 'details': {
                                                                'description': 'Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. \'Password01\'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)\n\nTypically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:\n\n* SSH (22/TCP)\n* Telnet (23/TCP)\n* FTP (21/TCP)\n* NetBIOS / SMB / Samba (139/TCP & 445/TCP)\n* LDAP (389/TCP)\n* Kerberos (88/TCP)\n* RDP / Terminal Services (3389/TCP)\n* HTTP/HTTP Management Services (80/TCP & 443/TCP)\n* MSSQL (1433/TCP)\n* Oracle (1521/TCP)\n* MySQL (3306/TCP)\n* VNC (5900/TCP)\n\nIn addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)\n\nIn default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.',
                                                                'metadata': {'tactics': ['Credential Access'],
                                                                             'technique': 'Brute Force',
                                                                             'malwares': ['Linux Rabbit'],
                                                                             'tools': ['MailSniper'],
                                                                             'platforms': ['Linux', 'macOS', 'Windows',
                                                                                           'AWS', 'GCP', 'Azure',
                                                                                           'Office 365', 'Azure AD',
                                                                                           'SaaS'], 'references': [
                                                                        {'source_name': 'mitre-attack',
                                                                         'external_id': 'T1110.003',
                                                                         'url': 'https://attack.mitre.org/techniques/T1110/003'},
                                                                        {
                                                                            'url': 'http://www.blackhillsinfosec.com/?p=4645',
                                                                            'description': 'Thyer, J. (2015, October 30). Password Spraying & Other Fun with RPCCLIENT. Retrieved April 25, 2017.',
                                                                            'source_name': 'BlackHillsInfosec Password Spraying'},
                                                                        {'source_name': 'US-CERT TA18-068A 2018',
                                                                         'url': 'https://www.us-cert.gov/ncas/alerts/TA18-086A',
                                                                         'description': 'US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.'},
                                                                        {
                                                                            'source_name': 'Trimarc Detecting Password Spraying',
                                                                            'url': 'https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing',
                                                                            'description': 'Metcalf, S. (2018, May 6). Trimarc Research: Detecting Password Spraying with Security Event Auditing. Retrieved January 16, 2019.'}],
                                                                             'permissionsRequired': ['User'],
                                                                             'dataSources': ['Authentication logs',
                                                                                             'Office 365 account logs']}},
                                                             'state': 'open',
                                                             'detection': 'Monitor authentication logs for system and application login failures of [Valid Accounts](https://attack.mitre.org/techniques/T1078). Specifically, monitor for many failed authentication attempts across various accounts that may result from password spraying attempts.\n\nConsider the following event IDs:(Citation: Trimarc Detecting Password Spraying)\n\n* Domain Controllers: "Audit Logon" (Success & Failure) for event ID 4625.\n* Domain Controllers: "Audit Kerberos Authentication Service" (Success & Failure) for event ID 4771.\n* All systems: "Audit Logon" (Success & Failure) for event ID 4648.',
                                                             'evidence': [
                                                                 "<sources> and <targets>'s password hashes were found identical"],
                                                             'vectorCount': 155, 'procedures': [{'vectorCount': 5,
                                                                                                 'severity': {
                                                                                                     'name': 'low',
                                                                                                     'percentage': 1.25,
                                                                                                     'value': 5}}],
                                                             'recommendations': [
                                                                 {'id': 1190, 'name': 'Account Use Policies',
                                                                  'description': 'Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed. Too strict a policy may create a denial of service condition and render environments un-usable, with all accounts used in the brute force being locked-out.'},
                                                                 {'id': 1191, 'name': 'Multi-factor Authentication',
                                                                  'description': 'Use multi-factor authentication. Where possible, also enable multi-factor authentication on externally facing services.'},
                                                                 {'id': 1192, 'name': 'Password Policies',
                                                                  'description': 'Refer to NIST guidelines when creating password policies. (Citation: NIST 800-63-3)'}]},
                                                            {'id': 357, 'name': 'Password Spraying', 'details': {
                                                                'description': 'Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. \'Password01\'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)\n\nTypically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:\n\n* SSH (22/TCP)\n* Telnet (23/TCP)\n* FTP (21/TCP)\n* NetBIOS / SMB / Samba (139/TCP & 445/TCP)\n* LDAP (389/TCP)\n* Kerberos (88/TCP)\n* RDP / Terminal Services (3389/TCP)\n* HTTP/HTTP Management Services (80/TCP & 443/TCP)\n* MSSQL (1433/TCP)\n* Oracle (1521/TCP)\n* MySQL (3306/TCP)\n* VNC (5900/TCP)\n\nIn addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)\n\nIn default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.',
                                                                'metadata': {'tactics': ['Credential Access'],
                                                                             'technique': 'Brute Force',
                                                                             'malwares': ['Linux Rabbit'],
                                                                             'tools': ['MailSniper'],
                                                                             'platforms': ['Linux', 'macOS', 'Windows',
                                                                                           'AWS', 'GCP', 'Azure',
                                                                                           'Office 365', 'Azure AD',
                                                                                           'SaaS'], 'references': [
                                                                        {'source_name': 'mitre-attack',
                                                                         'external_id': 'T1110.003',
                                                                         'url': 'https://attack.mitre.org/techniques/T1110/003'},
                                                                        {
                                                                            'url': 'http://www.blackhillsinfosec.com/?p=4645',
                                                                            'description': 'Thyer, J. (2015, October 30). Password Spraying & Other Fun with RPCCLIENT. Retrieved April 25, 2017.',
                                                                            'source_name': 'BlackHillsInfosec Password Spraying'},
                                                                        {'source_name': 'US-CERT TA18-068A 2018',
                                                                         'url': 'https://www.us-cert.gov/ncas/alerts/TA18-086A',
                                                                         'description': 'US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.'},
                                                                        {
                                                                            'source_name': 'Trimarc Detecting Password Spraying',
                                                                            'url': 'https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing',
                                                                            'description': 'Metcalf, S. (2018, May 6). Trimarc Research: Detecting Password Spraying with Security Event Auditing. Retrieved January 16, 2019.'}],
                                                                             'permissionsRequired': ['User'],
                                                                             'dataSources': ['Authentication logs',
                                                                                             'Office 365 account logs']}},
                                                             'state': 'open',
                                                             'detection': 'Monitor authentication logs for system and application login failures of [Valid Accounts](https://attack.mitre.org/techniques/T1078). Specifically, monitor for many failed authentication attempts across various accounts that may result from password spraying attempts.\n\nConsider the following event IDs:(Citation: Trimarc Detecting Password Spraying)\n\n* Domain Controllers: "Audit Logon" (Success & Failure) for event ID 4625.\n* Domain Controllers: "Audit Kerberos Authentication Service" (Success & Failure) for event ID 4771.\n* All systems: "Audit Logon" (Success & Failure) for event ID 4648.',
                                                             'evidence': [
                                                                 "<sources> and <targets>'s password hashes were found identical"],
                                                             'vectorCount': 155, 'procedures': [{'vectorCount': 139,
                                                                                                 'severity': {
                                                                                                     'name': 'critical',
                                                                                                     'percentage': 34.84,
                                                                                                     'value': 139}}],
                                                             'recommendations': [
                                                                 {'id': 1190, 'name': 'Account Use Policies',
                                                                  'description': 'Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed. Too strict a policy may create a denial of service condition and render environments un-usable, with all accounts used in the brute force being locked-out.'},
                                                                 {'id': 1191, 'name': 'Multi-factor Authentication',
                                                                  'description': 'Use multi-factor authentication. Where possible, also enable multi-factor authentication on externally facing services.'},
                                                                 {'id': 1192, 'name': 'Password Policies',
                                                                  'description': 'Refer to NIST guidelines when creating password policies. (Citation: NIST 800-63-3)'}]}],
                                          'vectorCount': 188}
        severity_type = mitigation["severity"]["name"].capitalize()
        severity_percentage = round(extended_info["severity"]["percentage"], 2)

        mitigations_formatted.append({"ID": mitigation["id"],
                                      "Name": mitigation["name"],
                                      "SeverityType": severity_type,
                                      "AttackVectorsUsePercentage": severity_percentage,
                                      "AttackVectorsCount": mitigation["vectorCount"],
                                      "Procedures": mitigation["procedures"],
                                      "Techniques": mitigation["mitigations"],
                                      "SubTechniques": extended_info["subtechniques"],
                                      "References": extended_info["references"]})

    readable_output = tableToMarkdown('Mitigations', mitigations_formatted, headers=table_headers)

    command_results = CommandResults(
        outputs_prefix="Cymptom.Mitigations",
        outputs_key_field="ID",
        readable_output=readable_output,
        outputs=mitigations_formatted,
    )
    return command_results


def get_users_with_cracked_passwords(client: Client):
    """
    This function uses a client argument
    """

    args = demisto.args()
    timeout = args.get("timeout", 60)
    timeout = int(timeout)

    mitigations_results = client.get_mitigations(timeout=timeout)
    users_formatted = []
    table_headers = ["Username"]
    procedures_ids = set()
    mitigation_id = None
    privileged_users = []
    unprivileged_users = []

    privileged = argToBoolean(args.get("privileged", "True"))

    for mitigation in mitigations_results["mitigations"]:

        if mitigation["name"] == "Brute Force":
            mitigation_id: int = mitigation["id"]
            break

    if mitigation_id:
        l_mitigations = client.get_mitigation_by_id(mitigation_id)

        for subtechnique in l_mitigations["subtechniques"]:
            if subtechnique["name"] == "Password Guessing":
                procedures_ids.add(subtechnique["id"])

    if procedures_ids:

        for proc_id in procedures_ids:
            l_users = client.get_mitigations_subtechnique_procedure_by_id(proc_id)

            if l_users:
                l_users = l_users[0]["targets"]
                for user in l_users:
                    if "Domain" in user["labels"]:
                        username_dict = user["name"]
                        if privileged and ("DomainAdmin" in user["labels"] or "ComputerAdmin" in user["labels"]):
                            privileged_users.append(username_dict)
                        else:
                            unprivileged_users.append(username_dict)

    if privileged_users:
        for username in privileged_users:
            users_formatted.append({"Username": username})
        readable_output = tableToMarkdown('Privileged Users With Cracked Passwords', privileged_users,
                                          headers=table_headers)
    elif unprivileged_users:
        for username in unprivileged_users:
            users_formatted.append({"Username": username})
        readable_output = tableToMarkdown('Unprivileged Users With Cracked Passwords', unprivileged_users,
                                          headers=table_headers)
    else:
        readable_output = tableToMarkdown('Users With Cracked Passwords', unprivileged_users,
                                          headers=table_headers)

    command_results = CommandResults(
        outputs_prefix="Cymptom.CrackedUsers",
        outputs_key_field="Username",
        readable_output=readable_output,
        outputs=users_formatted,
    )

    return command_results


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    LOG(f'Command being called is: {demisto.command()}')

    params = demisto.params()

    base_url = params['url']

    api_key = params['api_key']

    # Flag if use server proxy
    use_proxy = params.get('proxy', False)

    # Flag if use server 'verification'
    insecure = params.get('insecure', False)

    headers = {
        "Authorization": f"Bearer {api_key}"  # Replace ${token} with the token you have obtained
    }

    demisto.debug(" ---- MAIN CALL -----")
    demisto.debug(" ---- PARAMS -----")
    demisto.debug(f"base_url: {base_url}")
    demisto.debug(f"api_key: {api_key}")
    demisto.debug(f"insecure: {insecure}")
    demisto.debug(f"use_proxy: {use_proxy}")

    client = Client(base_url=base_url, headers=headers, proxy=use_proxy, verify=insecure)

    try:
        # This is the call made when pressing the integration Test button.
        if demisto.command() == 'test-module':
            return api_test(client)

        elif demisto.command() == 'cymptom-get-mitigations':
            return_results(get_mitigations(client))

        elif demisto.command() == 'cymptom-get-users-with-cracked-passwords':
            return_results(get_users_with_cracked_passwords(client))

    # Log exceptions
    except Exception as e:
        demisto.log(str(e))
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

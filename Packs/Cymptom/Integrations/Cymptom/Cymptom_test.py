# flake8: noqa
from Cymptom import Client, get_mitigations, api_test, get_users_with_cracked_passwords
# Mocked access credentials
MOCK_BASE_URL = "https://api.fake.cymptom.com/api/"
MOCK_API_KEY = "test-test-test"

# Mocked API responses
MOCK_GET_MITIGATIONS_API_RESPONSE = {'totalVectors': 399,
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

MOCK_GET_MITIGATION_BY_ID_API_RESPONSE = {'id': 3824, 'name': 'Brute Force', 'references': [
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

MOCK_GET_MITIGATIONS_SUBTECHNIQUE_PROCEDURE_BY_ID_API_RESPONSE = [{'id': 4635, 'vectorCount': 33,
                                                                   'sources': [{'name': 'tal', 'id': 3997,
                                                                                'labels': ['WindowsObject', 'User',
                                                                                           'Domain']}],
                                                                   'targets': [{'name': 'amber', 'id': 11379,
                                                                                'labels': ['WindowsObject', 'User',
                                                                                           'Domain']}],
                                                                   'cause': {'name': 'Aa123456', 'id': 5766,
                                                                             'labels': ['Password', 'Cracked']},
                                                                   'severity': {'name': 'medium', 'percentage': 8.27,
                                                                                'value': 33}, 'state': 'open',
                                                                   'ticket': None}]

# Mocked method responses

MOCK_GET_MITIGATIONS_RESPONSE = [
    {'ID': 3824, 'Name': 'Brute Force', 'Severity Type': 'High', 'Attack Vectors Use Percentage': 11.78,
     'Attack Vectors Count': 188, 'Procedures': [{'name': 'Password Guessing-5766', 'state': 'open'},
                                                 {'name': 'Password Spraying-5766', 'state': 'open'},
                                                 {'name': 'Password Spraying-5772', 'state': 'open'},
                                                 {'name': 'Password Spraying-5689', 'state': 'open'}],
     'Techniques': ['User Account Management', 'Multi-factor Authentication', 'Account Use Policies',
                    'Password Policies'],
     'Sub Techniques': [{'id': 356, 'name': 'Password Guessing', 'details': {
        'description': 'Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target\'s policies on password complexity or use policies that may lock accounts out after a number of failed attempts.\n\nGuessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization\'s login failure policies. (Citation: Cylance Cleaver)\n\nTypically, management services over commonly used ports are used when guessing passwords. Commonly targeted services include the following:\n\n* SSH (22/TCP)\n* Telnet (23/TCP)\n* FTP (21/TCP)\n* NetBIOS / SMB / Samba (139/TCP & 445/TCP)\n* LDAP (389/TCP)\n* Kerberos (88/TCP)\n* RDP / Terminal Services (3389/TCP)\n* HTTP/HTTP Management Services (80/TCP & 443/TCP)\n* MSSQL (1433/TCP)\n* Oracle (1521/TCP)\n* MySQL (3306/TCP)\n* VNC (5900/TCP)\n\nIn addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)\n\nIn default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.',
        'metadata': {'tactics': ['Credential Access'], 'technique': 'Brute Force',
                     'malwares': ['China Chopper', 'Pony', 'SpeakUp', 'Emotet', 'Xbash'], 'tools': [],
                     'platforms': ['Linux', 'macOS', 'Windows', 'Office 365', 'GCP', 'Azure AD', 'AWS', 'Azure',
                                   'SaaS'], 'references': [{'source_name': 'mitre-attack', 'external_id': 'T1110.001',
                                                            'url': 'https://attack.mitre.org/techniques/T1110/001'}, {
                                                               'url': 'https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf',
                                                               'description': 'Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.',
                                                               'source_name': 'Cylance Cleaver'},
                                                           {'source_name': 'US-CERT TA18-068A 2018',
                                                            'url': 'https://www.us-cert.gov/ncas/alerts/TA18-086A',
                                                            'description': 'US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.'}],
                     'permissionsRequired': ['User'],
                     'dataSources': ['Authentication logs', 'Office 365 account logs']}}, 'state': 'open',
                                                              'detection': 'Monitor authentication logs for system and application login failures of [Valid Accounts](https://attack.mitre.org/techniques/T1078). If authentication failures are high, then there may be a brute force attempt to gain access to a system using legitimate credentials.',
                                                              'evidence': [
                                                                  "<sources>'s and <targets>'s passwords were cracked using dictionaries of common passwords"],
                                                              'vectorCount': 33, 'procedures': [
            {'vectorCount': 33, 'severity': {'name': 'medium', 'percentage': 8.27, 'value': 33}}], 'recommendations': [
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
     'References': [
         {'source_name': 'mitre-attack', 'external_id': 'T1110', 'url': 'https://attack.mitre.org/techniques/T1110'},
         {'external_id': 'CAPEC-49', 'source_name': 'capec',
          'url': 'https://capec.mitre.org/data/definitions/49.html'}]}]

# Global variables
headers = {
    "Authorization": f"Bearer {MOCK_API_KEY}"  # Replace ${token} with the token you have obtained
}
client = Client(base_url=MOCK_BASE_URL, headers=headers, proxy=False, verify=False)


def create_mitigations_requests_mocks(requests_mock):
    """ Mocks get responses for specific API calls."""

    requests_mock.get(MOCK_BASE_URL + 'mitigations', json=MOCK_GET_MITIGATIONS_API_RESPONSE)
    requests_mock.get(MOCK_BASE_URL + 'mitigations/mitigation?id=3824', json=MOCK_GET_MITIGATION_BY_ID_API_RESPONSE)
    requests_mock.get(MOCK_BASE_URL + 'mitigations/subtechnique-procedures/356',
                      json=MOCK_GET_MITIGATIONS_SUBTECHNIQUE_PROCEDURE_BY_ID_API_RESPONSE)


def test_api_test(requests_mock):
    requests_mock.get(MOCK_BASE_URL + 'test', json={"status": "ok"})
    api_test(client=client)


def test_get_mitigations(requests_mock):
    create_mitigations_requests_mocks(requests_mock)
    outputs = get_mitigations(client=client).outputs
    assert len(outputs) == 1
    assert len(outputs[0]["Procedures"]) == 4
    assert len(outputs[0]["Techniques"]) == 4
    assert len(outputs[0]["SubTechniques"]) == 4


def test_get_users_with_cracked_passwords(requests_mock):
    create_mitigations_requests_mocks(requests_mock)
    assert get_users_with_cracked_passwords(client=client).outputs == [{'Username': 'amber'}]


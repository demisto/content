import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import json
import random
import string
import time
from datetime import datetime, timedelta

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token', '')
BASE_URL = demisto.params().get('url', '').strip('/')
INSECURE = not demisto.params().get('insecure')
ENTITY_ID = demisto.params().get('entity-id')

# Headers to be sent in requests
HEADERS = {
    'Authorization': 'Bearer ' + TOKEN,
    'Content-Type': 'application/json',
}


''' HTTP REST CALL FUNCTION '''


def http_request(method, url_suffix, data=None, headers=HEADERS):
    try:
        res = requests.request(
            method,
            BASE_URL + '/' + url_suffix,
            headers=headers,
            verify=INSECURE,
            data=data
        )
    except Exception as e:
        return_error(e)

    # Handle error responses gracefully
    # if res.headers.get('Content-Type') != 'application/json':
    #    return_error('invalid url or port: ' + BASE_URL)

    if res.status_code == 404:
        if res.json().get('message'):
            return_error(res.json().get('message'))
        else:
            return_error('No data returned')

    if res.status_code not in {200, 201, 202, 207}:
        return_error(
            'Error in API call to {}, status code: {}, reason: {}'.format(BASE_URL + '/' + url_suffix, res.status_code,
                                                                          res.json()['message']))

    return res.json()


''' COMMANDS FUNCTIONS '''


def test_module():
    http_request('GET', 'lr-admin-api/hosts')
    demisto.results('ok')


def fetch_incidents():
    headers = dict(HEADERS)

    last_run = demisto.getLastRun()

    day_ago = datetime.now() - timedelta(days=1)
    start_time = day_ago.time()

    # Check if first run. If not, continue running from the last case dateCreated field.
    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time')
        headers['createdAfter'] = start_time
        # print(start_time)
    else:
        headers['createdBefore'] = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Get list of cases
    cases = http_request('GET', 'lr-case-api/cases?entityNumber=' + str(ENTITY_ID), headers=headers)

    # Set Last Run to the last case dateCreated field
    if cases != []:
        demisto.setLastRun({
            'start_time': cases[len(cases) - 1]['dateCreated']
        })

    events = [
        {
            'name': 'event_1',
            'create_time': '2019-10-23T10:11:00Z',
            'event_id': 100
        }
    ]

    # Generate incidents
    incidents = []
    for case in cases:
        incident = {
            'name': 'Case #' + str(case['number']) + ' ' + str(case['name']),
            'occurred': str(case['dateCreated']),
            'rawJSON': json.dumps(case)
        }
        incidents.append(incident)

    demisto.incidents(incidents)


def lr_case_query(data_args):
    case_id = data_args.get('case-id')
    case = http_request('GET', 'lr-case-api/cases/' + case_id + '/evidence')
    result = CommandResults(
        outputs_prefix='Evidence',
        outputs=case
    )
    return_results(result)


def lr_search_data(data_args):
    number_of_date = data_args.get('number-of-date')
    source_entity = data_args.get('source-entity')
    source_type = data_args.get('source-type')
    host_name = data_args.get('host-name')
    username = data_args.get('username')
    subject = data_args.get('subject')
    sender = data_args.get('sender')
    recipient = data_args.get('recipient')
    Hash = data_args.get('hash')
    url = data_args.get('URL')
    process_name = data_args.get('process-name')
    Object = data_args.get('object')

    # Mapping type and name fields
    # Map your entity Name and ID here (optional)
    source_entity_map = {
        "entity1": 1,
        "entity2": 2,
        "entity3": 3,
    }

    source_type_map = {
        "API - AWS CloudTrail": 1000598,
        "API - AWS CloudWatch Alarm": 1000607,
        "API - AWS Config Event": 1000610,
        "API - AWS S3 Flat File": 1000703,
        "API - AWS S3 Server Access Event": 1000575,
        "API - BeyondTrust Retina Vulnerability Management": 1000299,
        "API - Box Event": 1000633,
        "API - Cisco IDS/IPS": 1000025,
        "API - Cradlepoint ECM": 1000600,
        "API - IP360 Vulnerability Scanner": 1000589,
        "API - Metasploit Penetration Scanner": 1000297,
        "API - Nessus Vulnerability Scanner": 1000237,
        "API - NetApp CIFS Security Audit Event Log": 1000238,
        "API - NeXpose Vulnerability Scanner": 1000296,
        "API - Office 365 Management Activity": 1000645,
        "API - Office 365 Message Tracking": 1000730,
        "API - Okta Event": 1000618,
        "API - Qualys Vulnerability Scanner": 1000232,
        "API - Salesforce EventLogFile": 1000609,
        "API - Sourcefire eStreamer": 1000298,
        "API - Tenable SecurityCenter": 1000663,
        "API - Tenable.io Scanner": 1000624,
        "Flat File - ActivIdentity CMS": 1000494,
        "Flat File - Airwatch MDM": 1000337,
        "Flat File - Alfresco": 1000604,
        "Flat File - AllScripts": 1000734,
        "Flat File - Apache Access Log": 1000000001,
        "Flat File - Apache Error Log": 80,
        "Flat File - Apache SSL Access Log": 1000000002,
        "Flat File - Apache SSL Error Log": 82,
        "Flat File - Apache Tomcat Access Log": 1000056,
        "Flat File - Apache Tomcat Console Log": 1000465,
        "Flat File - Avaya Secure Access Link Remote Access Log": 1000474,
        "Flat File - Avaya Voice Mail Log": 131,
        "Flat File - Axway SFTP": 1000372,
        "Flat File - Beacon Endpoint Profiler": 1000518,
        "Flat File - Bind 9": 1000084,
        "Flat File - BlackBerry Enterprise Server": 164,
        "Flat File - Blue Coat Proxy BCREPORTERMAIN Format": 1000000006,
        "Flat File - Blue Coat Proxy CSV Format": 95,
        "Flat File - Blue Coat Proxy SQUID-1 Format": 167,
        "Flat File - Blue Coat Proxy W3C Format": 1000003,
        "Flat File - Bro IDS Critical Stack Intel Log": 1000611,
        "Flat File - Broadcom SiteMinder": 1000794,
        "Flat File - CA ACF2 for z/OS - ACFRPTDS": 1000379,
        "Flat File - CA ACF2 for z/OS - ACFRPTEL": 1000386,
        "Flat File - CA ACF2 for z/OS - ACFRPTJL": 1000385,
        "Flat File - CA ACF2 for z/OS - ACFRPTLL": 1000384,
        "Flat File - CA ACF2 for z/OS - ACFRPTNV": 1000383,
        "Flat File - CA ACF2 for z/OS - ACFRPTOM": 1000371,
        "Flat File - CA ACF2 for z/OS - ACFRPTPW": 1000380,
        "Flat File - CA ACF2 for z/OS - ACFRPTRL": 1000382,
        "Flat File - CA ACF2 for z/OS - ACFRPTRV": 1000381,
        "Flat File - CA ControlMinder": 1000345,
        "Flat File - Cerberus FTP Server": 1000417,
        "Flat File - Cerner": 1000422,
        "Flat File - Cisco AMP for Endpoints": 1000744,
        "Flat File - Cisco Email Security Appliance": 1000615,
        "Flat File - Cisco LMS (cwcli)": 1000212,
        "Flat File - Cisco LMS (Syslog)": 1000207,
        "Flat File - Cisco NGFW": 1000107,
        "Flat File - Cisco Secure ACS CSV File": 139,
        "Flat File - Cisco Security Agent": 1000094,
        "Flat File - Cisco Umbrella DNS": 1000705,
        "Flat File - Cisco Web Security aclog": 1000224,
        "Flat File - Citrix Access Gateway IIS Format": 1000024,
        "Flat File - Citrix Access Gateway NCSA Common Format": 1000023,
        "Flat File - Citrix Access Gateway W3C Format": 1000022,
        "Flat File - Citrix Presentation Server": 1000086,
        "Flat File - Citrix Secure Gateway": 1000440,
        "Flat File - ClamAV Anti-Virus": 1000052,
        "Flat File - ColdFusion Application Log": 1000357,
        "Flat File - ColdFusion Exception Log": 1000395,
        "Flat File - ColdFusion Mail Log": 1000361,
        "Flat File - ColdFusion Mailsent Log": 1000360,
        "Flat File - ColdFusion Server Log": 1000355,
        "Flat File - Cornerstone Managed File Transfer": 1000374,
        "Flat File - Coyote Point Equalizer": 1000214,
        "Flat File - DB2 Audit Log": 1000035,
        "Flat File - DB2 via BMC Log Master": 1000290,
        "Flat File - Defender Server": 1000151,
        "Flat File - DocWorks": 1000424,
        "Flat File - eClinicalWorks Audit Log": 1000748,
        "Flat File - EMC Isilon": 1000563,
        "Flat File - Epicor Coalition": 1000124,
        "Flat File - FairWarning Ready-For-Healthcare": 1000269,
        "Flat File - FileZilla System Log": 1000564,
        "Flat File - FireEye Web MPS": 1000310,
        "Flat File - Forcepoint Web Security CEF Cloud Format": 1000706,
        "Flat File - Forescout CounterACT": 1000501,
        "Flat File - FoxT BoKS Server Access Control": 1000688,
        "Flat File - FundsXpress": 1000517,
        "Flat File - Gene6 FTP": 154,
        "Flat File - GlobalSCAPE EFT": 1000231,
        "Flat File - Hadoop": 1000457,
        "Flat File - HMC": 1000614,
        "Flat File - HP-UX Audit Log": 115,
        "Flat File - IBM 4690 POS": 1000109,
        "Flat File - IBM Informix Application Log": 1000169,
        "Flat File - IBM Informix Audit Log": 1000170,
        "Flat File - IBM Tivoli Storage Manager": 1000454,
        "Flat File - IBM WebSphere App Server v7 Audit Log": 1000179,
        "Flat File - IBM WebSphere Cast Iron Cloud Integration": 1000389,
        "Flat File - IBM ZOS Batch Decryption Log": 146,
        "Flat File - IBM ZOS CICS Decryption Log": 147,
        "Flat File - IBM ZOS RACF Access Log": 148,
        "Flat File - IBM ZOS RACF SMF Type 80": 175,
        "Flat File - IPSwitch WS_FTP": 1000777,
        "Flat File - Irix Audit Logs": 1000117,
        "Flat File - IT-CUBE AgileSI": 1000316,
        "Flat File - JBoss Log File": 134,
        "Flat File - Juniper Steel Belted Radius Server": 1000261,
        "Flat File - Kerio Mail Server": 1000115,
        "Flat File - KERISYS Doors Event Export Format": 1000129,
        "Flat File - Kippo Honeypot": 1000522,
        "Flat File - Linux Audit ASCII": 1000154,
        "Flat File - Linux Audit Log": 1000123,
        "Flat File - Linux Host Secure Log": 1000507,
        "Flat File - LOGbinder EX": 1000623,
        "Flat File - LogRhythm Alarm Reingest": 8,
        "Flat File - LogRhythm Data Indexer Monitor": 1000648,
        "Flat File - LogRhythm Oracle Log": 1000716,
        "Flat File - LogRhythm System Monitor": 17,
        "Flat File - LogRhythm System Monitor Log File": 1000858,
        "Flat File - LogRhythm Trebek Log": 1000717,
        "Flat File - LogRhythm Zeus Log": 1000715,
        "Flat File - Lotus Domino Client Log": 1000041,
        "Flat File - McAfee Cloud Proxy_do_not_use": 1000826,
        "Flat File - McAfee ePO HIPS": 1000552,
        "Flat File - McAfee Foundstone": 1000049,
        "Flat File - McAfee Proxy Cloud": 1000829,
        "Flat File - McAfee SaaS Web Protection": 1000638,
        "Flat File - McAfee Web Gateway Audit Log": 1000685,
        "Flat File - Merak": 1000312,
        "Flat File - Meridian": 1000098,
        "Flat File - Microsoft ActiveSync 2010": 1000404,
        "Flat File - Microsoft CRM": 1000106,
        "Flat File - Microsoft DHCP Server Log": 122,
        "Flat File - Microsoft Forefront TMG": 1000402,
        "Flat File - Microsoft Forefront TMG Web Proxy": 1000586,
        "Flat File - Microsoft IIS (IIS Format) File": 112,
        "Flat File - Microsoft IIS 7.x W3C Extended Format": 1000655,
        "Flat File - Microsoft IIS Error Log V6": 1000323,
        "Flat File - Microsoft IIS FTP IIS Log File Format": 1000150,
        "Flat File - Microsoft IIS FTP W3C Extended Format": 161,
        "Flat File - Microsoft IIS NCSA Common Format File": 111,
        "Flat File - Microsoft IIS SMTP W3C Format": 1000397,
        "Flat File - Microsoft IIS URL Scan Log": 1000054,
        "Flat File - Microsoft IIS W3C File": 84,
        "Flat File - Microsoft ISA Server 2004": 187,
        "Flat File - Microsoft ISA Server W3C File": 21,
        "Flat File - Microsoft Netlogon": 1000579,
        "Flat File - Microsoft Port Reporter PR-PORTS Log": 1000274,
        "Flat File - Microsoft Semantic Logging": 1000582,
        "Flat File - Microsoft SQL Server 2000 Error Log": 40,
        "Flat File - Microsoft SQL Server 2005 Error Log": 1000172,
        "Flat File - Microsoft SQL Server 2008 Error Log": 1000181,
        "Flat File - Microsoft SQL Server 2012 Error Log": 1000479,
        "Flat File - Microsoft SQL Server 2014 Error Log": 1000637,
        "Flat File - Microsoft Windows 2003 DNS": 1000506,
        "Flat File - Microsoft Windows 2008 DNS": 1000276,
        "Flat File - Microsoft Windows 2012 DNS": 1000619,
        "Flat File - Microsoft Windows Firewall": 119,
        "Flat File - MicroStrategy": 1000535,
        "Flat File - Mimecast Audit": 1000721,
        "Flat File - Mimecast Email": 1000726,
        "Flat File - Monetra": 1000288,
        "Flat File - MongoDB": 185,
        "Flat File - MS Exchange 2003 Message Tracking Log": 1000000005,
        "Flat File - MS Exchange 2007 Message Tracking Log": 1000000004,
        "Flat File - MS Exchange 2010 Message Tracking Log": 1000000007,
        "Flat File - MS Exchange 2013 Message Tracking Log": 1000561,
        "Flat File - MS Exchange 2016 Message Tracking Log": 1000805,
        "Flat File - MS Exchange RPC Client Access": 1000433,
        "Flat File - MS IAS/RAS Server NPS DB Log Format": 121,
        "Flat File - MS IAS/RAS Server Standard Log Format": 1000168,
        "Flat File - MS ISA Server 2006 ISA All Fields": 157,
        "Flat File - MS ISA Server 2006 W3C All Fields": 156,
        "Flat File - MS SQL Server Reporting Services 2008": 1000066,
        "Flat File - MySQL": 1000247,
        "Flat File - MySQL error.log": 1000252,
        "Flat File - MySQL mysql.log": 1000256,
        "Flat File - MySQL mysql-slow.log": 1000253,
        "Flat File - Nessus System Log": 1000220,
        "Flat File - NetApp Cluster": 1000593,
        "Flat File - Nginx Log": 1000718,
        "Flat File - Novell Audit": 1000110,
        "Flat File - Novell GroupWise": 1000429,
        "Flat File - Novell LDAP": 1000307,
        "Flat File - ObserveIT Enterprise": 1000363,
        "Flat File - Office 365 Message Tracking": 1000720,
        "Flat File - OpenDJ": 1000455,
        "Flat File - OpenVMS": 1000127,
        "Flat File - OpenVPN": 1000311,
        "Flat File - Oracle 11g Fine Grained Audit Trail": 1000227,
        "Flat File - Oracle 9i": 1000007,
        "Flat File - Oracle BRM CM Log": 1000515,
        "Flat File - Oracle BRM DM Log": 1000514,
        "Flat File - Oracle Listener Audit Trail": 1000346,
        "Flat File - Oracle SunOne Directory Server": 1000278,
        "Flat File - Oracle SunOne Web Server Access Log": 1000277,
        "Flat File - Oracle Virtual Directory": 1000315,
        "Flat File - Oracle WebLogic 11g Access Log": 1000471,
        "Flat File - Other": 127,
        "Flat File - PeopleSoft": 1000822,
        "Flat File - PhpMyAdmin Honeypot": 1000523,
        "Flat File - Postfix": 1000294,
        "Flat File - PowerBroker Servers": 1000528,
        "Flat File - Princeton Card Secure": 1000136,
        "Flat File - ProFTPD": 1000087,
        "Flat File - PureMessage For Exchange SMTP Log": 1000180,
        "Flat File - PureMessage For UNIX Blocklist Log": 1000176,
        "Flat File - PureMessage For UNIX Message Log": 1000177,
        "Flat File - RACF (SMF)": 1000033,
        "Flat File - Radmin": 1000367,
        "Flat File - Restic Backup Log": 14,
        "Flat File - RL Patient Feedback": 1000349,
        "Flat File - RSA Adaptive Authentication": 1000283,
        "Flat File - RSA Authentication Manager 6.1": 1000226,
        "Flat File - S2 Badge Reader": 1000630,
        "Flat File - Safenet": 1000714,
        "Flat File - Sendmail File": 133,
        "Flat File - Sharepoint ULS": 1000221,
        "Flat File - ShoreTel VOIP": 1000351,
        "Flat File - Siemens Radiology Information System": 1000091,
        "Flat File - Snort Fast Alert File": 37,
        "Flat File - Solaris - Sulog": 1000043,
        "Flat File - Solaris Audit Log": 1000116,
        "Flat File - SpamAssassin": 1000047,
        "Flat File - Squid Proxy": 1000070,
        "Flat File - Subversion": 1000516,
        "Flat File - Sudo.Log": 1000373,
        "Flat File - Swift Alliance": 1000099,
        "Flat File - Symantec Antivirus 10.x Corporate Edtn": 176,
        "Flat File - Symantec Antivirus 12.x Corporate Edtn": 1000602,
        "Flat File - Symitar Episys Console Log": 1000466,
        "Flat File - Symitar Episys Sysevent Log": 1000450,
        "Flat File - Tandem EMSOUT Log File": 138,
        "Flat File - Tandem XYGATE": 1000306,
        "Flat File - Tectia SSH Server": 1000476,
        "Flat File - Trade Innovations CSCS": 1000114,
        "Flat File - Trend Micro IMSS": 1000219,
        "Flat File - Trend Micro Office Scan": 1000244,
        "Flat File - Tumbleweed Mailgate Server": 1000067,
        "Flat File - Verint Audit Trail File": 142,
        "Flat File - VMWare Virtual Machine": 109,
        "Flat File - Voltage Securemail": 1000368,
        "Flat File - Vormetric Log File": 135,
        "Flat File - vsFTP Daemon Log": 1000042,
        "Flat File - Vyatta Firewall Kernel Log": 1000456,
        "Flat File - WordPot Honeypot": 1000524,
        "Flat File - X-NetStat Log": 38,
        "Flat File - XPient POS CCA Manager": 159,
        "Flat File - XPIENT POS POSLOG": 1000275,
        "Flat File - XPIENT POS Shell Log": 1000287,
        "IPFIX - IP Flow Information Export": 1000484,
        "J-Flow - Juniper J-Flow Version 5": 1000292,
        "J-Flow - Juniper J-Flow Version 9": 1000293,
        "LogRhythm CloudAI": 1000678,
        "LogRhythm Data Loss Defender": 1000044,
        "LogRhythm Demo File - Application Server Log": 1000186,
        "LogRhythm Demo File - Content Inspection Log": 1000190,
        "LogRhythm Demo File - Database Audit Log": 1000191,
        "LogRhythm Demo File - Ecom Server Log": 1000194,
        "LogRhythm Demo File - File Server Log": 1000184,
        "LogRhythm Demo File - Firewall Log": 1000189,
        "LogRhythm Demo File - FTP Log": 1000182,
        "LogRhythm Demo File - IDS Alarms Log": 1000188,
        "LogRhythm Demo File - Mail Server Log": 1000185,
        "LogRhythm Demo File - Netflow Log": 1000193,
        "LogRhythm Demo File - Network Device Log": 1000192,
        "LogRhythm Demo File - Network Server Log": 1000183,
        "LogRhythm Demo File - VPN Log": 1000195,
        "LogRhythm Demo File - Web Access Log": 1000187,
        "LogRhythm File Monitor (AIX)": 8,
        "LogRhythm File Monitor (HP-UX)": 1000137,
        "LogRhythm File Monitor (Linux)": 2,
        "LogRhythm File Monitor (Solaris)": 6,
        "LogRhythm File Monitor (Windows)": 3,
        "LogRhythm Filter": 1000695,
        "LogRhythm Network Connection Monitor (AIX)": 1000163,
        "LogRhythm Network Connection Monitor (HP-UX)": 1000164,
        "LogRhythm Network Connection Monitor (Linux)": 1000165,
        "LogRhythm Network Connection Monitor (Solaris)": 1000166,
        "LogRhythm Network Connection Monitor (Windows)": 1000162,
        "LogRhythm Process Monitor (AIX)": 1000159,
        "LogRhythm Process Monitor (HP-UX)": 1000160,
        "LogRhythm Process Monitor (Linux)": 1000167,
        "LogRhythm Process Monitor (Solaris)": 1000161,
        "LogRhythm Process Monitor (Windows)": 1000158,
        "LogRhythm Registry Integrity Monitor": 1000539,
        "LogRhythm SQL Server 2000 C2 Audit Log": 1000202,
        "LogRhythm SQL Server 2005 C2 Audit Log": 1000203,
        "LogRhythm SQL Server 2008 C2 Audit Log": 1000204,
        "LogRhythm SQL Server 2012+ C2 Audit Log": 1000475,
        "LogRhythm User Activity Monitor (AIX)": 1000062,
        "LogRhythm User Activity Monitor (HP-UX)": 1000138,
        "LogRhythm User Activity Monitor (Linux)": 1000060,
        "LogRhythm User Activity Monitor (Solaris)": 1000061,
        "LogRhythm User Activity Monitor (Windows)": 1000059,
        "MS Event Log for XP/2000/2003 - Application": 31,
        "MS Event Log for XP/2000/2003 - Application - Español": 1000571,
        "MS Event Log for XP/2000/2003 - BioPassword": 151,
        "MS Event Log for XP/2000/2003 - DFS": 1000112,
        "MS Event Log for XP/2000/2003 - Directory Service": 32,
        "MS Event Log for XP/2000/2003 - DNS": 76,
        "MS Event Log for XP/2000/2003 - DotDefender": 1000083,
        "MS Event Log for XP/2000/2003 - EMC Celerra NAS": 1000488,
        "MS Event Log for XP/2000/2003 - File Rep Service": 33,
        "MS Event Log for XP/2000/2003 - HA": 1000069,
        "MS Event Log for XP/2000/2003 - Kaspersky": 1000102,
        "MS Event Log for XP/2000/2003 - Micros POS": 1000354,
        "MS Event Log for XP/2000/2003 - PatchLink": 1000073,
        "MS Event Log for XP/2000/2003 - SafeWord 2008": 199,
        "MS Event Log for XP/2000/2003 - SCE": 1000173,
        "MS Event Log for XP/2000/2003 - Security": 23,
        "MS Event Log for XP/2000/2003 - Security - Español": 1000569,
        "MS Event Log for XP/2000/2003 - SMS 2003": 1000038,
        "MS Event Log for XP/2000/2003 - System": 30,
        "MS Event Log for XP/2000/2003 - System - Español": 1000570,
        "MS Event Log for XP/2000/2003 - Virtual Server": 1000075,
        "MS Windows Event Logging - ADFS Admin": 1000661,
        "MS Windows Event Logging - Application": 1000032,
        "MS Windows Event Logging - AppLockerApp": 1000557,
        "MS Windows Event Logging - Backup": 1000341,
        "MS Windows Event Logging - Citrix Delivery Services": 1000526,
        "MS Windows Event Logging - Citrix XenApp": 1000701,
        "MS Windows Event Logging - DFS": 1000121,
        "MS Windows Event Logging - DHCP Admin": 1000540,
        "MS Windows Event Logging - DHCP Operational": 1000537,
        "MS Windows Event Logging - Diagnosis-PLA": 1000280,
        "MS Windows Event Logging - Digital Persona": 1000483,
        "MS Windows Event Logging - Dir Service": 1000119,
        "MS Windows Event Logging - DNS": 1000120,
        "MS Windows Event Logging - Dot Defender": 1000303,
        "MS Windows Event Logging - ESD Data Flow Track": 1000583,
        "MS Windows Event Logging - Exchange Mailbox DB Failures": 1000446,
        "MS Windows Event Logging - FailoverClustering/Operational": 1000447,
        "MS Windows Event Logging - Firewall With Advanced Security": 1000302,
        "MS Windows Event Logging - Forefront AV": 1000352,
        "MS Windows Event Logging - Group Policy Operational": 1000301,
        "MS Windows Event Logging - Hyper-V Hvisor": 1000264,
        "MS Windows Event Logging - Hyper-V IMS": 1000263,
        "MS Windows Event Logging - Hyper-V Network": 1000265,
        "MS Windows Event Logging - Hyper-V SynthSt": 1000266,
        "MS Windows Event Logging - Hyper-V VMMS": 1000251,
        "MS Windows Event Logging - Hyper-V Worker": 1000262,
        "MS Windows Event Logging - Kaspersky": 1000495,
        "MS Windows Event Logging - Kernel PnP Configuration": 1000559,
        "MS Windows Event Logging - Lync Server": 1000628,
        "MS Windows Event Logging - MSExchange Management": 1000338,
        "MS Windows Event Logging - Operations Manager": 1000421,
        "MS Windows Event Logging - PowerShell": 1000627,
        "MS Windows Event Logging - Print Services": 1000356,
        "MS Windows Event Logging - Quest ActiveRoles EDM Server": 1000577,
        "MS Windows Event Logging - Replication": 1000122,
        "MS Windows Event Logging - SafeWord 2008": 1000419,
        "MS Windows Event Logging - Security": 1000030,
        "MS Windows Event Logging - Setup": 1000281,
        "MS Windows Event Logging - Sysmon": 1000558,
        "MS Windows Event Logging - System": 1000031,
        "MS Windows Event Logging - Task Scheduler": 1000308,
        "MS Windows Event Logging - TS Gateway": 1000532,
        "MS Windows Event Logging - TS Licensing": 1000272,
        "MS Windows Event Logging - TS Local Session Manager": 1000271,
        "MS Windows Event Logging - TS Remote Connection Manager": 1000300,
        "MS Windows Event Logging - TS Session Broker": 1000320,
        "MS Windows Event Logging - TS Session Broker Client": 1000309,
        "MS Windows Event Logging - VisualSVN": 1000578,
        "MS Windows Event Logging : Deutsch - Security": 1000470,
        "MS Windows Event Logging : Español - Application": 1000566,
        "MS Windows Event Logging : Español - Security": 1000565,
        "MS Windows Event Logging : Español - System": 1000568,
        "MS Windows Event Logging : Français - System": 1000468,
        "MS Windows Event Logging :Français - Security": 1000469,
        "MS Windows Event Logging XML - ADFS": 1000868,
        "MS Windows Event Logging XML - Application": 1000562,
        "MS Windows Event Logging XML - Forwarded Events": 1000746,
        "MS Windows Event Logging XML - Generic": 1000738,
        "MS Windows Event Logging XML – LRTracer": 1000784,
        "MS Windows Event Logging XML - Microsoft-Windows-NTLM/Operational": 1000781,
        "MS Windows Event Logging XML - Security": 1000639,
        "MS Windows Event Logging XML - Sysmon": 1000862,
        "MS Windows Event Logging XML - Sysmon 7.01": 1000724,
        "MS Windows Event Logging XML - Sysmon 8/9/10": 1000745,
        "MS Windows Event Logging XML - System": 1000662,
        "MS Windows Event Logging XML - Unisys Stealth": 1000681,
        "MS Windows Event Logging XML - Windows Defender": 1000856,
        "Netflow - Cisco Netflow Version 1": 101,
        "Netflow - Cisco Netflow Version 5": 102,
        "Netflow - Cisco Netflow Version 9": 1000174,
        "Netflow - Palo Alto Version 9": 191,
        "Netflow - SonicWALL Version 5": 1000436,
        "Netflow - SonicWALL Version 9": 1000437,
        "OPSEC LEA - Checkpoint Firewall": 125,
        "OPSEC LEA - Checkpoint Firewall Audit Log": 1000304,
        "OPSEC LEA - Checkpoint For LR 7.4.1+": 1000741,
        "OPSEC LEA - Checkpoint Log Server": 126,
        "sFlow - Version 5": 1000239,
        "SNMP Trap - Audiolog": 1000259,
        "SNMP Trap - Autoregistered": 1000149,
        "SNMP Trap - Brocade Switch": 1000599,
        "SNMP Trap - Cisco 5508 Wireless Controller": 1000545,
        "SNMP Trap - Cisco IP SLA": 1000572,
        "SNMP Trap - Cisco Prime": 1000629,
        "SNMP Trap - Cisco Router-Switch": 1000327,
        "SNMP Trap - CyberArk": 1000240,
        "SNMP Trap - Dell OpenManage": 1000322,
        "SNMP Trap - HP Network Node Manager": 1000377,
        "SNMP Trap - IBM TS3000 Series Tape Drive": 1000258,
        "SNMP Trap - Riverbed SteelCentral NetShark": 1000508,
        "SNMP Trap - RSA Authentication Manager": 1000248,
        "SNMP Trap - Swift Alliance": 1000405,
        "SNMP Trap - Trend Micro Control Manager": 1000413,
        "Syslog - 3Com Switch": 1000329,
        "Syslog - A10 Networks AX1000 Load Balancer": 1000268,
        "Syslog - A10 Networks Web Application Firewall": 1000785,
        "Syslog - Accellion Secure File Transfer Application": 1000665,
        "Syslog - Active Scout IPS": 128,
        "Syslog - Adallom": 1000585,
        "Syslog - Adtran Switch": 1000284,
        "Syslog - Aerohive Access Point": 1000467,
        "Syslog - Aerohive Firewall": 1000677,
        "Syslog - AIMIA Tomcat": 1000635,
        "Syslog - AirDefense Enterprise": 182,
        "Syslog - Airmagnet Wireless IDS": 177,
        "Syslog - AirTight IDS/IPS": 145,
        "Syslog - AirWatch MDM": 1000594,
        "Syslog - Airwave Management System Log": 150,
        "Syslog - AIX Host": 90,
        "Syslog - Alcatel-Lucent Switch": 1000756,
        "Syslog - Alcatel-Lucent Wireless Controller": 1000425,
        "Syslog - AlertLogic": 1000742,
        "Syslog - AMX AV Controller": 27,
        "Syslog - Apache Access Log": 1000255,
        "Syslog - Apache Error Log": 1000254,
        "Syslog - Apache Tomcat Request Parameters": 110,
        "Syslog - Apache Tomcat Service Clients Log": 1000418,
        "Syslog - APC ATS": 1000400,
        "Syslog - APC NetBotz Environmental Monitoring": 1000348,
        "Syslog - APC PDU": 1000416,
        "Syslog - APC UPS": 1000200,
        "Syslog - Apcon Network Monitor": 1000491,
        "Syslog - Apex One": 1000832,
        "Syslog - Arbor Networks Peakflow": 1000477,
        "Syslog - Arbor Networks Spectrum": 1000708,
        "Syslog - Arbor Pravail APS": 1000464,
        "Syslog - Arista Switch": 1000410,
        "Syslog - Array TMX Load Balancer": 1000525,
        "Syslog - Arris CMTS": 1000230,
        "Syslog - Aruba Clear Pass": 1000502,
        "Syslog - Aruba Mobility Controller": 144,
        "Syslog - Aruba Wireless Access Point": 1000529,
        "Syslog - AS/400 via Powertech Interact": 178,
        "Syslog - Asus WRT Router": 1000679,
        "Syslog - Avatier Identity Management Suite (AIMS)": 1000780,
        "Syslog - Avaya Communications Manager": 1000459,
        "Syslog - Avaya Ethernet Routing Switch": 1000482,
        "Syslog - Avaya G450 Media Gateway": 1000680,
        "Syslog - Avaya Router": 1000581,
        "Syslog - Aventail SSL/VPN": 1000132,
        "Syslog - Avocent Cyclades Terminal Server": 1000396,
        "Syslog - Azul Java Appliance": 1000217,
        "Syslog - Barracuda Load Balancer": 1000370,
        "Syslog - Barracuda Mail Archiver": 1000492,
        "Syslog - Barracuda NG Firewall": 1000442,
        "Syslog - Barracuda NG Firewall 6.x": 1000613,
        "Syslog - Barracuda Spam Firewall": 132,
        "Syslog - Barracuda Web Application Firewall": 1000342,
        "Syslog - Barracuda Webfilter": 140,
        "Syslog - BeyondTrust BeyondInsight LEEF": 1000778,
        "Syslog - Bind DNS": 1000621,
        "Syslog - Bit9 Parity Suite": 1000215,
        "Syslog - Bit9 Security Platform CEF": 1000622,
        "Syslog - Bit9+Carbon Black (Deprecated)": 1000620,
        "Syslog - BitDefender": 1000597,
        "Syslog - Black Diamond Switch": 1000004,
        "Syslog - Blue Coat CAS": 1000739,
        "Syslog - Blue Coat Forward Proxy": 1000509,
        "Syslog - Blue Coat PacketShaper": 1000392,
        "Syslog - Blue Coat ProxyAV ISA W3C Format": 1000126,
        "Syslog - Blue Coat ProxyAV MS Proxy 2.0 Format": 1000143,
        "Syslog - Blue Coat ProxySG": 166,
        "Syslog - Blue Socket Wireless Controller": 1000451,
        "Syslog - Bluecat Adonis": 1000438,
        "Syslog - BlueCedar": 1000753,
        "Syslog - BluVector": 1000769,
        "Syslog - Bomgar": 1000347,
        "Syslog - Bradford Networks NAC": 1000553,
        "Syslog - Bradford Remediation & Registration Svr": 155,
        "Syslog - Bro IDS": 1000723,
        "Syslog - Brocade Switch": 183,
        "Syslog - Bromium vSentry CEF": 1000513,
        "Syslog - BSD Host": 117,
        "Syslog - CA Privileged Access Manager": 1000808,
        "Syslog - Cb Defense CEF": 1000702,
        "Syslog - Cb Protection CEF": 1000420,
        "Syslog - Cb Response LEEF": 1000651,
        "Syslog - Cell Relay": 1000407,
        "Syslog - Certes Networks CEP": 1000445,
        "Syslog - Check Point Log Exporter": 1000806,
        "Syslog - Checkpoint Site-to-Site VPN": 1000376,
        "Syslog - Cisco ACS": 1000063,
        "Syslog - Cisco Aironet WAP": 1000002,
        "Syslog - Cisco APIC": 1000764,
        "Syslog - Cisco Application Control Engine": 1000130,
        "Syslog - Cisco ASA": 5,
        "Syslog - Cisco Clean Access (CCA) Appliance": 1000201,
        "Syslog - Cisco CSS Load Balancer": 1000064,
        "Syslog - Cisco Email Security Appliance": 1000021,
        "Syslog - Cisco FirePOWER": 1000683,
        "Syslog - Cisco Firepower Threat Defense": 18,
        "Syslog - Cisco FireSIGHT": 1000595,
        "Syslog - Cisco FWSM": 163,
        "Syslog - Cisco Global Site Selector": 1000068,
        "Syslog - Cisco ISE": 1000369,
        "Syslog - Cisco Meraki": 1000530,
        "Syslog - Cisco Nexus Switch": 1000225,
        "Syslog - Cisco PIX": 1000000003,
        "Syslog - Cisco Prime Infrastructure": 1000500,
        "Syslog - Cisco Router": 86,
        "Syslog - Cisco Secure ACS 5": 1000206,
        "Syslog - Cisco Session Border Controller": 11,
        "Syslog - Cisco Switch": 85,
        "Syslog - Cisco Telepresence Video Communications Server": 1000657,
        "Syslog - Cisco UCS": 1000391,
        "Syslog - Cisco Unified Comm Mgr (Call Mgr)": 1000133,
        "Syslog - Cisco VPN Concentrator": 116,
        "Syslog - Cisco WAAS": 1000333,
        "Syslog - Cisco Web Security": 1000390,
        "Syslog - Cisco Wireless Access Point": 1000394,
        "Syslog - Cisco Wireless Control System": 1000101,
        "Syslog - CiscoWorks": 1000260,
        "Syslog - Citrix Access Gateway Server": 1000403,
        "Syslog - Citrix Netscaler": 25,
        "Syslog - Citrix XenServer": 1000257,
        "Syslog - Claroty CTD CEF": 1000801,
        "Syslog - Clearswift Secure Email Gateway": 1000747,
        "Syslog - CloudLock": 1000659,
        "Syslog - CodeGreen Data Loss Prevention": 1000097,
        "Syslog - Cofense Triage CEF": 1000632,
        "Syslog - Consentry NAC": 165,
        "Syslog - Corero IPS": 1000431,
        "Syslog - Corero SmartWall DDoS": 22,
        "Syslog - CoyotePoint Equalizer": 1000289,
        "Syslog - Crowdstrike Falconhost CEF": 1000682,
        "Syslog - CyberArk": 1000325,
        "Syslog - CyberArk Privileged Threat Analytics": 1000652,
        "Syslog - Cylance CEF": 1000813,
        "Syslog - CylancePROTECT": 1000625,
        "Syslog - DarkTrace CEF": 1000710,
        "Syslog - Dell Force 10": 1000423,
        "Syslog - Dell PowerConnect Switch": 1000118,
        "Syslog - Dell Remote Access Controller": 1000324,
        "Syslog - Dell SecureWorks iSensor IPS": 1000554,
        "Syslog - Dialogic Media Gateway": 1000125,
        "Syslog - Digital Guardian CEF": 1000800,
        "Syslog - D-Link Switch": 1000504,
        "Syslog - Don not use": 1000827,
        "Syslog - Dragos Platform CEF": 1000852,
        "Syslog - Ecessa ShieldLink": 1000282,
        "Syslog - EfficientIP": 7,
        "Syslog - EMC Avamar": 1000556,
        "Syslog - EMC Centera": 1000490,
        "Syslog - EMC Data Domain": 1000551,
        "Syslog - EMC Isilon": 20,
        "Syslog - EMC Unity Array": 1000751,
        "Syslog - EMC VNX": 1000432,
        "Syslog - Ensilo NGAV": 1000830,
        "Syslog - Enterasys Dragon IDS": 1000131,
        "Syslog - Enterasys Router": 123,
        "Syslog - Enterasys Switch": 124,
        "Syslog - Entrust Entelligence Messaging Server": 1000462,
        "Syslog - Entrust IdentityGuard": 1000234,
        "Syslog - Epic Hyperspace CEF": 1000668,
        "Syslog - EqualLogic SAN": 189,
        "Syslog - eSafe Email Security": 1000366,
        "Syslog - ESET Remote Administrator (ERA) LEEF": 1000754,
        "Syslog - Event Reporter (Win 2000/XP/2003)": 1000046,
        "Syslog - Exabeam": 3,
        "Syslog - Exchange Message Tracking": 6,
        "Syslog - ExtraHop": 1000795,
        "Syslog - Extreme Wireless LAN": 1000058,
        "Syslog - ExtremeWare": 1000318,
        "Syslog - ExtremeXOS": 1000317,
        "Syslog - F5 BIG-IP Access Policy Manager": 1000676,
        "Syslog - F5 BIG-IP AFM": 1000771,
        "Syslog - F5 BIG-IP ASM": 1000236,
        "Syslog - F5 BIG-IP ASM Key-Value Pairs": 1000749,
        "Syslog - F5 BIG-IP ASM v12": 1000709,
        "Syslog - F5 Big-IP GTM & DNS": 188,
        "Syslog - F5 Big-IP LTM": 1000335,
        "Syslog - F5 FirePass Firewall": 179,
        "Syslog - F5 Silverline DDoS Protection": 1000799,
        "Syslog - Fargo HDP Card Printer and Encoder": 1000358,
        "Syslog - Fat Pipe Load Balancer": 1000807,
        "Syslog - Fidelis XPS": 1000104,
        "Syslog - FireEye E-Mail MPS": 1000542,
        "Syslog - FireEye EX": 1000831,
        "Syslog - FireEye Web MPS/CMS/ETP/HX": 1000359,
        "Syslog - Forcepoint DLP": 1000321,
        "Syslog - Forcepoint Email Security Gateway": 1000591,
        "Syslog - Forcepoint Stonesoft NGFW": 1000675,
        "Syslog - Forcepoint SureView Insider Threat": 1000660,
        "Syslog - Forcepoint Web Security": 1000375,
        "Syslog - Forcepoint Web Security CEF Format": 1000452,
        "Syslog - Forescout CounterACT NAC": 1000157,
        "Syslog - Fortinet FortiAnalyzer": 1000811,
        "Syslog - Fortinet FortiAuthenticator": 1000846,
        "Syslog - Fortinet FortiDDoS": 1000782,
        "Syslog - Fortinet FortiGate": 130,
        "Syslog - Fortinet FortiGate v4.0": 1000199,
        "Syslog - Fortinet FortiGate v5.0": 1000426,
        "Syslog - Fortinet FortiGate v5.2": 1000567,
        "Syslog - Fortinet FortiGate v5.4/v5.6": 1000700,
        "Syslog - Fortinet FortiGate v5.6 CEF": 1000722,
        "Syslog - Fortinet Fortigate v6.0": 1000774,
        "Syslog - Fortinet FortiMail": 1000536,
        "Syslog - Fortinet FortiWeb": 1000493,
        "Syslog - Foundry Switch": 1000050,
        "Syslog - Gene6 FTP": 153,
        "Syslog - Generic CEF": 1000725,
        "Syslog - Generic ISC DHCP": 1000088,
        "Syslog - Generic LEEF": 1000728,
        "Syslog - Guardium Database Activity Monitor": 1000326,
        "Syslog - H3C Router": 1000243,
        "Syslog - Hitachi Universal Storage Platform": 1000398,
        "Syslog - HP BladeSystem": 1000439,
        "Syslog - HP iLO": 1000616,
        "Syslog - HP Procurve Switch": 160,
        "Syslog - HP Router": 1000057,
        "Syslog - HP Switch": 1000444,
        "Syslog - HP Unix Tru64": 1000096,
        "Syslog - HP Virtual Connect Switch": 1000350,
        "Syslog - HP-UX Host": 89,
        "Syslog - Huawei Access Router": 1000541,
        "Syslog - IBM Blade Center": 1000401,
        "Syslog - IBM Security Network Protection": 1000521,
        "Syslog - IBM Virtual Tape Library Server": 1000511,
        "Syslog - IBM WebSphere DataPower Integration": 1000441,
        "Syslog - IBM zSecure Alert for ACF2 2.1.0": 1000590,
        "Syslog - IceWarp Server": 1000267,
        "Syslog - Imperva Incapsula CEF": 1000763,
        "Syslog - Imperva SecureSphere": 1000135,
        "Syslog - Imprivata OneSign SSO": 1000693,
        "Syslog - InfoBlox": 1000089,
        "Syslog - Invincea (LEEF)": 1000626,
        "Syslog - iPrism Proxy Log": 1000095,
        "Syslog - IPSWITCH MOVEit Server": 1000573,
        "Syslog - IPTables": 1000364,
        "Syslog - IRIX Host": 118,
        "Syslog - iSeries via Powertech Interact": 184,
        "Syslog - Ivanti FileDirector": 16,
        "Syslog - JetNexus Load Balancer": 1000332,
        "Syslog - Juniper DX Application Accelerator": 1000147,
        "Syslog - Juniper Firewall": 1000045,
        "Syslog - Juniper Firewall 3400": 1000601,
        "Syslog - Juniper Host Checker": 1000082,
        "Syslog - Juniper IDP": 1000053,
        "Syslog - Juniper NSM": 1000242,
        "Syslog - Juniper Router": 1000026,
        "Syslog - Juniper SSL VPN": 186,
        "Syslog - Juniper SSL VPN WELF Format": 1000111,
        "Syslog - Juniper Switch": 1000037,
        "Syslog - Juniper Trapeze": 1000343,
        "Syslog - Juniper vGW Virtual Gateway": 1000448,
        "Syslog - Kaspersky Security Center": 1000797,
        "Syslog - Kea DHCP Server": 10,
        "Syslog - Kemp Load Balancer": 1000412,
        "Syslog - KFSensor Honeypot": 1000672,
        "Syslog - KFSensor Honeypot CEF": 1000691,
        "Syslog - Lancope StealthWatch": 1000393,
        "Syslog - Lancope StealthWatch CEF": 1000698,
        "Syslog - Layer 7 SecureSpan SOA Gateway": 1000427,
        "Syslog - Legacy Checkpoint Firewall (Not Log Exporter)": 1000434,
        "Syslog - Legacy Checkpoint IPS (Not Log Exporter)": 1000103,
        "Syslog - Lieberman Enterprise Random Password Manager": 1000353,
        "Syslog - Linux Audit": 1000139,
        "Syslog - Linux Host": 13,
        "Syslog - Linux TACACS Plus": 23,
        "Syslog - LOGbinder EX": 1000533,
        "Syslog - LOGbinder SP": 1000408,
        "Syslog - LOGbinder SQL": 1000555,
        "Syslog - LogRhythm Data Indexer Monitor": 1000653,
        "Syslog - LogRhythm Inter Deployment Data Sharing": 1000815,
        "Syslog - LogRhythm Log Distribution Services": 1000840,
        "Syslog - LogRhythm Network Monitor": 197,
        "Syslog - LogRhythm Syslog Generator": 105,
        "Syslog - Lumension": 1000608,
        "Syslog - MacOS X": 1000144,
        "Syslog - Malwarebytes Endpoint Security CEF": 1000773,
        "Syslog - Mandiant MIR": 1000489,
        "Syslog - McAfee Advanced Threat Defense": 1000617,
        "Syslog - McAfee Email And Web Security": 1000051,
        "Syslog - McAfee ePO": 1000866,
        "Syslog - McAfee Firewall Enterprise": 1000001,
        "Syslog - McAfee Network Security Manager": 1000036,
        "Syslog - McAfee Secure Internet Gateway": 136,
        "Syslog - McAfee SecureMail": 1000092,
        "Syslog - McAfee Skyhigh for Shadow IT LEEF": 1000644,
        "Syslog - McAfee Web Gateway": 1000612,
        "Syslog - mGuard Firewall": 1000711,
        "Syslog - Microsoft Advanced Threat Analytics (ATA) CEF": 1000731,
        "Syslog - Microsoft Azure Log Integration": 1000733,
        "Syslog - Microsoft Azure MFA": 1000707,
        "Syslog - Microsoft Forefront UAG": 1000461,
        "Syslog - Mirapoint": 1000228,
        "Syslog - MobileIron": 1000497,
        "Syslog - Motorola Access Point": 1000313,
        "Syslog - MS IIS Web Log W3C Format (Snare)": 1000027,
        "Syslog - MS Windows Event Logging XML - Application": 1000783,
        "Syslog - MS Windows Event Logging XML - Security": 1000669,
        "Syslog - MS Windows Event Logging XML - System": 1000671,
        "Syslog - Nagios": 1000319,
        "Syslog - nCircle Configuration Compliance Manager": 1000430,
        "Syslog - NetApp Filer": 1000108,
        "Syslog - NETASQ Firewall": 1000485,
        "Syslog - NetGate Router": 1000527,
        "Syslog - NetMotion VPN": 1000592,
        "Syslog - Netscout nGenius InfiniStream": 1000481,
        "Syslog - NetScreen Firewall": 107,
        "Syslog - Netskope": 1000736,
        "Syslog - Netskope CEF": 1000853,
        "Syslog - Network Chemistry RFprotect": 108,
        "Syslog - Nginx Web Log": 1000584,
        "Syslog - Nimble Storage": 1000727,
        "Syslog - Nortel 8600 Switch": 1000081,
        "Syslog - Nortel BayStack Switch": 171,
        "Syslog - Nortel Contivity": 1000153,
        "Syslog - Nortel Firewall": 168,
        "Syslog - Nortel IP 1220": 1000205,
        "Syslog - Nortel Passport Switch": 169,
        "Syslog - Nozomi Networks Guardian CEF": 1000819,
        "Syslog - NuSecure Gateway": 1000198,
        "Syslog - Nutanix": 26,
        "Syslog - Open Collector": 1000759,
        "Syslog - Open Collector - AWS CloudTrail": 1000786,
        "Syslog - Open Collector - AWS CloudWatch": 1000789,
        "Syslog - Open Collector - AWS Config Events": 1000790,
        "Syslog - Open Collector - AWS Guard Duty": 1000791,
        "Syslog - Open Collector - AWS S3": 1000802,
        "Syslog - Open Collector - Azure Event Hub": 1000772,
        "Syslog - Open Collector - Carbon Black Cloud": 1000861,
        "Syslog - Open Collector - CarbonBlackBeat Heartbeat": 1000864,
        "Syslog - Open Collector - Cisco AMP": 1000842,
        "Syslog - Open Collector - Cisco Umbrella": 1000787,
        "Syslog - Open Collector - CiscoAMPBeat Heartbeat": 1000843,
        "Syslog - Open Collector - Duo Authentication Security": 1000854,
        "Syslog - Open Collector - DuoBeat Heartbeat": 1000855,
        "Syslog - Open Collector - EventHubBeat Heartbeat": 1000833,
        "Syslog - Open Collector - GCP Audit": 1000817,
        "Syslog - Open Collector - GCP Cloud Key Management Service": 1000820,
        "Syslog - Open Collector - GCP Http Load Balancer": 1000839,
        "Syslog - Open Collector - GCP Pub Sub": 1000812,
        "Syslog - Open Collector - GCP Security Command Center": 1000816,
        "Syslog - Open Collector - GCP Virtual Private Cloud": 1000821,
        "Syslog - Open Collector - Gmail Message Tracking": 1000823,
        "Syslog - Open Collector - GMTBeat Heartbeat": 1000834,
        "Syslog - Open Collector - GSuite": 1000758,
        "Syslog - Open Collector - GSuiteBeat Heartbeat": 1000838,
        "Syslog - Open Collector - Metricbeat": 1000841,
        "Syslog - Open Collector - Okta System Log": 1000863,
        "Syslog - Open Collector - OktaSystemLogBeat Heartbeat": 1000865,
        "Syslog - Open Collector - PubSubBeat Heartbeat": 1000836,
        "Syslog - Open Collector - S3Beat Heartbeat": 1000835,
        "Syslog - Open Collector - Sophos Central": 1000814,
        "Syslog - Open Collector - SophosCentralBeat Heartbeat": 1000837,
        "Syslog - Open Collector - Webhook": 1000850,
        "Syslog - Open Collector - Webhook OneLogin": 1000848,
        "Syslog - Open Collector - Webhook Zoom": 1000849,
        "Syslog - Open Collector - WebhookBeat Heartbeat": 1000851,
        "Syslog - Opengear Console": 28,
        "Syslog - OpenLDAP": 1000305,
        "Syslog - Oracle 10g Audit Trail": 1000071,
        "Syslog - Oracle 11g Audit Trail": 1000223,
        "Syslog - OSSEC Alerts": 1000218,
        "Syslog - Other": 92,
        "Syslog - Outpost24": 1000414,
        "Syslog - Palo Alto Cortex XDR": 1000867,
        "Syslog - Palo Alto Custom Pipe": 15,
        "Syslog - Palo Alto Firewall": 1000134,
        "Syslog - Palo Alto Traps CEF": 1000729,
        "Syslog - Palo Alto Traps Management Service": 1000796,
        "Syslog - Password Manager Pro": 21,
        "Syslog - pfSense Firewall": 1000740,
        "Syslog - PingFederate 7.2": 1000631,
        "Syslog - PingFederate CEF": 1000770,
        "Syslog - Polycom": 1000362,
        "Syslog - Postfix": 1000105,
        "Syslog - Procera PacketLogic": 9,
        "Syslog - Proofpoint Spam Firewall": 141,
        "Syslog - Protegrity Defiance DPS": 1000085,
        "Syslog - QLogic Infiniband Switch": 1000449,
        "Syslog - Quest Defender": 1000328,
        "Syslog - Radiator Radius": 4,
        "Syslog - RADiFlow 3180 Switch": 1000498,
        "Syslog - Radware Alteon Load Balancer": 1000245,
        "Syslog - Radware DefensePro": 1000241,
        "Syslog - Radware Web Server Director Audit Log": 1000344,
        "Syslog - Raritan KVM": 1000279,
        "Syslog - Raz-Lee": 1000428,
        "Syslog - RedSeal": 1000547,
        "Syslog - Riverbed": 1000156,
        "Syslog - RSA ACE": 190,
        "Syslog - RSA Authentication Manager v7.1": 1000233,
        "Syslog - RSA Authentication Manager v8.x": 1000656,
        "Syslog - RSA Web Threat Detection": 1000512,
        "Syslog - RSA Web Threat Detection 5.1": 1000574,
        "Syslog - RuggedRouter": 1000093,
        "Syslog - Safenet": 1000074,
        "Syslog - Sailpoint": 1000640,
        "Syslog - Sauce Labs": 1000704,
        "Syslog - SecureAuth IdP": 1000443,
        "Syslog - SecureAuth IdP v9": 1000713,
        "Syslog - SecureLink": 1000793,
        "Syslog - SecureTrack": 1000249,
        "Syslog - SEL 3610 Port Switch": 1000273,
        "Syslog - SEL 3620 Ethernet Security Gateway": 1000246,
        "Syslog - Sentinel IPS": 1000460,
        "Syslog - SentinelOne CEF": 1000712,
        "Syslog - Sguil": 1000719,
        "Syslog - Siemens Scalance X400": 1000473,
        "Syslog - Smoothwall Firewall": 1000435,
        "Syslog - SnapGear Firewall": 1000409,
        "Syslog - Snare Windows 2003 Event Log": 1000028,
        "Syslog - Snare Windows 2008 Event Log": 19,
        "Syslog - Snort IDS": 1000019,
        "Syslog - Solaris (Snare)": 120,
        "Syslog - Solaris Host": 91,
        "Syslog - SonicWALL": 106,
        "Syslog - SonicWALL SSL-VPN": 137,
        "Syslog - Sophos Email Encryption Appliance": 1000336,
        "Syslog - Sophos UTM": 113,
        "Syslog - Sophos Web Proxy": 1000399,
        "Syslog - Sophos XG Firewall": 1000792,
        "Syslog - Sourcefire IDS 3D": 1000080,
        "Syslog - Sourcefire RNA": 1000340,
        "Syslog - Spectracom Network Time Server": 1000463,
        "Syslog - Splunk API - Checkpoint Firewall": 1000689,
        "Syslog - Splunk API - Cisco Netflow V9": 1000697,
        "Syslog - Splunk API - Nessus Vulnerability Scanner": 1000692,
        "Syslog - Squid Proxy": 2,
        "Syslog - StealthBits Activity Monitor": 1000844,
        "Syslog - STEALTHbits StealthINTERCEPT": 1000737,
        "Syslog - StoneGate Firewall": 1000291,
        "Syslog - Stonesoft IPS": 1000480,
        "Syslog - Stormshield Network Security Firewall": 1000650,
        "Syslog - Sycamore Networks DNX-88": 1000588,
        "Syslog - Sygate Firewall": 180,
        "Syslog - Symantec Advanced Threat Protection (ATP) CEF": 1000798,
        "Syslog - Symantec DLP CEF": 181,
        "Syslog - Symantec Endpoint Server": 1000077,
        "Syslog - Symantec Messaging Gateway": 1000828,
        "Syslog - Symantec PGP Gateway": 1000387,
        "Syslog - Symbol Wireless Access Point": 114,
        "Syslog - Tanium": 1000674,
        "Syslog - Temporary LST-2": 1000699,
        "Syslog - Tenable SecurityCenter": 1000534,
        "Syslog - Thycotic Secret Server": 1000519,
        "Syslog - Tipping Point IPS": 143,
        "Syslog - Tipping Point SSL Reverse Proxy": 1000339,
        "Syslog - Top Layer IPS": 1000048,
        "Syslog - Townsend Alliance LogAgent": 1000213,
        "Syslog - Trend Micro Control Manager CEF": 1000750,
        "Syslog - Trend Micro Deep Discovery Inspector": 1000580,
        "Syslog - Trend Micro Deep Security CEF": 1000388,
        "Syslog - Trend Micro Deep Security LEEF": 1000804,
        "Syslog - Trend Micro IWSVA": 1000330,
        "Syslog - Trend Micro Vulnerability Protection Manager": 1000803,
        "Syslog - Tripwire": 192,
        "Syslog - Trustwave NAC": 1000596,
        "Syslog - Trustwave Secure Web Gateway": 1000499,
        "Syslog - Trustwave Web Application Firewall": 1000065,
        "Syslog - Tufin": 1000684,
        "Syslog - Tumbleweed Mailgate Server": 1000078,
        "Syslog - Ubiquiti UniFi Security Gateway": 1000760,
        "Syslog - Ubiquiti UniFi Switch": 1000757,
        "Syslog - Ubiquiti UniFi WAP": 1000762,
        "Syslog - Untangle": 1000365,
        "Syslog - Vamsoft ORF": 1000458,
        "Syslog - Vanguard Active Alerts": 1000694,
        "Syslog - Varonis DatAlert": 1000544,
        "Syslog - Vasco Digipass Identikey Server": 1000503,
        "Syslog - Vectra Networks": 1000779,
        "Syslog - Versa Networks SD-WAN": 1000824,
        "Syslog - VMWare ESX/ESXi Server": 1000000,
        "Syslog - VMware Horizon View": 1000603,
        "Syslog - VMWare NSX/NSX-T": 1000768,
        "Syslog - VMWare Unified Access Gateway": 1000871,
        "Syslog - VMWare vCenter Server": 1000752,
        "Syslog - VMWare vShield": 1000487,
        "Syslog - Voltage Securemail": 1000543,
        "Syslog - Vormetric CoreGuard": 1000210,
        "Syslog - Vormetric Data Security Manager": 1000486,
        "Syslog - WALLIX Bastion": 1000765,
        "Syslog - Watchguard FireBox": 129,
        "Syslog - WS2000 Wireless Access Point": 1000076,
        "Syslog - Wurldtech SmartFirewall": 198,
        "Syslog - Xirrus Wireless Array": 1000197,
        "Syslog - Zimbra System Log": 1000100,
        "Syslog - Zix E-mail Encryption": 1000654,
        "Syslog - Zscaler Nano Streaming Service": 1000546,
        "Syslog - ZXT Load Balancer": 1000411,
        "Syslog - ZyWALL VPN Firewall": 1000666,
        "Syslog Avaya G450 Media Gateway": 1000670,
        "Syslog File - AIX Host": 1000006,
        "Syslog File - BSD Format": 35,
        "Syslog File - HP-UX Host": 1000145,
        "Syslog File - IRIX Host": 1000295,
        "Syslog File - Linux Host": 103,
        "Syslog File - LogRhythm Syslog Generator": 13,
        "Syslog File - MS 2003 Event Log (Snare)": 1000039,
        "Syslog File - Oracle 10g Audit Trail": 1000072,
        "Syslog File - Oracle 11g Audit Trail": 1000222,
        "Syslog File - Solaris Host": 104,
        "UDLA - CA Single Sign-On": 1000636,
        "UDLA - Deepnet DualShield": 1000286,
        "UDLA - Drupal": 1000496,
        "UDLA - Finacle Core": 1000196,
        "UDLA - Finacle Treasury Logs": 1000178,
        "UDLA - Forcepoint": 1000020,
        "UDLA - Gallagher Command Centre": 1000810,
        "UDLA - iManage Worksite": 1000732,
        "UDLA - ISS Proventia SiteProtector - IPS": 1000034,
        "UDLA - LogRhythm Enterprise Monitoring Solution": 1000314,
        "UDLA - LREnhancedAudit": 1000548,
        "UDLA - McAfee ePolicy Orchestrator - Universal ePOEvents": 1000788,
        "UDLA - McAfee ePolicy Orchestrator 3.6 - Events": 158,
        "UDLA - McAfee ePolicy Orchestrator 4.0 - ePOEvents": 1000079,
        "UDLA - McAfee ePolicy Orchestrator 4.5 - ePOEvents": 1000175,
        "UDLA - McAfee ePolicy Orchestrator 5.0 - ePOEvents": 1000531,
        "UDLA - McAfee ePolicy Orchestrator 5.1 - ePOEvents": 1000550,
        "UDLA - McAfee ePolicy Orchestrator 5.3 - ePOEvents": 1000696,
        "UDLA - McAfee ePolicy Orchestrator 5.9 - ePOEvents": 1000761,
        "UDLA - McAfee Network Access Control": 1000055,
        "UDLA - McAfee Network Security Manager": 1000453,
        "UDLA - Microsoft System Center 2012 Endpoint Protection": 1000587,
        "UDLA - ObserveIT": 1000605,
        "UDLA - Oracle 10g Audit Trail": 152,
        "UDLA - Oracle 11g Audit Trail": 1000171,
        "UDLA - Oracle 12C Unified Auditing": 1000658,
        "UDLA - Oracle 9i Audit Trail": 1000040,
        "UDLA - Other": 1000576,
        "UDLA - SEL 3530 RTAC": 1000285,
        "UDLA - SharePoint 2007 AuditData": 1000208,
        "UDLA - SharePoint 2010 EventData": 1000415,
        "UDLA - SharePoint 2013 EventData": 1000606,
        "UDLA - Siemens Invision": 1000229,
        "UDLA - Sophos Anti-Virus": 1000090,
        "UDLA - Sophos Endpoint Security and Control": 1000735,
        "UDLA - Symantec CSP": 1000505,
        "UDLA - Symantec SEP": 1000520,
        "UDLA - Symmetry Access Control": 1000270,
        "UDLA - VMWare vCenter Server": 1000378,
        "UDLA - VMWare vCloud": 1000538,
        "VLS - Syslog - Infoblox - DNS RPZ": 1000643,
        "VLS - Syslog - Infoblox - Threat Protection": 1000642
    }
    # Create filter query
    query = []

    if host_name != None:
        query.append(
            {
                "filterItemType": 0,
                "fieldOperator": 1,
                "filterMode": 1,
                "values": [
                    {
                        "filterType": 23,
                        "valueType": 4,
                        "value": {
                            "value": host_name,
                            "matchType": 2
                        }
                    }
                ]
            }
        )

    if source_entity != None:
        if source_entity != "all":
            query.append(
                {
                    "filterItemType": 0,
                    "fieldOperator": 1,
                    "filterMode": 1,
                    "values": [
                        {
                            "filterType": 136,
                            "valueType": 2,
                            "value": int(ENTITY_ID)
                        }
                    ]
                }
            )

    if source_type != None:
        if source_type != "all":
            query.append(
                {
                    "filterItemType": 0,
                    "fieldOperator": 1,
                    "filterMode": 1,
                    "values": [
                        {
                            "filterType": 9,
                            "valueType": 2,
                            "value": source_type_map[source_type]
                        }
                    ]
                }
            )

    if username != None:
        query.append(
            {
                "filterItemType": 0,
                "fieldOperator": 1,
                "filterMode": 1,
                "values": [
                    {
                        "filterType": 43,
                        "valueType": 4,
                        "value": {
                            "value": username,
                            "matchType": 2
                        }
                    }
                ]
            }
        )

    if subject != None:
        query.append(
            {
                "filterItemType": 0,
                "fieldOperator": 1,
                "filterMode": 1,
                "values": [
                    {
                        "filterType": 33,
                        "valueType": 4,
                        "value": {
                            "value": subject,
                            "matchType": 2
                        }
                    }
                ]
            }
        )

    if sender != None:
        query.append(
            {
                "filterItemType": 0,
                "fieldOperator": 1,
                "filterMode": 1,
                "values": [
                    {
                        "filterType": 31,
                        "valueType": 4,
                        "value": {
                            "value": sender,
                            "matchType": 2
                        }
                    }
                ]
            }
        )

    if recipient != None:
        query.append(
            {
                "filterItemType": 0,
                "fieldOperator": 1,
                "filterMode": 1,
                "values": [
                    {
                        "filterType": 32,
                        "valueType": 4,
                        "value": {
                            "value": recipient,
                            "matchType": 2
                        }
                    }
                ]
            }
        )

    if Hash != None:
        query.append(
            {
                "filterItemType": 0,
                "fieldOperator": 1,
                "filterMode": 1,
                "values": [
                    {
                        "filterType": 138,
                        "valueType": 4,
                        "value": {
                            "value": Hash,
                            "matchType": 2
                        }
                    }
                ]
            }
        )

    if url != None:
        query.append(
            {
                "filterItemType": 0,
                "fieldOperator": 1,
                "filterMode": 1,
                "values": [
                    {
                        "filterType": 42,
                        "valueType": 4,
                        "value": {
                            "value": url,
                            "matchType": 2
                        }
                    }
                ]
            }
        )

    if process_name != None:
        query.append(
            {
                "filterItemType": 0,
                "fieldOperator": 1,
                "filterMode": 1,
                "values": [
                    {
                        "filterType": 41,
                        "valueType": 4,
                        "value": {
                            "value": process_name,
                            "matchType": 2
                        }
                    }
                ]
            }
        )

    if Object != None:
        query.append(
            {
                "filterItemType": 0,
                "fieldOperator": 1,
                "filterMode": 1,
                "values": [
                    {
                        "filterType": 34,
                        "valueType": 4,
                        "value": {
                            "value": Object,
                            "matchType": 2
                        }
                    }
                ]
            }
        )

    # Search and get TaskID
    querybody = {
        "maxMsgsToQuery": 50,
        "logCacheSize": 10000,
        "queryTimeout": 60,
        "queryRawLog": True,
        "queryEventManager": False,
        "dateCriteria": {
            "useInsertedDate": False,
            "lastIntervalValue": int(number_of_date),
            "lastIntervalUnit": 4
        },
        "queryLogSources": [],
        "queryFilter": {
            "msgFilterType": 2,
            "isSavedFilter": False,
            "filterGroup": {
                "filterItemType": 1,
                "fieldOperator": 1,
                "filterMode": 1,
                "filterGroupOperator": 0,
                "filterItems": query
            }
        }
    }

    headers = dict(HEADERS)
    headers['Content-Type'] = 'application/json'

    SearchTask = http_request('POST', 'lr-search-api/actions/search-task', json.dumps(querybody), headers)
    TaskId = SearchTask["TaskId"]

    # Get search result

    queryresult = json.dumps(
        {
            "data": {
                "searchGuid": TaskId,
                "search": {
                    "sort": [],
                    "fields": []
                },
                "paginator": {
                    "origin": 0,
                    "page_size": 50
                }
            }
        })

    run = 1
    while True:
        if run == 16:
            return_results("Sorry, we have been waiting 90 seconds but LR returned nothing, please try again")
            break

        time.sleep(5)
        SearchResult = http_request('POST', 'lr-search-api/actions/search-result', queryresult, headers)

        if SearchResult["TaskStatus"] != "Searching":

            for log in SearchResult["Items"]:
                log.pop('logMessage', None)

            markdown = tableToMarkdown("Your search result", SearchResult["Items"])

            results = CommandResults(
                readable_output=markdown,
                outputs=SearchResult["Items"],
                outputs_prefix="LRSearch"
            )
            return_results(results)
            break
        run += 1


''' INTEGRATION COMMANDS '''


def main():
    LOG('Command being called is %s' % (demisto.command()))

    try:
        handle_proxy()
        if demisto.command() == 'test-module':
            test_module()
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()
        elif demisto.command() == 'lr-search-data':
            lr_search_data(demisto.args())
        elif demisto.command() == 'lr-case-query':
            lr_case_query(demisto.args())
    except Exception as e:
        return_error('error has occurred: {}'.format(str(e)))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

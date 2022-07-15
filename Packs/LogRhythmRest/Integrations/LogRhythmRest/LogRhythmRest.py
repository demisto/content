# -*- coding: utf-8 -*-

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
import random
import string
from datetime import datetime, timedelta

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token', '')
BASE_URL = demisto.params().get('url', '').strip('/')
INSECURE = not demisto.params().get('insecure')
CLUSTER_ID = demisto.params().get('cluster-id')
ENTITY_ID = demisto.params().get('entity-id')

# Headers to be sent in requests
HEADERS = {
    'Authorization': 'Bearer ' + TOKEN,
    'Content-Type': 'application/json',
}

HOSTS_HEADERS = ["ID", "Name", "EntityId", "EntityName", "OS", "Status", "Location", "RiskLevel", "ThreatLevel",
                 "ThreatLevelComments", "DateUpdated", "HostZone"]
LOGS_HEADERS = ["Level", "Computer", "Channel", "Keywords", "EventData"]
PERSON_HEADERS = ["ID", "HostStatus", "IsAPIPerson", "FirstName", "LastName", "UserID", "UserLogin", "DateUpdated"]
NETWORK_HEADERS = ["ID", "BeganIP", "EndIP", "HostStatus", "Name", "RiskLevel", "EntityId", "EntityName", "Location",
                   "ThreatLevel", "DateUpdated", "HostZone"]
ALARM_SUMMARY_HEADERS = ["PIFType", "DrillDownSummaryLogs"]
USER_HEADERS = ["ID", "DateUpdated", "HostStatus", "LastName", "FirstName", "UserType", "Entity", "Owner", "ReadAccess",
                "WriteAccess"]
LOGIN_HEADERS = ["Login", "UserProfileId", "UserId", "DefaultEntityId", "HostStatus", "DateUpdated", "DateCreated"]
PROFILE_HEADERS = ["ID", "Name", "ShortDescription", "LongDescription", "DataProcessorAccessMode", "SecurityRole", "ProfileType",
                   "DateUpdated", "TotalAssociatedUsers"]

PIF_TYPES = {
    "1": "Direction",
    "2": "Priority",
    "3": "Normal Message Date",
    "4": "First Normal Message Date",
    "5": "Last Normal Message Date",
    "6": "Count",
    "7": "MessageDate",
    "8": "Entity",
    "9": "Log Source",
    "10": "Log Source Host",
    "11": "Log Source Type",
    "12": "Log Class Type",
    "13": "Log Class",
    "14": "Common Event",
    "15": "MPE Rule",
    "16": "Source",
    "17": "Destination",
    "18": "Service",
    "19": "Known Host",
    "20": "Known Host (Origin)",
    "21": "Known Host (Impacted)",
    "22": "Known Service",
    "23": "IP",
    "24": "IP Address (Origin)",
    "25": "IP Address (Impacted)",
    "26": "Host Name",
    "27": "Host Name (Origin)",
    "28": "Host Name (Impacted)",
    "29": "Port (Origin)",
    "30": "Port (Impacted)",
    "31": "Protocol",
    "32": "User (Origin)",
    "33": "User (Impacted)",
    "34": "Sender",
    "35": "Recipient",
    "36": "Subject",
    "37": "Object",
    "38": "Vendor Message ID",
    "39": "Vendor Message Name",
    "40": "Bytes In",
    "41": "Bytes Out",
    "42": "Items In",
    "43": "Items Out",
    "44": "Duration",
    "45": "Time Start",
    "46": "Time End",
    "47": "Process",
    "48": "Amount",
    "49": "Quantity",
    "50": "Rate",
    "51": "Size",
    "52": "Domain (Impacted)",
    "53": "Group",
    "54": "URL",
    "55": "Session",
    "56": "Sequence",
    "57": "Network (Origin)",
    "58": "Network (Impacted)",
    "59": "Location (Origin)",
    "60": "Country (Origin)",
    "61": "Region (Origin)",
    "62": "City (Origin)",
    "63": "Location (Impacted)",
    "64": "Country (Impacted)",
    "65": "Region (Impacted)",
    "66": "City (Impacted)",
    "67": "Entity (Origin)",
    "68": "Entity (Impacted)",
    "69": "Zone (Origin)",
    "70": "Zone (Impacted)",
    "72": "Zone",
    "73": "User",
    "74": "Address",
    "75": "MAC",
    "76": "NATIP",
    "77": "Interface",
    "78": "NATPort",
    "79": "Entity (Impacted or Origin)",
    "80": "RootEntity",
    "100": "Message",
    "200": "MediatorMsgID",
    "201": "MARCMsgID",
    "1040": "MAC (Origin)",
    "1041": "MAC (Impacted)",
    "1042": "NATIP (Origin)",
    "1043": "NATIP (Impacted)",
    "1044": "Interface (Origin)",
    "1045": "Interface (Impacted)",
    "1046": "PID",
    "1047": "Severity",
    "1048": "Version",
    "1049": "Command",
    "1050": "ObjectName",
    "1051": "NATPort (Origin)",
    "1052": "NATPort (Impacted)",
    "1053": "Domain (Origin)",
    "1054": "Hash",
    "1055": "Policy",
    "1056": "Vendor Info",
    "1057": "Result",
    "1058": "Object Type",
    "1059": "CVE",
    "1060": "UserAgent",
    "1061": "Parent Process Id",
    "1062": "Parent Process Name",
    "1063": "Parent Process Path",
    "1064": "Serial Number",
    "1065": "Reason",
    "1066": "Status",
    "1067": "Threat Id",
    "1068": "Threat Name",
    "1069": "Session Type",
    "1070": "Action",
    "1071": "Response Code",
    "1072": "User (Origin) Identity ID",
    "1073": "User (Impacted) Identity ID",
    "1074": "Sender Identity ID",
    "1075": "Recipient Identity ID",
    "1076": "User (Origin) Identity",
    "1077": "User (Impacted) Identity",
    "1078": "Sender Identity",
    "1079": "Recipient Identity",
    "1080": "User (Origin) Identity Domain",
    "1081": "User (Impacted) Identity Domain",
    "1082": "Sender Identity Domain",
    "1083": "Recipient Identity Domain",
    "1084": "User (Origin) Identity Company",
    "1085": "User (Impacted) Identity Company",
    "1086": "Sender Identity Company",
    "1087": "Recipient Identity Company",
    "1088": "User (Origin) Identity Department",
    "1089": "User (Impacted) Identity Department",
    "1090": "Sender Identity Department",
    "1091": "Recipient Identity Department",
    "1092": "User (Origin) Identity Title",
    "1093": "User (Impacted) Identity Title",
    "1094": "Sender Identity Title",
    "1095": "Recipient Identity Title",
    "10001": "Source Or Destination",
    "10002": "Port (Origin or Impacted)",
    "10003": "Network (Origin or Impacted)",
    "10004": "Location (Origin or Impacted)",
    "10005": "Country (Origin or Impacted)",
    "10006": "Region (Origin or Impacted)",
    "10007": "City (Origin or Impacted)",
    "10008": "Bytes In/Out",
    "10009": "Items In/Out"
}

ALARM_STATUS = {
    "0": "Waiting",
    "1": "In queue",
    "2": "Sent to SvcHost",
    "3": "Queued for retry",
    "4": "Completed",
}

# Mapping type and name fields

SOURCE_TYPE_MAP = {
    "API_-_AWS_CloudTrail": 1000598,
    "API_-_AWS_CloudWatch_Alarm": 1000607,
    "API_-_AWS_Config_Event": 1000610,
    "API_-_AWS_S3_Flat_File": 1000703,
    "API_-_AWS_S3_Server_Access_Event": 1000575,
    "API_-_BeyondTrust_Retina_Vulnerability_Management": 1000299,
    "API_-_Box_Event": 1000633,
    "API_-_Cisco_IDS/IPS": 1000025,
    "API_-_Cradlepoint_ECM": 1000600,
    "API_-_IP360_Vulnerability_Scanner": 1000589,
    "API_-_Metasploit_Penetration_Scanner": 1000297,
    "API_-_Nessus_Vulnerability_Scanner": 1000237,
    "API_-_NetApp_CIFS_Security_Audit_Event_Log": 1000238,
    "API_-_NeXpose_Vulnerability_Scanner": 1000296,
    "API_-_Office_365_Management_Activity": 1000645,
    "API_-_Office_365_Message_Tracking": 1000730,
    "API_-_Okta_Event": 1000618,
    "API_-_Qualys_Vulnerability_Scanner": 1000232,
    "API_-_Salesforce_EventLogFile": 1000609,
    "API_-_Sourcefire_eStreamer": 1000298,
    "API_-_Tenable_SecurityCenter": 1000663,
    "API_-_Tenable.io_Scanner": 1000624,
    "Flat_File_-_ActivIdentity_CMS": 1000494,
    "Flat_File_-_Airwatch_MDM": 1000337,
    "Flat_File_-_Alfresco": 1000604,
    "Flat_File_-_AllScripts": 1000734,
    "Flat_File_-_Apache_Access_Log": 1000000001,
    "Flat_File_-_Apache_Error_Log": 80,
    "Flat_File_-_Apache_SSL_Access_Log": 1000000002,
    "Flat_File_-_Apache_SSL_Error_Log": 82,
    "Flat_File_-_Apache_Tomcat_Access_Log": 1000056,
    "Flat_File_-_Apache_Tomcat_Console_Log": 1000465,
    "Flat_File_-_Avaya_Secure_Access_Link_Remote_Access_Log": 1000474,
    "Flat_File_-_Avaya_Voice_Mail_Log": 131,
    "Flat_File_-_Axway_SFTP": 1000372,
    "Flat_File_-_Beacon_Endpoint_Profiler": 1000518,
    "Flat_File_-_Bind_9": 1000084,
    "Flat_File_-_BlackBerry_Enterprise_Server": 164,
    "Flat_File_-_Blue_Coat_Proxy_BCREPORTERMAIN_Format": 1000000006,
    "Flat_File_-_Blue_Coat_Proxy_CSV_Format": 95,
    "Flat_File_-_Blue_Coat_Proxy_SQUID-1_Format": 167,
    "Flat_File_-_Blue_Coat_Proxy_W3C_Format": 1000003,
    "Flat_File_-_Bro_IDS_Critical_Stack_Intel_Log": 1000611,
    "Flat_File_-_Broadcom_SiteMinder": 1000794,
    "Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTDS": 1000379,
    "Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTEL": 1000386,
    "Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTJL": 1000385,
    "Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTLL": 1000384,
    "Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTNV": 1000383,
    "Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTOM": 1000371,
    "Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTPW": 1000380,
    "Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTRL": 1000382,
    "Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTRV": 1000381,
    "Flat_File_-_CA_ControlMinder": 1000345,
    "Flat_File_-_Cerberus_FTP_Server": 1000417,
    "Flat_File_-_Cerner": 1000422,
    "Flat_File_-_Cisco_AMP_for_Endpoints": 1000744,
    "Flat_File_-_Cisco_Email_Security_Appliance": 1000615,
    "Flat_File_-_Cisco_LMS_(cwcli)": 1000212,
    "Flat_File_-_Cisco_LMS_(Syslog)": 1000207,
    "Flat_File_-_Cisco_NGFW": 1000107,
    "Flat_File_-_Cisco_Secure_ACS_CSV_File": 139,
    "Flat_File_-_Cisco_Security_Agent": 1000094,
    "Flat_File_-_Cisco_Umbrella_DNS": 1000705,
    "Flat_File_-_Cisco_Web_Security_aclog": 1000224,
    "Flat_File_-_Citrix_Access_Gateway_IIS_Format": 1000024,
    "Flat_File_-_Citrix_Access_Gateway_NCSA_Common_Format": 1000023,
    "Flat_File_-_Citrix_Access_Gateway_W3C_Format": 1000022,
    "Flat_File_-_Citrix_Presentation_Server": 1000086,
    "Flat_File_-_Citrix_Secure_Gateway": 1000440,
    "Flat_File_-_ClamAV_Anti-Virus": 1000052,
    "Flat_File_-_ColdFusion_Application_Log": 1000357,
    "Flat_File_-_ColdFusion_Exception_Log": 1000395,
    "Flat_File_-_ColdFusion_Mail_Log": 1000361,
    "Flat_File_-_ColdFusion_Mailsent_Log": 1000360,
    "Flat_File_-_ColdFusion_Server_Log": 1000355,
    "Flat_File_-_Cornerstone_Managed_File_Transfer": 1000374,
    "Flat_File_-_Coyote_Point_Equalizer": 1000214,
    "Flat_File_-_DB2_Audit_Log": 1000035,
    "Flat_File_-_DB2_via_BMC_Log_Master": 1000290,
    "Flat_File_-_Defender_Server": 1000151,
    "Flat_File_-_DocWorks": 1000424,
    "Flat_File_-_eClinicalWorks_Audit_Log": 1000748,
    "Flat_File_-_EMC_Isilon": 1000563,
    "Flat_File_-_Epicor_Coalition": 1000124,
    "Flat_File_-_FairWarning_Ready-For-Healthcare": 1000269,
    "Flat_File_-_FileZilla_System_Log": 1000564,
    "Flat_File_-_FireEye_Web_MPS": 1000310,
    "Flat_File_-_Forcepoint_Web_Security_CEF_Cloud_Format": 1000706,
    "Flat_File_-_Forescout_CounterACT": 1000501,
    "Flat_File_-_FoxT_BoKS_Server_Access_Control": 1000688,
    "Flat_File_-_FundsXpress": 1000517,
    "Flat_File_-_Gene6_FTP": 154,
    "Flat_File_-_GlobalSCAPE_EFT": 1000231,
    "Flat_File_-_Hadoop": 1000457,
    "Flat_File_-_HMC": 1000614,
    "Flat_File_-_HP-UX_Audit_Log": 115,
    "Flat_File_-_IBM_4690_POS": 1000109,
    "Flat_File_-_IBM_Informix_Application_Log": 1000169,
    "Flat_File_-_IBM_Informix_Audit_Log": 1000170,
    "Flat_File_-_IBM_Tivoli_Storage_Manager": 1000454,
    "Flat_File_-_IBM_WebSphere_App_Server_v7_Audit_Log": 1000179,
    "Flat_File_-_IBM_WebSphere_Cast_Iron_Cloud_Integration": 1000389,
    "Flat_File_-_IBM_ZOS_Batch_Decryption_Log": 146,
    "Flat_File_-_IBM_ZOS_CICS_Decryption_Log": 147,
    "Flat_File_-_IBM_ZOS_RACF_Access_Log": 148,
    "Flat_File_-_IBM_ZOS_RACF_SMF_Type_80": 175,
    "Flat_File_-_IPSwitch_WS_FTP": 1000777,
    "Flat_File_-_Irix_Audit_Logs": 1000117,
    "Flat_File_-_IT-CUBE_AgileSI": 1000316,
    "Flat_File_-_JBoss_Log_File": 134,
    "Flat_File_-_Juniper_Steel_Belted_Radius_Server": 1000261,
    "Flat_File_-_Kerio_Mail_Server": 1000115,
    "Flat_File_-_KERISYS_Doors_Event_Export_Format": 1000129,
    "Flat_File_-_Kippo_Honeypot": 1000522,
    "Flat_File_-_Linux_Audit_ASCII": 1000154,
    "Flat_File_-_Linux_Audit_Log": 1000123,
    "Flat_File_-_Linux_Host_Secure_Log": 1000507,
    "Flat_File_-_LOGbinder_EX": 1000623,
    "Flat_File_-_LogRhythm_Alarm_Reingest": 8,
    "Flat_File_-_LogRhythm_Data_Indexer_Monitor": 1000648,
    "Flat_File_-_LogRhythm_Oracle_Log": 1000716,
    "Flat_File_-_LogRhythm_System_Monitor": 17,
    "Flat_File_-_LogRhythm_System_Monitor_Log_File": 1000858,
    "Flat_File_-_LogRhythm_Trebek_Log": 1000717,
    "Flat_File_-_LogRhythm_Zeus_Log": 1000715,
    "Flat_File_-_Lotus_Domino_Client_Log": 1000041,
    "Flat_File_-_McAfee_Cloud_Proxy_do_not_use": 1000826,
    "Flat_File_-_McAfee_ePO_HIPS": 1000552,
    "Flat_File_-_McAfee_Foundstone": 1000049,
    "Flat_File_-_McAfee_Proxy_Cloud": 1000829,
    "Flat_File_-_McAfee_SaaS_Web_Protection": 1000638,
    "Flat_File_-_McAfee_Web_Gateway_Audit_Log": 1000685,
    "Flat_File_-_Merak": 1000312,
    "Flat_File_-_Meridian": 1000098,
    "Flat_File_-_Microsoft_ActiveSync_2010": 1000404,
    "Flat_File_-_Microsoft_CRM": 1000106,
    "Flat_File_-_Microsoft_DHCP_Server_Log": 122,
    "Flat_File_-_Microsoft_Forefront_TMG": 1000402,
    "Flat_File_-_Microsoft_Forefront_TMG_Web_Proxy": 1000586,
    "Flat_File_-_Microsoft_IIS_(IIS_Format)_File": 112,
    "Flat_File_-_Microsoft_IIS_7.x_W3C_Extended_Format": 1000655,
    "Flat_File_-_Microsoft_IIS_Error_Log_V6": 1000323,
    "Flat_File_-_Microsoft_IIS_FTP_IIS_Log_File_Format": 1000150,
    "Flat_File_-_Microsoft_IIS_FTP_W3C_Extended_Format": 161,
    "Flat_File_-_Microsoft_IIS_NCSA_Common_Format_File": 111,
    "Flat_File_-_Microsoft_IIS_SMTP_W3C_Format": 1000397,
    "Flat_File_-_Microsoft_IIS_URL_Scan_Log": 1000054,
    "Flat_File_-_Microsoft_IIS_W3C_File": 84,
    "Flat_File_-_Microsoft_ISA_Server_2004": 187,
    "Flat_File_-_Microsoft_ISA_Server_W3C_File": 21,
    "Flat_File_-_Microsoft_Netlogon": 1000579,
    "Flat_File_-_Microsoft_Port_Reporter_PR-PORTS_Log": 1000274,
    "Flat_File_-_Microsoft_Semantic_Logging": 1000582,
    "Flat_File_-_Microsoft_SQL_Server_2000_Error_Log": 40,
    "Flat_File_-_Microsoft_SQL_Server_2005_Error_Log": 1000172,
    "Flat_File_-_Microsoft_SQL_Server_2008_Error_Log": 1000181,
    "Flat_File_-_Microsoft_SQL_Server_2012_Error_Log": 1000479,
    "Flat_File_-_Microsoft_SQL_Server_2014_Error_Log": 1000637,
    "Flat_File_-_Microsoft_Windows_2003_DNS": 1000506,
    "Flat_File_-_Microsoft_Windows_2008_DNS": 1000276,
    "Flat_File_-_Microsoft_Windows_2012_DNS": 1000619,
    "Flat_File_-_Microsoft_Windows_Firewall": 119,
    "Flat_File_-_MicroStrategy": 1000535,
    "Flat_File_-_Mimecast_Audit": 1000721,
    "Flat_File_-_Mimecast_Email": 1000726,
    "Flat_File_-_Monetra": 1000288,
    "Flat_File_-_MongoDB": 185,
    "Flat_File_-_MS_Exchange_2003_Message_Tracking_Log": 1000000005,
    "Flat_File_-_MS_Exchange_2007_Message_Tracking_Log": 1000000004,
    "Flat_File_-_MS_Exchange_2010_Message_Tracking_Log": 1000000007,
    "Flat_File_-_MS_Exchange_2013_Message_Tracking_Log": 1000561,
    "Flat_File_-_MS_Exchange_2016_Message_Tracking_Log": 1000805,
    "Flat_File_-_MS_Exchange_RPC_Client_Access": 1000433,
    "Flat_File_-_MS_IAS/RAS_Server_NPS_DB_Log_Format": 121,
    "Flat_File_-_MS_IAS/RAS_Server_Standard_Log_Format": 1000168,
    "Flat_File_-_MS_ISA_Server_2006_ISA_All_Fields": 157,
    "Flat_File_-_MS_ISA_Server_2006_W3C_All_Fields": 156,
    "Flat_File_-_MS_SQL_Server_Reporting_Services_2008": 1000066,
    "Flat_File_-_MySQL": 1000247,
    "Flat_File_-_MySQL_error.log": 1000252,
    "Flat_File_-_MySQL_mysql.log": 1000256,
    "Flat_File_-_MySQL_mysql-slow.log": 1000253,
    "Flat_File_-_Nessus_System_Log": 1000220,
    "Flat_File_-_NetApp_Cluster": 1000593,
    "Flat_File_-_Nginx_Log": 1000718,
    "Flat_File_-_Novell_Audit": 1000110,
    "Flat_File_-_Novell_GroupWise": 1000429,
    "Flat_File_-_Novell_LDAP": 1000307,
    "Flat_File_-_ObserveIT_Enterprise": 1000363,
    "Flat_File_-_Office_365_Message_Tracking": 1000720,
    "Flat_File_-_OpenDJ": 1000455,
    "Flat_File_-_OpenVMS": 1000127,
    "Flat_File_-_OpenVPN": 1000311,
    "Flat_File_-_Oracle_11g_Fine_Grained_Audit_Trail": 1000227,
    "Flat_File_-_Oracle_9i": 1000007,
    "Flat_File_-_Oracle_BRM_CM_Log": 1000515,
    "Flat_File_-_Oracle_BRM_DM_Log": 1000514,
    "Flat_File_-_Oracle_Listener_Audit_Trail": 1000346,
    "Flat_File_-_Oracle_SunOne_Directory_Server": 1000278,
    "Flat_File_-_Oracle_SunOne_Web_Server_Access_Log": 1000277,
    "Flat_File_-_Oracle_Virtual_Directory": 1000315,
    "Flat_File_-_Oracle_WebLogic_11g_Access_Log": 1000471,
    "Flat_File_-_Other": 127,
    "Flat_File_-_PeopleSoft": 1000822,
    "Flat_File_-_PhpMyAdmin_Honeypot": 1000523,
    "Flat_File_-_Postfix": 1000294,
    "Flat_File_-_PowerBroker_Servers": 1000528,
    "Flat_File_-_Princeton_Card_Secure": 1000136,
    "Flat_File_-_ProFTPD": 1000087,
    "Flat_File_-_PureMessage_For_Exchange_SMTP_Log": 1000180,
    "Flat_File_-_PureMessage_For_UNIX_Blocklist_Log": 1000176,
    "Flat_File_-_PureMessage_For_UNIX_Message_Log": 1000177,
    "Flat_File_-_RACF_(SMF)": 1000033,
    "Flat_File_-_Radmin": 1000367,
    "Flat_File_-_Restic_Backup_Log": 14,
    "Flat_File_-_RL_Patient_Feedback": 1000349,
    "Flat_File_-_RSA_Adaptive_Authentication": 1000283,
    "Flat_File_-_RSA_Authentication_Manager_6.1": 1000226,
    "Flat_File_-_S2_Badge_Reader": 1000630,
    "Flat_File_-_Safenet": 1000714,
    "Flat_File_-_Sendmail_File": 133,
    "Flat_File_-_Sharepoint_ULS": 1000221,
    "Flat_File_-_ShoreTel_VOIP": 1000351,
    "Flat_File_-_Siemens_Radiology_Information_System": 1000091,
    "Flat_File_-_Snort_Fast_Alert_File": 37,
    "Flat_File_-_Solaris_-_Sulog": 1000043,
    "Flat_File_-_Solaris_Audit_Log": 1000116,
    "Flat_File_-_SpamAssassin": 1000047,
    "Flat_File_-_Squid_Proxy": 1000070,
    "Flat_File_-_Subversion": 1000516,
    "Flat_File_-_Sudo.Log": 1000373,
    "Flat_File_-_Swift_Alliance": 1000099,
    "Flat_File_-_Symantec_Antivirus_10.x_Corporate_Edtn": 176,
    "Flat_File_-_Symantec_Antivirus_12.x_Corporate_Edtn": 1000602,
    "Flat_File_-_Symitar_Episys_Console_Log": 1000466,
    "Flat_File_-_Symitar_Episys_Sysevent_Log": 1000450,
    "Flat_File_-_Tandem_EMSOUT_Log_File": 138,
    "Flat_File_-_Tandem_XYGATE": 1000306,
    "Flat_File_-_Tectia_SSH_Server": 1000476,
    "Flat_File_-_Trade_Innovations_CSCS": 1000114,
    "Flat_File_-_Trend_Micro_IMSS": 1000219,
    "Flat_File_-_Trend_Micro_Office_Scan": 1000244,
    "Flat_File_-_Tumbleweed_Mailgate_Server": 1000067,
    "Flat_File_-_Verint_Audit_Trail_File": 142,
    "Flat_File_-_VMWare_Virtual_Machine": 109,
    "Flat_File_-_Voltage_Securemail": 1000368,
    "Flat_File_-_Vormetric_Log_File": 135,
    "Flat_File_-_vsFTP_Daemon_Log": 1000042,
    "Flat_File_-_Vyatta_Firewall_Kernel_Log": 1000456,
    "Flat_File_-_WordPot_Honeypot": 1000524,
    "Flat_File_-_X-NetStat_Log": 38,
    "Flat_File_-_XPient_POS_CCA_Manager": 159,
    "Flat_File_-_XPIENT_POS_POSLOG": 1000275,
    "Flat_File_-_XPIENT_POS_Shell_Log": 1000287,
    "IPFIX_-_IP_Flow_Information_Export": 1000484,
    "J-Flow_-_Juniper_J-Flow_Version_5": 1000292,
    "J-Flow_-_Juniper_J-Flow_Version_9": 1000293,
    "LogRhythm_CloudAI": 1000678,
    "LogRhythm_Data_Loss_Defender": 1000044,
    "LogRhythm_Demo_File_-_Application_Server_Log": 1000186,
    "LogRhythm_Demo_File_-_Content_Inspection_Log": 1000190,
    "LogRhythm_Demo_File_-_Database_Audit_Log": 1000191,
    "LogRhythm_Demo_File_-_Ecom_Server_Log": 1000194,
    "LogRhythm_Demo_File_-_File_Server_Log": 1000184,
    "LogRhythm_Demo_File_-_Firewall_Log": 1000189,
    "LogRhythm_Demo_File_-_FTP_Log": 1000182,
    "LogRhythm_Demo_File_-_IDS_Alarms_Log": 1000188,
    "LogRhythm_Demo_File_-_Mail_Server_Log": 1000185,
    "LogRhythm_Demo_File_-_Netflow_Log": 1000193,
    "LogRhythm_Demo_File_-_Network_Device_Log": 1000192,
    "LogRhythm_Demo_File_-_Network_Server_Log": 1000183,
    "LogRhythm_Demo_File_-_VPN_Log": 1000195,
    "LogRhythm_Demo_File_-_Web_Access_Log": 1000187,
    "LogRhythm_File_Monitor_(AIX)": 8,
    "LogRhythm_File_Monitor_(HP-UX)": 1000137,
    "LogRhythm_File_Monitor_(Linux)": 2,
    "LogRhythm_File_Monitor_(Solaris)": 6,
    "LogRhythm_File_Monitor_(Windows)": 3,
    "LogRhythm_Filter": 1000695,
    "LogRhythm_Network_Connection_Monitor_(AIX)": 1000163,
    "LogRhythm_Network_Connection_Monitor_(HP-UX)": 1000164,
    "LogRhythm_Network_Connection_Monitor_(Linux)": 1000165,
    "LogRhythm_Network_Connection_Monitor_(Solaris)": 1000166,
    "LogRhythm_Network_Connection_Monitor_(Windows)": 1000162,
    "LogRhythm_Process_Monitor_(AIX)": 1000159,
    "LogRhythm_Process_Monitor_(HP-UX)": 1000160,
    "LogRhythm_Process_Monitor_(Linux)": 1000167,
    "LogRhythm_Process_Monitor_(Solaris)": 1000161,
    "LogRhythm_Process_Monitor_(Windows)": 1000158,
    "LogRhythm_Registry_Integrity_Monitor": 1000539,
    "LogRhythm_SQL_Server_2000_C2_Audit_Log": 1000202,
    "LogRhythm_SQL_Server_2005_C2_Audit_Log": 1000203,
    "LogRhythm_SQL_Server_2008_C2_Audit_Log": 1000204,
    "LogRhythm_SQL_Server_2012+_C2_Audit_Log": 1000475,
    "LogRhythm_User_Activity_Monitor_(AIX)": 1000062,
    "LogRhythm_User_Activity_Monitor_(HP-UX)": 1000138,
    "LogRhythm_User_Activity_Monitor_(Linux)": 1000060,
    "LogRhythm_User_Activity_Monitor_(Solaris)": 1000061,
    "LogRhythm_User_Activity_Monitor_(Windows)": 1000059,
    "MS_Event_Log_for_XP/2000/2003_-_Application": 31,
    "MS_Event_Log_for_XP/2000/2003_-_Application_-_Espaniol": 1000571,
    "MS_Event_Log_for_XP/2000/2003_-_BioPassword": 151,
    "MS_Event_Log_for_XP/2000/2003_-_DFS": 1000112,
    "MS_Event_Log_for_XP/2000/2003_-_Directory_Service": 32,
    "MS_Event_Log_for_XP/2000/2003_-_DNS": 76,
    "MS_Event_Log_for_XP/2000/2003_-_DotDefender": 1000083,
    "MS_Event_Log_for_XP/2000/2003_-_EMC_Celerra_NAS": 1000488,
    "MS_Event_Log_for_XP/2000/2003_-_File_Rep_Service": 33,
    "MS_Event_Log_for_XP/2000/2003_-_HA": 1000069,
    "MS_Event_Log_for_XP/2000/2003_-_Kaspersky": 1000102,
    "MS_Event_Log_for_XP/2000/2003_-_Micros_POS": 1000354,
    "MS_Event_Log_for_XP/2000/2003_-_PatchLink": 1000073,
    "MS_Event_Log_for_XP/2000/2003_-_SafeWord_2008": 199,
    "MS_Event_Log_for_XP/2000/2003_-_SCE": 1000173,
    "MS_Event_Log_for_XP/2000/2003_-_Security": 23,
    "MS_Event_Log_for_XP/2000/2003_-_Security_-_Espaniol": 1000569,
    "MS_Event_Log_for_XP/2000/2003_-_SMS_2003": 1000038,
    "MS_Event_Log_for_XP/2000/2003_-_System": 30,
    "MS_Event_Log_for_XP/2000/2003_-_System_-_Espaniol": 1000570,
    "MS_Event_Log_for_XP/2000/2003_-_Virtual_Server": 1000075,
    "MS_Windows_Event_Logging_-_ADFS_Admin": 1000661,
    "MS_Windows_Event_Logging_-_Application": 1000032,
    "MS_Windows_Event_Logging_-_AppLockerApp": 1000557,
    "MS_Windows_Event_Logging_-_Backup": 1000341,
    "MS_Windows_Event_Logging_-_Citrix_Delivery_Services": 1000526,
    "MS_Windows_Event_Logging_-_Citrix_XenApp": 1000701,
    "MS_Windows_Event_Logging_-_DFS": 1000121,
    "MS_Windows_Event_Logging_-_DHCP_Admin": 1000540,
    "MS_Windows_Event_Logging_-_DHCP_Operational": 1000537,
    "MS_Windows_Event_Logging_-_Diagnosis-PLA": 1000280,
    "MS_Windows_Event_Logging_-_Digital_Persona": 1000483,
    "MS_Windows_Event_Logging_-_Dir_Service": 1000119,
    "MS_Windows_Event_Logging_-_DNS": 1000120,
    "MS_Windows_Event_Logging_-_Dot_Defender": 1000303,
    "MS_Windows_Event_Logging_-_ESD_Data_Flow_Track": 1000583,
    "MS_Windows_Event_Logging_-_Exchange_Mailbox_DB_Failures": 1000446,
    "MS_Windows_Event_Logging_-_FailoverClustering/Operational": 1000447,
    "MS_Windows_Event_Logging_-_Firewall_With_Advanced_Security": 1000302,
    "MS_Windows_Event_Logging_-_Forefront_AV": 1000352,
    "MS_Windows_Event_Logging_-_Group_Policy_Operational": 1000301,
    "MS_Windows_Event_Logging_-_Hyper-V_Hvisor": 1000264,
    "MS_Windows_Event_Logging_-_Hyper-V_IMS": 1000263,
    "MS_Windows_Event_Logging_-_Hyper-V_Network": 1000265,
    "MS_Windows_Event_Logging_-_Hyper-V_SynthSt": 1000266,
    "MS_Windows_Event_Logging_-_Hyper-V_VMMS": 1000251,
    "MS_Windows_Event_Logging_-_Hyper-V_Worker": 1000262,
    "MS_Windows_Event_Logging_-_Kaspersky": 1000495,
    "MS_Windows_Event_Logging_-_Kernel_PnP_Configuration": 1000559,
    "MS_Windows_Event_Logging_-_Lync_Server": 1000628,
    "MS_Windows_Event_Logging_-_MSExchange_Management": 1000338,
    "MS_Windows_Event_Logging_-_Operations_Manager": 1000421,
    "MS_Windows_Event_Logging_-_PowerShell": 1000627,
    "MS_Windows_Event_Logging_-_Print_Services": 1000356,
    "MS_Windows_Event_Logging_-_Quest_ActiveRoles_EDM_Server": 1000577,
    "MS_Windows_Event_Logging_-_Replication": 1000122,
    "MS_Windows_Event_Logging_-_SafeWord_2008": 1000419,
    "MS_Windows_Event_Logging_-_Security": 1000030,
    "MS_Windows_Event_Logging_-_Setup": 1000281,
    "MS_Windows_Event_Logging_-_Sysmon": 1000558,
    "MS_Windows_Event_Logging_-_System": 1000031,
    "MS_Windows_Event_Logging_-_Task_Scheduler": 1000308,
    "MS_Windows_Event_Logging_-_TS_Gateway": 1000532,
    "MS_Windows_Event_Logging_-_TS_Licensing": 1000272,
    "MS_Windows_Event_Logging_-_TS_Local_Session_Manager": 1000271,
    "MS_Windows_Event_Logging_-_TS_Remote_Connection_Manager": 1000300,
    "MS_Windows_Event_Logging_-_TS_Session_Broker": 1000320,
    "MS_Windows_Event_Logging_-_TS_Session_Broker_Client": 1000309,
    "MS_Windows_Event_Logging_-_VisualSVN": 1000578,
    "MS_Windows_Event_Logging_:_Deutsch_-_Security": 1000470,
    "MS_Windows_Event_Logging_:_Espaniol_-_Application": 1000566,
    "MS_Windows_Event_Logging_:_Espaniol_-_Security": 1000565,
    "MS_Windows_Event_Logging_:_Espaniol_-_System": 1000568,
    "MS_Windows_Event_Logging_:_Francais_-_System": 1000468,
    "MS_Windows_Event_Logging_:Francais_-_Security": 1000469,
    "MS_Windows_Event_Logging_XML_-_ADFS": 1000868,
    "MS_Windows_Event_Logging_XML_-_Application": 1000562,
    "MS_Windows_Event_Logging_XML_-_Forwarded_Events": 1000746,
    "MS_Windows_Event_Logging_XML_-_Generic": 1000738,
    "MS_Windows_Event_Logging_XML_-_LRTracer": 1000784,
    "MS_Windows_Event_Logging_XML_-_Microsoft-Windows-NTLM/Operational": 1000781,
    "MS_Windows_Event_Logging_XML_-_Security": 1000639,
    "MS_Windows_Event_Logging_XML_-_Sysmon": 1000862,
    "MS_Windows_Event_Logging_XML_-_Sysmon_7.01": 1000724,
    "MS_Windows_Event_Logging_XML_-_Sysmon_8/9/10": 1000745,
    "MS_Windows_Event_Logging_XML_-_System": 1000662,
    "MS_Windows_Event_Logging_XML_-_Unisys_Stealth": 1000681,
    "MS_Windows_Event_Logging_XML_-_Windows_Defender": 1000856,
    "Netflow_-_Cisco_Netflow_Version_1": 101,
    "Netflow_-_Cisco_Netflow_Version_5": 102,
    "Netflow_-_Cisco_Netflow_Version_9": 1000174,
    "Netflow_-_Palo_Alto_Version_9": 191,
    "Netflow_-_SonicWALL_Version_5": 1000436,
    "Netflow_-_SonicWALL_Version_9": 1000437,
    "OPSEC_LEA_-_Checkpoint_Firewall": 125,
    "OPSEC_LEA_-_Checkpoint_Firewall_Audit_Log": 1000304,
    "OPSEC_LEA_-_Checkpoint_For_LR_7.4.1+": 1000741,
    "OPSEC_LEA_-_Checkpoint_Log_Server": 126,
    "sFlow_-_Version_5": 1000239,
    "SNMP_Trap_-_Audiolog": 1000259,
    "SNMP_Trap_-_Autoregistered": 1000149,
    "SNMP_Trap_-_Brocade_Switch": 1000599,
    "SNMP_Trap_-_Cisco_5508_Wireless_Controller": 1000545,
    "SNMP_Trap_-_Cisco_IP_SLA": 1000572,
    "SNMP_Trap_-_Cisco_Prime": 1000629,
    "SNMP_Trap_-_Cisco_Router-Switch": 1000327,
    "SNMP_Trap_-_CyberArk": 1000240,
    "SNMP_Trap_-_Dell_OpenManage": 1000322,
    "SNMP_Trap_-_HP_Network_Node_Manager": 1000377,
    "SNMP_Trap_-_IBM_TS3000_Series_Tape_Drive": 1000258,
    "SNMP_Trap_-_Riverbed_SteelCentral_NetShark": 1000508,
    "SNMP_Trap_-_RSA_Authentication_Manager": 1000248,
    "SNMP_Trap_-_Swift_Alliance": 1000405,
    "SNMP_Trap_-_Trend_Micro_Control_Manager": 1000413,
    "Syslog_-_3Com_Switch": 1000329,
    "Syslog_-_A10_Networks_AX1000_Load_Balancer": 1000268,
    "Syslog_-_A10_Networks_Web_Application_Firewall": 1000785,
    "Syslog_-_Accellion_Secure_File_Transfer_Application": 1000665,
    "Syslog_-_Active_Scout_IPS": 128,
    "Syslog_-_Adallom": 1000585,
    "Syslog_-_Adtran_Switch": 1000284,
    "Syslog_-_Aerohive_Access_Point": 1000467,
    "Syslog_-_Aerohive_Firewall": 1000677,
    "Syslog_-_AIMIA_Tomcat": 1000635,
    "Syslog_-_AirDefense_Enterprise": 182,
    "Syslog_-_Airmagnet_Wireless_IDS": 177,
    "Syslog_-_AirTight_IDS/IPS": 145,
    "Syslog_-_AirWatch_MDM": 1000594,
    "Syslog_-_Airwave_Management_System_Log": 150,
    "Syslog_-_AIX_Host": 90,
    "Syslog_-_Alcatel-Lucent_Switch": 1000756,
    "Syslog_-_Alcatel-Lucent_Wireless_Controller": 1000425,
    "Syslog_-_AlertLogic": 1000742,
    "Syslog_-_AMX_AV_Controller": 27,
    "Syslog_-_Apache_Access_Log": 1000255,
    "Syslog_-_Apache_Error_Log": 1000254,
    "Syslog_-_Apache_Tomcat_Request_Parameters": 110,
    "Syslog_-_Apache_Tomcat_Service_Clients_Log": 1000418,
    "Syslog_-_APC_ATS": 1000400,
    "Syslog_-_APC_NetBotz_Environmental_Monitoring": 1000348,
    "Syslog_-_APC_PDU": 1000416,
    "Syslog_-_APC_UPS": 1000200,
    "Syslog_-_Apcon_Network_Monitor": 1000491,
    "Syslog_-_Apex_One": 1000832,
    "Syslog_-_Arbor_Networks_Peakflow": 1000477,
    "Syslog_-_Arbor_Networks_Spectrum": 1000708,
    "Syslog_-_Arbor_Pravail_APS": 1000464,
    "Syslog_-_Arista_Switch": 1000410,
    "Syslog_-_Array_TMX_Load_Balancer": 1000525,
    "Syslog_-_Arris_CMTS": 1000230,
    "Syslog_-_Aruba_Clear_Pass": 1000502,
    "Syslog_-_Aruba_Mobility_Controller": 144,
    "Syslog_-_Aruba_Wireless_Access_Point": 1000529,
    "Syslog_-_AS/400_via_Powertech_Interact": 178,
    "Syslog_-_Asus_WRT_Router": 1000679,
    "Syslog_-_Avatier_Identity_Management_Suite_(AIMS)": 1000780,
    "Syslog_-_Avaya_Communications_Manager": 1000459,
    "Syslog_-_Avaya_Ethernet_Routing_Switch": 1000482,
    "Syslog_-_Avaya_G450_Media_Gateway": 1000680,
    "Syslog_-_Avaya_Router": 1000581,
    "Syslog_-_Aventail_SSL/VPN": 1000132,
    "Syslog_-_Avocent_Cyclades_Terminal_Server": 1000396,
    "Syslog_-_Azul_Java_Appliance": 1000217,
    "Syslog_-_Barracuda_Load_Balancer": 1000370,
    "Syslog_-_Barracuda_Mail_Archiver": 1000492,
    "Syslog_-_Barracuda_NG_Firewall": 1000442,
    "Syslog_-_Barracuda_NG_Firewall_6.x": 1000613,
    "Syslog_-_Barracuda_Spam_Firewall": 132,
    "Syslog_-_Barracuda_Web_Application_Firewall": 1000342,
    "Syslog_-_Barracuda_Webfilter": 140,
    "Syslog_-_BeyondTrust_BeyondInsight_LEEF": 1000778,
    "Syslog_-_Bind_DNS": 1000621,
    "Syslog_-_Bit9_Parity_Suite": 1000215,
    "Syslog_-_Bit9_Security_Platform_CEF": 1000622,
    "Syslog_-_Bit9+Carbon_Black_(Deprecated)": 1000620,
    "Syslog_-_BitDefender": 1000597,
    "Syslog_-_Black_Diamond_Switch": 1000004,
    "Syslog_-_Blue_Coat_CAS": 1000739,
    "Syslog_-_Blue_Coat_Forward_Proxy": 1000509,
    "Syslog_-_Blue_Coat_PacketShaper": 1000392,
    "Syslog_-_Blue_Coat_ProxyAV_ISA_W3C_Format": 1000126,
    "Syslog_-_Blue_Coat_ProxyAV_MS_Proxy_2.0_Format": 1000143,
    "Syslog_-_Blue_Coat_ProxySG": 166,
    "Syslog_-_Blue_Socket_Wireless_Controller": 1000451,
    "Syslog_-_Bluecat_Adonis": 1000438,
    "Syslog_-_BlueCedar": 1000753,
    "Syslog_-_BluVector": 1000769,
    "Syslog_-_Bomgar": 1000347,
    "Syslog_-_Bradford_Networks_NAC": 1000553,
    "Syslog_-_Bradford_Remediation_&_Registration_Svr": 155,
    "Syslog_-_Bro_IDS": 1000723,
    "Syslog_-_Brocade_Switch": 183,
    "Syslog_-_Bromium_vSentry_CEF": 1000513,
    "Syslog_-_BSD_Host": 117,
    "Syslog_-_CA_Privileged_Access_Manager": 1000808,
    "Syslog_-_Cb_Defense_CEF": 1000702,
    "Syslog_-_Cb_Protection_CEF": 1000420,
    "Syslog_-_Cb_Response_LEEF": 1000651,
    "Syslog_-_Cell_Relay": 1000407,
    "Syslog_-_Certes_Networks_CEP": 1000445,
    "Syslog_-_Check_Point_Log_Exporter": 1000806,
    "Syslog_-_Checkpoint_Site-to-Site_VPN": 1000376,
    "Syslog_-_Cisco_ACS": 1000063,
    "Syslog_-_Cisco_Aironet_WAP": 1000002,
    "Syslog_-_Cisco_APIC": 1000764,
    "Syslog_-_Cisco_Application_Control_Engine": 1000130,
    "Syslog_-_Cisco_ASA": 5,
    "Syslog_-_Cisco_Clean_Access_(CCA)_Appliance": 1000201,
    "Syslog_-_Cisco_CSS_Load_Balancer": 1000064,
    "Syslog_-_Cisco_Email_Security_Appliance": 1000021,
    "Syslog_-_Cisco_FirePOWER": 1000683,
    "Syslog_-_Cisco_Firepower_Threat_Defense": 18,
    "Syslog_-_Cisco_FireSIGHT": 1000595,
    "Syslog_-_Cisco_FWSM": 163,
    "Syslog_-_Cisco_Global_Site_Selector": 1000068,
    "Syslog_-_Cisco_ISE": 1000369,
    "Syslog_-_Cisco_Meraki": 1000530,
    "Syslog_-_Cisco_Nexus_Switch": 1000225,
    "Syslog_-_Cisco_PIX": 1000000003,
    "Syslog_-_Cisco_Prime_Infrastructure": 1000500,
    "Syslog_-_Cisco_Router": 86,
    "Syslog_-_Cisco_Secure_ACS_5": 1000206,
    "Syslog_-_Cisco_Session_Border_Controller": 11,
    "Syslog_-_Cisco_Switch": 85,
    "Syslog_-_Cisco_Telepresence_Video_Communications_Server": 1000657,
    "Syslog_-_Cisco_UCS": 1000391,
    "Syslog_-_Cisco_Unified_Comm_Mgr_(Call_Mgr)": 1000133,
    "Syslog_-_Cisco_VPN_Concentrator": 116,
    "Syslog_-_Cisco_WAAS": 1000333,
    "Syslog_-_Cisco_Web_Security": 1000390,
    "Syslog_-_Cisco_Wireless_Access_Point": 1000394,
    "Syslog_-_Cisco_Wireless_Control_System": 1000101,
    "Syslog_-_CiscoWorks": 1000260,
    "Syslog_-_Citrix_Access_Gateway_Server": 1000403,
    "Syslog_-_Citrix_Netscaler": 25,
    "Syslog_-_Citrix_XenServer": 1000257,
    "Syslog_-_Claroty_CTD_CEF": 1000801,
    "Syslog_-_Clearswift_Secure_Email_Gateway": 1000747,
    "Syslog_-_CloudLock": 1000659,
    "Syslog_-_CodeGreen_Data_Loss_Prevention": 1000097,
    "Syslog_-_Cofense_Triage_CEF": 1000632,
    "Syslog_-_Consentry_NAC": 165,
    "Syslog_-_Corero_IPS": 1000431,
    "Syslog_-_Corero_SmartWall_DDoS": 22,
    "Syslog_-_CoyotePoint_Equalizer": 1000289,
    "Syslog_-_Crowdstrike_Falconhost_CEF": 1000682,
    "Syslog_-_CyberArk": 1000325,
    "Syslog_-_CyberArk_Privileged_Threat_Analytics": 1000652,
    "Syslog_-_Cylance_CEF": 1000813,
    "Syslog_-_CylancePROTECT": 1000625,
    "Syslog_-_DarkTrace_CEF": 1000710,
    "Syslog_-_Dell_Force_10": 1000423,
    "Syslog_-_Dell_PowerConnect_Switch": 1000118,
    "Syslog_-_Dell_Remote_Access_Controller": 1000324,
    "Syslog_-_Dell_SecureWorks_iSensor_IPS": 1000554,
    "Syslog_-_Dialogic_Media_Gateway": 1000125,
    "Syslog_-_Digital_Guardian_CEF": 1000800,
    "Syslog_-_D-Link_Switch": 1000504,
    "Syslog_-_Don_not_use": 1000827,
    "Syslog_-_Dragos_Platform_CEF": 1000852,
    "Syslog_-_Ecessa_ShieldLink": 1000282,
    "Syslog_-_EfficientIP": 7,
    "Syslog_-_EMC_Avamar": 1000556,
    "Syslog_-_EMC_Centera": 1000490,
    "Syslog_-_EMC_Data_Domain": 1000551,
    "Syslog_-_EMC_Isilon": 20,
    "Syslog_-_EMC_Unity_Array": 1000751,
    "Syslog_-_EMC_VNX": 1000432,
    "Syslog_-_Ensilo_NGAV": 1000830,
    "Syslog_-_Enterasys_Dragon_IDS": 1000131,
    "Syslog_-_Enterasys_Router": 123,
    "Syslog_-_Enterasys_Switch": 124,
    "Syslog_-_Entrust_Entelligence_Messaging_Server": 1000462,
    "Syslog_-_Entrust_IdentityGuard": 1000234,
    "Syslog_-_Epic_Hyperspace_CEF": 1000668,
    "Syslog_-_EqualLogic_SAN": 189,
    "Syslog_-_eSafe_Email_Security": 1000366,
    "Syslog_-_ESET_Remote_Administrator_(ERA)_LEEF": 1000754,
    "Syslog_-_Event_Reporter_(Win_2000/XP/2003)": 1000046,
    "Syslog_-_Exabeam": 3,
    "Syslog_-_Exchange_Message_Tracking": 6,
    "Syslog_-_ExtraHop": 1000795,
    "Syslog_-_Extreme_Wireless_LAN": 1000058,
    "Syslog_-_ExtremeWare": 1000318,
    "Syslog_-_ExtremeXOS": 1000317,
    "Syslog_-_F5_BIG-IP_Access_Policy_Manager": 1000676,
    "Syslog_-_F5_BIG-IP_AFM": 1000771,
    "Syslog_-_F5_BIG-IP_ASM": 1000236,
    "Syslog_-_F5_BIG-IP_ASM_Key-Value_Pairs": 1000749,
    "Syslog_-_F5_BIG-IP_ASM_v12": 1000709,
    "Syslog_-_F5_Big-IP_GTM_&_DNS": 188,
    "Syslog_-_F5_Big-IP_LTM": 1000335,
    "Syslog_-_F5_FirePass_Firewall": 179,
    "Syslog_-_F5_Silverline_DDoS_Protection": 1000799,
    "Syslog_-_Fargo_HDP_Card_Printer_and_Encoder": 1000358,
    "Syslog_-_Fat_Pipe_Load_Balancer": 1000807,
    "Syslog_-_Fidelis_XPS": 1000104,
    "Syslog_-_FireEye_E-Mail_MPS": 1000542,
    "Syslog_-_FireEye_EX": 1000831,
    "Syslog_-_FireEye_Web_MPS/CMS/ETP/HX": 1000359,
    "Syslog_-_Forcepoint_DLP": 1000321,
    "Syslog_-_Forcepoint_Email_Security_Gateway": 1000591,
    "Syslog_-_Forcepoint_Stonesoft_NGFW": 1000675,
    "Syslog_-_Forcepoint_SureView_Insider_Threat": 1000660,
    "Syslog_-_Forcepoint_Web_Security": 1000375,
    "Syslog_-_Forcepoint_Web_Security_CEF_Format": 1000452,
    "Syslog_-_Forescout_CounterACT_NAC": 1000157,
    "Syslog_-_Fortinet_FortiAnalyzer": 1000811,
    "Syslog_-_Fortinet_FortiAuthenticator": 1000846,
    "Syslog_-_Fortinet_FortiDDoS": 1000782,
    "Syslog_-_Fortinet_FortiGate": 130,
    "Syslog_-_Fortinet_FortiGate_v4.0": 1000199,
    "Syslog_-_Fortinet_FortiGate_v5.0": 1000426,
    "Syslog_-_Fortinet_FortiGate_v5.2": 1000567,
    "Syslog_-_Fortinet_FortiGate_v5.4/v5.6": 1000700,
    "Syslog_-_Fortinet_FortiGate_v5.6_CEF": 1000722,
    "Syslog_-_Fortinet_Fortigate_v6.0": 1000774,
    "Syslog_-_Fortinet_FortiMail": 1000536,
    "Syslog_-_Fortinet_FortiWeb": 1000493,
    "Syslog_-_Foundry_Switch": 1000050,
    "Syslog_-_Gene6_FTP": 153,
    "Syslog_-_Generic_CEF": 1000725,
    "Syslog_-_Generic_ISC_DHCP": 1000088,
    "Syslog_-_Generic_LEEF": 1000728,
    "Syslog_-_Guardium_Database_Activity_Monitor": 1000326,
    "Syslog_-_H3C_Router": 1000243,
    "Syslog_-_Hitachi_Universal_Storage_Platform": 1000398,
    "Syslog_-_HP_BladeSystem": 1000439,
    "Syslog_-_HP_iLO": 1000616,
    "Syslog_-_HP_Procurve_Switch": 160,
    "Syslog_-_HP_Router": 1000057,
    "Syslog_-_HP_Switch": 1000444,
    "Syslog_-_HP_Unix_Tru64": 1000096,
    "Syslog_-_HP_Virtual_Connect_Switch": 1000350,
    "Syslog_-_HP-UX_Host": 89,
    "Syslog_-_Huawei_Access_Router": 1000541,
    "Syslog_-_IBM_Blade_Center": 1000401,
    "Syslog_-_IBM_Security_Network_Protection": 1000521,
    "Syslog_-_IBM_Virtual_Tape_Library_Server": 1000511,
    "Syslog_-_IBM_WebSphere_DataPower_Integration": 1000441,
    "Syslog_-_IBM_zSecure_Alert_for_ACF2_2.1.0": 1000590,
    "Syslog_-_IceWarp_Server": 1000267,
    "Syslog_-_Imperva_Incapsula_CEF": 1000763,
    "Syslog_-_Imperva_SecureSphere": 1000135,
    "Syslog_-_Imprivata_OneSign_SSO": 1000693,
    "Syslog_-_InfoBlox": 1000089,
    "Syslog_-_Invincea_(LEEF)": 1000626,
    "Syslog_-_iPrism_Proxy_Log": 1000095,
    "Syslog_-_IPSWITCH_MOVEit_Server": 1000573,
    "Syslog_-_IPTables": 1000364,
    "Syslog_-_IRIX_Host": 118,
    "Syslog_-_iSeries_via_Powertech_Interact": 184,
    "Syslog_-_Ivanti_FileDirector": 16,
    "Syslog_-_JetNexus_Load_Balancer": 1000332,
    "Syslog_-_Juniper_DX_Application_Accelerator": 1000147,
    "Syslog_-_Juniper_Firewall": 1000045,
    "Syslog_-_Juniper_Firewall_3400": 1000601,
    "Syslog_-_Juniper_Host_Checker": 1000082,
    "Syslog_-_Juniper_IDP": 1000053,
    "Syslog_-_Juniper_NSM": 1000242,
    "Syslog_-_Juniper_Router": 1000026,
    "Syslog_-_Juniper_SSL_VPN": 186,
    "Syslog_-_Juniper_SSL_VPN_WELF_Format": 1000111,
    "Syslog_-_Juniper_Switch": 1000037,
    "Syslog_-_Juniper_Trapeze": 1000343,
    "Syslog_-_Juniper_vGW_Virtual_Gateway": 1000448,
    "Syslog_-_Kaspersky_Security_Center": 1000797,
    "Syslog_-_Kea_DHCP_Server": 10,
    "Syslog_-_Kemp_Load_Balancer": 1000412,
    "Syslog_-_KFSensor_Honeypot": 1000672,
    "Syslog_-_KFSensor_Honeypot_CEF": 1000691,
    "Syslog_-_Lancope_StealthWatch": 1000393,
    "Syslog_-_Lancope_StealthWatch_CEF": 1000698,
    "Syslog_-_Layer_7_SecureSpan_SOA_Gateway": 1000427,
    "Syslog_-_Legacy_Checkpoint_Firewall_(Not_Log_Exporter)": 1000434,
    "Syslog_-_Legacy_Checkpoint_IPS_(Not_Log_Exporter)": 1000103,
    "Syslog_-_Lieberman_Enterprise_Random_Password_Manager": 1000353,
    "Syslog_-_Linux_Audit": 1000139,
    "Syslog_-_Linux_Host": 13,
    "Syslog_-_Linux_TACACS_Plus": 23,
    "Syslog_-_LOGbinder_EX": 1000533,
    "Syslog_-_LOGbinder_SP": 1000408,
    "Syslog_-_LOGbinder_SQL": 1000555,
    "Syslog_-_LogRhythm_Data_Indexer_Monitor": 1000653,
    "Syslog_-_LogRhythm_Inter_Deployment_Data_Sharing": 1000815,
    "Syslog_-_LogRhythm_Log_Distribution_Services": 1000840,
    "Syslog_-_LogRhythm_Network_Monitor": 197,
    "Syslog_-_LogRhythm_Syslog_Generator": 105,
    "Syslog_-_Lumension": 1000608,
    "Syslog_-_MacOS_X": 1000144,
    "Syslog_-_Malwarebytes_Endpoint_Security_CEF": 1000773,
    "Syslog_-_Mandiant_MIR": 1000489,
    "Syslog_-_McAfee_Advanced_Threat_Defense": 1000617,
    "Syslog_-_McAfee_Email_And_Web_Security": 1000051,
    "Syslog_-_McAfee_ePO": 1000866,
    "Syslog_-_McAfee_Firewall_Enterprise": 1000001,
    "Syslog_-_McAfee_Network_Security_Manager": 1000036,
    "Syslog_-_McAfee_Secure_Internet_Gateway": 136,
    "Syslog_-_McAfee_SecureMail": 1000092,
    "Syslog_-_McAfee_Skyhigh_for_Shadow_IT_LEEF": 1000644,
    "Syslog_-_McAfee_Web_Gateway": 1000612,
    "Syslog_-_mGuard_Firewall": 1000711,
    "Syslog_-_Microsoft_Advanced_Threat_Analytics_(ATA)_CEF": 1000731,
    "Syslog_-_Microsoft_Azure_Log_Integration": 1000733,
    "Syslog_-_Microsoft_Azure_MFA": 1000707,
    "Syslog_-_Microsoft_Forefront_UAG": 1000461,
    "Syslog_-_Mirapoint": 1000228,
    "Syslog_-_MobileIron": 1000497,
    "Syslog_-_Motorola_Access_Point": 1000313,
    "Syslog_-_MS_IIS_Web_Log_W3C_Format_(Snare)": 1000027,
    "Syslog_-_MS_Windows_Event_Logging_XML_-_Application": 1000783,
    "Syslog_-_MS_Windows_Event_Logging_XML_-_Security": 1000669,
    "Syslog_-_MS_Windows_Event_Logging_XML_-_System": 1000671,
    "Syslog_-_Nagios": 1000319,
    "Syslog_-_nCircle_Configuration_Compliance_Manager": 1000430,
    "Syslog_-_NetApp_Filer": 1000108,
    "Syslog_-_NETASQ_Firewall": 1000485,
    "Syslog_-_NetGate_Router": 1000527,
    "Syslog_-_NetMotion_VPN": 1000592,
    "Syslog_-_Netscout_nGenius_InfiniStream": 1000481,
    "Syslog_-_NetScreen_Firewall": 107,
    "Syslog_-_Netskope": 1000736,
    "Syslog_-_Netskope_CEF": 1000853,
    "Syslog_-_Network_Chemistry_RFprotect": 108,
    "Syslog_-_Nginx_Web_Log": 1000584,
    "Syslog_-_Nimble_Storage": 1000727,
    "Syslog_-_Nortel_8600_Switch": 1000081,
    "Syslog_-_Nortel_BayStack_Switch": 171,
    "Syslog_-_Nortel_Contivity": 1000153,
    "Syslog_-_Nortel_Firewall": 168,
    "Syslog_-_Nortel_IP_1220": 1000205,
    "Syslog_-_Nortel_Passport_Switch": 169,
    "Syslog_-_Nozomi_Networks_Guardian_CEF": 1000819,
    "Syslog_-_NuSecure_Gateway": 1000198,
    "Syslog_-_Nutanix": 26,
    "Syslog_-_Open_Collector": 1000759,
    "Syslog_-_Open_Collector_-_AWS_CloudTrail": 1000786,
    "Syslog_-_Open_Collector_-_AWS_CloudWatch": 1000789,
    "Syslog_-_Open_Collector_-_AWS_Config_Events": 1000790,
    "Syslog_-_Open_Collector_-_AWS_Guard_Duty": 1000791,
    "Syslog_-_Open_Collector_-_AWS_S3": 1000802,
    "Syslog_-_Open_Collector_-_Azure_Event_Hub": 1000772,
    "Syslog_-_Open_Collector_-_Carbon_Black_Cloud": 1000861,
    "Syslog_-_Open_Collector_-_CarbonBlackBeat_Heartbeat": 1000864,
    "Syslog_-_Open_Collector_-_Cisco_AMP": 1000842,
    "Syslog_-_Open_Collector_-_Cisco_Umbrella": 1000787,
    "Syslog_-_Open_Collector_-_CiscoAMPBeat_Heartbeat": 1000843,
    "Syslog_-_Open_Collector_-_Duo_Authentication_Security": 1000854,
    "Syslog_-_Open_Collector_-_DuoBeat_Heartbeat": 1000855,
    "Syslog_-_Open_Collector_-_EventHubBeat_Heartbeat": 1000833,
    "Syslog_-_Open_Collector_-_GCP_Audit": 1000817,
    "Syslog_-_Open_Collector_-_GCP_Cloud_Key_Management_Service": 1000820,
    "Syslog_-_Open_Collector_-_GCP_Http_Load_Balancer": 1000839,
    "Syslog_-_Open_Collector_-_GCP_Pub_Sub": 1000812,
    "Syslog_-_Open_Collector_-_GCP_Security_Command_Center": 1000816,
    "Syslog_-_Open_Collector_-_GCP_Virtual_Private_Cloud": 1000821,
    "Syslog_-_Open_Collector_-_Gmail_Message_Tracking": 1000823,
    "Syslog_-_Open_Collector_-_GMTBeat_Heartbeat": 1000834,
    "Syslog_-_Open_Collector_-_GSuite": 1000758,
    "Syslog_-_Open_Collector_-_GSuiteBeat_Heartbeat": 1000838,
    "Syslog_-_Open_Collector_-_Metricbeat": 1000841,
    "Syslog_-_Open_Collector_-_Okta_System_Log": 1000863,
    "Syslog_-_Open_Collector_-_OktaSystemLogBeat_Heartbeat": 1000865,
    "Syslog_-_Open_Collector_-_PubSubBeat_Heartbeat": 1000836,
    "Syslog_-_Open_Collector_-_S3Beat_Heartbeat": 1000835,
    "Syslog_-_Open_Collector_-_Sophos_Central": 1000814,
    "Syslog_-_Open_Collector_-_SophosCentralBeat_Heartbeat": 1000837,
    "Syslog_-_Open_Collector_-_Webhook": 1000850,
    "Syslog_-_Open_Collector_-_Webhook_OneLogin": 1000848,
    "Syslog_-_Open_Collector_-_Webhook_Zoom": 1000849,
    "Syslog_-_Open_Collector_-_WebhookBeat_Heartbeat": 1000851,
    "Syslog_-_Opengear_Console": 28,
    "Syslog_-_OpenLDAP": 1000305,
    "Syslog_-_Oracle_10g_Audit_Trail": 1000071,
    "Syslog_-_Oracle_11g_Audit_Trail": 1000223,
    "Syslog_-_OSSEC_Alerts": 1000218,
    "Syslog_-_Other": 92,
    "Syslog_-_Outpost24": 1000414,
    "Syslog_-_Palo_Alto_Cortex_XDR": 1000867,
    "Syslog_-_Palo_Alto_Custom_Pipe": 15,
    "Syslog_-_Palo_Alto_Firewall": 1000134,
    "Syslog_-_Palo_Alto_Traps_CEF": 1000729,
    "Syslog_-_Palo_Alto_Traps_Management_Service": 1000796,
    "Syslog_-_Password_Manager_Pro": 21,
    "Syslog_-_pfSense_Firewall": 1000740,
    "Syslog_-_PingFederate_7.2": 1000631,
    "Syslog_-_PingFederate_CEF": 1000770,
    "Syslog_-_Polycom": 1000362,
    "Syslog_-_Postfix": 1000105,
    "Syslog_-_Procera_PacketLogic": 9,
    "Syslog_-_Proofpoint_Spam_Firewall": 141,
    "Syslog_-_Protegrity_Defiance_DPS": 1000085,
    "Syslog_-_QLogic_Infiniband_Switch": 1000449,
    "Syslog_-_Quest_Defender": 1000328,
    "Syslog_-_Radiator_Radius": 4,
    "Syslog_-_RADiFlow_3180_Switch": 1000498,
    "Syslog_-_Radware_Alteon_Load_Balancer": 1000245,
    "Syslog_-_Radware_DefensePro": 1000241,
    "Syslog_-_Radware_Web_Server_Director_Audit_Log": 1000344,
    "Syslog_-_Raritan_KVM": 1000279,
    "Syslog_-_Raz-Lee": 1000428,
    "Syslog_-_RedSeal": 1000547,
    "Syslog_-_Riverbed": 1000156,
    "Syslog_-_RSA_ACE": 190,
    "Syslog_-_RSA_Authentication_Manager_v7.1": 1000233,
    "Syslog_-_RSA_Authentication_Manager_v8.x": 1000656,
    "Syslog_-_RSA_Web_Threat_Detection": 1000512,
    "Syslog_-_RSA_Web_Threat_Detection_5.1": 1000574,
    "Syslog_-_RuggedRouter": 1000093,
    "Syslog_-_Safenet": 1000074,
    "Syslog_-_Sailpoint": 1000640,
    "Syslog_-_Sauce_Labs": 1000704,
    "Syslog_-_SecureAuth_IdP": 1000443,
    "Syslog_-_SecureAuth_IdP_v9": 1000713,
    "Syslog_-_SecureLink": 1000793,
    "Syslog_-_SecureTrack": 1000249,
    "Syslog_-_SEL_3610_Port_Switch": 1000273,
    "Syslog_-_SEL_3620_Ethernet_Security_Gateway": 1000246,
    "Syslog_-_Sentinel_IPS": 1000460,
    "Syslog_-_SentinelOne_CEF": 1000712,
    "Syslog_-_Sguil": 1000719,
    "Syslog_-_Siemens_Scalance_X400": 1000473,
    "Syslog_-_Smoothwall_Firewall": 1000435,
    "Syslog_-_SnapGear_Firewall": 1000409,
    "Syslog_-_Snare_Windows_2003_Event_Log": 1000028,
    "Syslog_-_Snare_Windows_2008_Event_Log": 19,
    "Syslog_-_Snort_IDS": 1000019,
    "Syslog_-_Solaris_(Snare)": 120,
    "Syslog_-_Solaris_Host": 91,
    "Syslog_-_SonicWALL": 106,
    "Syslog_-_SonicWALL_SSL-VPN": 137,
    "Syslog_-_Sophos_Email_Encryption_Appliance": 1000336,
    "Syslog_-_Sophos_UTM": 113,
    "Syslog_-_Sophos_Web_Proxy": 1000399,
    "Syslog_-_Sophos_XG_Firewall": 1000792,
    "Syslog_-_Sourcefire_IDS_3D": 1000080,
    "Syslog_-_Sourcefire_RNA": 1000340,
    "Syslog_-_Spectracom_Network_Time_Server": 1000463,
    "Syslog_-_Splunk_API_-_Checkpoint_Firewall": 1000689,
    "Syslog_-_Splunk_API_-_Cisco_Netflow_V9": 1000697,
    "Syslog_-_Splunk_API_-_Nessus_Vulnerability_Scanner": 1000692,
    "Syslog_-_Squid_Proxy": 2,
    "Syslog_-_StealthBits_Activity_Monitor": 1000844,
    "Syslog_-_STEALTHbits_StealthINTERCEPT": 1000737,
    "Syslog_-_StoneGate_Firewall": 1000291,
    "Syslog_-_Stonesoft_IPS": 1000480,
    "Syslog_-_Stormshield_Network_Security_Firewall": 1000650,
    "Syslog_-_Sycamore_Networks_DNX-88": 1000588,
    "Syslog_-_Sygate_Firewall": 180,
    "Syslog_-_Symantec_Advanced_Threat_Protection_(ATP)_CEF": 1000798,
    "Syslog_-_Symantec_DLP_CEF": 181,
    "Syslog_-_Symantec_Endpoint_Server": 1000077,
    "Syslog_-_Symantec_Messaging_Gateway": 1000828,
    "Syslog_-_Symantec_PGP_Gateway": 1000387,
    "Syslog_-_Symbol_Wireless_Access_Point": 114,
    "Syslog_-_Tanium": 1000674,
    "Syslog_-_Temporary_LST-2": 1000699,
    "Syslog_-_Tenable_SecurityCenter": 1000534,
    "Syslog_-_Thycotic_Secret_Server": 1000519,
    "Syslog_-_Tipping_Point_IPS": 143,
    "Syslog_-_Tipping_Point_SSL_Reverse_Proxy": 1000339,
    "Syslog_-_Top_Layer_IPS": 1000048,
    "Syslog_-_Townsend_Alliance_LogAgent": 1000213,
    "Syslog_-_Trend_Micro_Control_Manager_CEF": 1000750,
    "Syslog_-_Trend_Micro_Deep_Discovery_Inspector": 1000580,
    "Syslog_-_Trend_Micro_Deep_Security_CEF": 1000388,
    "Syslog_-_Trend_Micro_Deep_Security_LEEF": 1000804,
    "Syslog_-_Trend_Micro_IWSVA": 1000330,
    "Syslog_-_Trend_Micro_Vulnerability_Protection_Manager": 1000803,
    "Syslog_-_Tripwire": 192,
    "Syslog_-_Trustwave_NAC": 1000596,
    "Syslog_-_Trustwave_Secure_Web_Gateway": 1000499,
    "Syslog_-_Trustwave_Web_Application_Firewall": 1000065,
    "Syslog_-_Tufin": 1000684,
    "Syslog_-_Tumbleweed_Mailgate_Server": 1000078,
    "Syslog_-_Ubiquiti_UniFi_Security_Gateway": 1000760,
    "Syslog_-_Ubiquiti_UniFi_Switch": 1000757,
    "Syslog_-_Ubiquiti_UniFi_WAP": 1000762,
    "Syslog_-_Untangle": 1000365,
    "Syslog_-_Vamsoft_ORF": 1000458,
    "Syslog_-_Vanguard_Active_Alerts": 1000694,
    "Syslog_-_Varonis_DatAlert": 1000544,
    "Syslog_-_Vasco_Digipass_Identikey_Server": 1000503,
    "Syslog_-_Vectra_Networks": 1000779,
    "Syslog_-_Versa_Networks_SD-WAN": 1000824,
    "Syslog_-_VMWare_ESX/ESXi_Server": 1000000,
    "Syslog_-_VMware_Horizon_View": 1000603,
    "Syslog_-_VMWare_NSX/NSX-T": 1000768,
    "Syslog_-_VMWare_Unified_Access_Gateway": 1000871,
    "Syslog_-_VMWare_vCenter_Server": 1000752,
    "Syslog_-_VMWare_vShield": 1000487,
    "Syslog_-_Voltage_Securemail": 1000543,
    "Syslog_-_Vormetric_CoreGuard": 1000210,
    "Syslog_-_Vormetric_Data_Security_Manager": 1000486,
    "Syslog_-_WALLIX_Bastion": 1000765,
    "Syslog_-_Watchguard_FireBox": 129,
    "Syslog_-_WS2000_Wireless_Access_Point": 1000076,
    "Syslog_-_Wurldtech_SmartFirewall": 198,
    "Syslog_-_Xirrus_Wireless_Array": 1000197,
    "Syslog_-_Zimbra_System_Log": 1000100,
    "Syslog_-_Zix_E-mail_Encryption": 1000654,
    "Syslog_-_Zscaler_Nano_Streaming_Service": 1000546,
    "Syslog_-_ZXT_Load_Balancer": 1000411,
    "Syslog_-_ZyWALL_VPN_Firewall": 1000666,
    "Syslog_Avaya_G450_Media_Gateway": 1000670,
    "Syslog_File_-_AIX_Host": 1000006,
    "Syslog_File_-_BSD_Format": 35,
    "Syslog_File_-_HP-UX_Host": 1000145,
    "Syslog_File_-_IRIX_Host": 1000295,
    "Syslog_File_-_Linux_Host": 103,
    "Syslog_File_-_LogRhythm_Syslog_Generator": 13,
    "Syslog_File_-_MS_2003_Event_Log_(Snare)": 1000039,
    "Syslog_File_-_Oracle_10g_Audit_Trail": 1000072,
    "Syslog_File_-_Oracle_11g_Audit_Trail": 1000222,
    "Syslog_File_-_Solaris_Host": 104,
    "UDLA_-_CA_Single_Sign-On": 1000636,
    "UDLA_-_Deepnet_DualShield": 1000286,
    "UDLA_-_Drupal": 1000496,
    "UDLA_-_Finacle_Core": 1000196,
    "UDLA_-_Finacle_Treasury_Logs": 1000178,
    "UDLA_-_Forcepoint": 1000020,
    "UDLA_-_Gallagher_Command_Centre": 1000810,
    "UDLA_-_iManage_Worksite": 1000732,
    "UDLA_-_ISS_Proventia_SiteProtector_-_IPS": 1000034,
    "UDLA_-_LogRhythm_Enterprise_Monitoring_Solution": 1000314,
    "UDLA_-_LREnhancedAudit": 1000548,
    "UDLA_-_McAfee_ePolicy_Orchestrator_-_Universal_ePOEvents": 1000788,
    "UDLA_-_McAfee_ePolicy_Orchestrator_3.6_-_Events": 158,
    "UDLA_-_McAfee_ePolicy_Orchestrator_4.0_-_ePOEvents": 1000079,
    "UDLA_-_McAfee_ePolicy_Orchestrator_4.5_-_ePOEvents": 1000175,
    "UDLA_-_McAfee_ePolicy_Orchestrator_5.0_-_ePOEvents": 1000531,
    "UDLA_-_McAfee_ePolicy_Orchestrator_5.1_-_ePOEvents": 1000550,
    "UDLA_-_McAfee_ePolicy_Orchestrator_5.3_-_ePOEvents": 1000696,
    "UDLA_-_McAfee_ePolicy_Orchestrator_5.9_-_ePOEvents": 1000761,
    "UDLA_-_McAfee_Network_Access_Control": 1000055,
    "UDLA_-_McAfee_Network_Security_Manager": 1000453,
    "UDLA_-_Microsoft_System_Center_2012_Endpoint_Protection": 1000587,
    "UDLA_-_ObserveIT": 1000605,
    "UDLA_-_Oracle_10g_Audit_Trail": 152,
    "UDLA_-_Oracle_11g_Audit_Trail": 1000171,
    "UDLA_-_Oracle_12C_Unified_Auditing": 1000658,
    "UDLA_-_Oracle_9i_Audit_Trail": 1000040,
    "UDLA_-_Other": 1000576,
    "UDLA_-_SEL_3530_RTAC": 1000285,
    "UDLA_-_SharePoint_2007_AuditData": 1000208,
    "UDLA_-_SharePoint_2010_EventData": 1000415,
    "UDLA_-_SharePoint_2013_EventData": 1000606,
    "UDLA_-_Siemens_Invision": 1000229,
    "UDLA_-_Sophos_Anti-Virus": 1000090,
    "UDLA_-_Sophos_Endpoint_Security_and_Control": 1000735,
    "UDLA_-_Symantec_CSP": 1000505,
    "UDLA_-_Symantec_SEP": 1000520,
    "UDLA_-_Symmetry_Access_Control": 1000270,
    "UDLA_-_VMWare_vCenter_Server": 1000378,
    "UDLA_-_VMWare_vCloud": 1000538,
    "VLS_-_Syslog_-_Infoblox_-_DNS_RPZ": 1000643,
    "VLS_-_Syslog_-_Infoblox_-_Threat_Protection": 1000642
}

''' HELPER FUNCTIONS '''


def fix_date_values(item):
    date_keys = ['normalDateMin', 'normalDate', 'normalMsgDateMax', 'logDate']

    for key in date_keys:
        if item.get(key):
            item[key] = datetime.fromtimestamp(item.get(key) / 1000.0).\
                strftime('%Y-%m-%d %H:%M:%S')


def fix_location_value(items):
    for item in items:
        location_val = str(item.get('location'))
        if location_val == '{u\'id\': -1}':
            item['location'] = 'NA'

    return items


def get_time_frame(time_frame, start_arg, end_arg):
    start = datetime.now()
    end = datetime.now()

    if time_frame == 'Today':
        start = datetime(end.year, end.month, end.day)
    elif time_frame == 'Last2Days':
        start = end - timedelta(days=2)
    elif time_frame == 'LastWeek':
        start = end - timedelta(days=7)
    elif time_frame == 'LastMonth':
        start = end - timedelta(days=30)
    elif time_frame == 'Custom':
        if not start_arg:
            return_error('start-date argument is missing')
        if not end_arg:
            return_error('end-date argument is missing')
        start = datetime.strptime(start_arg, '%Y-%m-%d')
        end = datetime.strptime(end_arg, '%Y-%m-%d')

    return start, end


def http_request(method, url_suffix, data=None, headers=HEADERS):
    try:
        res = requests.request(
            method,
            urljoin(BASE_URL, url_suffix),
            headers=headers,
            verify=INSECURE,
            data=data
        )
    except Exception as e:
        return_error(e)

    # Handle error responses gracefully
    if 'application/json' not in res.headers.get('Content-Type', []) and res.status_code != 204:
        LOG(f'response status code is: {res.status_code}')
        return_error('invalid url or port: ' + BASE_URL)

    if res.status_code == 404:
        if res.json().get('message'):
            return_error(res.json().get('message'))
        else:
            return_error('No data returned')

    if res.status_code not in {200, 201, 202, 204, 207}:
        return_error(
            'Error in API call to {}, status code: {}, reason: {}'.format(BASE_URL + '/' + url_suffix, res.status_code,
                                                                          res.json()['message']))
    if res.status_code == 204:
        return {}
    return res.json()


def get_host_by_id(host_id):
    res = http_request('GET', 'lr-admin-api/hosts/' + host_id)
    return fix_location_value([res])


def update_hosts_keys(hosts):
    new_hosts = []

    for host in hosts:
        tmp_host = {
            'EntityId': host.get('entity').get('id'),
            'EntityName': host.get('entity').get('name'),
            'OS': host.get('os'),
            'ThreatLevel': host.get('threatLevel'),
            'UseEventlogCredentials': host.get('useEventlogCredentials'),
            'Name': host.get('name'),
            'DateUpdated': host.get('dateUpdated'),
            'HostZone': host.get('hostZone'),
            'RiskLevel': host.get('riskLevel'),
            'Location': host.get('location'),
            'Status': host.get('recordStatusName'),
            'ThreatLevelComments': host.get('threatLevelComments'),
            'ID': host.get('id'),
            'OSType': host.get('osType')
        }
        new_hosts.append(tmp_host)
    return new_hosts


def update_networks_keys(networks):
    new_networks = []

    for network in networks:
        tmp_network = {
            'EndIP': network.get('eip'),
            'HostStatus': network.get('recordStatusName'),
            'Name': network.get('name'),
            'RiskLevel': network.get('riskLevel'),
            'EntityId': network.get('entity').get('id'),
            'EntityName': network.get('entity').get('name'),
            'Location': network.get('location'),
            'ThreatLevel': network.get('threatLevel'),
            'DateUpdated': network.get('dateUpdated'),
            'HostZone': network.get('hostZone'),
            'ID': network.get('id'),
            'BeganIP': network.get('bip')
        }
        new_networks.append(tmp_network)
    return new_networks


def update_users_keys(users):
    new_users = []

    for user in users:
        tmp_user = {
            'ID': user.get('id'),
            'DateUpdated': user.get('dateUpdated'),
            'HostStatus': user.get('recordStatusName'),
            'LastName': user.get('lastName'),
            'FirstName': user.get('firstName'),
            'UserType': user.get('userType'),
            'Entity': user.get('objectPermissions').get('entity'),
            'Owner': user.get('objectPermissions').get('owner'),
            'ReadAccess': user.get('objectPermissions').get('readAccess'),
            'WriteAccess': user.get('objectPermissions').get('writeAccess')
        }
        new_users.append(tmp_user)
    return new_users


def update_logins_keys(logins):
    new_logins = []

    for login in logins:
        tmp_login = {
            'Login': login.get('login'),
            'UserProfileId': login.get('userProfileId'),
            'UserId': login.get('userId'),
            'DefaultEntityId': login.get('defaultEntityId'),
            'HostStatus': login.get('recordStatusName'),
            'DateUpdated': login.get('dateUpdated'),
            'DateCreated': login.get('dateCreated'),
            'Entities': login.get('entities')
        }
        new_logins.append(tmp_login)
    return new_logins


def update_profiles_keys(profiles):
    new_profiles = []

    for profile in profiles:
        tmp_profile = {
            'ID': profile.get('id'),
            'Name': profile.get('name'),
            'ShortDescription': profile.get('shortDescription'),
            'LongDescription': profile.get('longDescription'),
            'DataProcessorAccessMode': profile.get('dataProcessorAccessMode'),
            'SecurityRole': profile.get('securityRole'),
            'ProfileType': profile.get('ProfileType'),
            'DateUpdated': profile.get('dateUpdated'),
            'TotalAssociatedUsers': profile.get('totalAssociatedUsers'),
            'NotificationGroupsPermissions': profile.get('notificationGroupsPermissions'),
            'ADGroupsPermissions': profile.get('adGroupsPermissions'),
            'EntityPermissions': profile.get('entityPermissions'),
            'DataProcessorsPermissions': profile.get('dataProcessorsPermissions'),
            'LogsourceListPermissions': profile.get('logsourceListPermissions'),
            'LogSourcePermissions': profile.get('logSourcePermissions'),
            'Privileges': profile.get('privileges'),
            'SmartResponsePluginsPermissions': profile.get('smartResponsePluginsPermissions')

        }
        new_profiles.append(tmp_profile)
    return new_profiles


def update_persons_keys(persons):
    new_persons = []

    for person in persons:
        tmp_person = {
            'ID': person.get('id'),
            'DateUpdated': person.get('dateUpdated'),
            'HostStatus': person.get('recordStatusName'),
            'LastName': person.get('lastName'),
            'FirstName': person.get('firstName'),
            'IsAPIPerson': person.get('isAPIPerson'),
            'UserID': person.get('user').get('id'),
            'UserLogin': person.get('user').get('login')
        }
        new_persons.append(tmp_person)
    return new_persons


def generate_query_value(valueType, value):
    if valueType == 2:
        return int(value)
    elif valueType == 5:
        return str(value)
    else:
        return {
            "value": value,
            "matchType": 2
        }


def generate_query_item(filterType, valueType, value):
    query = {
        "filterItemType": 0,
        "fieldOperator": 1,
        "filterMode": 1,
        "values": [
            {
                "filterType": filterType,
                "valueType": valueType,
                "value": generate_query_value(valueType, value)
            }
        ]
    }

    return query


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    http_request('GET', 'lr-admin-api/hosts')
    demisto.results('ok')


def add_host(data_args):
    data = {
        "id": -1,
        "entity": {
            "id": int(data_args.get('entity-id')),
            "name": data_args.get('entity-name')
        },
        "name": data_args.get('name'),
        "shortDesc": data_args.get('short-description'),
        "longDesc": data_args.get('long-description'),
        "riskLevel": data_args.get('risk-level'),
        "threatLevel": data_args.get('threat-level'),
        "threatLevelComments": data_args.get('threat-level-comments'),
        "recordStatusName": data_args.get('host-status'),
        "hostZone": data_args.get('host-zone'),
        "os": data_args.get('os'),
        "useEventlogCredentials": bool(data_args.get('use-eventlog-credentials')),
        "osType": data_args.get('os-type')
    }

    res = http_request('POST', 'lr-admin-api/hosts/', json.dumps(data))
    res = fix_location_value([res])
    context = createContext(update_hosts_keys(res), removeNull=True)
    outputs = {'Logrhythm.Host(val.ID === obj.ID)': context}
    return_outputs(readable_output=data_args.get('name') + " added successfully to " + data_args.get('entity-name'),
                   outputs=outputs, raw_response=res)


def get_hosts_by_entity(data_args):
    res = http_request('GET', 'lr-admin-api/hosts?entity=' + data_args['entity-name'] + '&count=' + data_args['count'])
    res = fix_location_value(res)
    res = update_hosts_keys(res)
    context = createContext(res, removeNull=True)
    human_readable = tableToMarkdown('Hosts for ' + data_args.get('entity-name'), res, HOSTS_HEADERS)
    outputs = {'Logrhythm.Host(val.Name && val.ID === obj.ID)': context}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_hosts(data_args):
    id = data_args.get('host-id')
    if id:
        res = get_host_by_id(id)
    else:
        res = http_request('GET', 'lr-admin-api/hosts?count=' + data_args['count'])

    res = fix_location_value(res)
    res = update_hosts_keys(res)
    context = createContext(res, removeNull=True)
    human_readable = tableToMarkdown('Hosts information:', res, HOSTS_HEADERS)
    outputs = {'Logrhythm.Host(val.Name && val.ID === obj.ID)': context}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def change_status(data_args):
    data = [{
        "hostId": int(data_args.get('host-id')),
        "status": data_args.get('status')
    }]

    res = http_request('PUT', 'lr-admin-api/hosts/status', json.dumps(data))

    host_info = get_host_by_id(data_args.get('host-id'))
    context = createContext(update_hosts_keys(host_info), removeNull=True)
    outputs = {'Logrhythm.Host(val.ID === obj.ID)': context}
    return_outputs(readable_output='Status updated to ' + data_args.get('status'), outputs=outputs, raw_response=res)


def execute_query(data_args):
    # generate random string for request id
    req_id = ''.join(random.choice(string.ascii_letters) for x in range(8))
    start, end = get_time_frame(data_args.get('time-frame'), data_args.get('start-date'), data_args.get('end-date'))
    delta = end - start
    dates = []

    for i in range(delta.days + 1):
        dates.append((start + timedelta(days=i)).strftime("logs-%Y-%m-%d"))

    data = {
        "indices": dates,
        "searchType": "DFS_QUERY_THEN_FETCH",
        "source": {
            "size": data_args.get('page-size'),
            "query": {
                "query_string": {
                    "default_field": "logMessage",
                    "query": data_args.get('keyword')
                }
            },
            "stored_fields": "logMessage",
            "sort": [
                {
                    "normalDate": {
                        "order": "asc"
                    }
                }
            ]
        }
    }

    headers = dict(HEADERS)
    headers['Content-Type'] = 'application/json'
    headers['Request-Id'] = req_id
    headers['Request-Origin-Date'] = str(datetime.now())
    headers['x-gateway-route-to-tag'] = CLUSTER_ID

    res = http_request('POST', 'lr-legacy-search-api/esquery', json.dumps(data), headers)
    logs = res['hits']['hits']
    logs_response = []

    xml_ns = './/{http://schemas.microsoft.com/win/2004/08/events/event}'

    for log in logs:
        message = str(log['fields']['logMessage'])
        message = message[3:-2]

        try:
            root = ET.fromstring(message)

            log_item = {
                "EventID": str(root.find(xml_ns + 'EventID').text),  # type: ignore
                "Level": str(root.find(xml_ns + 'Level').text),  # type: ignore
                "Task": str(root.find(xml_ns + 'Task').text),  # type: ignore
                "Opcode": str(root.find(xml_ns + 'Opcode').text),  # type: ignore
                "Keywords": str(root.find(xml_ns + 'Keywords').text),  # type: ignore
                "Channel": str(root.find(xml_ns + 'Channel').text),  # type: ignore
                "Computer": str(root.find(xml_ns + 'Computer').text),  # type: ignore
                "EventData": str(root.find(xml_ns + 'EventData').text)  # type: ignore
                .replace('\\r\\n', '\n').replace('\\t', '\t')
            }
            logs_response.append(log_item)
        except Exception:
            continue

    context = createContext(logs_response, removeNull=True)
    human_readable = tableToMarkdown('logs results', logs_response, LOGS_HEADERS)
    outputs = {'Logrhythm.Log': context}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=logs_response)


def get_persons(data_args):
    id = data_args.get('person-id')
    if id:
        res = [http_request('GET', 'lr-admin-api/persons/' + id)]
    else:
        res = http_request('GET', 'lr-admin-api/persons?count=' + data_args['count'])
    res = update_persons_keys(res)
    context = createContext(res, removeNull=True)
    outputs = {'Logrhythm.Person(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Persons information', context, PERSON_HEADERS)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_users(data_args):
    id = data_args.get('user_id')
    if id:
        res = [http_request('GET', 'lr-admin-api/users/' + id)]
    else:
        res = http_request('GET', 'lr-admin-api/users?count=' + data_args['count'])
    res = update_users_keys(res)
    context = createContext(res, removeNull=True)
    outputs = {'Logrhythm.User(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Users information', context, USER_HEADERS)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def add_user(data_args):
    data = {
        "userType": "Individual",
        "firstName": data_args.get("first_name"),
        "lastName": data_args.get("last_name")
    }
    if not data_args.get("abbreviation"):
        data["abbreviation"] = f"{data_args.get('first_name')[0]}{data_args.get('last_name')}".lower()
    else:
        data["abbreviation"] = data_args.get("abbreviation")
    res = [http_request('POST', 'lr-admin-api/users/', json.dumps(data))]
    res = update_users_keys(res)
    context = createContext(res, removeNull=True)
    outputs = {'Logrhythm.User(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('User added', context, USER_HEADERS)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_logins(data_args):
    id = data_args.get('user_id')
    if id:
        res = [http_request('GET', 'lr-admin-api/users/' + id + '/login/')]
    else:
        res = http_request('GET', 'lr-admin-api/users/user-logins?count=' + data_args['count'])
    res = update_logins_keys(res)
    context = createContext(res, removeNull=True)
    outputs = {'Logrhythm.Login(val.Login === obj.Login)': context}
    human_readable = tableToMarkdown('Logins information', context, LOGIN_HEADERS)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def add_login(data_args):
    id = data_args.get('user_id')
    data = {
        "login": data_args.get("login"),
        "userProfileId": arg_to_number(data_args.get("profile_id")),
        "defaultEntityId": arg_to_number(data_args.get("entity_id")),
        "password": data_args.get("password")
    }
    res = [http_request('POST', 'lr-admin-api/users/' + id + '/login/', json.dumps(data))]
    res = update_logins_keys(res)
    context = createContext(res, removeNull=True)
    outputs = {'Logrhythm.User(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Login added', context, LOGIN_HEADERS)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_privileges(data_args):
    id = data_args.get('user_id')
    res = http_request('GET', 'lr-admin-api/users/' + id + '/privileges?offset='
                       + data_args['offset'] + '&count=' + data_args['count'])
    res = {"ID": id, "Privileges": res}
    context = createContext(res, removeNull=True)
    outputs = {'Logrhythm.Privileges(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Privileges information', context, ["Privileges"])
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_profiles(data_args):
    id = data_args.get('profile_id')
    if id:
        res = [http_request('GET', 'lr-admin-api/user-profiles/' + id)]
    else:
        res = http_request('GET', 'lr-admin-api/user-profiles?count=' + data_args['count'])
    res = update_profiles_keys(res)
    context = createContext(res, removeNull=True)
    outputs = {'Logrhythm.Profile(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Users information', context, PROFILE_HEADERS)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_networks(data_args):
    id = data_args.get('network-id')
    if id:
        res = [http_request('GET', 'lr-admin-api/networks/' + id)]
    else:
        res = http_request('GET', 'lr-admin-api/networks?count=' + data_args['count'])
    res = fix_location_value(res)
    res = update_networks_keys(res)
    context = createContext(res, removeNull=True)
    outputs = {'Logrhythm.Network(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Networks information', context, NETWORK_HEADERS)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_alarm_data(data_args):
    id = data_args.get('alarm-id')
    res = http_request('GET', 'lr-drilldown-cache-api/drilldown/' + id)
    if not res:
        return_outputs(readable_output=f"No data was found for alarm with ID {id}.")

    alarm_data = res['Data']['DrillDownResults']
    alarm_summaries = res['Data']['DrillDownResults']['RuleBlocks']
    del alarm_data['RuleBlocks']
    aie_message = xml2json(str(alarm_data.get('AIEMsgXml'))).replace('\"@', '\"')
    alarm_data['AIEMsgXml'] = json.loads(aie_message).get('aie')
    alarm_data['Status'] = ALARM_STATUS[str(alarm_data['Status'])]
    alarm_data['ID'] = alarm_data['AlarmID']
    del alarm_data['AlarmID']

    dds_summaries = []
    for block in alarm_summaries:
        for item in block['DDSummaries']:
            item['PIFType'] = PIF_TYPES[str(item['PIFType'])]
            m = re.findall(r'"field": "(([^"]|\\")*)"', item['DrillDownSummaryLogs'])
            fields = [k[0] for k in m]
            item['DrillDownSummaryLogs'] = ", ".join(fields)
            del item['DefaultValue']
            dds_summaries.append(item)

    alarm_data['Summary'] = dds_summaries

    context = createContext(alarm_data, removeNull=True)
    outputs = {'Logrhythm.Alarm(val.ID === obj.ID)': context}

    del alarm_data['AIEMsgXml']
    del alarm_data['Summary']
    human_readable = tableToMarkdown('Alarm information for alarm id ' + id, alarm_data) + tableToMarkdown(
        'Alarm summaries', dds_summaries, ALARM_SUMMARY_HEADERS)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_alarm_events(data_args):
    id = data_args.get('alarm-id')
    count = data_args.get('count')
    count = int(data_args.get('count'))
    fields = data_args.get('fields')
    show_log_message = data_args.get('get-log-message') == 'True'

    res = http_request('GET', 'lr-drilldown-cache-api/drilldown/' + id)
    if not res:
        return_outputs(readable_output=f"No events were found for alarm with ID {id}")
    res = res['Data']['DrillDownResults']['RuleBlocks']

    events = []

    for block in res:
        if not block.get('DrillDownLogs'):
            continue
        logs = json.loads(block['DrillDownLogs'])
        for log in logs:
            fix_date_values(log)
            if not show_log_message:
                del log['logMessage']
            events.append((log))

    events = events[:count]
    human_readable = tableToMarkdown('Events information for alarm ' + id, events)

    if fields:
        fields = fields.split(',')
        for event in events:
            for key in event.keys():
                if key not in fields:
                    del event[key]

    ec = {"ID": int(id), "Event": events}
    context = createContext(ec, removeNull=True)
    outputs = {'Logrhythm.Alarm(val.ID === obj.ID)': context}

    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def fetch_incidents():
    headers = dict(HEADERS)

    last_run = demisto.getLastRun()

    # Check if first run. If not, continue running from the last case dateCreated field.
    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time')
        headers['createdAfter'] = start_time
        # print(start_time)
    else:
        headers['createdBefore'] = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Get list of cases
    if ENTITY_ID:
        cases = http_request('GET', 'lr-case-api/cases?entityNumber=' + str(ENTITY_ID), headers=headers)
    else:
        cases = http_request('GET', 'lr-case-api/cases', headers=headers)
    # Set Last Run to the last case dateCreated field

    if cases:
        demisto.setLastRun({
            'start_time': cases[len(cases) - 1]['dateCreated']
        })

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


def lr_get_case_evidence(data_args):
    case_id = data_args.get('case_id')
    case = http_request('GET', 'lr-case-api/cases/' + case_id + '/evidence')

    result = CommandResults(
        outputs_prefix='Logrhythm.Evidence',
        outputs=case,
        readable_output=tableToMarkdown('Evidences for case ' + case_id, case, headerTransform=string_to_table_header),
        raw_response=case,
        outputs_key_field='number'
    )
    return_results(result)


def lr_execute_search_query(data_args):
    number_of_days = data_args.get('number_of_days')
    source_type = data_args.get('source_type')
    host_name = data_args.get('host_name')
    username = data_args.get('username')
    subject = data_args.get('subject')
    sender = data_args.get('sender')
    recipient = data_args.get('recipient')
    hash = data_args.get('hash')
    url = data_args.get('URL')
    process_name = data_args.get('process_name')
    object = data_args.get('object')
    ipaddress = data_args.get('ip_address')
    max_message = data_args.get('max_massage')
    query_timeout = data_args.get('query_timeout')

    # Create filter query
    query = []

    if host_name:
        query.append(generate_query_item(filterType=23, valueType=4, value=str(host_name)))

    if ENTITY_ID:
        query.append(generate_query_item(filterType=136, valueType=2, value=int(ENTITY_ID)))

    if source_type and source_type != "all":
        query.append(generate_query_item(filterType=9, valueType=2, value=SOURCE_TYPE_MAP[source_type]))

    if username:
        query.append(generate_query_item(filterType=43, valueType=4, value=str(username)))

    if subject:
        query.append(generate_query_item(filterType=33, valueType=4, value=str(subject)))

    if sender:
        query.append(generate_query_item(filterType=31, valueType=4, value=str(sender)))

    if recipient:
        query.append(generate_query_item(filterType=32, valueType=4, value=str(recipient)))

    if hash:
        query.append(generate_query_item(filterType=138, valueType=4, value=str(hash)))

    if url:
        query.append(generate_query_item(filterType=42, valueType=4, value=str(url)))

    if process_name:
        query.append(generate_query_item(filterType=41, valueType=4, value=str(process_name)))

    if object:
        query.append(generate_query_item(filterType=34, valueType=4, value=str(object)))

    if ipaddress:
        query.append(generate_query_item(filterType=17, valueType=5, value=str(ipaddress)))

    # Search and get TaskID
    querybody = {
        "maxMsgsToQuery": int(max_message),
        "logCacheSize": 10000,
        "queryTimeout": int(query_timeout),
        "queryRawLog": True,
        "queryEventManager": False,
        "dateCriteria": {
            "useInsertedDate": False,
            "lastIntervalValue": int(number_of_days),
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

    headers = HEADERS
    headers['Content-Type'] = 'application/json'

    search_task = http_request('POST', 'lr-search-api/actions/search-task', json.dumps(querybody), headers)
    task_id = search_task.get('TaskId')

    results = CommandResults(
        outputs={"TaskID": task_id},
        outputs_prefix="Logrhythm.Search.Task",
        outputs_key_field='taskID',
        raw_response=search_task,
        readable_output='New search query created, Task ID=' + task_id
    )

    return_results(results)


def lr_get_query_result(data_args):
    task_id = data_args.get('task_id')

    queryresult = json.dumps(
        {
            "data": {
                "searchGuid": task_id,
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

    headers = HEADERS
    headers['Content-Type'] = 'application/json'

    search_result = http_request('POST', 'lr-search-api/actions/search-result', queryresult, headers)

    context = {
        "TaskID": task_id,
        "TaskStatus": search_result["TaskStatus"],
        "Items": search_result["Items"]
    }

    if search_result["TaskStatus"] == "Completed: No Results":
        message = "#### No results, please modify your search"

    elif search_result["TaskStatus"] == "Searching":
        message = "#### Searching"

    elif search_result["TaskStatus"] == "Search Failed":
        message = "#### The search is timed out, please try again or modify your search"

    elif search_result["Items"]:
        for log in search_result["Items"]:
            log.pop('logMessage', None)
        message = tableToMarkdown("Search results for task " + task_id, search_result["Items"],
                                  headerTransform=string_to_table_header)
    else:
        message = "#### Please try again later"

    results = CommandResults(
        readable_output=message,
        outputs=context,
        outputs_key_field='TaskID',
        outputs_prefix="Logrhythm.Search.Results",
        raw_response=search_result
    )
    return_results(results)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    LOG('Command being called is %s' % (demisto.command()))

    try:
        handle_proxy()
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
        elif demisto.command() == 'lr-add-host':
            add_host(demisto.args())
        elif demisto.command() == 'lr-get-hosts-by-entity':
            get_hosts_by_entity(demisto.args())
        elif demisto.command() == 'lr-get-hosts':
            get_hosts(demisto.args())
        elif demisto.command() == 'lr-execute-query':
            execute_query(demisto.args())
        elif demisto.command() == 'lr-update-host-status':
            change_status(demisto.args())
        elif demisto.command() == 'lr-get-persons':
            get_persons(demisto.args())
        elif demisto.command() == 'lr-get-users':
            get_users(demisto.args())
        elif demisto.command() == 'lr-get-logins':
            get_logins(demisto.args())
        elif demisto.command() == 'lr-get-privileges':
            get_privileges(demisto.args())
        elif demisto.command() == 'lr-get-profiles':
            get_profiles(demisto.args())
        elif demisto.command() == 'lr-get-networks':
            get_networks(demisto.args())
        elif demisto.command() == 'lr-get-alarm-data':
            get_alarm_data(demisto.args())
        elif demisto.command() == 'lr-get-alarm-events':
            get_alarm_events(demisto.args())
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()
        elif demisto.command() == 'lr-execute-search-query':
            lr_execute_search_query(demisto.args())
        elif demisto.command() == 'lr-get-query-result':
            lr_get_query_result(demisto.args())
        elif demisto.command() == 'lr-get-case-evidence':
            lr_get_case_evidence(demisto.args())
        elif demisto.command() == 'lr-add-user':
            add_user(demisto.args())
        elif demisto.command() == 'lr-add-login':
            add_login(demisto.args())
    except Exception as e:
        return_error('error has occurred: {}'.format(str(e)))


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

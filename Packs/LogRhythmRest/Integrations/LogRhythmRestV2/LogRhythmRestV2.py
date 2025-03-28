import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
import mimetypes
import sys

import dateparser
import urllib3


urllib3.disable_warnings()


''' GLOBAL VARS '''
ALARM_HEADERS = ['alarmId', 'alarmStatus', 'associatedCases', 'alarmRuleName', 'dateInserted', 'dateUpdated',
                 'entityName', 'alarmDataCached', 'personId', 'eventCount', 'rbpMax', 'rbpAvg']

ALARM_EVENTS_HEADERS = ['commonEventName', 'logMessage', 'priority', 'logDate', 'impactedHostId', 'impactedZone',
                        'serviceName', '', 'entityName', 'classificationName', 'classificationTypeName']

CASE_EVIDENCES_HEADERS = ['number', 'type', 'status', 'dateCreated', 'createdBy', 'text', 'alarm', 'file']

TAG_HEADERS = ['number', 'text', 'dateCreated', 'createdBy']

ENTITY_HEADERS = ['id', 'name', 'fullName', 'recordStatusName', 'shortDesc', 'dateUpdated']

USER_HEADERS = ['id', 'fullName', 'userType', 'firstName', 'lastName', 'recordStatusName', 'dateUpdated',
                'objectPermissions']

LIST_HEADERS = ['guid', 'name', 'listType', 'status', 'shortDescription', 'id', 'entityName', 'dateCreated',
                'owner', 'writeAccess', 'readAccess']

NETWORK_HEADERS = ['id', 'name', 'shortDesc', 'longDesc', 'recordStatusName', 'bip', 'eip', 'entity', 'riskLevel',
                   'dateUpdated', 'threatLevel', 'threatLevelComment', 'hostZone', 'location']

ALARM_STATUS = {0: 'New',
                1: 'Opened',
                2: 'Working',
                3: 'Escalated',
                4: 'Closed',
                5: 'Closed_FalseAlarm',
                6: 'Closed_Resolved',
                7: 'Closed_Unresolved',
                8: 'Closed_Reported',
                9: 'Closed_Monitor'}

CASE_STATUS = {'Created': 1,
               'Completed': 2,
               'Incident': 3,
               'Mitigated': 4,
               'Resolved': 5}

QUERY_TYPES_MAP = {'host_name': {'filter_type': 23, 'value_type': 4},
                   'entity_id': {'filter_type': 136, 'value_type': 2},
                   'source_type': {'filter_type': 9, 'value_type': 2},
                   'username': {'filter_type': 43, 'value_type': 4},
                   'subject': {'filter_type': 33, 'value_type': 4},
                   'sender': {'filter_type': 31, 'value_type': 4},
                   'recipient': {'filter_type': 32, 'value_type': 4},
                   'hash_': {'filter_type': 138, 'value_type': 4},
                   'url': {'filter_type': 42, 'value_type': 4},
                   'process_name': {'filter_type': 41, 'value_type': 4},
                   'object_': {'filter_type': 34, 'value_type': 4},
                   'ipaddress': {'filter_type': 17, 'value_type': 5}}

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


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def alarms_list_request(self, alarm_id=None, alarm_status=None, offset=None, count=None, alarm_rule_name=None,
                            entity_name=None, case_association=None, created_after=None):
        if alarm_id:
            response = self._http_request('GET', f'lr-alarm-api/alarms/{alarm_id}')
            alarms = [response.get('alarmDetails')]
        else:
            if alarm_status:
                alarm_status = next((id for id, status in ALARM_STATUS.items() if status == alarm_status))

            params = assign_params(alarmStatus=alarm_status, offset=offset, count=count,
                                   associatedCases=case_association,
                                   alarmRuleName=alarm_rule_name, entityName=entity_name, orderby='DateInserted')

            response = self._http_request('GET', 'lr-alarm-api/alarms/', params=params)
            alarms = response.get('alarmsSearchDetails')
            alarms = alarms if alarms else []
            if created_after:
                filtered_alarms = []
                created_after = dateparser.parse(created_after)

                for alarm in alarms:
                    date_inserted = dateparser.parse(alarm.get('dateInserted'))
                    if date_inserted > created_after:
                        filtered_alarms.append(alarm)
                    else:
                        break

                alarms = filtered_alarms

        if alarms:
            for alarm in alarms:
                alarm['alarmStatus'] = ALARM_STATUS[alarm['alarmStatus']]

        return alarms, response

    def alarm_update_request(self, alarm_id, alarm_status, rbp):
        data = {"alarmStatus": alarm_status if alarm_status else None,
                "rBP": rbp if rbp else None}

        # delete empty values
        data = {k: v for k, v in data.items() if v}

        response = self._http_request('PATCH', f'lr-alarm-api/alarms/{alarm_id}', json_data=data)

        return response

    def alarm_add_comment_request(self, alarm_id, alarm_comment):
        data = {"alarmComment": alarm_comment}

        response = self._http_request('POST', f'lr-alarm-api/alarms/{alarm_id}/comment', json_data=data)

        return response

    def alarm_history_list_request(self, alarm_id, person_id, date_updated, type_, offset, count):
        params = assign_params(personId=person_id, dateUpdated=date_updated, type=type_, offset=offset, count=count)

        response = self._http_request('GET', f'lr-alarm-api/alarms/{alarm_id}/history', params=params)

        alarm_history = response.get('alarmHistoryDetails')
        return alarm_history, response

    def alarm_events_list_request(self, alarm_id):  # pragma: no cover
        response = self._http_request('GET', f'lr-alarm-api/alarms/{alarm_id}/events')

        alarm_events = response.get('alarmEventsDetails')
        return alarm_events, response

    def alarm_summary_request(self, alarm_id):  # pragma: no cover
        response = self._http_request('GET', f'lr-alarm-api/alarms/{alarm_id}/summary')

        alarm_summary = response.get('alarmSummaryDetails')
        return alarm_summary, response

    def get_alarm_details_request(self, alarm_id):  # pragma: no cover
        response = self._http_request('GET', f'lr-alarm-api/alarms/{alarm_id}')

        alarm_details = response.get('alarmDetails')
        return alarm_details, response

    def alarm_drilldown_request(self, alarm_id):  # pragma: no cover
        headers = self._headers | {'content-type': 'application/json'}
        response = self._http_request('GET', f'lr-drilldown-cache-api/drilldown/{alarm_id}', headers=headers)
        drilldown_results = response.get('Data', {}).get('DrillDownResults')
        return drilldown_results, response
    
    def alarm_drilldown_valid_empty_request(self, alarm_id):
        headers = self._headers | {'content-type': 'application/json'}
        response = self._http_request('GET', f'lr-drilldown-cache-api/drilldown/{alarm_id}', headers=headers,
                                            empty_valid_codes=[200,201,202,203,204])
        drilldown_results = response.get('Data', {}).get('DrillDownResults')
        return drilldown_results, response

    def alarm_drilldown_raw_response_request(self, alarm_id):  # pragma: no cover
        headers = self._headers | {'content-type': 'application/json'}
        response = self._http_request('GET', f'lr-drilldown-cache-api/drilldown/{alarm_id}', headers=headers,
                                      resp_type='response', return_empty_response=True)
        drilldown_results = response.get('Data', {}).get('DrillDownResults')
        return drilldown_results, response

    def cases_list_request(self, case_id=None, timestamp_filter_type=None, timestamp=None, priority=None, status=None,
                           owners=None, tags=None, text=None, evidence_type=None, reference_id=None, external_id=None,
                           offset=None, count=None):

        params = assign_params(priority=priority, statusNumber=status, ownerNumber=owners, tagNumber=tags, text=text,
                               evidenceType=evidence_type, referenceId=reference_id, externalId=external_id)
        headers = self._headers

        headers['orderBy'] = 'dateCreated'

        if timestamp_filter_type and timestamp:
            headers[timestamp_filter_type] = timestamp
        if offset:
            headers['offset'] = offset
        if count:
            headers['count'] = str(count)

        cases = self._http_request('GET', 'lr-case-api/cases', params=params, headers=headers)

        if case_id:
            cases = next((case for case in cases if case.get('id') == case_id), None)
        return cases

    def case_create_request(self, name, priority, external_id, due_date, summary):
        data = {"name": name, "priority": int(priority), "externalId": external_id, "dueDate": due_date,
                "summary": summary}

        # delete empty values
        data = {k: v for k, v in data.items() if v}

        response = self._http_request('POST', 'lr-case-api/cases', json_data=data)

        return response

    def case_update_request(self, case_id, name, priority, external_id, due_date, summary, entity_id, resolution):
        data = {"name": name, "externalId": external_id, "dueDate": due_date,
                "summary": summary, "entityId": int(entity_id) if entity_id else None,
                "resolution": int(resolution) if resolution else None,
                "priority": int(priority) if priority else None}

        # delete empty values
        data = {k: v for k, v in data.items() if v}

        response = self._http_request('PUT', f'lr-case-api/cases/{case_id}', json_data=data)

        return response

    def case_status_change_request(self, case_id, status):
        status_number = CASE_STATUS.get(status)

        data = {"statusNumber": status_number}

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/actions/changeStatus/', json_data=data)

        return response

    def case_evidence_list_request(self, case_id, evidence_number=None, evidence_type=None, status=None):
        params = assign_params(type=evidence_type, status=status)

        evidences = self._http_request('GET', f'lr-case-api/cases/{case_id}/evidence', params=params)

        if evidence_number:
            evidences = next((evidence for evidence in evidences if evidence.get('number') == int(evidence_number)),
                             None)
        return evidences

    def case_alarm_evidence_add_request(self, case_id, alarm_numbers):  # pragma: no cover
        alarms = [int(alarm) for alarm in alarm_numbers]
        data = {"alarmNumbers": alarms}

        response = self._http_request(
            'POST', f'lr-case-api/cases/{case_id}/evidence/alarms', json_data=data)

        return response

    def case_note_evidence_add_request(self, case_id, note):  # pragma: no cover
        data = {"text": note}
        response = self._http_request(
            'POST', f'lr-case-api/cases/{case_id}/evidence/note', json_data=data)

        return response

    def case_file_evidence_add_request(self, case_id, entry_id):
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data; boundary=---------------------------'

        get_file_path_res = demisto.getFilePath(entry_id)
        file_path = get_file_path_res["path"]
        file_name = get_file_path_res["name"]
        with open(file_path, 'rb') as file:
            file_bytes = file.read()

        file_content = file_bytes.decode('iso-8859-1')
        content_type = mimetypes.guess_type(file_path)[0]

        data = '-----------------------------\n' \
               f'Content-Disposition: form-data; name="file"; filename="{file_name}"\n' \
               f'Content-Type: {content_type}\n\n' \
               f'{file_content}\n' \
               '-----------------------------\n' \
               'Content-Disposition: form-data; name="note"\n\n' \
               '-------------------------------'

        response = self._http_request('POST', f'lr-case-api/cases/{case_id}/evidence/file', data=data)

        return response

    def case_evidence_delete_request(self, case_id, evidence_number):  # pragma: no cover
        self._http_request('DELETE', f'lr-case-api/cases/{case_id}/evidence/{evidence_number}', resp_type='text')

    def case_file_evidence_download_request(self, case_id, evidence_number):  # pragma: no cover
        response = self._http_request(
            'GET', f'lr-case-api/cases/{case_id}/evidence/{evidence_number}/download/', resp_type='other')

        filename = re.findall("filename=\"(.+)\"", response.headers['Content-Disposition'])[0]
        return fileResult(filename, response.content)

    def case_tags_add_request(self, case_id, tag_numbers):  # pragma: no cover
        tags = [int(tag) for tag in tag_numbers]
        data = {"numbers": tags}

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/actions/addTags', json_data=data)

        return response

    def case_tags_remove_request(self, case_id, tag_numbers):
        tags = [int(tag) for tag in tag_numbers]
        data = {"numbers": tags}

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/actions/removeTags', json_data=data)

        return response

    def tags_list_request(self, tag_name, offset, count):
        params = assign_params(tag=tag_name)
        headers = self._headers

        if offset:
            headers['offset'] = offset
        if count:
            headers['count'] = count

        response = self._http_request('GET', 'lr-case-api/tags', params=params, headers=headers)

        return response

    def case_collaborators_list_request(self, case_id):
        return self._http_request('GET', f'lr-case-api/cases/{case_id}/collaborators')

    def case_collaborators_update_request(self, case_id, owner, collaborators):
        collaborators = [int(collaborator) for collaborator in collaborators]

        data = {"owner": int(owner),
                "collaborators": collaborators}

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/collaborators', json_data=data)

        return response

    def entities_list_request(self, entity_id, parent_entity_id, offset, count):
        params = assign_params(parentEntityId=parent_entity_id, offset=offset, count=count)

        entities = self._http_request('GET', 'lr-admin-api/entities', params=params)
        if entity_id:
            entities = next((entity for entity in entities if entity.get('id') == int(entity_id)), None)
        return entities

    def hosts_list_request(self, host_name=None, entity_name=None, record_status=None, offset=None,
                           count=None, endpoint_id_list=None, endpoint_hostname_list=None):
        params = assign_params(name=host_name, entity=entity_name, recordStatus=record_status, offset=offset,
                               count=count)

        hosts = self._http_request('GET', 'lr-admin-api/hosts', params=params)

        if endpoint_id_list:
            endpoint_id_list = [int(id_) for id_ in endpoint_id_list]
            hosts = list(filter(lambda host: host.get('id') in endpoint_id_list, hosts))

        if endpoint_hostname_list:
            hosts = list(filter(lambda host: host.get('name') in endpoint_hostname_list, hosts))

        return hosts

    def users_list_request(self, user_ids, entity_ids, user_status, offset, count):
        params = assign_params(id=user_ids, entityIds=entity_ids, userStatus=user_status, offset=offset, count=count)

        response = self._http_request('GET', 'lr-admin-api/users', params=params)

        return response

    def lists_get_request(self, list_type, list_name, can_edit):
        headers = self._headers

        if list_type:
            headers['listType'] = list_type

        if list_name:
            headers['name'] = list_name

        if can_edit:
            headers['canEdit'] = can_edit

        response = self._http_request('GET', 'lr-admin-api/lists', headers=headers)

        return response

    def list_summary_create_update_request(self, list_type, name, enabled, use_patterns, replace_existing, read_access,
                                           write_access, restricted_read, entity_name, need_to_notify, does_expire,
                                           owner):
        data = {
            "autoImportOption": {"enabled": enabled, "replaceExisting": replace_existing, "usePatterns": use_patterns},
            "doesExpire": does_expire, "entityName": entity_name, "owner": int(owner),
            "listType": list_type, "name": name, "needToNotify": need_to_notify, "readAccess": read_access,
            "restrictedRead": restricted_read, "writeAccess": write_access}

        response = self._http_request('POST', 'lr-admin-api/lists', json_data=data)

        return response

    def list_details_and_items_get_request(self, list_id, max_items):
        self._headers['maxItemsThreshold'] = str(sys.maxsize)
        raw_response = self._http_request('GET', f'lr-admin-api/lists/{list_id}')
        response = raw_response.copy()
        if max_items and response.get('items'):
            items = response.get('items')[:int(max_items)]
            response['items'] = items
        return response, raw_response

    def list_items_add_request(self, list_id, items):
        if type(items) is dict:
            items = [items]
        data = {"items": items}
        response = self._http_request('POST', f'lr-admin-api/lists/{list_id}/items', json_data=data)

        return response

    def list_items_remove_request(self, list_id, items):
        if type(items) is dict:
            items = [items]
        data = {"items": items}

        response = self._http_request('DELETE', f'lr-admin-api/lists/{list_id}/items', json_data=data)

        return response

    def execute_search_query_request(self, number_of_days, source_type, host_name, username, subject, sender,
                                     recipient, hash_, url, process_name, object_, ipaddress, max_message,
                                     query_timeout, entity_id):
        # Create filter query
        query = []

        arguments = locals().copy()

        for field_key, field_val in arguments.items():
            if field_val and QUERY_TYPES_MAP.get(field_key):
                query_type = QUERY_TYPES_MAP[field_key]
                filter_type = query_type.get('filter_type')
                value_type = query_type.get('value_type')

                if field_key == 'source_type' and field_val != 'all':
                    query.append(self.generate_query_item(filter_type, value_type, SOURCE_TYPE_MAP[field_val]))
                else:
                    query.append(self.generate_query_item(filter_type, value_type, field_val))

        # Search and get TaskID
        data = {
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

        response = self._http_request('POST', 'lr-search-api/actions/search-task', json_data=data)

        return response

    def generate_query_item(self, filter_type, value_type, value):
        if value_type == 2:
            value = int(value)
        elif value_type == 5:
            value = str(value)
        else:
            value = {
                "value": value,
                "matchType": 2
            }

        query = {
            "filterItemType": 0,
            "fieldOperator": 1,
            "filterMode": 1,
            "values": [
                {
                    "filterType": filter_type,
                    "valueType": value_type,
                    "value": value
                }
            ]
        }

        return query

    def get_query_result_request(self, task_id, page_size):
        data = {
            'data': {
                'searchGuid': task_id,
                'search': {
                    'sort': [],
                    'groupBy': [
                        'string'
                    ],
                    'fields': []
                },
                'paginator': {
                    'origin': 0,
                    'page_size': int(page_size)
                }
            }
        }

        response = self._http_request('POST', 'lr-search-api/actions/search-result', json_data=data)

        return response

    def add_host_request(self, entity_id, entity_name, name, short_desc, long_desc, risk_level, threat_level,
                         threat_level_comments, status, host_zone, use_eventlog_credentials, os, os_type):
        data = {
            "id": -1,
            "entity": {
                "name": entity_name
            },
            "name": name,
            "shortDesc": short_desc,
            "longDesc": long_desc,
            "riskLevel": risk_level,
            "threatLevel": threat_level,
            "threatLevelComments": threat_level_comments,
            "recordStatusName": status,
            "hostZone": host_zone,
            "os": os,
            "useEventlogCredentials": use_eventlog_credentials,
            "osType": os_type
        }

        if entity_id:
            data['entity']['id'] = int(entity_id)

        # delete empty values
        data = {k: v for k, v in data.items() if isinstance(v, bool) or v}

        response = self._http_request('POST', 'lr-admin-api/hosts', json_data=data)

        return response

    def hosts_status_update(self, host_id, status):
        data = [{'hostId': int(host_id), 'status': status}]
        response = self._http_request('PUT', 'lr-admin-api/hosts/status', json_data=data)
        return response

    def networks_list_request(self, network_id, name, record_status, bip, eip, offset, count):
        if network_id:
            return self._http_request('GET', f'lr-admin-api/networks/{network_id}')
        else:
            params = assign_params(name=name, recordStatus=record_status, BIP=bip, EIP=eip, offset=offset, count=count)
            return self._http_request('GET', 'lr-admin-api/networks/', params=params)


def alarms_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    alarm_id = args.get('alarm_id')
    alarm_status = args.get('alarm_status')
    alarm_rule_name = args.get('alarm_rule_name')
    entity_name = args.get('entity_name')
    case_association = args.get('case_association')
    offset = args.get('offset')
    count = args.get('count')

    alarms, raw_response = client.alarms_list_request(alarm_id, alarm_status, offset, count, alarm_rule_name,
                                                      entity_name, case_association)

    if alarms:
        hr = tableToMarkdown('Alarms', alarms, headerTransform=pascalToSpace, headers=ALARM_HEADERS, removeNull=True)
    else:
        hr = 'No alarms were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Alarm',
        outputs_key_field='alarmId',
        outputs=alarms,
        raw_response=raw_response,
    )

    return command_results


def alarm_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    alarm_id = args.get('alarm_id')
    alarm_status = args.get('alarm_status')
    rbp = args.get('rbp')

    if not alarm_status and not rbp:
        raise DemistoException('alarm_status and rbp arguments are empty, please provide at least one of them.')

    response = client.alarm_update_request(alarm_id, alarm_status, rbp)
    command_results = CommandResults(
        readable_output=f'Alarm {alarm_id} has been updated.',
        raw_response=response,
    )

    return command_results


def alarm_add_comment_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    alarm_id = args.get('alarm_id')
    alarm_comment = args.get('alarm_comment')

    response = client.alarm_add_comment_request(alarm_id, alarm_comment)
    command_results = CommandResults(
        readable_output=f'Comment added successfully to the alarm {alarm_id}.',
        raw_response=response,
    )

    return command_results


def alarm_history_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    alarm_id = args.get('alarm_id')
    person_id = args.get('person_id')
    date_updated = args.get('date_updated')
    type_ = args.get('type')
    offset = args.get('offset')
    count = args.get('count')

    alarm_history, raw_response = client.alarm_history_list_request(alarm_id, person_id, date_updated, type_, offset,
                                                                    count)

    if alarm_history:
        hr = tableToMarkdown(f'History for alarm {alarm_id}', alarm_history, headerTransform=pascalToSpace)
    else:
        hr = f'No history records found for alarm {alarm_id}.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.AlarmHistory',
        outputs_key_field='',
        outputs=alarm_history,
        raw_response=raw_response,
    )

    return command_results


def alarm_events_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    alarm_id = args.get('alarm_id')
    if not alarm_id:
        raise DemistoException('Invalid alarm_id')

    alarm_events, raw_response = client.alarm_events_list_request(alarm_id)

    if alarm_events:
        hr = tableToMarkdown(f'Events for alarm {alarm_id}', alarm_events, headerTransform=pascalToSpace,
                             headers=ALARM_EVENTS_HEADERS)
    else:
        hr = f'No events found for alarm {alarm_id}.'

    [event.update({'alarmId': int(alarm_id)}) for event in alarm_events]

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.AlarmEvents',
        outputs_key_field='alarmId',
        outputs=alarm_events,
        raw_response=raw_response,
    )

    return command_results


def alarm_summary_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    alarm_id = args.get('alarm_id')
    if not alarm_id:
        raise DemistoException('Invalid alarm_id')

    alarm_summary, raw_response = client.alarm_summary_request(alarm_id)
    alarm_summary['alarmId'] = int(alarm_id)
    ec = alarm_summary.copy()

    alarm_event_summary = alarm_summary.get('alarmEventSummary')
    if alarm_event_summary:
        del alarm_summary['alarmEventSummary']
        hr = tableToMarkdown('Alarm summary', alarm_summary, headerTransform=pascalToSpace)
        hr = hr + tableToMarkdown('Alarm event summary', alarm_event_summary, headerTransform=pascalToSpace)
    else:
        hr = tableToMarkdown(f'Alarm {alarm_id} summary', alarm_summary, headerTransform=pascalToSpace)

    alarm_summary['alarmId'] = int(alarm_id)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.AlarmSummary',
        outputs_key_field='alarmId',
        outputs=ec,
        raw_response=raw_response,
    )

    return command_results


def get_alarm_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    alarm_id = args.get('alarm_id')
    if not alarm_id:
        raise DemistoException('Invalid alarm_id')

    alarm_details, raw_response = client.get_alarm_details_request(alarm_id)
    alarm_details['alarmId'] = int(alarm_id)
    ec = alarm_details.copy()

    hr = tableToMarkdown(f'Alarm {alarm_id} details', alarm_details, headerTransform=pascalToSpace)

    alarm_details['alarmId'] = int(alarm_id)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.AlarmDetails',
        outputs_key_field='alarmId',
        outputs=ec,
        raw_response=raw_response,
    )

    return command_results


def alarm_drilldown_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    alarm_id = args.get('alarm_id')
    if not alarm_id:
        raise DemistoException('Invalid alarm_id')
    drilldown_results, raw_response = client.alarm_drilldown_request(alarm_id)
    demisto.debug(f"alarm_drilldown_command {drilldown_results=}, {type(drilldown_results)}")
    demisto.debug(f"alarm_drilldown_command {raw_response=}, {type(raw_response)}")
    drilldown_results['AlarmID'] = int(alarm_id)
    ec = drilldown_results.copy()

    hr = tableToMarkdown(f'Alarm {alarm_id} Drilldown', drilldown_results, headerTransform=pascalToSpace)

    drilldown_results['AlarmID'] = int(alarm_id)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.AlarmDrilldown',
        outputs_key_field='AlarmID',
        outputs=ec,
        raw_response=raw_response,
    )

    return command_results


def alarm_drilldown_valid_empty_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    alarm_id = args.get('alarm_id')
    if not alarm_id:
        raise DemistoException('Invalid alarm_id')
    drilldown_results, raw_response = client.alarm_drilldown_valid_empty_request(alarm_id)
    demisto.debug(f"alarm_drilldown_valid_empty_command {drilldown_results=}, {type(drilldown_results)}")
    demisto.debug(f"alarm_drilldown_valid_empty_command {raw_response=}, {type(raw_response)}")

    command_results = CommandResults(
        readable_output="Successfully finished."
    )

    return command_results

def alarm_drilldown_raw_response_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    alarm_id = args.get('alarm_id')
    if not alarm_id:
        raise DemistoException('Invalid alarm_id')
    drilldown_results, raw_response = client.alarm_drilldown_raw_response_request(alarm_id)
    demisto.debug(f"alarm_drilldown_raw_response_command {type(raw_response)}, {raw_response=}")
    demisto.debug(f"alarm_drilldown_raw_response_command {type(drilldown_results), {drilldown_results}}")
    command_results = CommandResults(
        readable_output="Successfully finished.",
    )

    return command_results


def cases_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    timestamp_filter_type = args.get('timestamp_filter_type')
    timestamp = args.get('timestamp')
    priority = args.get('priority')
    status = args.get('status')
    owners = args.get('owners')
    tags = args.get('tags')
    text = args.get('text')
    evidence_type = args.get('evidence_type')
    reference_id = args.get('reference_id')
    external_id = args.get('external_id')
    offset = args.get('offset')
    count = args.get('count')

    cases = client.cases_list_request(case_id, timestamp_filter_type, timestamp, priority, status, owners, tags,
                                      text, evidence_type, reference_id, external_id, offset, count)

    if cases:
        hr = tableToMarkdown('Cases', cases, headerTransform=pascalToSpace)
    else:
        hr = 'No cases found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Case',
        outputs_key_field='id',
        outputs=cases,
        raw_response=cases,
    )

    return command_results


def case_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    name = args.get('name')
    priority = args.get('priority')
    external_id = args.get('external_id')
    due_date = args.get('due_date')
    summary = args.get('summary')

    response = client.case_create_request(name, priority, external_id, due_date, summary)

    hr = tableToMarkdown('Case created successfully', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Case',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def case_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    name = args.get('name')
    priority = args.get('priority')
    external_id = args.get('external_id')
    due_date = args.get('due_date')
    summary = args.get('summary')
    entity_id = args.get('entity_id')
    resolution = args.get('resolution')

    response = client.case_update_request(case_id, name, priority, external_id, due_date, summary, entity_id,
                                          resolution)

    hr = tableToMarkdown(f'Case {case_id} updated successfully', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Case',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def case_status_change_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    status = args.get('status')

    response = client.case_status_change_request(case_id, status)

    hr = tableToMarkdown('Case status updated successfully', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Case',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def case_evidence_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    evidence_number = args.get('evidence_number')
    evidence_type = args.get('evidence_type')
    status = args.get('status')

    evidences = client.case_evidence_list_request(case_id, evidence_number, evidence_type, status)

    if evidences:
        hr = tableToMarkdown(f'Evidences for case {case_id}', evidences, headerTransform=pascalToSpace,
                             headers=CASE_EVIDENCES_HEADERS)
    else:
        hr = f'No evidences found for case {case_id}.'

    ec = {'CaseID': case_id, 'Evidences': evidences}

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.CaseEvidence',
        outputs_key_field='CaseID',
        outputs=ec,
        raw_response=evidences,
    )

    return command_results


def case_alarm_evidence_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    alarm_numbers = argToList(args.get('alarm_numbers'))

    evidences = client.case_alarm_evidence_add_request(case_id, alarm_numbers)

    hr = tableToMarkdown(f'Alarms added as evidence to case {case_id} successfully', evidences,
                         headerTransform=pascalToSpace, headers=CASE_EVIDENCES_HEADERS)

    ec = [{'CaseID': case_id, 'Evidences': evidences}]

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.AlarmEvidence',
        outputs_key_field='CaseID',
        outputs=ec,
        raw_response=evidences,
    )

    return command_results


def case_note_evidence_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    note = args.get('note')

    evidences = client.case_note_evidence_add_request(case_id, note)
    hr = tableToMarkdown(f'Note added as evidence to case {case_id} successfully', evidences,
                         headerTransform=pascalToSpace, headers=CASE_EVIDENCES_HEADERS)

    ec = [{'CaseID': case_id, 'Evidences': evidences}]

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.NoteEvidence',
        outputs_key_field='',
        outputs=ec,
        raw_response=evidences,
    )

    return command_results


def case_file_evidence_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    entry_id = args.get('entryId')

    evidences = client.case_file_evidence_add_request(case_id, entry_id)
    hr = tableToMarkdown(f'File added as evidence to case {case_id} successfully', evidences,
                         headerTransform=pascalToSpace, headers=CASE_EVIDENCES_HEADERS)

    ec = [{'CaseID': case_id, 'Evidences': evidences}]

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.FileEvidence',
        outputs_key_field='',
        outputs=ec,
        raw_response=evidences,
    )

    return command_results


def case_evidence_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    evidence_number = args.get('evidence_number')

    client.case_evidence_delete_request(case_id, evidence_number)
    command_results = CommandResults(
        readable_output=f'Evidence deleted successfully from case {case_id}.',
    )

    return command_results


def case_file_evidence_download_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    evidence_number = args.get('evidence_number')

    return client.case_file_evidence_download_request(case_id, evidence_number)


def case_tags_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    tag_numbers = argToList(args.get('tag_numbers'))

    response = client.case_tags_add_request(case_id, tag_numbers)
    hr = tableToMarkdown(f'Tags added successfully to case {case_id}', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Case',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def case_tags_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    tag_numbers = argToList(args.get('tag_numbers'))

    response = client.case_tags_remove_request(case_id, tag_numbers)
    hr = tableToMarkdown(f'Tags removed successfully from case {case_id}', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Case',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def tags_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    tag_name = args.get('tag_name')
    offset = args.get('offset')
    count = args.get('count')

    response = client.tags_list_request(tag_name, offset, count)
    if response:
        hr = tableToMarkdown('Tags', response, headerTransform=pascalToSpace, headers=TAG_HEADERS)
    else:
        hr = 'No tags were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Tag',
        outputs_key_field='number',
        outputs=response,
        raw_response=response,
    )

    return command_results


def case_collaborators_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')

    response = client.case_collaborators_list_request(case_id)
    collaborators = response.get('collaborators')

    hr = tableToMarkdown('Case owner', response.get('owner'), headerTransform=pascalToSpace)
    if collaborators:
        hr = hr + tableToMarkdown('Case collaborators', collaborators, headerTransform=pascalToSpace)

    ec = response.copy()
    ec['CaseID'] = case_id

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.CaseCollaborator',
        outputs_key_field='CaseID',
        outputs=ec,
        raw_response=response,
    )

    return command_results


def case_collaborators_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    case_id = args.get('case_id')
    owner = args.get('owner')
    collaborators = argToList(args.get('collaborators'))

    response = client.case_collaborators_update_request(case_id, owner, collaborators)
    collaborators = response.get('collaborators')

    hr = f'### Case {case_id} updated successfully\n'
    hr = hr + tableToMarkdown('Case owner', response.get('owner'), headerTransform=pascalToSpace)
    if collaborators:
        hr = hr + tableToMarkdown('Case collaborators', collaborators, headerTransform=pascalToSpace)

    ec = response.copy()
    ec['CaseID'] = case_id

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.CaseCollaborator',
        outputs_key_field='CaseID',
        outputs=ec,
        raw_response=response,
    )

    return command_results


def entities_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    entity_id = args.get('entity_id')
    parent_entity_id = args.get('parent_entity_id')
    offset = args.get('offset')
    count = args.get('count')

    response = client.entities_list_request(entity_id, parent_entity_id, offset, count)
    if response:
        hr = tableToMarkdown('Entities', response, headerTransform=pascalToSpace, headers=ENTITY_HEADERS)
    else:
        hr = 'No entities were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Entity',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def hosts_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    host_id = args.get('host_id')
    host_name = args.get('host_name')
    entity_name = args.get('entity_name')
    record_status = args.get('record_status')
    offset = args.get('offset')
    count = args.get('count')
    host_ids = [host_id] if host_id else []

    response = client.hosts_list_request(host_name, entity_name, record_status, offset, count, host_ids)
    if response:
        hr = tableToMarkdown('Hosts', response, headerTransform=pascalToSpace)
    else:
        hr = 'No hosts were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Host',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def users_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    user_ids = args.get('user_ids')
    entity_ids = args.get('entity_ids')
    user_status = args.get('user_status')
    offset = args.get('offset')
    count = args.get('count')

    response = client.users_list_request(user_ids, entity_ids, user_status, offset, count)
    if response:
        hr = tableToMarkdown('Users', response, headerTransform=pascalToSpace, headers=USER_HEADERS)
    else:
        hr = 'No users were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.User',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def lists_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    list_type = args.get('list_type')
    list_name = args.get('list_name')
    can_edit = args.get('can_edit')

    response = client.lists_get_request(list_type, list_name, can_edit)
    if response:
        hr = tableToMarkdown('Lists', response, headerTransform=pascalToSpace, headers=LIST_HEADERS)
    else:
        hr = 'No lists were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.List',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def list_summary_create_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    list_type = args.get('list_type')
    name = args.get('name')
    enabled = argToBoolean(args.get('enabled'))
    use_patterns = argToBoolean(args.get('use_patterns'))
    replace_existing = argToBoolean(args.get('replace_existing'))
    read_access = args.get('read_access')
    write_access = args.get('write_access')
    restricted_read = argToBoolean(args.get('restricted_read'))
    entity_name = args.get('entity_name')
    need_to_notify = argToBoolean(args.get('need_to_notify'))
    does_expire = argToBoolean(args.get('does_expire'))
    owner = args.get('owner')

    response = client.list_summary_create_update_request(
        list_type, name, enabled, use_patterns, replace_existing, read_access, write_access, restricted_read,
        entity_name,
        need_to_notify, does_expire, owner)

    hr = tableToMarkdown('List created successfully', response, headerTransform=pascalToSpace, headers=LIST_HEADERS)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.List',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def list_details_and_items_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    list_guid = args.get('list_guid')
    max_items = args.get('max_items')

    response, raw_response = client.list_details_and_items_get_request(list_guid, max_items)
    response = response.copy()
    list_items = response.get('items')
    response.pop('items', None)

    hr = tableToMarkdown(f'List {list_guid} details', response, headerTransform=pascalToSpace, headers=LIST_HEADERS)
    if list_items:
        hr = hr + tableToMarkdown('List items', list_items, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.ListDetails',
        outputs_key_field='guid',
        outputs=raw_response,
        raw_response=raw_response,
    )

    return command_results


def list_items_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    list_guid = args.get('list_guid')
    items_json = args.get('items')
    if not items_json:
        raise DemistoException('Invalid items_json')

    try:
        items = json.loads(items_json)
    except ValueError as e:
        demisto.error(f'Unable to parse the items arg in lr-list-items-add command: {e}')
        raise DemistoException('Unable to parse JSON string. Please verify the items argument is valid.')

    response = client.list_items_add_request(list_guid, items)
    hr = tableToMarkdown(f'The item added to the list {list_guid}.', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.ListItemsAdd',
        outputs_key_field='guid',
        outputs=response,
        raw_response=response,
    )

    return command_results


def list_items_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    list_guid = args.get('list_guid')
    items_json = args.get('items')
    if not items_json:
        raise DemistoException('Invalid items_json')

    try:
        items = json.loads(items_json)
    except ValueError as e:
        demisto.error(f'Unable to parse the items arg in lr-list-items-remove command: {e}')
        raise DemistoException('Unable to parse JSON string. Please verify the items argument is valid.')

    response = client.list_items_remove_request(list_guid, items)
    hr = tableToMarkdown(f'The item deleted from the list {list_guid}.', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.ListItemsRemove',
        outputs_key_field='guid',
        outputs=response,
        raw_response=response,
    )

    return command_results


def execute_search_query_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    number_of_days = args.get('number_of_days')
    search_name = args.get('search_name')
    source_type = args.get('source_type')
    host_name = args.get('host_name')
    username = args.get('username')
    subject = args.get('subject')
    sender = args.get('sender')
    recipient = args.get('recipient')
    hash_ = args.get('hash')
    url = args.get('url')
    process_name = args.get('process_name')
    object_ = args.get('object')
    ipaddress = args.get('ip_address')
    max_message = args.get('max_message')
    query_timeout = args.get('query_timeout')
    entity_id = args.get('entity_id')
    page_size = args.get('page_size', 50)
    interval_in_secs = int(args.get('interval_in_seconds', 10))

    response = client.execute_search_query_request(number_of_days, source_type, host_name, username, subject, sender,
                                                   recipient, hash_, url, process_name, object_, ipaddress, max_message,
                                                   query_timeout, entity_id)
    task_id = response.get('TaskId')
    ec = {'TaskId': task_id, 'StatusMessage': response.get('StatusMessage')}

    if not search_name:
        search_name = f'LogRhythm search {datetime.now()}'
    ec['SearchName'] = search_name

    if not is_demisto_version_ge('6.2.0'):  # only 6.2.0 version and above support polling command.
        return CommandResults(
            readable_output=f'New search query created, Task ID={task_id}',
            outputs_prefix='LogRhythm.Search',
            outputs_key_field='TaskId',
            outputs=ec,
            raw_response=response,
        )

    get_results_args = {'task_id': task_id, 'page_size': page_size}
    query_results = client.get_query_result_request(task_id, page_size)
    items = query_results.get('Items', [])
    status = query_results.get('TaskStatus')

    if items:
        hr = tableToMarkdown(f'Search results for task {task_id}', items, headerTransform=pascalToSpace)
    else:
        hr = f'Task status: {status}'

    ec['TaskId'] = task_id
    ec['TaskStatus'] = status
    ec['Results'] = items

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Search',
        outputs_key_field='TaskId',
        outputs=ec,
        raw_response=query_results,
    )

    if status == 'Searching':
        scheduled_command = ScheduledCommand(command='lr-get-query-result', next_run_in_seconds=interval_in_secs,
                                             args=get_results_args, timeout_in_seconds=600)
        command_results.scheduled_command = scheduled_command
        return command_results

    return command_results


def get_query_result_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    task_id = args.get('task_id')
    page_size = args.get('page_size')

    response = client.get_query_result_request(task_id, page_size)

    items = response.get('Items')
    status = response.get('TaskStatus')
    if items:
        hr = tableToMarkdown(f'Search results for task {task_id}', items, headerTransform=pascalToSpace)
    else:
        hr = f'Task status: {status}'

    ec = [{'TaskId': task_id, 'TaskStatus': status, 'Results': items}]

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Search',
        outputs_key_field='TaskId',
        outputs=ec,
        raw_response=response,
    )

    return command_results


def add_host_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    entity_id = args.get('entity-id')
    entity_name = args.get('entity-name')
    name = args.get('name')
    short_desc = args.get('short-description')
    long_desc = args.get('long-description')
    risk_level = args.get('risk-level')
    threat_level = args.get('threat-level')
    threat_level_comments = args.get('threat-level-comments')
    status = args.get('host-status')
    host_zone = args.get('host-zone')
    use_eventlog_credentials = argToBoolean(args.get('use-eventlog-credentials'))
    os_type = args.get('os-type')
    os = args.get('os')

    response = client.add_host_request(entity_id, entity_name, name, short_desc, long_desc, risk_level, threat_level,
                                       threat_level_comments, status, host_zone, use_eventlog_credentials,
                                       os, os_type)

    hr = tableToMarkdown('Host added successfully', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Host',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def hosts_status_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    host_id = args.get('host_id')
    status = args.get('host_status')

    response = client.hosts_status_update(host_id, status)
    command_results = CommandResults(
        readable_output=f'Host status updated successfully to {status}.',
        raw_response=response,
    )

    return command_results


def networks_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    network_id = args.get('network_id')
    name = args.get('name')
    record_status = args.get('record_status')
    bip = args.get('bip')
    eip = args.get('eip')
    count = args.get('count')
    offset = args.get('offset')

    response = client.networks_list_request(network_id, name, record_status, bip, eip, offset, count)
    if response:
        hr = tableToMarkdown('Networks', response, headerTransform=pascalToSpace, headers=NETWORK_HEADERS)
    else:
        hr = 'No networks were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Network',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )

    return command_results


def endpoint_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:  # pragma: no cover
    endpoint_id_list = argToList(args.get('id'))
    endpoint_hostname_list = argToList(args.get('hostname'))

    endpoints = client.hosts_list_request(endpoint_id_list=endpoint_id_list,
                                          endpoint_hostname_list=endpoint_hostname_list)

    if type(endpoints) is dict:
        endpoints = [endpoints]

    command_results = []

    if endpoints:
        for endpoint in endpoints:
            hr = tableToMarkdown('Logrhythm endpoint', endpoint, headerTransform=pascalToSpace)

            endpoint_indicator = Common.Endpoint(
                id=endpoint.get('id'),
                hostname=endpoint.get('name'),
                os=endpoint.get('os'),
                os_version=endpoint.get('osVersion'),
                status='Online' if endpoint.get('recordStatusName') == "Active" else 'Offline')

            command_results.append(CommandResults(
                readable_output=hr,
                raw_response=endpoint,
                indicator=endpoint_indicator,
            ))

    else:
        command_results.append(CommandResults(
            readable_output="No endpoints were found.",
            raw_response=endpoints,
        ))
    return command_results


def test_module(client: Client, is_fetch: bool, fetch_type: str, cases_max_fetch: int, alarms_max_fetch: int,
                fetch_time: str) -> None:  # pragma: no cover
    client.lists_get_request(None, None, None)
    if is_fetch:
        fetch_incidents_command(client, fetch_type, cases_max_fetch, alarms_max_fetch, fetch_time)
    return_results('ok')


def fetch_incidents_command(client: Client, fetch_type: str, cases_max_fetch: int, alarms_max_fetch: int,
                            fetch_time: str, alarm_status_filter: str = '', alarm_rule_name_filter: str = '',
                            case_tags_filter: str = '', case_status_filter: str = '',
                            case_priority_filter: str = '', fetch_case_evidences=False):  # pragma: no cover
    if fetch_type == 'Both':
        case_incidents = fetch_cases(client, cases_max_fetch, fetch_time, fetch_case_evidences,
                                     case_tags_filter, case_status_filter, case_priority_filter)
        alarm_incidents = fetch_alarms(client, alarms_max_fetch, fetch_time,
                                       alarm_status_filter, alarm_rule_name_filter)
        return case_incidents + alarm_incidents
    elif fetch_type == 'Alarms':
        return fetch_alarms(client, alarms_max_fetch, fetch_time, alarm_status_filter, alarm_rule_name_filter)
    elif fetch_type == 'Cases':
        return fetch_cases(client, cases_max_fetch, fetch_time, fetch_case_evidences,
                           case_tags_filter, case_status_filter, case_priority_filter)


def fetch_alarms(client: Client, limit: int, fetch_time: str, alarm_status_filter: str,
                 alarm_rule_name_filter: str):  # pragma: no cover
    alarm_incidents = []
    last_run = demisto.getLastRun()
    alarm_last_run = last_run.get('AlarmLastRun')
    fetch_time_date = dateparser.parse(fetch_time)
    assert fetch_time_date is not None, f'could not parse {fetch_time}'
    first_run = fetch_time_date.strftime("%Y-%m-%dT%H:%M:%S")

    alarms_list_args: dict = {'count': limit}

    if alarm_last_run:
        alarms_list_args['created_after'] = alarm_last_run
    elif first_run:
        alarms_list_args['created_after'] = first_run

    # filter alerts
    if alarm_status_filter:
        alarms_list_args['alarm_status'] = alarm_status_filter  # type: ignore
    if alarm_rule_name_filter:
        alarms_list_args['alarm_rule_name'] = alarm_rule_name_filter  # type: ignore

    alarms, _ = client.alarms_list_request(**alarms_list_args)

    for alarm in alarms:
        alarm['incidentType'] = 'Alarm'
        incident = {
            'name': f'Alarm #{alarm.get("alarmId")} {alarm.get("alarmRuleName")}',
            'occurred': f'{alarm.get("dateInserted")}Z',
            'labels': [{'type': 'alarmId', 'value': str(alarm.get('alarmId'))}],
            'rawJSON': json.dumps(alarm)
        }
        alarm_incidents.append(incident)

    if alarms:
        last_run['AlarmLastRun'] = alarms[0].get('dateInserted')
        demisto.setLastRun(last_run)
    return alarm_incidents


def fetch_cases(client: Client, limit: int, fetch_time: str, fetch_case_evidences: bool,
                case_tags_filter: str, case_status_filter: str, case_priority_filter: str):  # pragma: no cover
    case_incidents = []
    last_run = demisto.getLastRun()
    case_last_run = last_run.get('CaseLastRun')
    fetch_time_date = dateparser.parse(fetch_time)
    assert fetch_time_date is not None, f'could not parse {fetch_time}'
    first_run = fetch_time_date.strftime("%Y-%m-%dT%H:%M:%SZ")

    cases_list_args = {'count': limit}

    if case_last_run:
        cases_list_args['timestamp_filter_type'] = 'createdAfter'  # type: ignore
        cases_list_args['timestamp'] = case_last_run
    elif first_run:
        cases_list_args['timestamp_filter_type'] = 'createdAfter'  # type: ignore
        cases_list_args['timestamp'] = first_run  # type: ignore

    # filter cases
    if case_tags_filter:
        cases_list_args['tags'] = case_tags_filter  # type: ignore
    if case_status_filter:
        cases_list_args['status'] = str(CASE_STATUS.get(case_status_filter))  # type: ignore
    if case_priority_filter:
        cases_list_args['priority'] = case_priority_filter  # type: ignore

    cases = client.cases_list_request(**cases_list_args)

    for case in cases:
        file_names = []
        case['incidentType'] = 'Case'

        if fetch_case_evidences:
            case_id = case.get('id')
            evidences = client.case_evidence_list_request(case_id)
            case['CaseEvidence'] = evidences
            for evidence in evidences:
                if evidence.get('type') == 'file':
                    file_result = client.case_file_evidence_download_request(case_id, evidence.get('number'))
                    file_names.append({
                        'path': file_result.get('FileID'),
                        'name': file_result.get('File')})

        incident = {
            'name': f'Case #{case.get("number")} {case.get("name")}',
            'occurred': case.get('dateCreated'),
            'attachment': file_names,
            'rawJSON': json.dumps(case)
        }
        case_incidents.append(incident)

    if cases:
        last_run['CaseLastRun'] = cases[-1].get('dateCreated')
        demisto.setLastRun(last_run)
    return case_incidents


def main() -> None:  # pragma: no cover
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    incidents_type = params.get('fetchType', 'Both')
    fetch_time = params.get('first_fetch', '7 days')
    is_fetch: bool = params.get('isFetch', False)
    alarms_max_fetch = params.get('alarmsMaxFetch', 100)
    cases_max_fetch = params.get('casesMaxFetch', 100)
    alarm_status_filter = params.get('alarm_status_filter', '')
    alarm_rule_name_filter = params.get('alarm_rule_name_filter', '')
    case_priority_filter = params.get('case_priority_filter', '')
    case_status_filter = params.get('case_status_filter', '')
    case_tags_filter = params.get('case_tags_filter', '')
    fetch_case_evidences = params.get('fetch_case_evidences', False)

    api_key = params.get('credentials', {}).get('password')
    headers = {'Authorization': f'Bearer {api_key}'}

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'lr-alarms-list': alarms_list_command,
            'lr-alarm-update': alarm_update_command,
            'lr-alarm-add-comment': alarm_add_comment_command,
            'lr-alarm-history-list': alarm_history_list_command,
            'lr-alarm-events-list': alarm_events_list_command,
            'lr-alarm-summary': alarm_summary_command,
            'lr-get-alarm-details': get_alarm_details_command,
            'lr-alarm-drilldown': alarm_drilldown_command,
            'lr-alarm-drilldown-test1': alarm_drilldown_raw_response_command,
            'lr-alarm-drilldown-test2': alarm_drilldown_valid_empty_command,
            'lr-cases-list': cases_list_command,
            'lr-case-create': case_create_command,
            'lr-case-update': case_update_command,
            'lr-case-status-change': case_status_change_command,
            'lr-case-evidence-list': case_evidence_list_command,
            'lr-case-alarm-evidence-add': case_alarm_evidence_add_command,
            'lr-case-note-evidence-add': case_note_evidence_add_command,
            'lr-case-file-evidence-add': case_file_evidence_add_command,
            'lr-case-evidence-delete': case_evidence_delete_command,
            'lr-case-file-evidence-download': case_file_evidence_download_command,
            'lr-case-tags-add': case_tags_add_command,
            'lr-case-tags-remove': case_tags_remove_command,
            'lr-tags-list': tags_list_command,
            'lr-case-collaborators-list': case_collaborators_list_command,
            'lr-case-collaborators-update': case_collaborators_update_command,
            'lr-entities-list': entities_list_command,
            'lr-hosts-list': hosts_list_command,
            'lr-users-list': users_list_command,
            'lr-lists-get': lists_get_command,
            'lr-list-summary-create-update': list_summary_create_update_command,
            'lr-list-details-and-items-get': list_details_and_items_get_command,
            'lr-list-items-add': list_items_add_command,
            'lr-list-items-remove': list_items_remove_command,
            'lr-execute-search-query': execute_search_query_command,
            'lr-get-query-result': get_query_result_command,
            'lr-add-host': add_host_command,
            'lr-hosts-status-update': hosts_status_update_command,
            'lr-networks-list': networks_list_command,
            'endpoint': endpoint_command,
        }

        if command == 'test-module':
            test_module(client, is_fetch, incidents_type, cases_max_fetch, alarms_max_fetch, fetch_time)
        elif command == 'fetch-incidents':
            demisto.incidents(fetch_incidents_command(client, incidents_type, cases_max_fetch, alarms_max_fetch,
                                                      fetch_time, alarm_status_filter=alarm_status_filter,
                                                      alarm_rule_name_filter=alarm_rule_name_filter,
                                                      case_tags_filter=case_tags_filter,
                                                      case_status_filter=case_status_filter,
                                                      case_priority_filter=case_priority_filter,
                                                      fetch_case_evidences=fetch_case_evidences))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

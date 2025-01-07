Use the xDome integration to manage assets and alerts.
This integration was integrated and tested with version 1.0.0 of XDome.

## Configure xDome in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| XDome public API base URL |  | True |
| API Token | The API token to use for connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| The initial time to fetch from |  | True |
| Fetch Only Unresolved Device-Alert Pairs |  | False |
| Alert Types Selection | If no alert types are selected, all types will be fetched | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### xdome-get-device-alert-relations

***
Gets all device-alert pairs from xDome. You can apply a query-filter.

#### Base Command

`xdome-get-device-alert-relations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Fields to return. Possible values are: all, alert_assignees, alert_category, alert_class, alert_id, alert_labels, alert_name, alert_type_name, alert_description, device_alert_detected_time, device_alert_status, device_alert_updated_time, device_assignees, device_category, device_effective_likelihood_subscore, device_effective_likelihood_subscore_points, device_first_seen_list, device_impact_subscore, device_impact_subscore_points, device_insecure_protocols, device_insecure_protocols_points, device_internet_communication, device_ip_list, device_known_vulnerabilities, device_known_vulnerabilities_points, device_labels, device_last_seen_list, device_likelihood_subscore, device_likelihood_subscore_points, device_mac_list, device_manufacturer, device_name, device_network_list, device_purdue_level, device_retired, device_risk_score, device_risk_score_points, device_site_name, device_subcategory, device_type, device_uid, mitre_technique_enterprise_ids, mitre_technique_enterprise_names, mitre_technique_ics_ids, mitre_technique_ics_names. Default is all. | Optional | 
| filter_by | A filter_by object, refer to the xDome API documentation. | Optional | 
| offset | An offset in the data. This can be used to fetch all data in a paginated manner, by e.g requesting (offset=0, limit=100) followed by (offset=100, limit=100), (offset=200, limit=100), etc. | Optional | 
| limit | Maximum amount of items to fetch. | Optional | 
| sort_by | Default: [{"field":"device_uid","order":"asc"},{"field":"alert_id","order":"asc"}]. Specifies how the returned data should be sorted. If more than one sort clause is passed, additional clauses will be used to sort data that is equal in all previous clauses. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XDome.DeviceAlert.alert_id | Number | Platform unique Alert ID. | 
| XDome.DeviceAlert.alert_name | String | The alert name, such as “Malicious Internet Communication: 62.172.138.35”. | 
| XDome.DeviceAlert.alert_type_name | String | An alert type such as "Outdated Firmware". | 
| XDome.DeviceAlert.alert_class | String | The alert class, such as “Pre-Defined Alerts” and “Custom Alerts”. | 
| XDome.DeviceAlert.alert_category | String | Alert category such as "Risk" or "Segmentation". | 
| XDome.DeviceAlert.alert_labels | String | The labels added to the alert manually or automatically. | 
| XDome.DeviceAlert.alert_assignees | String | The users and or groups the alert is assigned to. | 
| XDome.DeviceAlert.alert_description | String | The alert description, such as "SMBv1 Communication was detected by 2 OT Device devices". | 
| XDome.DeviceAlert.device_alert_detected_time | Date | Date and time when the Alert was first detected. | 
| XDome.DeviceAlert.device_alert_updated_time | Date | Date and time of last Alert update. | 
| XDome.DeviceAlert.device_alert_status | String | Device-Alert relation status \(Resolved or Unresolved\). | 
| XDome.DeviceAlert.device_uid | UUID | A universal unique identifier \(UUID\) for the device. | 
| XDome.DeviceAlert.device_name | String | The Device Name attribute is set automatically based on the priority of the Auto-Assigned Device attribute. You can also set it manually. The Device Name can be the device’s IP, hostname, etc. | 
| XDome.DeviceAlert.device_ip_list | List | IP address associated with the device. IPs may be suffixed by a / \(annotation\), where annotation may be a child device ID or \(Last Known IP\). | 
| XDome.DeviceAlert.device_mac_list | List | MAC address associated with the device. | 
| XDome.DeviceAlert.device_network_list | List | The network types, "Corporate" and or "Guest", that the device belongs to. | 
| XDome.DeviceAlert.device_category | String | The device category group \(see "About Device Categorization" in the Knowledge Base\). | 
| XDome.DeviceAlert.device_subcategory | String | The device sub-category group \(see "About Device Categorization" in the Knowledge Base\). | 
| XDome.DeviceAlert.device_type | String | The device type group \(see "About Device Categorization" in the Knowledge Base\). | 
| XDome.DeviceAlert.device_assignees | String | The users and or groups the device is assigned to. | 
| XDome.DeviceAlert.device_labels | String | The labels added to the device manually or automatically. | 
| XDome.DeviceAlert.device_retired | String | A boolean field indicating if the device is retired or not. | 
| XDome.DeviceAlert.device_purdue_level | String | The network layer the device belongs to, based on the Purdue Reference Model for Industrial Control System \(ICS\). The network segmentation-based model defines OT and IT systems into six levels and the logical network boundary controls for securing these networks. | 
| XDome.DeviceAlert.device_site_name | String | The name of the site within the organization the device is associated with. | 
| XDome.DeviceAlert.device_first_seen_list | List | The date and time a device's NIC was first seen. | 
| XDome.DeviceAlert.device_last_seen_list | List | The date and time a device's NIC was last seen. | 
| XDome.DeviceAlert.device_risk_score | String | The calculated risk level of a device, such as "Critical", or "High". | 
| XDome.DeviceAlert.device_risk_score_points | Number | The calculated risk points of a device, such as "54.1". | 
| XDome.DeviceAlert.device_effective_likelihood_subscore | String | The calculated effective likelihood subscore level of a device, such as "Critical", or "High". | 
| XDome.DeviceAlert.device_effective_likelihood_subscore_points | Number | The calculated effective likelihood subscore points of a device, such as "54.1". | 
| XDome.DeviceAlert.device_likelihood_subscore | String | The calculated likelihood subscore level of a device, such as "Critical", or "High". | 
| XDome.DeviceAlert.device_likelihood_subscore_points | Number | The calculated likelihood subscore points of a device, such as "54.1". | 
| XDome.DeviceAlert.device_impact_subscore | String | The calculated impact subscore level of a device, such as "Critical", or "High". | 
| XDome.DeviceAlert.device_impact_subscore_points | Number | The calculated impact subscore points of a device, such as "54.1". | 
| XDome.DeviceAlert.device_insecure_protocols | String | The calculated level of the device’s ‘insecure protocols’ likelihood factor, such as "Critical", or "High". | 
| XDome.DeviceAlert.device_insecure_protocols_points | Number | The calculated points for ‘insecure protocols’ likelihood factor of a device, such as "54.1". | 
| XDome.DeviceAlert.device_internet_communication | String | The manner of the device's communication over the internet. | 
| XDome.DeviceAlert.device_known_vulnerabilities | String | The calculated level of the device’s ‘known vulnerabilities’ likelihood factor, such as "Critical", or "High". | 
| XDome.DeviceAlert.device_known_vulnerabilities_points | Number | The calculated points for ‘known vulnerabilities’ likelihood factor of a device, such as "54.1". | 
| XDome.DeviceAlert.device_manufacturer | String | Manufacturer of the device, such as "Alaris". | 
| XDome.DeviceAlert.mitre_technique_enterprise_ids | List | MITRE ATT&amp;CK® Enterprise technique IDs mapped to the alert. | 
| XDome.DeviceAlert.mitre_technique_enterprise_names | List | MITRE ATT&amp;CK® Enterprise technique names mapped to the alert. | 
| XDome.DeviceAlert.mitre_technique_ics_ids | List | MITRE ATT&amp;CK® ICS technique IDs mapped to the alert. | 
| XDome.DeviceAlert.mitre_technique_ics_names | List | MITRE ATT&amp;CK® ICS technique names mapped to the alert. | 

### xdome-set-status-for-device-alert-relations

***
Set device-alert status to resolved or unresolved.

#### Base Command

`xdome-set-status-for-device-alert-relations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID, as indicated in the id field of an alert. | Required | 
| device_uids | Device UUIDs, as indicated in the uid field of a device. | Optional | 
| status | Set the device-alert status to resolve or unresolved. Possible values are: resolved, unresolved. | Required | 

#### Context Output

There is no context output for this command.
### xdome-get-device-vulnerability-relations

***
Get details of devices with their related vulnerabilities from the database. The data returned by this endpoint for each device corresponds to the vulnerabilities table in the single device page.

#### Base Command

`xdome-get-device-vulnerability-relations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Fields to return. Possible values are: all, device_network_list, device_category, device_subcategory, device_type, device_uid, device_asset_id, device_mac_list, device_ip_list, device_type_family, device_model, device_os_category, device_serial_number, device_vlan_list, device_retired, device_labels, device_assignees, device_hw_version, device_local_name, device_os_name, device_os_version, device_os_revision, device_os_subcategory, device_combined_os, device_endpoint_security_names, device_equipment_class, device_consequence_of_failure, device_management_services, device_ad_distinguished_name, device_ad_description, device_mdm_ownership, device_mdm_enrollment_status, device_mdm_compliance_status, device_last_domain_user, device_fda_class, device_mobility, device_purdue_level, device_purdue_level_source, device_dhcp_hostnames, device_http_hostnames, device_snmp_hostnames, device_windows_hostnames, device_other_hostnames, device_windows_last_seen_hostname, device_dhcp_last_seen_hostname, device_http_last_seen_hostname, device_snmp_last_seen_hostname, device_ae_titles, device_dhcp_fingerprint, device_note, device_domains, device_battery_level, device_internet_communication, device_financial_cost, device_handles_pii, device_machine_type, device_phi, device_cmms_state, device_cmms_ownership, device_cmms_asset_tag, device_cmms_campus, device_cmms_building, device_cmms_location, device_cmms_floor, device_cmms_department, device_cmms_owning_cost_center, device_cmms_asset_purchase_cost, device_cmms_room, device_cmms_manufacturer, device_cmms_model, device_cmms_serial_number, device_cmms_last_pm, device_cmms_technician, device_edr_is_up_to_date_text, device_mac_oui_list, device_ip_assignment_list, device_protocol_location_list, device_vlan_name_list, device_vlan_description_list, device_connection_type_list, device_ssid_list, device_bssid_list, device_wireless_encryption_type_list, device_ap_name_list, device_ap_location_list, device_switch_mac_list, device_switch_ip_list, device_switch_name_list, device_switch_port_list, device_switch_location_list, device_switch_port_description_list, device_wlc_name_list, device_wlc_location_list, device_applied_acl_list, device_applied_acl_type_list, device_collection_servers, device_edge_locations, device_number_of_nics, device_last_domain_user_activity, device_last_scan_time, device_edr_last_scan_time, device_retired_since, device_os_eol_date, device_last_seen_list, device_first_seen_list, device_wifi_last_seen_list, device_last_seen_on_switch_list, device_is_online, device_network_scope_list, device_ise_authentication_method_list, device_ise_endpoint_profile_list, device_ise_identity_group_list, device_ise_security_group_name_list, device_ise_security_group_tag_list, device_ise_logical_profile_list, device_cppm_authentication_status_list, device_cppm_roles_list, device_cppm_service_list, device_name, device_manufacturer, device_site_name, device_risk_score, device_risk_score_points, device_effective_likelihood_subscore, device_effective_likelihood_subscore_points, device_likelihood_subscore, device_likelihood_subscore_points, device_impact_subscore, device_impact_subscore_points, device_known_vulnerabilities, device_known_vulnerabilities_points, device_insecure_protocols, device_insecure_protocols_points, device_suspicious, device_switch_group_name_list, device_managed_by, device_authentication_user_list, device_collection_interfaces, device_slot_cards, device_cmms_financial_cost, device_software_or_firmware_version, device_enforcement_or_authorization_profiles_list, device_ise_security_group_description_list, device_recommended_firewall_group_name, device_recommended_zone_name, vulnerability_id, vulnerability_name, vulnerability_type, vulnerability_cve_ids, vulnerability_cvss_v2_score, vulnerability_cvss_v2_exploitability_subscore, vulnerability_cvss_v3_score, vulnerability_cvss_v3_exploitability_subscore, vulnerability_adjusted_vulnerability_score, vulnerability_adjusted_vulnerability_score_level, vulnerability_epss_score, vulnerability_sources, vulnerability_description, vulnerability_affected_products, vulnerability_recommendations, vulnerability_exploits_count, vulnerability_is_known_exploited, vulnerability_published_date, vulnerability_labels, vulnerability_assignees, vulnerability_note, vulnerability_last_updated, vulnerability_relevance, vulnerability_relevance_sources, vulnerability_manufacturer_remediation_info, vulnerability_manufacturer_remediation_info_source, vulnerability_overall_cvss_v3_score, device_vulnerability_detection_date, device_vulnerability_resolution_date, device_vulnerability_days_to_resolution, patch_install_date. Default is all. | Optional | 
| filter_by | A filter_by object, refer to the xDome API documentation. Input as a string and dont forget to escape quotes (\"). | Optional | 
| sort_by | Default: [{"field":"device_uid","order":"asc"}, {"field":"vulnerability_id","order":"asc"}]. Specifies how the returned data should be sorted. If more than one sort clause is passed, additional clauses will be used to sort data that is equal in all previous clauses. | Optional | 
| offset | An offset in the data. This can be used to fetch all data in a paginated manner, by e.g requesting (offset=0, limit=100) followed by (offset=100, limit=100), (offset=200, limit=100), etc. | Optional | 
| limit | Maximum amount of items to fetch. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XDome.DeviceVulnerability.vulnerability_name | String | Name designated by Claroty's Research team, based on the advisory name or CVE ID. | 
| XDome.DeviceVulnerability.vulnerability_type | String | Type such as "Application", "Clinical", "IoT" or "Platform". | 
| XDome.DeviceVulnerability.vulnerability_cve_ids | List | Relevant Common Vulnerability Exploits for the selected vulnerability. | 
| XDome.DeviceVulnerability.vulnerability_cvss_v3_score | Number | Common Vulnerability Scoring System Version 3 score \(0-10\). In case of multiple CVEs, the highest Subscore is displayed. | 
| XDome.DeviceVulnerability.vulnerability_adjusted_vulnerability_score | Number | The Adjusted Vulnerability Score represents the vulnerability score based on its impact and exploitability. | 
| XDome.DeviceVulnerability.vulnerability_adjusted_vulnerability_score_level | String | The calculated Adjusted vulnerability Score \(AVS\) level of a vulnerability, such as "Critical", or "High". | 
| XDome.DeviceVulnerability.vulnerability_epss_score | Number | A probability score between 0 to 1 indicating the likelihoodof a vulnerability to be exploited in the wild, based on the Exploit Prediction Scoring System \(EPSS\) model. | 
| XDome.DeviceVulnerability.vulnerability_description | String | Details about the vulnerability. | 
| XDome.DeviceVulnerability.vulnerability_exploits_count | Number | An aggregated numeric field of the number of known exploits based on ExploitDB. | 
| XDome.DeviceVulnerability.vulnerability_is_known_exploited | Boolean | A boolean field indicating whether a vulnerability is currently exploited in-the-wild, based on the CISA Catalog of Known Exploited Vulnerabilities. | 
| XDome.DeviceVulnerability.vulnerability_published_date | Date | The date and time the vulnerability was released. | 
| XDome.DeviceVulnerability.vulnerability_relevance | String | The device vulnerability relevance reflects the confidence level of the detection process, corresponding to several components, such as the vulnerability type. | 
| XDome.DeviceVulnerability.device_vulnerability_detection_date | Date | The date when the vulnerability was initially detected on the device. A vulnerability is considered detected once marked as “confirmed” or “potentially relevant” for the respective device. | 
| XDome.DeviceVulnerability.device_network_list | List | The network types, "Corporate" and or "Guest", that the device belongs to. | 
| XDome.DeviceVulnerability.device_category | String | The device category group \(see "About Device Categorization" in the Knowledge Base\). | 
| XDome.DeviceVulnerability.device_subcategory | String | The device sub-category group \(see "About Device Categorization" in the Knowledge Base\). | 
| XDome.DeviceVulnerability.device_type | String | The device type group \(see "About Device Categorization" in the Knowledge Base\). | 
| XDome.DeviceVulnerability.device_uid | String | A universal unique identifier \(UUID\) for the device. | 
| XDome.DeviceVulnerability.device_asset_id | String | Asset ID. | 
| XDome.DeviceVulnerability.device_mac_list | List | MAC address associated with the device. | 
| XDome.DeviceVulnerability.device_ip_list | List | IP address associated with the device. IPs may be suffixed by a / \(annotation\), where annotation may be a child device ID or \(Last Known IP\). | 
| XDome.DeviceVulnerability.device_type_family | String | The device type family group \(see "About Device Categorization" in the Knowledge Base\). | 
| XDome.DeviceVulnerability.device_model | String | The device's model. | 
| XDome.DeviceVulnerability.device_os_category | String | The device's OS category, such as "Windows", "Linux" or "Other". | 
| XDome.DeviceVulnerability.device_serial_number | String | The device's serial number. | 
| XDome.DeviceVulnerability.device_vlan_list | List | The virtual LAN to which the device belongs. | 
| XDome.DeviceVulnerability.device_labels | List | The labels added to the device manually or automatically. | 
| XDome.DeviceVulnerability.device_assignees | List | The users and or groups the device is assigned to. | 
| XDome.DeviceVulnerability.device_hw_version | String | The hardware version of the device. | 
| XDome.DeviceVulnerability.device_local_name | String | Similar to hostname, the device name identifier is extracted from protocol traffic. | 
| XDome.DeviceVulnerability.device_combined_os | String | The aggregated value of OS name, version and revision, such as "Windows XP SP3". | 
| XDome.DeviceVulnerability.device_endpoint_security_names | List | The names of endpoint security applications installed on the device. | 
| XDome.DeviceVulnerability.device_equipment_class | String | Determines the equipment class of the device, according to The Joint Commission \(TJC\). | 
| XDome.DeviceVulnerability.device_management_services | String | Defines whether the device is managed by Active Directory, Mobile Device Management, or neither. | 
| XDome.DeviceVulnerability.device_purdue_level | String | The network layer the device belongs to, based on the Purdue Reference Model for Industrial Control System \(ICS\). The network segmentation-based model defines OT and IT systems into six levels and the logical network boundary controls for securing these networks. | 
| XDome.DeviceVulnerability.device_http_last_seen_hostname | String | The most recent unique hostname identifier of the device, extracted from HTTP protocol traffic. | 
| XDome.DeviceVulnerability.device_snmp_last_seen_hostname | String | The most recent unique hostname identifier of the device, extracted from SNMP protocol traffic. | 
| XDome.DeviceVulnerability.device_note | String | The notes added to the device. | 
| XDome.DeviceVulnerability.device_domains | List | The domain name of the network that the device belongs to. | 
| XDome.DeviceVulnerability.device_internet_communication | String | The manner of the device's communication over the internet. | 
| XDome.DeviceVulnerability.device_edr_is_up_to_date_text | String | Determines whether the endpoint security application installed on the device is up-to-date. | 
| XDome.DeviceVulnerability.device_mac_oui_list | List | The vendor of the device's NIC, according to the OUI \(Organizational Unique Identifier\) in the MAC address. | 
| XDome.DeviceVulnerability.device_ip_assignment_list | List | The device's IP assignment method, extracted from DHCP protocol traffic, such as "DHCP", "DHCP \(Static Lease\)", or "Static". | 
| XDome.DeviceVulnerability.device_vlan_name_list | List | The name of the VLAN, extracted from switch configurations. | 
| XDome.DeviceVulnerability.device_vlan_description_list | List | The description of the VLAN, extracted from switch configurations. | 
| XDome.DeviceVulnerability.device_connection_type_list | List | The connection types of a device, such as "Ethernet". | 
| XDome.DeviceVulnerability.device_ssid_list | List | The name of the wireless network the device is connected to, such as "Guest". | 
| XDome.DeviceVulnerability.device_ap_location_list | List | The location of the access point the device is connected to, extracted from Network Management integrations. | 
| XDome.DeviceVulnerability.device_switch_port_list | List | The port identifier of the switch the device is connected to. | 
| XDome.DeviceVulnerability.device_switch_location_list | List | The location of the switch the device is connected to. | 
| XDome.DeviceVulnerability.device_number_of_nics | Number | The number of network interface cards seen on the network. | 
| XDome.DeviceVulnerability.device_last_seen_list | List | The date and time a device's NIC was last seen. | 
| XDome.DeviceVulnerability.device_first_seen_list | List | The date and time a device's NIC was first seen. | 
| XDome.DeviceVulnerability.device_is_online | Boolean | A boolean field indicating whether the device is online or not. | 
| XDome.DeviceVulnerability.device_network_scope_list | List | The device's Network Scope - used to differentiate between internal networks that share the same IP subnets. | 
| XDome.DeviceVulnerability.device_name | String | The Device Name attribute is set automatically based on the priority of the Auto-Assigned Device attribute. You can also set it manually. The Device Name can be the device’s IP, hostname, etc. | 
| XDome.DeviceVulnerability.device_manufacturer | String | Manufacturer of the device, such as "Alaris". | 
| XDome.DeviceVulnerability.device_site_name | String | The name of the site within the healthcare organization the device is associated with. | 
| XDome.DeviceVulnerability.device_risk_score | String | The calculated risk level of a device, such as "Critical", or "High". | 
| XDome.DeviceVulnerability.device_risk_score_points | Number | The calculated risk points of a device, such as "54.1". | 
| XDome.DeviceVulnerability.device_effective_likelihood_subscore | String | The calculated effective likelihood subscore level of a device, such as "Critical", or "High". | 
| XDome.DeviceVulnerability.device_effective_likelihood_subscore_points | Number | The calculated effective likelihood subscore points of a device, such as "54.1". | 
| XDome.DeviceVulnerability.device_likelihood_subscore | String | The calculated likelihood subscore level of a device, such as "Critical", or "High". | 
| XDome.DeviceVulnerability.device_likelihood_subscore_points | Number | The calculated likelihood subscore points of a device, such as "54.1". | 
| XDome.DeviceVulnerability.device_impact_subscore | String | The calculated impact subscore level of a device, such as "Critical", or "High". | 
| XDome.DeviceVulnerability.device_impact_subscore_points | Number | The calculated impact subscore points of a device, such as "54.1". | 
| XDome.DeviceVulnerability.device_suspicious | List | The reasons for which the device was marked as suspicious. | 
| XDome.DeviceVulnerability.device_authentication_user_list | List | The User name used to authenticate the device to the network using Radius/802.1x is extracted from the NAC integration and the traffic. | 
| XDome.DeviceVulnerability.device_software_or_firmware_version | String | The application version running on the device. | 
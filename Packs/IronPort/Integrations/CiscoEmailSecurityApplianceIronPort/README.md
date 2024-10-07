Cisco Email Security protects against ransomware, business email compromise, spoofing, and phishing
## Configure Cisco Email Security Appliance (IronPort) in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://192.168.0.1) | True |
| Port | True |
| Credentials | True |
| Password | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ironport-report
***
Retrieve email security appliance statistical reports.


#### Base Command

`ironport-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_range | Use this attribute to retrieve report(s) for a specified duration. Must provide either this or duration argument. Possible values are: 1d, 1h. | Optional | 
| report_type | The type of report to fetch. Possible values are: mail_authentication_summary, mail_dlp_outgoing_traffic_summary, mail_incoming_malware_threat_file_detail_summary, mail_incoming_traffic_summary, mail_mailbox_auto_remediation, mail_outgoing_traffic_summary, mail_security_summary, mail_sender_group_summary, mail_system_capacity, mail_authentication_incoming_domain_ip, mail_content_filter_incoming, mail_dmarc_incoming_traffic_summary, mail_env_sender_rate_limit, mail_env_sender_stats, mail_fed_content_filter_incoming, mail_hvm_msg_filter_stats, mail_incoming_hat_connections, mail_incoming_malware_threat_file_detail, mail_incoming_web_interaction_track_malicious_users, mail_incoming_web_interaction_track_urls, mail_md_attachment_incoming_file_type, mail_md_attachment_outgoing_file_type, mail_outgoing_web_interaction_track_malicious_users, mail_outgoing_web_interaction_track_urls, mail_msg_filter_stats, mail_sender_group_detail, mail_subject_stats, mail_url_category_summary, mail_url_domain_summary, mail_url_reputation_summary, mail_vof_threat_summary, mail_vof_threats_by_level, mail_vof_threats_by_threat_type, mail_vof_threats_by_time_threshold, mail_vof_threats_by_type, mail_vof_threats_rewritten_url, mail_authentication_incoming_domain, mail_content_filter_outgoing, mail_destination_domain_detail, mail_dlp_outgoing_policy_detail, mail_incoming_domain_detail, mail_incoming_ip_hostname_detail, mail_incoming_network_detail, mail_sender_domain_detail, mail_sender_ip_hostname_detail, mail_users_detail, mail_virus_type_detail. | Required | 
| max | Use this attribute to limit the number of results returned by the report. n is the number of results that you want the report to return and can assume values from 1 through 1000. Default is 30. Default is 30. | Optional | 
| duration | Aggregate report(s) for the specified duration. Supported values of TZD are Z , +hh:mm , or -hh:mm. Format should be YYYY-MM-DDThh:mmTZD/YYYY-MM-DDThh:mmTZD. | Optional | 
| entity | Use this attribute to retrieve reports based on a specified entity such as email address, IP address, and so on. You can choose whether to exactly match the specified text or look for items starting with the specified text (for instance, starts with "ex" will match "example.com"). | Optional | 
| starts_with | Use this attribute to retrieve items starting with the specified entity value. This attribute must be used in conjunction with the entity attribute and value must be set to true , for example, entity=us&amp;starts_with=true . | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ironport-report report_type=mail_authentication_summary time_range=1d```

#### Context Example
```json
{
    "IronPort": {
        "MailAuthenticationSummary": {
            "ReceivedAuth": 0,
            "ReceivedConnAuthFail": 0,
            "ReceivedConnAuthSuccess": 0,
            "ReceivedConnCertFail": 0,
            "ReceivedConnCertSuccess": 0,
            "ReceivedConnNoauth": 0,
            "ReceivedConnTotal": 0,
            "ReceivedNoauth": 0,
            "ReceivedTotal": 0
        }
    }
}
```

#### Human Readable Output

>### IronPort Report
> Received Auth| Received Conn Auth Fail| Received Conn Auth Success| Received Conn Cert Fail| Received Conn Cert Success| Received Conn Noauth| Received Conn Total| Received Noauth| Received Total
>---|---|---|---|---|---|---|---|---
>0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0

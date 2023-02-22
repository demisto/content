This is the core automation script for producing reports used to alert on the status of SSL Certificates across an enterprise. This automation parses the outputs placed into the SSLVerifierV2 context key from the SSLVerifierV2 automation script. 

**Parameters for the automation:**

**SSLVerifierKey**: The context key to pull the SSLVerifierV2 data from, defaults to **SSLVerifierV2**.
**StatusType**: The specific status to parse from the SSLVerifierKey (Good, Warning, Expiring, Expired, or All). 
**OutputToWarRoom**: Produces a markdown-formatted table and outputs it to the incident war room or playground (True/False).

**Outputs for the automation:**

**SSLReport.Expired**: An array of certificates that are expired
**SSLReport.Expiring**: An array of certificates that are expiring in 90 days or less
**SSLReport.Warning**: An array of certificates that are expiring within 91 to 180 days
**SSLReport.Good**: An array of certificates that are expiring in more than 180 days
**SSLReport.ExpiredTable**: Markdown table containing certificates in expired status
**SSLReport.ExpiringTable**: Markdown table containing certificates in expiring status
**SSLReport.WarningTable**: Markdown table containing certificates in warning status
**SSLReport.GoodTable**: Markdown table containing certificates in good status
**SSLReport.md**: Markdown table for all requested certificate statuses

**Sample Command Input**

***Parse certificates of all statuses, outputting the data to the war room/playground***
!SSLVerifierV2_ParseOutput OutputToWarRoom=True StatusType=all

***Parse expired certificates and output a report to the war room***
!SSLVerifierV2_ParseOutput OutputToWarRoom=True StatusType=expired

***Parse certificates of all statuses using a customer SSLVerifierV2 context key, outputting the data to the war room***
!SSLVerifierV2_ParseOutput OutputToWarRoom=True StatusType=all SSLVerifierKey=CustomVerifierKey

**Sample Context Output**

    {
    "SSLReport": {
        "Expired": [
            {
                "Domain": "expired.badssl.com",
                "ExpirationDate": "2015/04/12 - 23:59:59",
                "TimeToExpiration": "-2868"
            },
            {
                "Domain": "expired-rsa-dv.ssl.com",
                "ExpirationDate": "2016/08/02 - 20:48:30",
                "TimeToExpiration": "-2390"
            }
        ],
        "ExpiredTable": "|**Site**|**Expiration Date**|**Days Expired**|\n|--------------|--------------|--------------|\n|expired.badssl.com|2015/04/12 - 23:59:59|-2868 days|\n|expired-rsa-dv.ssl.com|2016/08/02 - 20:48:30|-2390 days|\n",
        "Expiring": [
            {
                "Domain": "www.google.com",
                "ExpirationDate": "2023/04/26 - 19:43:58",
                "TimeToExpiration": "68"
            },
            {
                "Domain": "www.norton.com",
                "ExpirationDate": "2023/03/10 - 23:59:59",
                "TimeToExpiration": "21"
            }
        ],
        "ExpiringTable": "|**Site**|**Expiration Date**|**Days to Expiration**|\n|--------------|--------------|--------------|\n|www.google.com|2023/04/26 - 19:43:58|68 days|\n|www.norton.com|2023/03/10 - 23:59:59|21 days|\n",
        "Good": [
            {
                "Domain": "www.microsoft.com",
                "ExpirationDate": "2023/09/29 - 23:23:11",
                "TimeToExpiration": "224"
            },
            {
                "Domain": "www.chase.com",
                "ExpirationDate": "2024/01/19 - 04:02:21",
                "TimeToExpiration": "335"
            }
        ],
        "GoodTable": "|**Site**|**Expiration Date**|**Days to Expiration**|\n|--------------|--------------|--------------|\n|www.microsoft.com|2023/09/29 - 23:23:11|224 days|\n|www.chase.com|2024/01/19 - 04:02:21|335 days|\n",
        "Warning": [
            {
                "Domain": "www.sans.org",
                "ExpirationDate": "2023/06/13 - 18:47:34",
                "TimeToExpiration": "116"
            },
            {
                "Domain": "www.paloaltonetworks.com",
                "ExpirationDate": "2023/07/26 - 23:59:59",
                "TimeToExpiration": "159"
            }
        ],
        "WarningTable": "|**Site**|**Expiration Date**|**Days to Expiration**|\n|--------------|--------------|--------------|\n|www.sans.org|2023/06/13 - 18:47:34|116 days|\n|www.paloaltonetworks.com|2023/07/26 - 23:59:59|159 days|\n",
        "md": "# {{color:red}}(** EXPIRED SSL CERTIFICATES **) #\n\n|**Site**|**Expiration Date**|**Days Expired**|\n|--------------|--------------|--------------|\n|expired.badssl.com|2015/04/12 - 23:59:59|-2868 days|\n|expired-rsa-dv.ssl.com|2016/08/02 - 20:48:30|-2390 days|\n### {{color:red}}(** SSL Certificates expiring in 90 days or less **) ###\n\n|**Site**|**Expiration Date**|**Days to Expiration**|\n|--------------|--------------|--------------|\n|www.google.com|2023/04/26 - 19:43:58|68 days|\n|www.norton.com|2023/03/10 - 23:59:59|21 days|\n### {{color:yellow}}(** SSL Certificates expiring between 91 and 180 days from now **) ###\n\n|**Site**|**Expiration Date**|**Days to Expiration**|\n|--------------|--------------|--------------|\n|www.sans.org|2023/06/13 - 18:47:34|116 days|\n|www.paloaltonetworks.com|2023/07/26 - 23:59:59|159 days|\n### {{color:green}}(** SSL Certificates expiring in greater than 180 days **) ###\n\n|**Site**|**Expiration Date**|**Days to Expiration**|\n|--------------|--------------|--------------|\n|www.microsoft.com|2023/09/29 - 23:23:11|224 days|\n|www.chase.com|2024/01/19 - 04:02:21|335 days|\n"
        }
    }


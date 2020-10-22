<!-- HTML_DOC -->
This integration was integrated and tested with <a href="https://caseapi.phishlabs.com/v1/data/docs/">V1.0 of PhishLabs
    IOC DRP</a>

<h2>Use Cases</h2>
<ul>
    <li>Get cases by filters from PhishLabs DRP service</li>
    <li>Get live incidents from PhishLabs DRP service</li>
</ul>
<h2> Detailed Description </h2>
<p>
    <a href="https://www.phishlabs.com/digital-risk-protection/">PhishLabs Digital Risk Protection (DRP)</a> is a
    solution that provides proactive detection and rapid mitigation of digital risks across:
<ul>
    <li>email</li>
    <li>domain</li>
    <li>social media</li>
    <li>mobile</li>
    <li>dark</li>
    <li>deep</li>
    <li>open web vectors</li>
</ul>

<h2>Configure PhishLabs IOC DRP on Demisto</h2>
<ol>
    <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
        &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.
    </li>
    <li>Search for PhishLabs IOC DRP.</li>
    <li>
        Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
        <ul>
            <li><strong>Name</strong>: a textual name for the integration instance.</li>
            <li><strong>Server URL (e.g. https://example.net)</strong></li>
            <li><strong>User</strong></li>
            <li><strong>Fetch incidents</strong></li>
            <li><strong>Incident type</strong></li>
            <li><strong>First fetch timestamp (
                <number>
                    <time unit>, e.g., 12 hours, 7 days)
            </strong></li>
            <li><strong>Fetch by date field</strong></li>
            <li><strong>Fetch limit (min 20)</strong></li>
            <li><strong>Trust any certificate (not secure)</strong></li>
            <li><strong>Use system proxy settings</strong></li>
        </ul>
    </li>
    <li>
        Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
    </li>
</ol>

<h2>Fetch Incidents</h2>
<p>Fetch incidents done by the following configuration:</p>
<ul>
    <li>Limit - limit amount of incidents by fetch</li>
    <li>Date field - Date field to fetch incidents by - created/modified/closed</li>
    <li>Time to fetch - date for starting collecting incidents (1 days ago, 1 hours ago etc)</li>
    <li>Incident type</li>
</ul>
<p>Incident data example:</p>
<pre>
  [
  {
    "name": "PhishLabs IOC - DRP: 12d329b7-13db-11ea-94e8-0ee0a3f3cb1c",
    "occurred": "2019-12-01T01:40:36Z",
    "rawJSON": {
      "caseId": "12d329b7-13db-11ea-94e8-0ee0a3f3cb1c",
      "title": "=? =?gb2312?Q?ted:_www.icloud.com.agona.cn?=",
      "description": "From: PhishLabs Security Operations <not@domain.com>\nSubject: =? =?gb2312?Q?ted:_www.icloud.com.agona.cn?=\n\n\r\n________________________________\r\nFrom: west263\r\nSent: Saturday, November 30, 2019 8:36:41 PM (UTC-05:00) Eastern Time (US & Canada)\r\nTo: PhishLabs Security Operations; not@domain.com; not@domain.com\r\nSubject: 回复：[PL-1405082] Malicious domain detected: www.icloud.com.agona.cn\r\n\r\n-- External email--\r\n\r\n\r\nThank you for allowing us an opportunity to assist you.\r\n\r\nWe have suspended our customer to use this domain. You can check it later.\r\n\r\nIf you have any questions, please do not hesitate to contact us. We look forward to assisting you.\r\n\r\nHave a wonderful day!\r\n\r\n\r\n\r\n------------------\r\n\r\nBest regards,\r\n\r\nLillian\r\n\r\n\r\n------------------ 原始邮件 ------------------\r\n\r\n发件人:  PhishLabs Security Operations<not@domain.com>;\r\n日  期:  2019-11-30 (星期六) 08:37:19\r\n收件人:  not@domain.com<not@domain.com>;not@domain.com<not@domain.com>;not@domain.com<not@domain.com>;\r\n主  题:  [PL-1405082] Malicious domain detected: www.icloud.com.agona.cn\r\n\r\n\r\nDuring an investigation of fraud, we discovered a domain(s) registered for the sole intent of malicious activity, which is being used to attack our client and their customers.\r\n\r\nWe have addressed this report to the responsible authoritative providers over this website who have the ability to disable the malicious content in question. This includes but is not limited to the hosting provider(s), nameserver, registrar and if applicable, the registry.  Based on your relationship to the content in question or services provided, please see our specific request below.\r\n\r\nThis threat has been active for at least 2.1 hours.\r\n\r\nhXXp www[.]icloud[.]com[.]agona[.]cn/ios/uy930glgr8yx54n4zkcw[.]asp?uy930glgr8yx54n4zkcw=\r\nhXXp www[.]icloud[.]com[.]agona[.]cn/ios/upvf7o4kon1kpt4vfy18[.]asp?upvf7o4kon1kpt4vfy18=\r\nhXXp www[.]icloud[.]com[.]agona[.]cn/ios/vweixhklbjw1t1ve3b4n[.]asp?vweixhklbjw1t1ve3b4n=\r\nhXXp www[.]icloud[.]com[.]agona[.]cn/an3n3abqqtkpuok9vw9c[.]asp?an3n3abqqtkpuok9vw9c\r\n\r\nFirst detection of malicious activity: 11-29-2019 22:26:17 UTC\r\nMost recent observation of malicious activity: 11-30-2019 00:35:06 UTC\r\nAssociated IP Addresses: 8.8.8.8\r\n\r\nEvidence of malicious content is provided below my signature.\r\n\r\n===   HOSTING  PROVIDER AND/OR WEBSITE OWNER    ===\r\nIf you agree that this is malicious, we kindly request that you take steps to have the content removed as soon as possible.  It is highly likely that the intruder who set up this phishing content has also left additional fraudulent material on this server such as illegitimate access points.\r\n\r\n===   REGISTRAR / REGISTRY   ===\r\nWe kindly request that this domain is placed on hold as soon as possible and all client related information sink holed. It is also very likely the registrant in question has registered various other domains through your service and it is suggested you investigate as you see fit.\r\n\r\n===   NAMESERVER, SOA   ===\r\nIf it is within your power, please consider disabling the routing to this domain to prevent further abuse to the public.\r\n\r\n===   CERT/CIRT, ETC.   ===\r\nIf you're able to assist in any means possible to see to the termination of this content, please do so.  Your local expertise and influence on this matter is critical to this effort.\r\n\r\nIf we have contacted you in error, or if there is a better way for us to report this incident, please let us know so that we may continue our investigation.\r\n\r\nWe are extremely grateful for your assistance.\r\n\r\nKind regards,\r\n\r\nYogender Chauhan\r\nPhishLabs Security Operations\r\n12023866001\r\nAvailable 24/7\r\n\r\n\r\nEvidence:\r\nPlease see attached screenshot.\r\n.\r\n\r\n[PL-1405082]\r\n\r\n\r\n ",
      "caseNumber": 1406220,
      "createdBy": {
        "id": "30c2e916-c72d-11e3-860e-002590387e36",
        "name": "soc.phishlabs",
        "displayName": "SOC PhishLabs"
      },
      "brand": "",
      "caseType": "Other",
      "resolutionStatus": "Accidental creation",
      "caseStatus": "Rejected",
      "dateCreated": "2019-12-01T01:37:02Z",
      "dateClosed": "2019-12-01T01:40:36Z",
      "dateModified": "2019-12-01T01:40:36Z",
      "customer": "PhishLabs",
      "attachments": [
        {
          "id": "12e5eeaa-13db-11ea-8247-0ad24386a0d6",
          "type": "Email",
          "description": "Source Email for case creation",
          "dateAdded": "2019-12-01T01:37:02Z",
          "fileName": "msg.oFAH.eml",
          "fileURL": "https://caseapi.phishlabs.com/v1/data/attachment/12e5eeaa-13db-11ea-8247-0ad24386a0d6"
        }
      ],
      "formReceiver": false,
      "brandAbuseFlag": false,
      "appDate": "0001-01-01T00:00:00Z",
      "primaryMarketplace": false
    }
  }
]
</pre>
<h2>Commands</h2>
<p>
    You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
    After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
    <li><a href="#phishlabs-ioc-drp-get-cases" target="_self">Get cases by filters:
        phishlabs-ioc-drp-get-cases</a></li>
    <li><a href="#phishlabs-ioc-drp-get-case-by-id" target="_self">Get case by ID:
        phishlabs-ioc-drp-get-case-by-id</a></li>
    <li><a href="#phishlabs-ioc-drp-get-open-cases" target="_self">Get open cases filters:
        phishlabs-ioc-drp-get-open-cases</a></li>
    <li><a href="#phishlabs-ioc-drp-get-closed-cases" target="_self">Get closed cases by
        filters: phishlabs-ioc-drp-get-closed-cases</a></li>
</ol>
<h3 id="phishlabs-ioc-drp-get-cases">1. phishlabs-ioc-drp-get-cases</h3>
<hr>
<p>Get cases by filters</p>
<h5>Base Command</h5>
<p>
    <code>phishlabs-ioc-drp-get-cases</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Argument Name</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
        <th>
            <strong>Required</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>status</td>
        <td>Filter cases based on the case status</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>case_type</td>
        <td>Filter cases by case type</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>max_records</td>
        <td>Maximum number of cases to return, default is 20, maximum is 200</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>offset</td>
        <td>Paginate results used in conjunction with maxRecords.</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>date_field</td>
        <td>Field to use to query using dateBegin and dateEnd parameters.</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>begin_date</td>
        <td>Date query beginning date</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>end_date</td>
        <td>Date query endining date</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>period</td>
        <td>timestamp (<number> <time unit>, e.g., 12 hours, 7 days)</td>
        <td>Optional</td>
    </tr>
    </tbody>
</table>

<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Path</strong>
        </th>
        <th>
            <strong>Type</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>PhishlabsIOC.DRP.CaseID</td>
        <td>String</td>
        <td>Case ID</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Title</td>
        <td>String</td>
        <td>Case title</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Description</td>
        <td>String</td>
        <td>Case description</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseNumber</td>
        <td>String</td>
        <td>Case number</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Resolution</td>
        <td>String</td>
        <td>Resolution</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ResolutionStatus</td>
        <td>String</td>
        <td>Resolution status</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.ID</td>
        <td>String</td>
        <td>Case creator ID</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.Name</td>
        <td>String</td>
        <td>Case creator name</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.DisplayName</td>
        <td>String</td>
        <td>Case creator display name</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Brand</td>
        <td>String</td>
        <td>Brand reported in case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Email</td>
        <td>String</td>
        <td>Email of case creator</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseType</td>
        <td>String</td>
        <td>Type of the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseStatus</td>
        <td>String</td>
        <td>Status of the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateCreated</td>
        <td>String</td>
        <td>Case creation date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateClosed</td>
        <td>String</td>
        <td>Case closing date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateModified</td>
        <td>String</td>
        <td>Case modification date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Customer</td>
        <td>String</td>
        <td>Customer reporting the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.URL</td>
        <td>String</td>
        <td>URL of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.UrlType</td>
        <td>String</td>
        <td>URL type of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.IP</td>
        <td>String</td>
        <td>IP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.ISP</td>
        <td>String</td>
        <td>ISP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.Country</td>
        <td>String</td>
        <td>ISP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.TargetedBrands</td>
        <td>String</td>
        <td>Target brands of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.FQDN</td>
        <td>String</td>
        <td>FQDN of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.Domain</td>
        <td>String</td>
        <td>Domain of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.IsMaliciousDomain</td>
        <td>Boolean</td>
        <td>Detect if domain of attack source is malicious</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registrant</td>
        <td>String</td>
        <td>URL of the registrant</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Created</td>
        <td>String</td>
        <td>Creation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Expires</td>
        <td>String</td>
        <td>Expiriation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Updated</td>
        <td>String</td>
        <td>Update date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Registrar</td>
        <td>String</td>
        <td>Registrar of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.NameServers</td>
        <td>String</td>
        <td>Name servers of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.ID</td>
        <td>String</td>
        <td>ID of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.Type</td>
        <td>String</td>
        <td>Type of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.Description</td>
        <td>String</td>
        <td>Description of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.DateAdded</td>
        <td>String</td>
        <td>Date adding of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.FileName</td>
        <td>String</td>
        <td>File name of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.FileURL</td>
        <td>String</td>
        <td>File URL of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ApplicationName</td>
        <td>String</td>
        <td>Application reported in the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Platform</td>
        <td>String</td>
        <td>Platform reported in the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Severity</td>
        <td>String</td>
        <td>Sevirity of DRP</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Developer</td>
        <td>String</td>
        <td>Developer of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DeveloperWebsite</td>
        <td>String</td>
        <td>Developer website of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ApplicationDescription</td>
        <td>String</td>
        <td>Descripion of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Language</td>
        <td>String</td>
        <td>Language of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Phone</td>
        <td>String</td>
        <td>Phone number of case creator</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Hardware</td>
        <td>String</td>
        <td>Hardware used by the application</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.URL</td>
        <td>String</td>
        <td>URL of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.UrlType</td>
        <td>String</td>
        <td>URL type of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.TargetedBrands</td>
        <td>String</td>
        <td>Target brands of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registrant</td>
        <td>String</td>
        <td>URL of the registrant</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Created</td>
        <td>String</td>
        <td>Creation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Expires</td>
        <td>String</td>
        <td>Expiriation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Updated</td>
        <td>String</td>
        <td>Update date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Registrar</td>
        <td>String</td>
        <td>Registrar of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.NameServers</td>
        <td>String</td>
        <td>Name servers of the URL</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
    <code>!phishlabs-ioc-drp-get-cases max_records=2</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "PhishLabsIOC": {
        "DRP": [
            {
                "Attachments": [
                    {
                        "DateAdded": "2019-12-09T07:56:02Z",
                        "Description": "Source Email for case creation",
                        "FileName": "msg.mFAH.eml",
                        "FileURL": "https://caseapi.phishlabs.com/v1/data/attachment/",
                        "ID": "581ba28d-1a59-11ea-8247-0ad24386a0d6",
                        "Type": "Email"
                    }
                ],
                "CaseID": "5808ec5a-1a59-11ea-94e8-0ee0a3f3cb1c",
                "CaseNumber": 1417871,
                "CaseStatus": "Rejected",
                "CaseType": "Other",
                "CreatedBy": {
                    "DisplayName": "SOC PhishLabs",
                    "ID": "30c2e916",
                    "Name": "soc.phishlabs"
                },
                "Customer": "PhishLabs",
                "DateClosed": "2019-12-09T08:01:34Z",
                "DateCreated": "2019-12-09T07:56:01Z",
                "DateModified": "2019-12-09T08:01:34Z",
                "Description": "From: ",
                "ResolutionStatus": "Accidental creation",
                "Title": "=?gb2312?B?"
            },
            {
                "Attachments": [
                    {
                        "DateAdded": "2019-12-09T07:46:02Z",
                        "Description": "Source Email for case creation",
                        "FileName": "msg.fKAH.eml",
                        "FileURL": "https://caseapi.phishlabs.com/v1/data/",
                        "ID": "f24c36a6",
                        "Type": "Email"
                    }
                ],
                "CaseID": "f239fe62",
                "CaseNumber": 1417866,
                "CaseStatus": "Rejected",
                "CaseType": "Other",
                "CreatedBy": {
                    "DisplayName": "SOC PhishLabs",
                    "ID": "30c2e916",
                    "Name": "soc.phishlabs"
                },
                "Customer": "PhishLabs",
                "DateClosed": "2019-12-09T07:49:11Z",
                "DateCreated": "2019-12-09T07:46:01Z",
                "DateModified": "2019-12-09T07:49:11Z",
                "Description": "From: ",
                "ResolutionStatus": "Accidental creation",
                "Title": "=?gb231"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>PhishLabs IOC - DRP - cases</h3>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th><strong>CaseID</strong></th>
        <th><strong>Title</strong></th>
        <th><strong>CaseStatus</strong></th>
        <th><strong>DateCreated</strong></th>
        <th><strong>ResolutionStatus</strong></th>
        <th><strong>CreatedBy</strong></th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> 5808ec5a-1a59-11ea-94e8-0ee0a3f3cb1c</td>
        <td>?Q?idenform[.]top?=</td>
        <td> Rejected</td>
        <td> 2019-12-09T07:56:01Z</td>
        <td> Accidental creation</td>
        <td> ID: 30c2e916<br>Name: soc.phishlabs<br>DisplayName: SOC PhishLabs</td>
    </tr>
    <tr>
        <td> f239fe62-1a57-11ea-94e8-0ee0a3f3cb1c</td>
        <td> =?gb2312?B?R</td>
        <td> Rejected</td>
        <td> 2019-12-09T07:46:01Z</td>
        <td> Accidental creation</td>
        <td> ID: 30c2e916<br>Name: soc.phishlabs<br>DisplayName: SOC PhishLabs</td>
    </tr>
    </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="phishlabs-ioc-drp-get-case-by-id">2. phishlabs-ioc-drp-get-case-by-id</h3>
<hr>
<p>Get case by ID of Phishlabs DRP service</p>
<h5>Base Command</h5>
<p>
    <code>phishlabs-ioc-drp-get-case-by-id</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Argument Name</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
        <th>
            <strong>Required</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>case_id</td>
        <td>ID of case, for expample ID from previous command</td>
        <td>Required</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Path</strong>
        </th>
        <th>
            <strong>Type</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>PhishlabsIOC.DRP.CaseID</td>
        <td>String</td>
        <td>Case ID</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Title</td>
        <td>String</td>
        <td>Case title</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Description</td>
        <td>String</td>
        <td>Case description</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseNumber</td>
        <td>String</td>
        <td>Case number</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Resolution</td>
        <td>String</td>
        <td>Resolution</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ResolutionStatus</td>
        <td>String</td>
        <td>Resolution status</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.ID</td>
        <td>String</td>
        <td>Case creator ID</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.Name</td>
        <td>String</td>
        <td>Case creator name</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.DisplayName</td>
        <td>String</td>
        <td>Case creator display name</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Brand</td>
        <td>String</td>
        <td>Brand reported in case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Email</td>
        <td>String</td>
        <td>Email of case creator</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseType</td>
        <td>String</td>
        <td>Type of the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseStatus</td>
        <td>String</td>
        <td>Status of the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateCreated</td>
        <td>String</td>
        <td>Case creation date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateClosed</td>
        <td>String</td>
        <td>Case closing date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateModified</td>
        <td>String</td>
        <td>Case modification date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Customer</td>
        <td>String</td>
        <td>Customer reporting the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.URL</td>
        <td>String</td>
        <td>URL of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.UrlType</td>
        <td>String</td>
        <td>URL type of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.IP</td>
        <td>String</td>
        <td>IP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.ISP</td>
        <td>String</td>
        <td>ISP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.Country</td>
        <td>String</td>
        <td>ISP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.TargetedBrands</td>
        <td>String</td>
        <td>Target brands of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.FQDN</td>
        <td>String</td>
        <td>FQDN of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.Domain</td>
        <td>String</td>
        <td>Domain of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.IsMaliciousDomain</td>
        <td>Boolean</td>
        <td>Detect if domain of attack source is malicious</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registrant</td>
        <td>String</td>
        <td>URL of the registrant</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Created</td>
        <td>String</td>
        <td>Creation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Expires</td>
        <td>String</td>
        <td>Expiriation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Updated</td>
        <td>String</td>
        <td>Update date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Registrar</td>
        <td>String</td>
        <td>Registrar of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.NameServers</td>
        <td>String</td>
        <td>Name servers of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.ID</td>
        <td>String</td>
        <td>ID of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.Type</td>
        <td>String</td>
        <td>Type of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.Description</td>
        <td>String</td>
        <td>Description of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.DateAdded</td>
        <td>String</td>
        <td>Date adding of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.FileName</td>
        <td>String</td>
        <td>File name of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.FileURL</td>
        <td>String</td>
        <td>File URL of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ApplicationName</td>
        <td>String</td>
        <td>Application reported in the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Platform</td>
        <td>String</td>
        <td>Platform reported in the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Severity</td>
        <td>String</td>
        <td>Sevirity of DRP</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Developer</td>
        <td>String</td>
        <td>Developer of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DeveloperWebsite</td>
        <td>String</td>
        <td>Developer website of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ApplicationDescription</td>
        <td>String</td>
        <td>Descripion of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Language</td>
        <td>String</td>
        <td>Language of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Hardware</td>
        <td>String</td>
        <td>Hardware used by the application</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Phone</td>
        <td>String</td>
        <td>Phone number of case creator</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Hardware</td>
        <td>String</td>
        <td>Hardware used by the application</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.URL</td>
        <td>String</td>
        <td>URL of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.UrlType</td>
        <td>String</td>
        <td>URL type of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.TargetedBrands</td>
        <td>String</td>
        <td>Target brands of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registrant</td>
        <td>String</td>
        <td>URL of the registrant</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Created</td>
        <td>String</td>
        <td>Creation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Expires</td>
        <td>String</td>
        <td>Expiriation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Updated</td>
        <td>String</td>
        <td>Update date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Registrar</td>
        <td>String</td>
        <td>Registrar of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.NameServers</td>
        <td>String</td>
        <td>Name servers of the URL</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
    <code>!phishlabs-ioc-drp-get-case-by-id case_id=08baa0d0-1a54-11ea-94e8-0ee0a3f3cb1c</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "PhishLabsIOC": {
        "DRP": [
            {
                "Attachments": [
                    {
                        "DateAdded": "2019-12-09T07:18:01Z",
                        "Description": "Source Email for case creation",
                        "FileName": "msg.nFAH.eml",
                        "FileURL": "https://caseapi.phishlabs.com/v1/data/attachment/08d0611d",
                        "ID": "08d0611d",
                        "Type": "Email"
                    }
                ],
                "CaseID": "08baa0d0",
                "CaseNumber": 1417854,
                "CaseStatus": "Rejected",
                "CaseType": "Other",
                "CreatedBy": {
                    "DisplayName": "SOC PhishLabs",
                    "ID": "30c2e916",
                    "Name": "soc.phishlabs"
                },
                "Customer": "PhishLabs",
                "DateClosed": "2019-12-09T07:18:46Z",
                "DateCreated": "2019-12-09T07:18:01Z",
                "DateModified": "2019-12-09T07:18:46Z",
                "Description": "From: PhishLabs Security Operations <soc@phishlabs.com>",
                "ResolutionStatus": "Accidental creation",
                "Title": "=?gb2312?"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>PhishLabs IOC - DRP - case ID None</h3>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th><strong>CaseID</strong></th>
        <th><strong>Title</strong></th>
        <th><strong>CaseStatus</strong></th>
        <th><strong>DateCreated</strong></th>
        <th><strong>ResolutionStatus</strong></th>
        <th><strong>CreatedBy</strong></th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> 08baa0d0-1a54-11ea-94e8-0ee0a3f3cb1c</td>
        <td> =?gb2312?B?</td>
        <td> Rejected</td>
        <td> 2019-12-09T07:18:01Z</td>
        <td> Accidental creation</td>
        <td> ID: 30c2e916<br>Name: soc.phishlabs<br>DisplayName: SOC PhishLabs</td>
    </tr>
    </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3 id="phishlabs-ioc-drp-get-open-cases">3. phishlabs-ioc-drp-get-open-cases</h3>
<hr>
<p>Get open cases of Phishlabs DRP service by filters</p>
<h5>Base Command</h5>
<p>
    <code>phishlabs-ioc-drp-get-open-cases</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Argument Name</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
        <th>
            <strong>Required</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>case_type</td>
        <td>Filter cases by case type</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>max_records</td>
        <td>Maximum number of cases to return, default is 20, maximum is 200</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>offset</td>
        <td>Paginate results used in conjunction with maxRecords, first 200 records maxRecords=200&offset=0 second 200
            records maxRecords=200&offset=200
        </td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>date_field</td>
        <td>Field to use to query using dateBegin and dateEnd parameters.</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>begin_date</td>
        <td>Date query beginning date</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>end_date</td>
        <td>Date query beginning date</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>period</td>
        <td>timestamp (<number> <time unit>, e.g., 12 hours, 7 days)</td>
        <td>Optional</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Path</strong>
        </th>
        <th>
            <strong>Type</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>PhishlabsIOC.DRP.CaseID</td>
        <td>String</td>
        <td>Case ID</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Title</td>
        <td>String</td>
        <td>Case title</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Description</td>
        <td>String</td>
        <td>Case description</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseNumber</td>
        <td>String</td>
        <td>Case number</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Resolution</td>
        <td>String</td>
        <td>Resolution</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ResolutionStatus</td>
        <td>String</td>
        <td>Resolution status</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.ID</td>
        <td>String</td>
        <td>Case creator ID</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.Name</td>
        <td>String</td>
        <td>Case creator name</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.DisplayName</td>
        <td>String</td>
        <td>Case creator display name</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Brand</td>
        <td>String</td>
        <td>Brand reported in case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Email</td>
        <td>String</td>
        <td>Email of case creator</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseType</td>
        <td>String</td>
        <td>Type of the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseStatus</td>
        <td>String</td>
        <td>Status of the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateCreated</td>
        <td>String</td>
        <td>Case creation date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateClosed</td>
        <td>String</td>
        <td>Case closing date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateModified</td>
        <td>String</td>
        <td>Case modification date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Customer</td>
        <td>String</td>
        <td>Customer reporting the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.URL</td>
        <td>String</td>
        <td>URL of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.UrlType</td>
        <td>String</td>
        <td>URL type of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.IP</td>
        <td>String</td>
        <td>IP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.ISP</td>
        <td>String</td>
        <td>ISP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.Country</td>
        <td>String</td>
        <td>ISP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.TargetedBrands</td>
        <td>String</td>
        <td>Target brands of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.FQDN</td>
        <td>String</td>
        <td>FQDN of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.Domain</td>
        <td>String</td>
        <td>Domain of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.IsMaliciousDomain</td>
        <td>Boolean</td>
        <td>Detect if domain of attack source is malicious</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registrant</td>
        <td>String</td>
        <td>URL of the registrant</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Created</td>
        <td>String</td>
        <td>Creation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Expires</td>
        <td>String</td>
        <td>Expiriation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Updated</td>
        <td>String</td>
        <td>Update date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Registrar</td>
        <td>String</td>
        <td>Registrar of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.NameServers</td>
        <td>String</td>
        <td>Name servers of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.ID</td>
        <td>String</td>
        <td>ID of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.Type</td>
        <td>String</td>
        <td>Type of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.Description</td>
        <td>String</td>
        <td>Description of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.DateAdded</td>
        <td>String</td>
        <td>Date adding of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.FileName</td>
        <td>String</td>
        <td>File name of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.FileURL</td>
        <td>String</td>
        <td>File URL of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ApplicationName</td>
        <td>String</td>
        <td>Application reported in the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Platform</td>
        <td>String</td>
        <td>Platform reported in the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Severity</td>
        <td>String</td>
        <td>Sevirity of DRP</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Developer</td>
        <td>String</td>
        <td>Developer of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DeveloperWebsite</td>
        <td>String</td>
        <td>Developer website of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ApplicationDescription</td>
        <td>String</td>
        <td>Descripion of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Language</td>
        <td>String</td>
        <td>Language of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Hardware</td>
        <td>String</td>
        <td>Hardware used by the application</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Phone</td>
        <td>String</td>
        <td>Phone number of case creator</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Hardware</td>
        <td>String</td>
        <td>Hardware used by the application</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.URL</td>
        <td>String</td>
        <td>URL of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.UrlType</td>
        <td>String</td>
        <td>URL type of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.TargetedBrands</td>
        <td>String</td>
        <td>Target brands of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registrant</td>
        <td>String</td>
        <td>URL of the registrant</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Created</td>
        <td>String</td>
        <td>Creation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Expires</td>
        <td>String</td>
        <td>Expiriation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Updated</td>
        <td>String</td>
        <td>Update date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Registrar</td>
        <td>String</td>
        <td>Registrar of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.NameServers</td>
        <td>String</td>
        <td>Name servers of the URL</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
    <code>!phishlabs-ioc-drp-get-open-cases max_records=2</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "PhishLabsIOC": {
        "DRP": [
            {
                "Attachments": [
                    {
                        "DateAdded": "2019-08-16T18:10:53Z",
                        "Description": "Proof CBS owns Maxpreps brand. Requesting take down of maxpreps.us",
                        "FileName": "CBS Maxpreps.png",
                        "FileURL": "https://caseapi.phishlabs.com/v1/data/attachment/2fca6455",
                        "ID": "2fca6455",
                        "Type": "Email"
                    }
                ],
                "CaseID": "7cc6d097",
                "CaseNumber": 1254167,
                "CaseStatus": "Assigned",
                "CaseType": "Other",
                "CreatedBy": {
                    "DisplayName": "Matt T.",
                    "ID": "1e59f06d",
                    "Name": "mtwitty"
                },
                "Customer": "PhishLabs",
                "DateClosed": "0001-01-01T00:00:00Z",
                "DateCreated": "2019-08-09T21:20:18Z",
                "DateModified": "2019-11-01T18:13:21Z",
                "Description": "Courtesy case for CBS ",
                "Title": " Brand Abuse"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>PhishLabs IOC - DRP - open cases</h3>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th><strong>CaseID</strong></th>
        <th><strong>Title</strong></th>
        <th><strong>CaseStatus</strong></th>
        <th><strong>DateCreated</strong></th>
        <th><strong>CreatedBy</strong></th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> 7cc6d097-baeb-11e9-94e8-0ee0a3f3cb1c</td>
        <td> Brand Abuse</td>
        <td> Assigned</td>
        <td> 2019-08-09T21:20:18Z</td>
        <td> ID: 1e59f06d-7b03-11e4-b9b0-0025902add30<br>Name: mtwitty<br>DisplayName: Matt T.</td>
    </tr>
    </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="phishlabs-ioc-drp-get-closed-cases">4. phishlabs-ioc-drp-get-closed-cases</h3>
<hr>
<p>Get closed cases of Phishlabs DRP service by filters</p>
<h5>Base Command</h5>
<p>
    <code>phishlabs-ioc-drp-get-closed-cases</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Argument Name</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
        <th>
            <strong>Required</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>case_type</td>
        <td>Filter cases by case type</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>max_records</td>
        <td>maximum number of cases to return, default is 20, maximum is 200</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>offset</td>
        <td>Paginate results used in conjunction with maxRecords, first 200 records maxRecords=200&offset=0 second 200
            records maxRecords=200&offset=200
        </td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>Date_field</td>
        <td>Field to use to query using dateBegin and dateEnd parameters.</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>begin_date</td>
        <td>Date query beginning date</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>end_date</td>
        <td>Date query beginning date</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>period</td>
        <td>timestamp (<number> <time unit>, e.g., 12 hours, 7 days)</td>
        <td>Optional</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Path</strong>
        </th>
        <th>
            <strong>Type</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>PhishlabsIOC.DRP.CaseID</td>
        <td>String</td>
        <td>Case ID</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Title</td>
        <td>String</td>
        <td>Case title</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Description</td>
        <td>String</td>
        <td>Case description</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseNumber</td>
        <td>String</td>
        <td>Case number</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Resolution</td>
        <td>String</td>
        <td>Resolution</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ResolutionStatus</td>
        <td>String</td>
        <td>Resolution status</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.ID</td>
        <td>String</td>
        <td>Case creator ID</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.Name</td>
        <td>String</td>
        <td>Case creator name</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CreatedBy.DisplayName</td>
        <td>String</td>
        <td>Case creator display name</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Brand</td>
        <td>String</td>
        <td>Brand reported in case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Email</td>
        <td>String</td>
        <td>Email of case creator</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseType</td>
        <td>String</td>
        <td>Type of the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.CaseStatus</td>
        <td>String</td>
        <td>Status of the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateCreated</td>
        <td>String</td>
        <td>Case creation date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateClosed</td>
        <td>String</td>
        <td>Case closing date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DateModified</td>
        <td>String</td>
        <td>Case modification date</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Customer</td>
        <td>String</td>
        <td>Customer reporting the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.URL</td>
        <td>String</td>
        <td>URL of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.UrlType</td>
        <td>String</td>
        <td>URL type of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.IP</td>
        <td>String</td>
        <td>IP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.ISP</td>
        <td>String</td>
        <td>ISP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.Country</td>
        <td>String</td>
        <td>ISP of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.TargetedBrands</td>
        <td>String</td>
        <td>Target brands of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.FQDN</td>
        <td>String</td>
        <td>FQDN of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.Domain</td>
        <td>String</td>
        <td>Domain of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.IsMaliciousDomain</td>
        <td>Boolean</td>
        <td>Detect if domain of attack source is malicious</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registrant</td>
        <td>String</td>
        <td>URL of the registrant</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Created</td>
        <td>String</td>
        <td>Creation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Expires</td>
        <td>String</td>
        <td>Expiriation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Updated</td>
        <td>String</td>
        <td>Update date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.Registration.Registrar</td>
        <td>String</td>
        <td>Registrar of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AttackSources.WhoIs.NameServers</td>
        <td>String</td>
        <td>Name servers of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.ID</td>
        <td>String</td>
        <td>ID of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.Type</td>
        <td>String</td>
        <td>Type of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.Description</td>
        <td>String</td>
        <td>Description of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.DateAdded</td>
        <td>String</td>
        <td>Date adding of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.FileName</td>
        <td>String</td>
        <td>File name of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Attachments.FileURL</td>
        <td>String</td>
        <td>File URL of case attachment</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ApplicationName</td>
        <td>String</td>
        <td>Application reported in the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Platform</td>
        <td>String</td>
        <td>Platform reported in the case</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Severity</td>
        <td>String</td>
        <td>Sevirity of DRP</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Developer</td>
        <td>String</td>
        <td>Developer of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.DeveloperWebsite</td>
        <td>String</td>
        <td>Developer website of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.ApplicationDescription</td>
        <td>String</td>
        <td>Descripion of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Language</td>
        <td>String</td>
        <td>Language of the application reported</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Hardware</td>
        <td>String</td>
        <td>Hardware used by the application</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Phone</td>
        <td>String</td>
        <td>Phone number of case creator</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.Hardware</td>
        <td>String</td>
        <td>Hardware used by the application</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.URL</td>
        <td>String</td>
        <td>URL of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.UrlType</td>
        <td>String</td>
        <td>URL type of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.TargetedBrands</td>
        <td>String</td>
        <td>Target brands of the attack source</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registrant</td>
        <td>String</td>
        <td>URL of the registrant</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Created</td>
        <td>String</td>
        <td>Creation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Expires</td>
        <td>String</td>
        <td>Expiriation date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Updated</td>
        <td>String</td>
        <td>Update date of the registration</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.Registration.Registrar</td>
        <td>String</td>
        <td>Registrar of the URL</td>
    </tr>
    <tr>
        <td>PhishlabsIOC.DRP.AssociatedURLs.WhoIs.NameServers</td>
        <td>String</td>
        <td>Name servers of the URL</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
    <code>!phishlabs-ioc-drp-get-closed-cases max_records=2</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "PhishLabsIOC": {
        "DRP": [
            {
                "Attachments": [
                    {
                        "DateAdded": "2019-12-09T07:56:02Z",
                        "Description": "Source Email for case creation",
                        "FileName": "msg.mFAH.eml",
                        "FileURL": "https://caseapi.phishlabs.com/v1/data/attachment/581ba28d",
                        "ID": "581ba28d-1a59-11ea-8247-0ad24386a0d6",
                        "Type": "Email"
                    }
                ],
                "CaseID": "5808ec5a",
                "CaseNumber": 1417871,
                "CaseStatus": "Rejected",
                "CaseType": "Other",
                "CreatedBy": {
                    "DisplayName": "SOC PhishLabs",
                    "ID": "30c2e916",
                    "Name": "soc.phishlabs"
                },
                "Customer": "PhishLabs",
                "DateClosed": "2019-12-09T08:01:34Z",
                "DateCreated": "2019-12-09T07:56:01Z",
                "DateModified": "2019-12-09T08:01:34Z",
                "Description": "From: PhishLabs Security Operations <soc@phishlabs.com>\nSubject:",
                "ResolutionStatus": "Accidental creation",
                "Title": "=?gb2312?B?Rlc6I"
            },
            {
                "Attachments": [
                    {
                        "DateAdded": "2019-12-09T07:46:02Z",
                        "Description": "Source Email for case creation",
                        "FileName": "msg.fKAH.eml",
                        "FileURL": "https://caseapi.phishlabs.com/v1/data/attachment/f24c36a3",
                        "ID": "f24c36a3",
                        "Type": "Email"
                    }
                ],
                "CaseID": "f239fe62",
                "CaseNumber": 1417866,
                "CaseStatus": "Rejected",
                "CaseType": "Other",
                "CreatedBy": {
                    "DisplayName": "SOC PhishLabs",
                    "ID": "30c2e916",
                    "Name": "soc.phishlabs"
                },
                "Customer": "PhishLabs",
                "DateClosed": "2019-12-09T07:49:11Z",
                "DateCreated": "2019-12-09T07:46:01Z",
                "DateModified": "2019-12-09T07:49:11Z",
                "Description": "From: PhishLabs Security ",
                "ResolutionStatus": "Accidental creation",
                "Title": "?="
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>PhishLabs IOC - DRP - Closed cases</h3>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th><strong>CaseID</strong></th>
        <th><strong>Title</strong></th>
        <th><strong>CaseStatus</strong></th>
        <th><strong>DateCreated</strong></th>
        <th><strong>ResolutionStatus</strong></th>
        <th><strong>CreatedBy</strong></th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> 5808ec5a</td>
        <td> ?=</td>
        <td> Rejected</td>
        <td> 2019-12-09T07:56:01Z</td>
        <td> Accidental creation</td>
        <td> ID: 30c2e916 SOC PhishLabs</td>
    </tr>
    <tr>
        <td> f239fe62c</td>
        <td> =1?=</td>
        <td> Rejected</td>
        <td> 2019-12-09T07:46:01Z</td>
        <td> Accidental creation</td>
        <td> ID: 30c2e916<br>Name: soc.phishlabs<br>DisplayName: SOC PhishLabs</td>
    </tr>
    </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<p>
    Get security event from <a href="https://www.akamai.com/us/en/resources/waf.jsp">Akamai Web Application Firewall (WAF)</a>
    service.
    This integration was integrated and tested with <a href="https://developer.akamai.com/api/cloud_security/siem/v1.html"> API version 1.0 of Akamai WAF
    SIEM</a>
</p>

<h2>Use Cases</h2>
<ul>
    <li>Get security events from Akamai WAF.</li>
    <li>Analyze security events generated on the Akamai platform and correlate them with security events generated from
        other sources in Cortex XSOAR</li>
</ul>

<h2>Detailed Description</h2>
<p>
    A WAF (web application firewall) is a filter that protects against HTTP application attacks. It inspects HTTP traffic
    before
    it reaches your application and protects your server by filtering out threats that could damage your site
    functionality or
    compromise data.
</p>

<h2>API keys generating steps</h2>
<ol>
    <li>Go to `WEB & DATA CENTER SECURITY`>`Security Configuration`>choose you configuration>`Advanced settings`> Enable SIEM integration.</li>
    <li><a href="https://control.akamai.com/">Open Control panel</a> and login with admin account.</li>
    <li>Open <code>identity and access management</code> menu.</li>
    <li>Create user with assign roles <code>Manage SIEM</code> or make sure the admin has rights for manage SIEM.</li>
    <li>Log in to new account you created in the last step.</li>
    <li>Open <code>identity and access management</code> menu.</li>
    <li>Create <code>new api client for me</code></li>
    <li>Assign API key to the relevant users group, and assign on next page <code>Read/Write</code> access for <code>SIEM</code>.</li>
    <li>Save configuration and go to API detail you created.</li>
    <li>Press <code>new credentials</code> and download or copy it.</li>
    <li>Now use the credentials for configure Akamai WAF in Cortex XSOAR</li>
</ol>

<h2>Configure Akamai WAF SIEM on Cortex XSOAR</h2>
<ol>
    <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
        &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.
    </li>
    <li>Search for Akamai WAF SIEM.</li>
    <li>
        Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
        <ul>
            <li><strong>Name</strong>: a textual name for the integration instance.</li>
            <li><strong>Server URL (e.g. https://example.net)</strong></li>
            <li><strong>Client token</strong></li>
            <li><strong>Access token</strong></li>
            <li><strong>Client secret</strong></li>
            <li><strong>Config ids to fetch (can have multiple seperated by semi commas ';')</strong></li>
            <li><strong>Incident type</strong></li>
            <li>First fetch timestamp (for example 12 hours, 7 days)</li>
            <li><strong>Fetch limit </strong></li>
            <li><strong>Trust any certificate (not secure)</strong></li>
            <li><strong>Use system proxy settings</strong></li>
        </ul>
    </li>
    <li>
        Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
    </li>
</ol>

<h2>Fetch Incidents</h2>
<pre>
    [
      {
        "name": "Akamai SIEM: 50170",
        "occurred": "2019-12-10T18:28:27Z",
        "rawJSON": {
          "type": "akamai_siem",
          "format": "json",
          "version": "1.0",
          "attackData": {
            "configId": "50170",
            "policyId": "1234",
            "clientIP": "8.8.8.8",
            "rules": "test",
            "ruleVersions": "",
            "ruleMessages": "Test",
            "ruleTags": "Test",
            "ruleData": "",
            "ruleSelectors": "",
            "ruleActions": "Test"
          },
          "httpMessage": {
            "requestId": "3fbce3e",
            "start": "1576002507",
            "protocol": "HTTP/1.1",
            "method": "HEAD",
            "host": "google.com",
            "port": "80",
            "path": "index",
            "requestHeaders": "Test",
            "status": "403",
            "bytes": "0",
            "responseHeaders": "Server"
          },
          "geo": {
            "continent": "NA",
            "country": "US",
            "city": "LOSANGELES",
            "regionCode": "CA",
            "asn": "5650"
          }
        }
      },
      {
        "name": "Akamai SIEM: 50170",
        "occurred": "2019-12-10T18:28:26Z",
        "rawJSON": {
          "type": "akamai_siem",
          "format": "json",
          "version": "1.0",
          "attackData": {
            "configId": "50170",
            "policyId": "1234",
            "clientIP": "8.8.8.8",
            "rules": "test",
            "ruleVersions": "",
            "ruleMessages": "Test",
            "ruleTags": "Test",
            "ruleData": "",
            "ruleSelectors": "",
            "ruleActions": "Test"
          },
          "httpMessage": {
            "requestId": "3fbd757",
            "start": "1576002506",
            "protocol": "HTTP/1.1",
            "method": "HEAD",
            "host": "google.com",
            "port": "80",
            "path": "index",
            "requestHeaders": "Test",
            "status": "403",
            "bytes": "0",
            "responseHeaders": "Server"
          },
          "geo": {
            "continent": "NA",
            "country": "US",
            "city": "LOSANGELES",
            "regionCode": "CA",
            "asn": "5650"
          }
        }
      }
    ]
</pre>

<h2>Commands</h2>
<p>
    You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
    After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
    <li><a href="#akamai-siem-get-events" target="_self">Get security events from Akamai WAF: akamai-siem-get-events</a>
    </li>
</ol>
<h3 id="akamai-siem-get-events">1. akamai-siem-get-events</h3>
<hr>
<p>Get security events from Akamai WAF</p>
<h5>Base Command</h5>
<p>
    <code>akamai-siem-get-events</code>
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
        <td>config_ids</td>
        <td>Unique identifier for each security configuration. To report on more than one configuration, separate
            integer identifiers with semicolons, e.g. 12892;29182;82912.
        </td>
        <td>Required</td>
    </tr>
    <tr>
        <td>offset</td>
        <td>This token denotes the last message. If specified, this operation fetches only security events that have
            occurred from offset. This is a required parameter for offset mode and you can’t use it in time-based
            requests.
        </td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>limit</td>
        <td>Defines the approximate maximum number of security events each fetch returns</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>from_epoch</td>
        <td>The start of a specified time range, expressed in Unix epoch seconds.</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>to_epoch</td>
        <td>The end of a specified time range, expressed in Unix epoch seconds.</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>timestamp</td>
        <td>timestamp (for example 12 hours, 7 days of events</td>
        <td>Optional</td>
    </tr>
    </tbody>
</table>

<p>Allowed query parameters combinations:</p>
<ol>
    <li>offset - Since a prior request.</li>
    <li>offset, limit - Since a prior request, limited.</li>
    <li>from - Since a point in time.</li>
    <li>from, limit - Since a point in time, limited.</li>
    <li>from, to - Over a range of time.</li>
    <li>from, to, limit - Over a range of time, limited.</li>
</ol>


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
        <td>Akamai.SIEM.AttackData.clientIP</td>
        <td>String</td>
        <td>IP involved in the attack.</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.ConfigID</td>
        <td>String</td>
        <td>Unique identifier of security configuration involved</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.PolicyID</td>
        <td>String</td>
        <td>Unique identifier of Policy configuration involved</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.PolicyID</td>
        <td>String</td>
        <td>Policy ID trigered</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.Geo.Asn</td>
        <td>String</td>
        <td>Geographic ASN location of involved IP</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.Geo.City</td>
        <td>String</td>
        <td>City of involved IP</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.Geo.Continent</td>
        <td>String</td>
        <td>Continent of involved IP</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.Geo.Country</td>
        <td>String</td>
        <td>Country of involved IP</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.Geo.RegionCode</td>
        <td>String</td>
        <td>Region code of involved IP</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.Bytes</td>
        <td>Number</td>
        <td>HTTP messege size in bytes</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.Host</td>
        <td>String</td>
        <td>HTTP messege host</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.Method</td>
        <td>String</td>
        <td>HTTP messege method</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.Path</td>
        <td>String</td>
        <td>HTTP messege path</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.Port</td>
        <td>String</td>
        <td>HTTP messege port</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.Protocol</td>
        <td>String</td>
        <td>HTTP messege protocol</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.Query</td>
        <td>String</td>
        <td>HTTP messege query</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.RequestHeaders</td>
        <td>String</td>
        <td>HTTP messege request headers</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.RequestID</td>
        <td>String</td>
        <td>HTTP messege request ID</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.ResponseHeaders</td>
        <td>String</td>
        <td>HTTP messege respose headers</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.Start</td>
        <td>Date</td>
        <td>HTTP messege epoch start time</td>
    </tr>
    <tr>
        <td>Akamai.SIEM.AttackData.HttpMessage.Status</td>
        <td>Number</td>
        <td>HTTP messege status code</td>
    </tr>
    <tr>
        <td>IP.Address</td>
        <td>String</td>
        <td>IP address</td>
    </tr>
    <tr>
        <td>IP.ASN</td>
        <td>String</td>
        <td>The autonomous system name for the IP address, for example: "AS8948"."</td>
    </tr>
    <tr>
        <td>IP.Geo.Country</td>
        <td>String</td>
        <td>The country in which the IP address is located</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
    <code>!akamai-siem-get-events config_ids="50170" period="3 hours"</code>
</p>
<h5>Context Example</h5>
<pre>
{
  "Akamai": {
    "SIEM": [
        {
            "AttackData": {
                "ClientIP": "8.8.8.8",
                "ConfigID": "50170",
                "PolicyID": "1234_89452",
                "RuleActions": [
                    "alert",
                    "deny"
                ],
                "RuleMessages": [
                    "Custom_RegEX_Rule",
                    "No Accept Header AND No User Agent Header"
                ],
                "RuleTags": [
                    "example",
                    "No-AH-UA"
                ],
                "Rules": [
                    "642118",
                    "642119"
                ]
            },
            "Geo": {
                "Asn": "16509",
                "City": "FRANKFURT",
                "Continent": "EU",
                "Country": "DE",
                "RegionCode": "HE"
            },
            "HttpMessage": {
                "Bytes": "296",
                "Host": "wordpress.demisto.ninja",
                "Method": "POST",
                "Path": "/wp-cron.php",
                "Port": "80",
                "Protocol": "HTTP/1.1",
                "RequestHeaders": "Host",
                "RequestId": "87bb604",
                "ResponseHeaders": "Server",
                "Start": "1576746102",
                "Status": "403"
            }
        },
        {
            "AttackData": {
                "ClientIP": "8.8.8.8",
                "ConfigID": "50170",
                "PolicyID": "1234_89452",
                "RuleActions": [
                    "alert",
                    "deny"
                ],
                "RuleMessages": [
                    "Custom_RegEX_Rule",
                    "No Accept Header AND No User Agent Header"
                ],
                "RuleTags": [
                    "example",
                    "No-AH-UA"
                ],
                "Rules": [
                    "642118",
                    "642119"
                ]
            },
            "Geo": {
                "Asn": "16509",
                "City": "FRANKFURT",
                "Continent": "EU",
                "Country": "DE",
                "RegionCode": "HE"
            },
            "HttpMessage": {
                "Bytes": "296",
                "Host": "wordpress.demisto.ninja",
                "Method": "POST",
                "Path": "/wp-cron.php",
                "Port": "80",
                "Protocol": "HTTP/1.1",
                "RequestHeaders": "Header",
                "RequestId": "32e63ee2",
                "ResponseHeaders": "Server",
                "Start": "1576746179",
                "Status": "403"
            }
        }
    ]
  },
  "IP": [
    {
      "ASN": "5650",
      "Address": "8.8.8.8",
      "Geo": {
        "Country": "US"
      }
    },
    {
      "ASN": "5650",
      "Address": "8.8.8.8",
      "Geo": {
        "Country": "US"
      }
    }
  ]
}
</pre>

<h3>Akamai SIEM - Attacks list</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Attacking IP</strong></th>
      <th><strong>Config ID</strong></th>
      <th><strong>Date occured</strong></th>
      <th><strong>Location</strong></th>
      <th><strong>Policy ID</strong></th>
      <th><strong>Rule actions</strong></th>
      <th><strong>Rule messages</strong></th>
      <th><strong>Rules</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 3.124.101.138 </td>
      <td> 50170 </td>
      <td> 2019-12-19T09:00:42Z </td>
      <td> Country: DE<br>City: FRANKFURT </td>
      <td> 1234_89452 </td>
      <td> alert,<br>deny </td>
      <td> Custom_RegEX_Rule,<br>No Accept Header AND No User Agent Header </td>
      <td> 642118,<br>642119 </td>
    </tr>
    <tr>
      <td> 3.124.101.138 </td>
      <td> 50170 </td>
      <td> 2019-12-19T09:01:42Z </td>
      <td> Country: DE<br>City: FRANKFURT </td>
      <td> 1234_89452 </td>
      <td> alert,<br>deny </td>
      <td> Custom_RegEX_Rule,<br>No Accept Header AND No User Agent Header </td>
      <td> 642118,<br>642119 </td>
    </tr>
  </tbody>
</table>

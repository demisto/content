<p>
    Get security event from [Akamai Web Application Firewall (WAF)](https://www.akamai.com/us/en/resources/waf.jsp)
    service.

    This integration was integrated and tested with [version 1.0 of Akamai WAF
    SIEM](https://developer.akamai.com/api/cloud_security/siem/v1.html)
</p>

<h2>Use Cases</h2>
<ul>
    <li>Get security events from Akamai WAF.</li>
    <li>analyze security events generated on the Akamai platform and correlate them with security events generated from
        other sources in Demisto</li>

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
    <li>[Open Control panel](https://control.akamai.com/) and login with admin account.</li>
    <li>Open identity and access management menu.</li>
    <li>Create user with assign roles <code>Manage SIEM</code> or make sure the admin has rights for manage SIEM.</li>
    <li>Log in to new account you created in the last step.</li>
    <li>Open identity and access management menu.</li>
    <li>Create <code>new api client for me</code></li>
    <li>Assign API key to the relevant users group, and assign on next page <code>Read/Write</code> access for <code>SIEM</code>.</li>
    <li>Save configuration and go to API detail you created.</li>
    <li>Press <code>new credentials</code> and download or copy it.</li>
    <li>Now use the credentials for configure Akamai WAF in Demisto</li>
</ol>

<h2>Configure Akamai WAF SIEM on Demisto</h2>
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
            <li><strong>Config ids to fetch (can have multiple seperated by commas ';')</strong></li>
            <li><strong>Incident type</strong></li>
            <li><strong>First fetch timestamp (
                <number>
                    <time unit>, e.g., 12 hours, 7 days)
            </strong></li>
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
    You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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
        <td>period</td>
        <td>period timestamp (
            <number>
                <time unit>, e.g., 12 hours, 7 days of events
        </td>
        <td>Optional</td>
    </tr>
    </tbody>
</table>

<p>
    Allowed query parameters combinations:
    1. offset - Since a prior request.
    2. offset, limit - Since a prior request, limited.
    3. from - Since a point in time.
    4. from, limit - Since a point in time, limited.
    5. from, to - Over a range of time.
    6. from, to, limit - Over a range of time, limited.
</p>

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
          "PolicyID": "1234"
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
          "Host": "wordpress.demisto.ninja",
          "RequestId": "321a8ec5",
          "ResponseHeaders": "Server",
          "Start": "1576637273",
          "Status": "403"
        }
      },
      {
        "AttackData": {
          "ClientIP": "8.8.8.8",
          "ConfigID": "50170",
          "PolicyID": "1234"
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
          "RequestHeaders": "wordpress.demisto.ninja",
          "RequestId": "83e044a",
          "ResponseHeaders": "Server",
          "Start": "1576637333",
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
<h5>Human Readable Output</h5>
<p>
<h3>Akamai SIEM - security events</h3>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th><strong>ClientIP</strong></th>
        <th><strong>ConfigID</strong></th>
        <th><strong>PolicyID</strong></th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> 8.8.8.8</td>
        <td> 50170</td>
        <td> 1234</td>
    </tr>
    <tr>
        <td> 8.8.8.8</td>
        <td> 50170</td>
        <td> 1234</td>
    </tr>
    </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->


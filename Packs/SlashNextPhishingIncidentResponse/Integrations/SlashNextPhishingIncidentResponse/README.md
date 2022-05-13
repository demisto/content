<p>
  <br>
  <b>SlashNext Phishing Incident Response</b> integration enables Cortex XSOAR users to fully automate analysis of suspicious
  URLs. For example, IR teams responsible for abuse inbox management can extract links or domains out of suspicious
  emails and automatically analyze them with the SlashNext SEER™ threat detection cloud to get definitive, binary
  verdicts (malicious or benign) along with IOCs, screen shots, and more. Automating URL analysis can save IR teams
  hundreds of hours versus manually triaging these emails or checking URLs and domains against less accurate phishing
  databases and domain reputation services.
  <br>

  <br>
  This integration was integrated and tested with version <b>v1.1</b> of SlashNext Phishing Incident Response APIs.
  <br>
</p>
<h2>SlashNext Phishing Incident Response Playbook</h2>
<p>SlashNext have developed two sample playbooks to demonstrate two of the major use cases.</p>
<ul>
  <li>SlashNext - Host Reputation Default v1</li>
  <li>SlashNext - URL Scan Default v1</li>
</ul>
<h2>Use Cases</h2>
<ul>
<li>
  Abuse inbox management
</li>
<li>
 Playbooks that mine and analyze network logs
</li>
</ul>
<h2>Detailed Description</h2>
<p>
  SlashNext Phishing Incident Response integration uses an API key to authenticate with SlashNext Cloud. If you
  don’t have a valid API key, contact the SlashNext team <a href = "mailto: support@slashnext.com">support@slashnext.com</a>
</p>
<h2>Fetch Incidents</h2>
<p>
  Any phishing incidents/events that contain supsicious URLs, domains, or IP addresses through the use of an
  <b>Abuse Inbox</b> or by manual reporting.
</p>
<h2>Configure SlashNext Phishing Incident Response on Cortex XSOAR</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for <b>SlashNext Phishing Incident Response</b> using the search box on the top of the page.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: A textual name for the integration instance.</li>
   <li><strong>SlashNext API Base URL</strong>: Use the default value unless specifically provided by SlashNext.</li>
   <li><strong>SlashNext API Key</strong>: If you don’t have a valid API key, please reach us at <a href = "mailto: support@slashnext.com">support@slashnext.com</a></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>ip</li>
  <li>domain</li>
  <li>url</li>
  <li>slashnext-host-reputation</li>
  <li>slashnext-host-report</li>
  <li>slashnext-host-urls</li>
  <li>slashnext-url-reputation</li>
  <li>slashnext-url-scan</li>
  <li>slashnext-url-scan-sync</li>
  <li>slashnext-scan-report</li>
  <li>slashnext-download-screenshot</li>
  <li>slashnext-download-html</li>
  <li>slashnext-download-text</li>
  <li>slashnext-api-quota</li>
</ol>
<h3>1. ip</h3>
<hr>
<p>Lookup an IP address indicator in SlashNext Threat Intelligence database.</p>
<h5>Base Command</h5>
<p>
  <code>ip</code>
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
      <td>ip</td>
      <td>IPv4 address which to be looked up in SlashNext Threat Intelligence database.</td>
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
      <td>DBotScore.Indicator</td>
      <td>string</td>
      <td>The indicator that was tested</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>string</td>
      <td>Indicator type</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>string</td>
      <td>Vendor used to calculate the score</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>number</td>
      <td>The actual score</td>
    </tr>
    <tr>
      <td>IP.Address</td>
      <td>string</td>
      <td>IP address</td>
    </tr>
    <tr>
      <td>IP.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious IP addresses, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>IP.Malicious.Description</td>
      <td>string</td>
      <td>For malicious IP addresses, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.IP.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.IP.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.IP.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.IP.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!ip ip=8.8.8.8</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 1,
        "Type": "ip",
        "Vendor": "SlashNext Phishing Incident Response"
    },
    "IP": {
        "Address": "8.8.8.8"
    },
    "SlashNext.IP": {
        "FirstSeen": "09-26-2019 07:46:25 UTC",
        "LastSeen": "09-26-2019 07:46:36 UTC",
        "ThreatName": "N/A",
        "ThreatStatus": "N/A",
        "ThreatType": "N/A",
        "Type": "IP",
        "Value": "8.8.8.8",
        "Verdict": "Benign"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>SlashNext Phishing Incident Response - IP Lookup</h3>
<h5>ip = 8.8.8.8</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Value</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Verdict</strong></th>
      <th><strong>ThreatStatus</strong></th>
      <th><strong>ThreatName</strong></th>
      <th><strong>ThreatType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 8.8.8.8 </td>
      <td> IP </td>
      <td> Benign </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 09-26-2019 07:46:25 UTC </td>
      <td> 09-26-2019 07:46:36 UTC </td>
    </tr>
  </tbody>
</table>
</p>

<h3>2. domain</h3>
<hr>
<p>Lookup a FQDN indicator in SlashNext Threat Intelligence database.</p>
<h5>Base Command</h5>
<p>
  <code>domain</code>
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
      <td>domain</td>
      <td>FQDN which to be looked up in SlashNext Threat Intelligence database.</td>
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
      <td>DBotScore.Indicator</td>
      <td>string</td>
      <td>The indicator that was tested</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>string</td>
      <td>Indicator type</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>string</td>
      <td>Vendor used to calculate the score</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>number</td>
      <td>The actual score</td>
    </tr>
    <tr>
      <td>Domain.Name</td>
      <td>string</td>
      <td>Domain name</td>
    </tr>
    <tr>
      <td>Domain.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious domain names, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>Domain.Malicious.Description</td>
      <td>string</td>
      <td>For malicious domain names, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!domain domain=www.google.com</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": {
        "Indicator": "www.google.com",
        "Score": 1,
        "Type": "domain",
        "Vendor": "SlashNext Phishing Incident Response"
    },
    "Domain": {
        "Name": "www.google.com"
    },
    "SlashNext.Domain": {
        "FirstSeen": "12-10-2018 13:04:17 UTC",
        "LastSeen": "10-10-2019 11:26:43 UTC",
        "ThreatName": "N/A",
        "ThreatStatus": "N/A",
        "ThreatType": "N/A",
        "Type": "Domain",
        "Value": "www.google.com",
        "Verdict": "Benign"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>SlashNext Phishing Incident Response - Domain Lookup</h3>
<h5>domain = www.google.com</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Value</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Verdict</strong></th>
      <th><strong>ThreatStatus</strong></th>
      <th><strong>ThreatName</strong></th>
      <th><strong>ThreatType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> www.google.com </td>
      <td> Domain </td>
      <td> Benign </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 12-10-2018 13:04:17 UTC </td>
      <td> 10-10-2019 11:26:43 UTC </td>
    </tr>
  </tbody>
</table>
</p>

<h3>3. url</h3>
<hr>
<p>Queries the SlashNext Cloud database and retrieves the reputation of a url.</p>
<h5>Base Command</h5>
<p>
  <code>url</code>
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
      <td>url</td>
      <td>The url to look up in the SlashNext Threat Intelligence database.</td>
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
      <td>DBotScore.Indicator</td>
      <td>string</td>
      <td>The indicator that was tested</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>string</td>
      <td>Indicator type</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>string</td>
      <td>Vendor used to calculate the score</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>number</td>
      <td>The actual score</td>
    </tr>
    <tr>
      <td>URL.Data</td>
      <td>string</td>
      <td>URL reported</td>
    </tr>
    <tr>
      <td>URL.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious URLs, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>URL.Malicious.Description</td>
      <td>string</td>
      <td>For malicious URLs, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Value</td>
      <td>string</td>
      <td>Final IoC value in case original IoC is a redirector to same domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Type</td>
      <td>string</td>
      <td>Type of the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Value</td>
      <td>string</td>
      <td>Landing IoC value in case original IoC is a redirector to different domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Type</td>
      <td>string</td>
      <td>Type of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.FirstSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.LastSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was last observed</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!url url=www.google.com</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": [
        {
            "Indicator": "http://www.google.com/",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/?gws_rd=ssl",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        }
    ],
    "SlashNext.URL": {
        "Final": {
            "Type": "Final URL",
            "Value": "https://www.google.com/?gws_rd=ssl",
            "Verdict": "Benign"
        },
        "FirstSeen": "08-26-2019 17:29:38 UTC",
        "LastSeen": "08-26-2019 19:41:19 UTC",
        "ThreatName": "N/A",
        "ThreatStatus": "N/A",
        "ThreatType": "N/A",
        "Type": "Scanned URL",
        "Value": "http://www.google.com/",
        "Verdict": "Benign"
    },
    "URL": [
        {
            "Data": "http://www.google.com/"
        },
        {
            "Data": "https://www.google.com/?gws_rd=ssl"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>SlashNext Phishing Incident Response - URL Lookup</h3>
<h5>url = http://www.google.com/</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Value</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Verdict</strong></th>
      <th><strong>ThreatStatus</strong></th>
      <th><strong>ThreatName</strong></th>
      <th><strong>ThreatType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> http://www.google.com/ </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 08-26-2019 17:29:38 UTC </td>
      <td> 08-26-2019 19:41:19 UTC </td>
    </tr>
    <tr>
      <td> --------> https://www.google.com/?gws_rd=ssl </td>
      <td> Final URL </td>
      <td> Benign </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
  </tbody>
</table>
</p>

<h3>4. slashnext-host-reputation</h3>
<hr>
<p>Search in SlashNext Cloud database and retrieve reputation of a host.</p>
<h5>Base Command</h5>
<p>
  <code>slashnext-host-reputation</code>
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
      <td>host</td>
      <td>host can either be a domain name or an IPv4 address.</td>
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
      <td>DBotScore.Indicator</td>
      <td>string</td>
      <td>The indicator that was tested</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>string</td>
      <td>Indicator type</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>string</td>
      <td>Vendor used to calculate the score</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>number</td>
      <td>The actual score</td>
    </tr>
    <tr>
      <td>IP.Address</td>
      <td>string</td>
      <td>IP address</td>
    </tr>
    <tr>
      <td>IP.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious IP addresses, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>IP.Malicious.Description</td>
      <td>string</td>
      <td>For malicious IP addresses, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.IP.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.IP.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.IP.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.IP.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
    <tr>
      <td>Domain.Name</td>
      <td>string</td>
      <td>Domain name</td>
    </tr>
    <tr>
      <td>Domain.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious domain names, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>Domain.Malicious.Description</td>
      <td>string</td>
      <td>For malicious domain names, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slashnext-host-reputation host=www.google.com</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": {
        "Indicator": "www.google.com",
        "Score": 1,
        "Type": "domain",
        "Vendor": "SlashNext Phishing Incident Response"
    },
    "Domain": {
        "Name": "www.google.com"
    },
    "SlashNext.Domain": {
        "FirstSeen": "12-10-2018 13:04:17 UTC",
        "LastSeen": "10-10-2019 11:26:43 UTC",
        "ThreatName": "N/A",
        "ThreatStatus": "N/A",
        "ThreatType": "N/A",
        "Type": "Domain",
        "Value": "www.google.com",
        "Verdict": "Benign"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>SlashNext Phishing Incident Response - Host Reputation</h3>
<h5>host = www.google.com</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Value</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Verdict</strong></th>
      <th><strong>ThreatStatus</strong></th>
      <th><strong>ThreatName</strong></th>
      <th><strong>ThreatType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> www.google.com </td>
      <td> Domain </td>
      <td> Benign </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 12-10-2018 13:04:17 UTC </td>
      <td> 10-10-2019 11:26:43 UTC </td>
    </tr>
  </tbody>
</table>
</p>

<h3>5. slashnext-host-report</h3>
<hr>
<p>Search in SlashNext Cloud database and retrieve a detailed report for a host and associated URL.</p>
<h5>Base Command</h5>
<p>
  <code>slashnext-host-report</code>
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
      <td>host</td>
      <td>host can either be a domain name or IPv4 address.</td>
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
      <td>DBotScore.Indicator</td>
      <td>string</td>
      <td>The indicator that was tested</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>string</td>
      <td>Indicator type</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>string</td>
      <td>Vendor used to calculate the score</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>number</td>
      <td>The actual score</td>
    </tr>
    <tr>
      <td>IP.Address</td>
      <td>string</td>
      <td>IP address</td>
    </tr>
    <tr>
      <td>IP.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious IP addresses, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>IP.Malicious.Description</td>
      <td>string</td>
      <td>For malicious IP addresses, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.IP.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.IP.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.IP.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.IP.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.IP.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
    <tr>
      <td>Domain.Name</td>
      <td>string</td>
      <td>Domain name</td>
    </tr>
    <tr>
      <td>Domain.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious domain names, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>Domain.Malicious.Description</td>
      <td>string</td>
      <td>For malicious domain names, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.Domain.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slashnext-host-report host=www.google.com</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": {
        "Indicator": "www.google.com",
        "Score": 1,
        "Type": "domain",
        "Vendor": "SlashNext Phishing Incident Response"
    },
    "Domain": {
        "Name": "www.google.com"
    },
    "SlashNext.Domain": {
        "FirstSeen": "12-10-2018 13:04:17 UTC",
        "LastSeen": "10-10-2019 11:26:43 UTC",
        "ThreatName": "N/A",
        "ThreatStatus": "N/A",
        "ThreatType": "N/A",
        "Type": "Domain",
        "Value": "www.google.com",
        "Verdict": "Benign"
    }
}{
    "DBotScore": [
        {
            "Indicator": "http://www.google.com/wasif",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        }
    ],
    "SlashNext.URL": {
        "FirstSeen": "10-03-2019 08:24:04 UTC",
        "LastSeen": "10-03-2019 08:24:14 UTC",
        "ScanID": "61fe7c96-88e3-440e-a56f-75834b734b06",
        "ThreatName": "N/A",
        "ThreatStatus": "N/A",
        "ThreatType": "N/A",
        "Type": "Scanned URL",
        "Value": "http://www.google.com/wasif",
        "Verdict": "Benign"
    },
    "URL": [
        {
            "Data": "http://www.google.com/wasif"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>SlashNext Phishing Incident Response - Host Report</h3>
<h5>host = www.google.com</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Value</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Verdict</strong></th>
      <th><strong>ThreatStatus</strong></th>
      <th><strong>ThreatName</strong></th>
      <th><strong>ThreatType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> www.google.com </td>
      <td> Domain </td>
      <td> Benign </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 12-10-2018 13:04:17 UTC </td>
      <td> 10-10-2019 11:26:43 UTC </td>
    </tr>
  </tbody>
</table>

<h3>SlashNext Phishing Incident Response - Latest Scanned URL</h3>
<h5>host = www.google.com</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Value</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Verdict</strong></th>
      <th><strong>ScanID</strong></th>
      <th><strong>ThreatStatus</strong></th>
      <th><strong>ThreatName</strong></th>
      <th><strong>ThreatType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> http://www.google.com/wasif </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> 61fe7c96-88e3-440e-a56f-75834b734b06 </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 10-03-2019 08:24:04 UTC </td>
      <td> 10-03-2019 08:24:14 UTC </td>
    </tr>
  </tbody>
</table>

<p>
Forensics: Webpage Screenshot for the Scanned URL = http://www.google.com/wasif<br>
Forensics: Webpage HTML for the Scanned URL = http://www.google.com/wasif<br>
Forensics: Webpage Rendered Text for the Scanned URL = http://www.google.com/wasif<br>
</p>
</p>

<h3>6. slashnext-host-urls</h3>
<hr>
<p>Search in SlashNext Cloud database and retrieve list of all URLs associated with the specified host.</p>
<h5>Base Command</h5>
<p>
  <code>slashnext-host-urls</code>
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
      <td>host</td>
      <td>host can either be a domain name or IPv4 address.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>maximum number of URL records to fetch. This is an optional parameter with a default value of 10.</td>
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
      <td>DBotScore.Indicator</td>
      <td>string</td>
      <td>The indicator that was tested</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>string</td>
      <td>Indicator type</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>string</td>
      <td>Vendor used to calculate the score</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>number</td>
      <td>The actual score</td>
    </tr>
    <tr>
      <td>URL.Data</td>
      <td>string</td>
      <td>URL reported</td>
    </tr>
    <tr>
      <td>URL.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious URLs, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>URL.Malicious.Description</td>
      <td>string</td>
      <td>For malicious URLs, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ScanID</td>
      <td>string</td>
      <td>Scan ID to be used to get the IoC forensics data for further investigation</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Value</td>
      <td>string</td>
      <td>Final IoC value in case original IoC is a redirector to same domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Type</td>
      <td>string</td>
      <td>Type of the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Value</td>
      <td>string</td>
      <td>Landing IoC value in case original IoC is a redirector to different domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Type</td>
      <td>string</td>
      <td>Type of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ScanID</td>
      <td>string</td>
      <td>Scan ID to be used to get the landing IoC forensics data for further investigation</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.FirstSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.LastSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was last observed</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slashnext-host-urls host=www.google.com</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": [
        {
            "Indicator": "http://www.google.com/wasif",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "http://www.google.com/abrar",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "http://www.google.com/saadat",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/url?q=replacedlink/&source=gmail&...",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "http://www.google.com/",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/?gws_rd=ssl",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "http://www.google.com/maps/place/2307",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/maps/place/2307",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "http://www.google.com/maps/place/2307+Watterson+Trail",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/maps/place/2307+Watterson+Trail",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "http://www.google.com/maps/place/2307&#43;Watterson&#43;Trail",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/maps/place/2307&#43;Watterson&#43;Trail",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "http://www.google.com/maps/place/2307&#43;Watterson&#43;Trail,&#43;Jeffersontown,&#43;KY&#43;40299/@38.2107207,-85.5607165,17z/data=!3m1!4b1!4m5!3m4!1s0x8869a1b57420f6d9:0xccc95b8f32dcfd4b!8m2!3d38.2107165!4d-85.5585225",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/maps/place/2307&#43;Watterson&#43;Trail,&#43;Jeffersontown,&#43;KY&#43;40299/@38.2107207,-85.5607165,17z/data=!3m1!4b1!4m5!3m4!1s0x8869a1b57420f6d9:0xccc95b8f32dcfd4b!8m2!3d38.2107165!4d-85.5585225",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        }
    ],
    "SlashNext.URL": [
        {
            "FirstSeen": "10-03-2019 08:24:04 UTC",
            "LastSeen": "10-03-2019 08:24:14 UTC",
            "ScanID": "61fe7c96-88e3-440e-a56f-75834b734b06",
            "ThreatName": "N/A",
            "ThreatStatus": "N/A",
            "ThreatType": "N/A",
            "Type": "Scanned URL",
            "Value": "http://www.google.com/wasif",
            "Verdict": "Benign"
        },
        {
            "FirstSeen": "10-03-2019 08:22:36 UTC",
            "LastSeen": "10-03-2019 08:22:46 UTC",
            "ScanID": "820275cd-c6de-46e9-b3a3-7cb072179bb4",
            "ThreatName": "N/A",
            "ThreatStatus": "N/A",
            "ThreatType": "N/A",
            "Type": "Scanned URL",
            "Value": "http://www.google.com/abrar",
            "Verdict": "Benign"
        },
        {
            "FirstSeen": "10-03-2019 08:17:49 UTC",
            "LastSeen": "10-03-2019 08:18:00 UTC",
            "ScanID": "905cf63e-7761-4681-b314-4b8820f04c41",
            "ThreatName": "N/A",
            "ThreatStatus": "N/A",
            "ThreatType": "N/A",
            "Type": "Scanned URL",
            "Value": "http://www.google.com/saadat",
            "Verdict": "Benign"
        },
        {
            "FirstSeen": "08-27-2019 10:32:19 UTC",
            "LastSeen": "08-27-2019 12:34:52 UTC",
            "ScanID": "4f1540b9-3517-4e6c-bca8-923acc3eed43",
            "ThreatName": "N/A",
            "ThreatStatus": "N/A",
            "ThreatType": "N/A",
            "Type": "Scanned URL",
            "Value": "https://www.google.com/",
            "Verdict": "Benign"
        },
        {
            "FirstSeen": "08-30-2019 06:06:10 UTC",
            "LastSeen": "08-30-2019 06:06:21 UTC",
            "ScanID": "7277ea43-df3d-4692-8615-8c15485249c5",
            "ThreatName": "N/A",
            "ThreatStatus": "N/A",
            "ThreatType": "N/A",
            "Type": "Scanned URL",
            "Value": "https://www.google.com/url?q=replacedlink/&source=gmail&...",
            "Verdict": "Benign"
        },
        {
            "Final": {
                "Type": "Final URL",
                "Value": "https://www.google.com/?gws_rd=ssl",
                "Verdict": "Benign"
            },
            "FirstSeen": "08-26-2019 17:29:38 UTC",
            "LastSeen": "08-26-2019 19:41:19 UTC",
            "ScanID": "48ae7b06-5915-4633-bc51-2cfaa0036742",
            "ThreatName": "N/A",
            "ThreatStatus": "N/A",
            "ThreatType": "N/A",
            "Type": "Scanned URL",
            "Value": "http://www.google.com/",
            "Verdict": "Benign"
        },
        {
            "Final": {
                "Type": "Final URL",
                "Value": "https://www.google.com/maps/place/2307",
                "Verdict": "Benign"
            },
            "FirstSeen": "10-01-2019 12:50:34 UTC",
            "LastSeen": "10-01-2019 12:50:47 UTC",
            "ScanID": "N/A",
            "ThreatName": "N/A",
            "ThreatStatus": "N/A",
            "ThreatType": "N/A",
            "Type": "Scanned URL",
            "Value": "http://www.google.com/maps/place/2307",
            "Verdict": "Benign"
        },
        {
            "Final": {
                "Type": "Final URL",
                "Value": "https://www.google.com/maps/place/2307+Watterson+Trail",
                "Verdict": "Benign"
            },
            "FirstSeen": "10-01-2019 12:50:12 UTC",
            "LastSeen": "10-01-2019 12:50:26 UTC",
            "ScanID": "N/A",
            "ThreatName": "N/A",
            "ThreatStatus": "N/A",
            "ThreatType": "N/A",
            "Type": "Scanned URL",
            "Value": "http://www.google.com/maps/place/2307+Watterson+Trail",
            "Verdict": "Benign"
        },
        {
            "Final": {
                "Type": "Final URL",
                "Value": "https://www.google.com/maps/place/2307&#43;Watterson&#43;Trail",
                "Verdict": "Benign"
            },
            "FirstSeen": "10-01-2019 12:50:11 UTC",
            "LastSeen": "10-01-2019 12:50:24 UTC",
            "ScanID": "N/A",
            "ThreatName": "N/A",
            "ThreatStatus": "N/A",
            "ThreatType": "N/A",
            "Type": "Scanned URL",
            "Value": "http://www.google.com/maps/place/2307&#43;Watterson&#43;Trail",
            "Verdict": "Benign"
        },
        {
            "Final": {
                "Type": "Final URL",
                "Value": "https://www.google.com/maps/place/2307&#43;Watterson&#43;Trail,&#43;Jeffersontown,&#43;KY&#43;40299/@38.2107207,-85.5607165,17z/data=!3m1!4b1!4m5!3m4!1s0x8869a1b57420f6d9:0xccc95b8f32dcfd4b!8m2!3d38.2107165!4d-85.5585225",
                "Verdict": "Benign"
            },
            "FirstSeen": "10-01-2019 12:49:44 UTC",
            "LastSeen": "10-01-2019 12:49:58 UTC",
            "ScanID": "N/A",
            "ThreatName": "N/A",
            "ThreatStatus": "N/A",
            "ThreatType": "N/A",
            "Type": "Scanned URL",
            "Value": "http://www.google.com/maps/place/2307&#43;Watterson&#43;Trail,&#43;Jeffersontown,&#43;KY&#43;40299/@38.2107207,-85.5607165,17z/data=!3m1!4b1!4m5!3m4!1s0x8869a1b57420f6d9:0xccc95b8f32dcfd4b!8m2!3d38.2107165!4d-85.5585225",
            "Verdict": "Benign"
        }
    ],
    "URL": [
        {
            "Data": "http://www.google.com/wasif"
        },
        {
            "Data": "http://www.google.com/abrar"
        },
        {
            "Data": "http://www.google.com/saadat"
        },
        {
            "Data": "https://www.google.com/"
        },
        {
            "Data": "https://www.google.com/url?q=replacedlink/&source=gmail&..."
        },
        {
            "Data": "http://www.google.com/"
        },
        {
            "Data": "https://www.google.com/?gws_rd=ssl"
        },
        {
            "Data": "http://www.google.com/maps/place/2307"
        },
        {
            "Data": "https://www.google.com/maps/place/2307"
        },
        {
            "Data": "http://www.google.com/maps/place/2307+Watterson+Trail"
        },
        {
            "Data": "https://www.google.com/maps/place/2307+Watterson+Trail"
        },
        {
            "Data": "http://www.google.com/maps/place/2307&#43;Watterson&#43;Trail"
        },
        {
            "Data": "https://www.google.com/maps/place/2307&#43;Watterson&#43;Trail"
        },
        {
            "Data": "http://www.google.com/maps/place/2307&#43;Watterson&#43;Trail,&#43;Jeffersontown,&#43;KY&#43;40299/@38.2107207,-85.5607165,17z/data=!3m1!4b1!4m5!3m4!1s0x8869a1b57420f6d9:0xccc95b8f32dcfd4b!8m2!3d38.2107165!4d-85.5585225"
        },
        {
            "Data": "https://www.google.com/maps/place/2307&#43;Watterson&#43;Trail,&#43;Jeffersontown,&#43;KY&#43;40299/@38.2107207,-85.5607165,17z/data=!3m1!4b1!4m5!3m4!1s0x8869a1b57420f6d9:0xccc95b8f32dcfd4b!8m2!3d38.2107165!4d-85.5585225"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>SlashNext Phishing Incident Response - Host URLs</h3>
<h5>host = www.google.com</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Value</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Verdict</strong></th>
      <th><strong>ScanID</strong></th>
      <th><strong>ThreatStatus</strong></th>
      <th><strong>ThreatName</strong></th>
      <th><strong>ThreatType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> http://www.google.com/wasif </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> 61fe7c96-88e3-440e-a56f-75834b734b06 </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 10-03-2019 08:24:04 UTC </td>
      <td> 10-03-2019 08:24:14 UTC </td>
    </tr>
    <tr>
      <td> http://www.google.com/abrar </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> 820275cd-c6de-46e9-b3a3-7cb072179bb4 </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 10-03-2019 08:22:36 UTC </td>
      <td> 10-03-2019 08:22:46 UTC </td>
    </tr>
    <tr>
      <td> http://www.google.com/saadat </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> 905cf63e-7761-4681-b314-4b8820f04c41 </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 10-03-2019 08:17:49 UTC </td>
      <td> 10-03-2019 08:18:00 UTC </td>
    </tr>
    <tr>
      <td> https://www.google.com/ </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> 4f1540b9-3517-4e6c-bca8-923acc3eed43 </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 08-27-2019 10:32:19 UTC </td>
      <td> 08-27-2019 12:34:52 UTC </td>
    </tr>
    <tr>
      <td> https://www.google.com/url?q=replacedlink/&source=gmail&... </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> 7277ea43-df3d-4692-8615-8c15485249c5 </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 08-30-2019 06:06:10 UTC </td>
      <td> 08-30-2019 06:06:21 UTC </td>
    </tr>
    <tr>
      <td> http://www.google.com/ </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> 48ae7b06-5915-4633-bc51-2cfaa0036742 </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 08-26-2019 17:29:38 UTC </td>
      <td> 08-26-2019 19:41:19 UTC </td>
    </tr>
    <tr>
      <td> --------> https://www.google.com/?gws_rd=ssl </td>
      <td> Final URL </td>
      <td> Benign </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
    <tr>
      <td> http://www.google.com/maps/place/2307 </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 10-01-2019 12:50:34 UTC </td>
      <td> 10-01-2019 12:50:47 UTC </td>
    </tr>
    <tr>
      <td> --------> https://www.google.com/maps/place/2307 </td>
      <td> Final URL </td>
      <td> Benign </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
    <tr>
      <td> http://www.google.com/maps/place/2307+Watterson+Trail </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 10-01-2019 12:50:12 UTC </td>
      <td> 10-01-2019 12:50:26 UTC </td>
    </tr>
    <tr>
      <td> --------> https://www.google.com/maps/place/2307+Watterson+Trail </td>
      <td> Final URL </td>
      <td> Benign </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
    <tr>
      <td> http://www.google.com/maps/place/2307&#43;Watterson&#43;Trail </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 10-01-2019 12:50:11 UTC </td>
      <td> 10-01-2019 12:50:24 UTC </td>
    </tr>
    <tr>
      <td> --------> https://www.google.com/maps/place/2307&#43;Watterson&#43;Trail </td>
      <td> Final URL </td>
      <td> Benign </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
    <tr>
      <td> http://www.google.com/maps/place/2307&#43;Watterson&#43;Trail,&#43;Jeffersontown,&#43;KY&#43;40299/@38.2107207,-85.5607165,17z/data=!3m1!4b1!4m5!3m4!1s0x8869a1b57420f6d9:0xccc95b8f32dcfd4b!8m2!3d38.2107165!4d-85.5585225 </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 10-01-2019 12:49:44 UTC </td>
      <td> 10-01-2019 12:49:58 UTC </td>
    </tr>
    <tr>
      <td> --------> https://www.google.com/maps/place/2307&#43;Watterson&#43;Trail,&#43;Jeffersontown,&#43;KY&#43;40299/@38.2107207,-85.5607165,17z/data=!3m1!4b1!4m5!3m4!1s0x8869a1b57420f6d9:0xccc95b8f32dcfd4b!8m2!3d38.2107165!4d-85.5585225 </td>
      <td> Final URL </td>
      <td> Benign </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
  </tbody>
</table>
</p>

<h3>7. slashnext-url-reputation</h3>
<hr>
<p>Queries the SlashNext Cloud database and retrieves the reputation of a url.</p>
<h5>Base Command</h5>
<p>
  <code>slashnext-url-reputation</code>
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
      <td>url</td>
      <td>The url to look up in the SlashNext Threat Intelligence database.</td>
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
      <td>DBotScore.Indicator</td>
      <td>string</td>
      <td>The indicator that was tested</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>string</td>
      <td>Indicator type</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>string</td>
      <td>Vendor used to calculate the score</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>number</td>
      <td>The actual score</td>
    </tr>
    <tr>
      <td>URL.Data</td>
      <td>string</td>
      <td>URL reported</td>
    </tr>
    <tr>
      <td>URL.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious URLs, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>URL.Malicious.Description</td>
      <td>string</td>
      <td>For malicious URLs, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Value</td>
      <td>string</td>
      <td>Final IoC value in case original IoC is a redirector to same domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Type</td>
      <td>string</td>
      <td>Type of the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Value</td>
      <td>string</td>
      <td>Landing IoC value in case original IoC is a redirector to different domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Type</td>
      <td>string</td>
      <td>Type of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.FirstSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.LastSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was last observed</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slashnext-url-reputation url=www.google.com</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": [
        {
            "Indicator": "http://www.google.com/",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/?gws_rd=ssl",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        }
    ],
    "SlashNext.URL": {
        "Final": {
            "Type": "Final URL",
            "Value": "https://www.google.com/?gws_rd=ssl",
            "Verdict": "Benign"
        },
        "FirstSeen": "08-26-2019 17:29:38 UTC",
        "LastSeen": "08-26-2019 19:41:19 UTC",
        "ThreatName": "N/A",
        "ThreatStatus": "N/A",
        "ThreatType": "N/A",
        "Type": "Scanned URL",
        "Value": "http://www.google.com/",
        "Verdict": "Benign"
    },
    "URL": [
        {
            "Data": "http://www.google.com/"
        },
        {
            "Data": "https://www.google.com/?gws_rd=ssl"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>SlashNext Phishing Incident Response - URL Reputation</h3>
<h5>url = http://www.google.com/</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Value</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Verdict</strong></th>
      <th><strong>ThreatStatus</strong></th>
      <th><strong>ThreatName</strong></th>
      <th><strong>ThreatType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> http://www.google.com/ </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 08-26-2019 17:29:38 UTC </td>
      <td> 08-26-2019 19:41:19 UTC </td>
    </tr>
    <tr>
      <td> --------> https://www.google.com/?gws_rd=ssl </td>
      <td> Final URL </td>
      <td> Benign </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
  </tbody>
</table>
</p>

<h3>8. slashnext-url-scan</h3>
<hr>
<p>Perform a real-time URL scan with SlashNext cloud-based SEER Engine. If the specified URL already exists in the cloud database, scan results will get returned immediately. If not, this command will submit a URL scan request and return with ‘check back later’ message along with a unique Scan ID. User can check results of this scan with ‘slashnext-scan-report’ command after 60 seconds or later using the retuned Scan ID</p>
<h5>Base Command</h5>
<p>
  <code>slashnext-url-scan</code>
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
      <td>url</td>
      <td>The URL that needs to be scanned.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>extended_info</td>
      <td>If extented_info is set ‘true’ the system along with URL reputation also downloads forensics data like screenshot, HTML and rendered text. If this parameter is not filled, the system will consider this as 'false'.</td>
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
      <td>DBotScore.Indicator</td>
      <td>string</td>
      <td>The indicator that was tested</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>string</td>
      <td>Indicator type</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>string</td>
      <td>Vendor used to calculate the score</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>number</td>
      <td>The actual score</td>
    </tr>
    <tr>
      <td>URL.Data</td>
      <td>string</td>
      <td>URL reported</td>
    </tr>
    <tr>
      <td>URL.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious URLs, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>URL.Malicious.Description</td>
      <td>string</td>
      <td>For malicious URLs, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ScanID</td>
      <td>string</td>
      <td>Scan ID to be used to get the IoC forensics data for further investigation</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Value</td>
      <td>string</td>
      <td>Final IoC value in case original IoC is a redirector to same domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Type</td>
      <td>string</td>
      <td>Type of the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Value</td>
      <td>string</td>
      <td>Landing IoC value in case original IoC is a redirector to different domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Type</td>
      <td>string</td>
      <td>Type of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ScanID</td>
      <td>string</td>
      <td>Scan ID to be used to get the landing IoC forensics data for further investigation</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.FirstSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.LastSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was last observed</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slashnext-url-scan url=www.google.com extednded_info=true</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": [
        {
            "Indicator": "http://www.google.com/",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/?gws_rd=ssl",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        }
    ],
    "SlashNext.URL": {
        "Final": {
            "Type": "Final URL",
            "Value": "https://www.google.com/?gws_rd=ssl",
            "Verdict": "Benign"
        },
        "FirstSeen": "08-26-2019 17:29:38 UTC",
        "LastSeen": "08-26-2019 19:41:19 UTC",
        "ScanID": "48ae7b06-5915-4633-bc51-2cfaa0036742",
        "ThreatName": "N/A",
        "ThreatStatus": "N/A",
        "ThreatType": "N/A",
        "Type": "Scanned URL",
        "Value": "http://www.google.com/",
        "Verdict": "Benign"
    },
    "URL": [
        {
            "Data": "http://www.google.com/"
        },
        {
            "Data": "https://www.google.com/?gws_rd=ssl"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>SlashNext Phishing Incident Response - URL Scan</h3>
<h5>url = http://www.google.com/</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Value</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Verdict</strong></th>
      <th><strong>ScanID</strong></th>
      <th><strong>ThreatStatus</strong></th>
      <th><strong>ThreatName</strong></th>
      <th><strong>ThreatType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> http://www.google.com/ </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> 48ae7b06-5915-4633-bc51-2cfaa0036742 </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 08-26-2019 17:29:38 UTC </td>
      <td> 08-26-2019 19:41:19 UTC </td>
    </tr>
    <tr>
      <td> --------> https://www.google.com/?gws_rd=ssl </td>
      <td> Final URL </td>
      <td> Benign </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
  </tbody>
</table>
</p>

<h3>9. slashnext-url-scan-sync</h3>
<hr>
<p>Perform a real-time URL scan with SlashNext cloud-based SEER Engine in a blocking mode. If the specified URL already exists in the cloud database, scan result will get returned immediately. If not, this command will submit a URL scan request and wait for the scan to finish. The scan may take up to 60 seconds to finish.</p>
<h5>Base Command</h5>
<p>
  <code>slashnext-url-scan-sync</code>
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
      <td>url</td>
      <td>The URL that needs to be scanned.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>timeout</td>
      <td>A timeout value in seconds. If the system is unable to complete a scan within the specified timeout, a timeout error will be returned. User may try again with a different timeout. If no timeout value is specified, a default value of 60 seconds will be used.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>extended_info</td>
      <td>If extented_info is set ‘true’ the system along with URL reputation also downloads forensics data like screenshot, HTML and rendered text. If this parameter is not filled, the system will consider this as 'false'.</td>
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
      <td>DBotScore.Indicator</td>
      <td>string</td>
      <td>The indicator that was tested</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>string</td>
      <td>Indicator type</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>string</td>
      <td>Vendor used to calculate the score</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>number</td>
      <td>The actual score</td>
    </tr>
    <tr>
      <td>URL.Data</td>
      <td>string</td>
      <td>URL reported</td>
    </tr>
    <tr>
      <td>URL.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious URLs, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>URL.Malicious.Description</td>
      <td>string</td>
      <td>For malicious URLs, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ScanID</td>
      <td>string</td>
      <td>Scan ID to be used to get the IoC forensics data for further investigation</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Value</td>
      <td>string</td>
      <td>Final IoC value in case original IoC is a redirector to same domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Type</td>
      <td>string</td>
      <td>Type of the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Value</td>
      <td>string</td>
      <td>Landing IoC value in case original IoC is a redirector to different domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Type</td>
      <td>string</td>
      <td>Type of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ScanID</td>
      <td>string</td>
      <td>Scan ID to be used to get the landing IoC forensics data for further investigation</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.FirstSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.LastSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was last observed</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slashnext-url-scan-sync url=www.google.com extednded_info=true</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": [
        {
            "Indicator": "http://www.google.com/",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/?gws_rd=ssl",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        }
    ],
    "SlashNext.URL": {
        "Final": {
            "Type": "Final URL",
            "Value": "https://www.google.com/?gws_rd=ssl",
            "Verdict": "Benign"
        },
        "FirstSeen": "08-26-2019 17:29:38 UTC",
        "LastSeen": "08-26-2019 19:41:19 UTC",
        "ScanID": "48ae7b06-5915-4633-bc51-2cfaa0036742",
        "ThreatName": "N/A",
        "ThreatStatus": "N/A",
        "ThreatType": "N/A",
        "Type": "Scanned URL",
        "Value": "http://www.google.com/",
        "Verdict": "Benign"
    },
    "URL": [
        {
            "Data": "http://www.google.com/"
        },
        {
            "Data": "https://www.google.com/?gws_rd=ssl"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>SlashNext Phishing Incident Response - URL Scan Sync</h3>
<h5>url = http://www.google.com/</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Value</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Verdict</strong></th>
      <th><strong>ScanID</strong></th>
      <th><strong>ThreatStatus</strong></th>
      <th><strong>ThreatName</strong></th>
      <th><strong>ThreatType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> http://www.google.com/ </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> 48ae7b06-5915-4633-bc51-2cfaa0036742 </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 08-26-2019 17:29:38 UTC </td>
      <td> 08-26-2019 19:41:19 UTC </td>
    </tr>
    <tr>
      <td> --------> https://www.google.com/?gws_rd=ssl </td>
      <td> Final URL </td>
      <td> Benign </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
  </tbody>
</table>
</p>

<h3>10. slashnext-scan-report</h3>
<hr>
<p>Retrieve URL scan results against a previous Scan request. If the scan is finished, result will be retuned immediately; otherwise a ‘check back later’ message will be returned.</p>
<h5>Base Command</h5>
<p>
  <code>slashnext-scan-report</code>
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
      <td>scanid</td>
      <td>Scan ID returned by an earlier call to ‘slashnext-url-scan’ or ‘slashnext-url-scan-sync’ commands.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>extended_info</td>
      <td>If extented_info is set ‘true’ the system along with URL reputation also downloads forensics data like screenshot, HTML and rendered text. If this parameter is not filled, the system will consider this as 'false'.</td>
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
      <td>DBotScore.Indicator</td>
      <td>string</td>
      <td>The indicator that was tested</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>string</td>
      <td>Indicator type</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>string</td>
      <td>Vendor used to calculate the score</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>number</td>
      <td>The actual score</td>
    </tr>
    <tr>
      <td>URL.Data</td>
      <td>string</td>
      <td>URL reported</td>
    </tr>
    <tr>
      <td>URL.Malicious.Vendor</td>
      <td>string</td>
      <td>For malicious URLs, the vendor that made the decision</td>
    </tr>
    <tr>
      <td>URL.Malicious.Description</td>
      <td>string</td>
      <td>For malicious URLs, the reason that the vendor made the decision</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Value</td>
      <td>string</td>
      <td>Value of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Type</td>
      <td>string</td>
      <td>Type of the Indicator of Compromise (IoC)</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ScanID</td>
      <td>string</td>
      <td>Scan ID to be used to get the IoC forensics data for further investigation</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.FirstSeen</td>
      <td>date</td>
      <td>Time when the IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.LastSeen</td>
      <td>date</td>
      <td>Time when the IoC was last observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Value</td>
      <td>string</td>
      <td>Final IoC value in case original IoC is a redirector to same domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Type</td>
      <td>string</td>
      <td>Type of the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Final.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the final IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Value</td>
      <td>string</td>
      <td>Landing IoC value in case original IoC is a redirector to different domain</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Type</td>
      <td>string</td>
      <td>Type of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ScanID</td>
      <td>string</td>
      <td>Scan ID to be used to get the landing IoC forensics data for further investigation</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.Verdict</td>
      <td>string</td>
      <td>SlashNext Phishing Incident Response verdict on the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatStatus</td>
      <td>string</td>
      <td>Threat status of the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatName</td>
      <td>string</td>
      <td>Name of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.ThreatType</td>
      <td>string</td>
      <td>Type of the threat posed by the landing IoC</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.FirstSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was first observed</td>
    </tr>
    <tr>
      <td>SlashNext.URL.Landing.LastSeen</td>
      <td>date</td>
      <td>Time when the landing IoC was last observed</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slashnext-scan-report scanid=48ae7b06-5915-4633-bc51-2cfaa0036742 extednded_info=true</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": [
        {
            "Indicator": "http://www.google.com/",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        },
        {
            "Indicator": "https://www.google.com/?gws_rd=ssl",
            "Score": 1,
            "Type": "url",
            "Vendor": "SlashNext Phishing Incident Response"
        }
    ],
    "SlashNext.URL": {
        "Final": {
            "Type": "Final URL",
            "Value": "https://www.google.com/?gws_rd=ssl",
            "Verdict": "Benign"
        },
        "FirstSeen": "08-26-2019 17:29:38 UTC",
        "LastSeen": "08-26-2019 19:41:19 UTC",
        "ScanID": "48ae7b06-5915-4633-bc51-2cfaa0036742",
        "ThreatName": "N/A",
        "ThreatStatus": "N/A",
        "ThreatType": "N/A",
        "Type": "Scanned URL",
        "Value": "http://www.google.com/",
        "Verdict": "Benign"
    },
    "URL": [
        {
            "Data": "http://www.google.com/"
        },
        {
            "Data": "https://www.google.com/?gws_rd=ssl"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>SlashNext Phishing Incident Response - Scan Report</h3>
<h5>url = http://www.google.com/</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Value</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Verdict</strong></th>
      <th><strong>ScanID</strong></th>
      <th><strong>ThreatStatus</strong></th>
      <th><strong>ThreatName</strong></th>
      <th><strong>ThreatType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> http://www.google.com/ </td>
      <td> Scanned URL </td>
      <td> Benign </td>
      <td> 48ae7b06-5915-4633-bc51-2cfaa0036742 </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> N/A </td>
      <td> 08-26-2019 17:29:38 UTC </td>
      <td> 08-26-2019 19:41:19 UTC </td>
    </tr>
    <tr>
      <td> --------> https://www.google.com/?gws_rd=ssl </td>
      <td> Final URL </td>
      <td> Benign </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
  </tbody>
</table>
</p>

<h3>11. slashnext-download-screenshot</h3>
<hr>
<p>Download webpage screenshot against a previous URL Scan request.</p>
<h5>Base Command</h5>
<p>
  <code>slashnext-download-screenshot</code>
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
      <td>scanid</td>
      <td>Scan ID returned by an earlier call to ‘slashnext-url-scan’ or ‘slashnext-url-scan-sync’ command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>resolution</td>
      <td>Resolution of the webpage screenshot. Currently only 'high' and 'medium' resolutions are supported.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slashnext-download-screenshot scanid=48ae7b06-5915-4633-bc51-2cfaa0036742</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Forensics: Webpage Screenshot for URL Scan ID = 48ae7b06-5915-4633-bc51-2cfaa0036742
</p>
</p>

<h3>12. slashnext-download-html</h3>
<hr>
<p>Download webpage HTML against a previous URL Scan request.</p>
<h5>Base Command</h5>
<p>
  <code>slashnext-download-html</code>
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
      <td>scanid</td>
      <td>Scan ID returned by an earlier call to ‘slashnext-url-scan’ or ‘slashnext-url-scan-sync’ command.</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slashnext-download-html scanid=48ae7b06-5915-4633-bc51-2cfaa0036742</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Forensics: Webpage HTML for URL Scan ID = 48ae7b06-5915-4633-bc51-2cfaa0036742
</p>
</p>

<h3>13. slashnext-download-text</h3>
<hr>
<p>Download  webpage text against a previous URL Scan request.</p>
<h5>Base Command</h5>
<p>
  <code>slashnext-download-text</code>
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
      <td>scanid</td>
      <td>Scan ID returned by an earlier call to ‘slashnext-url-scan’ or ‘slashnext-url-scan-sync’ command.</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slashnext-download-text scanid=48ae7b06-5915-4633-bc51-2cfaa0036742</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Forensics: Webpage Rendered Text for URL Scan ID = 48ae7b06-5915-4633-bc51-2cfaa0036742
</p>
</p>

<h3>14. slashnext-api-quota</h3>
<hr>
<p>Queries the SlashNext cloud database and retrieves the details of API quota.</p>
<h5>Base Command</h5>
<p>
  <code>slashnext-api-quota</code>
</p>

<h5>Input</h5>
No input parameter is required.
<p>&nbsp;</p>
<h5>Context Output</h5>
<pre>
{
    "SlashNext.Quota": {
        "LicensedQuota": "Unlimited",
        "RemainingQuota": "Unlimited",
        "ExpirationDate": "2020-12-01",
        "IsExpired": false
    }
}
</pre>
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slashnext-api-quota</code>
</p>
<h5>Human Readable Output</h5>
<p>
<h3>SlashNext Phishing Incident Response - API Quota</h3>
<h5>Note: Your annual API quota will be reset to zero, once either the limit is reached or upon quota expiration date indicated above.</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>LicensedQuota</strong></th>
      <th><strong>RemainingQuota</strong></th>
      <th><strong>ExpirationDate</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> Unlimited </td>
      <td> Unlimited </td>
      <td> 2020-12-01 </td>
    </tr>
  </tbody>
</table>
</p>

<h2>Additional Information</h2><h2>Known Limitations</h2><h2>Troubleshooting</h2>

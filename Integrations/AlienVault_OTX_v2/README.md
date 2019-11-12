<h1>AlienVault OTX integration</h1>
<p>
  Query Indicators of Compromise in AlienVault OTX.
  This integration was integrated and tested with version 1.0 of AlienVault OTX v2
</p>
<h2>Use Cases</h2>
<ul>
  <li>IPv4/v6, domain, hostname, file hashes, dns enrichment</li>
  <li>Pulses searches</li>
</ul> 
<h2>Configure AlienVault OTX v2 on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for AlienVault OTX v2.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Server address</strong></li>
   <li><strong>API Token</strong></li>
   <li><strong>Indicator Threshold. The minimum number of pulses to consider the indicator as malicious.</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Use system proxy settings</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>ip</li>
  <li>domain</li>
  <li>alienvault-search-ipv6</li>
  <li>alienvault-search-hostname</li>
  <li>file</li>
  <li>alienvault-search-cve</li>
  <li>alienvault-get-related-urls-by-indicator</li>
  <li>alienvault-get-related-hashes-by-indicator</li>
  <li>alienvault-get-passive-dns-data-by-indicator</li>
  <li>alienvault-search-pulses</li>
  <li>alienvault-get-pulse-details</li>
  <li>url: url</li>
</ol>
<h3>1. ip</h3>
<hr>
<p>Queries an IP address in AlienVault OTX.</p>
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
      <td>The IP address to query.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>threshold</td>
      <td>If the number of pulses is bigger than the threshold, the IP address is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings.</td>
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
      <td>IP.Address</td>
      <td>String</td>
      <td>The address of the IP.</td>
    </tr>
    <tr>
      <td>IP.ASN</td>
      <td>String</td>
      <td>The autonomous system name for the IP address. For example, "AS8948".</td>
    </tr>
    <tr>
      <td>IP.Geo.Country</td>
      <td>String</td>
      <td>The country where the IP address is located.</td>
    </tr>
    <tr>
      <td>IP.Geo.Location</td>
      <td>String</td>
      <td>The geolocation where the IP address is located, in the format: latitude:longitude.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.IP.Reputation</td>
      <td>String</td>
      <td>The reputation of the IP address.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.IP.IP</td>
      <td>String</td>
      <td>IP address</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>Number</td>
      <td>The actual score.</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>String</td>
      <td>The type of indicator.</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>String</td>
      <td>The AlienVault OTX vendor.</td>
    </tr>
    <tr>
      <td>DBotScore.Indicator</td>
      <td>String</td>
      <td>The indicator that was tested.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!ip ip=8.8.8.8"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AlienVaultOTX": {
        "IP": {
            "IP": "8.8.8.8",
            "Reputation": 0
        }
    },
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 3,
        "Type": "IPv4",
        "Vendor": "AlienVault OTX v2"
    },
    "IP": {
        "ASN": "AS15169 Google LLC",
        "Address": "8.8.8.8",
        "Geo": {
            "Country": "US",
            "Location": "37.751,-97.822"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - Results for IPv4 query</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ASN</strong></th>
      <th><strong>Address</strong></th>
      <th><strong>Geo</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> AS15169 Google LLC </td>
      <td> 8.8.8.8 </td>
      <td> Country: US<br>Location: 37.751,-97.822 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>2. domain</h3>
<hr>
<p>Queries a domain in AlienVault OTX.</p>
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
      <td>The domain to query.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>threshold</td>
      <td>If the number of pulses is bigger than the threshold, the domain is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings.</td>
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
      <td>Domain.Name</td>
      <td>String</td>
      <td>The domain name. For example, "google.com".</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Domain.Alexa</td>
      <td>String</td>
      <td>Alexa URL for the domain data.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Domain.Whois</td>
      <td>String</td>
      <td>Whois URL for the domain data.</td>
    </tr>
    <tr>
      <td>DBotScore.Indicator</td>
      <td>String</td>
      <td>The indicator that was tested.</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>Number</td>
      <td>The actual score.</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>String</td>
      <td>The type of indicator.</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>String</td>
      <td>The AlienVault OTX vendor.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!domain domain=google.com"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AlienVaultOTX": {
      "Domain": {
        "Alexa": "http://www.alexa.com/siteinfo/google.com",
        "Name": "google.com",
        "Whois": "http://whois.domaintools.com/google.com"
      }
    },
    "DBotScore": {
        "Indicator": "google.com",
        "Score": 3,
        "Type": "domain",
        "Vendor": "AlienVault OTX v2"
    },
    "Domain": {
        "Name": "google.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - Results for Domain query</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Alexa</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Whois</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> http://www.alexa.com/siteinfo/google.com </td>
      <td> google.com </td>
      <td> http://whois.domaintools.com/google.com </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>3. alienvault-search-ipv6</h3>
<hr>
<p>Queries IPv6 in AlienVault OTX.</p>
<h5>Base Command</h5>
<p>
  <code>alienvault-search-ipv6</code>
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
      <td>The IP address to query.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>threshold</td>
      <td>If the number of pulses is bigger than the threshold, the IP address is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings.</td>
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
      <td>IP.Address</td>
      <td>String</td>
      <td>The IP address.</td>
    </tr>
    <tr>
      <td>IP.ASN</td>
      <td>String</td>
      <td>The autonomous system name for the IP address. For example, "AS8948".</td>
    </tr>
    <tr>
      <td>IP.AlienVaultOTX.Reputation</td>
      <td>String</td>
      <td>The IP reputation in AlienVault OTX.</td>
    </tr>
    <tr>
      <td>DBotScore.Indicator</td>
      <td>String</td>
      <td>The indicator that was tested.</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>Number</td>
      <td>The actual score.</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>String</td>
      <td>The type of the indicator.</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>String</td>
      <td>The AlienVault OTX vendor.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!alienvault-search-ipv6 ip=2001:4860:4860::8888</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AlienVaultOTX": {
        "IP": {
            "IP": "2001:4860:4860::8888",
            "Reputation": 0
        }
    },
    "DBotScore": {
        "Indicator": "2001:4860:4860::8888",
        "Score": 0,
        "Type": "IPv6",
        "Vendor": "AlienVault OTX v2"
    },
    "IP": {
        "ASN": "AS15169 Google LLC",
        "Address": "2001:4860:4860::8888",
        "Geo": {
            "Country": "US",
            "Location": "37.751,-97.822"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - Results for IPv6 query</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ASN</strong></th>
      <th><strong>Address</strong></th>
      <th><strong>Geo</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> AS15169 Google LLC </td>
      <td> 2001:4860:4860::8888 </td>
      <td> Country: US<br>Location: 37.751,-97.822 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>4. alienvault-search-hostname</h3>
<hr>
<p>Searches for a host name in AlienVault OTX.</p>
<h5>Base Command</h5>
<p>
  <code>alienvault-search-hostname</code>
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
      <td>hostname</td>
      <td>The host name to query.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>threshold</td>
      <td>If the number of pulses is bigger than the threshold, the host name is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings.</td>
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
      <td>Endpoint.Hostname</td>
      <td>String</td>
      <td>The hostname that is mapped to the endpoint.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Endpoint.Hostname</td>
      <td>String</td>
      <td>The hostname that is mapped to the endpoint.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Endpoint.Alexa</td>
      <td>String</td>
      <td>The Alexa URL endpoint.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Endpoint.Whois</td>
      <td>String</td>
      <td>The Whois URL endpoint.</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>Number</td>
      <td>The actual score.</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>String</td>
      <td>The type of the indicator.</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>String</td>
      <td>The AlienVault OTX vendor.</td>
    </tr>
    <tr>
      <td>DBotScore.Indicator</td>
      <td>String</td>
      <td>The indicator that was tested.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!alienvault-search-hostname hostname=demisto.com</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AlienVaultOTX": {
        "Endpoint": {
          "Alexa": "http://www.alexa.com/siteinfo/demisto.com",
          "Hostname": "demisto.com",
          "Whois": "http://whois.domaintools.com/demisto.com"
        } 
    },
    "DBotScore": {
        "Indicator": "demisto.com",
        "Score": 0,
        "Type": "hostname",
        "Vendor": "AlienVault OTX v2"
    },
    "Endpoint": {
        "Hostname": "demisto.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - Results for Hostname query</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Alexa</strong></th>
      <th><strong>Hostname</strong></th>
      <th><strong>Whois</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> http://www.alexa.com/siteinfo/demisto.com </td>
      <td> demisto.com </td>
      <td> http://whois.domaintools.com/demisto.com </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>5. file</h3>
<hr>
<p>Query a file in AlienVault OTX.</p>
<h5>Base Command</h5>
<p>
  <code>file</code>
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
      <td>file</td>
      <td>The file hash to query.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>threshold</td>
      <td>If the number of pulses is bigger than the threshold, the file is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings.</td>
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
      <td>File.MD5</td>
      <td>String</td>
      <td>The MD5 hash of the file.</td>
    </tr>
    <tr>
      <td>File.SHA1</td>
      <td>String</td>
      <td>The SHA1 hash of the file.</td>
    </tr>
    <tr>
      <td>File.SHA256</td>
      <td>String</td>
      <td>The SHA256 hash of the file.</td>
    </tr>
    <tr>
      <td>File.Malicious.PulseIDs</td>
      <td>String</td>
      <td>IDs of pulses which are marked as malicious.</td>
    </tr>
    <tr>
      <td>File.Type</td>
      <td>String</td>
      <td>The file type, as determined by libmagic (same as displayed in file entries).</td>
    </tr>
    <tr>
      <td>File.Size</td>
      <td>Number</td>
      <td>The size of the file in bytes.</td>
    </tr>
    <tr>
      <td>File.SSDeep</td>
      <td>String</td>
      <td>The SSDeep hash of the file (same as displayed in file entries).</td>
    </tr>
    <tr>
      <td>DBotScore.Indicator</td>
      <td>String</td>
      <td>The indicator that was tested.</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>Number</td>
      <td>The actual score.</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>String</td>
      <td>The type of the indicator.</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>String</td>
      <td>The AlienVault OTX vendor.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!file file=6c5360d41bd2b14b1565f5b18e5c203cf512e493"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": {
        "Indicator": "6c5360d41bd2b14b1565f5b18e5c203cf512e493",
        "Score": 0,
        "Type": "file",
        "Vendor": "AlienVault OTX v2"
    },
    "File": {
        "MD5": "2eb14920c75d5e73264f77cfa273ad2c",
        "Malicious": {
            "PulseIDs": []
        },
        "SHA1": "6c5360d41bd2b14b1565f5b18e5c203cf512e493",
        "SHA256": "4cf9322c49adebf63311a599dc225bbcbf16a253eca59bbe1a02e4ae1d824412",
        "SSDeep": "",
        "Size": "437760",
        "Type": "PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - Results for File hash query</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>MD5</strong></th>
      <th><strong>Malicious</strong></th>
      <th><strong>SHA1</strong></th>
      <th><strong>SHA256</strong></th>
      <th><strong>SSDeep</strong></th>
      <th><strong>Size</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 2eb14920c75d5e73264f77cfa273ad2c </td>
      <td> PulseIDs:  </td>
      <td> 6c5360d41bd2b14b1565f5b18e5c203cf512e493 </td>
      <td> 4cf9322c49adebf63311a599dc225bbcbf16a253eca59bbe1a02e4ae1d824412 </td>
      <td>  </td>
      <td> 437760 </td>
      <td> PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>6. alienvault-search-cve</h3>
<hr>
<p>Query Common Vulnerabilities and Exposures (CVE) in AlienVault OTX.</p>
<h5>Base Command</h5>
<p>
  <code>alienvault-search-cve</code>
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
      <td>cve_id</td>
      <td>The CVE to query.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>threshold</td>
      <td>If the number of pulses is bigger than the threshold, the CVE is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings.</td>
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
      <td>CVE.ID</td>
      <td>String</td>
      <td>The ID of the CVE. For example, "CVE-2015-1653".</td>
    </tr>
    <tr>
      <td>CVE.CVSS</td>
      <td>String</td>
      <td>The CVSS of the CVE. For example, "10.0".</td>
    </tr>
    <tr>
      <td>CVE.Published</td>
      <td>String</td>
      <td>The timestamp of when the CVE was published.</td>
    </tr>
    <tr>
      <td>CVE.Modified</td>
      <td>String</td>
      <td>The timestamp of when the CVE was last modified.</td>
    </tr>
    <tr>
      <td>CVE.Description</td>
      <td>String</td>
      <td>A description of the CVE.</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>Number</td>
      <td>The actual score.</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>String</td>
      <td>The type of indicator.</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>String</td>
      <td>The AlienVault OTX vendor.</td>
    </tr>
    <tr>
      <td>DBotScore.Indicator</td>
      <td>String</td>
      <td>The indicator that was tested.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!alienvault-search-cve cve_id=CVE-2014-0160</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "CVE": {
        "CVSS": "5.0",
        "Description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.",
        "ID": "CVE-2014-0160",
        "Modified": "2019-10-09T19:09:21",
        "Published": "2014-04-07T18:55:03"
    },
    "DBotScore": {
        "Indicator": "CVE-2014-0160",
        "Score": 3,
        "Type": "cve",
        "Vendor": "AlienVault OTX v2"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - Results for Hostname query</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>CVSS</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>ID</strong></th>
      <th><strong>Modified</strong></th>
      <th><strong>Published</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 5.0 </td>
      <td> The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug. </td>
      <td> CVE-2014-0160 </td>
      <td> 2019-10-09T19:09:21 </td>
      <td> 2014-04-07T18:55:03 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>7. alienvault-get-related-urls-by-indicator</h3>
<hr>
<p>Returns related URLs by indicator.</p>
<h5>Base Command</h5>
<p>
  <code>alienvault-get-related-urls-by-indicator</code>
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
      <td>indicator_type</td>
      <td>The type of the indicator. Can be: "IPv4", "IPv6", "domain", "hostname", or "url".</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>indicator</td>
      <td>The indicator for which to search related URLs.</td>
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
      <td>AlienVaultOTX.URL.Data</td>
      <td>Unknown</td>
      <td>The path of the related URLs.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!alienvault-get-related-urls-by-indicator indicator=8.8.8.8 indicator_type=IPv4</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AlienVaultOTX": {
      "URL": [
          {
              "Data": "http://8.8.8.8/w/cohernece.txt"
          },
          {
              "Data": "https://dns.google.com/resolve?name=apv3.stel.com&type=ANY&random_padding=HUmzJ9Da0EHn5FZ7yfdbqJOhiVBKnWl5DjWYk4Ba4ooy3vVFHsQmu1hM5BYEgFSKmUcfu1mcd0sBv10gOvN09oERfhQG2da2sJBpPVpk6rR2AmIxzO7FQ"
          },
          {
              "Data": "http://8.8.8.8/siteepres/horatrtbdg.asp"
          },
          {
              "Data": "https://dns.google.com/experimental?ct=application%2Fdns-udpwireformat&dns"
          },
          {
              "Data": "https://dns.google/dns"
          },
          {
              "Data": "https://dns.google.com/resolve?name=apv2.stel.com&type=ANY&random_padding=FKWsRuGcTpuYcyBx3LEJVC2dx25ihCICFP303ZhUndPC3DwfcCqp2jpO"
          },
          {
              "Data": "https://tagnet.app/itlikf/login.php?l%3D_JeHFUq_VJOXK0QWHtoGYDw1774256418%26fid.13InboxLight.aspxn.1774256418%26fid.125289964252813InboxLight99642_Product-userid%26userid%3D"
          },
          {
              "Data": "http://8.8.8.8/XmWLPDQ2M"
          },
          {
              "Data": "https://paulvmoreau.github.io/BeltFedNPCs"
          }
      ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - Related url list to queried indicator</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Data</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> https://8.8.8.8/x8me1s </td>
    </tr>
    <tr>
      <td> http://8.8.8.8/w/cohernece.txt </td>
    </tr>
    <tr>
      <td> https://dns.google.com/resolve?name=apv3.stel.com&type=ANY&random_padding=HUmzJ9Da0EHn5FZ7yfdbqJOhiVBKnWl5DjWYk4Ba4ooy3vVFHsQmu1hM5BYEgFSKmUcfu1mcd0sBv10gOvN09oERfhQG2da2sJBpPVpk6rR2AmIxzO7FQ </td>
    </tr>
    <tr>
      <td> http://8.8.8.8/siteepres/horatrtbdg.asp </td>
    </tr>
    <tr>
      <td> https://dns.google.com/experimental?ct=application%2Fdns-udpwireformat&dns </td>
    </tr>
    <tr>
      <td> https://dns.google/dns </td>
    </tr>
    <tr>
      <td> https://dns.google.com/resolve?name=apv2.stel.com&type=ANY&random_padding=FKWsRuGcTpuYcyBx3LEJVC2dx25ihCICFP303ZhUndPC3DwfcCqp2jpO </td>
    </tr>
    <tr>
      <td> https://tagnet.app/itlikf/login.php?l%3D_JeHFUq_VJOXK0QWHtoGYDw1774256418%26fid.13InboxLight.aspxn.1774256418%26fid.125289964252813InboxLight99642_Product-userid%26userid%3D </td>
    </tr>
    <tr>
      <td> http://8.8.8.8/XmWLPDQ2M </td>
    </tr>
    <tr>
      <td> https://paulvmoreau.github.io/BeltFedNPCs </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>8. alienvault-get-related-hashes-by-indicator</h3>
<hr>
<p>Returns related hashes by indicator.</p>
<h5>Base Command</h5>
<p>
  <code>alienvault-get-related-hashes-by-indicator</code>
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
      <td>indicator</td>
      <td>The indicator for which to search for related hashes.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>indicator_type</td>
      <td>The type of the indicator. Can be: "IPv4", "IPv6", "domain", or "hostname".</td>
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
      <td>AlienVaultOTX.File.Hash</td>
      <td>Unknown</td>
      <td>The path of the url.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!alienvault-get-related-hashes-by-indicator indicator=8.8.8.8 indicator_type=IPv4</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AlienVaultOTX.File": [
        {
            "Hash": "ffc2595aefa80b61621023252b5f0ccb22b6e31d7f1640913cd8ff74ddbd8b41"
        },
        {
            "Hash": "0b4d4a7c35a185680bc5102bdd98218297e2cdf0a552bde10e377345f3622c1c"
        },
        {
            "Hash": "d8b8a5c941b6a1c3cb58f7e59489b2554ed14e6c6655d1fbf6852e45404b7516"
        },
        {
            "Hash": "b3d8adc185834ab858ebf55082828cb9fc1170bbe8de222821d225a6056ff5dc"
        },
        {
            "Hash": "e43cf3f5fa5e14972ba3f159dee6e98330bd19dccc1267cfc91b1000aef975d9"
        },
        {
            "Hash": "9e11b1e769da3c8059345b36c62b4a857845bd7e14c7c14af2945ce26570d91f"
        },
        {
            "Hash": "ae695ce9b8ff4bb831721a8c60377c1757d6d4fe579640b54f3c7f62b175f506"
        },
        {
            "Hash": "093bde5d50daba59bfe68b31251cf2c39353bdfe8ad510284935ca027f269637"
        },
        {
            "Hash": "438b531ba399feb19ed7bf73657d3de6996e001ee5054c04af6b2943e41b402e"
        },
        {
            "Hash": "5019a6b3ec69eae63f716b1df74434bf66f090a6c75a594e2392c7a22f1698cc"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - Related malware list to queried indicator</h3>
<p>
**No entries.**
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>9. alienvault-get-passive-dns-data-by-indicator</h3>
<hr>
<p>Returns passive DNS records by indicator.</p>
<h5>Base Command</h5>
<p>
  <code>alienvault-get-passive-dns-data-by-indicator</code>
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
      <td>indicator_type</td>
      <td>The type of the indicator. Can be: "IPv4", "IPv6", "domain", or "hostname".</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>indicator</td>
      <td>The indicator for which to search URLs.</td>
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
      <td>AlienVaultOTX.PassiveDNS.Hostname</td>
      <td>String</td>
      <td>The domain value.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.PassiveDNS.IP</td>
      <td>String</td>
      <td>The IP passive DNS.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.PassiveDNS.Domain</td>
      <td>String</td>
      <td>The domain value.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.PassiveDNS.Type</td>
      <td>String</td>
      <td>The asset type.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.PassiveDNS.FirstSeen</td>
      <td>Date</td>
      <td>The date first seen.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.PassiveDNS.LastSeen</td>
      <td>Date</td>
      <td>The date last seen.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!alienvault-get-passive-dns-data-by-indicator indicator=8.8.8.8 indicator_type=IPv4</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AlienVaultOTX":
      "PassiveDNS": [
        {
            "FirstSeen": "2019-10-29T23:41:54+00:00",
            "Hostname": "bjnn.com.cn",
            "IP": "8.8.8.8",
            "LastSeen": "2019-10-29T23:41:54+00:00",
            "Type": "hostname"
        },
        {
            "FirstSeen": "2019-10-29T17:01:00+00:00",
            "Hostname": "api.cloudapps-sand.dhcs.ca.gov",
            "IP": "8.8.8.8",
            "LastSeen": "2019-10-29T17:01:00+00:00",
            "Type": "hostname"
        },
        {
            "FirstSeen": "2019-10-29T13:21:44+00:00",
            "Hostname": "1",
            "IP": "8.8.8.8",
            "LastSeen": "2019-10-29T13:21:46+00:00",
            "Type": "domain"
        },
        {
            "FirstSeen": "2019-10-29T04:10:19+00:00",
            "Hostname": "ronssr.xyz",
            "IP": "8.8.8.8",
            "LastSeen": "2019-10-29T04:10:19+00:00",
            "Type": "domain"
        },
        {
            "FirstSeen": "2019-10-29T01:56:59+00:00",
            "Hostname": "true.nxtv.cn",
            "IP": "8.8.8.8",
            "LastSeen": "2019-10-29T01:56:59+00:00",
            "Type": "hostname"
        },
        {
            "FirstSeen": "2019-10-28T04:57:51+00:00",
            "Hostname": "furymice.com",
            "IP": "8.8.8.8",
            "LastSeen": "2019-10-28T04:57:51+00:00",
            "Type": "domain"
        },
        {
            "FirstSeen": "2019-10-27T23:25:58+00:00",
            "Hostname": "diogroup.vn",
            "IP": "8.8.8.8",
            "LastSeen": "2019-10-27T23:25:58+00:00",
            "Type": "domain"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - Related passive dns list to queried indicator</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>FirstSeen</strong></th>
      <th><strong>Hostname</strong></th>
      <th><strong>IP</strong></th>
      <th><strong>LastSeen</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 2019-10-29T23:41:54+00:00 </td>
      <td> bjnn.com.cn </td>
      <td> 8.8.8.8 </td>
      <td> 2019-10-29T23:41:54+00:00 </td>
      <td> hostname </td>
    </tr>
    <tr>
      <td> 2019-10-29T17:01:00+00:00 </td>
      <td> api.cloudapps-sand.dhcs.ca.gov </td>
      <td> 8.8.8.8 </td>
      <td> 2019-10-29T17:01:00+00:00 </td>
      <td> hostname </td>
    </tr>
    <tr>
      <td> 2019-10-29T13:21:44+00:00 </td>
      <td> 2</td>
      <td> 8.8.8.8 </td>
      <td> 2019-10-29T13:21:46+00:00 </td>
      <td> domain </td>
    </tr>
    <tr>
      <td> 2019-10-29T04:10:19+00:00 </td>
      <td> ronssr.xyz </td>
      <td> 8.8.8.8 </td>
      <td> 2019-10-29T04:10:19+00:00 </td>
      <td> domain </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>10. alienvault-search-pulses</h3>
<hr>
<p>Searches for pulses in AlienVault OTX.</p>
<h5>Base Command</h5>
<p>
  <code>alienvault-search-pulses</code>
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
      <td>page</td>
      <td>The page of the pulse to retrieve.</td>
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
      <td>AlienVaultOTX.Pulses.ID</td>
      <td>String</td>
      <td>The ID of the pulse.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Author.ID</td>
      <td>String</td>
      <td>The ID of the Author.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Author.Username</td>
      <td>String</td>
      <td>The username of the Author.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Count</td>
      <td>String</td>
      <td>The pulse count.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Modified</td>
      <td>Date</td>
      <td>The date of the pulse modification.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Name</td>
      <td>String</td>
      <td>The name of the pulse.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Source</td>
      <td>String</td>
      <td>The source of the Pulse.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.SubscriberCount</td>
      <td>String</td>
      <td>The count of the pulse subscriber.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Tags</td>
      <td>String</td>
      <td>The tags of the pulse.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Description</td>
      <td>String</td>
      <td>The description of the pulse.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!alienvault-search-pulses page=1</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AlienVaultOTX.Pulses": [
        {
            "Author": {
                "ID": "2",
                "Username": "AlienVault"
            },
            "Count": 28,
            "ID": "546ce8eb11d40838dc6e43f1",
            "Modified": "728 days ago ",
            "Name": "PoS Scammers Toolbox",
            "Source": "web",
            "SubscriberCount": 94133
        },
        {
            "Author": {
                "ID": "2",
                "Username": "AlienVault"
            },
            "Count": 11,
            "ID": "546cf5ba11d40839ea8821ca",
            "Modified": "1553 days ago ",
            "Name": " RAZOR BLADES IN THE CANDY JAR",
            "Source": "web",
            "SubscriberCount": 94115
        },
        {
            "Author": {
                "ID": "2",
                "Username": "AlienVault"
            },
            "Count": 10,
            "ID": "546e2e4f11d4083bc021c37d",
            "Modified": "796 days ago ",
            "Name": "Linking Asprox, Zemot, Rovix and  Rerdom Malware Families ",
            "Source": "web",
            "SubscriberCount": 94108,
            "Tags": [
                "Asprox",
                "Zemot",
                "Rovix"
            ]
        },
        {
            "Author": {
                "ID": "2",
                "Username": "AlienVault"
            },
            "Count": 23,
            "ID": "546fc7bf11d4083bc021c37f",
            "Modified": "796 days ago ",
            "Name": "Operation Double Tap",
            "Source": "web",
            "SubscriberCount": 94113
        },
        {
            "Author": {
                "ID": "2",
                "Username": "AlienVault"
            },
            "Count": 60,
            "Description": "Regin is a multi-purpose data collection tool which dates back several years. Symantec first began looking into this threat in the fall of 2013. Multiple versions of Regin were found in the wild, targeting several corporations, institutions, academics, and individuals.\nRegin has a wide range of standard capabilities, particularly around monitoring targets and stealing data. It also has the ability to load custom features tailored to individual targets. Some of Regin\u2019s custom payloads point to a high level of specialist knowledge in particular sectors, such as telecoms infrastructure software, on the part of\nthe developers.",
            "ID": "5473709d11d4083bc021c387",
            "Modified": "279 days ago ",
            "Name": "Regin",
            "Source": "web",
            "SubscriberCount": 94092
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - pulse page 1</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Author</strong></th>
      <th><strong>Count</strong></th>
      <th><strong>ID</strong></th>
      <th><strong>Modified</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Source</strong></th>
      <th><strong>SubscriberCount</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> ID: 2<br>Username: AlienVault </td>
      <td> 28 </td>
      <td> 546ce8eb11d40838dc6e43f1 </td>
      <td> 728 days ago  </td>
      <td> PoS Scammers Toolbox </td>
      <td> web </td>
      <td> 94133 </td>
    </tr>
    <tr>
      <td> ID: 2<br>Username: AlienVault </td>
      <td> 11 </td>
      <td> 546cf5ba11d40839ea8821ca </td>
      <td> 1553 days ago  </td>
      <td>  RAZOR BLADES IN THE CANDY JAR </td>
      <td> web </td>
      <td> 94115 </td>
    </tr>
    <tr>
      <td> ID: 2<br>Username: AlienVault </td>
      <td> 10 </td>
      <td> 546e2e4f11d4083bc021c37d </td>
      <td> 796 days ago  </td>
      <td> Linking Asprox, Zemot, Rovix and  Rerdom Malware Families  </td>
      <td> web </td>
      <td> 94108 </td>
    </tr>
    <tr>
      <td> ID: 2<br>Username: AlienVault </td>
      <td> 23 </td>
      <td> 546fc7bf11d4083bc021c37f </td>
      <td> 796 days ago  </td>
      <td> Operation Double Tap </td>
      <td> web </td>
      <td> 94113 </td>
    </tr>
    <tr>
      <td> ID: 2<br>Username: AlienVault </td>
      <td> 60 </td>
      <td> 5473709d11d4083bc021c387 </td>
      <td> 279 days ago  </td>
      <td> Regin </td>
      <td> web </td>
      <td> 94092 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>11. alienvault-get-pulse-details</h3>
<hr>
<p>Returns pulse details.</p>
<h5>Base Command</h5>
<p>
  <code>alienvault-get-pulse-details</code>
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
      <td>pulse_id</td>
      <td>The ID of the pulse.</td>
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
      <td>AlienVaultOTX.Pulses.Created</td>
      <td>Date</td>
      <td>The date the pulse was created.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Author.Username</td>
      <td>String</td>
      <td>The author username of the pulse.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.ID</td>
      <td>String</td>
      <td>The ID of the pulse.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Name</td>
      <td>String</td>
      <td>The name of the pulse.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Tags</td>
      <td>String</td>
      <td>The tags of the pulse.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.TargetedCountries</td>
      <td>String</td>
      <td>The targeted countries of the pulse.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.Pulses.Description</td>
      <td>String</td>
      <td>The description of the pulse.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!alienvault-get-pulse-details pulse_id=57204e9b3c4c3e015d93cb12</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AlienVaultOTX.Pulses": {
        "Author": {
            "Username": "AlienVault"
        },
        "Created": "2016-04-27T05:31:06.941000",
        "Description": "The infamous Remote Access Trojan (RAT) Poison Ivy (hereafter referred to as PIVY) has resurfaced recently, and exhibits some new behaviors. PIVY has been observed targeting a number of Asian countries for various purposes over the past year. Palo Alto Networks\u2019 Unit 42 recently blogged about a new Poison Ivy variant targeting Hong Kong activists dubbed SPIVY that uses DLL sideloading and operates quite differently from a variant recently observed by ASERT that has been active for at least the past 12 months.",
        "ID": "57204e9b3c4c3e015d93cb12",
        "Name": "Poison Ivy Activity Targeting Myanmar, Asian Countries",
        "Tags": [
            "rat",
            "remote access trojan",
            "poison ivy",
            "pivy",
            "Myanmar",
            "asia",
            "Hong Kong",
            "arbornetworks"
        ],
        "TargetedCountries": []
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - pulse id details</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Author</strong></th>
      <th><strong>Created</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>ID</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Tags</strong></th>
      <th><strong>TargetedCountries</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> Username: AlienVault </td>
      <td> 2016-04-27T05:31:06.941000 </td>
      <td> The infamous Remote Access Trojan (RAT) Poison Ivy (hereafter referred to as PIVY) has resurfaced recently, and exhibits some new behaviors. PIVY has been observed targeting a number of Asian countries for various purposes over the past year. Palo Alto Networks’ Unit 42 recently blogged about a new Poison Ivy variant targeting Hong Kong activists dubbed SPIVY that uses DLL sideloading and operates quite differently from a variant recently observed by ASERT that has been active for at least the past 12 months. </td>
      <td> 57204e9b3c4c3e015d93cb12 </td>
      <td> Poison Ivy Activity Targeting Myanmar, Asian Countries </td>
      <td> rat,<br>remote access trojan,<br>poison ivy,<br>pivy,<br>Myanmar,<br>asia,<br>Hong Kong,<br>arbornetworks </td>
      <td>  </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>12. url</h3>
<hr>
<p>Queries a URL in AlienVault OTX.</p>
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
      <td>The URL to query.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>threshold</td>
      <td>If the number of pulses is bigger than the threshold, the URL is considered as malicious. If threshold is not specified, the default indicator threshold is used, which is configured in the instance settings.</td>
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
      <td>URL.Data</td>
      <td>String</td>
      <td>The URL.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.URL.Hostname</td>
      <td>String</td>
      <td>The host name of the URL.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.URL.Domain</td>
      <td>String</td>
      <td>The domain of the URL.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.URL.Alexa</td>
      <td>String</td>
      <td>The domain data for the Alexa URL.</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.URL.Url</td>
      <td>String</td>
      <td>Url</td>
    </tr>
    <tr>
      <td>AlienVaultOTX.URL.Whois</td>
      <td>String</td>
      <td>The Whois URL for domain data.</td>
    </tr>
    <tr>
      <td>DBotScore.Indicator</td>
      <td>String</td>
      <td>The indicator that was tested.</td>
    </tr>
    <tr>
      <td>DBotScore.Score</td>
      <td>Number</td>
      <td>The actual score.</td>
    </tr>
    <tr>
      <td>DBotScore.Type</td>
      <td>String</td>
      <td>The type of indicator.</td>
    </tr>
    <tr>
      <td>DBotScore.Vendor</td>
      <td>String</td>
      <td>The AlienVault OTX vendor.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!url url=http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AlienVaultOTX.URL": {
        "Alexa": "http://www.alexa.com/siteinfo/fotoidea.com",
        "Domain": "fotoidea.com",
        "Hostname": "www.fotoidea.com",
        "Url": "http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list",
        "Whois": "http://whois.domaintools.com/fotoidea.com"
    },
    "DBotScore": {
        "Indicator": "http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list",
        "Score": "0",
        "Type": "url",
        "Vendor": "AlienVault OTX v2"
    },
    "URL": {
        "Data": "http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>AlienVault OTX v2 - Results for url query</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Alexa</strong></th>
      <th><strong>Domain</strong></th>
      <th><strong>Hostname</strong></th>
      <th><strong>Url</strong></th>
      <th><strong>Whois</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> http://www.alexa.com/siteinfo/fotoidea.com </td>
      <td> fotoidea.com </td>
      <td> www.fotoidea.com </td>
      <td> http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list </td>
      <td> http://whois.domaintools.com/fotoidea.com </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

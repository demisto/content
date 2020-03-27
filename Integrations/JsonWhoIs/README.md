<<<<<<< HEAD
<h1>JsonWhoIs Integration</h1>
<h2>Use Cases</h2>
<ul>
<li>Research on malicious url.</li>
</ul><h2>Detailed Description</h2>
<p>Use the Whois integration to enrich domain indicators.</p>
<p>The integraiton require API token that should be provided from <a href="https://jsonwhois.com/">here</a> </p>

<h2>Configure JsonWhoIs on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for JsonWhoIs.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
      <li><strong>API token</strong>enter token you purchased from <a href="https://jsonwhois.com/">here</a></li>
      <li><strong>System proxy</strong>: Check if you want to use the system proxy.</li>
      <li><strong>Trust any certificate</strong>: Check if you want to trust any CA.</li>
      <li><strong>Do not use by default</strong>: Check if to you don't to use this commands by default
        (influence if two command are the same).</li>
    </ul>
  </li>
</ol>
<ol start="4">
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
  <li>whois: Perform enhancement on url or ip.</li>
</ol>
<h3>1. whois</h3>
<!-- <hr> -->
<p>Provides data enrichment for Domains, URLs, and IP addresses.</p>
<h5>Base Command</h5>
<p>
  <code>whois</code>
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
      <td>query</td>
      <td>URL, IP, or domain to be enriched</td>
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
      <td>Domain.WHOIS.DomainStatus</td>
      <td>Boolean</td>
      <td>b'Domain'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.NameServers</td>
      <td>String</td>
      <td>b'Name servers'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.CreationDate</td>
      <td>Date</td>
      <td>b'Creation date'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.UpdatedDate</td>
      <td>Date</td>
      <td>b'Updated date'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.ExpirationDate</td>
      <td>Date</td>
      <td>b'Expiration date'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.Registrant.Name</td>
      <td>String</td>
      <td>b'Registrant name'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.Registrant.Email</td>
      <td>String</td>
      <td>b'Registrant email'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.Registrant.Phone</td>
      <td>String</td>
      <td>b'Registrant phone'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.Registrar.Name</td>
      <td>String</td>
      <td>b'Registrar name'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.Registrar.Url</td>
      <td>String</td>
      <td>b'Registrar email'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.Registrar.Organization</td>
      <td>String</td>
      <td>b'Registrar organization name'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.Registrar.Id</td>
      <td>Number</td>
      <td>b'Registrar ID'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.Admin.Name</td>
      <td>String</td>
      <td>b'Admin name'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.Admin.Email</td>
      <td>String</td>
      <td>b'Admin email'</td>
    </tr>
    <tr>
      <td>Domain.WHOIS.Admin.Phone</td>
      <td>String</td>
      <td>b'Admin phone'</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!whois query=demisto.com</code>
</p>
<h5>Context Example</h5>
<pre>
=======
Use the JsonWhoIs integration to  enrich domain indicators.


## Configure JsonWhoIs on Demisto

1.  Navigate to **Settings** > **Integrations**  > **Servers & Services**.
2.  Search for JsonWhoIs.
3.  Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Example** |
    | ---------             | -----------           | -------            |
    | Name | A meaningful name for the integration instance. | JsonWhoIs_instance_1 |
    | API Token  |  Your [JsonWhoIs API token](https://jsonwhois.com/) |  N/A  |
    | System proxy | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration.     | https:/<span></span>/proxyserver.com |
    | Trust any certificate (not secure) | When selected, certificates are not checked. | N/A |
    | Do Not Use by Default  | If checked the commands will not be used by default (this is influenced if two command are the same). | N/A  |

4.  Click **Test** to validate the new instance.

## Commands

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get enriched data

Returns enriched data for Domains, URLs, and IP addresses.

##### Base Command

`whois`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The URL, IP address, or domain to enrich. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.WHOIS.DomainStatus | Boolean | Whether the domain is registered. |
| Domain.WHOIS.NameServers | String | The name servers. |
| Domain.WHOIS.CreationDate | Date | The creation date. |
| Domain.WHOIS.UpdatedDate | Date | The updated date. |
| Domain.WHOIS.ExpirationDate | Date | The expiration date. |
| Domain.WHOIS.Registrant.Name | String | The registrant name. |
| Domain.WHOIS.Registrant.Email | String | The registrant email. |
| Domain.WHOIS.Registrant.Phone | String | The registrant phone. |
| Domain.WHOIS.Registrar.Name | String | The registrar name. |
| Domain.WHOIS.Registrar.Url | String | The registrar email. |
| Domain.WHOIS.Registrar.Organization | String | The registrar organization name. |
| Domain.WHOIS.Registrar.Id | Number | The registrar ID. |
| Domain.WHOIS.Admin.Name | String | The Admin name. |
| Domain.WHOIS.Admin.Email | String | The Admin email. |
| Domain.WHOIS.Admin.Phone | String | The Admin phone. |

##### Command Example
```
!whois query=demisto.com
```

##### Context Example
```
>>>>>>> upstream/master
{
    "Domain": {
        "WHOIS": {
            "Admin": [
                {
                    "Email": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com",
                    "Name": "WhoisGuard Protected",
                    "Phone": "+507.8365503"
                }
            ],
            "CreationDate": "2015-01-16T21:36:27.000Z",
            "DomainStatus": "registered",
            "ExpirationDate": "2026-01-16T21:36:27.000Z",
            "NameServers": [
                {
                    "Name": "pns31.cloudns.net"
                },
                {
                    "Name": "pns32.cloudns.net"
                },
                {
                    "Name": "pns33.cloudns.net"
                },
                {
                    "Name": "pns34.cloudns.net"
                }
            ],
            "Registrant": [
                {
                    "Email": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com",
                    "Name": "WhoisGuard Protected",
                    "Phone": "+507.8365503"
                }
            ],
            "Registrar": {
                "Id": "1068",
                "Name": "NameCheap, Inc.",
                "Url": "http://www.namecheap.com"
            },
            "UpdatedDate": "2019-05-14T16:14:12.000Z"
        }
    }
}
<<<<<<< HEAD
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Admin account</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Email</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Phone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>5be9245893ff486d98c3640879bb2657.protect@whoisguard.com</td>
      <td>WhoisGuard Protected</td>
      <td>+507.8365503</td>
    </tr>
  </tbody>
</table>

<h3>Name servers</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>pns31.cloudns.net</td>
    </tr>
    <tr>
      <td>pns32.cloudns.net</td>
    </tr>
    <tr>
      <td>pns33.cloudns.net</td>
    </tr>
    <tr>
      <td>pns34.cloudns.net</td>
    </tr>
  </tbody>
</table>

<h3>Registrant</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Email</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Phone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>5be9245893ff486d98c3640879bb2657.protect@whoisguard.com</td>
      <td>WhoisGuard Protected</td>
      <td>+507.8365503</td>
    </tr>
  </tbody>
</table>

<h3>Registrar</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Id</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Url</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>1068</td>
      <td>NameCheap, Inc.</td>
      <td>http://www.namecheap.com</td>
    </tr>
  </tbody>
</table>

<h3>Others</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>CreationDate</strong></th>
      <th><strong>DomainStatus</strong></th>
      <th><strong>ExpirationDate</strong></th>
      <th><strong>UpdatedDate</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>2015-01-16T21:36:27.000Z</td>
      <td>registered</td>
      <td>2026-01-16T21:36:27.000Z</td>
      <td>2019-05-14T16:14:12.000Z</td>
    </tr>
  </tbody>
</table>
<h2>Known Limitations</h2>
<ul>
  <li>JsonWhoIs isn't a stable API, therefor the implementation try to query 3 times before failing.</li>
</ul>
=======
```

##### Human Readable Output

##### Admin account

| **Email** | **Name** | **Phone** |
| --- | --- | --- |
| 5be9245893ff486d98c3640879bb2657.protect<span></span>@whoisguard.com | WhoisGuard Protected | +507.8365503 |

##### Name servers

| **Name** |
| --- |
| pns31.cloudns<span></span>.net |
| pns32.cloudns<span></span>.net |
| pns33.cloudns<span></span>.net |
| pns34.cloudns<span></span>.net |

##### Registrant

| **Email** | **Name** | **Phone** |
| --- | --- | --- |
| 5be9245893ff486d98c3640879bb2657.protect<span></span>@whoisguard.com | WhoisGuard Protected | +507.8365503 |

##### Registrar

| **Id** | **Name** | **Url** |
| --- | --- | --- |
| 1068 | NameCheap, Inc. | http:/<span></span>/www<span></span>.namecheap<span></span>.com |

##### Others

| **CreationDate** | **DomainStatus** | **ExpirationDate** | **UpdatedDate** |
| --- | --- | --- | --- |
| 2015-01-16T21:36:27.000Z | registered | 2026-01-16T21:36:27.000Z | 2019-05-14T16:14:12.000Z |

## Troubleshooting

The JsonWhoIs API is not stable. We recommend attempting a query three times before considering the query to fail.
>>>>>>> upstream/master

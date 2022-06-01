<p>
Infoblox enables you to receive metadata about IPs in your network and manages the DNS Firewall by configuring RPZs. It defines RPZ rules to block DNS resolution for malicious or unauthorized hostnames, or redirect clients to a walled garden by substituting responses.

This integration was integrated and tested with version V2 of Infoblox
</p>
<h2>Configure Infoblox on XSOAR</h2>
<h5>Required Permissions</h5>
<p>The API supports only HTTP Basic Authentication. Every user must have permissions that grants them access to the API.</p>

<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Infoblox.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Server URL (e.g. https://example.net)</strong></li>
   <li><strong>User Name</strong></li>
   <li><strong>Password</strong></li>
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
  You can execute these commands from the XSOAR CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li><a href="#infoblox-get-ip" target="_self">Get IP info: infoblox-get-ip</a></li>
  <li><a href="#infoblox-search-related-objects-by-ip" target="_self">Searches IP related objects by a given IP: infoblox-search-related-objects-by-ip</a></li>
  <li><a href="#infoblox-list-response-policy-zone-rules" target="_self">Lists all response policy rules that belong to the given response policy zone: infoblox-list-response-policy-zone-rules</a></li>
  <li><a href="#infoblox-list-response-policy-zones" target="_self">List all response policy zones: infoblox-list-response-policy-zones</a></li>
  <li><a href="#infoblox-create-response-policy-zone" target="_self">Creates a response policy zone: infoblox-create-response-policy-zone</a></li>
  <li><a href="#infoblox-create-rpz-rule" target="_self">Creates a response policy rule: infoblox-create-rpz-rule</a></li>
  <li><a href="#infoblox-create-a-substitute-record-rule" target="_self">Creates a substitute record rule: infoblox-create-a-substitute-record-rule</a></li>
  <li><a href="#infoblox-create-aaaa-substitute-record-rule" target="_self">Creates a substitute rule for an AAAA record: infoblox-create-aaaa-substitute-record-rule</a></li>
  <li><a href="#infoblox-create-mx-substitute-record-rule" target="_self">Creates a substitute rule for the MX record: infoblox-create-mx-substitute-record-rule</a></li>
  <li><a href="#infoblox-create-naptr-substitute-record-rule" target="_self">Creates a substitute rule for a NAPTR record: infoblox-create-naptr-substitute-record-rule</a></li>
  <li><a href="#infoblox-create-ptr-substitute-record-rule" target="_self">Creates a substitute rule of the PTR record: infoblox-create-ptr-substitute-record-rule</a></li>
  <li><a href="#infoblox-create-srv-substitute-record-rule" target="_self">Creates a substitute rule of a SRV record: infoblox-create-srv-substitute-record-rule</a></li>
  <li><a href="#infoblox-create-txt-substitute-record-rule" target="_self">Create a substitute rule for a txt record: infoblox-create-txt-substitute-record-rule</a></li>
  <li><a href="#infoblox-create-ipv4-substitute-record-rule" target="_self">Create a substitute rule for an IPv4 rule: infoblox-create-ipv4-substitute-record-rule</a></li>
  <li><a href="#infoblox-create-ipv6-substitute-record-rule" target="_self">Creates a substitute of the IPv6 record rule: infoblox-create-ipv6-substitute-record-rule</a></li>
  <li><a href="#infoblox-enable-rule" target="_self">Disables a rule by its reference ID (reference ID could be extracted by running the searah rules command): infoblox-enable-rule</a></li>
  <li><a href="#infoblox-disable-rule" target="_self">Disable a rule by its reference ID (reference ID could be extracted by running the 'infoblox-search-rule' command): infoblox-disable-rule</a></li>
  <li><a href="#infoblox-get-object-fields" target="_self">Returns the object fields names which can be used in the search rules command: infoblox-get-object-fields</a></li>
  <li><a href="#infoblox-search-rule" target="_self">Searches a specific rule by its name: infoblox-search-rule</a></li>
  <li><a href="#infoblox-delete-rpz-rule" target="_self">Deletes a rule: infoblox-delete-rpz-rule</a></li>
  <li><a href="#infoblox-delete-response-policy-zone" target="_self">Deletes a given response policy zone: infoblox-delete-response-policy-zone</a></li>
</ol>
<h3 id="infoblox-get-ip">1. infoblox-get-ip</h3>
<hr>
<p>Get IP info</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-get-ip</code>
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
      <td>The IP address for which to retrieve information.</td>
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
      <td>Infoblox.IP.ReferenceID</td>
      <td>number</td>
      <td>Reference ID of the object.</td>
    </tr>
    <tr>
      <td>Infoblox.IP.MacAddress</td>
      <td>string</td>
      <td>The Mac address of the IP.</td>
    </tr>
    <tr>
      <td>Infoblox.IP.Network</td>
      <td>string</td>
      <td>The network that the IP belongs, in FQDN/CIDR format.</td>
    </tr>
    <tr>
      <td>Infoblox.IP.NetworkView</td>
      <td>string</td>
      <td>The name of the network view.</td>
    </tr>
    <tr>
      <td>Infoblox.IP.Status</td>
      <td>string</td>
      <td>The current status of the address.</td>
    </tr>
    <tr>
      <td>Infoblox.IP.IsConflict</td>
      <td>string</td>
      <td>Whether the IP address has either a MAC address conflict or a DHCP lease conflict detected through a network discovery (if set to true).</td>
    </tr>
    <tr>
      <td>Infoblox.IP. Objects</td>
      <td>string</td>
      <td>The objects associated with the IP address.</td>
    </tr>
    <tr>
      <td>Infoblox.IP.Types</td>
      <td>string</td>
      <td>The current status of the address.</td>
    </tr>
    <tr>
      <td>Infoblox.IP. Names</td>
      <td>string</td>
      <td>The DNS names. For example, if the IP address belongs to a host record, this field contains the hostname.</td>
    </tr>
    <tr>
      <td>Infoblox.IP. Extattrs</td>
      <td>string</td>
      <td>Extra attributes relevant for this object.</td>
    </tr>
    <tr>
      <td>Infoblox.IP.IpAddress</td>
      <td>string</td>
      <td>The IP address.</td>
    </tr>
    <tr>
      <td>Infoblox.IP.Usage</td>
      <td>string</td>
      <td>Indicates whether the IP address is configured for DNS or DHCP.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-get-ip ip="172.0.0.0"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.IP": {
        "Extattrs": {},
        "IpAddress": "172.0.0.0",
        "IsConflict": false,
        "MacAddress": "",
        "Names": [],
        "Network": "172.0.0.0/24",
        "NetworkView": "default",
        "Objects": [],
        "ReferenceID": "ipv4address/Li5pcHY0X2FkZHJlc3MkMTcyLjAuMC4wLzA:172.0.0.0",
        "Status": "USED",
        "Types": [
            "NETWORK"
        ],
        "Usage": []
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - IP: 172.0.0.0 info.</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Extattrs</strong></th>
      <th><strong>Ip Address</strong></th>
      <th><strong>Is Conflict</strong></th>
      <th><strong>Mac Address</strong></th>
      <th><strong>Names</strong></th>
      <th><strong>Network</strong></th>
      <th><strong>Network View</strong></th>
      <th><strong>Objects</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Types</strong></th>
      <th><strong>Usage</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>  </td>
      <td> 172.0.0.0 </td>
      <td> false </td>
      <td>  </td>
      <td>  </td>
      <td> 172.0.0.0/24 </td>
      <td> default </td>
      <td>  </td>
      <td> ipv4address/Li5pcHY0X2FkZHJlc3MkMTcyLjAuMC4wLzA:172.0.0.0 </td>
      <td> USED </td>
      <td> NETWORK </td>
      <td>  </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-search-related-objects-by-ip">2. infoblox-search-related-objects-by-ip</h3>
<hr>
<p>Searches IP related objects by a given IP.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-search-related-objects-by-ip</code>
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
      <td>The IP address for which to search.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>max_results</td>
      <td>The maximum results to return.</td>
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
      <td>Infoblox.IPRelatedObjects.ReferenceID</td>
      <td>Unknown</td>
      <td>The reference ID of the related object.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-search-related-objects-by-ip ip="172.0.0.0"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.IPRelatedObjects": [
        {
            "Network": "172.0.0.0/24",
            "NetworkView": "default",
            "ReferenceID": "network/ZG5zLm5ldHdvcmskMTcyLjAuMC4wLzI0LzA:172.0.0.0/24/default"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - IP: 172.0.0.0 search results.</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Network</strong></th>
      <th><strong>Network View</strong></th>
      <th><strong>Reference ID</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 172.0.0.0/24 </td>
      <td> default </td>
      <td> network/ZG5zLm5ldHdvcmskMTcyLjAuMC4wLzI0LzA:172.0.0.0/24/default </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-list-response-policy-zone-rules">3. infoblox-list-response-policy-zone-rules</h3>
<hr>
<p>Lists all response policy rules that belong to the given response policy zone.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-list-response-policy-zone-rules</code>
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
      <td>response_policy_zone_name</td>
      <td>The response policy zone name to list the rules (FQDN).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>page_size</td>
      <td>The number of results in each page.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>next_page_id</td>
      <td>The next page ID that was returned when last running this command.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>view</td>
      <td>The DNS view in which the records are located. By default, the 'default' DNS view is searched.</td>
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
      <td>Infoblox.ResponsePolicyZoneRulesList.Name</td>
      <td>string</td>
      <td>Rule name.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZoneRulesList.Disable</td>
      <td>boolean</td>
      <td>Whether the rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZoneRulesList.Comment</td>
      <td>string</td>
      <td>The comment for this rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZoneRulesList.Type</td>
      <td>string</td>
      <td>The object type as used in Infoblox.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZoneRulesList.View</td>
      <td>string</td>
      <td>View of the definition.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZoneRulesList.Zone</td>
      <td>string</td>
      <td>The zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.RulesNextPage.NextPageID</td>
      <td>string</td>
      <td>Retrieves the next page of the search. The last NextpageID corresponds to the last search performed.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-list-response-policy-zone-rules response_policy_zone_name=infoblow.com page_size="8"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ResponsePolicyZoneRulesList": [
        {
            "Comment": "",
            "Disable": false,
            "Name": "4.4.4.5",
            "Type": "record:rpz:cname",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "1.1.1.1",
            "Type": "record:rpz:cname:ipaddressdn",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "2.2.2.2",
            "Type": "record:rpz:a:ipaddress",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "5.5.5.111",
            "Type": "record:rpz:cname:ipaddress",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "moshe",
            "Type": "record:rpz:cname",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "moshe2",
            "Type": "record:rpz:cname",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "moshe3",
            "Type": "record:rpz:cname",
            "View": "default",
            "Zone": "infoblow.com"
        }
    ],
    "Infoblox.RulesNextPage": {
        "NextPageID": "789c9d525b4ec33010fcf739905a89cacaa3a5ed11fa83101cc0726c2735385ecb7668cbe9d935a1503e51a4489edd9d997d2c75a8d9cb02a2c953f4a2b7c6e92446d069c1428391fb054b2f8b111344908321b86587aa2654c681de6bb6d46183b91fe00dbe1fd8d2852dbeadefa17370e20a46c4774c26e29267110bd19e1d76c443c4829211ab2ba614840ba60c0c7f0a7cca71521922066bb65433eb99a31aef6432ec09eb0f886242c39410dd645db65e0806ddab5119f1963de6e75017ab3579ed219e64d4a4f8f0dd4fca326642b68810e0ec680bb09b9d0e90410448365bf002fa3e9912dfcf055a664983ab48a7a1c9f636a65cfa885abc990b4569ae34137e6d45fbc43bebb5505e8ee68e0b6d7a39b9fc3bebc4377c4d1f51b4c59e44eaa34cc29b33d968d6df9d1c8dd4242a14c09ba5a5341b36fca90ad1bc5384faafae915babdb7f5a1d211d4d4b0c38b7d42139ae225f42b1b24752e95c0c1f5f62e5a88a83db3b24b8a6636a696224b7a2135ba1d2687c5e699b64e7cc6ae66d5b3c30dce2d4fd949785b71be22e9b206cee977f02207ef4bc-1cbe432a6c562d903bd34ea2dd75f482330d98e249c3359e4e258b9"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Zone: Infoblow.com rule list.</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Comment</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>  </td>
      <td> false </td>
      <td> 4.4.4.5 </td>
      <td> record:rpz:cname </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
    <tr>
      <td>  </td>
      <td> false </td>
      <td> 1.1.1.1 </td>
      <td> record:rpz:cname:ipaddressdn </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
    <tr>
      <td>  </td>
      <td> false </td>
      <td> 2.2.2.2 </td>
      <td> record:rpz:a:ipaddress </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
    <tr>
      <td>  </td>
      <td> false </td>
      <td> 5.5.5.111 </td>
      <td> record:rpz:cname:ipaddress </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
    <tr>
      <td>  </td>
      <td> false </td>
      <td> moshe </td>
      <td> record:rpz:cname </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
    <tr>
      <td>  </td>
      <td> false </td>
      <td> moshe2 </td>
      <td> record:rpz:cname </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
    <tr>
      <td>  </td>
      <td> false </td>
      <td> moshe3 </td>
      <td> record:rpz:cname </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-list-response-policy-zones">4. infoblox-list-response-policy-zones</h3>
<hr>
<p>List all response policy zones.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-list-response-policy-zones</code>
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
      <td>max_results</td>
      <td>Maximum results to return. (default is 50)</td>
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
      <td>Infoblox.ResponsePolicyZones.Disable</td>
      <td>boolean</td>
      <td>Whether this zone is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.FQDN</td>
      <td>string</td>
      <td>The fully qualified domain name.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the object.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.RpzPolicy</td>
      <td>string</td>
      <td>The response policy zone override policy.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.RpzSeverity</td>
      <td>string</td>
      <td>The severity of this response policy zone.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.RpzType</td>
      <td>string</td>
      <td>The type of response policy zone.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-list-response-policy-zones</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ResponsePolicyZones": [
        {
            "Disable": false,
            "FQDN": "local.rpz",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LnJwei5sb2NhbA:local.rpz/default",
            "RpzPolicy": "GIVEN",
            "RpzSeverity": "MAJOR",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "infoblow.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdw:infoblow.com/default",
            "RpzPolicy": "SUBSTITUTE",
            "RpzSeverity": "WARNING",
            "RpzType": "LOCAL",
            "SubstituteName": "infoblox.com",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGU:google.com/default",
            "RpzPolicy": "DISABLED",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "SubstituteName": "sdfdsf",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google2.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUy:google2.com/default",
            "RpzPolicy": "DISABLED",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "SubstituteName": "sdfdsf",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google3.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUz:google3.com/default",
            "RpzPolicy": "DISABLED",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "SubstituteName": "sdfdsf",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google4.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGU0:google4.com/default",
            "RpzPolicy": "DISABLED",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "SubstituteName": "sdfdsf",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google33.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUzMw:google33.com/default",
            "RpzPolicy": "GIVEN",
            "RpzSeverity": "WARNING",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google.test.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0Lmdvb2dsZQ:google.test.com/default",
            "RpzPolicy": "NXDOMAIN",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google.test2.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0Mi5nb29nbGU:google.test2.com/default",
            "RpzPolicy": "NXDOMAIN",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google.test4.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0NC5nb29nbGU:google.test4.com/default",
            "RpzPolicy": "NXDOMAIN",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "test.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0:test.com/default",
            "RpzPolicy": "GIVEN",
            "RpzSeverity": "WARNING",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "test123.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0MTIz:test123.com/default",
            "RpzPolicy": "GIVEN",
            "RpzSeverity": "WARNING",
            "RpzType": "LOCAL",
            "View": "default"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zones list (first 50 results):</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Disable</strong></th>
      <th><strong>FQDN</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Rpz Policy</strong></th>
      <th><strong>Rpz Severity</strong></th>
      <th><strong>Rpz Type</strong></th>
      <th><strong>View</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> false </td>
      <td> local.rpz </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LnJwei5sb2NhbA:local.rpz/default </td>
      <td> GIVEN </td>
      <td> MAJOR </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
    <tr>
      <td> false </td>
      <td> infoblow.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdw:infoblow.com/default </td>
      <td> SUBSTITUTE </td>
      <td> WARNING </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
    <tr>
      <td> false </td>
      <td> google.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGU:google.com/default </td>
      <td> DISABLED </td>
      <td> INFORMATIONAL </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
    <tr>
      <td> false </td>
      <td> google2.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUy:google2.com/default </td>
      <td> DISABLED </td>
      <td> INFORMATIONAL </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
    <tr>
      <td> false </td>
      <td> google3.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUz:google3.com/default </td>
      <td> DISABLED </td>
      <td> INFORMATIONAL </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
    <tr>
      <td> false </td>
      <td> google4.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGU0:google4.com/default </td>
      <td> DISABLED </td>
      <td> INFORMATIONAL </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
    <tr>
      <td> false </td>
      <td> google33.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUzMw:google33.com/default </td>
      <td> GIVEN </td>
      <td> WARNING </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
    <tr>
      <td> false </td>
      <td> google.test.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0Lmdvb2dsZQ:google.test.com/default </td>
      <td> NXDOMAIN </td>
      <td> INFORMATIONAL </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
    <tr>
      <td> false </td>
      <td> google.test2.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0Mi5nb29nbGU:google.test2.com/default </td>
      <td> NXDOMAIN </td>
      <td> INFORMATIONAL </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
    <tr>
      <td> false </td>
      <td> google.test4.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0NC5nb29nbGU:google.test4.com/default </td>
      <td> NXDOMAIN </td>
      <td> INFORMATIONAL </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
    <tr>
      <td> false </td>
      <td> test.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0:test.com/default </td>
      <td> GIVEN </td>
      <td> WARNING </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
    <tr>
      <td> false </td>
      <td> test123.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0MTIz:test123.com/default </td>
      <td> GIVEN </td>
      <td> WARNING </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-create-response-policy-zone">5. infoblox-create-response-policy-zone</h3>
<hr>
<p>Creates a response policy zone.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-create-response-policy-zone</code>
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
      <td>FQDN</td>
      <td>The name of this DNS zone in FQDN format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rpz_policy</td>
      <td>The override policy of the response policy zone. Can be: "DISABLED", "GIVEN", "NODATA", "NXDOMAIN", "PASSTHRU", or "SUBSTITUTE".</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rpz_severity</td>
      <td>The severity of the response policy zone. Can be: "CRITICAL", "MAJOR", "WARNING", or "INFORMATIONAL".</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>substitute_name</td>
      <td>The alternative name of the redirect target in a substitute response policy. policy zone.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>rpz_type</td>
      <td>The type of the rpz zone. Can be: "FEED", "FIREEYE", or "LOCAL".</td>
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
      <td>Infoblox.ResponsePolicyZones.Disable</td>
      <td>boolean</td>
      <td>Whether this zone is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.FQDN</td>
      <td>string</td>
      <td>A fully qualified domain name.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the object.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.RpzPolicy</td>
      <td>string</td>
      <td>The response policy zone override policy.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.RpzSeverity</td>
      <td>string</td>
      <td>The severity of the response policy zone.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.RpzType</td>
      <td>string</td>
      <td>The type of rpz zone.</td>
    </tr>
    <tr>
      <td>Infoblox.ResponsePolicyZones.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-create-response-policy-zone FQDN="infonlox.nightly.tpb.com" rpz_policy="DISABLED" rpz_severity="INFORMATIONAL" rpz_type="FEED"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ResponsePolicyZones": {
        "Disable": false,
        "FQDN": "infonlox.nightly.tpb.com",
        "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50cGIubmlnaHRseS5pbmZvbmxveA:infonlox.nightly.tpb.com/default",
        "RpzPolicy": "DISABLED",
        "RpzSeverity": "INFORMATIONAL",
        "RpzType": "LOCAL",
        "View": "default"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone: infonlox.nightly.tpb.com has been created</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Disable</strong></th>
      <th><strong>FQDN</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Rpz Policy</strong></th>
      <th><strong>Rpz Severity</strong></th>
      <th><strong>Rpz Type</strong></th>
      <th><strong>View</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> false </td>
      <td> infonlox.nightly.tpb.com </td>
      <td> zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50cGIubmlnaHRseS5pbmZvbmxveA:infonlox.nightly.tpb.com/default </td>
      <td> DISABLED </td>
      <td> INFORMATIONAL </td>
      <td> LOCAL </td>
      <td> default </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-create-rpz-rule">6. infoblox-create-rpz-rule</h3>
<hr>
<p>Creates a response policy rule.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-create-rpz-rule</code>
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
      <td>rule_type</td>
      <td>The type of the rule to create. Can be: "Passthru", "Block" (No such domain), "Block" (No data), or "Substitute" (domain name).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>object_type</td>
      <td>The type of the object for which to assign the rule. Can be: "Domain Name", "IP address", or "Client IP address".</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>name</td>
      <td>The rule name in a FQDN format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rp_zone</td>
      <td>The zone to assign the rule.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>Adds a comment for this rule.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>substitute_name</td>
      <td>The substitute name to assign (substitute domain only).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>view</td>
      <td>The DNS view in which the records are located. By default, the 'default' DNS view is searched.</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The rule name.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The comment for this rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Type</td>
      <td>string</td>
      <td>The object type as used in Infoblox.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-create-rpz-rule rule_type="Passthru" object_type="Domain Name" name="nightly-test-rpz-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-rpz-sub" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Canonical": "nightly-test-rpz-sub.infoblow.com",
        "Disable": false,
        "Name": "nightly-test-rpz-sub.infoblow.com",
        "ReferenceID": "record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy5uaWdodGx5LXRlc3QtcnB6LXN1Yg:nightly-test-rpz-sub.infoblow.com/default",
        "Type": "record:rpz:cname",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: nightly-test-rpz-sub.infoblow.com has been created:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Canonical</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> nightly-test-rpz-sub.infoblow.com </td>
      <td> false </td>
      <td> nightly-test-rpz-sub.infoblow.com </td>
      <td> record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy5uaWdodGx5LXRlc3QtcnB6LXN1Yg:nightly-test-rpz-sub.infoblow.com/default </td>
      <td> record:rpz:cname </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-create-a-substitute-record-rule">7. infoblox-create-a-substitute-record-rule</h3>
<hr>
<p>Creates a substitute record rule.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-create-a-substitute-record-rule</code>
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
      <td>name</td>
      <td>The name for a record in FQDN format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rp_zone</td>
      <td>The zone to assign the rule.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>Add a comment for this rule.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ipv4addr</td>
      <td>The IPv4 address of the substitute rule.</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The name of the rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The comment for this rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Type</td>
      <td>string</td>
      <td>The object type as used in Infoblox.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-create-a-substitute-record-rule name="nightly-test-a-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-a-sub" ipv4addr="0.0.0.0" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-a-sub",
        "Disable": false,
        "Ipv4addr": "0.0.0.0",
        "Name": "nightly-test-a-sub.infoblow.com",
        "ReferenceID": "record:rpz:a/ZG5zLmJpbmRfYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LG5pZ2h0bHktdGVzdC1hLXN1YiwwLjAuMC4w:nightly-test-a-sub.infoblow.com/default",
        "Type": "record:rpz:a",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: nightly-test-a-sub.infoblow.com has been created:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Comment</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Ipv 4 Addr</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> nightly-test-a-sub </td>
      <td> false </td>
      <td> 0.0.0.0 </td>
      <td> nightly-test-a-sub.infoblow.com </td>
      <td> record:rpz:a/ZG5zLmJpbmRfYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LG5pZ2h0bHktdGVzdC1hLXN1YiwwLjAuMC4w:nightly-test-a-sub.infoblow.com/default </td>
      <td> record:rpz:a </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-create-aaaa-substitute-record-rule">8. infoblox-create-aaaa-substitute-record-rule</h3>
<hr>
<p>Creates a substitute rule for an AAAA record.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-create-aaaa-substitute-record-rule</code>
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
      <td>name</td>
      <td>The name for a record in FQDN format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rp_zone</td>
      <td>The zone to assign the rule.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>Add a comment for this rule.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ipv6addr</td>
      <td>The IPv6 address of the substitute rule.</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The name of the rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The comment for this rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Type</td>
      <td>string</td>
      <td>The object type as used in Infoblox.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-create-aaaa-substitute-record-rule name="nightly-test-aaaa-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-aaaa-sub" ipv6addr="fd60:e32:f1b9::2" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-aaaa-sub",
        "Disable": false,
        "Ipv6addr": "fd60:e32:f1b9::2",
        "Name": "nightly-test-aaaa-sub.infoblow.com",
        "ReferenceID": "record:rpz:aaaa/ZG5zLmJpbmRfYWFhYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LG5pZ2h0bHktdGVzdC1hYWFhLXN1YixmZDYwOmUzMjpmMWI5Ojoy:nightly-test-aaaa-sub.infoblow.com/default",
        "Type": "record:rpz:aaaa",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: nightly-test-aaaa-sub.infoblow.com has been created:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Comment</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Ipv 6 Addr</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> nightly-test-aaaa-sub </td>
      <td> false </td>
      <td> fd60:e32:f1b9::2 </td>
      <td> nightly-test-aaaa-sub.infoblow.com </td>
      <td> record:rpz:aaaa/ZG5zLmJpbmRfYWFhYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LG5pZ2h0bHktdGVzdC1hYWFhLXN1YixmZDYwOmUzMjpmMWI5Ojoy:nightly-test-aaaa-sub.infoblow.com/default </td>
      <td> record:rpz:aaaa </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-create-mx-substitute-record-rule">9. infoblox-create-mx-substitute-record-rule</h3>
<hr>
<p>Creates a substitute rule for the MX record.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-create-mx-substitute-record-rule</code>
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
      <td>name</td>
      <td>The name for a record in FQDN format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rp_zone</td>
      <td>The zone to assign the rule.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>Add a comment for this rule.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>mail_exchanger</td>
      <td>The mail exchanger name in FQDN format. This value can be in unicode format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>preference</td>
      <td>Preference value, 0 to 65535 (inclusive).</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The name of the rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The comment for this rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Type</td>
      <td>string</td>
      <td>The object type as used in Infoblox.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-create-mx-substitute-record-rule name="nightly-test-mx-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-mx-sub" mail_exchanger="0.0.0.0" preference="5" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-mx-sub",
        "Disable": false,
        "MailExchanger": "0.0.0.0",
        "Name": "nightly-test-mx-sub.infoblow.com",
        "Preference": 5,
        "ReferenceID": "record:rpz:mx/ZG5zLmJpbmRfbXgkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy5uaWdodGx5LXRlc3QtbXgtc3ViLjAuMC4wLjAuNQ:nightly-test-mx-sub.infoblow.com/default",
        "Type": "record:rpz:mx",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: nightly-test-mx-sub.infoblow.com has been created:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Comment</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Mail Exchanger</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Preference</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> nightly-test-mx-sub </td>
      <td> false </td>
      <td> 0.0.0.0 </td>
      <td> nightly-test-mx-sub.infoblow.com </td>
      <td> 5 </td>
      <td> record:rpz:mx/ZG5zLmJpbmRfbXgkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy5uaWdodGx5LXRlc3QtbXgtc3ViLjAuMC4wLjAuNQ:nightly-test-mx-sub.infoblow.com/default </td>
      <td> record:rpz:mx </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-create-naptr-substitute-record-rule">10. infoblox-create-naptr-substitute-record-rule</h3>
<hr>
<p>Creates a substitute rule for a NAPTR record.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-create-naptr-substitute-record-rule</code>
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
      <td>name</td>
      <td>The name for a record in FQDN forma.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rp_zone</td>
      <td>The zone to assign the rule.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>Add a comment for this rule.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>order</td>
      <td>The order parameter of the substitute rule of the NAPTR record. This parameter specifies the order in which the NAPTR rules are applied when multiple rules are present. Can be from 0 to 65535 (inclusive).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>preference</td>
      <td>Preference value, 0 to 65535 (inclusive).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>replacement</td>
      <td>The substitute rule object replacement field of the NAPTR record. For non-terminal NAPTR records, this field specifies the next domain name to look up.</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The name of the rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The comment for this rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Type</td>
      <td>string</td>
      <td>The object type as used in Infoblox.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-create-naptr-substitute-record-rule name="nightly-test-naptr-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-naptr-sub" order="0" preference="1" replacement="infoblow.com" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-naptr-sub",
        "Disable": false,
        "Name": "nightly-test-naptr-sub.infoblow.com",
        "Order": 0,
        "Preference": 1,
        "ReferenceID": "record:rpz:naptr/ZG5zLmJpbmRfbmFwdHIkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdyxuaWdodGx5LXRlc3QtbmFwdHItc3ViLDAsMSwsLCxpbmZvYmxvdy5jb20:nightly-test-naptr-sub.infoblow.com/default",
        "Regexp": "",
        "Replacement": "infoblow.com",
        "Services": "",
        "Type": "record:rpz:naptr",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: nightly-test-naptr-sub.infoblow.com has been created:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Comment</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Order</strong></th>
      <th><strong>Preference</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Regexp</strong></th>
      <th><strong>Replacement</strong></th>
      <th><strong>Services</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> nightly-test-naptr-sub </td>
      <td> false </td>
      <td> nightly-test-naptr-sub.infoblow.com </td>
      <td> 0 </td>
      <td> 1 </td>
      <td> record:rpz:naptr/ZG5zLmJpbmRfbmFwdHIkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdyxuaWdodGx5LXRlc3QtbmFwdHItc3ViLDAsMSwsLCxpbmZvYmxvdy5jb20:nightly-test-naptr-sub.infoblow.com/default </td>
      <td>  </td>
      <td> infoblow.com </td>
      <td>  </td>
      <td> record:rpz:naptr </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-create-ptr-substitute-record-rule">11. infoblox-create-ptr-substitute-record-rule</h3>
<hr>
<p>Creates a substitute rule of the PTR record.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-create-ptr-substitute-record-rule</code>
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
      <td>rp_zone</td>
      <td>The zone to assign the rule.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>Add a comment for this rule.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ptrdname</td>
      <td>The domain name of the RPZ substitute rule object of the PTR record in FQDN format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>name</td>
      <td>The name of the RPZ Substitute rule object of the PTR record in FQDN format.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ipv4addr</td>
      <td>The IPv4 Address of the substitute rule.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ipv6addr</td>
      <td>The IPv6 Address of the substitute rule.</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The name of the rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The Comment for this rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Type</td>
      <td>string</td>
      <td>The object type as used in Infoblox.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-create-ptr-substitute-record-rule rp_zone="infoblow.com" comment="nightly-test-ptr-sub" ptrdname="infoblow.com" ipv4addr="0.0.0.0" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-ptr-sub",
        "Disable": false,
        "Ipv4addr": "0.0.0.0",
        "Name": "0.0.0.0.in-addr.arpa.infoblow.com",
        "Ptrdname": "infoblow.com",
        "ReferenceID": "record:rpz:ptr/ZG5zLmJpbmRfcHRyJC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cuYXJwYS5pbi1hZGRyLjAuMC4wLjAuaW5mb2Jsb3cuY29t:0.0.0.0.in-addr.arpa.infoblow.com/default",
        "Type": "record:rpz:ptr",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: None has been created:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Comment</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Ipv 4 Addr</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Ptrdname</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> nightly-test-ptr-sub </td>
      <td> false </td>
      <td> 0.0.0.0 </td>
      <td> 0.0.0.0.in-addr.arpa.infoblow.com </td>
      <td> infoblow.com </td>
      <td> record:rpz:ptr/ZG5zLmJpbmRfcHRyJC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cuYXJwYS5pbi1hZGRyLjAuMC4wLjAuaW5mb2Jsb3cuY29t:0.0.0.0.in-addr.arpa.infoblow.com/default </td>
      <td> record:rpz:ptr </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-create-srv-substitute-record-rule">12. infoblox-create-srv-substitute-record-rule</h3>
<hr>
<p>Creates a substitute rule of a SRV record.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-create-srv-substitute-record-rule</code>
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
      <td>name</td>
      <td>The name for a record in FQDN format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rp_zone</td>
      <td>The zone to assign the rule.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>Add a comment for this rule.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>port</td>
      <td>The port of the substitute rule of the SRV record. Can be 0 to 65535 (inclusive).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>priority</td>
      <td>The priority of the substitute rule for the SRV Record. Can be 0 to 65535 (inclusive).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>target</td>
      <td>The target of the substitute rule of the SRV record in FQDN format. This value can be in unicode format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>weight</td>
      <td>The weight of the substitute rule of the SRV record. Can be 0 to 65535 (inclusive).</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The rule name.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The comment for this rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Type</td>
      <td>string</td>
      <td>The object type as used in Infoblox.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-create-srv-substitute-record-rule name="nightly-test-srv-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-srv-sub" port="22" priority="10" target="infoblow.com" weight="10" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-srv-sub",
        "Disable": false,
        "Name": "nightly-test-srv-sub.infoblow.com",
        "Port": 22,
        "Priority": 10,
        "ReferenceID": "record:rpz:srv/ZG5zLmJpbmRfc3J2JC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cvbmlnaHRseS10ZXN0LXNydi1zdWIvMTAvMTAvMjIvaW5mb2Jsb3cuY29t:nightly-test-srv-sub.infoblow.com/default",
        "Target": "infoblow.com",
        "Type": "record:rpz:srv",
        "View": "default",
        "Weight": 10,
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: nightly-test-srv-sub.infoblow.com has been created:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Comment</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Port</strong></th>
      <th><strong>Priority</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Target</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Weight</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> nightly-test-srv-sub </td>
      <td> false </td>
      <td> nightly-test-srv-sub.infoblow.com </td>
      <td> 22 </td>
      <td> 10 </td>
      <td> record:rpz:srv/ZG5zLmJpbmRfc3J2JC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cvbmlnaHRseS10ZXN0LXNydi1zdWIvMTAvMTAvMjIvaW5mb2Jsb3cuY29t:nightly-test-srv-sub.infoblow.com/default </td>
      <td> infoblow.com </td>
      <td> record:rpz:srv </td>
      <td> default </td>
      <td> 10 </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-create-txt-substitute-record-rule">13. infoblox-create-txt-substitute-record-rule</h3>
<hr>
<p>Create a substitute rule for a txt record.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-create-txt-substitute-record-rule</code>
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
      <td>name</td>
      <td>The name for a record in FQDN format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rp_zone</td>
      <td>The zone to assign the rule.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>Add a comment for this rule.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>text</td>
      <td>Text associated with the record. To enter leading, trailing, or embedded spaces in the text, add quotes around the text to preserve the spaces.</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The rule name.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The comment for this rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Type</td>
      <td>string</td>
      <td>The object type as used in Infoblox.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-create-txt-substitute-record-rule name="nightly-test-txt-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-txt-sub" text="nightly-test-txt-sub" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-txt-sub",
        "Disable": false,
        "Name": "nightly-test-txt-sub.infoblow.com",
        "ReferenceID": "record:rpz:txt/ZG5zLmJpbmRfdHh0JC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cubmlnaHRseS10ZXN0LXR4dC1zdWIuIm5pZ2h0bHktdGVzdC10eHQtc3ViIg:nightly-test-txt-sub.infoblow.com/default",
        "Text": "nightly-test-txt-sub",
        "Type": "record:rpz:txt",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: nightly-test-txt-sub.infoblow.com has been created:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Comment</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Text</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> nightly-test-txt-sub </td>
      <td> false </td>
      <td> nightly-test-txt-sub.infoblow.com </td>
      <td> record:rpz:txt/ZG5zLmJpbmRfdHh0JC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cubmlnaHRseS10ZXN0LXR4dC1zdWIuIm5pZ2h0bHktdGVzdC10eHQtc3ViIg:nightly-test-txt-sub.infoblow.com/default </td>
      <td> nightly-test-txt-sub </td>
      <td> record:rpz:txt </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-create-ipv4-substitute-record-rule">14. infoblox-create-ipv4-substitute-record-rule</h3>
<hr>
<p>Create a substitute rule for an IPv4 rule.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-create-ipv4-substitute-record-rule</code>
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
      <td>name</td>
      <td>The name for a record in FQDN format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rp_zone</td>
      <td>The zone to assign the rule.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>Add a comment for this rule.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ipv4addr</td>
      <td>The IPv4 Address of the substitute rule.</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The rule name.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The comment for this rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Type</td>
      <td>string</td>
      <td>The object type as used in Infoblox.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-create-ipv4-substitute-record-rule name="3.3.3.3.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-ipv4-sub" ipv4addr="3.3.3.4" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-ipv4-sub",
        "Disable": false,
        "Ipv4addr": "3.3.3.4",
        "Name": "3.3.3.3.infoblow.com",
        "ReferenceID": "record:rpz:a:ipaddress/ZG5zLmJpbmRfYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LHJwei1pcC4zLjMuMy4zLjMyLDMuMy4zLjQ:3.3.3.3.infoblow.com/default",
        "Type": "record:rpz:a:ipaddress",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: 3.3.3.3.infoblow.com has been created:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Comment</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Ipv 4 Addr</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> nightly-test-ipv4-sub </td>
      <td> false </td>
      <td> 3.3.3.4 </td>
      <td> 3.3.3.3.infoblow.com </td>
      <td> record:rpz:a:ipaddress/ZG5zLmJpbmRfYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LHJwei1pcC4zLjMuMy4zLjMyLDMuMy4zLjQ:3.3.3.3.infoblow.com/default </td>
      <td> record:rpz:a:ipaddress </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-create-ipv6-substitute-record-rule">15. infoblox-create-ipv6-substitute-record-rule</h3>
<hr>
<p>Creates a substitute of the IPv6 record rule.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-create-ipv6-substitute-record-rule</code>
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
      <td>name</td>
      <td>The name for a record in FQDN format.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rp_zone</td>
      <td>The zone to assign the rule.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>Add a comment for this rule.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ipv6addr</td>
      <td>The IPv6 Address of the substitute rule.</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The rule name.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The comment for this rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Type</td>
      <td>string</td>
      <td>The object type as used in Infoblox.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-create-ipv6-substitute-record-rule name="000:000:000::1.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-ipv6-sub" ipv6addr="fd60:e22:f1b9::2" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-ipv6-sub",
        "Disable": false,
        "Ipv6addr": "fd60:e22:f1b9::2",
        "Name": "::1.infoblow.com",
        "ReferenceID": "record:rpz:aaaa:ipaddress/ZG5zLmJpbmRfYWFhYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LHJwei1pcC56ei4xLjEyOCxmZDYwOmUyMjpmMWI5Ojoy:%3A%3A1.infoblow.com/default",
        "Type": "record:rpz:aaaa:ipaddress",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: 000:000:000::1.infoblow.com has been created:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Comment</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Ipv 6 Addr</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> nightly-test-ipv6-sub </td>
      <td> false </td>
      <td> fd60:e22:f1b9::2 </td>
      <td> ::1.infoblow.com </td>
      <td> record:rpz:aaaa:ipaddress/ZG5zLmJpbmRfYWFhYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LHJwei1pcC56ei4xLjEyOCxmZDYwOmUyMjpmMWI5Ojoy:%3A%3A1.infoblow.com/default </td>
      <td> record:rpz:aaaa:ipaddress </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-enable-rule">16. infoblox-enable-rule</h3>
<hr>
<p>Disables a rule by its reference ID (reference ID could be extracted by running the searah rules command).</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-enable-rule</code>
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
      <td>reference_id</td>
      <td>The ID of the rule reference (could be extracted by running the search rules command).</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The rule comment.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The rule name.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The response policy zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-enable-rule reference_id="record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Canonical": "4.4.4.5.infoblow.com",
        "Disable": false,
        "Name": "4.4.4.5.infoblow.com",
        "ReferenceID": "record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: 4.4.4.5.infoblow.com has been enabled</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Canonical</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 4.4.4.5.infoblow.com </td>
      <td> false </td>
      <td> 4.4.4.5.infoblow.com </td>
      <td> record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-disable-rule">17. infoblox-disable-rule</h3>
<hr>
<p>Disable a rule by its reference ID (reference ID could be extracted by running the 'infoblox-search-rule' command).</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-disable-rule</code>
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
      <td>reference_id</td>
      <td>The ID of the rule reference (reference ID could be extracted by running the 'infoblox-search-rule' command).</td>
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
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Disable</td>
      <td>boolean</td>
      <td>Whether this rule is disabled.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Comment</td>
      <td>string</td>
      <td>The rule comment.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Name</td>
      <td>string</td>
      <td>The rule name.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID</td>
      <td>string</td>
      <td>The ID of the rule reference.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.Zone</td>
      <td>string</td>
      <td>The response policy zone to which this rule belongs.</td>
    </tr>
    <tr>
      <td>Infoblox.ModifiedResponsePolicyZoneRules.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-disable-rule reference_id="record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Canonical": "4.4.4.5.infoblow.com",
        "Disable": true,
        "Name": "4.4.4.5.infoblow.com",
        "ReferenceID": "record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Response Policy Zone rule: 4.4.4.5.infoblow.com has been disabled</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Canonical</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 4.4.4.5.infoblow.com </td>
      <td> true </td>
      <td> 4.4.4.5.infoblow.com </td>
      <td> record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-get-object-fields">18. infoblox-get-object-fields</h3>
<hr>
<p>Returns the object fields names which can be used in the search rules command.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-get-object-fields</code>
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
      <td>object_type</td>
      <td>The Infoblox object type (can be retrieved by running the 'infoblox-list-response-policy-zone-rules' command).</td>
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
      <td>Infoblox.ObjectFields.ObjectType</td>
      <td>string</td>
      <td>The Infoblox object type.</td>
    </tr>
    <tr>
      <td>Infoblox.ObjectFields.SupportedFields</td>
      <td>string</td>
      <td>The list of supported fields for this object.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-get-object-fields object_type="record:rpz:cname" </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.ObjectFields": {
        "ObjectType": "record:rpz:cname",
        "SupportedFields": [
            "canonical",
            "comment",
            "disable",
            "extattrs",
            "name",
            "rp_zone",
            "ttl",
            "use_ttl",
            "view",
            "zone"
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Object record:rpz:cname supported fields: </h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Field Names</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> canonical </td>
    </tr>
    <tr>
      <td> comment </td>
    </tr>
    <tr>
      <td> disable </td>
    </tr>
    <tr>
      <td> extattrs </td>
    </tr>
    <tr>
      <td> name </td>
    </tr>
    <tr>
      <td> rp_zone </td>
    </tr>
    <tr>
      <td> ttl </td>
    </tr>
    <tr>
      <td> use_ttl </td>
    </tr>
    <tr>
      <td> view </td>
    </tr>
    <tr>
      <td> zone </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-search-rule">19. infoblox-search-rule</h3>
<hr>
<p>Searches a specific rule by its name.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-search-rule</code>
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
      <td>object_type</td>
      <td>The Infoblox object type (can be retrieved by running the 'infoblox-list-response-policy-zone-rules' command).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The full rule name (usually the rule name followed by its zone. Example: name.domain.com)</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>output_fields</td>
      <td>The fields to include in the return object (supported object fields can be retrieved by running the *infoblox-get-object-fields* command).</td>
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
      <td>Infoblox.RulesSearchResults.Name</td>
      <td>string</td>
      <td>The rule name.</td>
    </tr>
    <tr>
      <td>Infoblox.RulesSearchResults.ReferenceID</td>
      <td>string</td>
      <td>The reference ID of the rule.</td>
    </tr>
    <tr>
      <td>Infoblox.RulesSearchResults.View</td>
      <td>string</td>
      <td>The view of the definition.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-search-rule object_type="record:rpz:cname" rule_name="4.4.4.5.infoblow.com" output_fields="canonical,comment,disable,extattrs,name,rp_zone,ttl,use_ttl,view,zone"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Infoblox.RulesSearchResults": [
        {
            "Canonical": "4.4.4.5.infoblow.com",
            "Disable": false,
            "Extattrs": {},
            "Name": "4.4.4.5.infoblow.com",
            "ReferenceID": "record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default",
            "UseTtl": false,
            "View": "default",
            "Zone": "infoblow.com"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Infoblox Integration - Search result for: 4.4.4.5.infoblow.com: </h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Canonical</strong></th>
      <th><strong>Disable</strong></th>
      <th><strong>Extattrs</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Reference ID</strong></th>
      <th><strong>Use Ttl</strong></th>
      <th><strong>View</strong></th>
      <th><strong>Zone</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 4.4.4.5.infoblow.com </td>
      <td> false </td>
      <td>  </td>
      <td> 4.4.4.5.infoblow.com </td>
      <td> record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default </td>
      <td> false </td>
      <td> default </td>
      <td> infoblow.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="infoblox-delete-rpz-rule">20. infoblox-delete-rpz-rule</h3>
<hr>
<p>Deletes a rule.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-delete-rpz-rule</code>
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
      <td>reference_id</td>
      <td>The reference ID of the rule (reference ID can be retrieved by running the 'infoblox-search-rule' command).</td>
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
  <code>!infoblox-delete-rpz-rule reference_id=record:rpz:ptr/ZG5zLmJpbmRfcHRyJC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cuYXJwYS5pbi1hZGRyLjAuMC4wLjAuaW5mb2Jsb3cuY29t:0.0.0.0.in-addr.arpa.infoblow.com/default</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
Infoblox Integration - A rule with the following id was deleted: 
 record:rpz:ptr/ZG5zLmJpbmRfcHRyJC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cuYXJwYS5pbi1hZGRyLjAuMC4wLjAuaW5mb2Jsb3cuY29t:0.0.0.0.in-addr.arpa.infoblow.com/default
</p>
</p>

<h3 id="infoblox-delete-response-policy-zone">21. infoblox-delete-response-policy-zone</h3>
<hr>
<p>Deletes a given response policy zone.</p>
<h5>Base Command</h5>
<p>
  <code>infoblox-delete-response-policy-zone</code>
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
      <td>reference_id</td>
      <td>The reference ID of the rule (could be extracted by running the search rules command).</td>
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
  <code>!infoblox-delete-response-policy-zone reference_id="zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50cGIubmlnaHRseS5pbmZvbmxveA:infonlox.nightly.tpb.com/default\"</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
Infoblox Integration - Response Policy Zone with the following id was deleted: 
 zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50cGIubmlnaHRseS5pbmZvbmxveA:infonlox.nightly.tpb.com/default
</p>
</p>
<h2>Additional Information</h2>
<p>
    In order to create new rule for a response policy zone for all rules different from substitute record use the command 'create-rpz-rule'. For substitute record rules use the designated command for each use case.
</p>
<h2>Known Limitations</h2><h2>Troubleshooting</h2>

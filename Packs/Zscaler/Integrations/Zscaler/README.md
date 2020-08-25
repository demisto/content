<!-- HTML_DOC -->
<p>Use the Zscaler integration to block manage domains using whitelists and blacklists.</p>
<p>In order that the integration will work properly, one must use a Zscaler user with admin permissions.</p>
<p>Category ID is the same as the category name, except all letters are capitalized and each word is separated with an underscored instead of spaces. For example, if the category name is Other Education, then the Category ID is OTHER_EDUCATION.</p>
<p>Custom category ID has the format <code>CUSTOM_01</code>, which is not indicative of the category. Use the using <code style="font-size: 13px;">zscaler-get-categories </code>command to get a custom category and its configured name.</p>
<h2>Configure the Zscaler Integration on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Zscaler.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Cloud Name</strong></li>
<li><strong>Credentials</strong></li>
<li><strong>Password</strong></li>
<li><strong>API Key</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and token.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_72704990741530445377113">Return information for a URL: url</a></li>
<li><a href="#h_606653445161530445696735">Return information for an IP address: ip</a></li>
<li><a href="#h_986896988321530446495994">Add URLs to the whitelist: zscaler-whitelist-url</a></li>
<li><a href="#h_946436799521530446728370">Add URLs to the blacklist: zscaler-blacklist-url</a></li>
<li><a href="#h_2799418871001530447071560">Add IP addresses to the whitelist: zscaler-whitelist-ip</a></li>
<li><a href="#h_1046709421281530447220542">Add IP addresses to the blacklist: zscaler-blacklist-ip</a></li>
<li><a href="#h_1292906881601530447452325">Remove URLs from the whitelist: zscaler-undo-whitelist-url</a></li>
<li><a href="#h_6236117861961530447626104">Remove URLs from the blacklist: zcaler-undo-blacklist-url</a></li>
<li><a href="#h_7946287922361530447749430">Remove IP addresses from the whitelist: zscaler-undo-whitelist-ip</a></li>
<li><a href="#h_1313179502801530447828500">Remove IP addresses from the blacklist: zscaler-undo-blacklist-ip</a></li>
<li><a href="#h_23094662441533240711403">Add a URL address to a category: zscaler-category-add-url</a></li>
<li><a href="#h_9026902511211533240731253">Add an IP address to a category: zscaler-category-add-ip</a></li>
<li><a href="#h_6610309801971533240744267">Remove a URL address from a category: zscaler-category-remove-url</a></li>
<li><a href="#h_3806347742721533240755284">Remove an IP address from a category: zscaler-category-remove-ip</a></li>
<li><a href="#h_654309151761534745757240">Return a list of categories: zscaler-get-categories</a></li>
<li><a href="#h_298989072761537086943237">Return the default blacklist: zscaler-get-blacklist</a></li>
<li><a href="#h_8266012961761537086952350">Return the default whitelist: zscaler-get-whitelist</a></li>
<li>Get a report for an MD5 hash: zscaler-sandbox-report</li>
</ol>
<hr>
<h3 id="h_72704990741530445377113">1. Return information for a URL: url</h3>
<p>Returns information about a specified URL.</p>
<h5>Base Command</h5>
<p><code>url</code></p>
<h5>Input</h5>
<table style="height: 223px; width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 327px;"><strong>Path</strong></td>
<td style="width: 453px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 327px;">url</td>
<td style="width: 453px;">URL to return information for</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 223px; width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 301px;"><strong>Path</strong></td>
<td style="width: 479px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 301px;">URL.Address</td>
<td style="width: 479px;">URL that was searched</td>
</tr>
<tr>
<td style="width: 301px;">URL.urlClassifications</td>
<td style="width: 479px;">URL classification</td>
</tr>
<tr>
<td style="width: 301px;">URL.urlClassificationsWithSecurityAlert</td>
<td style="width: 479px;">Classifications with security alert of the URL</td>
</tr>
<tr>
<td style="width: 301px;">URL.Malicious.Vendor</td>
<td style="width: 479px;">For malicious URLs, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 301px;">URL.Malicious.Description</td>
<td style="width: 479px;">For malicious URLs, the reason for the vendor to make the decision</td>
</tr>
<tr>
<td style="width: 301px;">DBotScore.Indicator</td>
<td style="width: 479px;">The tested indicator</td>
</tr>
<tr>
<td style="width: 301px;">DBotScore.Type</td>
<td style="width: 479px;">Indicator type</td>
</tr>
<tr>
<td style="width: 301px;">DBotScore.Vendor</td>
<td style="width: 479px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 301px;">DBotScore.Score</td>
<td style="width: 479px;">The actual score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[
{
"url": "facebook.com",
"urlClassifications": "SOCIAL_NETWORKING",
"urlClassificationsWithSecurityAlert": ""
}
]
</pre>
<hr>
<h3 id="h_606653445161530445696735">2. Return information for an IP address: ip</h3>
<p>Returns information about a specified IP address.</p>
<h5>Base Command</h5>
<p><code>ip</code></p>
<h5>Input</h5>
<table style="height: 223px; width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 327px;"><strong>Path</strong></td>
<td style="width: 453px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 327px;">ip</td>
<td style="width: 453px;">IP to return information for</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 223px; width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 301px;"><strong>Path</strong></td>
<td style="width: 479px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 301px;">IP.Address</td>
<td style="width: 479px;">IP address that was searched</td>
</tr>
<tr>
<td style="width: 301px;">IP.urlClassifications</td>
<td style="width: 479px;">IP address classification</td>
</tr>
<tr>
<td style="width: 301px;">IP.urlClassificationsWithSecurityAlert</td>
<td style="width: 479px;">Classifications with security alert of the IP address</td>
</tr>
<tr>
<td style="width: 301px;">IP.Malicious.Vendor</td>
<td style="width: 479px;">For malicious IP addresses, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 301px;">IP.Malicious.Description</td>
<td style="width: 479px;">For malicious IP addresses, the reason for the vendor to make the decision</td>
</tr>
<tr>
<td style="width: 301px;">DBotScore.Indicator</td>
<td style="width: 479px;">The tested indicator</td>
</tr>
<tr>
<td style="width: 301px;">DBotScore.Type</td>
<td style="width: 479px;">Indicator type</td>
</tr>
<tr>
<td style="width: 301px;">DBotScore.Vendor</td>
<td style="width: 479px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 301px;">DBotScore.Score</td>
<td style="width: 479px;">The actual score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "ip":"8.8.8.8",
      "ipClassifications":"WEB_SEARCH",
      "ipClassificationsWithSecurityAlert":""
   }
]
</pre>
<hr>
<h3 id="h_986896988321530446495994">3. Add a URL to the whitelist</h3>
<p>Comma-separated list that adds specified URLs to the whitelist.</p>
<h5>Base Command</h5>
<p><code>zscaler-whitelist-url</code></p>
<h5>Input</h5>
<table style="height: 223px; width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 327px;"><strong>Path</strong></td>
<td style="width: 453px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 327px;">url</td>
<td style="width: 453px;">Comma-separated list of URLs to add to the whitelist</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Added the following URLs to the whitelist successfully:
phishing.com
malware.net
</pre>
<hr>
<h3 id="h_946436799521530446728370">4. Add a URL to the blacklist</h3>
<p>Comma-separated list that adds specified URLs to the blacklist.</p>
<h5>Base Command</h5>
<p><code>zscaler-blacklist-url</code></p>
<h5>Input</h5>
<table style="height: 223px; width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 327px;"><strong>Path</strong></td>
<td style="width: 453px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 327px;">url</td>
<td style="width: 453px;">Comma-separated list of URLs to add to the blacklist</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Added the following URLs to the blacklist successfully:</pre>
<p>phishing.com</p>
<p>malware.net</p>
<pre> </pre>
<hr>
<h3 id="h_2799418871001530447071560">5. Add IP addresses to the whitelist</h3>
<p>Comma-separated list that adds specified IP addresses to the whitelist.</p>
<h5>Base Command</h5>
<p><code>zscaler-whitelist-ip</code></p>
<h5>Input</h5>
<table style="height: 223px; width: 746px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 244px;"><strong>Path</strong></td>
<td style="width: 536px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 244px;">ip</td>
<td style="width: 536px;">Comma-separated list of IP addresses to add to the whitelist</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Added the following IP addresses to the whitelist successfully:
2.2.2.2
3.3.3.3
</pre>
<hr>
<h3 id="h_1046709421281530447220542">6. Add IP addresses to the blacklist: zscaler-blacklist-ip</h3>
<p>Comma-separated list that adds specified IP addresses to the blacklist.</p>
<h5>Base Command</h5>
<p><code>zscaler-blacklist-ip</code></p>
<h5>Input</h5>
<table style="height: 223px; width: 746px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 235px;"><strong>Path</strong></td>
<td style="width: 545px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 235px;">ip</td>
<td style="width: 545px;">Comma-separated list of IP addresses to add to the blacklist</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Added the following IP addresses to the blacklist successfully:
2.2.2.2
3.3.3.3
</pre>
<hr>
<h3 id="h_1292906881601530447452325">7. Remove URLs from the whitelist</h3>
<p>Comma-separated list that removes specified URLs from the whitelist.</p>
<h5>Base Command</h5>
<p><code>zscaler-undo-whitelist-url</code></p>
<h5>Input</h5>
<table style="height: 223px; width: 746px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 235px;"><strong>Path</strong></td>
<td style="width: 545px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 235px;">url</td>
<td style="width: 545px;">Comma-separated list of URLs to remove from the whitelist</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Removed the following URLs from the whitelist successfully:
phishing.com
malware.net
</pre>
<hr>
<h3 id="h_6236117861961530447626104">8. Remove URLs from the blacklist: zcaler-undo-blacklist-url</h3>
<p>Comma-separated list that removes specified URLs from the blacklist.</p>
<h5>Base Command</h5>
<p><code>zscaler-undo-whitelist-url</code></p>
<h5>Input</h5>
<table style="height: 223px; width: 746px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 235px;"><strong>Path</strong></td>
<td style="width: 545px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 235px;">url</td>
<td style="width: 545px;">Comma-separated list of URLs to remove from the blacklist</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Removed the following URLs from the blacklist successfully:
phishing.com
malware.net
</pre>
<hr>
<h3 id="h_7946287922361530447749430">9. Remove IP addresses from the whitelist</h3>
<p>Comma-separated list that removes specified IP addresses from the whitelist.</p>
<h5>Base Command</h5>
<p><code>zscaler-undo-whitelist-ip</code></p>
<h5>Input</h5>
<table style="height: 223px; width: 746px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 235px;"><strong>Path</strong></td>
<td style="width: 545px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 235px;">url</td>
<td style="width: 545px;">Comma-separated list of IP addresses to remove from the whitelist</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Removed the following IP addresses from the whitelist successfully:
2.2.2.2
3.3.3.3
</pre>
<hr>
<h3 id="h_1313179502801530447828500">10. Remove IP addresses from the blacklist</h3>
<p>Comma-separated list that removes specified IP addresses from the blacklist.</p>
<h5>Base Command</h5>
<p><code>zscaler-undo-blacklist-ip</code></p>
<h5>Input</h5>
<table style="height: 223px; width: 746px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 235px;"><strong>Path</strong></td>
<td style="width: 545px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 235px;">url</td>
<td style="width: 545px;">Comma-separated list of IP addresses to remove from the blacklist</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Removed the following IP addresses from the whitelist successfully:
2.2.2.2
3.3.3.3
</pre>
<hr>
<h3 id="h_23094662441533240711403">11. Add a URL address to a category</h3>
<p>Adds a URL address to a specified category.</p>
<h5>Base Command</h5>
<p><code>zscaler-category-add-url</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 153.8px;"><strong>Argument Name</strong></th>
<th style="width: 414.2px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153.8px;">category-id</td>
<td style="width: 414.2px;">Category ID to add the URL to, for example RADIO_STATIONS</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 153.8px;">url</td>
<td style="width: 414.2px;">URL address to add to the category. Comma separated values supported, for example, pandora.com,spotify.com</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Zscaler.Category.CustomCategory</td>
<td>boolean</td>
<td>True if category is custom</td>
</tr>
<tr>
<td>Zscaler.Category.Description</td>
<td>string</td>
<td>Category description</td>
</tr>
<tr>
<td>Zscaler.Category.ID</td>
<td>string</td>
<td>Category ID</td>
</tr>
<tr>
<td>Zscaler.Category.URL</td>
<td>unknown</td>
<td>List of category URL addresses</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!zscaler-category-add-url category-id=MUSIC url=demisto.com,apple.com</code></p>
<p><code></code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Zscaler": {
      "Category": {
        "CustomCategory": false,
        "Description": "MUSIC_DESC",
        "ID": "MUSIC",
        "URL": [
            "demisto.com",
            "apple.com"
        ]
      }
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p>Added the following URL addresses to category MUSIC:</p>
<ul>
<li>demisto.com</li>
<li>apple.com</li>
</ul>
<hr>
<h3 id="h_9026902511211533240731253">12. Add an IP address to a category</h3>
<p>Adds an IP address to a specified category.</p>
<h5>Base Command</h5>
<p><code>zscaler-category-add-ip</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 161.8px;"><strong>Argument Name</strong></th>
<th style="width: 406.2px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 161.8px;">category-id</td>
<td style="width: 406.2px;">Category ID to add IP to, for example RADIO_STATIONS</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 161.8px;">ip</td>
<td style="width: 406.2px;">IP address to add to the category. Comma separated values supported, for example 8.8.8.8,1.2.3.4</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Zscaler.Category.CustomCategory</td>
<td>boolean</td>
<td>True if category is custom</td>
</tr>
<tr>
<td>Zscaler.Category.Description</td>
<td>string</td>
<td>Category description</td>
</tr>
<tr>
<td>Zscaler.Category.ID</td>
<td>string</td>
<td>Category ID</td>
</tr>
<tr>
<td>Zscaler.Category.URL</td>
<td>unknown</td>
<td>List of category URL addresses</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!zscaler-category-add-ip category-id=REFERENCE_SITES ip=1.2.3.4,8.8.8.8</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Zscaler": {
      "Category": {
        "CustomCategory": false,
        "Description": "REFERENCE_SITES_DESC",
        "ID": "REFERENCE_SITES",
        "URL": [
            "1.2.3.4",
            "8.8.8.8"
        ]
      }
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p>Added the following IP addresses to category REFERENCE_SITES:</p>
<ul>
<li>1.2.3.4</li>
<li>8.8.8.8</li>
</ul>
<hr>
<h3 id="h_6610309801971533240744267">13. Remove a URL address from a category</h3>
<p>Removes a URL address from a specified category.</p>
<h5>Base Command</h5>
<p><code>zscaler-category-remove-url</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 145.6px;"><strong>Argument Name</strong></th>
<th style="width: 422.4px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145.6px;">category-id</td>
<td style="width: 422.4px;">Category ID to remove URL from, for example RADIO_STATIONS</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145.6px;">url</td>
<td style="width: 422.4px;">URL address to remove from the category. Comma separated values supported, for example pandora.com,spotify.com</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Zscaler.Category.CustomCategory</td>
<td>boolean</td>
<td>True if category is custom</td>
</tr>
<tr>
<td>Zscaler.Category.Description</td>
<td>string</td>
<td>Category description</td>
</tr>
<tr>
<td>Zscaler.Category.ID</td>
<td>string</td>
<td>Category ID</td>
</tr>
<tr>
<td>Zscaler.Category.URL</td>
<td>unknown</td>
<td>List of category URL addresses</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!zscaler-category-remove-url category-id=MUSIC url=apple.com</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Zscaler": {
      "Category": {
        "CustomCategory": false,
        "Description": "MUSIC_DESC",
        "ID": "MUSIC",
        "URL": [
            "demisto.com"
        ]
      }
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p>Removed the following URL addresses to category MUSIC:</p>
<ul>
<li>apple.com</li>
</ul>
<hr>
<h3 id="h_3806347742721533240755284">14. Remove an IP address from a category</h3>
<p>Removes an IP address from a specified category.</p>
<h5>Base Command</h5>
<p><code>zscaler-category-remove-ip</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 133.2px;"><strong>Argument Name</strong></th>
<th style="width: 434.8px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133.2px;">category-id</td>
<td style="width: 434.8px;">Category ID to remove IP from, for example RADIO_STATIONS</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133.2px;">ip</td>
<td style="width: 434.8px;">IP address to remove from the category. Comma separated values supported, for example 8.8.8.8,1.2.3.4</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Zscaler.Category.CustomCategory</td>
<td>boolean</td>
<td>True if category is custom</td>
</tr>
<tr>
<td>Zscaler.Category.Description</td>
<td>string</td>
<td>Category description</td>
</tr>
<tr>
<td>Zscaler.Category.ID</td>
<td>string</td>
<td>Category ID</td>
</tr>
<tr>
<td>Zscaler.Category.URL</td>
<td>unknown</td>
<td>List of category URL addresses</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!zscaler-category-remove-ip category-id=REFERENCE_SITES ip=1.2.3.4</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Zscaler": {
      "Category": {
        "CustomCategory": false,
        "Description": "REFERENCE_SITES_DESC",
        "ID": "REFERENCE_SITES",
        "URL": [
            "8.8.8.8"
        ]
      }
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p>Removed the following IP addresses to category REFERENCE_SITES:</p>
<ul>
<li>1.2.3.4</li>
</ul>
<p> </p>
<h3>15. Return a list of categories</h3>
<hr>
<p>Returns a list of all categories.</p>
<h5>Base Command</h5>
<p><code>zscaler-get-categories</code></p>
<h5>Input</h5>
<p>There is no input for t his command.</p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Zscaler.Category.ID</td>
<td>string</td>
<td>Category ID</td>
</tr>
<tr>
<td>Zscaler.Category.CustomCategory</td>
<td>boolean</td>
<td>True if category is custom, else false.</td>
</tr>
<tr>
<td>Zscaler.Category.URL</td>
<td>string</td>
<td>List of category URL addresses</td>
</tr>
<tr>
<td>Zscaler.Category.Description</td>
<td>string</td>
<td>Category description</td>
</tr>
<tr>
<td>Zscaler.Category.Name</td>
<td>string</td>
<td>Category name</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!zscaler-get-categories</code></p>
<h5>Context Example</h5>
<pre>{  
   "Zscaler":{  
      "Category":{  
         "ID":"INTERNET_SERVICES",
         "Description":"INTERNET_SERVICES_DESC",
         "URL":[  
            "google.com",
            "facebook.com"
         ],
         "CustomCategory":"false"
      },
      "ID":"CUSTOM_01",
      "Name":"CustomCategory",
      "URL":[  
         "demisto.com",
         "apple.com"
      ],
      "CustomCategory":"true"
   }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<h3 id="h_654309151761534745757240">Zscaler Categories</h3>
<table border="2" cellpadding="6">
<thead>
<tr>
<th>CustomCategory</th>
<th>Description</th>
<th>ID</th>
<th>Name</th>
<th>URL</th>
</tr>
</thead>
<tbody>
<tr>
<td>false</td>
<td>INTERNET_SERVICES_DESC</td>
<td>INTERNET_SERVICES</td>
<td> </td>
<td>google.com,facebook.com</td>
</tr>
<tr>
<td>true</td>
<td> </td>
<td>CUSTOM_01</td>
<td>CustomCategory</td>
<td>demisto.com,apple.com</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_298989072761537086943237">16. Return the default blacklist</h3>
<hr>
<p>Returns the default Zscaler blacklist.</p>
<h5>Base Command</h5>
<p><code>zscaler-get-blacklist</code></p>
<h5>Input</h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Zscaler.Blacklist</td>
<td>string</td>
<td>Default Zscaler blacklist</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!zscaler-get-blacklist</code></p>
<h5>Context Example</h5>
<pre>{
    "Zscaler": {
        "Blacklist": [
            "malicious.com,
            "bad.net"
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Zscaler blacklist</h3>
<ul>
<li>malicious.com</li>
<li>bad.net</li>
</ul>
<h3 id="h_8266012961761537086952350">17. Return the default whitelist</h3>
<hr>
<p>Returns the default Zscaler whitelist.</p>
<h5>Base Command</h5>
<p><code>zscaler-get-whitelist</code></p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Zscaler.Whitelist</td>
<td>string</td>
<td>Defualt Zsclaer whitelist</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!zscaler-get-whitelist</code></p>
<h5>Context Example</h5>
<pre>{
    "Zscaler": {
        "Whitelist": [
            "demisto.com,
            "apple.com"
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Zscaler whitelist</h3>
<ul>
<li>demisto.com</li>
<li>apple.net</li>
</ul>
<h3>18. Get a report for an MD5 hash</h3>
<hr>
<p>Gets a full report or a summary detail report for an MD5 hash of a file that was analyzed by Zscaler Sandbox.</p>
<h5>Base Command</h5>
<p><code>zscaler-sandbox-report</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 430px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">md5</td>
<td style="width: 430px;">MD5 hash of a file.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 137px;">details</td>
<td style="width: 430px;">Report type (full or summary).</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 187px;"><strong>Path</strong></th>
<th style="width: 49px;"><strong>Type</strong></th>
<th style="width: 472px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 187px;">File.MD5</td>
<td style="width: 49px;">string</td>
<td style="width: 472px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 187px;">File.Malicious.Vendor</td>
<td style="width: 49px;">string</td>
<td style="width: 472px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 187px;">File.Malicious.Description</td>
<td style="width: 49px;">string</td>
<td style="width: 472px;">For malicious files, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 187px;">File.DetectedMalware</td>
<td style="width: 49px;">string</td>
<td style="width: 472px;">Malware that was detected.</td>
</tr>
<tr>
<td style="width: 187px;">File.FileType</td>
<td style="width: 49px;">string</td>
<td style="width: 472px;">The file type.</td>
</tr>
<tr>
<td style="width: 187px;">DBotScore.Indicator</td>
<td style="width: 49px;">string</td>
<td style="width: 472px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 187px;">DBotScore.Type</td>
<td style="width: 49px;">string</td>
<td style="width: 472px;">Indicator type.</td>
</tr>
<tr>
<td style="width: 187px;">DBotScore.Vendor</td>
<td style="width: 49px;">string</td>
<td style="width: 472px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 187px;">DBotScore.Score</td>
<td style="width: 49px;">number</td>
<td style="width: 472px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!zscaler-sandbox-report md5=3FD0EA0AE759D58274310C022FB0CBBA details=summary</code></p>
<h5>Context Example</h5>
<pre><code>{
    "DBotScore": {
        "Vendor": "Zscaler", 
        "Indicator": "3FD0EA0AE759D58274310C022FB0CBBA", 
        "Score": 3, 
        "Type": "file"
    }, 
    "File": {
        "Zscaler": {
            "FileType": null, 
            "DetectedMalware": ""
        }, 
        "Malicious": {
            "Vendor": "Zscaler", 
            "Description": "Classified as Malicious, with threat score: 100"
        }, 
        "MD5": "3FD0EA0AE759D58274310C022FB0CBBA"
    }
}
</code></pre>
<h5>Human Readable Output</h5>
<h3>Full Sandbox Report</h3>
<table border="2">
<thead>
<tr>
<th>Category</th>
<th>Indicator</th>
<th>Vendor</th>
<th>Score</th>
<th>Zscaler Score</th>
<th>Type</th>
</tr>
</thead>
<tbody>
<tr>
<td>MALWARE_BOTNET</td>
<td>3FD0EA0AE759D58274310C022FB0CBBA</td>
<td>Zscaler</td>
<td>3</td>
<td>100</td>
<td>file</td>
</tr>
<tr>
<td>None</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3>More information</h3>
<h2>Screenshots</h2>
<p><a href="https://user-images.githubusercontent.com/44546251/56854828-8a921480-6945-11e9-8784-cb55e6c7d83e.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/44546251/56854828-8a921480-6945-11e9-8784-cb55e6c7d83e.png" alt="image"></a></p>
<p><a href="https://user-images.githubusercontent.com/44546251/56854735-291d7600-6944-11e9-8c05-b917cc25e322.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/44546251/56854735-291d7600-6944-11e9-8c05-b917cc25e322.png" alt="image"></a></p>
<!-- HTML_DOC -->
<p>Forcepoint is an advanced threat protection product with added local management controls.</p>
<p>The Forcepoint-XSOAR integration allows you to create and manage custom categories.</p>
<h3>To set up Forcepoint to work with Cortex XSOAR:</h3>
<ul>
<li>Make sure you have administrator permissions.</li>
<li>Make sure you have port 15873 open.</li>
</ul>
<h3>To set up the integration on Cortex XSOAR:</h3>
<ol>
<li>Go to ‘Settings &gt; Integrations &gt; Servers &amp; Services’</li>
<li>Locate ‘Forcepoint ’ by searching for it using the search box on the top of the page.</li>
<li>Click ‘Add instance’ to create and configure a new integration. You should configure the following settings:<br><strong>Name</strong>: A textual name for the integration instance.<br><strong>Server URL</strong>: API Server URL.<br><strong>Username and Password: </strong>The username and password for accessing the integration.<br><strong>Use system proxy settings: </strong>Specify whether to communicate with the integration via the system proxy server or not.<br><strong>Do not validate server certificate: </strong>Select in case you wish to circumvent server certification validation.  You may want to do this in case the server you are connecting to does not have a valid certificate.<strong><br></strong><strong>Cortex XSOAR engine</strong>: If relevant, select the engine that acts as a proxy to the server. Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Cortex XSOAR server from accessing the remote networks.<br>For more information on Cortex XSOAR engines see:<br><a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Engines">Cortex XSOAR 6.13 - Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Engines">Cortex XSOAR 8 Cloud- Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Engines">Cortex XSOAR 8.7 On-prem - Engines</a>
</li>
<li>Press the ‘Test’ button to validate connection.
</li>
<li>After completing the test successfully, press the ‘Done’ button.</li>
</ol>
<h3>Fetched incidents data:</h3>
<p>This integration does not fetch incidents.</p>
<h3> Top Use-cases:</h3>
<p>Forcepoint integration can be used to create a block list category for URL and IP addresses.</p>
<p>A possible flow of commands could be:</p>
<ol>
<li>Use ‘fp-add-category’ to add a new category. The new category will automatically be set to block access.</li>
<li>Use ‘fp-get-category-details’ to get the new category ID.</li>
<li>Use ‘fp-add-addresses-to-category’ to add URLs and/or IP addresses to the category. Use the category name or ID as identifier.</li>
<li>Use ‘fp-delete-addresses-from-category’ to remove URLs and/or IP addresses from the category.</li>
</ol>
<p>The integration can also be used to view a detailed list of managed categories. Use ‘fp-list-categories’ to view all Forceoint categories or only categories managed by the integration.</p>
<h3>Commands:</h3>
<ul>
<li style="font-family: courier;"><strong>fp-list-categories</strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>Option to list all categories or only API-managed categories (default).</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>```</p>
<p>{</p>
<p>Forcepoint: {</p>
<p>            ListCategories: [</p>
<p>{</p>
<p>CategoryDescription: Sites that provide information about or that sell or provide curriculum materials or direct instruction; also, learned journals and similar publications.</p>
<p>CategoryID: 118</p>
<p>CategoryName: Educational Materials</p>
<p>CategoryOwner: Forcepoint</p>
<p>CategoryParent: Education</p>
<p>}</p>
<p>                        ]</p>
<p>}</p>
<p>```</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p><strong>```</strong></p>
<p>[</p>
<p>{</p>
<p>Category Description: Parent category that contains categories known to consume bandwidth resources.</p>
<p>Category Hierarchy: 890</p>
<p>Category ID: 116</p>
<p>Category Name: Bandwidth</p>
<p>Category Owner: Forcepoint</p>
<p>CategoryParent:</p>
<p>Children: [</p>
<p>{</p>
<p>Category Description: Sites that store personal files on Internet servers for backup or exchange.</p>
<p>Category Hierarchy: 1510</p>
<p>Category ID: 113</p>
<p>Category Name: Personal Network Storage and Backup</p>
<p>Category Owner: Forcepoint</p>
<p>CategoryParent: Bandwidth</p>
<p>}</p>
<p>]</p>
<p>            }</p>
<p>            ]</p>
<p><strong>```</strong></p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;">
<p>fp-get-category-details</p>
</li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>category name or  ID</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>{</p>
<p>Forcepoint: {</p>
<p>            CategoryDetails: {</p>
<p>                         CategoryID: 116</p>
<p>                         CategoryName: Bandwidth</p>
<p>                         IPs: []  </p>
<p>                         URLs: []</p>
<p>                                    }</p>
<p>                       }</p>
<p> }</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>```</strong></p>
<p>{</p>
<p>       Category ID: 116</p>
<p>       Category Name: Bandwidth</p>
<p>       IPs: []  </p>
<p>       URLs: []</p>
<p>}</p>
<p><strong>```</strong></p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>fp-add-category</strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>category name, category description, category parent.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>```</strong></p>
<p>{</p>
<p>            Forcepoint: {</p>
<p>                        Add Category: {</p>
<p>Categories:</p>
<p>[</p>
<p>{ Category Name: Test category }</p>
<p>                                                ]</p>
<p>}</p>
<p>                        }</p>
<p>            }</p>
<p> </p>
<p> </p>
<p>                                   </p>
<p><strong>```</strong></p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>```</p>
<p>{</p>
<p>Categories: [</p>
<p>{ Category Name: Test category }</p>
<p>                        ]</p>
<p>}</p>
<p>```</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>fp-add-addresses-to-category</strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>Category name or  ID , list of URLs and/or list of IP addresses.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>```</strong></p>
<p>            {</p>
<p>                        Forcepoint: {</p>
<p>                                    AddAddressToCategory: {</p>
<p>Category ID: 1932</p>
<p>Category Name:</p>
<p>Totals: {</p>
<p>Added IPs: 0</p>
<p>Added URLs: 1</p>
<p>                        }</p>
<p>            }</p>
<p>}</p>
<p>            }          </p>
<p><strong>```</strong><strong><br></strong></p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>```</p>
<p>{</p>
<p>Category ID: 1932</p>
<p>Category Name:</p>
<p>Totals: {</p>
<p>Added IPs: 0</p>
<p>Added URLs: 1</p>
<p>                        }</p>
<p>            }</p>
<p>```</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>fp-delete-addresses-from-category</strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>category name or  ID , list of URLs and/or list of IP addresses.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>```</strong></p>
<p>            {</p>
<p>                        Forcepoint: {</p>
<p>                                    AddAddressToCategory: {</p>
<p>Category ID: 1932</p>
<p>Category Name:</p>
<p>Totals: {</p>
<p>Deleted IPs: 0</p>
<p>Deleted URLs: 1</p>
<p>                        }</p>
<p>            }</p>
<p>}</p>
<p>            }</p>
<p><strong>```</strong></p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>```</p>
<p>{</p>
<p>Category ID: 1932</p>
<p>Category Name:</p>
<p>Totals: {</p>
<p>Deleted IPs: 0</p>
<p>Deleted URLs: 1</p>
<p>                        }</p>
<p>            }</p>
<p>```</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>fp-delete-category</strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>List of category names or  IDs</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>```</strong></p>
<p>{</p>
<p>Forcepoint: {</p>
<p>            DeletedCategories: [</p>
<p>{</p>
<p>CategoryID: 116</p>
<p>CategoryName: Bandwidth</p>
<p>IPs: []  </p>
<p>URLs: []</p>
<p>},</p>
<p>…</p>
<p>                                                ]                      </p>
<p>            }</p>
<p>            }</p>
<p><strong>```</strong></p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>```</p>
<p>{</p>
<p>Category ID: 116</p>
<p>Category Name: Bandwidth</p>
<p>IPs: []  </p>
<p>URLs: []</p>
<p>},</p>
<p>…</p>
<p>            ]</p>
<p><strong>```</strong></p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Additional info:</h3>
<p><strong>URL restrictions and clarifications:</strong></p>
<ul>
<li>Only the hostname field (part of the authority) is required.</li>
<li>Other parts are optional, but can be used to define a stricter match.</li>
<li>CGI parameters (anything after the "?" in a URL) are automatically removed from the URL.</li>
<li>If no protocol is specified, the following protocols will be added to the database: <br>http://, https://, and ftp://.</li>
<li>URLs can be added to more than one category. When the URL is matched, all categories for the URL are returned for use in policy enforcement.</li>
</ul>
<p><strong>IP addresses restrictions and clarification:</strong></p>
<ul>
<li>IP addresses and ranges are as specified by IPv4 and IPv6.</li>
<li>IP addresses and ranges can be added to more than one category. When an IP address is matched, all categories for the IP address are returned for use in policy enforcement.</li>
</ul>
<h3>Known Limitations</h3>
<ul>
<li>New category will automatically be set to block access. You may change category access with Forcepoint TRITON manager.</li>
</ul>
<h3>Troubleshooting</h3>
<ul>
<li>
<strong>Failed attempts to add/delete URL or IP addresses</strong> to a category might be caused by invalid category name or ID.<br>Invalid category name/ID indicates one of the following:
<ul>
<li>The category does not exist.</li>
<li>The ID/name belongs to a Forcepoint-defined category.</li>
<li>The ID/name belongs to a custom category defined via the TRITON Manager.</li>
</ul>
</li>
</ul>
<ul>
<li>
<strong>Failed attempts to create a new category</strong> might be caused by:
<ul>
<li>The name provided is associated with another category.</li>
</ul>
</li>
</ul>
<ul>
<li>
<strong>Recurring error ‘Another transaction is in process …’</strong>:<br>This error might rise when running a playbook with parallel tasks assigned to the integration commands.<br>This error is caused by the Forcepoint data enforcement protocol. Any request to update/add/delete a category cannot run in parallel to another request of this type.<br>If this error arises, try to avoid assigning the following commands to parallel tasks:
<ul>
<li>‘fp-add-category’</li>
<li>‘fp-add-addresses-to-category’</li>
<li>‘fp-delete-addresses-from-category’</li>
<li>‘fp-delete-category’</li>
</ul>
</li>
</ul>
<p> </p>
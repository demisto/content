<!-- HTML_DOC -->
<p>Use the VulnDB integration to get information about vulnerabilities for various products, including operating systems, applications, and so on.</p>
<h2>
<a id="Configure_VulnDB_on_Demisto_2"></a>Configure VulnDB on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for VulnDB.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Hostname, IP address, or server URL</strong></li>
<li><strong>Client ID</strong></li>
<li><strong>Client Secret</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>
<a id="Commands_15"></a>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_87eccbb7-b791-43e3-bc50-751655f9fac9" target="_self">Get information for a vulnerability (ID): vulndb-get-vuln-by-id</a></li>
<li><a href="#h_7da6d70b-7f4d-4a84-b289-af5f1ee3118d" target="_self">Get information for a vendor: vulndb-get-vendor</a></li>
<li><a href="#h_6dca1b8a-18a8-411a-8f60-6b8304853068" target="_self">Get a list of product versions: vulndb-get-product</a></li>
<li><a href="#h_3270cd83-c23d-4a82-b312-92c9e78d21c8" target="_self">Get the version of a single product: vulndb-get-version</a></li>
<li><a href="#h_cce1e236-2e89-4fc0-aa37-a4ffa401bbf1" target="_self">Get a list of recent vulnerabilities: vulndb-get-updates-by-dates-or-hours</a></li>
<li><a href="#h_a1997885-8f58-44c0-97db-9fc75c3f368e" target="_self">Get information for a vulnerability (vendor name and product name): vulndb-get-vuln-by-vendor-and-product-name</a></li>
<li><a href="#h_55e0eb99-4e57-423d-a349-f31dfe56269e" target="_self">Get information for a vulnerability (vendor ID and product ID): vulndb-get-vuln-by-vendor-and-product-id</a></li>
<li><a href="#h_21475f01-9ada-47dd-a4ff-1891ac74be95" target="_self">Get information for a vulnerability (vendor ID): vulndb-get-vuln-by-vendor-id</a></li>
<li><a href="#h_45fded2f-0807-4475-9e29-f99f211d5052" target="_self">Get information for a vulnerability (product ID): vulndb-get-vuln-by-product-id</a></li>
<li><a href="#h_e32ddd90-9b43-4fc7-bc72-b27216e8077f" target="_self">Get information for a vulnerability (CVE ID): vulndb-get-vuln-by-cve-id</a></li>
</ol>
<h3 id="h_87eccbb7-b791-43e3-bc50-751655f9fac9">
<a id="1_Get_information_for_a_vulnerability_ID_27"></a>1. Get information for a vulnerability (ID)</h3>
<hr>
<p>Returns full details about a specific vulnerability.</p>
<h5>
<a id="Base_Command_30"></a>Base Command</h5>
<p><code>vulndb-get-vuln-by-id</code></p>
<h5>
<a id="Input_33"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 170px;"><strong>Argument Name</strong></th>
<th style="width: 479px;"><strong>Description</strong></th>
<th style="width: 91px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170px;">vuln_id</td>
<td style="width: 479px;">ID of the vulnerability for which to return information.</td>
<td style="width: 91px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_40"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 333px;"><strong>Path</strong></th>
<th style="width: 57px;"><strong>Type</strong></th>
<th style="width: 350px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.ID</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability ID.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.Title</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability title (human readable).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.Keywords</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability keywords.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.Description</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability description (human readable).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.Solution</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability solution (human readable).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.PublishedDate</td>
<td style="width: 57px;">date</td>
<td style="width: 350px;">Vulnerability published date.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.TDescription</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability description (human readable).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.SolutionDate</td>
<td style="width: 57px;">date</td>
<td style="width: 350px;">Vulnerability solution date.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.DiscoveryDate</td>
<td style="width: 57px;">date</td>
<td style="width: 350px;">Vulnerability discovery date.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.ExploitPublishDate</td>
<td style="width: 57px;">date</td>
<td style="width: 350px;">Exploit publish date.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CVE-ExtReferences.Value</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVE (constant string).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.Id</td>
<td style="width: 57px;">number</td>
<td style="width: 350px;">CVSS reference value.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.AccessVector</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS access vector.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.AccessComplexity</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS access complexity.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.Authentication</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS metric authentication.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.ConfidentialityImpact</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS confidentiality impact.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.cvssMetrics.IntegrityImpact</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS integrity impact.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.AvailabilityImpact</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS availability impact.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.GeneratedOn</td>
<td style="width: 57px;">date</td>
<td style="width: 350px;">CVSS metric date.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.Score</td>
<td style="width: 57px;">number</td>
<td style="width: 350px;">CVSS score.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vendor.Id</td>
<td style="width: 57px;">number</td>
<td style="width: 350px;">Vendor ID.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vendor.Name</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vendor name.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Products.Id</td>
<td style="width: 57px;">number</td>
<td style="width: 350px;">Product IDs.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Products.Name</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Product names.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Products.Versions.Id</td>
<td style="width: 57px;">number</td>
<td style="width: 350px;">Product version IDs.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Products.Versions.Name</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Product version names.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Classification.Longname</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Classification name (long).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Classification.Description</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Classification description (human-readable).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_74"></a>Command Example</h5>
<pre>!vulndb-get-vuln-by-id vuln_id="1"</pre>
<h5>
<a id="Human_Readable_Output_77"></a>Human Readable Output</h5>
<h3 id="h_7da6d70b-7f4d-4a84-b289-af5f1ee3118d">
<a id="2_Get_information_for_a_vendor_80"></a>2. Get information for a vendor</h3>
<hr>
<p>Returns all, or specific, vendor details to include vendor name and ID.</p>
<h5>
<a id="Base_Command_83"></a>Base Command</h5>
<p><code>vulndb-get-vendor</code></p>
<h5>
<a id="Input_86"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 148px;"><strong>Argument Name</strong></th>
<th style="width: 521px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">vendor_id</td>
<td style="width: 521px;">Vendor ID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">vendor_name</td>
<td style="width: 521px;">Vendor name (only human-readable).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">max_size</td>
<td style="width: 521px;">Maximum number of entries to return. A high number of entries might affect performance.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_95"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 280px;"><strong>Path</strong></th>
<th style="width: 74px;"><strong>Type</strong></th>
<th style="width: 386px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 280px;">VulnDB.Results.Id</td>
<td style="width: 74px;">number</td>
<td style="width: 386px;">Result ID.</td>
</tr>
<tr>
<td style="width: 280px;">VulnDB.Results.Name</td>
<td style="width: 74px;">string</td>
<td style="width: 386px;">Result name.</td>
</tr>
<tr>
<td style="width: 280px;">VulnDB.Results.ShortName</td>
<td style="width: 74px;">string</td>
<td style="width: 386px;">Result short name.</td>
</tr>
<tr>
<td style="width: 280px;">VulnDB.Results.VendorUrl</td>
<td style="width: 74px;">string</td>
<td style="width: 386px;">Result vendor URL (human-readable).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_105"></a>Command Example</h5>
<pre>!vulndb-get-vendor max_size="20"</pre>
<h5>
<a id="Human_Readable_Output_108"></a>Human Readable Output</h5>
<h3 id="h_6dca1b8a-18a8-411a-8f60-6b8304853068">
<a id="3_Get_a_list_of_product_versions_111"></a>3. Get a list of product versions</h3>
<hr>
<p>Returns a list of versions by product name or ID.</p>
<h5>
<a id="Base_Command_114"></a>Base Command</h5>
<p><code>vulndb-get-product</code></p>
<h5>
<a id="Input_117"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 522px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">vendor_id</td>
<td style="width: 522px;">Vendor ID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 147px;">vendor_name</td>
<td style="width: 522px;">Vendor name.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 147px;">max_size</td>
<td style="width: 522px;">Maximum number of entries to return. A high number of entries might effect performance.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_126"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 381px;"><strong>Path</strong></th>
<th style="width: 129px;"><strong>Type</strong></th>
<th style="width: 230px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 381px;">VulnDB.Results.Id</td>
<td style="width: 129px;">number</td>
<td style="width: 230px;">Result ID.</td>
</tr>
<tr>
<td style="width: 381px;">VulnDB.Results.Name</td>
<td style="width: 129px;">string</td>
<td style="width: 230px;">Result name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_134"></a>Command Example</h5>
<pre>!vulndb-get-product vendor_id="2974649" max_size="20"</pre>
<h5>
<a id="Human_Readable_Output_137"></a>Human Readable Output</h5>
<h3 id="h_3270cd83-c23d-4a82-b312-92c9e78d21c8">
<a id="4_Get_the_version_of_a_single_product_140"></a>4. Get the version of a single product</h3>
<hr>
<p>Returns the version of the specified product.</p>
<h5>
<a id="Base_Command_143"></a>Base Command</h5>
<p><code>vulndb-get-version</code></p>
<h5>
<a id="Input_146"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 156px;"><strong>Argument Name</strong></th>
<th style="width: 513px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 156px;">product_name</td>
<td style="width: 513px;">Product name.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 156px;">product_id</td>
<td style="width: 513px;">Product ID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 156px;">max_size</td>
<td style="width: 513px;">Maximum number of entries to return. A high number of entries might effect performance.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_155"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 357px;"><strong>Path</strong></th>
<th style="width: 149px;"><strong>Type</strong></th>
<th style="width: 234px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 357px;">VulnDB.Results.Id</td>
<td style="width: 149px;">number</td>
<td style="width: 234px;">Version ID.</td>
</tr>
<tr>
<td style="width: 357px;">VulnDB.Results.Name</td>
<td style="width: 149px;">Unknown</td>
<td style="width: 234px;">Version name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_163"></a>Command Example</h5>
<pre>!vulndb-get-version product_name="1-Search" max_size="20"</pre>
<h5>
<a id="Human_Readable_Output_166"></a>Human Readable Output</h5>
<h3 id="h_cce1e236-2e89-4fc0-aa37-a4ffa401bbf1">
<a id="5_Get_a_list_of_recent_vulnerabilities_169"></a>5. Get a list of recent vulnerabilities</h3>
<hr>
<p>Returns recent vulnerabilities, by date or number of hours.</p>
<h5>
<a id="Base_Command_172"></a>Base Command</h5>
<p><code>vulndb-get-updates-by-dates-or-hours</code></p>
<h5>
<a id="Input_175"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 155px;"><strong>Argument Name</strong></th>
<th style="width: 514px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">start_date</td>
<td style="width: 514px;">Start date for which to return vulnerabilities.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">end_date</td>
<td style="width: 514px;">End date for which to return vulnerabilities.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">hours_ago</td>
<td style="width: 514px;">Number of previous hours for which to return vulnerabilities.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">max_size</td>
<td style="width: 514px;">Maximum number of entries to return. A high number of entries might effect performance.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_185"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 325px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 350px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 325px;">VulnDB.Vulnerability.ID</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Vulnerability ID.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Vulnerability.Title</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Vulnerability title (human-readable).</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Vulnerability.Keywords</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Vulnerability keywords.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Vulnerability.Description</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Vulnerability description (human-readable).</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Vulnerability.Solution</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Vulnerability solution (human readable).</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Vulnerability.PublishedDate</td>
<td style="width: 65px;">date</td>
<td style="width: 350px;">Vulnerability published date.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Vulnerability.TDescription</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Vulnerability description (human-readable).</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Vulnerability.SolutionDate</td>
<td style="width: 65px;">date</td>
<td style="width: 350px;">Vulnerability solution date.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Vulnerability.DiscoveryDate</td>
<td style="width: 65px;">date</td>
<td style="width: 350px;">Vulnerability discovery date.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Vulnerability.ExploitPublishDate</td>
<td style="width: 65px;">date</td>
<td style="width: 350px;">Exploit publish date.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.CVE-ExtReferences.Value</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">CVE (constant string).</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.CvssMetrics.Id</td>
<td style="width: 65px;">number</td>
<td style="width: 350px;">CVSS reference value.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.CvssMetrics.AccessVector</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">CVSS access vector.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.CvssMetrics.AccessComplexity</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Cvss access complexity</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.CvssMetrics.Authentication</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">CVSS metric authentication.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.CvssMetrics.ConfidentialityImpact</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">CVSS confidentiality impact.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.cvssMetrics.integrity_impact</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">CVSS integrity impact.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.CvssMetrics.AvailabilityImpact</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">CVSS availability impact.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.CvssMetrics.Generated_on</td>
<td style="width: 65px;">date</td>
<td style="width: 350px;">CVSS metric date.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.CvssMetrics.Score</td>
<td style="width: 65px;">number</td>
<td style="width: 350px;">CVSS score.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Vendors.Id</td>
<td style="width: 65px;">number</td>
<td style="width: 350px;">Vendor ID.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Vendor.Name</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Vendor name.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Products.Id</td>
<td style="width: 65px;">number</td>
<td style="width: 350px;">Product IDs.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Products.Name</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Product names.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Products.Versions.Id</td>
<td style="width: 65px;">number</td>
<td style="width: 350px;">Product version IDs.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Products.Versions.Name</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Product version names.</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Classification.Longname</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Classification name (long).</td>
</tr>
<tr>
<td style="width: 325px;">VulnDB.Classification.Description</td>
<td style="width: 65px;">string</td>
<td style="width: 350px;">Classification description (human-readable).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_219"></a>Command Example</h5>
<pre>!vulndb-get-updates-by-dates-or-hours start_date="2015-10-27T04:27:22" end_date="2017-10-27T04:27:22" max_size="20"</pre>
<h3 id="h_a1997885-8f58-44c0-97db-9fc75c3f368e">
<a id="6_Get_information_for_a_vulnerability_vendor_name_and_product_name_224"></a>6. Get information for a vulnerability (vendor name and product name)</h3>
<hr>
<p>Returns full details about a specific vulnerability, by vendor name and product name.</p>
<h5>
<a id="Base_Command_227"></a>Base Command</h5>
<p><code>vulndb-get-vuln-by-vendor-and-product-name</code></p>
<h5>
<a id="Input_230"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 155px;"><strong>Argument Name</strong></th>
<th style="width: 514px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">vendor_name</td>
<td style="width: 514px;">Vendor name.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">product_name</td>
<td style="width: 514px;">Product name.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">max_size</td>
<td style="width: 514px;">Maximum number of entries to return. A high number of entries might affect performance.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_239"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 328px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 349px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 328px;">VulnDB.Vulnerability.ID</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">Vulnerability ID.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Vulnerability.Title</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">Vulnerability title (human-readable).</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Vulnerability.Keywords</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">Vulnerability keywords.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Vulnerability.Description</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">Vulnerability description (human-readable).</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Vulnerability.Solution</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">Vulnerability solution (human-readable).</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Vulnerability.PublishedDate</td>
<td style="width: 63px;">date</td>
<td style="width: 349px;">Vulnerability published date.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Vulnerability.TDescription</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">Vulnerability description (human-readable).</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Vulnerability.SolutionDate</td>
<td style="width: 63px;">date</td>
<td style="width: 349px;">Vulnerability solution date.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Vulnerability.DiscoveryDate</td>
<td style="width: 63px;">date</td>
<td style="width: 349px;">Vulnerability discovery date.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Vulnerability.ExploitPublishDate</td>
<td style="width: 63px;">date</td>
<td style="width: 349px;">Exploit publish date.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.CVE-ExtReferences.Value</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">CVE (constant string).</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.CvssMetrics.Id</td>
<td style="width: 63px;">number</td>
<td style="width: 349px;">CVSS reference value.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.CvssMetrics.AccessVector</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">CVSS access vector.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.CvssMetrics.AccessComplexity</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">CVSS access complexity.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.CvssMetrics.Authentication</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">CVSS metric authentication.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.CvssMetrics.ConfidentialityImpact</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">CVSS confidentiality impact.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.cvssMetrics.integrity_impact</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">CVSS integrity impact.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.CvssMetrics.AvailabilityImpact</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">CVSS availability impact.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.CvssMetrics.Generated_on</td>
<td style="width: 63px;">date</td>
<td style="width: 349px;">CVSS metric date.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.CvssMetrics.Score</td>
<td style="width: 63px;">number</td>
<td style="width: 349px;">CVSS score.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Vendors.Id</td>
<td style="width: 63px;">number</td>
<td style="width: 349px;">Vendor ID.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Vendor.Name</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">Vendor name.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Products.Id</td>
<td style="width: 63px;">number</td>
<td style="width: 349px;">Product IDs.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Products.Name</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">Product names.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Products.Versions.Id</td>
<td style="width: 63px;">number</td>
<td style="width: 349px;">Product version IDs.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Products.Versions.Name</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">Product version names.</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Classification.Longname</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">Classification (name).</td>
</tr>
<tr>
<td style="width: 328px;">VulnDB.Classification.Description</td>
<td style="width: 63px;">string</td>
<td style="width: 349px;">Classification description (human-readable).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_273"></a>Command Example</h5>
<pre>!vulndb-get-vuln-by-vendor-and-product-name vendor_name="Adobe Systems Incorporated" product_name="ColdFusion" max_size="20"</pre>
<h3 id="h_55e0eb99-4e57-423d-a349-f31dfe56269e">
<a id="7_Get_information_for_a_vulnerability_vendor_ID_and_product_ID_279"></a>7. Get information for a vulnerability (vendor ID and product ID)</h3>
<hr>
<p>Returns full details about a specific vulnerability, by vendor ID and product ID.</p>
<h5>
<a id="Base_Command_282"></a>Base Command</h5>
<p><code>vulndb-get-vuln-by-vendor-and-product-id</code></p>
<h5>
<a id="Input_285"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 158px;"><strong>Argument Name</strong></th>
<th style="width: 511px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 158px;">vendor_id</td>
<td style="width: 511px;">Vendor ID.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 158px;">product_id</td>
<td style="width: 511px;">Product ID.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 158px;">max_size</td>
<td style="width: 511px;">Maximum number of entries to return. A high number of entries might affect performance.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_294"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 750px;">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>VulnDB.Vulnerability.ID</td>
<td>string</td>
<td>Vulnerability ID.</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.Title</td>
<td>string</td>
<td>Vulnerability title (human-readable).</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.Keywords</td>
<td>string</td>
<td>Vulnerability keywords.</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.Description</td>
<td>string</td>
<td>Vulnerability description (human-readable).</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.Solution</td>
<td>string</td>
<td>Vulnerability solution (human-readable).</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.PublishedDate</td>
<td>date</td>
<td>Vulnerability published date.</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.TDescription</td>
<td>string</td>
<td>Vulnerability description (human-readable).</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.SolutionDate</td>
<td>date</td>
<td>Vulnerability solution date.</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.DiscoveryDate</td>
<td>date</td>
<td>Vulnerability discovery date.</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.ExploitPublishDate</td>
<td>date</td>
<td>Exploit publish date.</td>
</tr>
<tr>
<td>VulnDB.CVE-ExtReferences.Value</td>
<td>string</td>
<td>CVE (constant string).</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.Id</td>
<td>number</td>
<td>CVSS reference value.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.AccessVector</td>
<td>string</td>
<td>CVSS access vector.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.AccessComplexity</td>
<td>string</td>
<td>CVSS access complexity.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.Authentication</td>
<td>string</td>
<td>CVSS metric authentication.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.ConfidentialityImpact</td>
<td>string</td>
<td>CVSS confidentiality impact.</td>
</tr>
<tr>
<td>VulnDB.cvssMetrics.integrity_impact</td>
<td>string</td>
<td>CVSS integrity impact.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.AvailabilityImpact</td>
<td>string</td>
<td>CVSS availability impact.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.Generated_on</td>
<td>date</td>
<td>CVSS metric date.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.Score</td>
<td>number</td>
<td>CVSS score.</td>
</tr>
<tr>
<td>VulnDB.Vendors.Id</td>
<td>number</td>
<td>Vendor ID.</td>
</tr>
<tr>
<td>VulnDB.Vendor.Name</td>
<td>string</td>
<td>Vendor name.</td>
</tr>
<tr>
<td>VulnDB.Products.Id</td>
<td>number</td>
<td>Product IDs.</td>
</tr>
<tr>
<td>VulnDB.Products.Name</td>
<td>string</td>
<td>Product names.</td>
</tr>
<tr>
<td>VulnDB.Products.Versions.Id</td>
<td>number</td>
<td>Product version IDs.</td>
</tr>
<tr>
<td>VulnDB.Products.Versions.Name</td>
<td>string</td>
<td>Product version names.</td>
</tr>
<tr>
<td>VulnDB.Classification.Longname</td>
<td>string</td>
<td>Classification name (long).</td>
</tr>
<tr>
<td>VulnDB.Classification.Description</td>
<td>string</td>
<td>Classification description (human-readable).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_328"></a>Command Example</h5>
<pre>!vulndb-get-vuln-by-vendor-and-product-id vendor_id="5011" product_id="1777" max_size="20"</pre>
<h5>
<a id="Human_Readable_Output_331"></a>Human Readable Output</h5>
<h3 id="h_21475f01-9ada-47dd-a4ff-1891ac74be95">
<a id="8_Get_information_for_a_vulnerability_vendor_ID_334"></a>8. Get information for a vulnerability (vendor ID)</h3>
<hr>
<p>Returns full details about vulnerabilities, by vendor ID.</p>
<h5>
<a id="Base_Command_337"></a>Base Command</h5>
<p><code>vulndb-get-vuln-by-vendor-id</code></p>
<h5>
<a id="Input_340"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 140px;"><strong>Argument Name</strong></th>
<th style="width: 529px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 140px;">vendor_id</td>
<td style="width: 529px;">Vendor ID.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 140px;">max_size</td>
<td style="width: 529px;">Maximum number of entries to return. A high number of entries might effect performance.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_348"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 750px;">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>VulnDB.Vulnerability.ID</td>
<td>string</td>
<td>Vulnerability ID.</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.Title</td>
<td>string</td>
<td>Vulnerability title (human-readable).</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.Keywords</td>
<td>string</td>
<td>Vulnerability keywords.</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.Description</td>
<td>string</td>
<td>Vulnerability description (human-readable).</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.Solution</td>
<td>string</td>
<td>Vulnerability solution (human-readable).</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.PublishedDate</td>
<td>date</td>
<td>Vulnerability published date.</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.TDescription</td>
<td>string</td>
<td>Vulnerability description (human-readable).</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.SolutionDate</td>
<td>date</td>
<td>Vulnerability solution date.</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.DiscoveryDate</td>
<td>date</td>
<td>Vulnerability discovery date.</td>
</tr>
<tr>
<td>VulnDB.Vulnerability.ExploitPublishDate</td>
<td>date</td>
<td>Exploit publish date.</td>
</tr>
<tr>
<td>VulnDB.CVE-ExtReferences.Value</td>
<td>string</td>
<td>CVE (constant string).</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.Id</td>
<td>number</td>
<td>CVSS reference value.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.AccessVector</td>
<td>string</td>
<td>CVSS access vector.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.AccessComplexity</td>
<td>string</td>
<td>CVSS access complexity.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.Authentication</td>
<td>string</td>
<td>CVSS metric authentication.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.ConfidentialityImpact</td>
<td>string</td>
<td>CVSS confidentiality impact.</td>
</tr>
<tr>
<td>VulnDB.cvssMetrics.integrity_impact</td>
<td>string</td>
<td>CVSS integrity impact.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.AvailabilityImpact</td>
<td>string</td>
<td>CVSS availability impact.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.Generated_on</td>
<td>date</td>
<td>CVSS metric date.</td>
</tr>
<tr>
<td>VulnDB.CvssMetrics.Score</td>
<td>number</td>
<td>CVSS score.</td>
</tr>
<tr>
<td>VulnDB.Vendors.Id</td>
<td>number</td>
<td>Vendor ID.</td>
</tr>
<tr>
<td>VulnDB.Vendor.Name</td>
<td>string</td>
<td>Vendor name.</td>
</tr>
<tr>
<td>VulnDB.Products.Id</td>
<td>number</td>
<td>Product IDs.</td>
</tr>
<tr>
<td>VulnDB.Products.Name</td>
<td>string</td>
<td>Product names.</td>
</tr>
<tr>
<td>VulnDB.Products.Versions.Id</td>
<td>number</td>
<td>Product version IDs.</td>
</tr>
<tr>
<td>VulnDB.Products.Versions.Name</td>
<td>string</td>
<td>Product version names.</td>
</tr>
<tr>
<td>VulnDB.Classification.Longname</td>
<td>string</td>
<td>Classification (name).</td>
</tr>
<tr>
<td>VulnDB.Classification.Description</td>
<td>string</td>
<td>Classification description (human-readable).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_382"></a>Command Example</h5>
<pre>!vulndb-get-vuln-by-vendor-id vendor_id="5011" max_size="20"</pre>
<h3 id="h_45fded2f-0807-4475-9e29-f99f211d5052">
<a id="9_Get_information_for_a_vulnerability_product_ID_386"></a>9. Get information for a vulnerability (product ID)</h3>
<hr>
<p>Returns full details about vulnerabilities, by product ID.</p>
<h5>
<a id="Base_Command_389"></a>Base Command</h5>
<p><code>vulndb-get-vuln-by-product-id</code></p>
<h5>
<a id="Input_392"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 522px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">product_id</td>
<td style="width: 522px;">Product ID.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">max_size</td>
<td style="width: 522px;">Maximum number of entries to return. A high number of entries might affect performance.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_400"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 333px;"><strong>Path</strong></th>
<th style="width: 57px;"><strong>Type</strong></th>
<th style="width: 350px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.ID</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability ID.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.Title</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability title (human-readable).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.Keywords</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability keywords.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.Description</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability description (human-readable).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.Solution</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability solution (human-readable).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.PublishedDate</td>
<td style="width: 57px;">date</td>
<td style="width: 350px;">Vulnerability published date.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.TDescription</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vulnerability description (human-readable).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.SolutionDate</td>
<td style="width: 57px;">date</td>
<td style="width: 350px;">Vulnerability solution date.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.DiscoveryDate</td>
<td style="width: 57px;">date</td>
<td style="width: 350px;">Vulnerability discovery date.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vulnerability.ExploitPublishDate</td>
<td style="width: 57px;">date</td>
<td style="width: 350px;">Exploit publish date.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CVE-ExtReferences.Value</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVE (constant string).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.Id</td>
<td style="width: 57px;">number</td>
<td style="width: 350px;">CVSS reference value.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.AccessVector</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS access vector.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.AccessComplexity</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS access complexity.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.Authentication</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS metric authentication.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.ConfidentialityImpact</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS confidentiality impact.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.cvssMetrics.integrity_impact</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS integrity impact.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.AvailabilityImpact</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">CVSS availability impact.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.Generated_on</td>
<td style="width: 57px;">date</td>
<td style="width: 350px;">CVSS metric date.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.CvssMetrics.Score</td>
<td style="width: 57px;">number</td>
<td style="width: 350px;">CVSS score.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vendors.Id</td>
<td style="width: 57px;">number</td>
<td style="width: 350px;">Vendor ID.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Vendor.Name</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Vendor name.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Products.Id</td>
<td style="width: 57px;">number</td>
<td style="width: 350px;">Products ID.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Products.Name</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Product names.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Products.Versions.Id</td>
<td style="width: 57px;">number</td>
<td style="width: 350px;">Product version IDs.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Products.Versions.Name</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Product version names.</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Classification.Longname</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Classification (name).</td>
</tr>
<tr>
<td style="width: 333px;">VulnDB.Classification.Description</td>
<td style="width: 57px;">string</td>
<td style="width: 350px;">Classification description (human-readable).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_434"></a>Command Example</h5>
<pre>!vulndb-get-vuln-by-product-id product_id="1777" max_size="20"</pre>
<h3 id="h_e32ddd90-9b43-4fc7-bc72-b27216e8077f">
<a id="10_Get_information_for_a_vulnerability_CVE_ID_438"></a>10. Get information for a vulnerability (CVE ID)</h3>
<hr>
<p>Returns full details about vulnerabilities, by CVE ID.</p>
<h5>
<a id="Base_Command_441"></a>Base Command</h5>
<p><code>vulndb-get-vuln-by-cve-id</code></p>
<h5>
<a id="Input_444"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 160px;"><strong>Argument Name</strong></th>
<th style="width: 509px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160px;">cve</td>
<td style="width: 509px;">CVE ID.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 160px;">max_size</td>
<td style="width: 509px;">Maximum number of entries to return. A high number of entries might effect performance.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_452"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 334px;"><strong>Path</strong></th>
<th style="width: 56px;"><strong>Type</strong></th>
<th style="width: 350px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334px;">VulnDB.Vulnerability.ID</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">Vulnerability ID.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Vulnerability.Title</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">Vulnerability title (human-readable).</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Vulnerability.Keywords</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">Vulnerability keywords.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Vulnerability.Description</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">Vulnerability description (human-readable).</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Vulnerability.Solution</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">Vulnerability solution (human-readable).</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Vulnerability.PublishedDate</td>
<td style="width: 56px;">date</td>
<td style="width: 350px;">Vulnerability published date.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Vulnerability.TDescription</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">Vulnerability description (human-readable).</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Vulnerability.SolutionDate</td>
<td style="width: 56px;">date</td>
<td style="width: 350px;">Vulnerability solution date.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Vulnerability.DiscoveryDate</td>
<td style="width: 56px;">date</td>
<td style="width: 350px;">Vulnerability discovery date.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Vulnerability.ExploitPublishDate</td>
<td style="width: 56px;">date</td>
<td style="width: 350px;">Exploit publish date.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.CVE-ExtReferences.Value</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">CVE (constant string).</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.CvssMetrics.Id</td>
<td style="width: 56px;">number</td>
<td style="width: 350px;">CVSS reference value.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.CvssMetrics.AccessVector</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">CVSS access vector.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.CvssMetrics.AccessComplexity</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">CVSS access complexity.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.CvssMetrics.Authentication</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">CVSS metric authentication.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.CvssMetrics.ConfidentialityImpact</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">CVSS confidentiality impact.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.cvssMetrics.integrity_impact</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">CVSS integrity impact.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.CvssMetrics.AvailabilityImpact</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">CVSS availability impact.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.CvssMetrics.Generated_on</td>
<td style="width: 56px;">date</td>
<td style="width: 350px;">CVSS metric date.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.CvssMetrics.Score</td>
<td style="width: 56px;">number</td>
<td style="width: 350px;">CVSS score.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Vendors.Id</td>
<td style="width: 56px;">number</td>
<td style="width: 350px;">Vendor ID.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Vendor.Name</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">Vendor name.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Products.Id</td>
<td style="width: 56px;">number</td>
<td style="width: 350px;">Product IDs.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Products.Name</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">Product names.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Products.Versions.Id</td>
<td style="width: 56px;">number</td>
<td style="width: 350px;">Product version IDs.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Products.Versions.Name</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">Product version names.</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Classification.Longname</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">Classification name (long).</td>
</tr>
<tr>
<td style="width: 334px;">VulnDB.Classification.Description</td>
<td style="width: 56px;">string</td>
<td style="width: 350px;">Classification description (human-readable).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_486"></a>Command Example</h5>
<pre>!vulndb-get-vuln-by-cve-id cve="2013-1228" max_size="20"</pre>
### vulndb-get-vuln-report-by-vuln-id

***
Returns the PDF report for a vulnerability as generated by VulnDB

#### Base Command

`vulndb-get-vuln-report-by-vuln-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vuln_id | ID of the vulnerability for which to return information. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | unknown | Name of the report | 
| InfoFile.EntryID | unknown | Entry ID of the report | 
| InfoFile.Size | unknown | Report size | 
| InfoFile.Type | unknown | Report type e.g. "PDF" | 
| InfoFile.Info | unknown | Basic info about the report | 

### vulndb-get-cpe-by-vuln-id

***
Returns the CPE(s) for a vulnerability, by VulnDB ID

#### Base Command

`vulndb-get-cpe-by-vuln-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vuln_id | VulnDB vulnerability ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VulnDB.CPE.Value | string | The CPE\(s\) for the given vulnerability. | 


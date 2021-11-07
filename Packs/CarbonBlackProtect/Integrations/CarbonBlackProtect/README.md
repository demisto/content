<!-- HTML_DOC -->
<p>This integration uses VMware Carbon Black App Control’s (formerly known as Carbon Black Enterprise Protection) searchable file catalog and application control capabilities, such as finding and blocking files by their hash.</p>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name"> </div>
</div>
<h3>To set up the integration on Cortex XSOAR:</h3>
<ol>
<li>Go to ‘Settings &gt; Integrations &gt; Servers &amp; Services’</li>
<li>Locate the VMware Carbon Black App Control v2 integration by searching for ‘VMware Carbon Black App Control v2’ using the search box on the top of the page.</li>
<li>Click ‘Add instance’ to create and configure a new integration. You should configure the following VMware Carbon Black App Control and XSOAR-specific settings:                               <br> <strong>Name</strong>: A textual name for the integration instance.</li>
</ol>
<p class="wysiwyg-indent4"><strong>Server URL</strong>: The hostname or IP address of the VMware Carbon Black App Control application. Make sure the URL is reachable with respect to IP address and port.</p>
<p class="wysiwyg-indent4"><strong>API Token: </strong>The API Token provided for VMware Carbon Black App Control. <strong> </strong></p>
<p class="wysiwyg-indent4"><strong>Incident type:</strong> Choose the type of incident for Cortex XSOAR handling from the drop-down list.</p>
<p class="wysiwyg-indent4"><strong>Do not validate server certificate</strong>: Select to avoid server certification validation. You may want to do this in case Cortex XSOAR cannot validate the integration server certificate (due to missing CA certificate)</p>
<p class="wysiwyg-indent4"><strong>Use system proxy settings</strong>: Select whether to communicate via the system proxy server or not.</p>
<p class="wysiwyg-indent4"><strong>Cortex XSOAR engine:</strong> If relevant, select the engine that acts as a proxy to the server.  <br> Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Cortex XSOAR server from accessing the remote networks.<br> <br> For more information on Cortex XSOAR engines see:<br> <a href="https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/engines">https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/engines</a></p>
<p class="wysiwyg-indent4"><strong>Require users to enter additional password:</strong> Select whether you’d like an additional step where users are required to authenticate themselves with a password.</p>
<ol start="4">
<li>Press the ‘Test’ button to validate connection.</li>
<li>After completing the test successfully, press the ‘Done’ button.</li>
</ol>
<h3>Commands:</h3>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-approvalRequest-search</strong> - Search for approval requests. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#approvalrequest</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-computer-get</strong> - Returns computer. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#computer</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-computer-search</strong> - Search for computers. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#computer</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-computer-update</strong> - Updates computer object. Note that some computer properties can be changed only if the specific boolean param is set, as noted below. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#computer</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-connector-get</strong> - Returns object instance of this class</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-connector-search</strong> - Returns objects that match given criteria</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-event-search</strong> - Search for events. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#event</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileAnalysis-createOrUpdate</strong> - Creates or updates file analysis request</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileAnalysis-get</strong> - Returns object instance of this class</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileAnalysis-search</strong> - Returns objects that match given criteria</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileCatalog-search</strong> - Search for file catalogs. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#filecatalog</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileInstance-search</strong> - Search for file instances. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#fileinstance</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileRule-delete</strong> - Deletes the file rule. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#filerule</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileRule-get</strong> - Gets the file rule. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#filerule</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileRule-search</strong> - Search for file rules. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#filerule</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileRule-update</strong> - Creates or updates file rule. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#filerule </div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileUpload-download - </strong>Returns object instance of this class</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileUpload-get - </strong>Returns object instance of this class</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-fileUpload-search - </strong>Returns objects that match given criteria</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-notification-search - </strong>Search for notifications. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#notification</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-policy-search - </strong>Search for policies. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#policy</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-publisher-search - </strong>Search for publishers. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#publisher</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>cbp-serverConfig-search - </strong>Search in server configurations. See more: https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#serverconfig</div>
</div>
</div>
</div>

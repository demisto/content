<!-- HTML_DOC -->
<p>This article describes the way in which to set up the FireEye (AX Series) integration on Demisto. </p>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name"> </div>
</div>
<h3><span class="wysiwyg-font-size-large">Setting up the FireEye Web Services API to work with Demisto:</span></h3>
<p>This section explains what needs to be done to set up a Fire Eye Web Services API for Demisto integration on the FireEye side.  </p>
<p>This integration supports AXSeriesWebServicesAPI versions 7.7.0 and up.</p>
<p>To use this integration, you need to have a Fire Eye user account of either api_analyst or api_monitor.</p>
<p>To set up the FireEye Web Services API:</p>
<p>1. On the machine where the FireEye API will run, open the CLI and enter the following:  </p>
<p class="wysiwyg-indent2" style="font-family: courier;">hostname &gt; enable</p>
<p class="wysiwyg-indent2" style="font-family: courier;">hostname # configure terminal</p>
<p class="wysiwyg-indent2" style="font-family: courier;">hostname (config) # wsapi enable</p>
<p>2. Make sure that FireEye Web Services API is running ether the following:</p>
<p class="wysiwyg-indent2" style="font-family: courier;">hostname(config)#showwsapi</p>
<p>The reply should indicate that the Server is ‘enabled’ and in ‘running’ state.  </p>
<h3><span class="wysiwyg-font-size-large">Setting up the integration on Demisto:</span></h3>
<p>1. Go to ‘Settings &gt; Integrations &gt; Servers &amp; Services’</p>
<p>2. Locate the FireEye (AX Series) integration by searching for ‘FireEye’ using the search box on the top of the page.</p>
<p>3. Click ‘Add instance’ to create and configure a new integration. You should configure the following FireEye and Demisto-specific settings:</p>
<p class="wysiwyg-indent2"><strong>Name</strong>: A textual name for the integration instance.<br> <strong>Server URL</strong>: The hostname or IP address of the FireEye’ application. Make sure the URL is reachable with respect to IP address and port.<br> <strong>Credentials and Password</strong>: Your FireEye username and password.<br> <strong>Do not validate server certificate</strong>: Select to avoid server certification validation. You may want to do this in case Demisto cannot validate the integration server certificate (due to missing CA certificate)<br> <strong>Use system proxy settings</strong> – Mark this option.</p>
<p>4. Press the ‘Test’ button to validate connection.</p>
<p>5. After completing the test successfully, press the ‘Done’ button.</p>
<h3>Commands:</h3>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>fe-alert</strong> - FireEye view existing alert command. See the FireEye Web Services API Guide for details</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>fe-config</strong> - Configuration commands. See the FireEye Web Services API Guide for details</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>fe-report</strong> - Return a requested report</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>fe-submit</strong> - Submit a malware object for analysis by FireEye</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>fe-submit-result</strong> - Submission key of the submission</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>fe-submit-status</strong> - Get a status for a malware object submitted to FireEye analysis</div>
<div class="five wide break-word column integration-command-name">
<strong>fe-submit-url</strong> - Submit a URL to FireEye for analysis</div>
<div class="five wide break-word column integration-command-name">
<strong>fe-submit-url-status</strong> - Get the status of a URL submitted to FireEye for analysis</div>
</div>

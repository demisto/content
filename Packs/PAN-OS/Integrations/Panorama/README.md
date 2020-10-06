<!-- HTML_DOC -->
<p>This integration supports both Palo Alto Networks Panorama and Palo Alto Networks Firewall. You can create separate instances of each integration, and they are not necessarily related or dependent on one another.</p>
<p>This integration was integrated and tested with version 8.1.0 of Palo Alto Firewall, Palo Alto Panorama</p>
<h2>Panorama Playbook</h2>
<ul>
<li>
<strong> PanoramaCommitConfiguration</strong>: Based on the playbook input, the Playbook will commit the configuration to Palo Alto Firewall, or push the configuration from Panorama to predefined device groups of firewalls. The integration is available from Demisto v3.0, but playbook uses the GenericPooling sub-playbook, which is only available from Demisto v4.0.</li>
<li>
<strong><span>(Deprecated) PanoramaQueryTrafficLogs</span></strong>: Use the Panorama Query Logs playbook instead.W<span>raps the following commands with genericPolling to enable a complete flow to query traffic logs.</span>
<ul>
<li><a href="#h_2b8614b9-d61c-4211-9eaa-1dc82c08e8b1" target="_self">panorama-query-traffic-logs</a></li>
<li><a href="#h_001774c2-0ef7-47f2-9cb2-4c5fd54e671a" target="_self">panorama-check-traffic-logs-status<span></span></a></li>
<li><a href="#h_147e1590-cfe0-4bc5-8b47-9b6f68bac585" target="_self">panorama-get-traffic-logs</a></li>
</ul>
</li>
<li>
<strong><span>Panorama Query Logs</span></strong>: W<span>raps several commands (listed below) with genericPolling to enable a complete flow to query the following log types: traffic, threat, URL, data-filtering, and Wildfire.</span>
<ul>
<li><a href="#h_2b8614b9-d61c-4211-9eaa-1dc82c08e8b1" target="_self">panorama-query-logs</a></li>
<li><a href="#h_001774c2-0ef7-47f2-9cb2-4c5fd54e671a" target="_self">panorama-check-logs-status<span></span></a></li>
<li><a href="#h_147e1590-cfe0-4bc5-8b47-9b6f68bac585" target="_self">panorama-get-logs</a></li>
</ul>
</li>
<li>PAN-OS DAG Configuration</li>
<li>PAN-OS EDL Setup</li>
</ul>
<h2>Use Cases</h2>
<ul>
<li>Create custom security rules in Palo Alto Networks PAN-OS.</li>
<li>Creating and updating address objects, address-groups, custom URL categories, URL filtering objects.</li>
<li>Get URL Filtering category information from Palo Alto - Request Change is a known Palo Alto limitation.</li>
<li>Add URL filtering objects including overrides to Palo Alto Panorama and Firewall</li>
<li>Committing configuration to Palo Alto FW and to Panorama, and pushing configuration from Panorama to Pre-Defined Device-Groups of Firewalls.</li>
<li>Block IP addresses using registered IP tags from PAN-OS without committing the PAN-OS instance. First you have to create a registered IP tag, DAG, and security rule, and commit the instance. You can then register additional IP addresses to the tag without committing the instance.
<ol>
<li>
<p>Create a registered IP tag and add the necessary IP addresses by running the <a href="#register-ip-addresses-to-a-tag" target="_self">panorama-register-ip-tag</a> command.</p>
</li>
<li>
<p>Create a dynamic address group (DAG), by running the <a href="#h_40710829938141545893545157" target="_self">panorama-create-address-group</a> command. Specify values for the following arguments: type="dynamic", match={<em>tagname</em>}.</p>
</li>
<li>
<p>Create a security rule using the DAG created in the previous step, by running the <a href="#h_28406745597601545894536518" target="_self">panorama-create-rule</a> command.</p>
</li>
<li>
<p>Commit the PAN-OS instance by running the PanoramaCommitConfiguration playbook.</p>
</li>
<li>
<p>You can now register IP addresses to, or unregister IP addresses from, the IP tag by running the <a style="background-color: #ffffff;" href="#register-ip-addresses-to-a-tag" target="_self">panorama-register-ip-tag</a> command, or <a style="background-color: #ffffff;" href="#unregister-ip-addresses-from-a-tag" target="_self">panorama-unregister-ip-tag</a> command, respectively, without committing the PAN-OS instance.</p>
</li>
</ol>
</li>
<li>Create a predefined security profiles with the best practices by Palo Alto Networks.</li>
<li>Get security profiles best practices as defined by Palo Alto Networks.
<br>For more inforamtion about Palo Alto Networks best practices, visit <a href="https://docs.paloaltonetworks.com/best-practices/9-0/internet-gateway-best-practices/best-practice-internet-gateway-security-policy/create-best-practice-security-profiles">Palo Alto Networks best practices</a>.</li>
<li>Apply security profiles to specific rule.</li>
<li>Set default categories to block in the URL filtering profile.</li>
<li>Enforce WildFire best practice.
<ol>
<li>Set file upload to the maximum size.</li>
<li>WildFire Update Schedule is set to download and install updates every minute.</li>
<li>All file types are forwarded.</li>
</ol>
</li>
</ul>
<h2>Known Limitations</h2>
<ul>
<li>Maximum commit queue length is 3. Running numerous Panorama commands simultaneously might cause errors.</li>
<li>After you run <code>panorama-create-</code> commands and the object is not committed, then the <code>panorama-edit</code> commands or <code>panorama-get</code> commands might not run correctly.</li>
<li>URL Filtering <code>request change</code> of a URL is not available via the API. Instead, you need to use the <a href="https://urlfiltering.paloaltonetworks.com/" rel="nofollow">https://urlfiltering.paloaltonetworks.com</a> website.</li>
<li>If you do not specify a vsys (Firewall instances) or a device group (Panorama instances), you will only be able to execute certain commands.
<ul>
<li><a href="#h_87493434580411545894477329" target="_self">panorama-get-url-category</a></li>
<li><a href="#h_52691506824281545892929354" target="_self">panorama-commit</a></li>
<li><a href="#h_14932195817471545892886648" target="_self">panorama-push-to-device-group</a></li>
<li><a href="#register-ip-addresses-to-a-tag" target="_self">panorama-register-ip-tag</a></li>
<li><a href="#unregister-ip-addresses-from-a-tag" target="_self">panorama-unregister-ip-tag</a></li>
<li><a href="#h_2b8614b9-d61c-4211-9eaa-1dc82c08e8b1" target="_self">panorama-query-logs</a></li>
<li><a href="#h_001774c2-0ef7-47f2-9cb2-4c5fd54e671a" target="_self">panorama-check-logs-status<span></span></a></li>
<li><a href="#h_147e1590-cfe0-4bc5-8b47-9b6f68bac585" target="_self">panorama-get-logs</a></li>
</ul>
</li>
</ul>
<h2>Configure Panorama on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Panorama.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. <a href="https://192.168.0.1/" rel="nofollow">https://192.168.0.1</a>)</strong></li>
<li><strong>Port</strong></li>
<li><strong>API Key</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li>
<strong>Device group - Required for Panorama instance</strong>. If you want to use a shared location, the value in this field should be "shared".</li>
<li>
<strong>Vsys - Required for Firewall instance (PAN-OS default is 'vsys1'):</strong> retrieve this from the Demisto URL, for example: &lt;server_url&gt;:port/&lt;vsys_name&gt;. If you have multiple vysys, select the one to configure on this instance.</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_7040597420811545892921540">Run any command supported in the Panorama API: panorama</a></li>
<li><a href="#h_52691506824281545892929354">Commit a configuration: panorama-commit</a></li>
<li><a href="#h_14932195817471545892886648">Push rules from Panorama to a device group: panorama-push-to-device-group</a></li>
<li><a href="#h_16451231627791545893085264">Get a list of addresses: panorama-list-addresses</a></li>
<li><a href="#h_57314291029541545893122182">Get address details: panorama-get-address</a></li>
<li><a href="#h_97114196131281545893157671">Create an address object: panorama-create-address</a></li>
<li><a href="#h_97340533533011545893318174">Delete an address: panorama-delete-address</a></li>
<li><a href="#h_18768207634731545893356092">Get a list of address groups: panorama-list-address-groups</a></li>
<li><a href="#h_17078113636441545893426970">Get details for an address group: panorama-get-address-group</a></li>
<li><a href="#h_40710829938141545893545157">Create an address group: panorama-create-address-group</a></li>
<li><a href="#h_6809869552871545893579085">Delete an address group: panorama-delete-address-group</a></li>
<li><a href="#h_98711249164271545893589241">Edit an address group: panorama-edit-address-group</a></li>
<li><a href="#h_85506443065931545893850241">Get details for a custom URL category: panorama-get-custom-url-category</a></li>
<li><a href="#h_17570418969191545894451093">Create a custom URL category: panorama-create-custom-url-category</a></li>
<li><a href="#h_69714146472431545894462566">Delete a custom URL category: panorama-delete-custom-url-category</a></li>
<li><a href="#h_15757837375651545894471041">Add/Remove sites from a custom URL category: panorama-edit-custom-url-category</a></li>
<li><a href="#h_87493434580411545894477329">Get details for a URL category: panorama-get-url-category</a></li>
<li><a href="#h_7426967282031545894498970">Get details for a URL filtering rule: panorama-get-url-filter</a></li>
<li><a href="#h_49203186986741545894507538">Create a URL filtering rule: panorama-create-url-filter</a></li>
<li><a href="#h_70728994189871545894514725">Edit a URL filter: panorama-edit-url-filter</a></li>
<li><a href="#h_51942600592991545894523815">Delete a URL filtering rule: panorama-delete-url-filter</a></li>
<li><a href="#h_28406745597601545894536518">Create a rule: panorama-create-rule</a></li>
<li><a href="#h_353141275100681545894548340">Create a custom block policy rule: panorama-custom-block-rule</a></li>
<li><a href="#h_189209860103731545894553169">Change the location of a policy rule: panorama-move-rule</a></li>
<li><a href="#h_626779749108261545894558673">Edit a policy rule: panorama-edit-rule</a></li>
<li><a href="#h_372847952111281545894564883">Delete a policy rule: panorama-delete-rule</a></li>
<li><a href="#h_476348815115751545894571725">Get a list of applications: panorama-list-applications</a></li>
<li><a href="#h_298117829120191545894577230">Get the commit status for a configuration: panorama-commit-status</a></li>
<li><a href="#h_432098286126051545894584071">Get the push status for a configuration: panorama-push-status</a></li>
<li><a href="#h_7213490231451549377931816">Get a list of services: panorama-list-services</a></li>
<li><a href="#h_7054447343481549377938336">Get information for a service: panorama-get-service</a></li>
<li><a href="#h_9044031655501549377945144">Create a service: panorama-create-service</a></li>
<li><a href="#h_66783294117261549377952328">Delete a service: panorama-delete-service</a></li>
<li><a href="#h_66708612219261549377957626">Get a list of service groups: panorama-list-service-groups</a></li>
<li><a href="#h_1b918da1-b45b-4738-a07a-a483eacb59ff" target="_self">Get information for a service group: panorama-get-service-group</a></li>
<li><a href="#h_6f00ae35-41ae-48c2-92d3-f10f29459f88" target="_self">Create a service group: panorama-create-service-group</a></li>
<li><a href="#h_47461b58-42a1-44cc-b0c9-41ec5c44c665" target="_self">Delete a service group: panorama-delete-service-group</a></li>
<li><a href="#h_4582fce3-9660-481e-b899-e8eaebffaca1" target="_self">Edit a service group: panorama-edit-service group</a></li>
<li><a href="#get-information-for-pcap-files" target="_self">Get information for PCAP files: panorama-get-pcap</a></li>
<li><a href="#get-a-list-of-all-pcap-files" target="_self">Get a list of all PCAP files: panorama-list-pcaps</a></li>
<li><a href="#get-a-list-of-edls" target="_self">Get a list of EDLs: panorama-list-edls</a></li>
<li><a href="#get-information-for-an-edl" target="_self">Get information for an EDL: panorama-get-edl</a></li>
<li><a href="#create-an-edl" target="_self">Create an : panorama-create-edl</a></li>
<li><a href="#edit-an-edl" target="_self">Edit an EDL: panorama-edit-edl</a></li>
<li><a href="#delete-an-edl" target="_self">Delete an EDL: panorama-delete-edl</a></li>
<li><a href="#refresh-an-edl" target="_self">Refresh an EDL: panorama-refresh-edl</a></li>
<li><a href="#register-ip-addresses-to-a-tag" target="_self">Register IP addresses to a tag: panorama-register-ip-tag</a></li>
<li><a href="#unregister-ip-addresses-from-a-tag" target="_self">Unregister IP addresses from a tag: panorama-unregister-ip-tag</a></li>
<li><a href="#h_2b8614b9-d61c-4211-9eaa-1dc82c08e8b1" target="_self">Query traffic logs: panorama-query-traffic-logs</a></li>
<li><a href="#h_001774c2-0ef7-47f2-9cb2-4c5fd54e671a" target="_self"> Check the query status of traffic logs: panorama-check-traffic-logs-status </a></li>
<li><a href="#h_147e1590-cfe0-4bc5-8b47-9b6f68bac585" target="_self">Get traffic logs: panorama-get-traffic-logs</a></li>
<li><a href="#h_8230c267-2e89-43f5-b2e8-d6ac6fab2334" target="_self"> Get a list of predefined security rules: panorama-list-rules</a></li>
<li><a href="#53-panorama-query-logs" target="_self">Query logs: panorama-query-logs</a></li>
<li><a href="#54-panorama-check-logs-status" target="_self">Check the query status of logs: panorama-check-logs-status</a></li>
<li><a href="#55-panorama-get-logs" target="_self">Get the data of a logs query: panorama-get-logs</a></li>
<li><a href="#panorama-security-policy-match" target="_self">Checks whether a session matches the specified security policy. This command is only available on Firewall instances: panorama-security-policy-match</a></li>
<li><a href="#panorama-list-static-routes" target="_self">Lists the static routes of a virtual router: panorama-list-static-routes</a></li>
<li><a href="#panorama-get-static-route" target="_self">Returns the specified static route of a virtual router: panorama-get-static-route</a></li>
<li><a href="#panorama-add-static-route" target="_self">Adds a static route: panorama-add-static-route</a></li>
<li><a href="#panorama-delete-static-route" target="_self">Deletes a static route: panorama-delete-static-route</a></li>
<li><a href="#panorama-show-device-version" target="_self">Show firewall device software version: panorama-show-device-version</a></li>
<li><a href="#panorama-download-latest-content-update" target="_self">Downloads the latest content update: panorama-download-latest-content-update</a></li>
<li><a href="#panorama-content-update-download-status" target="_self">Checks the download status of a content update: panorama-content-update-download-status</a></li>
<li><a href="#panorama-install-latest-content-update" target="_self">Installs the latest content update: panorama-install-latest-content-update</a></li>
<li><a href="#panorama-content-update-install-status" target="_self">Gets the installation status of the content update: panorama-content-update-install-status</a></li>
<li><a href="#panorama-check-latest-panos-software" target="_self">Checks the PAN-OS software version from the repository: panorama-check-latest-panos-software</a></li>
<li><a href="#panorama-download-panos-version" target="_self">Downloads the target PAN-OS software version to install on the target device: panorama-download-panos-version</a></li>
<li><a href="#panorama-download-panos-status" target="_self">Gets the download status of the target PAN-OS software: panorama-download-panos-status</a></li>
<li><a href="#panorama-install-panos-version" target="_self">Installs the target PAN-OS version on the specified target device: panorama-install-panos-version</a></li>
<li><a href="#panorama-install-panos-status" target="_self">Gets the installation status of the PAN-OS software: panorama-install-panos-status</a></li>
<li><a href="#panorama-device-reboot" target="_self">Reboots the Firewall device: panorama-device-reboot</a></li>
<li><a href="#panorama-show-location-ip" target="_self">Show the IP location information: panorama-show-location-ip</a></li>
<li><a href="#panorama-get-licences" target="_self">Get information about PAN-OS available licenses and their statuses: panorama-get-licences</a></li>
<li><a href="#panorama-get-security-profiles" target="_self">Get information about profiles: panorama-get-security-profiles</a></li>
<li><a href="#panorama-apply-security-profile" target="_self">Apply profile to specific rules / rules with specific tag: panorama-apply-security-profile</a></li>
<li><a href="#panorama-get-ssl-decryption-rules" target="_self">Show ssl decryption rules under policies -> decryption -> rules: panorama-get-ssl-decryption-rules</a></li>
<li><a href="#panorama-get-wildfire-configuration" target="_self">Retrieve Wildfire Configuration: panorama-get-wildfire-configuration</a></li>
<li><a href="#panorama-url-filtering-block-default-categories" target="_self">Set default categories to block in the URL filtering profile: panorama-url-filtering-block-default-categories</a></li>
<li><a href="#panorama-get-anti-spyware-best-practice" target="_self">Show anti-spyware best practices: panorama-get-anti-spyware-best-practice</a></li>
<li><a href="#panorama-get-file-blocking-best-practice" target="_self">Show file-blocking best practices: panorama-get-file-blocking-best-practice</a></li>
<li><a href="#panorama-get-antivirus-best-practice" target="_self">Show anti-virus best practices: panorama-get-antivirus-best-practice</a></li>
<li><a href="#panorama-get-vulnerability-protection-best-practice" target="_self">Show vulnerability-protection best practices: panorama-get-vulnerability-protection-best-practice</a></li>
<li><a href="#panorama-get-wildfire-best-practice" target="_self">Show WildFire best practices: panorama-get-wildfire-best-practice</a></li>
<li><a href="#panorama-get-url-filtering-best-practice" target="_self">Show URL Filtering best practices: panorama-get-url-filtering-best-practice</a></li>
<li><a href="#panorama-enforce-wildfire-best-practice" target="_self">Enforce wildfire file upload to the maximum size + all file types are forwarded and update schedule: panorama-enforce-wildfire-best-practice</a></li>
<li><a href="#panorama-create-antivirus-best-practice-profile" target="_self">Create antivirus best practice profile: panorama-create-antivirus-best-practice-profile</a></li>
<li><a href="#panorama-create-anti-spyware-best-practice-profile" target="_self">Create Anti Spyware best practice profile: panorama-create-anti-spyware-best-practice-profile</a></li>
<li><a href="#panorama-create-vulnerability-best-practice-profile" target="_self">Create vulnerability protection best practice profile: panorama-create-vulnerability-best-practice-profile</a></li>
<li><a href="#panorama-create-url-filtering-best-practice-profile" target="_self">Create URL filtering best practice profile: panorama-create-url-filtering-best-practice-profile</a></li>
<li><a href="#panorama-create-file-blocking-best-practice-profile" target="_self">Create file blocking best practice profile: panorama-create-file-blocking-best-practice-profile</a></li>
<li><a href="#panorama-create-wildfire-best-practice-profile" target="_self">Create WildFire analysis best practice profile: panorama-create-wildfire-best-practice-profile</a></li>
</ol>
<h3 id="h_7040597420811545892921540">1. Run any command supported in the PAN-OS API</h3>
<hr>
<p>Run any command supported in the API.</p>
<h5>Base Command</h5>
<p><code>panorama</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 154px;"><strong>Argument Name</strong></th>
<th style="width: 515px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154px;">action</td>
<td style="width: 515px;">Action to take. Can be: show, get, set, edit, delete, rename, clone, move, or override.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">category</td>
<td style="width: 515px;">Category parameter. e.g. when exporting a configuration file use category=configuration.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">cmd</td>
<td style="width: 515px;">Used for operations commands cmd specifies the xml struct that defines the command.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">command</td>
<td style="width: 515px;">Run a command. e.g. "command = ".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">dst</td>
<td style="width: 515px;">Specifies destination.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">element</td>
<td style="width: 515px;">Used to define a new value for an object.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">to</td>
<td style="width: 515px;">To parameter (used in specifying time and when cloning an object).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">from</td>
<td style="width: 515px;">From parameter (used in specifying time and when cloning an object).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">key</td>
<td style="width: 515px;">Sets a key value.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">where</td>
<td style="width: 515px;">Specifies the type of a move operation (e.g. where=after, where=before, where=top, where=bottom).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">period</td>
<td style="width: 515px;">Describe a time period. E.g. period=last-24-hrs.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">xpath</td>
<td style="width: 515px;">Defines a location e.g. xpath=/config/predefined/application/entry[<a class="user-mention" href="https://github.com/name" data-hovercard-type="user" data-hovercard-url="/hovercards?user_id=39627038" data-octo-click="hovercard-link-click" data-octo-dimensions="link_type:self">@name</a>='hotmail']</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">pcap-id</td>
<td style="width: 515px;">The threat PCAP ID in the threat log.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">serialno</td>
<td style="width: 515px;">Specifies the device serial number.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">reporttype</td>
<td style="width: 515px;">Choose dynamic, predefined or custom report.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">reportname</td>
<td style="width: 515px;">The report name.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">log-type</td>
<td style="width: 515px;">Used for retrieving logs. e.g. log-type=threat for threat logs.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">type</td>
<td style="width: 515px;">The request type (e.g. export, import, log, config).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">search-time</td>
<td style="width: 515px;">Used for threat PCAPs, the time that the PCAP was received on the firewall.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">target</td>
<td style="width: 515px;">Target number of the firewall (Panorama instance).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h3 id="h_52691506824281545892929354">2. Commit a configuration</h3>
<hr>
<p>Commits a configuration to Palo Alto Networks PAN-OS, but does not validate if the commit was successful. Committing toPAN-OS will not push the configuration to the Firewalls. To push the configuration, run the <a href="#h_14932195817471545892886648">panorama-push-to-device-group</a> command.</p>
<h5>Base Command</h5>
<p><code>panorama-commit</code></p>
<h5>Input</h5>
<p>There are no input arguments for this command.</p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 248px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 420px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 248px;">Panorama.Commit.JobID</td>
<td style="width: 72px;">number</td>
<td style="width: 420px;">Job ID of the configuration to commit.</td>
</tr>
<tr>
<td style="width: 248px;">Panorama.Commit.Status</td>
<td style="width: 72px;">string</td>
<td style="width: 420px;">Commit status.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-commit</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50423080-3709a000-0859-11e9-83a3-ba1012ee0a2d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50423080-3709a000-0859-11e9-83a3-ba1012ee0a2d.png" alt="screen shot 2018-12-25 at 15 24 02"></a></p>
<h3 id="h_14932195817471545892886648">3. Push rules from PAN-OS to a device group</h3>
<hr>
<p>Pushes rules fromPAN-OS to the configured device group.</p>
<h5>Base Command</h5>
<p><code>panorama-push-to-device-group</code></p>
<h5>Input</h5>
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 192px;"><strong>Argument Name</strong></th>
<th style="width: 418px;"><strong>Description</strong></th>
<th style="width: 130px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 192px;">device-group</td>
<td style="width: 418px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 130px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5><span style="font-size: 15px;">Context Output</span></h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 264px;"><strong>Path</strong></th>
<th style="width: 76px;"><strong>Type</strong></th>
<th style="width: 400px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 264px;">Panorama.Push.DeviceGroup</td>
<td style="width: 76px;">string</td>
<td style="width: 400px;">Device group to which the policies were pushed.</td>
</tr>
<tr>
<td style="width: 264px;">Panorama.Push.JobID</td>
<td style="width: 76px;">number</td>
<td style="width: 400px;">Job ID of the configuration to be pushed.</td>
</tr>
<tr>
<td style="width: 264px;">Panorama.Push.Status</td>
<td style="width: 76px;">string</td>
<td style="width: 400px;">Push status.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-push-to-device-group</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50422939-f3626680-0857-11e9-8c97-b27e02b8f77c.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50422939-f3626680-0857-11e9-8c97-b27e02b8f77c.png" alt="screen shot 2018-12-25 at 15 15 09"></a></p>
<h3 id="h_16451231627791545893085264">4. Get a list of addresses</h3>
<hr>
<p>Returns a list of addresses.</p>
<h5>Base Command</h5>
<p><code>panorama-list-addresses</code></p>
<h5>Input</h5>
<table style="height: 14px; width: 746px;">
<thead>
<tr>
<th style="width: 192px;"><strong>Argument Name</strong></th>
<th style="width: 418px;"><strong>Description</strong></th>
<th style="width: 130px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">device-group</td>
<td style="width: 494px;">The device group for which to return addresses (Panorama instances). If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 109px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">Tag</td>
<td style="width: 494px;">The tag for which to filter the list of addresses.</td>
<td style="width: 109px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 398px;"><strong>Path</strong></th>
<th style="width: 93px;"><strong>Type</strong></th>
<th style="width: 249px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 398px;">Panorama.Addresses.Name</td>
<td style="width: 93px;">string</td>
<td style="width: 249px;">Address name.</td>
</tr>
<tr>
<td style="width: 398px;">Panorama.Addresses.Description</td>
<td style="width: 93px;">string</td>
<td style="width: 249px;">Address description.</td>
</tr>
<tr>
<td style="width: 398px;">Panorama.Addresses.FQDN</td>
<td style="width: 93px;">string</td>
<td style="width: 249px;">Address FQDN.</td>
</tr>
<tr>
<td style="width: 398px;">Panorama.Addresses.IP_Netmask</td>
<td style="width: 93px;">string</td>
<td style="width: 249px;">Address IP netmask.</td>
</tr>
<tr>
<td style="width: 398px;">Panorama.Addresses.IP_Range</td>
<td style="width: 93px;">string</td>
<td style="width: 249px;">Address IP range.</td>
</tr>
<tr>
<td style="width: 398px;">Panorama.Addresses.DeviceGroup</td>
<td style="width: 93px;">string</td>
<td style="width: 249px;">Address device group.</td>
</tr>
<tr>
<td style="width: 398px;">Panorama.Addresses.Tages</td>
<td style="width: 93px;">string</td>
<td style="width: 249px;">Address tags.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-list-addresses</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50417869-51c81e80-0831-11e9-9769-a3fa4c315c5f.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50417869-51c81e80-0831-11e9-9769-a3fa4c315c5f.png" alt="screen shot 2018-12-25 at 10 36 30"></a></p>
<h3 id="h_57314291029541545893122182">5. Get address details</h3>
<hr>
<p>Returns address details for the supplied address name.</p>
<h5>Base Command</h5>
<p><code>panorama-get-address</code></p>
<h5>Input</h5>
<table style="width: 744px;">
<thead>
<tr>
<th style="width: 168px;"><strong>Argument Name</strong></th>
<th style="width: 468px;"><strong>Description</strong></th>
<th style="width: 104px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168px;">name</td>
<td style="width: 468px;">Address name.</td>
<td style="width: 104px;">Required</td>
</tr>
<tr>
<td style="width: 168px;">device-group</td>
<td style="width: 468px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 104px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 400px;"><strong>Path</strong></th>
<th style="width: 91px;"><strong>Type</strong></th>
<th style="width: 249px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 400px;">Panorama.Addresses.Name</td>
<td style="width: 91px;">string</td>
<td style="width: 249px;">Address name.</td>
</tr>
<tr>
<td style="width: 400px;">Panorama.Addresses.Description</td>
<td style="width: 91px;">string</td>
<td style="width: 249px;">Address description.</td>
</tr>
<tr>
<td style="width: 400px;">Panorama.Addresses.FQDN</td>
<td style="width: 91px;">string</td>
<td style="width: 249px;">Address FQDN.</td>
</tr>
<tr>
<td style="width: 400px;">Panorama.Addresses.IP_Netmask</td>
<td style="width: 91px;">string</td>
<td style="width: 249px;">Address IP netmask.</td>
</tr>
<tr>
<td style="width: 400px;">Panorama.Addresses.IP_Range</td>
<td style="width: 91px;">string</td>
<td style="width: 249px;">Address IP range.</td>
</tr>
<tr>
<td style="width: 400px;">Panorama.Addresses.DeviceGroup</td>
<td style="width: 91px;">string</td>
<td style="width: 249px;">Address device group.</td>
</tr>
<tr>
<td style="width: 400px;">Panorama.Addresses.Tags</td>
<td style="width: 91px;">string</td>
<td style="width: 249px;">Address tags.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-get-address name="Demisto address"</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50422418-5a315100-0853-11e9-80cd-363788f88ef7.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50422418-5a315100-0853-11e9-80cd-363788f88ef7.png" alt="screen shot 2018-12-25 at 14 42 39"></a></p>
<h3 id="h_97114196131281545893157671">6. Create an address object</h3>
<hr>
<p>Creates an address object.</p>
<h5>Base Command</h5>
<p><code>panorama-create-address</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 161px;"><strong>Argument Name</strong></th>
<th style="width: 494px;"><strong>Description</strong></th>
<th style="width: 85px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 161px;">name</td>
<td style="width: 494px;">Name for the new address.</td>
<td style="width: 85px;">Required</td>
</tr>
<tr>
<td style="width: 161px;">description</td>
<td style="width: 494px;">A description of the new address.</td>
<td style="width: 85px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">fqdn</td>
<td style="width: 494px;">FQDN of the new address.</td>
<td style="width: 85px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">ip_netmask</td>
<td style="width: 494px;">IP netmask of the new address, e.g., 10.10.10.10/24.</td>
<td style="width: 85px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">ip_range</td>
<td style="width: 494px;">IP range of the new address, e.g., 10.10.10.0-10.10.10.255.</td>
<td style="width: 85px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">device-group</td>
<td style="width: 494px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 85px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">tag</td>
<td style="width: 494px;">The tag for the new address</td>
<td style="width: 85px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 410px;"><strong>Path</strong></th>
<th style="width: 81px;"><strong>Type</strong></th>
<th style="width: 249px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 410px;">Panorama.Addresses.Name</td>
<td style="width: 81px;">string</td>
<td style="width: 249px;">Address name.</td>
</tr>
<tr>
<td style="width: 410px;">Panorama.Addresses.Description</td>
<td style="width: 81px;">string</td>
<td style="width: 249px;">Address description.</td>
</tr>
<tr>
<td style="width: 410px;">Panorama.Addresses.FQDN</td>
<td style="width: 81px;">string</td>
<td style="width: 249px;">Address FQDN.</td>
</tr>
<tr>
<td style="width: 410px;">Panorama.Addresses.IP_Netmask</td>
<td style="width: 81px;">string</td>
<td style="width: 249px;">Address IP netmask.</td>
</tr>
<tr>
<td style="width: 410px;">Panorama.Addresses.IP_Range</td>
<td style="width: 81px;">string</td>
<td style="width: 249px;">Address IP range.</td>
</tr>
<tr>
<td style="width: 410px;">Panorama.Adddresses.DeviceGroup</td>
<td style="width: 81px;">string</td>
<td style="width: 249px;">Address Device Group.</td>
</tr>
<tr>
<td style="width: 410px;">Panorama.Addresses.Tag</td>
<td style="width: 81px;">string</td>
<td style="width: 249px;">Address tag.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-create-address name="address_test_pb" description="just a desc" ip_range="10.10.10.9-10.10.10.10"</pre>
<h5>Human Readable Output</h5>
<h3 id="h_97340533533011545893318174">7. Delete an address object</h3>
<hr>
<p>Deletes an address object.</p>
<h5>Base Command</h5>
<p><code>panorama-delete-address</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 226px;"><strong>Argument Name</strong></th>
<th style="width: 385px;"><strong>Description</strong></th>
<th style="width: 129px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 226px;">name</td>
<td style="width: 385px;">Name of the address to delete.</td>
<td style="width: 129px;">Required</td>
</tr>
<tr>
<td style="width: 226px;">device-group</td>
<td style="width: 385px;">
<span>The device group for which to return addresses (Panorama instances). </span>If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 129px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 279px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 395px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 279px;">Panorama.Addresses.Name</td>
<td style="width: 66px;">string</td>
<td style="width: 395px;">Name of the address that was deleted.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-delete-address name="address_test_pb"</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50421893-c78db380-084c-11e9-8451-9491f8589b2f.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50421893-c78db380-084c-11e9-8451-9491f8589b2f.png" alt="screen shot 2018-12-25 at 13 55 34"></a></p>
<h3 id="h_18768207634731545893356092">8. Get a list of address groups</h3>
<hr>
<p>Returns a list of address groups.</p>
<h5>Base Command</h5>
<p><code>panorama-list-address-groups</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<tbody>
<tr>
<th style="width: 226px;"><strong>Argument Name</strong></th>
<th style="width: 385px;"><strong>Description</strong></th>
<th style="width: 129px;"><strong>Required</strong></th>
</tr>
<tr>
<td style="width: 226px;">device-group</td>
<td style="width: 385px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 129px;">Optional</td>
</tr>
<tr>
<td style="width: 226px;">tag</td>
<td style="width: 385px;">The tag for which to filter the address group.</td>
<td style="width: 129px;">Optional</td>
</tr>
</tbody>
</table>
<p>There are no input arguments for this command.</p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 365px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 311px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 365px;">Panorama.AddressGroups.Name</td>
<td style="width: 64px;">string</td>
<td style="width: 311px;">Address group name.</td>
</tr>
<tr>
<td style="width: 365px;">Panorama.AddressGroups.Type</td>
<td style="width: 64px;">string</td>
<td style="width: 311px;">Address group type.</td>
</tr>
<tr>
<td style="width: 365px;">Panorama.AddressGroups.Match</td>
<td style="width: 64px;">string</td>
<td style="width: 311px;">Dynamic address group match.</td>
</tr>
<tr>
<td style="width: 365px;">Panorama.AddressGroups.Description</td>
<td style="width: 64px;">string</td>
<td style="width: 311px;">Address group description.</td>
</tr>
<tr>
<td style="width: 365px;">Panorama.AddressGroups.Addresses</td>
<td style="width: 64px;">string</td>
<td style="width: 311px;">Static address group addresses.</td>
</tr>
<tr>
<td style="width: 365px;">Panorama.AddressGroups.DeviceGroup</td>
<td style="width: 64px;">string</td>
<td style="width: 311px;">Address device group.</td>
</tr>
<tr>
<td style="width: 365px;">Panorama.AddressGroups.Tag</td>
<td style="width: 64px;">string</td>
<td style="width: 311px;">Address group tag.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-list-address-groups</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50421902-e2602800-084c-11e9-9c87-c21fb77d4553.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50421902-e2602800-084c-11e9-9c87-c21fb77d4553.png" alt="screen shot 2018-12-25 at 13 56 20"></a></p>
<h3 id="h_17078113636441545893426970">9. Get information for an address group. A dynamic address group with a tag will return only the tag name, not the IPs associated with this tag.</h3>
<hr>
<p>Returns details for the specified address group.</p>
<h5>Base Command</h5>
<p><code>panorama-get-address-group</code></p>
<h5>Input</h5>
<table style="width: 746px;">
<thead>
<tr>
<th style="width: 162px;"><strong>Argument Name</strong></th>
<th style="width: 453px;"><strong>Description</strong></th>
<th style="width: 125px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162px;">name</td>
<td style="width: 453px;">Address group name.</td>
<td style="width: 125px;">Required</td>
</tr>
<tr>
<td style="width: 162px;">device-group</td>
<td style="width: 453px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 125px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 367px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 311px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 367px;">Panorama.AddressGroups.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 311px;">Address group name.</td>
</tr>
<tr>
<td style="width: 367px;">Panorama.AddressGroups.Type</td>
<td style="width: 62px;">string</td>
<td style="width: 311px;">Address group type.</td>
</tr>
<tr>
<td style="width: 367px;">Panorama.AddressGroups.Match</td>
<td style="width: 62px;">string</td>
<td style="width: 311px;">Dynamic address group match.</td>
</tr>
<tr>
<td style="width: 367px;">Panorama.AddressGroups.Description</td>
<td style="width: 62px;">string</td>
<td style="width: 311px;">Address group description.</td>
</tr>
<tr>
<td style="width: 367px;">Panorama.AddressGroups.Addresses</td>
<td style="width: 62px;">string</td>
<td style="width: 311px;">Static address group addresses.</td>
</tr>
<tr>
<td style="width: 367px;">Panorama.AddressGroups.DeviceGroup</td>
<td style="width: 62px;">string</td>
<td style="width: 311px;">Address device group.</td>
</tr>
<tr>
<td style="width: 367px;"><span>Panorama.AddressGroups.Tags</span></td>
<td style="width: 62px;">string</td>
<td style="width: 311px;">Address group tags.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-get-address-group name=suspicious_address_group</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50423656-eeee7b80-0860-11e9-8495-48a951ddd97f.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50423656-eeee7b80-0860-11e9-8495-48a951ddd97f.png" alt="screen shot 2018-12-25 at 16 19 48"></a></p>
<h3 id="h_40710829938141545893545157">10. Create an address group</h3>
<hr>
<p>Creates an address group; "static" or "dynamic".</p>
<h5>Base Command</h5>
<p><code>panorama-create-address-group</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 156px;"><strong>Argument Name</strong></th>
<th style="width: 495px;"><strong>Description</strong></th>
<th style="width: 89px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 156px;">name</td>
<td style="width: 495px;">Address group name.</td>
<td style="width: 89px;">Required</td>
</tr>
<tr>
<td style="width: 156px;">type</td>
<td style="width: 495px;">Address group type.</td>
<td style="width: 89px;">Required</td>
</tr>
<tr>
<td style="width: 156px;">match</td>
<td style="width: 495px;">Dynamic address group match. e.g., "1.1.1.1 or 2.2.2.2".</td>
<td style="width: 89px;">Optional</td>
</tr>
<tr>
<td style="width: 156px;">addresses</td>
<td style="width: 495px;">Static address group list of addresses.</td>
<td style="width: 89px;">Optional</td>
</tr>
<tr>
<td style="width: 156px;">description</td>
<td style="width: 495px;">Address group description.</td>
<td style="width: 89px;">Optional</td>
</tr>
<tr>
<td style="width: 156px;">device-group</td>
<td style="width: 495px;">The device group for which to return addresses (Panorama instances). If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 89px;">Optional</td>
</tr>
<tr>
<td style="width: 156px;">tags</td>
<td style="width: 495px;">The tags for the address group.</td>
<td style="width: 89px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 370px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 307px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 370px;">Panorama.AddressGroups.Name</td>
<td style="width: 63px;">string</td>
<td style="width: 307px;">Address group name.</td>
</tr>
<tr>
<td style="width: 370px;">Panorama.AddressGroups.Type</td>
<td style="width: 63px;">string</td>
<td style="width: 307px;">Address group type.</td>
</tr>
<tr>
<td style="width: 370px;">Panorama.AddressGroups.Match</td>
<td style="width: 63px;">string</td>
<td style="width: 307px;">Dynamic address group match.</td>
</tr>
<tr>
<td style="width: 370px;">Panorama.AddressGroups.Addresses</td>
<td style="width: 63px;">string</td>
<td style="width: 307px;">Static address group list.</td>
</tr>
<tr>
<td style="width: 370px;">Panorama.AddressGroups.Description</td>
<td style="width: 63px;">string</td>
<td style="width: 307px;">Address group description.</td>
</tr>
<tr>
<td style="width: 370px;"><span>Panorama.AddressGroups.DeviceGroup</span></td>
<td style="width: 63px;">string</td>
<td style="width: 307px;">Address device group.</td>
</tr>
<tr>
<td style="width: 370px;"><span>Panorama.AddressGroups.Tag</span></td>
<td style="width: 63px;">string</td>
<td style="width: 307px;">Address group tags.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-create-address-group name=suspicious_address_group type=dynamic match=1.1.1.1
          description="this ip is very bad"</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50423665-11809480-0861-11e9-8ec4-e3d0e3eef7c5.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50423665-11809480-0861-11e9-8ec4-e3d0e3eef7c5.png" alt="screen shot 2018-12-25 at 16 20 48"></a></p>
<h3 id="h_6809869552871545893579085">11. Delete an address group</h3>
<hr>
<p>Deletes an address group.</p>
<h5>Base Command</h5>
<p><code>panorama-delete-address-group</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 218px;"><strong>Argument Name</strong></th>
<th style="width: 399px;"><strong>Description</strong></th>
<th style="width: 123px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 218px;">name</td>
<td style="width: 399px;">Name of address group to delete.</td>
<td style="width: 123px;">Optional</td>
</tr>
<tr>
<td style="width: 218px;">device-group</td>
<td style="width: 399px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 123px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 300px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 382px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 300px;">Panorama.AddressGroups.Name</td>
<td style="width: 58px;">string</td>
<td style="width: 382px;">Name of address group that was deleted.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-delete-address-group name="dynamic_address_group_test_pb3"</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50421983-e80a3d80-084d-11e9-9872-c9370a738dee.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50421983-e80a3d80-084d-11e9-9872-c9370a738dee.png" alt="screen shot 2018-12-25 at 14 03 36"></a></p>
<h3 id="h_98711249164271545893589241">12. Edit an address group</h3>
<hr>
<p>Edit an address group; "static" or "dynamic".</p>
<h5>Base Command</h5>
<p><code>panorama-edit-address-group</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 152px;"><strong>Argument Name</strong></th>
<th style="width: 517px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 152px;">name</td>
<td style="width: 517px;">Name of the address group to edit.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 152px;">type</td>
<td style="width: 517px;">Address group type.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 152px;">match</td>
<td style="width: 517px;">Address group new match, e.g., "1.1.1.1 and 2.2.2.2".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">element_to_add</td>
<td style="width: 517px;">Element to add to the list of the static address group. Only existing Address objects can be added.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">element_to_remove</td>
<td style="width: 517px;">Element to remove to the list of the static address group. Only existing Address objects can be added.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">description</td>
<td style="width: 517px;">Address group new description.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">tag</td>
<td style="width: 517px;">Address group tag to edit.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 366px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 311px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 366px;">Panorama.AddressGroups.Name</td>
<td style="width: 63px;">string</td>
<td style="width: 311px;">Address group name.</td>
</tr>
<tr>
<td style="width: 366px;">Panorama.AddressGroups.Type</td>
<td style="width: 63px;">string</td>
<td style="width: 311px;">Address group type.</td>
</tr>
<tr>
<td style="width: 366px;">Panorama.AddressGroups.Filter</td>
<td style="width: 63px;">string</td>
<td style="width: 311px;">Dynamic address group match.</td>
</tr>
<tr>
<td style="width: 366px;">Panorama.AddressGroups.Description</td>
<td style="width: 63px;">string</td>
<td style="width: 311px;">Address group description.</td>
</tr>
<tr>
<td style="width: 366px;">Panorama.AddressGroups.Addresses</td>
<td style="width: 63px;">string</td>
<td style="width: 311px;">Static address group addresses.</td>
</tr>
<tr>
<td style="width: 366px;"><span>Panorama.AddressGroups.DeviceGroup</span></td>
<td style="width: 63px;">string</td>
<td style="width: 311px;">Address device group.</td>
</tr>
<tr>
<td style="width: 366px;"><span>Panorama.AddressGroups.Tags</span></td>
<td style="width: 63px;">string</td>
<td style="width: 311px;">Address group tags.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_85506443065931545893850241">13. Get details for a custom URL category</h3>
<hr>
<p>Returns information for a custom URL category.</p>
<h5>Base Command</h5>
<p><code>panorama-get-custom-url-category</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 232px;"><strong>Argument Name</strong></th>
<th style="width: 374px;"><strong>Description</strong></th>
<th style="width: 134px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 232px;">name</td>
<td style="width: 374px;">Custom URL category name.</td>
<td style="width: 134px;">Required</td>
</tr>
<tr>
<td style="width: 232px;">device-group</td>
<td style="width: 374px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 134px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 374px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 300px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 374px;">Panorama.CustomURLCategory.Name</td>
<td style="width: 66px;">string</td>
<td style="width: 300px;">Custom URL category name.</td>
</tr>
<tr>
<td style="width: 374px;">Panorama.CustomURLCategory.Description</td>
<td style="width: 66px;">string</td>
<td style="width: 300px;">Custom URL category description.</td>
</tr>
<tr>
<td style="width: 374px;">Panorama.CustomURLCategory.Sites</td>
<td style="width: 66px;">string</td>
<td style="width: 300px;">Custom URL category list of sites.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-get-custom-url-category name=my_personal_url_category</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50423774-90c29800-0862-11e9-812e-7dbfac0d7c7f.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50423774-90c29800-0862-11e9-812e-7dbfac0d7c7f.png" alt="screen shot 2018-12-25 at 16 31 30"></a></p>
<h3 id="h_17570418969191545894451093">14. Create a custom URL category</h3>
<hr>
<p>Creates a custom URL category.</p>
<h5>Base Command</h5>
<p><code>panorama-create-custom-url-category</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 168px;"><strong>Argument Name</strong></th>
<th style="width: 475px;"><strong>Description</strong></th>
<th style="width: 97px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168px;">name</td>
<td style="width: 475px;">Name for the custom URL category to create.</td>
<td style="width: 97px;">Required</td>
</tr>
<tr>
<td style="width: 168px;">description</td>
<td style="width: 475px;">Description of the custom URL category to create.</td>
<td style="width: 97px;">Optional</td>
</tr>
<tr>
<td style="width: 168px;">sites</td>
<td style="width: 475px;">List of sites for the custom URL category.</td>
<td style="width: 97px;">Optional</td>
</tr>
<tr>
<td style="width: 168px;">device-group</td>
<td style="width: 475px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 97px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 378px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 300px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 378px;">Panorama.CustomURLCategory.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 300px;">Custom URL category name</td>
</tr>
<tr>
<td style="width: 378px;">Panorama.CustomURLCategory.Description</td>
<td style="width: 62px;">string</td>
<td style="width: 300px;">Custom URL category description.</td>
</tr>
<tr>
<td style="width: 378px;">Panorama.CustomURLCategory.Sites</td>
<td style="width: 62px;">string</td>
<td style="width: 300px;">Custom URL category list of sites.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-create-custom-url-category name=suspicious_address_group sites=["thepill.com","abortion.com"] description=momo</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50423804-fd3d9700-0862-11e9-8554-a0c5040ecf50.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50423804-fd3d9700-0862-11e9-8554-a0c5040ecf50.png" alt="screen shot 2018-12-25 at 16 34 18"></a></p>
<h3 id="h_69714146472431545894462566">15. Delete a custom URL category</h3>
<hr>
<p>Deletes a custom URL category.</p>
<h5>Base Command</h5>
<p><code>panorama-delete-custom-url-category</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 182px;"><strong>Argument Name</strong></th>
<th style="width: 453px;"><strong>Description</strong></th>
<th style="width: 105px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 182px;">name</td>
<td style="width: 453px;">Name of the custom URL category to delete.</td>
<td style="width: 105px;">Optional</td>
</tr>
<tr>
<td style="width: 182px;">device-group</td>
<td style="width: 453px;">
<span>The device group for which to return addresses (Panorama instances). </span>If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 105px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 315px;"><strong>Path</strong></th>
<th style="width: 54px;"><strong>Type</strong></th>
<th style="width: 371px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 315px;">Panorama.CustomURLCategory.Name</td>
<td style="width: 54px;">string</td>
<td style="width: 371px;">Name of the custom URL category to delete.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-delete-custom-url-category name=suspicious_address_group</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50423810-147c8480-0863-11e9-8a4d-4ae8386b3128.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50423810-147c8480-0863-11e9-8a4d-4ae8386b3128.png" alt="screen shot 2018-12-25 at 16 35 12"></a></p>
<h3 id="h_15757837375651545894471041">16. Add/Remove sites from a custom URL category</h3>
<hr>
<p>Add sites to, or remove sites from a custom URL category.</p>
<h5>Base Command</h5>
<p><code>panorama-edit-custom-url-category</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 156px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 85px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 156px;">name</td>
<td style="width: 499px;">Name of the custom URL category to which to add or remove sites.</td>
<td style="width: 85px;">Required</td>
</tr>
<tr>
<td style="width: 156px;">sites</td>
<td style="width: 499px;">CSV list of sites to add to the custom URL category.</td>
<td style="width: 85px;">Required</td>
</tr>
<tr>
<td style="width: 156px;">action</td>
<td style="width: 499px;">Add or remove sites; "add" or "remove".</td>
<td style="width: 85px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 376px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 300px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 376px;">Panorama.CustomURLCategory.Name</td>
<td style="width: 64px;">string</td>
<td style="width: 300px;">Custom URL category name.</td>
</tr>
<tr>
<td style="width: 376px;">Panorama.CustomURLCategory.Description</td>
<td style="width: 64px;">string</td>
<td style="width: 300px;">Custom URL category description.</td>
</tr>
<tr>
<td style="width: 376px;">Panorama.CustomURLCategory.Sites</td>
<td style="width: 64px;">string</td>
<td style="width: 300px;">Custom URL category list of sites.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Human Readable Output</h5>
<h3 id="h_87493434580411545894477329">17. Get details for a URL category</h3>
<hr>
<p>Gets a URL category from URL Filtering.</p>
<h5>Base Command</h5>
<p><code>panorama-get-url-category</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 319px;"><strong>Argument Name</strong></th>
<th style="width: 239px;"><strong>Description</strong></th>
<th style="width: 182px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 319px;">url</td>
<td style="width: 239px;">URL to check.</td>
<td style="width: 182px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 426px;"><strong>Path</strong></th>
<th style="width: 122px;"><strong>Type</strong></th>
<th style="width: 192px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 426px;">Panorama.URLFiltering.URL</td>
<td style="width: 122px;">string</td>
<td style="width: 192px;">URL.</td>
</tr>
<tr>
<td style="width: 426px;">Panorama.URLFiltering.Category</td>
<td style="width: 122px;">string</td>
<td style="width: 192px;">URL category.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-get-url-category url="poker.com"</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50422009-41726c80-084e-11e9-9c56-234b51b34f01.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50422009-41726c80-084e-11e9-9c56-234b51b34f01.png" alt="screen shot 2018-12-25 at 14 06 07"></a></p>
<h3 id="h_7426967282031545894498970">18. Get details for a URL filtering rule</h3>
<hr>
<p>Get information for a URL filtering rule.</p>
<h5>Base Command</h5>
<p><code>panorama-get-url-filter</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 163px;"><strong>Argument Name</strong></th>
<th style="width: 456px;"><strong>Description</strong></th>
<th style="width: 121px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 163px;">name</td>
<td style="width: 456px;">URL filter name.</td>
<td style="width: 121px;">Required</td>
</tr>
<tr>
<td style="width: 163px;">device-group</td>
<td style="width: 456px;"><span>The device group for which to return addresses (Panorama instances). If no value is supplied, the default group configured integration parameter is applied.</span></td>
<td style="width: 121px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 381px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 291px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 381px;">Panorama.URLFilter.Name</td>
<td style="width: 68px;">string</td>
<td style="width: 291px;">URL filter name.</td>
</tr>
<tr>
<td style="width: 381px;">Panorama.URLFilter.Category.Name</td>
<td style="width: 68px;">string</td>
<td style="width: 291px;">URL filter category name.</td>
</tr>
<tr>
<td style="width: 381px;">Panorama.URLFilter.Category.Action</td>
<td style="width: 68px;">string</td>
<td style="width: 291px;">Action for the URL category.</td>
</tr>
<tr>
<td style="width: 381px;">Panorama.URLFilter.OverrideBlockList</td>
<td style="width: 68px;">string</td>
<td style="width: 291px;">URL filter override block list.</td>
</tr>
<tr>
<td style="width: 381px;">Panorama.URLFilter.OverrideAllowList</td>
<td style="width: 68px;">string</td>
<td style="width: 291px;">URL filter override allow list.</td>
</tr>
<tr>
<td style="width: 381px;">Panorama.URLFilter.Description</td>
<td style="width: 68px;">string</td>
<td style="width: 291px;">URL filter description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-get-url-filter name=demisto_default_url_filter</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50422729-8221b400-0855-11e9-9f12-382685a708b3.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50422729-8221b400-0855-11e9-9f12-382685a708b3.png" alt="screen shot 2018-12-25 at 14 58 04"></a></p>
<h3 id="h_49203186986741545894507538">19. Create a URL filtering rule</h3>
<hr>
<p>Creates a URL filtering rule.</p>
<h5>Base Command</h5>
<p><code>panorama-create-url-filter</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 145px;"><strong>Argument Name</strong></th>
<th style="width: 524px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145px;">name</td>
<td style="width: 524px;">Name of the URL filter to create.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">url_category</td>
<td style="width: 524px;">One or more URL categories.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">action</td>
<td style="width: 524px;">Action for the URL categories; "allow", "block", "alert", "continue", "override".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">override_allow_list</td>
<td style="width: 524px;">CSV list of URLs to exclude from the allow list.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">override_block_list</td>
<td style="width: 524px;">CSV list of URLs to exclude from the block list.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">description</td>
<td style="width: 524px;">URL filter description.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">device-group</td>
<td style="width: 524px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 382px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 291px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 382px;">Panorama.URLFilter.Name</td>
<td style="width: 67px;">string</td>
<td style="width: 291px;">URL filter name</td>
</tr>
<tr>
<td style="width: 382px;">Panorama.URLFilter.Category.Name</td>
<td style="width: 67px;">string</td>
<td style="width: 291px;">URL filter category name</td>
</tr>
<tr>
<td style="width: 382px;">Panorama.URLFilter.Category.Action</td>
<td style="width: 67px;">string</td>
<td style="width: 291px;">Action for the URL category</td>
</tr>
<tr>
<td style="width: 382px;">Panorama.URLFilter.OverrideBlockList</td>
<td style="width: 67px;">string</td>
<td style="width: 291px;">URL filter override allow list</td>
</tr>
<tr>
<td style="width: 382px;">Panorama.URLFilter.OverrideBlockList</td>
<td style="width: 67px;">string</td>
<td style="width: 291px;">URL filter override block list</td>
</tr>
<tr>
<td style="width: 382px;">Panorama.URLFilter.Description</td>
<td style="width: 67px;">string</td>
<td style="width: 291px;">URL filter description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_70728994189871545894514725">20. Edit a URL filter</h3>
<hr>
<p>Name of the URL filter to edit.</p>
<h5>Base Command</h5>
<p><code>panorama-edit-url-filter</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 163px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 163px;">name</td>
<td style="width: 506px;">URL filter to edit</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 163px;">element_to_change</td>
<td style="width: 506px;">Element to change; "override_allow_list", "ovveride_block_list"</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 163px;">element_value</td>
<td style="width: 506px;">Element value, limited to one value.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 163px;">add_remove_element</td>
<td style="width: 506px;">Add or remove an element from the Allow List field or Block List field, default is "add" the element_value to the list.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 345px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 334px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 345px;">Panorama.URLFilter.Name</td>
<td style="width: 61px;">string</td>
<td style="width: 334px;">URL filter name.</td>
</tr>
<tr>
<td style="width: 345px;">Panorama.URLFilter.Description</td>
<td style="width: 61px;">string</td>
<td style="width: 334px;">URL filter description.</td>
</tr>
<tr>
<td style="width: 345px;">Panorama.URLFilter.Category.Name</td>
<td style="width: 61px;">string</td>
<td style="width: 334px;">URL filter category.</td>
</tr>
<tr>
<td style="width: 345px;">Panorama.URLFilter.Action</td>
<td style="width: 61px;">string</td>
<td style="width: 334px;">Action for the URL category.</td>
</tr>
<tr>
<td style="width: 345px;">Panorama.URLFilter.OverrideAllowList</td>
<td style="width: 61px;">string</td>
<td style="width: 334px;">Allow Overrides for the URL category.</td>
</tr>
<tr>
<td style="width: 345px;">Panorama.URLFilter.OverrideBlockList</td>
<td style="width: 61px;">string</td>
<td style="width: 334px;">Block Overrides for the URL category.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-edit-url-filter name=demisto_default_url_filter element_to_change=override_allow_list element_value="poker.com" add_remove_element=add</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50422758-cb720380-0855-11e9-9741-7471db17eef8.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50422758-cb720380-0855-11e9-9741-7471db17eef8.png" alt="screen shot 2018-12-25 at 15 00 05"></a></p>
<h3 id="h_51942600592991545894523815">21. Delete a URL filtering rule</h3>
<hr>
<p>Deletes a URL filtering rule.</p>
<h5>Base Command</h5>
<p><code>panorama-delete-url-filter</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 204px;"><strong>Argument Name</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
<th style="width: 117px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 204px;">name</td>
<td style="width: 419px;">Name of the URL filter rule to delete.</td>
<td style="width: 117px;">Required</td>
</tr>
<tr>
<td style="width: 204px;">device-group</td>
<td style="width: 419px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 117px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 353px;"><strong>Path</strong></th>
<th style="width: 101px;"><strong>Type</strong></th>
<th style="width: 286px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 353px;">Panorama.URLFilter.Name</td>
<td style="width: 101px;">string</td>
<td style="width: 286px;">URL filter rule name that was deleted.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_28406745597601545894536518">22. Create a policy rule</h3>
<hr>
<p>Creates a policy rule.</p>
<h5>Base Command</h5>
<p><code>panorama-create-rule</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 524px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">rulename</td>
<td style="width: 524px;">Name of the rule to create.</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">description</td>
<td style="width: 524px;">Description of the rule to create.</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">action</td>
<td style="width: 524px;">Action for the rule; "allow", "deny", "drop".</td>
<td style="width: 72px;">Required</td>
</tr>
<tr>
<td style="width: 144px;">source</td>
<td style="width: 524px;">Source address; "address", "address group".</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">destination</td>
<td style="width: 524px;">Destination address; "address", "address group".</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">source_zone</td>
<td style="width: 524px;">A comma-separated list of source zones..</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">destination_zone</td>
<td style="width: 524px;">A comma-separated list of source zones..</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">negate_source</td>
<td style="width: 524px;">Whether to negate the source (address, address group); "Yes" or "No".</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">negate_destination</td>
<td style="width: 524px;">Whether to negate the destination (address, address group); "Yes" or "No".</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">service</td>
<td style="width: 524px;">Service for the rule (service object) to create.</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">disable</td>
<td style="width: 524px;">Whether to disable the rule; "Yes" or "No" (default is "No").</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">application</td>
<td style="width: 524px;">Application for the rule to create.</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">source_user</td>
<td style="width: 524px;">Source user for the rule to create.</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">pre_post</td>
<td style="width: 524px;">Pre rule or Post rule.</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">target</td>
<td style="width: 524px;">Specify a target firewall for the rule.</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">log_forwarding</td>
<td style="width: 524px;"><span>Log forwarding profile (Panorama instances).</span></td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">device-group</td>
<td style="width: 524px;"><span>The device group for which to return addresses for the rule (Panorama instances). If no value is supplied, the default group configured integration parameter is applied.</span></td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">tags</td>
<td style="width: 524px;"><span>Rule tags to create.</span></td>
<td style="width: 72px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 313px;"><strong>Path</strong></th>
<th style="width: 49px;"><strong>Type</strong></th>
<th style="width: 378px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 313px;">Panorama.SecurityRule.Name</td>
<td style="width: 49px;">string</td>
<td style="width: 378px;">Rule name.</td>
</tr>
<tr>
<td style="width: 313px;">Panorama.SecurityRule.Description</td>
<td style="width: 49px;">string</td>
<td style="width: 378px;">Rule description.</td>
</tr>
<tr>
<td style="width: 313px;">Panorama.SecurityRule.Action</td>
<td style="width: 49px;">string</td>
<td style="width: 378px;">Action for the rule.</td>
</tr>
<tr>
<td style="width: 313px;">Panorama.SecurityRule.Source</td>
<td style="width: 49px;">string</td>
<td style="width: 378px;">Source address.</td>
</tr>
<tr>
<td style="width: 313px;">Panorama.SecurityRule.Destination</td>
<td style="width: 49px;">string</td>
<td style="width: 378px;">Destination address.</td>
</tr>
<tr>
<td style="width: 313px;">Panorama.SecurityRule.NegateSource</td>
<td style="width: 49px;">boolean</td>
<td style="width: 378px;">Whether the source is negated (address, address group).</td>
</tr>
<tr>
<td style="width: 313px;">Panorama.SecurityRule.NegateDestination</td>
<td style="width: 49px;">boolean</td>
<td style="width: 378px;">Whether the destination is negated (address, address group).</td>
</tr>
<tr>
<td style="width: 313px;">Panorama.SecurityRule.Service</td>
<td style="width: 49px;">string</td>
<td style="width: 378px;">Service for the rule.</td>
</tr>
<tr>
<td style="width: 313px;">Panorama.SecurityRule.Disabled</td>
<td style="width: 49px;">string</td>
<td style="width: 378px;">Whether the rule is disabled.</td>
</tr>
<tr>
<td style="width: 313px;">Panorama.SecurityRule.Application</td>
<td style="width: 49px;">string</td>
<td style="width: 378px;">Application for the rule.</td>
</tr>
<tr>
<td style="width: 313px;">Panorama.SecurityRule.Target</td>
<td style="width: 49px;">string</td>
<td style="width: 378px;">Target firewall.</td>
</tr>
<tr>
<td style="width: 313px;"><span>Panorama.SecurityRule.LogForwarding</span></td>
<td style="width: 49px;">string</td>
<td style="width: 378px;"><span>Log forwarding profile (Panorama instances).</span></td>
</tr>
<tr>
<td style="width: 313px;"><span>Panorama.SecurityRule.DeviceGroup</span></td>
<td style="width: 49px;">string</td>
<td style="width: 378px;"><span>Device group for the rule (Panorama instances).</span></td>
</tr>
<tr>
<td style="width: 313px;"><span>Panorama.SecurityRules.Tags</span></td>
<td style="width: 49px;">string</td>
<td style="width: 378px;"><span>Rule tags.</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-create-rule rulename="block_bad_application" description="do not play at work" action="deny" application="fortnite"</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50422080-28b68680-084f-11e9-98c8-e1145c3322c9.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50422080-28b68680-084f-11e9-98c8-e1145c3322c9.png" alt="screen shot 2018-12-25 at 14 12 20"></a></p>
<h3 id="h_353141275100681545894548340">23. Create a custom block policy rule</h3>
<hr>
<p>Creates a custom block policy rule.</p>
<h5>Base Command</h5>
<p><code>panorama-custom-block-rule</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 155px;"><strong>Argument Name</strong></th>
<th style="width: 514px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">rulename</td>
<td style="width: 514px;">Name of the custom block policy rule to create.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">object_type</td>
<td style="width: 514px;">Object type to block in the policy rule. Can be "ip", "address-group", "edl", or "custom-url-category".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">object_value</td>
<td style="width: 514px;">Object value.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">direction</td>
<td style="width: 514px;">Direction to block. Can be "to", "from", or "both". Default is "both". This argument is not applicable to the "custom-url-category" object_type.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">pre_post</td>
<td style="width: 514px;">Pre rule or Post rule.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">target</td>
<td style="width: 514px;">Specify a target firewall for the rule.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">log_forwarding</td>
<td style="width: 514px;"><span>Log forwarding profile (Panorama instances).</span></td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">device-group</td>
<td style="width: 514px;">
<span>The device group for which to return addresses for the rule (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">tags</td>
<td style="width: 514px;">The tags for the custom block policy rule.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 314px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 362px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 314px;">Panorama.SecurityRule.Name</td>
<td style="width: 64px;">string</td>
<td style="width: 362px;">Rule name.</td>
</tr>
<tr>
<td style="width: 314px;">Panorama.SecurityRule.Object</td>
<td style="width: 64px;">string</td>
<td style="width: 362px;">Blocked object.</td>
</tr>
<tr>
<td style="width: 314px;">Panorama.SecurityRule.Direction</td>
<td style="width: 64px;">string</td>
<td style="width: 362px;">Direction blocked.</td>
</tr>
<tr>
<td style="width: 314px;">Panorama.SecurityRule.Target</td>
<td style="width: 64px;">string</td>
<td style="width: 362px;">Target firewall.</td>
</tr>
<tr>
<td style="width: 314px;"><span>Panorama.SecurityRule.LogForwarding</span></td>
<td style="width: 64px;">string</td>
<td style="width: 362px;"><span>Log forwarding profile (Panorama instances).</span></td>
</tr>
<tr>
<td style="width: 314px;"><span>Panorama.SecurityRule.DeviceGroup</span></td>
<td style="width: 64px;">string</td>
<td style="width: 362px;"><span>Device group for the rule (Panorama instances).</span></td>
</tr>
<tr>
<td style="width: 314px;"><span>Panorama.SecurityRule.Tags</span></td>
<td style="width: 64px;">string</td>
<td style="width: 362px;"><span>Rule tags.</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_189209860103731545894553169">24. Change the location of a policy rule</h3>
<hr>
<p>Changes the location of a policy rule.</p>
<h5>Base Command</h5>
<p><code>panorama-move-rule</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 133px;"><strong>Argument Name</strong></th>
<th style="width: 536px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133px;">rulename</td>
<td style="width: 536px;">Name of the rule to move.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133px;">where</td>
<td style="width: 536px;">Where to move the rule to; "before", "after", "top", or "bottom". If you specify "up" or "down", you need to supply the "dst" argument.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133px;">dst</td>
<td style="width: 536px;">Destination rule relative to the rule you are moving. Only supply this argument if you specified "up" or "down" for the "where" argument.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">pre_post</td>
<td style="width: 536px;">Rule location. </td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">device-group</td>
<td style="width: 536px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 443px;"><strong>Path</strong></th>
<th style="width: 101px;"><strong>Type</strong></th>
<th style="width: 196px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 443px;">Panorama.SecurityRule.Name</td>
<td style="width: 101px;">string</td>
<td style="width: 196px;">Rule name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-move-rule rulename="test_rule3" where="bottom"</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50422050-957d5100-084e-11e9-8770-37b43d214dc3.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50422050-957d5100-084e-11e9-8770-37b43d214dc3.png" alt="screen shot 2018-12-25 at 14 08 18"></a></p>
<h3 id="h_626779749108261545894558673">25. Edit a policy rule</h3>
<hr>
<p>Edit a policy rule.</p>
<h5>Base Command</h5>
<p><code>panorama-edit-rule</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 162px;"><strong>Argument Name</strong></th>
<th style="width: 507px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162px;">rulename</td>
<td style="width: 507px;">Name of the rule to edit.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 162px;">element_to_change</td>
<td style="width: 507px;">Parameter in the security rule to change. Can be "source", "destination", "application", "action", "category", "description", "disabled", "target", "log-forwarding", or "tag".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 162px;">element_value</td>
<td style="width: 507px;">New value for the parameter.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 162px;">pre_post</td>
<td style="width: 507px;">Pre rule or Post rule (Panorama instances).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 301px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 378px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 301px;">Panorama.SecurityRule.Name</td>
<td style="width: 61px;">string</td>
<td style="width: 378px;">Rule name.</td>
</tr>
<tr>
<td style="width: 301px;">Panorama.SecurityRule.Description</td>
<td style="width: 61px;">string</td>
<td style="width: 378px;">Rule description.</td>
</tr>
<tr>
<td style="width: 301px;">Panorama.SecurityRule.Action</td>
<td style="width: 61px;">string</td>
<td style="width: 378px;">Action for the rule.</td>
</tr>
<tr>
<td style="width: 301px;">Panorama.SecurityRule.Source</td>
<td style="width: 61px;">string</td>
<td style="width: 378px;">Source address.</td>
</tr>
<tr>
<td style="width: 301px;">Panorama.SecurityRule.Destination</td>
<td style="width: 61px;">string</td>
<td style="width: 378px;">Destination address.</td>
</tr>
<tr>
<td style="width: 301px;">Panorama.SecurityRule.NegateSource</td>
<td style="width: 61px;">boolean</td>
<td style="width: 378px;">Is the source negated (address, address group).</td>
</tr>
<tr>
<td style="width: 301px;">Panorama.SecurityRule.NegateDestination</td>
<td style="width: 61px;">boolean</td>
<td style="width: 378px;">Is the destination negated (address, address group).</td>
</tr>
<tr>
<td style="width: 301px;">Panorama.SecurityRule.Service</td>
<td style="width: 61px;">string</td>
<td style="width: 378px;">Service for the rule.</td>
</tr>
<tr>
<td style="width: 301px;">Panorama.SecurityRule.Disabled</td>
<td style="width: 61px;">string</td>
<td style="width: 378px;">Is the rule disabled.</td>
</tr>
<tr>
<td style="width: 301px;">Panorama.SecurityRule.Application</td>
<td style="width: 61px;">string</td>
<td style="width: 378px;">Application for the rule.</td>
</tr>
<tr>
<td style="width: 301px;">Panorama.SecurityRule.Target</td>
<td style="width: 61px;">string</td>
<td style="width: 378px;">Target firewall (Panorama instances).</td>
</tr>
<tr>
<td style="width: 301px;"><span>Panorama.SecurityRule.DeviceGroup</span></td>
<td style="width: 61px;">string</td>
<td style="width: 378px;">
<span> </span><span class="pl-s">Device group for the rule (Panorama instances).</span>
</td>
</tr>
<tr>
<td style="width: 301px;"><span>Panorama.SecurityRule.Tags</span></td>
<td style="width: 61px;">string</td>
<td style="width: 378px;"><span>Tags for the rule.</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-edit-rule rulename="block_bad_application" element_to_change=action element_value=drop</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50422247-8cda4a00-0851-11e9-8fb5-4c97c3f6a88b.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50422247-8cda4a00-0851-11e9-8fb5-4c97c3f6a88b.png" alt="screen shot 2018-12-25 at 14 29 40"></a></p>
<h3 id="h_372847952111281545894564883">26. Delete a policy rule</h3>
<hr>
<p>Deletes a policy rule.</p>
<h5>Base Command</h5>
<p><code>panorama-delete-rule</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 183px;"><strong>Argument Name</strong></th>
<th style="width: 451px;"><strong>Description</strong></th>
<th style="width: 106px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 183px;">rulename</td>
<td style="width: 451px;">Name of the rule to delete.</td>
<td style="width: 106px;">Required</td>
</tr>
<tr>
<td style="width: 183px;">pre_post</td>
<td style="width: 451px;">Pre rule or Post rule (Panorama instances).</td>
<td style="width: 106px;">Optional</td>
</tr>
<tr>
<td style="width: 183px;">device-group</td>
<td style="width: 451px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 106px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 435px;"><strong>Path</strong></th>
<th style="width: 109px;"><strong>Type</strong></th>
<th style="width: 196px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 435px;">Panorama.SecurityRule.Name</td>
<td style="width: 109px;">string</td>
<td style="width: 196px;">Rule name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-delete-rule rulename=block_bad_application</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50422263-b5fada80-0851-11e9-8001-30c064ddf257.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50422263-b5fada80-0851-11e9-8001-30c064ddf257.png" alt="screen shot 2018-12-25 at 14 30 48"></a></p>
<h3 id="h_476348815115751545894571725">27. Get a list of applications</h3>
<hr>
<p>Returns a list of predefined applications.</p>
<h5>Base Command</h5>
<p><code>panorama-list-applications</code></p>
<h5>Input</h5>
<p>There are no input arguments for this command.</p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 380px;"><strong>Path</strong></th>
<th style="width: 95px;"><strong>Type</strong></th>
<th style="width: 265px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 380px;">Panorama.Applications.Name</td>
<td style="width: 95px;">string</td>
<td style="width: 265px;">Application name.</td>
</tr>
<tr>
<td style="width: 380px;">Panorama.Applications.Id</td>
<td style="width: 95px;">number</td>
<td style="width: 265px;">Application ID.</td>
</tr>
<tr>
<td style="width: 380px;">Panorama.Applications.Category</td>
<td style="width: 95px;">string</td>
<td style="width: 265px;">Application category.</td>
</tr>
<tr>
<td style="width: 380px;">Panorama.Applications.SubCategory</td>
<td style="width: 95px;">string</td>
<td style="width: 265px;">Application sub-category.</td>
</tr>
<tr>
<td style="width: 380px;">Panorama.Applications.Technology</td>
<td style="width: 95px;">string</td>
<td style="width: 265px;">Application technology.</td>
</tr>
<tr>
<td style="width: 380px;">Panorama.Applications.Risk</td>
<td style="width: 95px;">number</td>
<td style="width: 265px;">Application risk (1-5).</td>
</tr>
<tr>
<td style="width: 380px;">Panorama.Applications.Description</td>
<td style="width: 95px;">string</td>
<td style="width: 265px;">Application description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-list-applications</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50422304-1f7ae900-0852-11e9-9da4-d94e94992a89.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50422304-1f7ae900-0852-11e9-9da4-d94e94992a89.png" alt="screen shot 2018-12-25 at 14 33 50"></a></p>
<h3 id="h_298117829120191545894577230">28. Get the commit status for a configuration</h3>
<hr>
<p>Get the commit status for a configuration.</p>
<h5>Base Command</h5>
<p><code>panorama-commit-status</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 297px;"><strong>Argument Name</strong></th>
<th style="width: 271px;"><strong>Description</strong></th>
<th style="width: 172px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 297px;">job_id</td>
<td style="width: 271px;">Job ID to check.</td>
<td style="width: 172px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 242px;"><strong>Path</strong></th>
<th style="width: 81px;"><strong>Type</strong></th>
<th style="width: 417px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 242px;">Panorama.Commit.JobID</td>
<td style="width: 81px;">number</td>
<td style="width: 417px;">Job ID of the configuration to be committed.</td>
</tr>
<tr>
<td style="width: 242px;">Panorama.Commit.Status</td>
<td style="width: 81px;">string</td>
<td style="width: 417px;">Commit status.</td>
</tr>
<tr>
<td style="width: 242px;">Panorama.Commit.Details</td>
<td style="width: 81px;">string</td>
<td style="width: 417px;">Job ID details.</td>
</tr>
<tr>
<td style="width: 242px;">Panorama.Commit.Warnings</td>
<td style="width: 81px;">string</td>
<td style="width: 417px;">Job ID warnings.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-commit-status job_id=948</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50422779-0d02ae80-0856-11e9-8b96-f0c9a9daeb29.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50422779-0d02ae80-0856-11e9-8b96-f0c9a9daeb29.png" alt="screen shot 2018-12-25 at 15 01 14"></a></p>
<h3 id="h_432098286126051545894584071">29. Get the push status for a configuration</h3>
<hr>
<p>Get the push status for a configuration.</p>
<h5>Base Command</h5>
<p><code>panorama-push-status</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 296px;"><strong>Argument Name</strong></th>
<th style="width: 272px;"><strong>Description</strong></th>
<th style="width: 172px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 296px;">job_id</td>
<td style="width: 272px;">Job ID to check.</td>
<td style="width: 172px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 258px;"><strong>Path</strong></th>
<th style="width: 82px;"><strong>Type</strong></th>
<th style="width: 400px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 258px;">Panorama.Push.DeviceGroup</td>
<td style="width: 82px;">string</td>
<td style="width: 400px;">Device group to which the policies were pushed.</td>
</tr>
<tr>
<td style="width: 258px;">Panorama.Push.JobID</td>
<td style="width: 82px;">number</td>
<td style="width: 400px;">Job ID of the configuration to be pushed.</td>
</tr>
<tr>
<td style="width: 258px;">Panorama.Push.Status</td>
<td style="width: 82px;">string</td>
<td style="width: 400px;">Push status.</td>
</tr>
<tr>
<td style="width: 258px;">Panorama.Push.Details</td>
<td style="width: 82px;">string</td>
<td style="width: 400px;">Job ID details.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-push-status job_id=951</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/50423067-117c9680-0859-11e9-9cdb-99cca8b4b78e.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/50423067-117c9680-0859-11e9-9cdb-99cca8b4b78e.png" alt="screen shot 2018-12-25 at 15 23 18"></a></p>
<h3 id="h_7213490231451549377931816">30. Get a list of services</h3>
<hr>
<p>Returns a list of all services.</p>
<h5>Base Command</h5>
<p><code>panorama-list-services</code></p>
<h5>Input</h5>
<table style="width: 745px;">
<tbody>
<tr>
<th style="width: 161px;"><strong>Argument Name</strong></th>
<th style="width: 441px;"><strong>Description</strong></th>
<th style="width: 138px;"><strong>Required</strong></th>
</tr>
<tr>
<td style="width: 161px;">device-group</td>
<td style="width: 441px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 138px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">tag</td>
<td style="width: 441px;">The tag for which to filter the service.</td>
<td style="width: 138px;">Optional</td>
</tr>
</tbody>
</table>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 291px;">Path</td>
<td style="width: 87px;">Type</td>
<td style="width: 362px;">Description</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 291px;">Panorama.Services.Name</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service name.</td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.Protocol</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service protocol.</td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.Description</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service description.</td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.DestinationPort</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service destination port.</td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.SourcePort</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service source port.</td>
</tr>
<tr>
<td style="width: 291px;"><span>Panorama.Services.DeviceGroup</span></td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service device group.</td>
</tr>
<tr>
<td style="width: 291px;"><span>Panorama.Services.Tags</span></td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service tags.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-list-services</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37335599/51698000-d9ac6e80-2011-11e9-8c7f-45594abca515.png" alt="screen shot 2019-01-24 at 19 52 45"></p>
<h3 id="h_7054447343481549377938336">31. Get information for a service</h3>
<hr>
<p>Returns service details for the supplied service name.</p>
<h5>Base Command</h5>
<p><code>panorama-get-service</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 133px;">Argument Name</td>
<td style="width: 544px;">Description</td>
<td style="width: 63px;">Required</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133px;">name</td>
<td style="width: 544px;">Service name.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">device-group</td>
<td style="width: 544px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 63px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 291px;">Path</td>
<td style="width: 87px;">Type</td>
<td style="width: 362px;">Description</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 291px;">Panorama.Services.Name</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service name.</td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.Protocol</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service protocol.</td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.Description</td>
<td style="width: 87px;">string </td>
<td style="width: 362px;">Service descriptions.</td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.DestinationPort</td>
<td style="width: 87px;">string </td>
<td style="width: 362px;">Service destination port. </td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.SourcePort</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service source port.</td>
</tr>
<tr>
<td style="width: 291px;"><span>Panorama.Services.DeviceGroup</span></td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service device group.</td>
</tr>
<tr>
<td style="width: 291px;"><span>Panorama.Service.Tags</span></td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service tags.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-get-service name=guy_ser3</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37335599/51698044-ee890200-2011-11e9-87fc-5ac433cee710.png" alt="screen shot 2019-01-24 at 19 53 04"></p>
<h3 id="h_9044031655501549377945144">32. Create a service</h3>
<hr>
<p>Creates a service.</p>
<h5>Base Command</h5>
<p><code>panorama-create-service</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<td style="width: 149px;">Argument Name</td>
<td style="width: 528px;">Description</td>
<td style="width: 63px;">Required</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">name</td>
<td style="width: 528px;">Name for the new service.</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 149px;">protocol</td>
<td style="width: 528px;">Protocol for the new service.</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 149px;">destination_port</td>
<td style="width: 528px;">Destination port for the new service.</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 149px;">source_port</td>
<td style="width: 528px;">Source port for the new service.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">description</td>
<td style="width: 528px;">Description of the new service.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">device-group</td>
<td style="width: 528px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">tags</td>
<td style="width: 528px;">The tags for the new service.</td>
<td style="width: 63px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 291px;">Path</td>
<td style="width: 87px;">Type</td>
<td style="width: 362px;">Description</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 291px;">Panorama.Services.Name</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service name.</td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.Protocol</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service protocol.</td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.Description</td>
<td style="width: 87px;">string </td>
<td style="width: 362px;">Service descriptions.</td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.DestinationPort</td>
<td style="width: 87px;">string </td>
<td style="width: 362px;">Service destination port.</td>
</tr>
<tr>
<td style="width: 291px;">Panorama.Services.SourcePort</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service source port.</td>
</tr>
<tr>
<td style="width: 291px;"><span>Panorama.Services.DeviceGroup</span></td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service device group.</td>
</tr>
<tr>
<td style="width: 291px;"><span>Panorama.Services.Tags</span></td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service tags.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-create-service name=guy_ser3 protocol=udp destination_port=36 description=bfds</pre>
<h5>Human Readable Output</h5>
<p>placeholder</p>
<h3 id="h_66783294117261549377952328">33. Delete a service</h3>
<hr>
<p>Deletes a service.</p>
<h5>Base Command</h5>
<p><code>panorama-delete-service</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 176px;">Argument Name</td>
<td style="width: 501px;">Description</td>
<td style="width: 63px;">Required</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 176px;">name</td>
<td style="width: 501px;">Name of the service to delete.</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 176px;">device-group</td>
<td style="width: 501px;">
<span>The device group for which to return addresses (Panorama instances). </span>If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 63px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 291px;">Path</td>
<td style="width: 87px;">Type</td>
<td style="width: 362px;">Description</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 291px;">Panorama.Services.Name</td>
<td style="width: 87px;">string</td>
<td style="width: 362px;">Service name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-delete-service name=guy_ser3</pre>
<h5>Human Readable Output</h5>
<p>placeholder</p>
<h3 id="h_66708612219261549377957626">34. Get a list of service groups</h3>
<hr>
<p>Returns a list of service groups.</p>
<h5>Base Command</h5>
<p><code>panorama-list-service-groups</code></p>
<h5>Input</h5>
<table style="width: 745px;">
<tbody>
<tr>
<th style="width: 166px;">Argument Name</th>
<th style="width: 166px;">Description</th>
<th style="width: 166px;">Required</th>
</tr>
<tr>
<td style="width: 166px;">device-group</td>
<td style="width: 511px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 63px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 id="context-output">Context Output</h5>
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 198px;"><strong>Path</strong></th>
<th style="width: 123px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198px;">Panarama.ServiceGroups.Name</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">Service group name</td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.Services</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">Service group related services</td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.DeviceGroup</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;"><span>Service device group.</span></td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.Tags</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;"><span>Service tags.</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-list-service-groups</pre>
<h5>Human Readable Output</h5>
<p>placeholder</p>
</div>
<p> </p>
<h3 id="h_1b918da1-b45b-4738-a07a-a483eacb59ff">35. Get information for a service group</h3>
<hr>
<p>Returns details for the specified service group.</p>
<h5>Base Command</h5>
<p><code>panorama-get-service-group</code></p>
<h5>Input</h5>
<table style="width: 745px;">
<tbody>
<tr>
<th style="width: 166px;">Argument Name</th>
<th style="width: 166px;">Description</th>
<th style="width: 166px;">Required</th>
</tr>
<tr>
<td style="width: 166px;">name</td>
<td style="width: 511px;">Service group name.</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 166px;">device-group</td>
<td style="width: 511px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 63px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 id="context-output">Context Output</h5>
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 198px;"><strong>Path</strong></th>
<th style="width: 123px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198px;">Panarama.ServiceGroups.Name</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">Service group name.</td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.Services</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">Service group related services.</td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.DeviceGroup</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;"><span>Service device group.</span></td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.Tags</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;"><span>Service group tags.</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-get-service-group name=ser_group6</pre>
<h5>Human Readable Output</h5>
<p>placeholder</p>
</div>
<p> </p>
<h3 id="h_6f00ae35-41ae-48c2-92d3-f10f29459f88">36. Create a service group</h3>
<hr>
<p>Creates a service group.</p>
<h5>Base Command</h5>
<p><code>panorama-create-service-group</code></p>
<h5>Input</h5>
<table style="width: 745px;">
<tbody>
<tr>
<th style="width: 166px;">Argument Name</th>
<th style="width: 166px;">Description</th>
<th style="width: 166px;">Required</th>
</tr>
<tr>
<td style="width: 166px;">name</td>
<td style="width: 511px;">Service group Name.</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 166px;">services</td>
<td style="width: 511px;">Service group related services.</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 166px;">device-group</td>
<td style="width: 511px;">
<span> </span><span class="pl-s">The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 166px;">tags</td>
<td style="width: 511px;">The tags for which to filter the service groups.</td>
<td style="width: 63px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 id="context-output">Context Output</h5>
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 198px;"><strong>Path</strong></th>
<th style="width: 123px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198px;">Panarama.ServiceGroups.Name</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">Service group name.</td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.Services</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">Service group related services.</td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.DeviceGroup</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;"><span>Service device group.</span></td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.Tags</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;"><span>Service group tags.</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>    !panorama-create-service-group name=lalush_sg4 services=`["demisto_service1","demi_service_test_pb"]
  </pre>
<p> </p>
<h5>Human Readable Output</h5>
<p>placeholder</p>
</div>
<p> </p>
<h3 id="h_47461b58-42a1-44cc-b0c9-41ec5c44c665">37. Delete a service group</h3>
<hr>
<p>Deletes a service group.</p>
<h5>Base Command</h5>
<p><code>panorama-delete-service-group</code></p>
<h5>Input</h5>
<table style="width: 745px;">
<tbody>
<tr>
<th style="width: 166px;">Argument Name</th>
<th style="width: 166px;">Description</th>
<th style="width: 166px;">Required</th>
</tr>
<tr>
<td style="width: 166px;">name</td>
<td style="width: 511px;">Name of the service group to delete.</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 166px;">device-group</td>
<td style="width: 511px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 63px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 id="context-output">Context Output</h5>
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 198px;"><strong>Path</strong></th>
<th style="width: 123px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198px;">Panarama.ServiceGroups.Name</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">Name of the service group that was deleted.</td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.DeviceGroup</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;"><span>Device group for the service group that was deleted (Panorama instances).</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-delete-service-group name=lalush_sg4</pre>
<h5>Human Readable Output</h5>
<p>placeholder</p>
</div>
<p> </p>
<h3 id="h_4582fce3-9660-481e-b899-e8eaebffaca1">38. Edit a service group</h3>
<hr>
<p>Modifies details of a service group.</p>
<h5>Base Command</h5>
<p><code>panorama-edit-service-group</code></p>
<h5>Input</h5>
<table style="width: 745px;">
<tbody>
<tr>
<th style="width: 166px;">Argument Name</th>
<th style="width: 166px;">Description</th>
<th style="width: 166px;">Required</th>
</tr>
<tr>
<td style="width: 166px;">name</td>
<td style="width: 511px;">Service group name</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 166px;">services_to_remove</td>
<td style="width: 511px;">Services to remove from the service group. Only existing Services<br> objects can be removed.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 166px;">services_to_add</td>
<td style="width: 511px;">Services to add to the service group. Only existing Services objects<br> can be added.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 166px;">tags</td>
<td style="width: 511px;">Services group tag to edit.</td>
<td style="width: 63px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 id="context-output">Context Output</h5>
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 198px;"><strong>Path</strong></th>
<th style="width: 123px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198px;">Panarama.ServiceGroups.Name</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">Service group name.</td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.Services</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">Service group related services.</td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.DeviceGroup</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;"><span>Service device group.</span></td>
</tr>
<tr>
<td style="width: 198px;"><span>Panorama.ServiceGroups.Tags</span></td>
<td style="width: 123px;">string</td>
<td style="width: 419px;"><span>Service group tags.</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>    panorama-edit-service-group name=lalush_sg4 services_to_remove=`["serice_udp_test_pb","demisto_service1"]
  </pre>
</div>
<h5>Human Readable Output<img src="https://user-images.githubusercontent.com/37335599/51698334-91da1700-2012-11e9-9dae-c036418ad6a9.png" alt="screen shot 2019-01-24 at 19 58 56"> </h5>
<p> </p>
<h3 id="get-information-for-pcap-files">39. Get information for a PCAP file</h3>
<hr>
<p>Returns information for a Panorama PCAP file. The recommended maximum file size is 5 MB. If the limit is exceeded, you might need to SSH the firewall and run the <code>scp export</code> command to export the PCAP file. For more information, see the <a href="https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000CleECAS" target="_blank" rel="noopener">Palo Alto Networks documentation</a>.</p>
<h5 id="base-command">Base Command</h5>
<p><code>panorama-get-pcap</code></p>
<h5 id="input">Input</h5>
<div class="table-wrapper"></div>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 532px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">pcapType</td>
<td style="width: 532px;">The type of packet capture.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 137px;">from</td>
<td style="width: 532px;">The file name for the PCAP type ("dlp-pcap", "filters-pcap", "application-pcap".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">localName</td>
<td style="width: 532px;">The new name for the PCAP file after downloading. If this argument is not specified, the file name will be the PCAP file name that was set in the firewall.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">serialNo</td>
<td style="width: 532px;">The serial number for the request. For more information, see the Panorama XML API Documentation.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">searchTime</td>
<td style="width: 532px;">The search time for the request. For more information, see the Panorama XML API Documentation.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">pcapID</td>
<td style="width: 532px;">The ID of the PCAP for the request. For more information, see the Panorama XML API Documentation.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">password</td>
<td style="width: 532px;">The password for Panorama. This is only required for the "dlp-pcap" PCAP type.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">deviceName</td>
<td style="width: 532px;">The Device Name on which the PCAP is stored. For further information, see the Panorama XML API Documentation.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">sessionID</td>
<td style="width: 532px;">The Session ID of the PCAP. For further information, see the Panorama XML API Documentation.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 id="context-output">Context Output</h5>
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 198px;"><strong>Path</strong></th>
<th style="width: 123px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198px;">File.Size</td>
<td style="width: 123px;">number</td>
<td style="width: 419px;">The file size.</td>
</tr>
<tr>
<td style="width: 198px;">File.Name</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">The file name.</td>
</tr>
<tr>
<td style="width: 198px;">File.Type</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">The file type.</td>
</tr>
<tr>
<td style="width: 198px;">File.Info</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">The file info.</td>
</tr>
<tr>
<td style="width: 198px;">File.Extenstion</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">The file extension.</td>
</tr>
<tr>
<td style="width: 198px;">File.EntryID</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">The file entryID.</td>
</tr>
<tr>
<td style="width: 198px;">File.MD5</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 198px;">File.SHA1</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">The SHA-1 hash of the file.</td>
</tr>
<tr>
<td style="width: 198px;">File.SHA256</td>
<td style="width: 123px;">string</td>
<td style="width: 419px;">The SHA-256 hash of the file.</td>
</tr>
</tbody>
</table>
</div>
<p> </p>
<h5 id="command-example">Command Example</h5>
<pre>!panorama-get-pcaps pcapType="filter-pcap" from=pcap_test</pre>
<h5 id="human-readable-output">Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37335599/54295643-1fba9300-45bc-11e9-9d22-7155da91e0c2.png" alt="pcap_is_working" width="1130"> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-all-pcap-files">40. Get a list of all PCAP files</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of all Panorama PCAP files, by PCAP type.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>panorama-list-pcaps</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 523px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">pcapType</td>
<td style="width: 523px;">The type of packet capture.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">from</td>
<td style="width: 523px;">The file name for the PCAP type (“dlp-pcap”, “filters-pcap”, “application-pcap”). For “application-pcap”, also use .</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">password</td>
<td style="width: 523px;">The password for Panorama. This is only required for the “dlp-pcap” PCAP type.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 363px;"><strong>Path</strong></th>
<th style="width: 106px;"><strong>Type</strong></th>
<th style="width: 271px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 363px;">Panorama.Pcaps.Name</td>
<td style="width: 106px;">string</td>
<td style="width: 271px;">The PCAP name.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!panorama-list-pcaps pcapType=“filter-pcap”</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/54688552-82fd7580-4b26-11e9-8299-b4c2d729526c.png" alt="Screen Shot 2019-03-20 at 14 58 23"></p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-edls">41. Get a list of EDLs</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of external dynamic lists.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>panorama-list-edls</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<table style="width: 749px;">
<tbody>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 523px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
<tr>
<td style="width: 146px;">device-group</td>
<td style="width: 523px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 333px;"><strong>Path</strong></th>
<th style="width: 20px;"><strong>Type</strong></th>
<th style="width: 387px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 333px;">Panorama.EDL.Name</td>
<td style="width: 20px;">string</td>
<td style="width: 387px;">Name of the EDL.</td>
</tr>
<tr>
<td style="width: 333px;">Panorama.EDL.Type</td>
<td style="width: 20px;">string</td>
<td style="width: 387px;">The type of EDL.</td>
</tr>
<tr>
<td style="width: 333px;">Panorama.EDL.URL</td>
<td style="width: 20px;">string</td>
<td style="width: 387px;">URL in which the EDL is stored.</td>
</tr>
<tr>
<td style="width: 333px;">Panorama.EDL.Description</td>
<td style="width: 20px;">string</td>
<td style="width: 387px;">Description of the EDL.</td>
</tr>
<tr>
<td style="width: 333px;">Panorama.EDL.CertificateProfile</td>
<td style="width: 20px;">string</td>
<td style="width: 387px;">EDL certificate profile.</td>
</tr>
<tr>
<td style="width: 333px;">Panorama.EDL.Recurring</td>
<td style="width: 20px;">string</td>
<td style="width: 387px;">Time interval that the EDL was pulled and updated.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!panorama-list-edls</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/55964787-ff92f800-5c7d-11e9-89b4-a4002f959bbf.png" alt="Screen Shot 2019-04-11 at 17 18 50"></p>
</div>
<div class="cl-preview-section">
<h3 id="get-information-for-an-edl">42. Get information for an EDL</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns information for an external dynamic list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>panorama-get-edl</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 198px;"><strong>Argument Name</strong></th>
<th style="width: 409px;"><strong>Description</strong></th>
<th style="width: 133px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198px;">name</td>
<td style="width: 409px;">Name of the EDL.</td>
<td style="width: 133px;">Required</td>
</tr>
<tr>
<td style="width: 198px;">device-group</td>
<td style="width: 409px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 133px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 292px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 376px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 292px;">Panorama.EDL.Name</td>
<td style="width: 72px;">string</td>
<td style="width: 376px;">Name of the EDL.</td>
</tr>
<tr>
<td style="width: 292px;">Panorama.EDL.Type</td>
<td style="width: 72px;">string</td>
<td style="width: 376px;">The type of EDL.</td>
</tr>
<tr>
<td style="width: 292px;">Panorama.EDL.URL</td>
<td style="width: 72px;">string</td>
<td style="width: 376px;">URL in which the EDL is stored.</td>
</tr>
<tr>
<td style="width: 292px;">Panorama.EDL.Description</td>
<td style="width: 72px;">string</td>
<td style="width: 376px;">Description of the EDL.</td>
</tr>
<tr>
<td style="width: 292px;">Panorama.EDL.CertificateProfile</td>
<td style="width: 72px;">string</td>
<td style="width: 376px;">EDL certificate profile.</td>
</tr>
<tr>
<td style="width: 292px;">Panorama.EDL.Recurring</td>
<td style="width: 72px;">string</td>
<td style="width: 376px;">Time interval that the EDL was pulled and updated.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!panorama-get-edl name=test_pb_domain_edl_DONT_DEL</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/55965094-8cd64c80-5c7e-11e9-8ac8-4a9f5175e03a.png" alt="Screen Shot 2019-04-11 at 17 23 05"></p>
</div>
<div class="cl-preview-section">
<h3 id="create-an-edl">43. Create an EDL</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Creates an external dynamic list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>panorama-create-edl</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 169px;"><strong>Argument Name</strong></th>
<th style="width: 500px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 169px;">name</td>
<td style="width: 500px;">Name of the EDL.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 169px;">url</td>
<td style="width: 500px;">URL from which to pull the EDL.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 169px;">type</td>
<td style="width: 500px;">The type of EDL.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 169px;">recurring</td>
<td style="width: 500px;">Time interval for pulling and updating the EDL.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 169px;">certificate_profile</td>
<td style="width: 500px;">Certificate Profile name for the URL that was previously uploaded to PAN OS.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 169px;">description</td>
<td style="width: 500px;">Description of the EDL.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 169px;">device-group</td>
<td style="width: 500px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 333px;"><strong>Path</strong></th>
<th style="width: 37px;"><strong>Type</strong></th>
<th style="width: 370px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 333px;">Panorama.EDL.Name</td>
<td style="width: 37px;">string</td>
<td style="width: 370px;">Name of the EDL.</td>
</tr>
<tr>
<td style="width: 333px;">Panorama.EDL.Type</td>
<td style="width: 37px;">string</td>
<td style="width: 370px;">The type of EDL.</td>
</tr>
<tr>
<td style="width: 333px;">Panorama.EDL.URL</td>
<td style="width: 37px;">string</td>
<td style="width: 370px;">URL in which the EDL is stored.</td>
</tr>
<tr>
<td style="width: 333px;">Panorama.EDL.Description</td>
<td style="width: 37px;">string</td>
<td style="width: 370px;">Description of the EDL.</td>
</tr>
<tr>
<td style="width: 333px;">Panorama.EDL.CertificateProfile</td>
<td style="width: 37px;">string</td>
<td style="width: 370px;">EDL certificate profile.</td>
</tr>
<tr>
<td style="width: 333px;">Panorama.EDL.Recurring</td>
<td style="width: 37px;">string</td>
<td style="width: 370px;">Time interval that the EDL was pulled and updated.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="edit-an-edl">44. Edit an EDL</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Modifies an element of an external dynamic list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>panorama-edit-edl</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 148px;"><strong>Argument Name</strong></th>
<th style="width: 521px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">name</td>
<td style="width: 521px;">Name of the external dynamic list to edit</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 148px;">element_to_change</td>
<td style="width: 521px;">The element to change (“url”, “recurring”, “certificate_profile”, “description”).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 148px;">element_value</td>
<td style="width: 521px;">The element value.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 746px;">
<thead>
<tr>
<th style="width: 339px;"><strong>Path</strong></th>
<th style="width: 19px;"><strong>Type</strong></th>
<th style="width: 382px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 339px;">Panorama.EDL.Name</td>
<td style="width: 19px;">string</td>
<td style="width: 382px;">Name of the EDL.</td>
</tr>
<tr>
<td style="width: 339px;">Panorama.EDL.URL</td>
<td style="width: 19px;">string</td>
<td style="width: 382px;">URL in which the EDL is stored</td>
</tr>
<tr>
<td style="width: 339px;">Panorama.EDL.Description</td>
<td style="width: 19px;">string</td>
<td style="width: 382px;">Description of the EDL.</td>
</tr>
<tr>
<td style="width: 339px;">Panorama.EDL.CertificateProfile</td>
<td style="width: 19px;">string</td>
<td style="width: 382px;">EDL certificate profile.</td>
</tr>
<tr>
<td style="width: 339px;">Panorama.EDL.Recurring</td>
<td style="width: 19px;">string</td>
<td style="width: 382px;">Time interval that the EDL was pulled and updated.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!panorama-edit-edl name=test_pb_domain_edl_DONT_DEL element_to_change=description element_value="new description3"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/55964986-5d274480-5c7e-11e9-97c8-ed353acd7ece.png" alt="Screen Shot 2019-04-11 at 17 21 56"></p>
</div>
<div class="cl-preview-section">
<h3 id="delete-an-edl">45. Delete an EDL</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes an external dynamic list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>panorama-delete-edl</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 239px;"><strong>Argument Name</strong></th>
<th style="width: 365px;"><strong>Description</strong></th>
<th style="width: 136px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 239px;">name</td>
<td style="width: 365px;">Name of the EDL to delete.</td>
<td style="width: 136px;">Required</td>
</tr>
<tr>
<td style="width: 239px;">device-group</td>
<td style="width: 365px;">
<span>The device group for which to return addresses (Panorama instances). </span>If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 136px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 250px;"><strong>Path</strong></th>
<th style="width: 73px;"><strong>Type</strong></th>
<th style="width: 417px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 250px;">Panorama.EDL.Name</td>
<td style="width: 73px;">string</td>
<td style="width: 417px;">Name of the EDL that was deleted.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!panorama-delete-edl name=shani_uel33</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/55965020-6fa17e00-5c7e-11e9-9c41-b6cf859e8f07.png" alt="Screen Shot 2019-04-11 at 17 22 38"></p>
</div>
<div class="cl-preview-section">
<h3 id="refresh-an-edl">46. Refresh an EDL</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Refreshes the specified external dynamic list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>panorama-refresh-edl</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 288px;"><strong>Argument Name</strong></th>
<th style="width: 289px;"><strong>Description</strong></th>
<th style="width: 163px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 288px;">name</td>
<td style="width: 289px;">Name of the EDL.</td>
<td style="width: 163px;">Required</td>
</tr>
<tr>
<td style="width: 288px;">device-group</td>
<td style="width: 289px;">
<span>The device group for which to return addresses (Panorama instances).</span> If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 163px;">Optional</td>
</tr>
<tr>
<td style="width: 288px;">edl_type</td>
<td style="width: 289px;">The type of the EDL. Required when refreshing an EDL object which is configured on Panorama.</td>
<td style="width: 163px;">Optional</td>
</tr>
<tr>
<td style="width: 288px;">location</td>
<td style="width: 289px;">The location of the EDL. Required when refreshing an EDL object which is configured on Panorama.</td>
<td style="width: 163px;">Optional</td>
</tr>
<tr>
<td style="width: 288px;">vsys</td>
<td style="width: 289px;">The Vsys of the EDL. Required when refreshing an EDL object which is configured on Panorama.</td>
<td style="width: 163px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!panorama-refresh-edl name=domain_edl66</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/56093626-b5a34f80-5ed3-11e9-97f7-7361a65a408b.png" alt="Screen Shot 2019-04-14 at 16 37 57"></p>
</div>
<div class="cl-preview-section">
<h3 id="register-ip-addresses-to-a-tag">47. Register IP addresses to a tag</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Registers IP addresses to a tag.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>panorama-register-ip-tag</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 125px;"><strong>Argument Name</strong></th>
<th style="width: 544px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 125px;">tag</td>
<td style="width: 544px;">Tag to which to register IP addresses.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 125px;">IPs</td>
<td style="width: 544px;">IP addresses to register.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 125px;">persistent</td>
<td style="width: 544px;">Whether the IP addresses remain registered to the tag after device reboots (“True”:persistent, “False":non-persistent). Default is “True”.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-6">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 349px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 311px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 349px;">Panorama.DynamicTags.Tag</td>
<td style="width: 80px;">string</td>
<td style="width: 311px;">Name for the tag.</td>
</tr>
<tr>
<td style="width: 349px;">Panorama.DynamicTags.IPs</td>
<td style="width: 80px;">string</td>
<td style="width: 311px;">Registered IP addresses.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!panorama-register-ip-tag tag=tag02 IPs=[“10.0.0.13”,“10.0.0.14”]</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/56190390-c9b19300-6032-11e9-80f6-0b006ce1c08f.png" alt="Screen Shot 2019-04-16 at 9 57 58"></p>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/56190428-d8984580-6032-11e9-844e-7f777214c626.png" alt="Screen Shot 2019-04-16 at 9 58 32"></p>
</div>
<div class="cl-preview-section">
<h3 id="unregister-ip-addresses-from-a-tag">48. Unregister IP addresses from a tag</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Unregisters IP addresses from a tag.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>panorama-unregister-ip-tag</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 179px;"><strong>Argument Name</strong></th>
<th style="width: 456px;"><strong>Description</strong></th>
<th style="width: 105px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 179px;">tag</td>
<td style="width: 456px;">Tag from which to unregister IP addresses.</td>
<td style="width: 105px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">IPs</td>
<td style="width: 456px;">IP addresses to unregister.</td>
<td style="width: 105px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-6">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!panorama-unregister-ip-tag tag=tag02 IPs=`["10.0.0.13","10.0.0.14"]</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/56190374-c0c0c180-6032-11e9-9983-ec317b8614f9.png" alt="Screen Shot 2019-04-16 at 9 58 18"></p>
<h3 id="h_2b8614b9-d61c-4211-9eaa-1dc82c08e8b1">49. Query traffic logs</h3>
<hr>
<p>Queries traffic logs.</p>
<h5>Base Command</h5>
<p><code>panorama-query-traffic-logs</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 157px;"><strong>Argument Name</strong></th>
<th style="width: 512px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 157px;">query</td>
<td style="width: 512px;">Specifies the match criteria for the logs. This is similar to the query provided in the web interface under the Monitor tab when viewing the logs.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">number_of_logs</td>
<td style="width: 512px;">The number of logs to retrieve. Default is 100. Maximum is 5,000.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">direction</td>
<td style="width: 512px;">Whether logs are shown oldest first (forward) or newest first (backward). Default is backward.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">source</td>
<td style="width: 512px;">Source address for the query.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">destination</td>
<td style="width: 512px;">Destination address for the query.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">receive_time</td>
<td style="width: 512px;">Date and time after which logs were received, in the format: YYYY/MM/DD HH:MM:SS.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">application</td>
<td style="width: 512px;">Application for the query.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">to_port</td>
<td style="width: 512px;">Destination port for the query.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">action</td>
<td style="width: 512px;">Action for the query.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 310px;"><strong>Path</strong></th>
<th style="width: 92px;"><strong>Type</strong></th>
<th style="width: 338px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 310px;">Panorama.TrafficLogs.JobID</td>
<td style="width: 92px;">Number</td>
<td style="width: 338px;">Job ID of the traffic logs query.</td>
</tr>
<tr>
<td style="width: 310px;">Panorama.TrafficLogs.Status</td>
<td style="width: 92px;">String</td>
<td style="width: 338px;">Status of the traffic logs query.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-query-traffic-logs query="" number_of_logs="100" direction="backward" source="" destination="" receive_time="" application="" to_port="" action="allow"</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/60493680-0ac25680-9cb6-11e9-9c77-1079f25286a0.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/60493680-0ac25680-9cb6-11e9-9c77-1079f25286a0.png" alt="Screen Shot 2019-07-02 at 10 41 45"></a></p>
<h3 id="h_001774c2-0ef7-47f2-9cb2-4c5fd54e671a">50. Check the query status of traffic logs</h3>
<hr>
<p>Checks the query status of traffic logs.</p>
<h5>Base Command</h5>
<p><code>panorama-check-traffic-logs-status</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 288px;"><strong>Argument Name</strong></th>
<th style="width: 296px;"><strong>Description</strong></th>
<th style="width: 156px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 288px;">job_id</td>
<td style="width: 296px;">Job ID of the query.</td>
<td style="width: 156px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 316px;"><strong>Path</strong></th>
<th style="width: 84px;"><strong>Type</strong></th>
<th style="width: 340px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 316px;">Panorama.TrafficLogs.JobID</td>
<td style="width: 84px;">Number</td>
<td style="width: 340px;">Job ID of the traffic logs query.</td>
</tr>
<tr>
<td style="width: 316px;">Panorama.TrafficLogs.Status</td>
<td style="width: 84px;">String</td>
<td style="width: 340px;">Status of the traffic logs query.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-check-traffic-logs-status job_id="1865"</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/60493796-48bf7a80-9cb6-11e9-84b6-0f49f8d2becd.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/60493796-48bf7a80-9cb6-11e9-84b6-0f49f8d2becd.png" alt="Screen Shot 2019-07-02 at 10 43 32"></a></p>
<h3 id="h_147e1590-cfe0-4bc5-8b47-9b6f68bac585">51. Get traffic logs</h3>
<hr>
<p>Retrieves traffic log query data by job id</p>
<h5>Base Command</h5>
<p><code>panorama-get-traffic-logs</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 282px;"><strong>Argument Name</strong></th>
<th style="width: 302px;"><strong>Description</strong></th>
<th style="width: 156px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 282px;">job_id</td>
<td style="width: 302px;">Job ID of the query.</td>
<td style="width: 156px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table>
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Panorama.TrafficLogs.JobID</td>
<td>Number</td>
<td>Job ID of the traffic logs query.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Status</td>
<td>String</td>
<td>Status of the traffic logs query.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.Action</td>
<td>String</td>
<td>Action of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.ActionSource</td>
<td>String</td>
<td>Action source of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.Application</td>
<td>String</td>
<td>Application of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.Category</td>
<td>String</td>
<td>Category of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.DeviceName</td>
<td>String</td>
<td>Device name of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.Destination</td>
<td>String</td>
<td>Destination of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.DestinationPort</td>
<td>String</td>
<td>Destination port of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.FromZone</td>
<td>String</td>
<td>From zone of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.Protocol</td>
<td>String</td>
<td>Protocol of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.ReceiveTime</td>
<td>String</td>
<td>Receive time of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.Rule</td>
<td>String</td>
<td>Rule of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.SessionEndReason</td>
<td>String</td>
<td>Session end reason of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.Source</td>
<td>String</td>
<td>Source of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.SourcePort</td>
<td>String</td>
<td>Source port of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.StartTime</td>
<td>String</td>
<td>Start time of the traffic log.</td>
</tr>
<tr>
<td>Panorama.TrafficLogs.Logs.ToZone</td>
<td>String</td>
<td>To zone of the traffic log.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-get-traffic-logs job_id="1865"</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/60494086-c8e5e000-9cb6-11e9-9ee1-91c897c8798e.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/60494086-c8e5e000-9cb6-11e9-9ee1-91c897c8798e.png" alt="Screen Shot 2019-07-02 at 10 44 12 copy"></a></p>
<h3 id="h_8230c267-2e89-43f5-b2e8-d6ac6fab2334">52. Get a list of predefined security rules</h3>
<hr>
<p>Returns a list of predefined security rules.</p>
<h5>Base Command</h5>
<p><code>panorama-list-rules</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 531px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">pre_post</td>
<td style="width: 531px;">Rules location. Can be "pre-rulebase" or "post-rulebase". Mandatory for Panorama instances.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">device-group</td>
<td style="width: 531px;">
<span>The device group for which to return addresses (Panorama instances). </span>If no value is supplied, the default group configured integration parameter is applied.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">tag</td>
<td style="width: 531px;">The tag for which to filter the rules.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table>
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Panorama.SecurityRule.Name</td>
<td>String</td>
<td>Rule name.</td>
</tr>
<tr>
<td>Panorama.SecurityRule.Action</td>
<td>String</td>
<td>Action for the rule.</td>
</tr>
<tr>
<td>Panorama.SecurityRule.Location</td>
<td>String</td>
<td>Rule location.</td>
</tr>
<tr>
<td>Panorama.SecurityRule.Category</td>
<td>String</td>
<td>Rule category.</td>
</tr>
<tr>
<td>Panorama.SecurityRule.Application</td>
<td>String</td>
<td>Application for the rule.</td>
</tr>
<tr>
<td>Panorama.SecurityRule.Destination</td>
<td>String</td>
<td>Destination address.</td>
</tr>
<tr>
<td>Panorama.SecurityRule.From</td>
<td>String</td>
<td>Rule from.</td>
</tr>
<tr>
<td>Panorama.SecurityRule.Service</td>
<td>String</td>
<td>Service for the rule.</td>
</tr>
<tr>
<td>Panorama.SecurityRule.To</td>
<td>String</td>
<td>Rule to.</td>
</tr>
<tr>
<td>Panorama.SecurityRule.Source</td>
<td>String</td>
<td>Source address.</td>
</tr>
<tr>
<td><span>Panorama.SecurityRule.DeviceGroup</span></td>
<td>String</td>
<td><span>Device group for the rule (Panorama instances).</span></td>
</tr>
<tr>
<td><span>Panorama.SecurityRules.Tags</span></td>
<td>String</td>
<td><span>Rule tags.</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!panorama-list-rules</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/62034335-84d2f600-b1f6-11e9-99a1-4eba2436790a.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/62034335-84d2f600-b1f6-11e9-99a1-4eba2436790a.png" alt="Screen Shot 2019-07-29 at 11 46 09"></a><br> <a href="https://user-images.githubusercontent.com/37335599/62034336-84d2f600-b1f6-11e9-9402-15a1dc4675f0.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/62034336-84d2f600-b1f6-11e9-9402-15a1dc4675f0.png" alt="Screen Shot 2019-07-29 at 11 46 22"></a></p>
<p> </p>
<h3 id="53-panorama-query-logs">53. Query logs</h3>
<hr>
<p>Query logs in Panorama. </p>
<h5 id="base-command">Base Command</h5>
<p><code>panorama-query-logs</code></p>
<h5 id="input">Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 133.333px;"><strong>Argument Name</strong></th>
<th style="width: 535.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133.333px;">log-type</td>
<td style="width: 535.667px;">The log type. Can be "threat", "traffic", "wildfire", "url", or "data".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133.333px;">query</td>
<td style="width: 535.667px;">The query string by which to match criteria for the logs. This is similar to the query provided in the web interface under the Monitor tab when viewing the logs.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.333px;">time-generated</td>
<td style="width: 535.667px;">The time that the log was generated from the timestamp and prior to it. For example: "2019/08/11 01:10:44".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.333px;">addr-src</td>
<td style="width: 535.667px;">Source address.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.333px;">ip</td>
<td style="width: 535.667px;">The source or destination IP address.</td>
<td style="width: 71px;"> </td>
</tr>
<tr>
<td style="width: 133.333px;">addr-dst</td>
<td style="width: 535.667px;">Destination address.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.333px;">zone-src</td>
<td style="width: 535.667px;">Source zone.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.333px;">zone-dst</td>
<td style="width: 535.667px;">Destination Source.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.333px;">action</td>
<td style="width: 535.667px;">Rule action.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.333px;">port-dst</td>
<td style="width: 535.667px;">Destination port.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.333px;">rule</td>
<td style="width: 535.667px;">Rule name, for example: "Allow all outbound".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.333px;">url</td>
<td style="width: 535.667px;">URL, for example: "safebrowsing.googleapis.com".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.333px;">filedigest</td>
<td style="width: 535.667px;">File hash (for WildFIre logs only).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.333px;">number_of_logs</td>
<td style="width: 535.667px;">Maximum number of logs to retrieve. If empty, the default is 100. The maximum is 5,000.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 id="context-output">Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 325px;"><strong>Path</strong></th>
<th style="width: 86px;"><strong>Type</strong></th>
<th style="width: 330px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 325px;">Panorama.Monitor.JobID</td>
<td style="width: 86px;">String</td>
<td style="width: 330px;">Job ID of the logs query.</td>
</tr>
<tr>
<td style="width: 325px;">Panorama.Monitor.Status</td>
<td style="width: 86px;">String</td>
<td style="width: 330px;">Status of the logs query.</td>
</tr>
<tr>
<td style="width: 325px;">Panorama.Monitor.Message</td>
<td style="width: 86px;">String</td>
<td style="width: 330px;">Message of the logs query.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 id="command-example">Command Example</h5>
<pre>!panorama-query-logs log-type=data query=( addr.src in 192.168.1.12 )</pre>
<h5 id="human-readable-output">Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37335599/63257028-918cbc00-c281-11e9-8f9c-9d6076fd52c3.png" alt="Screen Shot 2019-08-19 at 12 59 42"></p>
<h5 id="command-example">Command Example</h5>
<pre>!panorama-query-logs log-type=wildfire filedigest=4f79697b40d0932e91105bd496908f8e02c130a0e36f6d3434d6243e79ef82e0</pre>
<h5 id="human-readable-output">Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37335599/63257035-95b8d980-c281-11e9-8e7c-a808570bf7a0.png" alt="Screen Shot 2019-08-19 at 13 01 38"></p>
<h3 id="54-panorama-check-logs-status">54. Check log query status</h3>
<hr>
<p>Checks the status of a logs query. </p>
<h5 id="base-command">Base Command</h5>
<p><code>panorama-check-logs-status</code></p>
<h5 id="input">Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 271px;"><strong>Argument Name</strong></th>
<th style="width: 313px;"><strong>Description</strong></th>
<th style="width: 156px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 271px;">job_id</td>
<td style="width: 313px;">Job ID of the query.</td>
<td style="width: 156px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 id="context-output">Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 322.667px;"><strong>Path</strong></th>
<th style="width: 91.3333px;"><strong>Type</strong></th>
<th style="width: 327px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 322.667px;">Panorama.Monitor.JobID</td>
<td style="width: 91.3333px;">String</td>
<td style="width: 327px;">Job ID of the logs query.</td>
</tr>
<tr>
<td style="width: 322.667px;">Panorama.Monitor.Status</td>
<td style="width: 91.3333px;">String</td>
<td style="width: 327px;">Status of the logs query.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 id="command-example">Command Example</h5>
<pre>!panorama-check-logs-status job_id=657</pre>
<h5 id="human-readable-output">Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37335599/63257080-b2551180-c281-11e9-97e0-17594e5ba2ee.png" alt="Screen Shot 2019-08-19 at 13 02 54"></p>
<h3 id="55-panorama-get-logs">55. Get log query data</h3>
<hr>
<p>Retrieves the data of a logs query. </p>
<h5 id="base-command">Base Command</h5>
<p><code>panorama-get-logs</code></p>
<h5 id="input">Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 147.333px;"><strong>Argument Name</strong></th>
<th style="width: 521.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147.333px;">job_id</td>
<td style="width: 521.667px;">Job ID of the query.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 147.333px;">ignore_auto_extract</td>
<td style="width: 521.667px;">Whether to auto-enrich the War Room entry. If "true", entry is not auto-enriched. If "false", entry is auto-extracted. Default is "true".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 260px;"><strong>Path</strong></th>
<th style="width: 55px;"><strong>Type</strong></th>
<th style="width: 426px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 260px;">Panorama.Monitor.Action</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">Action taken for the session. Can be "alert", "allow", "deny", "drop", "drop-all-packets", "reset-client", "reset-server", "reset-both", of "block-url".</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.Application</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">Application associated with the session.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.Bytes</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">Total log bytes.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.BytesReceived</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">Log bytes received.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.BytesSent</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">Log bytes sent.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.Category</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">The URL category of the URL subtype. For WildFire subtype, it is the verdict on the file, and can be either "malicious", "phishing", "grayware"’, or "benign". For other subtypes, the value is "any".</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.DeviceName</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">The hostname of the firewall on which the session was logged.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.DestinationAddress</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">Original session destination IP address.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.DestinationUser</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">Username of the user to which the session was destined.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.DestinationCountry</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">Destination country or internal region for private addresses. Maximum length is 32 bytes.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.DestinationPort</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">Destination port utilized by the session.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.FileDigest</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">Only for the WildFire subtype, all other types do not use this field. The filedigest string shows the binary hash of the file sent to be analyzed by the WildFire service.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.FileName</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">File name or file type when the subtype is file.File name when the subtype is virus. File name when the subtype is wildfire-virus. File name when the subtype is wildfire.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.FileType</td>
<td style="width: 55px;">String</td>
<td style="width: 426px;">Only for the WildFire subtype, all other types do not use this field. Specifies the type of file that the firewall forwarded for WildFire analysis.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.FromZone<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">The zone from which the session was sourced.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.URLOrFilename</td>
<td style="width: 55px;"><span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;">String </span></td>
<td style="width: 426px;">The actual URI when the subtype is url. File name or file type when the subtype is file. File name when the subtype is virus. File name when the subtype is wildfire-virus. File name when the subtype is wildfire. URL or file name when the subtype is vulnerability (if applicable)</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.NATDestinationIP<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">If destination NAT performed, the post-NAT destination IP address.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.NATDestinationPort</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">Post-NAT destination port.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.NATSourceIP<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">If source NAT performed, the post-NAT source IP address.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.NATSourcePort</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">Post-NAT source port.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.PCAPid<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">The packet capture (pcap) ID is a 64 bit unsigned integral denoting an ID to correlate threat pcap files with extended pcaps taken as a part of that flow. All threat logs will contain either a pcap_id of 0 (no associated pcap), or an ID referencing the extended pcap file.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.IPProtocol</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">IP protocol associated with the session.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.Recipient<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">Only for the WildFire subtype, all other types do not use this field. Specifies the name of the receiver of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.Rule</td>
<td style="width: 55px;">String<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">Name of the rule that the session matched.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.RuleID<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">ID of the rule that the session matched.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.ReceiveTime</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">Time the log was received at the management plane.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.Sender<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">Only for the WildFire subtype; all other types do not use this field. Specifies the name of the sender of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.SessionID</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">An internal numerical identifier applied to each session.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.DeviceSN<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">The serial number of the firewall on which the session was logged.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.Severity</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">Severity associated with the threat. Can be "informational", "low", "medium", "high", or "critical".</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.SourceAddress<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">Original session source IP address.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.SourceCountry</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">Source country or internal region for private addresses. Maximum length is 32 bytes.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.SourceUser<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">Username of the user who initiated the session.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.SourcePort</td>
<td style="width: 55px;">String<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">Source port utilized by the session.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.ThreatCategory <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">Describes threat categories used to classify different types of threat signatures.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.Name</td>
<td style="width: 55px;">String<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">Palo Alto Networks identifier for the threat. It is a description string followed by a 64-bit numerical identifier</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.ID<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">Palo Alto Networks ID for the threat.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.ToZone</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">The zone to which the session was destined.</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.TimeGenerated<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
<td style="width: 426px;">Time that the log was generated on the dataplane.<span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span>
</td>
</tr>
<tr>
<td style="width: 260px;">Panorama.Monitor.URLCategoryList</td>
<td style="width: 55px;">String <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px;"></span> </td>
<td style="width: 426px;">A list of the URL filtering categories that the firewall used to enforce the policy.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 id="command-example">Command Example</h5>
<pre>!panorama-get-logs job_id=678</pre>
<h5 id="human-readable-output">Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37335599/63256853-2e028e80-c281-11e9-9178-d7ab801dc2da.png" alt="Screen Shot 2019-08-19 at 12 59 16"></p>
<h5 id="command-example">Command Example</h5>
<pre>!panorama-get-logs job_id=676</pre>
<h5 id="human-readable-output">Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37335599/63256926-57bbb580-c281-11e9-87e9-57932a4189b7.png" alt="Screen Shot 2019-08-19 at 13 00 25"></p>
<h2>Playbook Videos</h2>
<p>These video show how to set up and use the PAN-OS DAG Configuration playbook and PAN-OS EDL Setup playbook.</p>
<h3>PAN-OS DAG Configuration</h3>
<p> </p>
<h3>PAN-OS EDL Setup</h3>
</div>
</div>
<h3 id="panorama-get-licences">77. panorama-get-licences</h3>
<hr>
<p>Get information about PAN-OS available licenses and their statuses.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-get-licences</code>
</p>

<h5>Input</h5>
There are no inputs for this command.

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
      <td>Panorama.License.Authcode</td>
      <td>String</td>
      <td>License authentication code.</td>
    </tr>
    <tr>
      <td>Panorama.License.Base-license-name</td>
      <td>String</td>
      <td>Base License name.</td>
    </tr>
    <tr>
      <td>Panorama.License.Description</td>
      <td>String</td>
      <td>The License description.</td>
    </tr>
    <tr>
      <td>Panorama.License.Expired</td>
      <td>String</td>
      <td>Is the license expired.</td>
    </tr>
    <tr>
      <td>Panorama.License.Expires</td>
      <td>String</td>
      <td>When the license will be expired.</td>
    </tr>
    <tr>
      <td>Panorama.License.Feature</td>
      <td>String</td>
      <td>The license feature.</td>
    </tr>
    <tr>
      <td>Panorama.License.Issued</td>
      <td>String</td>
      <td>When the license was issued.</td>
    </tr>
    <tr>
      <td>Panorama.License.Serial</td>
      <td>String</td>
      <td>The license serial.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <pre>!panorama-get-licences</pre>
</p>

<h5>Human Readable Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Authcode</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Feature</strong>
      </th>
      <th>
        <strong>Serial</strong>
      </th>
      <th>
        <strong>Expired</strong>
      </th>
      <th>
        <strong>Expires</strong>
      </th>
      <th>
        <strong>Issued</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>I9805928</td>
      <td>NFR Support</td>
      <td>NFR Support</td>
      <td>007DEMISTO1t</td>
      <td>no</td>
      <td>Never</td>
      <td>November 25, 2019</td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="panorama-get-security-profiles">78. panorama-get-security-profiles</h3>
<hr>
<p>Get information about profiles.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-get-security-profiles</code>
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
      <td>security_profile</td>
      <td>The security profile to get.</td>
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
      <td>Panorama.Spyware.Name</td>
      <td>String</td>
      <td>Profile Name.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.Rules.Action</td>
      <td>String</td>
      <td>The rule action</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.Rules.Cateogry</td>
      <td>String</td>
      <td>The category to apply the rule on.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.Rules.Name</td>
      <td>String</td>
      <td>Rule name.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.Rules.Packet-capture</td>
      <td>String</td>
      <td>Is packet capture enabled.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.Rules.Severity</td>
      <td>String</td>
      <td>Rule severity.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.Rules.Threat-name</td>
      <td>String</td>
      <td>Threat name to apply the rule.</td>
    </tr>
    <tr>
      <td>Panorama.URLFilter.Name</td>
      <td>String</td>
      <td>Profile name.</td>
    </tr>
    <tr>
      <td>Panorama.URLFilter.Rules.Category.Action</td>
      <td>String</td>
      <td>Rule action to apply on the category.</td>
    </tr>
    <tr>
      <td>Panorama.URLFilter.Rules.Category.Name</td>
      <td>String</td>
      <td>Category name.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.Name</td>
      <td>String</td>
      <td>WildFire profile name.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.Rules.Analysis</td>
      <td>String</td>
      <td>Rule analysis.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.Rules.Application</td>
      <td>String</td>
      <td>Application to apply the rule on.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.Rules.File-type</td>
      <td>String</td>
      <td>File type to apply the rule on.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.Rules.Name</td>
      <td>String</td>
      <td>Rule name.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Name</td>
      <td>String</td>
      <td>Vulnerability profile name.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rules.Vendor-id</td>
      <td>String</td>
      <td>Vendor ID to apply the rule on.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rules.Packet-capture</td>
      <td>String</td>
      <td>Is packet capture enabled.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rules.Host</td>
      <td>String</td>
      <td>Rule host.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rules.Name</td>
      <td>String</td>
      <td>Rule name.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rules.Cateogry</td>
      <td>String</td>
      <td>Category to apply the rule on.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rules.CVE</td>
      <td>String</td>
      <td>CVE to apply the rule on.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rules.Action</td>
      <td>String</td>
      <td>Rule action.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rules.Severity</td>
      <td>String</td>
      <td>Rule severity.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rules.Threat-name</td>
      <td>String</td>
      <td>Threat to apply the rule on.</td>
    </tr>
    <tr>
      <td>Panorama.Antivirus.Name</td>
      <td>String</td>
      <td>Antivirus profile name.</td>
    </tr>
    <tr>
      <td>Panorama.Antivirus.Rules.Action</td>
      <td>String</td>
      <td>Rule action.</td>
    </tr>
    <tr>
      <td>Panorama.Antivirus.Rules.Name</td>
      <td>String</td>
      <td>Rule name.</td>
    </tr>
    <tr>
      <td>Panorama.Antivirus.Rules.WildFire-action</td>
      <td>String</td>
      <td>WildFire action.</td>
    </tr>
    <tr>
      <td>Panorama.FileBlocking.Name</td>
      <td>String</td>
      <td>File blocking profile name.</td>
    </tr>
    <tr>
      <td>Panorama.FileBlocking.Rules.Action</td>
      <td>String</td>
      <td>Rule action.</td>
    </tr>
    <tr>
      <td>Panorama.FileBlocking.Rules.Application</td>
      <td>String</td>
      <td>Application to apply the rule.</td>
    </tr>
    <tr>
      <td>Panorama.FileBlocking.Rules.File-type</td>
      <td>String</td>
      <td>File type to apply the rule.</td>
    </tr>
    <tr>
      <td>Panorama.FileBlocking.Rules.Name</td>
      <td>String</td>
      <td>Rule name.</td>
    </tr>
    <tr>
      <td>Panorama.DataFiltering.Name</td>
      <td>String</td>
      <td>Data filtering profile name.</td>
    </tr>
    <tr>
      <td>Panorama.DataFiltering.Rules.Alert-threshold</td>
      <td>String</td>
      <td>Alert threshold.</td>
    </tr>
    <tr>
      <td>Panorama.DataFiltering.Rules.Application</td>
      <td>String</td>
      <td>Application to apply the rule.</td>
    </tr>
    <tr>
      <td>Panorama.DataFiltering.Rules.Block-threshold</td>
      <td>String</td>
      <td>Block threshold.</td>
    </tr>
    <tr>
      <td>Panorama.DataFiltering.Rules.Data-object</td>
      <td>String</td>
      <td>Data object.</td>
    </tr>
    <tr>
      <td>Panorama.DataFiltering.Rules.Direction</td>
      <td>String</td>
      <td>Rule direction.</td>
    </tr>
    <tr>
      <td>Panorama.DataFiltering.Rules.File-type</td>
      <td>String</td>
      <td>File type to apply the rule on.</td>
    </tr>
    <tr>
      <td>Panorama.DataFiltering.Rules.Log-severity</td>
      <td>String</td>
      <td>Log severity.</td>
    </tr>
    <tr>
      <td>Panorama.DataFiltering.Rules.Name</td>
      <td>String</td>
      <td>Rule name.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <pre>!panorama-get-security-profiles security_profile=spyware</pre>
</p>

<h5>Human Readable Output</h5>
<p>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Name</strong>
      </th>
      <th>
        <strong>Rules</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>best-practice</td>
      <td>
{'Name': 'simple-critical', 'Action': {'reset-both': None}, 'Category': 'any', 'Severity': 'critical', 'Threat-name': 'any', 'Packet-capture': 'disable'},<br><br>
{'Name': 'simple-high', 'Action': {'reset-both': None}, 'Category': 'any', 'Severity': 'high', 'Threat-name': 'any', 'Packet-capture': 'disable'},<br><br>
{'Name': 'simple-medium', 'Action': {'reset-both': None}, 'Category': 'any', 'Severity': 'medium', 'Threat-name': 'any', 'Packet-capture': 'disable'},<br><br>
{'Name': 'simple-informational', 'Action': {'default': None}, 'Category': 'any', 'Severity': 'informational', 'Threat-name': 'any', 'Packet-capture': 'disable'},<br><br>
{'Name': 'simple-low', 'Action': {'default': None}, 'Category': 'any', 'Severity': 'low', 'Threat-name': 'any', 'Packet-capture': 'disable'}</td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="panorama-apply-security-profile">79. panorama-apply-security-profile</h3>
<hr>
<p>Apply profile to specific rules / rules with specific tag.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-apply-security-profile</code>
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
      <td>profile_type</td>
      <td>Security profile type.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The rule name to apply.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>profile_name</td>
      <td>The profile name to apply to the rule.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>pre_post</td>
      <td>Rules location. Can be 'pre-rulebase' or 'post-rulebase'. Mandatory for Panorama instances.</td>
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
  <pre>!panorama-apply-security-profile profile_name=test profile_type=spyware rule_name=rule1 pre_post="pre-rulebase"</pre>
</p>

<h5>Human Readable Output</h5>
<p>

The profile test has been applied to the rule rule1
</p>

<h3 id="panorama-get-ssl-decryption-rules">80. panorama-get-ssl-decryption-rules</h3>
<hr>
<p>Show ssl decryption rules under policies -> decryption -> rules</p>
<h5>Base Command</h5>
<p>
  <code>panorama-get-ssl-decryption-rules</code>
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
      <td>pre_post</td>
      <td>Rules location. Can be 'pre-rulebase' or 'post-rulebase'. Mandatory for Panorama instances.</td>
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
      <td>Panorama.SSLRule.From</td>
      <td>String</td>
      <td>SSL rule from source.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.Name</td>
      <td>String</td>
      <td>Name of the SSL rule.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.Destination</td>
      <td>String</td>
      <td>Destination of the SSL rule.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.Target</td>
      <td>String</td>
      <td>The target od the SSL rule.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.Service</td>
      <td>String</td>
      <td>SSL rule service.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.Action</td>
      <td>String</td>
      <td>SSL rule action.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.Type</td>
      <td>String</td>
      <td>SSL rule type.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.Source</td>
      <td>String</td>
      <td>The source of the SSL rule.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.To</td>
      <td>String</td>
      <td>SSL rule to destination.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.UUID</td>
      <td>String</td>
      <td>SSl rule UUID.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.Description</td>
      <td>String</td>
      <td>SSL rule description.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.Source-user</td>
      <td>String</td>
      <td>SSL rule source user.</td>
    </tr>
    <tr>
      <td>Panorama.SSLRule.Category</td>
      <td>String</td>
      <td>SSL rule category.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <pre>!panorama-get-ssl-decryption-rules pre_post="pre-rulebase"</pre>
</p>

<h5>Human Readable Output</h5>
<p>
SSL Decryption Rules
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Name</strong>
      </th>
      <th>
        <strong>UUID</strong>
      </th>
      <th>
        <strong>Target</strong>
      </th>
      <th>
        <strong>Service</strong>
      </th>
      <th>
        <strong>Category</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>From</strong>
      </th>
      <th>
        <strong>To</strong>
      </th>
      <th>
        <strong>Source</strong>
      </th>
      <th>
        <strong>Destination</strong>
      </th>
      <th>
        <strong>Action</strong>
      </th>
      <th>
        <strong>Source-user</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>test</td>
      <td>cd3f0487-3872-4691-8387-1a15e7de142b</td>
      <td>negate: no</td>
      <td>any</td>
      <td>member: any</td>
      <td>ssl-forward-proxy: null</td>
      <td>any</td>
      <td>any</td>
      <td>any</td>
      <td>any</td>
      <td>no-decrypt</td>
      <td>any</td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="panorama-get-wildfire-configuration">81. panorama-get-wildfire-configuration</h3>
<hr>
<p>Retrieve Wildfire Configuration</p>
<h5>Base Command</h5>
<p>
  <code>panorama-get-wildfire-configuration</code>
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
      <td>template</td>
      <td>The template name.</td>
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
      <td>Panorama.WildFire.Name</td>
      <td>String</td>
      <td>File type.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.Size-limit</td>
      <td>String</td>
      <td>File size limit.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.recurring</td>
      <td>String</td>
      <td>Schedule recurring</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!panorama-get-wildfire-configuration template=WildFire</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Panorama.WildFire": [
        {
            "Name": "pe",
            "Size-limit": "10"
        },
        {
            "Name": "apk",
            "Size-limit": "30"
        },
        {
            "Name": "pdf",
            "Size-limit": "1000"
        },
        {
            "Name": "ms-office",
            "Size-limit": "2000"
        },
        {
            "Name": "jar",
            "Size-limit": "5"
        },
        {
            "Name": "flash",
            "Size-limit": "5"
        },
        {
            "Name": "MacOSX",
            "Size-limit": "1"
        },
        {
            "Name": "archive",
            "Size-limit": "10"
        },
        {
            "Name": "linux",
            "Size-limit": "2"
        },
        {
            "Name": "script",
            "Size-limit": "20"
        }
    ],
    "Panorama.WildFire.Schedule": {
        "recurring": {
            "every-min": {
                "action": "download-and-install"
            }
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>WildFire Configuration</h3>
<p>
 Report Grayware File: yes
</p>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>Size-limit</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> pe </td>
      <td> 10 </td>
    </tr>
    <tr>
      <td> apk </td>
      <td> 30 </td>
    </tr>
    <tr>
      <td> pdf </td>
      <td> 1000 </td>
    </tr>
    <tr>
      <td> ms-office </td>
      <td> 2000 </td>
    </tr>
    <tr>
      <td> jar </td>
      <td> 5 </td>
    </tr>
    <tr>
      <td> flash </td>
      <td> 5 </td>
    </tr>
    <tr>
      <td> MacOSX </td>
      <td> 1 </td>
    </tr>
    <tr>
      <td> archive </td>
      <td> 10 </td>
    </tr>
    <tr>
      <td> linux </td>
      <td> 2 </td>
    </tr>
    <tr>
      <td> script </td>
      <td> 20 </td>
    </tr>
  </tbody>
</table>

<h3>The updated schedule for Wildfire</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>recurring</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> every-min: {"action": "download-and-install"} </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="panorama-url-filtering-block-default-categories">82. panorama-url-filtering-block-default-categories</h3>
<hr>
<p>Set default categories to block in the URL filtering profile.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-url-filtering-block-default-categories</code>
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
      <td>profile_name</td>
      <td>The url-filtering profile name. Get the name by running get-security-profiles command.</td>
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
  <code>!panorama-url-filtering-block-default-categories profile_name=test</code>
</p>

<h5>Human Readable Output</h5>
<p>
The default categories to block has been set successfully to test
</p>


<h3 id="panorama-get-anti-spyware-best-practice">83. panorama-get-anti-spyware-best-practice</h3>
<hr>
<p>Show anti-spyware best practices.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-get-anti-spyware-best-practice</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.

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
      <td>Panorama.Spyware.BotentDomain.Name</td>
      <td>String</td>
      <td>Botnet domain name.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.BotentDomain.Action</td>
      <td>String</td>
      <td>Botnet domain action.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.BotentDomain.Packet-capture</td>
      <td>String</td>
      <td>Is packet capture enabled.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.BotentDomain.Sinkhole.ipv4-address</td>
      <td>String</td>
      <td>Botnet domain ipv4 address.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.BotentDomain.Sinkhole.ipv6-address</td>
      <td>String</td>
      <td>Botnet domain ipv6 address.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.Rule.Cateogry</td>
      <td>String</td>
      <td>Rule category.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.Rule.Action</td>
      <td>String</td>
      <td>Rule action.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.Rule.Name</td>
      <td>String</td>
      <td>Rule name.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.Rule.Severity</td>
      <td>String</td>
      <td>Rule severity.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.Rule.Threat-name</td>
      <td>String</td>
      <td>Rule threat name.</td>
    </tr>
    <tr>
      <td>Panorama.Spyware.BotentDomain.Max_version</td>
      <td>String</td>
      <td>Botnet domain max version.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!panorama-get-anti-spyware-best-practice</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Panorama.Spyware.BotentDomain": [
        {
            "Action": {
                "sinkhole": null
            },
            "Name": "default-paloalto-dns",
            "Packet-capture": "disable"
        },
        {
            "Action": {
                "allow": null
            },
            "Max_version": "9.1.9",
            "Name": "default-paloalto-cloud",
            "Packet-capture": "disable"
        }
    ],
    "Panorama.Spyware.BotentDomain.Sinkhole": [
        {
            "ipv4-address": "pan-sinkhole-default-ip",
            "ipv6-address": "::1"
        }
    ],
    "Panorama.Spyware.Rule": [
        {
            "Action": {
                "reset-both": null
            },
            "Category": "any",
            "Name": "simple-critical",
            "Severity": "critical",
            "Threat-name": "any"
        },
        {
            "Action": {
                "reset-both": null
            },
            "Category": "any",
            "Name": "simple-high",
            "Severity": "high",
            "Threat-name": "any"
        },
        {
            "Action": {
                "reset-both": null
            },
            "Category": "any",
            "Name": "simple-medium",
            "Severity": "medium",
            "Threat-name": "any"
        },
        {
            "Action": {
                "default": null
            },
            "Category": "any",
            "Name": "simple-informational",
            "Severity": "informational",
            "Threat-name": "any"
        },
        {
            "Action": {
                "default": null
            },
            "Category": "any",
            "Name": "simple-low",
            "Severity": "low",
            "Threat-name": "any"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Anti Spyware Botnet-Domains Best Practice</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>Action</strong></th>
      <th><strong>Packet-capture</strong></th>
      <th><strong>ipv4-address</strong></th>
      <th><strong>ipv6-address</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> default-paloalto-dns </td>
      <td> sinkhole: null </td>
      <td> disable </td>
      <td>  </td>
      <td>  </td>
    </tr>
    <tr>
      <td> default-paloalto-cloud </td>
      <td> allow: null </td>
      <td> disable </td>
      <td>  </td>
      <td>  </td>
    </tr>
    <tr>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td> pan-sinkhole-default-ip </td>
      <td> ::1 </td>
    </tr>
  </tbody>
</table>

<h3>Anti Spyware Best Practice Rules</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>Severity</strong></th>
      <th><strong>Action</strong></th>
      <th><strong>Category</strong></th>
      <th><strong>Threat-name</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> simple-critical </td>
      <td> critical </td>
      <td> reset-both: null </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-high </td>
      <td> high </td>
      <td> reset-both: null </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-medium </td>
      <td> medium </td>
      <td> reset-both: null </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-informational </td>
      <td> informational </td>
      <td> default: null </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-low </td>
      <td> low </td>
      <td> default: null </td>
      <td> any </td>
      <td> any </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="panorama-get-file-blocking-best-practice">84. panorama-get-file-blocking-best-practice</h3>
<hr>
<p>Show file-blocking best practices.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-get-file-blocking-best-practice</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.

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
      <td>Panorama.FileBlocking.Rule.Action</td>
      <td>String</td>
      <td>Rule action.</td>
    </tr>
    <tr>
      <td>Panorama.FileBlocking.Rule.Application</td>
      <td>String</td>
      <td>Rule application.</td>
    </tr>
    <tr>
      <td>Panorama.FileBlocking.Rule.File-type</td>
      <td>String</td>
      <td>Rule file type.</td>
    </tr>
    <tr>
      <td>Panorama.FileBlocking.Rule.Name</td>
      <td>String</td>
      <td>Rule name.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!panorama-get-file-blocking-best-practice</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Panorama.FileBlocking.Rule": [
        {
            "Action": "block",
            "Application": "any",
            "File-type": [
                "7z",
                "bat",
                "cab",
                "chm",
                "class",
                "cpl",
                "dll",
                "exe",
                "flash",
                "hlp",
                "hta",
                "jar",
                "msi",
                "Multi-Level-Encoding",
                "ocx",
                "PE",
                "pif",
                "rar",
                "scr",
                "tar",
                "torrent",
                "vbe",
                "wsf"
            ],
            "Name": "Block all risky file types"
        },
        {
            "Action": "block",
            "Application": "any",
            "File-type": [
                "encrypted-rar",
                "encrypted-zip"
            ],
            "Name": "Block encrypted files"
        },
        {
            "Action": "alert",
            "Application": "any",
            "File-type": "any",
            "Name": "Log all other file types"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>File Blocking Profile Best Practice</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>Action</strong></th>
      <th><strong>File-type</strong></th>
      <th><strong>Application</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> Block all risky file types </td>
      <td> block </td>
      <td> 7z,<br>bat,<br>cab,<br>chm,<br>class,<br>cpl,<br>dll,<br>exe,<br>flash,<br>hlp,<br>hta,<br>jar,<br>msi,<br>Multi-Level-Encoding,<br>ocx,<br>PE,<br>pif,<br>rar,<br>scr,<br>tar,<br>torrent,<br>vbe,<br>wsf </td>
      <td> any </td>
    </tr>
    <tr>
      <td> Block encrypted files </td>
      <td> block </td>
      <td> encrypted-rar,<br>encrypted-zip </td>
      <td> any </td>
    </tr>
    <tr>
      <td> Log all other file types </td>
      <td> alert </td>
      <td> any </td>
      <td> any </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="panorama-get-antivirus-best-practice">85. panorama-get-antivirus-best-practice</h3>
<hr>
<p>Show anti-virus best practices.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-get-antivirus-best-practice</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.

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
      <td>Panorama.Antivirus.Decoder.Action</td>
      <td>String</td>
      <td>Rule action.</td>
    </tr>
    <tr>
      <td>Panorama.Antivirus.Decoder.Name</td>
      <td>String</td>
      <td>Rule name.</td>
    </tr>
    <tr>
      <td>Panorama.Antivirus.Decoder.WildFire-action</td>
      <td>String</td>
      <td>WildFire action.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!panorama-get-antivirus-best-practice</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Panorama.Antivirus.Decoder": [
        {
            "Action": "default",
            "Name": "http",
            "WildFire-action": "default"
        },
        {
            "Action": "default",
            "Name": "http2",
            "WildFire-action": "default"
        },
        {
            "Action": "default",
            "Name": "smtp",
            "WildFire-action": "default"
        },
        {
            "Action": "default",
            "Name": "imap",
            "WildFire-action": "default"
        },
        {
            "Action": "default",
            "Name": "pop3",
            "WildFire-action": "default"
        },
        {
            "Action": "default",
            "Name": "ftp",
            "WildFire-action": "default"
        },
        {
            "Action": "default",
            "Name": "smb",
            "WildFire-action": "default"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Antivirus Best Practice Profile</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>Action</strong></th>
      <th><strong>WildFire-action</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> http </td>
      <td> default </td>
      <td> default </td>
    </tr>
    <tr>
      <td> http2 </td>
      <td> default </td>
      <td> default </td>
    </tr>
    <tr>
      <td> smtp </td>
      <td> default </td>
      <td> default </td>
    </tr>
    <tr>
      <td> imap </td>
      <td> default </td>
      <td> default </td>
    </tr>
    <tr>
      <td> pop3 </td>
      <td> default </td>
      <td> default </td>
    </tr>
    <tr>
      <td> ftp </td>
      <td> default </td>
      <td> default </td>
    </tr>
    <tr>
      <td> smb </td>
      <td> default </td>
      <td> default </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="panorama-get-vulnerability-protection-best-practice">86. panorama-get-vulnerability-protection-best-practice</h3>
<hr>
<p>Show vulnerability-protection best practices.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-get-vulnerability-protection-best-practice</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.

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
      <td>Panorama.Vulnerability.Rule.Action</td>
      <td>String</td>
      <td>Rule action.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rule.CVE</td>
      <td>String</td>
      <td>Rule CVE.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rule.Cateogry</td>
      <td>String</td>
      <td>Rule category.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rule.Host</td>
      <td>String</td>
      <td>The rule host.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rule.Name</td>
      <td>String</td>
      <td>Rule name.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rule.Severity</td>
      <td>String</td>
      <td>The rule severity.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rule.Threat-name</td>
      <td>String</td>
      <td>The threat name.</td>
    </tr>
    <tr>
      <td>Panorama.Vulnerability.Rule.Vendor-id</td>
      <td>String</td>
      <td>The vendor ID.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!panorama-get-vulnerability-protection-best-practice</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Panorama.Vulnerability.Rule": [
        {
            "Action": {
                "reset-both": null
            },
            "CVE": "any",
            "Category": "any",
            "Host": "client",
            "Name": "simple-client-critical",
            "Severity": "critical",
            "Threat-name": "any",
            "Vendor-id": "any"
        },
        {
            "Action": {
                "reset-both": null
            },
            "CVE": "any",
            "Category": "any",
            "Host": "client",
            "Name": "simple-client-high",
            "Severity": "high",
            "Threat-name": "any",
            "Vendor-id": "any"
        },
        {
            "Action": {
                "reset-both": null
            },
            "CVE": "any",
            "Category": "any",
            "Host": "client",
            "Name": "simple-client-medium",
            "Severity": "medium",
            "Threat-name": "any",
            "Vendor-id": "any"
        },
        {
            "Action": {
                "default": null
            },
            "CVE": "any",
            "Category": "any",
            "Host": "client",
            "Name": "simple-client-informational",
            "Severity": "informational",
            "Threat-name": "any",
            "Vendor-id": "any"
        },
        {
            "Action": {
                "default": null
            },
            "CVE": "any",
            "Category": "any",
            "Host": "client",
            "Name": "simple-client-low",
            "Severity": "low",
            "Threat-name": "any",
            "Vendor-id": "any"
        },
        {
            "Action": {
                "reset-both": null
            },
            "CVE": "any",
            "Category": "any",
            "Host": "server",
            "Name": "simple-server-critical",
            "Severity": "critical",
            "Threat-name": "any",
            "Vendor-id": "any"
        },
        {
            "Action": {
                "reset-both": null
            },
            "CVE": "any",
            "Category": "any",
            "Host": "server",
            "Name": "simple-server-high",
            "Severity": "high",
            "Threat-name": "any",
            "Vendor-id": "any"
        },
        {
            "Action": {
                "reset-both": null
            },
            "CVE": "any",
            "Category": "any",
            "Host": "server",
            "Name": "simple-server-medium",
            "Severity": "medium",
            "Threat-name": "any",
            "Vendor-id": "any"
        },
        {
            "Action": {
                "default": null
            },
            "CVE": "any",
            "Category": "any",
            "Host": "server",
            "Name": "simple-server-informational",
            "Severity": "informational",
            "Threat-name": "any",
            "Vendor-id": "any"
        },
        {
            "Action": {
                "default": null
            },
            "CVE": "any",
            "Category": "any",
            "Host": "server",
            "Name": "simple-server-low",
            "Severity": "low",
            "Threat-name": "any",
            "Vendor-id": "any"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>vulnerability Protection Best Practice Profile</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>Action</strong></th>
      <th><strong>Host</strong></th>
      <th><strong>Severity</strong></th>
      <th><strong>Category</strong></th>
      <th><strong>Threat-name</strong></th>
      <th><strong>CVE</strong></th>
      <th><strong>Vendor-id</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> simple-client-critical </td>
      <td> reset-both: null </td>
      <td> client </td>
      <td> critical </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-client-high </td>
      <td> reset-both: null </td>
      <td> client </td>
      <td> high </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-client-medium </td>
      <td> reset-both: null </td>
      <td> client </td>
      <td> medium </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-client-informational </td>
      <td> default: null </td>
      <td> client </td>
      <td> informational </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-client-low </td>
      <td> default: null </td>
      <td> client </td>
      <td> low </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-server-critical </td>
      <td> reset-both: null </td>
      <td> server </td>
      <td> critical </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-server-high </td>
      <td> reset-both: null </td>
      <td> server </td>
      <td> high </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-server-medium </td>
      <td> reset-both: null </td>
      <td> server </td>
      <td> medium </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-server-informational </td>
      <td> default: null </td>
      <td> server </td>
      <td> informational </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
    </tr>
    <tr>
      <td> simple-server-low </td>
      <td> default: null </td>
      <td> server </td>
      <td> low </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
      <td> any </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="panorama-get-wildfire-best-practice">87. panorama-get-wildfire-best-practice</h3>
<hr>
<p>Show WildFire best practices.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-get-wildfire-best-practice</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.

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
      <td>Panorama.WildFire.Analysis</td>
      <td>String</td>
      <td>WildFire analysis.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.Application</td>
      <td>String</td>
      <td>WildFire application.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.File.File-size</td>
      <td>String</td>
      <td>Recommended file size.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.File.Name</td>
      <td>String</td>
      <td>File name.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.File-type</td>
      <td>String</td>
      <td>WildFire profile file type.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.Name</td>
      <td>String</td>
      <td>WildFire profile name.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.SSLDecrypt</td>
      <td>String</td>
      <td>SSL decrypt content.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.Schedule.Action</td>
      <td>String</td>
      <td>WildFire schedule action.</td>
    </tr>
    <tr>
      <td>Panorama.WildFire.Schedule.Recurring</td>
      <td>String</td>
      <td>WildFire schedule recurring.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!panorama-get-wildfire-best-practice</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Panorama.WildFire": {
        "Analysis": "public-cloud",
        "Application": "any",
        "File-type": "any",
        "Name": "default"
    },
    "Panorama.WildFire.File": [
        {
            "File-size": "10",
            "Name": "pe"
        },
        {
            "File-size": "30",
            "Name": "apk"
        },
        {
            "File-size": "1000",
            "Name": "pdf"
        },
        {
            "File-size": "2000",
            "Name": "ms-office"
        },
        {
            "File-size": "5",
            "Name": "jar"
        },
        {
            "File-size": "5",
            "Name": "flash"
        },
        {
            "File-size": "1",
            "Name": "MacOS"
        },
        {
            "File-size": "10",
            "Name": "archive"
        },
        {
            "File-size": "2",
            "Name": "linux"
        },
        {
            "File-size": "20",
            "Name": "script"
        }
    ],
    "Panorama.WildFire.SSLDecrypt": {
        "allow-forward-decrypted-content": "yes"
    },
    "Panorama.WildFire.Schedule": {
        "Action": "download-and-install",
        "Recurring": "every-minute"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>WildFire Best Practice Profile</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>Analysis</strong></th>
      <th><strong>Application</strong></th>
      <th><strong>File-type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> default </td>
      <td> public-cloud </td>
      <td> any </td>
      <td> any </td>
    </tr>
  </tbody>
</table>

<h3>Wildfire Best Practice Schedule</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Action</strong></th>
      <th><strong>Recurring</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> download-and-install </td>
      <td> every-minute </td>
    </tr>
  </tbody>
</table>

<h3>Wildfire SSL Decrypt Settings</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>allow-forward-decrypted-content</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> yes </td>
    </tr>
  </tbody>
</table>

<h3>Wildfire System Settings</h3>
<p>
 report-grayware-file: yes
</p>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>File-size</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> pe </td>
      <td> 10 </td>
    </tr>
    <tr>
      <td> apk </td>
      <td> 30 </td>
    </tr>
    <tr>
      <td> pdf </td>
      <td> 1000 </td>
    </tr>
    <tr>
      <td> ms-office </td>
      <td> 2000 </td>
    </tr>
    <tr>
      <td> jar </td>
      <td> 5 </td>
    </tr>
    <tr>
      <td> flash </td>
      <td> 5 </td>
    </tr>
    <tr>
      <td> MacOS </td>
      <td> 1 </td>
    </tr>
    <tr>
      <td> archive </td>
      <td> 10 </td>
    </tr>
    <tr>
      <td> linux </td>
      <td> 2 </td>
    </tr>
    <tr>
      <td> script </td>
      <td> 20 </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="panorama-get-url-filtering-best-practice">88. panorama-get-url-filtering-best-practice</h3>
<hr>
<p>Show URL Filtering best practices.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-get-url-filtering-best-practice</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.

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
      <td>Panorama.URLFilter.Category.Action</td>
      <td>String</td>
      <td>The action to perform on the category.</td>
    </tr>
    <tr>
      <td>Panorama.URLFilter.Category.Name</td>
      <td>String</td>
      <td>Category name.</td>
    </tr>
    <tr>
      <td>Panorama.URLFilter.DeviceGroup</td>
      <td>String</td>
      <td>Device group name.</td>
    </tr>
    <tr>
      <td>Panorama.URLFilter.Name</td>
      <td>String</td>
      <td>Profile name.</td>
    </tr>
    <tr>
      <td>Panorama.URLFilter.Header.log-container-page-only</td>
      <td>String</td>
      <td>Log container page only.</td>
    </tr>
    <tr>
      <td>Panorama.URLFilter.Header.log-http-hdr-referer</td>
      <td>String</td>
      <td>Log HTTP header referer.</td>
    </tr>
    <tr>
      <td>Panorama.URLFilter.Header.log-http-hdr-user</td>
      <td>String</td>
      <td>Log HTTP header user.</td>
    </tr>
    <tr>
      <td>Panorama.URLFilter.Header.log-http-hdr-xff</td>
      <td>String</td>
      <td>Log HTTP header xff.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!panorama-get-url-filtering-best-practice</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Panorama.URLFilter": {
        "Category": [
            {
                "Action": "alert",
                "Name": "abortion"
            },
            {
                "Action": "alert",
                "Name": "abused-drugs"
            },
            {
                "Action": "alert",
                "Name": "adult"
            },
            {
                "Action": "alert",
                "Name": "alcohol-and-tobacco"
            },
            {
                "Action": "alert",
                "Name": "auctions"
            },
            {
                "Action": "alert",
                "Name": "business-and-economy"
            },
            {
                "Action": "alert",
                "Name": "computer-and-internet-info"
            },
            {
                "Action": "alert",
                "Name": "content-delivery-networks"
            },
            {
                "Action": "alert",
                "Name": "cryptocurrency"
            },
            {
                "Action": "alert",
                "Name": "dating"
            },
            {
                "Action": "alert",
                "Name": "educational-institutions"
            },
            {
                "Action": "alert",
                "Name": "entertainment-and-arts"
            },
            {
                "Action": "alert",
                "Name": "financial-services"
            },
            {
                "Action": "alert",
                "Name": "gambling"
            },
            {
                "Action": "alert",
                "Name": "games"
            },
            {
                "Action": "alert",
                "Name": "government"
            },
            {
                "Action": "alert",
                "Name": "grayware"
            },
            {
                "Action": "alert",
                "Name": "health-and-medicine"
            },
            {
                "Action": "alert",
                "Name": "high-risk"
            },
            {
                "Action": "alert",
                "Name": "home-and-garden"
            },
            {
                "Action": "alert",
                "Name": "hunting-and-fishing"
            },
            {
                "Action": "alert",
                "Name": "insufficient-content"
            },
            {
                "Action": "alert",
                "Name": "internet-communications-and-telephony"
            },
            {
                "Action": "alert",
                "Name": "internet-portals"
            },
            {
                "Action": "alert",
                "Name": "job-search"
            },
            {
                "Action": "alert",
                "Name": "legal"
            },
            {
                "Action": "alert",
                "Name": "low-risk"
            },
            {
                "Action": "alert",
                "Name": "medium-risk"
            },
            {
                "Action": "alert",
                "Name": "military"
            },
            {
                "Action": "alert",
                "Name": "motor-vehicles"
            },
            {
                "Action": "alert",
                "Name": "music"
            },
            {
                "Action": "alert",
                "Name": "newly-registered-domain"
            },
            {
                "Action": "alert",
                "Name": "news"
            },
            {
                "Action": "alert",
                "Name": "not-resolved"
            },
            {
                "Action": "alert",
                "Name": "nudity"
            },
            {
                "Action": "alert",
                "Name": "online-storage-and-backup"
            },
            {
                "Action": "alert",
                "Name": "peer-to-peer"
            },
            {
                "Action": "alert",
                "Name": "personal-sites-and-blogs"
            },
            {
                "Action": "alert",
                "Name": "philosophy-and-political-advocacy"
            },
            {
                "Action": "alert",
                "Name": "private-ip-addresses"
            },
            {
                "Action": "alert",
                "Name": "questionable"
            },
            {
                "Action": "alert",
                "Name": "real-estate"
            },
            {
                "Action": "alert",
                "Name": "recreation-and-hobbies"
            },
            {
                "Action": "alert",
                "Name": "reference-and-research"
            },
            {
                "Action": "alert",
                "Name": "religion"
            },
            {
                "Action": "alert",
                "Name": "search-engines"
            },
            {
                "Action": "alert",
                "Name": "sex-education"
            },
            {
                "Action": "alert",
                "Name": "shareware-and-freeware"
            },
            {
                "Action": "alert",
                "Name": "shopping"
            },
            {
                "Action": "alert",
                "Name": "social-networking"
            },
            {
                "Action": "alert",
                "Name": "society"
            },
            {
                "Action": "alert",
                "Name": "sports"
            },
            {
                "Action": "alert",
                "Name": "stock-advice-and-tools"
            },
            {
                "Action": "alert",
                "Name": "streaming-media"
            },
            {
                "Action": "alert",
                "Name": "swimsuits-and-intimate-apparel"
            },
            {
                "Action": "alert",
                "Name": "training-and-tools"
            },
            {
                "Action": "alert",
                "Name": "translation"
            },
            {
                "Action": "alert",
                "Name": "travel"
            },
            {
                "Action": "alert",
                "Name": "weapons"
            },
            {
                "Action": "alert",
                "Name": "web-advertisements"
            },
            {
                "Action": "alert",
                "Name": "web-based-email"
            },
            {
                "Action": "alert",
                "Name": "web-hosting"
            },
            {
                "Action": "block",
                "Name": "command-and-control"
            },
            {
                "Action": "block",
                "Name": "copyright-infringement"
            },
            {
                "Action": "block",
                "Name": "dynamic-dns"
            },
            {
                "Action": "block",
                "Name": "extremism"
            },
            {
                "Action": "block",
                "Name": "hacking"
            },
            {
                "Action": "block",
                "Name": "malware"
            },
            {
                "Action": "block",
                "Name": "parked"
            },
            {
                "Action": "block",
                "Name": "phishing"
            },
            {
                "Action": "block",
                "Name": "proxy-avoidance-and-anonymizers"
            },
            {
                "Action": "block",
                "Name": "unknown"
            }
        ],
        "DeviceGroup": "Demisto sales lab",
        "Name": "best-practice"
    },
    "Panorama.URLFilter.Header": {
        "log-container-page-only": "no",
        "log-http-hdr-referer": "yes",
        "log-http-hdr-user": "yes",
        "log-http-hdr-xff": "yes"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>URL Filtering Best Practice Profile Categories</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Category</strong></th>
      <th><strong>DeviceGroup</strong></th>
      <th><strong>Name</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> {'Name': 'abortion', 'Action': 'alert'},<br>{'Name': 'abused-drugs', 'Action': 'alert'},<br>{'Name': 'adult', 'Action': 'alert'},<br>{'Name': 'alcohol-and-tobacco', 'Action': 'alert'},<br>{'Name': 'auctions', 'Action': 'alert'},<br>{'Name': 'business-and-economy', 'Action': 'alert'},<br>{'Name': 'computer-and-internet-info', 'Action': 'alert'},<br>{'Name': 'content-delivery-networks', 'Action': 'alert'},<br>{'Name': 'cryptocurrency', 'Action': 'alert'},<br>{'Name': 'dating', 'Action': 'alert'},<br>{'Name': 'educational-institutions', 'Action': 'alert'},<br>{'Name': 'entertainment-and-arts', 'Action': 'alert'},<br>{'Name': 'financial-services', 'Action': 'alert'},<br>{'Name': 'gambling', 'Action': 'alert'},<br>{'Name': 'games', 'Action': 'alert'},<br>{'Name': 'government', 'Action': 'alert'},<br>{'Name': 'grayware', 'Action': 'alert'},<br>{'Name': 'health-and-medicine', 'Action': 'alert'},<br>{'Name': 'high-risk', 'Action': 'alert'},<br>{'Name': 'home-and-garden', 'Action': 'alert'},<br>{'Name': 'hunting-and-fishing', 'Action': 'alert'},<br>{'Name': 'insufficient-content', 'Action': 'alert'},<br>{'Name': 'internet-communications-and-telephony', 'Action': 'alert'},<br>{'Name': 'internet-portals', 'Action': 'alert'},<br>{'Name': 'job-search', 'Action': 'alert'},<br>{'Name': 'legal', 'Action': 'alert'},<br>{'Name': 'low-risk', 'Action': 'alert'},<br>{'Name': 'medium-risk', 'Action': 'alert'},<br>{'Name': 'military', 'Action': 'alert'},<br>{'Name': 'motor-vehicles', 'Action': 'alert'},<br>{'Name': 'music', 'Action': 'alert'},<br>{'Name': 'newly-registered-domain', 'Action': 'alert'},<br>{'Name': 'news', 'Action': 'alert'},<br>{'Name': 'not-resolved', 'Action': 'alert'},<br>{'Name': 'nudity', 'Action': 'alert'},<br>{'Name': 'online-storage-and-backup', 'Action': 'alert'},<br>{'Name': 'peer-to-peer', 'Action': 'alert'},<br>{'Name': 'personal-sites-and-blogs', 'Action': 'alert'},<br>{'Name': 'philosophy-and-political-advocacy', 'Action': 'alert'},<br>{'Name': 'private-ip-addresses', 'Action': 'alert'},<br>{'Name': 'questionable', 'Action': 'alert'},<br>{'Name': 'real-estate', 'Action': 'alert'},<br>{'Name': 'recreation-and-hobbies', 'Action': 'alert'},<br>{'Name': 'reference-and-research', 'Action': 'alert'},<br>{'Name': 'religion', 'Action': 'alert'},<br>{'Name': 'search-engines', 'Action': 'alert'},<br>{'Name': 'sex-education', 'Action': 'alert'},<br>{'Name': 'shareware-and-freeware', 'Action': 'alert'},<br>{'Name': 'shopping', 'Action': 'alert'},<br>{'Name': 'social-networking', 'Action': 'alert'},<br>{'Name': 'society', 'Action': 'alert'},<br>{'Name': 'sports', 'Action': 'alert'},<br>{'Name': 'stock-advice-and-tools', 'Action': 'alert'},<br>{'Name': 'streaming-media', 'Action': 'alert'},<br>{'Name': 'swimsuits-and-intimate-apparel', 'Action': 'alert'},<br>{'Name': 'training-and-tools', 'Action': 'alert'},<br>{'Name': 'translation', 'Action': 'alert'},<br>{'Name': 'travel', 'Action': 'alert'},<br>{'Name': 'weapons', 'Action': 'alert'},<br>{'Name': 'web-advertisements', 'Action': 'alert'},<br>{'Name': 'web-based-email', 'Action': 'alert'},<br>{'Name': 'web-hosting', 'Action': 'alert'},<br>{'Name': 'command-and-control', 'Action': 'block'},<br>{'Name': 'copyright-infringement', 'Action': 'block'},<br>{'Name': 'dynamic-dns', 'Action': 'block'},<br>{'Name': 'extremism', 'Action': 'block'},<br>{'Name': 'hacking', 'Action': 'block'},<br>{'Name': 'malware', 'Action': 'block'},<br>{'Name': 'parked', 'Action': 'block'},<br>{'Name': 'phishing', 'Action': 'block'},<br>{'Name': 'proxy-avoidance-and-anonymizers', 'Action': 'block'},<br>{'Name': 'unknown', 'Action': 'block'} </td>
      <td> Demisto sales lab </td>
      <td> best-practice </td>
    </tr>
  </tbody>
</table>

<h3>Best Practice Headers</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>log-container-page-only</strong></th>
      <th><strong>log-http-hdr-referer</strong></th>
      <th><strong>log-http-hdr-user</strong></th>
      <th><strong>log-http-hdr-xff</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> no </td>
      <td> yes </td>
      <td> yes </td>
      <td> yes </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="panorama-enforce-wildfire-best-practice">89. panorama-enforce-wildfire-best-practice</h3>
<hr>
<p>Enforce wildfire file upload to the maximum size + all file types are forwarded and update schedule.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-enforce-wildfire-best-practice</code>
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
      <td>template</td>
      <td>The template name.</td>
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
  <code>!panorama-enforce-wildfire-best-practice template=WildFire</code>
</p>

<h5>Human Readable Output</h5>
<p>
The schedule was updated according to the best practice.
Recurring every minute with the action of "download and install"
The file upload for all file types is set to the maximum size.
</p>

<h3 id="panorama-create-antivirus-best-practice-profile">90. panorama-create-antivirus-best-practice-profile</h3>
<hr>
<p>Create antivirus best practice profile.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-create-antivirus-best-practice-profile</code>
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
      <td>profile_name</td>
      <td>The name of the profile</td>
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
  <pre>!panorama-create-antivirus-best-practice-profile profile_name=test</pre>
</p>

<h5>Human Readable Output</h5>
<p>
The profile test was created successfully.
</p>

<h3 id="panorama-create-anti-spyware-best-practice-profile">91. panorama-create-anti-spyware-best-practice-profile</h3>
<hr>
<p>Create Anti Spyware best practice profile.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-create-anti-spyware-best-practice-profile</code>
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
      <td>profile_name</td>
      <td>The profile name.</td>
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
  <pre>!panorama-create-anti-spyware-best-practice-profile profile_name=test</pre>
</p>

<h5>Human Readable Output</h5>
<p>
The profile test was created successfully.
</p>

<h3 id="panorama-create-vulnerability-best-practice-profile">92. panorama-create-vulnerability-best-practice-profile</h3>
<hr>
<p>Create vulnerability protection best practice profile.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-create-vulnerability-best-practice-profile</code>
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
      <td>profile_name</td>
      <td>The profile name.</td>
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
  <pre>!panorama-create-vulnerability-best-practice-profile profile_name=test</pre>
</p>

<h5>Human Readable Output</h5>
<p>
The profile test was created successfully.
</p>

<h3 id="panorama-create-url-filtering-best-practice-profile">93. panorama-create-url-filtering-best-practice-profile</h3>
<hr>
<p>Create URL filtering best practice profile.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-create-url-filtering-best-practice-profile</code>
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
      <td>profile_name</td>
      <td>The profile name.</td>
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
  <pre>!panorama-create-url-filtering-best-practice-profile profile_name=test</pre>
</p>

<h5>Human Readable Output</h5>
<p>

The profile test was created successfully.
</p>

<h3 id="panorama-create-file-blocking-best-practice-profile">94. panorama-create-file-blocking-best-practice-profile</h3>
<hr>
<p>Create file blocking best practice profile.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-create-file-blocking-best-practice-profile</code>
</p>
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
      <td>profile_name</td>
      <td>The name of the profile.</td>
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
  <pre>!panorama-create-file-blocking-best-practice-profile profile_name=test</pre>
</p>

<h5>Human Readable Output</h5>
The profile test was created successfully.
</p>

<h3 id="panorama-create-wildfire-best-practice-profile">95. panorama-create-wildfire-best-practice-profile</h3>
<hr>
<p>Create WildFire analysis best practice profile.</p>
<h5>Base Command</h5>
<p>
  <code>panorama-create-wildfire-best-practice-profile</code>
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
      <td>profile_name</td>
      <td>The name of the profile.</td>
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
<pre> !panorama-create-wildfire-best-practice-profile profile_name=test </pre>
</p>

<h5>Human Readable Output</h5>
<p>
The profile test was created successfully.
</p>

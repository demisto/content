<!-- HTML_DOC -->
<p>VMWare is used by Demisto to manage and control virtual machines that it is using.</p>
<h3>To set up the integration on Demisto:</h3>
<ol>
<li>Go to ‘Settings &gt; Integrations &gt; Servers &amp; Services’</li>
<li>Locate ‘VMware’ by searching for it using the search box on the top of the page.</li>
<li>Click ‘Add instance’ to create and configure a new integration. You should configure the following settings:<br><strong>Name</strong>: A textual name for the integration instance.<br><strong>Server URL</strong>: Server URL to access.<br><strong>Credentials: </strong>The credentials for accessing the integration.<br><strong>Do not validate server certificate: </strong>Select in case you wish to circumvent server certification validation.  You may want to do this in case the server you are connecting to does not have a valid certificate.<br><strong>Use system proxy settings: </strong>Specify whether to communicate with the integration via the system proxy server or not.<br><strong>Demisto engine</strong>: If relevant, select the engine that acts as a proxy to the server. Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Demisto server from accessing the remote networks.<br>For more information on Demisto engines see:<br><a href="https://support.demisto.com/hc/en-us/articles/226274727-Settings-Integrations-Engines">https://demisto.zendesk.com/hc/en-us/articles/226274727-Settings-Integrations-Engines</a>
</li>
<li>Press the ‘Test’ button to validate connection.<br>If you are experiencing issues with the service configuration, please contact Demisto support at <a href="mailto:support@demisto.com">support@demisto.com</a>
</li>
<li>After completing the test successfully, press the ‘Done’ button.</li>
</ol>
<h3>Top Use-cases:</h3>
<ul>
<li>Create and revert to snapshot.</li>
<li>Get information regarding virtual machines.</li>
<li>Power-on, power-off, suspend and rebooting virtual machines.</li>
</ul>
<h3>Commands</h3>
<ul>
<li style="font-family: courier;">
<p>vmware-get-vms</p>
</li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>none</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>VMWare.Name</strong>: VM name<br><strong>VMWare.Template</strong>: true if template, else false<br><strong>VMWare.Path</strong>: Path to VM<br><strong>VMWare.Guest</strong>: Guest full name<br><strong>VMWare.UUID</strong>: VM instance UUID<br><strong>VMWare.IP</strong>: VM IP address<br><strong>VMWare.State</strong>: VM State (i.e. on, off, suspended)<br><strong>VMWare.HostName</strong>: Host name of VM<br><strong>VMWare.MACAddress</strong>: MAC Address of VM</p>
<p> </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>[<br>{<br>"Guest": "Ubuntu Linux (64-bit)",<br>"HostName": "ubuntu",<br>"IP": "192.168.100.1",<br>"MACAddress": "00:50:56:bc:86:ec",<br>"Name": "UbuntuTest",<br>"Path": "[datastore1] UbuntuTest/UbuntuTest.vmx",<br>"State": "poweredOn",<br>"Template": false,<br>"UUID": "503ca58b-0821-cf21-fb56-459e55df6d19"<br>}<br>] </p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<ul>
<li style="font-family: courier;">
<p>vmware-poweron</p>
</li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>vm-uuid</strong> - VM UUID of virtual machine to be powered on.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>VMWare.UUID:</strong> VM instance UUID<strong><br>VMWare.State: </strong>VM State (i.e. on, off, suspended)</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>{<br>"VMWare(val.UUID \u0026\u0026 val.UUID === obj.UUID)": {<br>"State": "poweredOn",<br>"UUID": "503ca58b-0821-cf21-fb56-459e55df6d19"<br>}<br>}</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;">vmware-poweroff</li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>vm-uuid</strong> - VM UUID of virtual machine to be powered on.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>VMWare.UUID:</strong> VM instance UUID<strong><br>VMWare.State: </strong>VM State (i.e. on, off, suspended)</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>{<br>"VMWare(val.UUID \u0026\u0026 val.UUID === obj.UUID)": {<br>"State": "poweredOff",<br>"UUID": "503ca58b-0821-cf21-fb56-459e55df6d19"<br>}<br>}</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;">
<p>vmware-suspend</p>
</li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>vm-uuid</strong> - VM UUID of virtual machine to suspend.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>none</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>"Virtual Machine was suspended successfully."</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;">vmware-hard-reboot</li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>vm-uuid</strong> - VM UUID of virtual machine to reboot.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>none </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>"Virtual Machine was suspended successfully."</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;">
<p>vmware-soft-reboot</p>
</li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>vm-uuid</strong> - VM UUID of virtual machine to reboot.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>none </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>"A request to reboot the guest has been sent."</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;">
<p>vmware-create-snapshot</p>
</li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>vm-uuid</strong> - VM UUID of virtual machine.<br><strong>name</strong> - Snapshot name<br><strong>description</strong> - Snapshot description<br><strong>memory</strong> - Snapshot the virtual machine's memory<br><strong>quiesce</strong> - Quiesce guest file system (needs VMWare Tools installed).</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>none </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>name</strong>="VM Daily Snapshot" <br><strong>description</strong>="A daily snapshot of VM" <br><strong>memory</strong>=true <br><strong>quiesce</strong>=false:<br>"Snapshot SnapShotName completed."</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;">
<p>vmware-revert-snapshot</p>
</li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>vm-uuid</strong> - VM UUID of virtual machine.<br><strong>snapshot-name</strong> - Snapshot name</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>none </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>"Reverted to snapshot SnapShotName successfully."</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;">
<p>vmware-get-events</p>
</li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>vm-uuid</strong> - VM UUID of virtual machine.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>none </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>[<br>{<br>"Created Time": "2017-12-27 08:17:56",<br>"Event": "UbuntuTest on 192.168.1.117 in Datacenter is powered on"<br>},<br>{<br>"Created Time": "2017-12-27 08:34:39",<br>"Event": "Guest OS reboot for UbuntuTest on 192.168.1.117 in Datacenter"<br>},<br>{<br>"Created Time": "2017-12-27 08:44:29",<br>"Event": "Guest OS shut down for UbuntuTest on 192.168.1.117 in Datacenter"<br>},<br>{<br>"Created Time": "2017-12-27 08:44:42",<br>"Event": "UbuntuTest on 192.168.1.117 in Datacenter is powered off"<br>}<br>]</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
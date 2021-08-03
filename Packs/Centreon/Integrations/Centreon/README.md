<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use Centreon to check the status of hosts and services.</p>
<p>This integration was integrated and tested with Centreon v2.8.20.</p>
<p><strong>NOTE</strong>: Cortex XSOAR only works for Centreon v2.8.14 and later.</p>
<hr>
<h2>Use Cases</h2>
<ul>
<li>Check the status of hosts.</li>
<li>Check the status of services.</li>
</ul>
<hr>
<h2>Configure Centreon on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Centreon.</li>
<li>Click <strong>Add instance</strong><span class="wysiwyg-color-black"> to create and configure a new integration instance.</span>
<ul>
<li>
<strong>Name:</strong> a textual name for the integration instance</li>
<li>
<strong>Server URL</strong> (http://147.75.33.100:20016/)</li>
<li><strong>Username</strong></li>
<li>Do not validate server certificate (not secure)</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>
</ol>
<hr>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ul>
<li>
<p><a href="#h_5712255351527683650738">Get host status: centreon-get-host-status</a></p>
</li>
<li>
<p><a href="#h_70965456691528185023267">Get service status: centreon-get-service-status</a></p>
</li>
</ul>
<hr>
<h3 id="h_5712255351527683650738">Get host status: centreon-get-host-status</h3>
<h4>Command Example</h4>
<p><code>!centreon-get-host-status viewType=all fields=id,name limit=10</code></p>
<h4>Inputs</h4>
<table style="height: 141px; width: 626px;" border="2" cellpadding="6">
<tbody>
<tr style="height: 20px;">
<td style="width: 163px; height: 20px;"><strong>Parameter</strong></td>
<td style="width: 460px; height: 20px;"><strong>Description</strong></td>
</tr>
<tr style="height: 124px;">
<td style="width: 163px; height: 124px;">viewType</td>
<td style="width: 460px; height: 124px;">
<p>Predefined filter (like in the monitoring view).</p>
<ul>
<li>all</li>
<li>unhandled</li>
<li>problems</li>
</ul>
</td>
</tr>
<tr style="height: 104px;">
<td style="width: 163px; height: 104px;">fields</td>
<td style="width: 460px; height: 104px;">
<p>List of fields that you want to get. Fields are separated from each other with a comma.</p>
<p>For example: fields=id,name,alias,address.</p>
</td>
</tr>
<tr style="height: 166px;">
<td style="width: 163px; height: 166px;">status</td>
<td style="width: 460px; height: 166px;">
<p>Status of the host you want to<span class="wysiwyg-color-black"> get.</span></p>
<ul>
<li><span class="wysiwyg-color-black">up</span></li>
<li>down</li>
<li>unreachable</li>
<li>pending</li>
<li>all</li>
</ul>
</td>
</tr>
<tr style="height: 48px;">
<td style="width: 163px; height: 48px;">hostgroup</td>
<td style="width: 460px; height: 48px;">
<p>Hostgroup ID filter.</p>
<p>For example: hostgroup=2.</p>
</td>
</tr>
<tr style="height: 42.4792px;">
<td style="width: 163px; height: 42.4792px;">instance</td>
<td style="width: 460px; height: 42.4792px;">
<p>Instance ID filter.</p>
<p>For example: instance=2.</p>
</td>
</tr>
<tr style="height: 69px;">
<td style="width: 163px; height: 69px;">search</td>
<td style="width: 460px; height: 69px;">
<p>Search pattern applied on host name.</p>
<p>For example: search="localhost".</p>
</td>
</tr>
<tr style="height: 20px;">
<td style="width: 163px; height: 20px;">criticality</td>
<td style="width: 460px; height: 20px;">A specific criticality.</td>
</tr>
<tr style="height: 20px;">
<td style="width: 163px; height: 20px;">sortType</td>
<td style="width: 460px; height: 20px;">
<p>Sorting method.</p>
<ul>
<li>Ascending: <em>asc</em>
</li>
<li>Descending: <em>desc</em>
</li>
</ul>
</td>
</tr>
<tr style="height: 20px;">
<td style="width: 163px; height: 20px;">limit</td>
<td style="width: 460px; height: 20px;">Number of lines that you want.</td>
</tr>
<tr style="height: 20px;">
<td style="width: 163px; height: 20px;">number</td>
<td style="width: 460px; height: 20px;">Page number.</td>
</tr>
</tbody>
</table>
<p> </p>
<h4>Context Output</h4>
<table style="height: 147px; width: 623.333px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 288px;"><strong>Path</strong></td>
<td style="width: 333.333px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 288px;">Centreon.Host.Output</td>
<td style="width: 333.333px;">Host output</td>
</tr>
<tr>
<td style="width: 288px;">Centreon.Host.Name</td>
<td style="width: 333.333px;">Host name</td>
</tr>
<tr>
<td style="width: 288px;">Centreon.Host.State</td>
<td style="width: 333.333px;">Host state</td>
</tr>
<tr>
<td style="width: 288px;">Centreon.Host.Address</td>
<td style="width: 333.333px;">Host address</td>
</tr>
<tr>
<td style="width: 288px;">Centreon.Host.Id</td>
<td style="width: 333.333px;">Host ID</td>
</tr>
</tbody>
</table>
<h4>
<br> Raw Output</h4>
<pre>{  
    "Host":[  
               {  
               "Acknowledged":"0",
               "Address":"127.0.0.1",
               "Alias":"Localhost",
               "CheckAttempt":"1",
               "Criticality":"",
               "Id":"17",
               "InstanceName":"Central",
               "LastCheck":"1524487617",
               "LastHardStateChange":"",
               "LastStateChange":"",
               "MaxCheckAttempts":"3",
               "Name":"Localhost",
               "Output":"OK - 127.0.0.1: rta 0.076ms, lost 0%",
               "State":"0",
              "StateType":"1"            
      },
               {  
               "Acknowledged":"0",
               "Address":"192.168.1.22",
               "Alias":"jumphost",
               "CheckAttempt":"1",
               "Criticality":"",
               "Id":"37",
               "InstanceName":"Central",
               "LastCheck":"1524487822",
               "LastHardStateChange":"1523986444",
               "LastStateChange":"1523986444",
               "MaxCheckAttempts":"3",
               "Name":"jumphost",
               "Output":"OK - 192.168.1.22: rta 0.379ms, lost 0%",
               "State":"0",
               "StateType":"1"            
      },
               {  
               "Acknowledged":"0",
               "Address":"192.168.1.22",
               "Alias":"jumphost",
               "CheckAttempt":"1",
               "Criticality":"",
               "Id":"38",
               "InstanceName":"Central",
               "LastCheck":"1524487722",
               "LastHardStateChange":"1523987517",
               "LastStateChange":"1523987517",
               "MaxCheckAttempts":"3",
               "Name":"jumphost_1",
               "Output":"OK - 192.168.1.22: rta 0.389ms, lost 0%",
               "State":"0",
               "StateType":"1"            
      }       
   ]
}
</pre>
<hr>
<h3 id="h_70965456691528185023267">Get service status: centreon-get-service-status</h3>
<h4>Command Example</h4>
<p><code>!centreon-get-service-status status=ok fields=id,host_id limit=5 sortType=asc</code></p>
<h4>Inputs</h4>
<table style="height: 164px; width: 610px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 155.333px;"><strong>Parameter</strong></td>
<td style="width: 452.667px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 155.333px;">viewType</td>
<td style="width: 452.667px;">
<p>Predefined filter (like in the monitoring view).</p>
<ul>
<li>all</li>
<li>unhandled</li>
<li>problems</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 155.333px;">fields</td>
<td style="width: 452.667px;">
<p>The list of fields that you want to get, each field separated by a comma.</p>
<p>For example: fields=id,name,alias,address.</p>
</td>
</tr>
<tr>
<td style="width: 155.333px;">status</td>
<td style="width: 452.667px;">
<p>Status of the host you want to<span class="wysiwyg-color-black"> get.</span></p>
<ul>
<li>ok</li>
<li>warning</li>
<li>critical</li>
<li>unknown</li>
<li>pending</li>
<li>all</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 155.333px;">hostgroup</td>
<td style="width: 452.667px;">
<p>Hostgroup ID filter.</p>
<p>For example: hostgroup=2.</p>
</td>
</tr>
<tr>
<td style="width: 155.333px;">servicegroup</td>
<td style="width: 452.667px;">Servicegroup ID filter.</td>
</tr>
<tr>
<td style="width: 155.333px;">instance</td>
<td style="width: 452.667px;">
<p>Instance ID filter.</p>
<p>For example: instance=2.</p>
</td>
</tr>
<tr>
<td style="width: 155.333px;">search</td>
<td style="width: 452.667px;">Search pattern applied on service.</td>
</tr>
<tr>
<td style="width: 155.333px;">searchHost</td>
<td style="width: 452.667px;">Search pattern applied on host.</td>
</tr>
<tr>
<td style="width: 155.333px;">searchOutput</td>
<td style="width: 452.667px;">Search pattern applied on output.</td>
</tr>
<tr>
<td style="width: 155.333px;">criticality</td>
<td style="width: 452.667px;">A specific criticality.</td>
</tr>
<tr>
<td style="width: 155.333px;">sortType</td>
<td style="width: 452.667px;">
<p>Sorting method.</p>
<ul>
<li>Ascending: <em>asc</em>
</li>
<li>Descending: <em>desc</em>
</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 155.333px;">limit</td>
<td style="width: 452.667px;">Number of lines that you want.</td>
</tr>
<tr>
<td style="width: 155.333px;">number</td>
<td style="width: 452.667px;">Page number.</td>
</tr>
</tbody>
</table>
<h4> </h4>
<h4>Context Output</h4>
<table style="height: 102px;" border="2" width="604" cellpadding="6">
<tbody>
<tr>
<td style="width: 298.667px;"><strong>Path</strong></td>
<td style="width: 299.333px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 298.667px;">Centreon.Service.Output</td>
<td style="width: 299.333px;">Service output</td>
</tr>
<tr>
<td style="width: 298.667px;">Centreon.Service.Name</td>
<td style="width: 299.333px;">Service name</td>
</tr>
<tr>
<td style="width: 298.667px;">Centreon.Service.State</td>
<td style="width: 299.333px;">Service state</td>
</tr>
<tr>
<td style="width: 298.667px;">Centreon.Service.Description</td>
<td style="width: 299.333px;">Service description</td>
</tr>
<tr>
<td style="width: 298.667px;">Centreon.Service.Id</td>
<td style="width: 299.333px;">Service ID</td>
</tr>
</tbody>
</table>
<h4> </h4>
<h4>Raw Output</h4>
<pre>{
  "Service": [
    {
      "Acknowledged": "0",
      "CheckAttempt": "1",
      "Criticality": "",
      "Description": "Ping",
      "HostId": "37",
      "LastCheck": "1524487467",
      "LastHardStateChange": "1523986444",
      "LastStateChange": "1523986444",
      "MaxCheckAttempts": "3",
      "Name": "jumphost",
      "Output": "OK - 192.168.1.22: rta 0.185ms, lost 0%",
      "Perfdata": "rta=0.185ms;200.000;400.000;0; pl=0%;20;50;; rtmax=0.398ms;;;; rtmin=0.106ms;;;;",
      "ServiceId": "132",
      "State": "0",
      "StateType": "1"
    },
    {
      "Acknowledged": "0",
      "CheckAttempt": "1",
      "Criticality": "",
      "Description": "Ping",
      "HostId": "38",
      "LastCheck": "1524487617",
      "LastHardStateChange": "1523987517",
      "LastStateChange": "1523987517",
      "MaxCheckAttempts": "3",
      "Name": "jumphost_1",
      "Output": "OK - 192.168.1.22: rta 0.235ms, lost 0%",
      "Perfdata": "rta=0.235ms;200.000;400.000;0; pl=0%;20;50;; rtmax=0.514ms;;;; rtmin=0.134ms;;;;",
      "ServiceId": "133",
      "State": "0",
      "StateType": "1"
    }
  ]
}

</pre>
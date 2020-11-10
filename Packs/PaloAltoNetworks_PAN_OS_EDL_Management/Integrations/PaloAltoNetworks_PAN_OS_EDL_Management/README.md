<p>
  This integration enables you to manage and edit files located on a remote web
  server via SSH using integration context as Single Source of Truth.
</p>

<p>
    This integration requires root access in order to execute ssh commands. 
    If you've configured the server to run Docker images with a non-root internal user make sure to exclude the demisto/openssh Docker image as documented <a href="https://docs.paloaltonetworks.com/cortex/cortex-xsoar/5-5/cortex-xsoar-admin/docker/docker-hardening-guide/run-docker-with-non-root-internal-users.html"> here </a>
</p>

<h2>Palo Alto Networks PAN-OS EDL Management Playbook</h2>
<p>PAN-OS EDL Setup</p>
<h2>Use Cases</h2>
<ul>
  <li>
    Manage blacklists and whitelists in the web-server in a dynamic manner to
    control the blacklists in PAN-OS.
  </li>
</ul>
<h2>Detailed Description</h2>
<p>
  To use the Palo Alto Networks PAN-OS EDL Management integration, you need to
  set up a remote web server.
</p>
<ol>
  <li>Set up a remote server with Apache.</li>
  <li>
    Generate a pair of SSH keys. Send the private key to the user’s home directory,
    into the “.ssh” folder in the Apache server.
  </li>
  <li>Append the public key to the “authorized_keys” file.</li>
  <li>Save the private SSH key in Demisto Credentials.</li>
  <li>
    To verify the location of the document root where the files are stored, run
    the following command.
    <ul>
      <li>
        <strong>CentOS</strong>: <code>"httpd -S"</code>
      </li>
      <li>
        <strong>Ubuntu</strong>: <code>apcahe2 -S"</code>
      </li>
    </ul>
  </li>
</ol>
<p>&nbsp;</p>
<h2>Configure Palo Alto Networks PAN-OS EDL on Demisto</h2>
<ol>
  <li>
    Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
    &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.
  </li>
  <li>Search for palo_alto_networks_pan_os_edl_management.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new
    integration instance.
    <ul>
      <li>
        <strong>Name</strong>: a textual name for the integration instance.
      </li>
      <li>
        <strong>Hostname or IP of server</strong>
      </li>
      <li>
        <strong>server port</strong>
      </li>
      <li>
        <strong>SSH credentials to server (username and certificate)</strong>
      </li>
      <li>
        <strong>SSH extra parameters (e.g., "-c ChaCha20")</strong>
      </li>
      <li>
        <strong>SCP extra parameters (e.g., "-c ChaCha20 -l 8000")</strong>
      </li>
      <li>
        <strong>Document root (e.g., var/www/html/files)</strong>
      </li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation,
  or in a playbook. After you successfully execute a command, a DBot message appears
  in the War Room with the command details.
</p>
<ol>
  <li>
    <a href="#pan-os-edl-get-external-file" target="_self">Display the contents of remote file(s) located in the War Room: pan-os-edl-get-external-file</a>
  </li>
  <li>
    <a href="#pan-os-edl-search-external-file" target="_self">Search for a string in a remote file: pan-os-edl-search-external-file</a>
  </li>
  <li>
    <a href="#pan-os-edl-update" target="_self">Update instance context, and override the path of the remote file: pan-os-edl-update</a>
  </li>
  <li>
    <a href="#pan-os-edl-update-from-external-file" target="_self">Update internal list data: pan-os-edl-update-from-external-file</a>
  </li>
  <li>
    <a href="#pan-os-edl-delete-external-file" target="_self">Delete a file from a remote server: pan-os-edl-delete-external-file</a>
  </li>
  <li>
    <a href="#pan-os-edl-print-internal-list" target="_self">Display internal list data in the War Room: pan-os-edl-print-internal-list</a>
  </li>
  <li>
    <a href="#pan-os-edl-dump-internal-list" target="_self">Dump (copies) instance context: pan-os-edl-dump-internal-list</a>
  </li>
  <li>
    <a href="#pan-os-edl-list-internal-lists" target="_self">Display instance context list names: pan-os-edl-list-internal-lists</a>
  </li>
  <li>
    <a href="#pan-os-edl-search-internal-list" target="_self">Search for a string in internal list: pan-os-edl-search-internal-list</a>
  </li>
  <li>
    <a href="#pan-os-edl-compare" target="_self">Compare internal list and external file contents: pan-os-edl-compare</a>
  </li>
  <li>
    <a href="#pan-os-edl-get-external-file-metadata" target="_self">Get metadata for an external file: pan-os-edl-get-external-file-metadata</a>
  </li>
  <li>
    <a href="#pan-os-edl-update-internal-list" target="_self">Update the instance context: pan-os-edl-update-internal-list</a>
  </li>
  <li>
    <a href="#pan-os-edl-update-external-file" target="_self">Update a remote file: pan-os-edl-update-external-file</a>
  </li>
</ol>
<h3 id="pan-os-edl-get-external-file">
  1.&nbsp;Display the contents of a remote file located in the War Room
</h3>
<hr>
<p>
  Displays the contents of the specified remote file located in the War Room.
</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-get-external-file</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:173.444px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:433.556px">
        <strong>Description</strong>
      </th>
      <th style="width:107px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:173.444px">file_path</td>
      <td style="width:433.556px">Unique path to the file on a remote server.</td>
      <td style="width:107px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-get-external-file file_path=kili1.txt</pre>
<h5>Human Readable Output</h5>
<h3>File Content:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>List</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>1.2.3.4</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h3 id="pan-os-edl-search-external-file">2. Search for a string in a remote file</h3>
<hr>
<p>Searches for a string in a remote file.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-search-external-file</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:177.444px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:429.556px">
        <strong>Description</strong>
      </th>
      <th style="width:107px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:177.444px">file_path</td>
      <td style="width:429.556px">Unique path to the file on a remote server.</td>
      <td style="width:107px">Required</td>
    </tr>
    <tr>
      <td style="width:177.444px">search_string</td>
      <td style="width:429.556px">String to search for in the remote file.</td>
      <td style="width:107px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-search-external-file file_path=kili1.txt search_string=1.0.0.39</pre>
<h5>Human Readable Output</h5>
<p>
  Search string was not found in the external file path given.
</p>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h3 id="pan-os-edl-update">
  3. Update instance context, and override the path of the remote file
</h3>
<hr>
<p>
  Updates the instance context with the specified list name and list items, and
  then overrides the path of the remote file with the internal list.
</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-update</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:144.778px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:492.222px">
        <strong>Description</strong>
      </th>
      <th style="width:77px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:144.778px">list_name</td>
      <td style="width:492.222px">
        List from the instance context with which to override the remote
        file.
      </td>
      <td style="width:77px">Required</td>
    </tr>
    <tr>
      <td style="width:144.778px">file_path</td>
      <td style="width:492.222px">Unique path to file.</td>
      <td style="width:77px">Required</td>
    </tr>
    <tr>
      <td style="width:144.778px">verbose</td>
      <td style="width:492.222px">
        Prints the updated remote file to the War Room. Default is "false".
      </td>
      <td style="width:77px">Optional</td>
    </tr>
    <tr>
      <td style="width:144.778px">list_items</td>
      <td style="width:492.222px">List items.</td>
      <td style="width:77px">Required</td>
    </tr>
    <tr>
      <td style="width:144.778px">add_or_remove</td>
      <td style="width:492.222px">
        Whether to add to or remove from the list. Default is "add".
      </td>
      <td style="width:77px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-update add_or_remove=add list_items=104.196.188.170 file_path=kili1.txt list_name=kili1</pre>
<h5>Human Readable Output</h5>
<p>
  Instance context updated successfully. External file updated successfully.
</p>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h3 id="pan-os-edl-update-from-external-file">4. Update internal list data</h3>
<hr>
<p>
  Updates internal list data with the contents of a remote file.
</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-update-from-external-file</code>
</p>
<h5>Input</h5>
<table style="width:744px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:139.333px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:501.667px">
        <strong>Description</strong>
      </th>
      <th style="width:73px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:139.333px">file_path</td>
      <td style="width:501.667px">Unique path to the file on a remote server.</td>
      <td style="width:73px">Required</td>
    </tr>
    <tr>
      <td style="width:139.333px">list_name</td>
      <td style="width:501.667px">List name.</td>
      <td style="width:73px">Required</td>
    </tr>
    <tr>
      <td style="width:139.333px">type</td>
      <td style="width:501.667px">
        Update type. "Merge" adds non-duplicate values, "Override" deletes
        existing data in the internal list. Default is "merge".
      </td>
      <td style="width:73px">Required</td>
    </tr>
    <tr>
      <td style="width:139.333px">verbose</td>
      <td style="width:501.667px">
        Prints the updated internal list to the War Room. Default is "false".
      </td>
      <td style="width:73px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-update-from-external-file file_path=kili1.txt list_name=kili1_copy type=override verbose=true</pre>
<h5>Human Readable Output</h5>
<h3>List items:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>kili1_copy</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>104.196.188.170</td>
    </tr>
    <tr>
      <td>176.10.104.240</td>
    </tr>
    <tr>
      <td>10.1.1.1</td>
    </tr>
    <tr>
      <td>10.1.1.0</td>
    </tr>
    <tr>
      <td>5.6.7.8</td>
    </tr>
    <tr>
      <td>5.79.86.16</td>
    </tr>
    <tr>
      <td>12.12.12.12</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h3 id="pan-os-edl-delete-external-file">5. Delete a file from a remote server</h3>
<hr>
<p>Deletes a file from a remote server.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-delete-external-file</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:188.444px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:418.556px">
        <strong>Description</strong>
      </th>
      <th style="width:107px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:188.444px">file_path</td>
      <td style="width:418.556px">Unique path to the file on a remote server.</td>
      <td style="width:107px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-delete-external-file file_path=kili1_copy.txt</pre>
<h5>Human Readable Output</h5>
<p>File deleted successfully.</p>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h3 id="pan-os-edl-print-internal-list">6. Display&nbsp;internal list data in the War Room</h3>
<hr>
<p>Displays internal list data in the War Room.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-print-internal-list</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:290.889px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:242.111px">
        <strong>Description</strong>
      </th>
      <th style="width:182px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:290.889px">list_name</td>
      <td style="width:242.111px">List name.</td>
      <td style="width:182px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-print-internal-list list_name=kili1</pre>
<h5>Human Readable Output</h5>
<h3>List items:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>kili1</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>104.196.188.170</td>
    </tr>
    <tr>
      <td>176.10.104.240</td>
    </tr>
    <tr>
      <td>10.1.1.1</td>
    </tr>
    <tr>
      <td>10.1.1.0</td>
    </tr>
    <tr>
      <td>5.6.7.8</td>
    </tr>
    <tr>
      <td>5.79.86.16</td>
    </tr>
    <tr>
      <td>12.12.12.12</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h3 id="pan-os-edl-dump-internal-list">7. Dump (copies) instance context</h3>
<hr>
<p>
  Dumps (copies) instance context to either the incident context or a file.
</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-dump-internal-list</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:190.667px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:407.333px">
        <strong>Description</strong>
      </th>
      <th style="width:116px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:190.667px">destination</td>
      <td style="width:407.333px">List data destination. Default is "file".</td>
      <td style="width:116px">Required</td>
    </tr>
    <tr>
      <td style="width:190.667px">list_name</td>
      <td style="width:407.333px">List name.</td>
      <td style="width:116px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:283.778px">
        <strong>Path</strong>
      </th>
      <th style="width:88.2222px">
        <strong>Type</strong>
      </th>
      <th style="width:342px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:283.778px">PANOSEDL.ListItems</td>
      <td style="width:88.2222px">string</td>
      <td style="width:342px">Items of the internal list.</td>
    </tr>
    <tr>
      <td style="width:283.778px">PANOSEDL.ListName</td>
      <td style="width:88.2222px">string</td>
      <td style="width:342px">Name of the internal list.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-dump-internal-list destination=file list_name=kili1</pre>
<h5>Human Readable Output</h5>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h3 id="pan-os-edl-list-internal-lists">8. Display instance context list names.</h3>
<hr>
<p>Displays instance context list names.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-list-internal-lists</code>
</p>
<h5>Input</h5>
<p>There are no input arguments for this command.</p>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-list-internal-lists</pre>
<h5>Human Readable Output</h5>
<h3>Instance context Lists:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>List names</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>kili1</td>
    </tr>
    <tr>
      <td>kili1_copy</td>
    </tr>
    <tr>
      <td>kili2</td>
    </tr>
    <tr>
      <td>test_playbook_list4</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h3 id="pan-os-edl-search-internal-list">9. Search for a string in internal list</h3>
<hr>
<p>Search for a string in internal list.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-search-internal-list</code>
</p>
<h5>Input</h5>
<table style="width:746px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:207.444px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:392.556px">
        <strong>Description</strong>
      </th>
      <th style="width:114px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:207.444px">list_name</td>
      <td style="width:392.556px">Name of list.</td>
      <td style="width:114px">Required</td>
    </tr>
    <tr>
      <td style="width:207.444px">search_string</td>
      <td style="width:392.556px">String to search for in the remote file.</td>
      <td style="width:114px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-search-internal-list list_name=kili1 search_string=216.3.128.82</pre>
<h5>Human Readable Output</h5>
<p>Search string is in internal list.</p>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h3 id="pan-os-edl-compare">10. Compare internal list and external file contents</h3>
<hr>
<p>Compares internal list and external file contents.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-compare</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:177.444px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:429.556px">
        <strong>Description</strong>
      </th>
      <th style="width:107px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:177.444px">list_name</td>
      <td style="width:429.556px">List name.</td>
      <td style="width:107px">Required</td>
    </tr>
    <tr>
      <td style="width:177.444px">file_path</td>
      <td style="width:429.556px">Unique path to the file on a remote server.</td>
      <td style="width:107px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-compare file_path=kili1.txt list_name=kili1</pre>
<h5>Human Readable Output</h5>
<p>Internal list and external file have the same values.</p>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h3 id="pan-os-edl-get-external-file-metadata">11. Get metadata for an external file</h3>
<hr>
<p>Gets metadata for an external file.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-get-external-file-metadata</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:192.444px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:414.556px">
        <strong>Description</strong>
      </th>
      <th style="width:107px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:192.444px">file_path</td>
      <td style="width:414.556px">Unique path to the file on a remote server.</td>
      <td style="width:107px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:266.778px">
        <strong>Path</strong>
      </th>
      <th style="width:86.2222px">
        <strong>Type</strong>
      </th>
      <th style="width:361px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:266.778px">PANOSEDL.FileName</td>
      <td style="width:86.2222px">String</td>
      <td style="width:361px">Name of the external file.</td>
    </tr>
    <tr>
      <td style="width:266.778px">PANOSEDL.Size</td>
      <td style="width:86.2222px">Number</td>
      <td style="width:361px">File size.</td>
    </tr>
    <tr>
      <td style="width:266.778px">PANOSEDL.NumberOfLines</td>
      <td style="width:86.2222px">Number</td>
      <td style="width:361px">Number of lines.</td>
    </tr>
    <tr>
      <td style="width:266.778px">PANOSEDL.LastModified</td>
      <td style="width:86.2222px">String</td>
      <td style="width:361px">Date that the file was last modified.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-get-external-file-metadata file_path=kili1.txt</pre>
<h5>Context Example</h5>
<pre>{
    "PANOSEDL": {
        "FileName": "kili1.txt",
        "LastModified": "2019-12-03 10:04:56.391849212",
        "NumberOfLines": 7,
        "Size": 67
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>File metadata:</h3>
<table style="width:739px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:92px">
        <strong>FileName</strong>
      </th>
      <th style="width:39px">
        <strong>Size</strong>
      </th>
      <th style="width:149px">
        <strong>NumberOfLines</strong>
      </th>
      <th style="width:148.556px">
        <strong>LastModified</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:92px">kili1.txt</td>
      <td style="width:39px">67</td>
      <td style="width:149px">7</td>
      <td style="width:273.444px">2019-12-03 10:04:56.391849212</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<!-- remove the following comments to manually add an image: -->
<p>&nbsp;</p>
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
<h3 id="pan-os-edl-update-internal-list">12.&nbsp;Update the instance context</h3>
<hr>
<p>
  Updates the instance context with the specified list name and list items.
</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-update-internal-list</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:147.667px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:493.333px">
        <strong>Description</strong>
      </th>
      <th style="width:73px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:147.667px">list_name</td>
      <td style="width:493.333px">The list from the instance context to update.</td>
      <td style="width:73px">Required</td>
    </tr>
    <tr>
      <td style="width:147.667px">list_items</td>
      <td style="width:493.333px">An array of list items.</td>
      <td style="width:73px">Required</td>
    </tr>
    <tr>
      <td style="width:147.667px">verbose</td>
      <td style="width:493.333px">
        Whether to print the updated remote file to the War Room. Can be
        "true" or "false". Default is "false".
      </td>
      <td style="width:73px">Optional</td>
    </tr>
    <tr>
      <td style="width:147.667px">add_or_remove</td>
      <td style="width:493.333px">
        Whether to add to, or remove from the list. Can be "add" or "remove".
        Default is "add".
      </td>
      <td style="width:73px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-update-internal-list add_or_remove=add list_items=19.12.13.11 list_name=kili1</pre>
<h5>Human Readable Output</h5>
<p>Instance context updated successfully.</p>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h3 id="pan-os-edl-update-external-file">13.&nbsp;Update a remote file</h3>
<hr>
<p>
  Updates a remote file with the contents of an internal list.
</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-update-external-file</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:141.778px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:499.222px">
        <strong>Description</strong>
      </th>
      <th style="width:73px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:141.778px">file_path</td>
      <td style="width:499.222px">Unique path to the file on a remote server.</td>
      <td style="width:73px">Required</td>
    </tr>
    <tr>
      <td style="width:141.778px">list_name</td>
      <td style="width:499.222px">List name.</td>
      <td style="width:73px">Required</td>
    </tr>
    <tr>
      <td style="width:141.778px">verbose</td>
      <td style="width:499.222px">
        Whether to add to, or remove from the list. Can be "add" or "remove".
        Default is "add".
      </td>
      <td style="width:73px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!pan-os-edl-update-external-file file_path=kili1.txt list_name=kili1 verbose=false</pre>
<h5>Human Readable Output</h5>
<p>External file updated successfully.</p>
<p>
  <!-- remove the following comments to manually add an image: -->
   
  <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

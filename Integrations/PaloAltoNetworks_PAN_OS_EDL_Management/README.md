<p>
This integration enables you to manage and edit files located on a remote web server via SSH using integration context as Single Source of Truth.
</p>
<h2>Palo Alto Networks PAN-OS EDL Management Playbook</h2>
<p>PAN-OS EDL Setup</p>
<h2>Use Cases</h2>
<ul>
<li>Manage blcklists and whitelists in the web-server in a dynamic manner to control the blocklists in PAN-OS.</li>
</ul><h2>Detailed Description</h2>
<ul>
<li> Set Up a Remote Web Server</li>
<li> To use the Palo Alto Networks PAN-OS EDL Management integration, you need to set up a remote web server.</li>
<li> 1. Set up a remote server with Apache.</li>
<li> 2. Generate a pair of SSH keys. Send the private key into the user’s home directory, into “.ssh” folder in the Apache server. </li>
<li>    Append it to the “authorized_keys” file.</li>
<li> 3. Save the private SSH key in Demisto Credentials.</li>
<li> 4. To verify the location of the document root where the files are stored, run the following command.</li>
<li>   - **CentOS**: `"httpd -S"` </li>
<li>   - **Ubuntu**: `apcahe2 -S"`</li>
</ul><h2>Fetch Incidents</h2>
<p>Populate this section with Fetch incidents data</p>
<h2>Configure palo_alto_networks_pan_os_edl_management on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for palo_alto_networks_pan_os_edl_management.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Hostname or IP of server</strong></li>
   <li><strong>server port</strong></li>
   <li><strong>SSH credentials to server (username and certificate)</strong></li>
   <li><strong>SSH extra parameters (e.g., "-c ChaCha20")</strong></li>
   <li><strong>SCP extra parameters (e.g., "-c ChaCha20 -l 8000")</strong></li>
   <li><strong>Document root (e.g., var/www/html/files)</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li><a href="#pan-os-edl-get-external-file" target="_self">Displays the contents of the specified remote file located in the War Room: pan-os-edl-get-external-file</a></li>
  <li><a href="#pan-os-edl-search-external-file" target="_self">Searches for a string in a remote file: pan-os-edl-search-external-file</a></li>
  <li><a href="#pan-os-edl-update" target="_self">Updates the instance context with the specified list name and list items, and then overrides the path of the remote file with the internal list: pan-os-edl-update</a></li>
  <li><a href="#pan-os-edl-update-from-external-file" target="_self">Updates internal list data with the contents of a remote file: pan-os-edl-update-from-external-file</a></li>
  <li><a href="#pan-os-edl-delete-external-file" target="_self">Deletes a file from a remote server: pan-os-edl-delete-external-file</a></li>
  <li><a href="#pan-os-edl-print-internal-list" target="_self">Displays internal list data in the War Room: pan-os-edl-print-internal-list</a></li>
  <li><a href="#pan-os-edl-dump-internal-list" target="_self">Dumps (copies) instance context to either the incident context or a file: pan-os-edl-dump-internal-list</a></li>
  <li><a href="#pan-os-edl-list-internal-lists" target="_self">Displays instance context list names: pan-os-edl-list-internal-lists</a></li>
  <li><a href="#pan-os-edl-search-internal-list" target="_self">Search for a string in internal list: pan-os-edl-search-internal-list</a></li>
  <li><a href="#pan-os-edl-compare" target="_self">Compares internal list and external file contents: pan-os-edl-compare</a></li>
  <li><a href="#pan-os-edl-get-external-file-metadata" target="_self">Gets metadata for an external file: pan-os-edl-get-external-file-metadata</a></li>
  <li><a href="#pan-os-edl-update-internal-list" target="_self">Updates the instance context with the specified list name and list items: pan-os-edl-update-internal-list</a></li>
  <li><a href="#pan-os-edl-update-external-file" target="_self">Updates a remote file with the contents of an internal list: pan-os-edl-update-external-file</a></li>
</ol>
<h3 id="pan-os-edl-get-external-file">1. pan-os-edl-get-external-file</h3>
<hr>
<p>Displays the contents of the specified remote file located in the War Room.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-get-external-file</code>
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
      <td>file_path</td>
      <td>Unique path to the file on a remote server.</td>
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
  <code>!pan-os-edl-get-external-file file_path=kili1.txt</code>
</p>

<h5>Human Readable Output</h5>
<p>
<h3>File Content:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>List</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 1.2.3.4 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-search-external-file">2. pan-os-edl-search-external-file</h3>
<hr>
<p>Searches for a string in a remote file.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-search-external-file</code>
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
      <td>file_path</td>
      <td>Unique path to the file on a remote server.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>search_string</td>
      <td>String to search for in the remote file.</td>
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
  <code>!pan-os-edl-search-external-file file_path=kili1.txt search_string=1.0.0.39</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Search string was not found in the external file path given.
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-update">3. pan-os-edl-update</h3>
<hr>
<p>Updates the instance context with the specified list name and list items, and then overrides the path of the remote file with the internal list.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-update</code>
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
      <td>list_name</td>
      <td>List from the instance context with which to override the remote file.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>file_path</td>
      <td>Unique path to file</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>verbose</td>
      <td>Prints the updated remote file to the War Room. Default is "false".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>list_items</td>
      <td>List items.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>add_or_remove</td>
      <td>Whether to add to, or remove from the list. Default is "add".</td>
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
  <code>!pan-os-edl-update add_or_remove=add list_items=104.196.188.170 file_path=kili1.txt list_name=kili1</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Instance context updated successfully.External file updated successfully.
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-update-from-external-file">4. pan-os-edl-update-from-external-file</h3>
<hr>
<p>Updates internal list data with the contents of a remote file.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-update-from-external-file</code>
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
      <td>file_path</td>
      <td>Unique path to the file on a remote server.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>list_name</td>
      <td>List name.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>type</td>
      <td>Update type. "Merge" adds non-duplicate values, "Override" deletes existing data in the internal list. Default is "merge".</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>verbose</td>
      <td>Prints the updated internal list to the War Room. Default is "false".</td>
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
  <code>!pan-os-edl-update-from-external-file file_path=kili1.txt list_name=kili1_copy type=override verbose=true</code>
</p>

<h5>Human Readable Output</h5>
<p>
<h3>List items:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>kili1_copy</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 104.196.188.170 </td>
    </tr>
    <tr>
      <td> 176.10.104.240 </td>
    </tr>
    <tr>
      <td> 10.1.1.1 </td>
    </tr>
    <tr>
      <td> 10.1.1.0 </td>
    </tr>
    <tr>
      <td> 5.6.7.8 </td>
    </tr>
    <tr>
      <td> 5.79.86.16 </td>
    </tr>
    <tr>
      <td> 12.12.12.12 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-delete-external-file">5. pan-os-edl-delete-external-file</h3>
<hr>
<p>Deletes a file from a remote server.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-delete-external-file</code>
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
      <td>file_path</td>
      <td>Unique path to the file on a remote server.</td>
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
  <code>!pan-os-edl-delete-external-file file_path=kili1_copy.txt</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
File deleted successfully
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-print-internal-list">6. pan-os-edl-print-internal-list</h3>
<hr>
<p>Displays internal list data in the War Room.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-print-internal-list</code>
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
      <td>list_name</td>
      <td>List name.</td>
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
  <code>!pan-os-edl-print-internal-list list_name=kili1</code>
</p>

<h5>Human Readable Output</h5>
<p>
<h3>List items:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>kili1</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 104.196.188.170 </td>
    </tr>
    <tr>
      <td> 176.10.104.240 </td>
    </tr>
    <tr>
      <td> 10.1.1.1 </td>
    </tr>
    <tr>
      <td> 10.1.1.0 </td>
    </tr>
    <tr>
      <td> 5.6.7.8 </td>
    </tr>
    <tr>
      <td> 5.79.86.16 </td>
    </tr>
    <tr>
      <td> 12.12.12.12 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-dump-internal-list">7. pan-os-edl-dump-internal-list</h3>
<hr>
<p>Dumps (copies) instance context to either the incident context or a file.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-dump-internal-list</code>
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
      <td>destination</td>
      <td>List data destination. Default is "file".</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>list_name</td>
      <td>List name.</td>
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
      <td>PANOSEDL.ListItems</td>
      <td>string</td>
      <td>Items of the internal list.</td>
    </tr>
    <tr>
      <td>PANOSEDL.ListName</td>
      <td>string</td>
      <td>Name of the internal list.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!pan-os-edl-dump-internal-list destination=file list_name=kili1</code>
</p>

<h5>Human Readable Output</h5>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-list-internal-lists">8. pan-os-edl-list-internal-lists</h3>
<hr>
<p>Displays instance context list names.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-list-internal-lists</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.
<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!pan-os-edl-list-internal-lists</code>
</p>

<h5>Human Readable Output</h5>
<p>
<h3>Instance context Lists:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>List names</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> kili1 </td>
    </tr>
    <tr>
      <td> kili1_copy </td>
    </tr>
    <tr>
      <td> kili2 </td>
    </tr>
    <tr>
      <td> test_playbook_list4 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-search-internal-list">9. pan-os-edl-search-internal-list</h3>
<hr>
<p>Search for a string in internal list.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-search-internal-list</code>
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
      <td>list_name</td>
      <td>Name of list</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>search_string</td>
      <td>String to search for in the remote file.</td>
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
  <code>!pan-os-edl-search-internal-list list_name=kili1 search_string=216.3.128.82</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Search string is in internal list.
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-compare">10. pan-os-edl-compare</h3>
<hr>
<p>Compares internal list and external file contents.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-compare</code>
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
      <td>list_name</td>
      <td>List name.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>file_path</td>
      <td>Unique path to the file on a remote server.</td>
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
  <code>!pan-os-edl-compare file_path=kili1.txt list_name=kili1</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Internal list and external file have the same values.
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-get-external-file-metadata">11. pan-os-edl-get-external-file-metadata</h3>
<hr>
<p>Gets metadata for an external file.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-get-external-file-metadata</code>
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
      <td>file_path</td>
      <td>Unique path to the file on a remote server.</td>
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
      <td>PANOSEDL.FileName</td>
      <td>String</td>
      <td>Name of the external file.</td>
    </tr>
    <tr>
      <td>PANOSEDL.Size</td>
      <td>Number</td>
      <td>File size.</td>
    </tr>
    <tr>
      <td>PANOSEDL.NumberOfLines</td>
      <td>Number</td>
      <td>Number of lines.</td>
    </tr>
    <tr>
      <td>PANOSEDL.LastModified</td>
      <td>String</td>
      <td>Date that the file was last modified.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!pan-os-edl-get-external-file-metadata file_path=kili1.txt</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "PANOSEDL": {
        "FileName": "kili1.txt",
        "LastModified": "2019-12-03 10:04:56.391849212",
        "NumberOfLines": 7,
        "Size": 67
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>File metadata:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>FileName</strong></th>
      <th><strong>Size</strong></th>
      <th><strong>NumberOfLines</strong></th>
      <th><strong>LastModified</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> kili1.txt </td>
      <td> 67 </td>
      <td> 7 </td>
      <td> 2019-12-03 10:04:56.391849212 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-update-internal-list">12. pan-os-edl-update-internal-list</h3>
<hr>
<p>Updates the instance context with the specified list name and list items.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-update-internal-list</code>
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
      <td>list_name</td>
      <td>The list from the instance context to update.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>list_items</td>
      <td>An array of list items.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>verbose</td>
      <td>Whether to print the updated remote file to the War Room. Can ve "true" or "false". Default is "false".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>add_or_remove</td>
      <td>Whether to add to, or remove from the list. Can be "add" or "remove". Default is "add".</td>
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
  <code>!pan-os-edl-update-internal-list add_or_remove=add list_items=19.12.13.11 list_name=kili1</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Instance context updated successfully.
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-edl-update-external-file">13. pan-os-edl-update-external-file</h3>
<hr>
<p>Updates a remote file with the contents of an internal list.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-edl-update-external-file</code>
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
      <td>file_path</td>
      <td>Unique path to the file on a remote server.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>list_name</td>
      <td>List name.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>verbose</td>
      <td>Whether to add to, or remove from the list. Can be "add" or "remove". Default is "add".</td>
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
  <code>!pan-os-edl-update-external-file file_path=kili1.txt list_name=kili1 verbose=false</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
External file updated successfully.
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h2>Additional Information</h2><h2>Known Limitations</h2><h2>Troubleshooting</h2>
<p>
Serves a URL filtering list to be fetched by proxies
</p>

<h2>Use Cases</h2>
<ul>
<li>Serves a URL filtering list to be fetched by proxy servers.</li>
</ul><h2>Detailed Description</h2>
<ul>
<li>Serves a URL filtering list to be fetched by proxy servers.</li>
<li>Enable this integration then point your proxy to fetch the filter file from http://ip.of.demisto.host:port/</li>
</ul>

<h2>Configure Proxy URL Filter Server on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for <strong>Proxy URL Filter Server</strong></li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Filter Format</strong> - by default set to <strong>Symantec ProxySG</strong></li>
   <li><strong>Long running instance</strong></li>
   <li><strong>Port mapping ([port] or [host port]:[docker port])</strong></li>
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
  <li><a href="#proxy-filter-add-url" target="_self">Add a URL to the proxy filter list: proxy-filter-add-url</a></li>
  <li><a href="#proxy-filter-del-url" target="_self">Remove a URL from the proxy filter list: proxy-filter-del-url</a></li>
</ol>
<h3 id="proxy-filter-add-url">1. proxy-filter-add-url</h3>
<hr>
<p>Add a URL to the proxy filter list</p>
<h5>Base Command</h5>
<p>
  <code>proxy-filter-add-url</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
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
      <td>url</td>
      <td>URL to block</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>category</td>
      <td>Category</td>
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
  <code>!proxy-filter-add-url url="http://woo.demisto.com" category="whitelist"</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Done
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="proxy-filter-del-url">2. proxy-filter-del-url</h3>
<hr>
<p>Remove a URL from the proxy filter list</p>
<h5>Base Command</h5>
<p>
  <code>proxy-filter-del-url</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
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
      <td>url</td>
      <td>URL to remove</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>category</td>
      <td>Category</td>
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
  <code>!proxy-filter-del-url url="http://woo.demisto.com" category="whitelist"</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Done
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h2>Additional Information</h2>
<p>
In order to test that the integration serves properly a URL list, you can run:
<br><strong>!http method=GET url=http://0.0.0.0:7000</strong> in Demisto
<br><strong>curl http://0.0.0.0:7000</strong> in the terminal

<strong>Note:</strong> port 7000 is just an example, it depend on the port you configured in the instance.
</p>
<h2>Known Limitations</h2>
<p>
Avoid using proxy-filter-add-url and proxy-filter-del-url in parallel, multiple cammand calls can override other. 
These commands are better used in jobs, when each interval playbook executed and populates the URL list. 

</p>
<h2>Troubleshooting</h2>
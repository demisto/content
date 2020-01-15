<h2>Overview</h2>
<p>
  This integration provides the ability to import <strong>Palo Alto Networks - Prisma Cloud Compute</strong> alerts into Demisto.
</p>
<h2>Use Cases</h2>
<ul>
<li>Manage Prisma Cloud Compute alerts in Demisto, analyze, assign tasks, open tickets on other platforms, create playbooks, and much more.</li>
</ul>
<p>Before you can use the Prisma Cloud Compute integration on Demisto, there are several configuration steps required on the Prisma Cloud Platform.</p>
<h2>Prerequisites</h2>
<h3>Configure Demisto alert profile in Prisma Cloud Compute:</h3>
<ul>
<li>Login to your Prisma Cloud Compute console.</li>
<li>Navigate to Manage -&gt; Alerts.</li>
<li>Create a new alert profile by clicking the &quot;Add Profile&quot; button.</li>
<li>Choose &quot;Demisto&quot; from the provider list on the left and choose what would you like Demisto to be alerted about from the alert triggers on the right.</li>
<li>Click &quot;Save&quot; to save the alert profile.</li>
</ul>
<h2>Configure Prisma Cloud Compute on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Prisma Cloud Compute.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: A textual name for the integration instance.</li>
      <li><strong>Fetches incidents</strong>: Check if you wish this integration instance would fetch alerts from Prisma Cloud Compute.</li>
      <li><strong>Prisma Cloud Compute Full URL</strong>: The URL address to fetch alerts from Prisma Cloud Compute, copy the address from the alert profile created in the previous step on Prisma Cloud Compute.</li>
      <li><strong>Trust any certificate (not secure)</strong>: Check to skip verification of the CA certificate (not recommended).</li>
      <li><strong>Use system proxy settings</strong>: Check to use the system proxy settings.</li>
      <li><strong>Credentials</strong>: Prisma Cloud Compute login credentials.</li>
      <li><strong>Prisma Cloud Compute CA Certificate</strong>: CA Certificate used by Prismae Cloud Compute, copy the certificate from the alert profile created in the previous step on Prisma Cloud Compute.</li>
    </ul>
  </li>
</ol>
<ol start="4">
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Troubleshooting</h2>
<p>If any alerts are missing on Demisto, check the integration status on the integration page:</p>
<img alt="" src="https://user-images.githubusercontent.com/49071222/72086124-18b0fe00-330f-11ea-894b-6b2f9f0528fd.png"/>
<br>
<span>If you're having further issues, contact us at <a href="mailto:support@demisto.com">support@demisto.com</a> and attach the server logs.</span>

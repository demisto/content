<p>
Use the Proofpoint Targeted Attack Protection (TAP) integration to protect against and provide additional visibility into phishing and other malicious email attacks.

This integration was integrated and tested with version 8.15.0 of Proofpoint TAP
</p>
</ul><h2>Detailed Description</h2>
<ul>
<li>## Configure an API account</li>
<li>To configure an instance of the integration in Demisto, you need to supply your Service Principal and Service Secret. When you configure the integration instance, enter the Service Principal in the Service Principal field, and the Service Secret in the Password field.</li>
<li>1. Log in to your Proofpoint TAP environment.</li>
<li>2. Navigate to **Connect Applications > Service Credentials**.</li>
</ul><h2>Fetch Incidents</h2>
<p>Populate this section with Fetch incidents data</p>
<h2>Configure Proofpoint TAP v2 on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Proofpoint TAP v2.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Server URL (e.g., https://tap-api-v2.proofpoint.com)</strong></li>
   <li><strong>Service Principal (the Password refers to Secret)</strong></li>
   <li><strong>API Version</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Use system proxy settings</strong></li>
   <li><strong>A string specifying which threat type to return. If empty, all threat types are returned. Can be "url", "attachment", or "messageText".</strong></li>
   <li><strong>A string specifying which threat statuses to return. If empty, will return "active" and "cleared" threats.</strong></li>
   <li><strong>Events to fetch</strong></li>
   <li><strong>First fetch time range (<number> <time unit>, e.g., 1 hour, 30 minutes) - Proofpoint supports maximum 1 hour fetch back</strong></li>
   <li><strong>Fetch incidents</strong></li>
   <li><strong>Incident type</strong></li>
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
  <li>proofpoint-get-events: proofpoint-get-events</li>
  <li>proofpoint-get-forensics: proofpoint-get-forensics</li>
</ol>
<h3>1. proofpoint-get-events</h3>
<hr>
<p>Fetches events for all clicks and messages relating to known threats within the specified time period. Details as per clicks/blocked.</p>
<h5>Base Command</h5>
<p>
  <code>proofpoint-get-events</code>
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
      <td>interval</td>
      <td>A string containing an ISO8601-formatted interval. If this interval overlaps with previous requests for data, records from the previous request might be duplicated. The minimum interval is thirty seconds. The maximum interval is one hour. Examples:  2016-05-01T12:00:00Z/2016-05-01T13:00:00Z - an hour interval, beginning at noon UTC on 05-01-2016 PT30M/2016-05-01T12:30:00Z - the thirty minutes beginning at noon UTC on 05-01-2016 and ending at 12:30pm UTC 2016-05-01T05:00:00-0700/PT30M - the same interval as above, but using -0700 as the time zone</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>threatType</td>
      <td>A string specifying which threat type to return. If empty, all threat types are returned. The following values are accepted: url,attachment, messageText</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>threatStatus</td>
      <td>A string specifying which threat statuses to return. If empty, active and cleared threats are returned. Can be "active", "cleared", "falsePositive".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>sinceTime</td>
      <td>A string containing an ISO8601 date. It represents the start of the data retrieval period. The end of the period is determined by the current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result. Example: 2016-05-01T12:00:00Z</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>sinceSeconds</td>
      <td>An integer representing a time window (in seconds) from the current API server time. The start of the window is the current API server time, rounded to the nearest minute, less the number of seconds provided. The end of the window is the current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>eventTypes</td>
      <td>Event types to return.</td>
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
      <td>Proofpoint.MessagesDelivered.GUID</td>
      <td>String</td>
      <td>The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.QID</td>
      <td>String</td>
      <td>The queue ID of the message within PPS. It can be used to identify the message in PPS and is not unique.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.ccAddresses</td>
      <td>String</td>
      <td>A list of email addresses contained within the CC: header, excluding friendly names.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.clusterId</td>
      <td>String</td>
      <td>The name of the PPS cluster which processed the message.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.fromAddress</td>
      <td>String</td>
      <td>The email address contained in the From: header, excluding friendly name.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.headerCC</td>
      <td>String</td>
      <td>headerCC</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.headerFrom</td>
      <td>String</td>
      <td>The full content of the From: header, including any friendly name.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.headerReplyTo</td>
      <td>String</td>
      <td>If present, the full content of the Reply-To: header, including any friendly names.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.impostorScore</td>
      <td>Number</td>
      <td>The impostor score of the message. Higher scores indicate higher certainty.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.malwareScore</td>
      <td>Number</td>
      <td>The malware score of the message. Higher scores indicate higher certainty.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.messageId</td>
      <td>String</td>
      <td>Message-ID extracted from the headers of the email message. It can be used to look up the associated message in PPS and is not unique.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.threatsInfoMap.threat</td>
      <td>String</td>
      <td>The artifact which was condemned by Proofpoint. The malicious URL, hash of the attachment threat, or email address of the impostor sender.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.threatsInfoMap.threatId</td>
      <td>String</td>
      <td>The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.threatsInfoMap.threatStatus</td>
      <td>String</td>
      <td>The current state of the threat (active, expired, falsepositive, cleared).</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.threatsInfoMap.threatTime</td>
      <td>Date</td>
      <td>Proofpoint assigned the threatStatus at this time (ISO8601 format).</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.threatsInfoMap.threatType</td>
      <td>String</td>
      <td>Whether the threat was an attachment, URL, or message type.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.threatsInfoMap.threatUrl</td>
      <td>String</td>
      <td>A link to the entry about the threat on the TAP Dashboard.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.messageTime</td>
      <td>Date</td>
      <td>When the message was delivered to the user or quarantined by PPS.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.messageTime</td>
      <td>String</td>
      <td>The list of PPS modules which processed the message.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.modulesRun</td>
      <td>String</td>
      <td>The list of PPS modules which processed the message.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.phishScore</td>
      <td>Number</td>
      <td>The phish score of the message. Higher scores indicate higher certainty.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.policyRoutes</td>
      <td>String</td>
      <td>The policy routes that the message matched during processing by PPS.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.quarantineFolder</td>
      <td>String</td>
      <td>The name of the folder which contains the quarantined message. This appears only for messagesBlocked.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.quarantineRule</td>
      <td>String</td>
      <td>The name of the rule which quarantined the message. This appears only for messagesBlocked events.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.recipient</td>
      <td>String</td>
      <td>A list containing the email addresses of the recipients.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.replyToAddress</td>
      <td>String</td>
      <td>The email address contained in the Reply-To: header, excluding friendly name.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.sender</td>
      <td>String</td>
      <td>The email address of the SMTP (envelope) sender. The user-part is hashed. The domain-part is cleartext.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.senderIP</td>
      <td>String</td>
      <td>The IP address of the sender.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.spamScore</td>
      <td>Number</td>
      <td>The spam score of the message. Higher scores indicate higher certainty.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesDelivered.subject</td>
      <td>String</td>
      <td>The subject line of the message, if available.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.GUID</td>
      <td>String</td>
      <td>The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.QID</td>
      <td>String</td>
      <td>The queue ID of the message within PPS. It can be used to identify the message in PPS and is not unique.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.ccAddresses</td>
      <td>String</td>
      <td>A list of email addresses contained within the CC: header, excluding friendly names.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.clusterId</td>
      <td>String</td>
      <td>The name of the PPS cluster which processed the message.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.fromAddress</td>
      <td>String</td>
      <td>The email address contained in the From: header, excluding friendly name.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.headerCC</td>
      <td>String</td>
      <td>headerCC</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.headerFrom</td>
      <td>String</td>
      <td>The full content of the From: header, including any friendly name.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.headerReplyTo</td>
      <td>String</td>
      <td>If present, the full content of the Reply-To: header, including any friendly names.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.impostorScore</td>
      <td>Number</td>
      <td>The impostor score of the message. Higher scores indicate higher certainty.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.malwareScore</td>
      <td>Number</td>
      <td>The malware score of the message. Higher scores indicate higher certainty.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.messageId</td>
      <td>String</td>
      <td>Message-ID extracted from the headers of the email message. It can be used to look up the associated message in PPS and is not unique.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.threatsInfoMap.threat</td>
      <td>String</td>
      <td>The artifact which was condemned by Proofpoint. The malicious URL, hash of the attachment threat, or email address of the impostor sender.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.threatsInfoMap.threatId</td>
      <td>String</td>
      <td>The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.threatsInfoMap.threatStatus</td>
      <td>String</td>
      <td>The current state of the threat (active, expired, falsepositive, cleared).</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.threatsInfoMap.threatTime</td>
      <td>Date</td>
      <td>Proofpoint assigned the threatStatus at this time (ISO8601 format).</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.threatsInfoMap.threatType</td>
      <td>String</td>
      <td>Whether the threat was an attachment, URL, or message type.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.threatsInfoMap.threatUrl</td>
      <td>String</td>
      <td>A link to the entry about the threat on the TAP Dashboard.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.messageTime</td>
      <td>Date</td>
      <td>When the message was Blocked to the user or quarantined by PPS.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.messageTime</td>
      <td>String</td>
      <td>The list of PPS modules which processed the message.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.modulesRun</td>
      <td>String</td>
      <td>The list of PPS modules which processed the message.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.phishScore</td>
      <td>Number</td>
      <td>The phish score of the message. Higher scores indicate higher certainty.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.policyRoutes</td>
      <td>String</td>
      <td>The policy routes that the message matched during processing by PPS.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.quarantineFolder</td>
      <td>String</td>
      <td>The name of the folder which contains the quarantined message. This appears only for messagesBlocked.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.quarantineRule</td>
      <td>String</td>
      <td>The name of the rule which quarantined the message. This appears only for messagesBlocked events.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.recipient</td>
      <td>String</td>
      <td>A list containing the email addresses of the recipients.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.replyToAddress</td>
      <td>String</td>
      <td>The email address contained in the Reply-To: header, excluding friendly name.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.sender</td>
      <td>String</td>
      <td>The email address of the SMTP (envelope) sender. The user-part is hashed. The domain-part is cleartext.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.senderIP</td>
      <td>String</td>
      <td>The IP address of the sender.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.spamScore</td>
      <td>Number</td>
      <td>The spam score of the message. Higher scores indicate higher certainty.</td>
    </tr>
    <tr>
      <td>Proofpoint.MessagesBlocked.subject</td>
      <td>String</td>
      <td>The subject line of the message, if available.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.GUID</td>
      <td>String</td>
      <td>The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.campaignId</td>
      <td>String</td>
      <td>An identifier for the campaign of which the threat is a member, if available at the time of the query. Threats can be linked to campaigns even after these events are retrieved.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.classification</td>
      <td>String</td>
      <td>The threat category of the malicious URL.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.clickIP</td>
      <td>String</td>
      <td>The external IP address of the user who clicked on the link. If the user is behind a firewall performing network address translation, the IP address of the firewall will be shown.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.clickTime</td>
      <td>Date</td>
      <td>The time the user clicked on the URL</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.messageID</td>
      <td>String</td>
      <td>Message-ID extracted from the headers of the email message. It can be used to look up the associated message in PPS and is not unique.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.recipient</td>
      <td>String</td>
      <td>The email address of the recipient.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.sender</td>
      <td>String</td>
      <td>The email address of the sender. The user-part is hashed. The domain-part is cleartext.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.senderIP</td>
      <td>String</td>
      <td>The IP address of the sender.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.threatID</td>
      <td>String</td>
      <td>The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints. </td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.threatTime</td>
      <td>Date</td>
      <td>Proofpoint identified the URL as a threat at this time.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.threatURL</td>
      <td>String</td>
      <td>A link to the entry on the TAP Dashboard for the particular threat.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.url</td>
      <td>String</td>
      <td>The malicious URL which was clicked.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksPermitted.userAgent</td>
      <td>String</td>
      <td>The User-Agent header from the clicker's HTTP request.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.GUID</td>
      <td>String</td>
      <td>The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.campaignId</td>
      <td>String</td>
      <td>An identifier for the campaign of which the threat is a member, if available at the time of the query. Threats can be linked to campaigns even after these events are retrieved.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.classification</td>
      <td>String</td>
      <td>The threat category of the malicious URL.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.clickIP</td>
      <td>String</td>
      <td>The external IP address of the user who clicked on the link. If the user is behind a firewall performing network address translation, the IP address of the firewall will be shown.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.clickTime</td>
      <td>Date</td>
      <td>The time the user clicked on the URL</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.messageID</td>
      <td>String</td>
      <td>Message-ID extracted from the headers of the email message. It can be used to look up the associated message in PPS and is not unique.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.recipient</td>
      <td>String</td>
      <td>The email address of the recipient.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.sender</td>
      <td>String</td>
      <td>The email address of the sender. The user-part is hashed. The domain-part is cleartext.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.senderIP</td>
      <td>String</td>
      <td>The IP address of the sender.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.threatID</td>
      <td>String</td>
      <td>The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints. </td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.threatTime</td>
      <td>Date</td>
      <td>Proofpoint identified the URL as a threat at this time.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.threatURL</td>
      <td>String</td>
      <td>A link to the entry on the TAP Dashboard for the particular threat.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.url</td>
      <td>String</td>
      <td>The malicious URL which was clicked.</td>
    </tr>
    <tr>
      <td>Proofpoint.ClicksBlocked.userAgent</td>
      <td>String</td>
      <td>The User-Agent header from the clicker's HTTP request.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!proofpoint-get-events eventTypes=All, threatStatus=active interval=05-01-2016 PT30M/2016-05-01T12:30:00Z</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Proofpoint.ClicksBlocked": [
        {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "clickIP": "192.0.2.2",
            "clickTime": "2010-01-22T00:00:10.000Z",
            "messageID": "4444",
            "recipient": "bruce.wayne@pharmtech.zz",
            "sender": "9facbf452def2d7efc5b5c48cdb837fa@badguy.zz",
            "senderIP": "192.0.2.255",
            "threatID": "61f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50",
            "threatTime": "2010-01-22T00:00:20.000Z",
            "threatURL": "https://threatinsight.proofpoint.com/#/f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50",
            "url": "http://badguy.zz/",
            "userAgent": "Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0"
        }
    ],
    "Proofpoint.ClicksPermitted": [
        {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "clickIP": "192.0.2.1",
            "clickTime": "2010-01-11T00:00:20.000Z",
            "messageID": "3333",
            "recipient": "bruce.wayne@pharmtech.zz",
            "sender": "9facbf452def2d7efc5b5c48cdb837fa@badguy.zz",
            "senderIP": "192.0.2.255",
            "threatID": "61f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50",
            "threatTime": "2010-01-11T00:00:10.000Z",
            "threatURL": "https://threatinsight.proofpoint.com/#/f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50",
            "url": "http://badguy.zz/",
            "userAgent": "Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0"
        }
    ],
    "Proofpoint.MessagesBlocked": [
        {
            "GUID": "2222",
            "QID": "r2FNwRHF004109",
            "ccAddresses": [
                "bruce.wayne@university-of-education.zz"
            ],
            "clusterId": "pharmtech_hosted",
            "fromAddress": "badguy@evil.zz",
            "headerCC": "\"Bruce Wayne\" <bruce.wayne@university-of-education.zz>",
            "headerFrom": "\"A. Badguy\" <badguy@evil.zz>",
            "headerReplyTo": null,
            "headerTo": "\"Clark Kent\" <clark.kent@pharmtech.zz>; \"Diana Prince\" <diana.prince@pharmtech.zz>",
            "impostorScore": 0,
            "malwareScore": 100,
            "messageID": "2222@evil.zz",
            "messageTime": "2010-01-25T00:00:10.000Z",
            "modulesRun": [
                "pdr",
                "sandbox",
                "spam",
                "urldefense"
            ],
            "phishScore": 46,
            "policyRoutes": [
                "default_inbound",
                "executives"
            ],
            "quarantineFolder": "Attachment Defense",
            "quarantineRule": "module.sandbox.threat",
            "recipient": [
                "clark.kent@pharmtech.zz",
                "diana.prince@pharmtech.zz"
            ],
            "replyToAddress": null,
            "sender": "e99d7ed5580193f36a51f597bc2c0210@evil.zz",
            "senderIP": "192.0.2.255",
            "spamScore": 4,
            "subject": "Please find a totally safe invoice attached.",
            "threatsInfoMap": [
                {
                    "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
                    "classification": "MALWARE",
                    "threat": "2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca",
                    "threatId": "2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca",
                    "threatStatus": "active",
                    "threatTime": "2010-01-25T00:00:40.000Z",
                    "threatType": "ATTACHMENT",
                    "threatUrl": "https://threatinsight.proofpoint.com/43fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca"
                },
                {
                    "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
                    "classification": "MALWARE",
                    "threat": "badsite.zz",
                    "threatId": "3ba97fc852c66a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa",
                    "threatTime": "2010-01-25T00:00:30.000Z",
                    "threatType": "URL",
                    "threatUrl": "https://threatinsight.proofpoint.com/a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa"
                }
            ]
        }
    ],
    "Proofpoint.MessagesDelivered": [
        {
            "GUID": "1111",
            "QID": "r2FNwRHF004109",
            "ccAddresses": [
                "bruce.wayne@university-of-education.zz"
            ],
            "clusterId": "pharmtech_hosted",
            "fromAddress": "badguy@evil.zz",
            "headerCC": "\"Bruce Wayne\" <bruce.wayne@university-of-education.zz>",
            "headerFrom": "\"A. Badguy\" <badguy@evil.zz>",
            "headerReplyTo": null,
            "headerTo": "\"Clark Kent\" <clark.kent@pharmtech.zz>; \"Diana Prince\" <diana.prince@pharmtech.zz>",
            "impostorScore": 0,
            "malwareScore": 100,
            "messageID": "1111@evil.zz",
            "messageTime": "2010-01-30T00:00:59.000Z",
            "modulesRun": [
                "pdr",
                "sandbox",
                "spam",
                "urldefense"
            ],
            "phishScore": 46,
            "policyRoutes": [
                "default_inbound",
                "executives"
            ],
            "quarantineFolder": "Attachment Defense",
            "quarantineRule": "module.sandbox.threat",
            "recipient": [
                "clark.kent@pharmtech.zz",
                "diana.prince@pharmtech.zz"
            ],
            "replyToAddress": null,
            "sender": "e99d7ed5580193f36a51f597bc2c0210@evil.zz",
            "senderIP": "192.0.2.255",
            "spamScore": 4,
            "subject": "Please find a totally safe invoice attached.",
            "threatsInfoMap": [
                {
                    "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
                    "classification": "MALWARE",
                    "threat": "2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca",
                    "threatId": "2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca",
                    "threatStatus": "active",
                    "threatTime": "2010-01-30T00:00:40.000Z",
                    "threatType": "ATTACHMENT",
                    "threatUrl": "https://threatinsight.proofpoint.com/43fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca"
                },
                {
                    "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
                    "classification": "MALWARE",
                    "threat": "badsite.zz",
                    "threatId": "3ba97fc852c66a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa",
                    "threatTime": "2010-01-30T00:00:30.000Z",
                    "threatType": "URL",
                    "threatUrl": "https://threatinsight.proofpoint.com/a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa"
                }
            ]
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Proofpoint Events</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>clicksBlocked</strong></th>
      <th><strong>clicksPermitted</strong></th>
      <th><strong>messagesBlocked</strong></th>
      <th><strong>messagesDelivered</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> {'campaignId': '46e01b8a-c899-404d-bcd9-189bb393d1a7', 'classification': 'MALWARE', 'clickIP': '192.0.2.2', 'clickTime': '2010-01-22T00:00:10.000Z', 'messageID': '4444', 'recipient': 'bruce.wayne@pharmtech.zz', 'sender': '9facbf452def2d7efc5b5c48cdb837fa@badguy.zz', 'senderIP': '192.0.2.255', 'threatID': '61f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50', 'threatTime': '2010-01-22T00:00:20.000Z', 'threatURL': 'https://threatinsight.proofpoint.com/#/f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50', 'url': 'http://badguy.zz/', 'userAgent': 'Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0'} </td>
      <td> {'campaignId': '46e01b8a-c899-404d-bcd9-189bb393d1a7', 'classification': 'MALWARE', 'clickIP': '192.0.2.1', 'clickTime': '2010-01-11T00:00:20.000Z', 'messageID': '3333', 'recipient': 'bruce.wayne@pharmtech.zz', 'sender': '9facbf452def2d7efc5b5c48cdb837fa@badguy.zz', 'senderIP': '192.0.2.255', 'threatID': '61f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50', 'threatTime': '2010-01-11T00:00:10.000Z', 'threatURL': 'https://threatinsight.proofpoint.com/#/f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50', 'url': 'http://badguy.zz/', 'userAgent': 'Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0'} </td>
      <td> {'GUID': '2222', 'QID': 'r2FNwRHF004109', 'ccAddresses': ['bruce.wayne@university-of-education.zz'], 'clusterId': 'pharmtech_hosted', 'fromAddress': 'badguy@evil.zz', 'headerCC': '"Bruce Wayne" <bruce.wayne@university-of-education.zz>', 'headerFrom': '"A. Badguy" <badguy@evil.zz>', 'headerReplyTo': None, 'headerTo': '"Clark Kent" <clark.kent@pharmtech.zz>; "Diana Prince" <diana.prince@pharmtech.zz>', 'impostorScore': 0, 'malwareScore': 100, 'messageID': '2222@evil.zz', 'threatsInfoMap': [{'campaignId': '46e01b8a-c899-404d-bcd9-189bb393d1a7', 'classification': 'MALWARE', 'threat': '2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca', 'threatId': '2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca', 'threatStatus': 'active', 'threatTime': '2010-01-25T00:00:40.000Z', 'threatType': 'ATTACHMENT', 'threatUrl': 'https://threatinsight.proofpoint.com/43fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca'}, {'campaignId': '46e01b8a-c899-404d-bcd9-189bb393d1a7', 'classification': 'MALWARE', 'threat': 'badsite.zz', 'threatId': '3ba97fc852c66a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa', 'threatTime': '2010-01-25T00:00:30.000Z', 'threatType': 'URL', 'threatUrl': 'https://threatinsight.proofpoint.com/a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa'}], 'messageTime': '2010-01-25T00:00:10.000Z', 'modulesRun': ['pdr', 'sandbox', 'spam', 'urldefense'], 'phishScore': 46, 'policyRoutes': ['default_inbound', 'executives'], 'quarantineFolder': 'Attachment Defense', 'quarantineRule': 'module.sandbox.threat', 'recipient': ['clark.kent@pharmtech.zz', 'diana.prince@pharmtech.zz'], 'replyToAddress': None, 'sender': 'e99d7ed5580193f36a51f597bc2c0210@evil.zz', 'senderIP': '192.0.2.255', 'spamScore': 4, 'subject': 'Please find a totally safe invoice attached.'} </td>
      <td> {'GUID': '1111', 'QID': 'r2FNwRHF004109', 'ccAddresses': ['bruce.wayne@university-of-education.zz'], 'clusterId': 'pharmtech_hosted', 'fromAddress': 'badguy@evil.zz', 'headerCC': '"Bruce Wayne" <bruce.wayne@university-of-education.zz>', 'headerFrom': '"A. Badguy" <badguy@evil.zz>', 'headerReplyTo': None, 'headerTo': '"Clark Kent" <clark.kent@pharmtech.zz>; "Diana Prince" <diana.prince@pharmtech.zz>', 'impostorScore': 0, 'malwareScore': 100, 'messageID': '1111@evil.zz', 'threatsInfoMap': [{'campaignId': '46e01b8a-c899-404d-bcd9-189bb393d1a7', 'classification': 'MALWARE', 'threat': '2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca', 'threatId': '2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca', 'threatStatus': 'active', 'threatTime': '2010-01-30T00:00:40.000Z', 'threatType': 'ATTACHMENT', 'threatUrl': 'https://threatinsight.proofpoint.com/43fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca'}, {'campaignId': '46e01b8a-c899-404d-bcd9-189bb393d1a7', 'classification': 'MALWARE', 'threat': 'badsite.zz', 'threatId': '3ba97fc852c66a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa', 'threatTime': '2010-01-30T00:00:30.000Z', 'threatType': 'URL', 'threatUrl': 'https://threatinsight.proofpoint.com/a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa'}], 'messageTime': '2010-01-30T00:00:59.000Z', 'modulesRun': ['pdr', 'sandbox', 'spam', 'urldefense'], 'phishScore': 46, 'policyRoutes': ['default_inbound', 'executives'], 'quarantineFolder': 'Attachment Defense', 'quarantineRule': 'module.sandbox.threat', 'recipient': ['clark.kent@pharmtech.zz', 'diana.prince@pharmtech.zz'], 'replyToAddress': None, 'sender': 'e99d7ed5580193f36a51f597bc2c0210@evil.zz', 'senderIP': '192.0.2.255', 'spamScore': 4, 'subject': 'Please find a totally safe invoice attached.'} </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>2. proofpoint-get-forensics</h3>
<hr>
<p>gets forensics evidence</p>
<h5>Base Command</h5>
<p>
  <code>proofpoint-get-forensics</code>
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
      <td>threatId</td>
      <td>ID of threat (must fill threatId or campaignId)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>campaignId</td>
      <td>ID of campaign (must fill threatId or campaignId)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>includeCampaignForensics</td>
      <td>Can be provide only with threatId</td>
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
      <td>Proofpoint.Report.ID</td>
      <td>String</td>
      <td>ID of report</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Type</td>
      <td>String</td>
      <td>The threat type: attachment, url, or hybrid</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Scope</td>
      <td>String</td>
      <td>Whether the report scope covers a campaign or an individual threat</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Attachment.Time</td>
      <td>Date</td>
      <td>The relative time at which the evidence was observed during sandboxing.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Attachment.Malicious</td>
      <td>String</td>
      <td>whether the evidence was used to reach a malicious verdict.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Attachment.Display</td>
      <td>String</td>
      <td>A friendly display string.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Attachment.SHA256</td>
      <td>String</td>
      <td>The SHA256 hash of the attachment's contents.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Attachment.MD5</td>
      <td>String</td>
      <td>The MD5 hash of the attachment's contents.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Attachment.Blacklisted</td>
      <td>Number</td>
      <td>Optional, whether the file was blacklisted.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Attachment.Offset</td>
      <td>Number</td>
      <td>Optional, the offset in bytes where the malicious content was found.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Attachment.Size</td>
      <td>Number</td>
      <td>Optional, the size in bytes of the attachment's contents.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Attachment.Platform.Name</td>
      <td>String</td>
      <td>Name of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Attachment.Platform.OS</td>
      <td>String</td>
      <td>OS of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Attachment.Platform.Version</td>
      <td>String</td>
      <td>Version of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Cookie.Time</td>
      <td>Date</td>
      <td>The relative time at which the evidence was observed during sandboxing.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Cookie.Malicious</td>
      <td>String</td>
      <td>whether the evidence was used to reach a malicious verdict.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Cookie.Display</td>
      <td>String</td>
      <td>A friendly display string.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Cookie.Action</td>
      <td>String</td>
      <td>Whether the cookie was set or deleted</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Cookie.Domain</td>
      <td>String</td>
      <td>Which domain set the cookie.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Cookie.Key</td>
      <td>String</td>
      <td>The name of the cookie being set or deleted.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Cookie.Value</td>
      <td>String</td>
      <td>Optional, content of the cookie being set.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Cookie.Platform.Name</td>
      <td>String</td>
      <td>Name of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Cookie.Platform.OS</td>
      <td>String</td>
      <td>OS of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Cookie.Platform.Version</td>
      <td>String</td>
      <td>Version of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.DNS.Time</td>
      <td>Date</td>
      <td>The relative time at which the evidence was observed during sandboxing.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.DNS.Malicious</td>
      <td>String</td>
      <td>whether the evidence was used to reach a malicious verdict.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.DNS.Display</td>
      <td>String</td>
      <td>A friendly display string.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.DNS.Host</td>
      <td>String</td>
      <td>The hostname being resolved.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.DNS.CNames</td>
      <td>String</td>
      <td>Optional, an array of cnames which were associated with the hostname.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.DNS.IP</td>
      <td>String</td>
      <td>Optional, an array of IP addresses which were resolved to the hostname.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.DNS.NameServers</td>
      <td>String</td>
      <td>Optional, the nameservers responsible for the hostname's domain.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.DNS.NameServersList</td>
      <td>String</td>
      <td>Optional, the nameservers responsible for the hostname's.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.DNS.Platform.Name</td>
      <td>String</td>
      <td>Name of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.DNS.Platform.OS</td>
      <td>String</td>
      <td>OS of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.DNS.Platform.Version</td>
      <td>String</td>
      <td>Version of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Dropper.Time</td>
      <td>Date</td>
      <td>The relative time at which the evidence was observed during sandboxing.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Dropper.Malicious</td>
      <td>String</td>
      <td>whether the evidence was used to reach a malicious verdict.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Dropper.Display</td>
      <td>String</td>
      <td>A friendly display string.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Dropper.Path</td>
      <td>String</td>
      <td>The location of the dropper file.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Dropper.URL</td>
      <td>String</td>
      <td>Optional, the name of the static rule inside the sandbox which identified the dropper.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Dropper.Rule</td>
      <td>String</td>
      <td>Optional, the URL the dropper contacted.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Dropper.Platform.Name</td>
      <td>String</td>
      <td>Name of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Dropper.Platform.OS</td>
      <td>String</td>
      <td>OS of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Dropper.Platform.Version</td>
      <td>String</td>
      <td>Version of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.Time</td>
      <td>Date</td>
      <td>The relative time at which the evidence was observed during sandboxing.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.Malicious</td>
      <td>String</td>
      <td>whether the evidence was used to reach a malicious verdict.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.Display</td>
      <td>String</td>
      <td>A friendly display string.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.Path</td>
      <td>String</td>
      <td>Optional, the location of the file operated on.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.Action</td>
      <td>String</td>
      <td>Optional, the filesystem call made create (modify, or delete).</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.Rule</td>
      <td>String</td>
      <td>Optional, the name of the static rule inside the sandbox which identified the suspicious file.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.SHA256</td>
      <td>Unknown</td>
      <td>Optional, the SH256 sum of the file's contents.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.MD5</td>
      <td>String</td>
      <td>Optional, the MD5 sum of the file's contents.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.Size</td>
      <td>Number</td>
      <td>Optional, the size in bytes of the file's contents.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.Platform.Name</td>
      <td>String</td>
      <td>Name of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.Platform.OS</td>
      <td>String</td>
      <td>OS of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.File.Platform.Version</td>
      <td>String</td>
      <td>Version of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.IDS.Time</td>
      <td>Date</td>
      <td>The relative time at which the evidence was observed during sandboxing.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.IDS.Malicious</td>
      <td>String</td>
      <td>whether the evidence was used to reach a malicious verdict.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.IDS.Display</td>
      <td>String</td>
      <td>A friendly display string.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.IDS.Name</td>
      <td>String</td>
      <td>The friendly name of the IDS rule which observed the malicious traffic.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.IDS.SignatureID</td>
      <td>String</td>
      <td>The identifier of the IDS rule which observed the malicious traffic.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.IDS.Platform.Name</td>
      <td>String</td>
      <td>Name of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.IDS.Platform.OS</td>
      <td>String</td>
      <td>OS of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.IDS.Platform.Version</td>
      <td>String</td>
      <td>Version of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Mutex.Time</td>
      <td>Date</td>
      <td>The relative time at which the evidence was observed during sandboxing.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Mutex.Malicious</td>
      <td>String</td>
      <td>whether the evidence was used to reach a malicious verdict.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Mutex.Display</td>
      <td>String</td>
      <td>A friendly display string.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Mutex.Name</td>
      <td>String</td>
      <td>The name of the mutex.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Mutex.Path</td>
      <td>String</td>
      <td>Optional, the path to the process which spawned the mutex.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Mutex.Platform.Name</td>
      <td>String</td>
      <td>Name of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Mutex.Platform.OS</td>
      <td>String</td>
      <td>OS of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Mutex.Platform.Version</td>
      <td>String</td>
      <td>Version of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Network.Time</td>
      <td>Date</td>
      <td>The relative time at which the evidence was observed during sandboxing.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Network.Malicious</td>
      <td>String</td>
      <td>whether the evidence was used to reach a malicious verdict.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Network.Display</td>
      <td>String</td>
      <td>A friendly display string.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Network.Action</td>
      <td>String</td>
      <td>The type of network activity being initated (connect or listen).</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Network.IP</td>
      <td>String</td>
      <td>The remote IP address being contacted.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Network.Port</td>
      <td>String</td>
      <td>The remote IP Port being contacted.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Network.Type</td>
      <td>String</td>
      <td>The protocol being used (tcp or udp).</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Network.Platform.Name</td>
      <td>String</td>
      <td>Name of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Network.Platform.OS</td>
      <td>String</td>
      <td>OS of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Network.Platform.Version</td>
      <td>String</td>
      <td>Version of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Process.Time</td>
      <td>Date</td>
      <td>The relative time at which the evidence was observed during sandboxing.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Process.Malicious</td>
      <td>String</td>
      <td>whether the evidence was used to reach a malicious verdict.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Process.Display</td>
      <td>String</td>
      <td>A friendly display string.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Process.Action</td>
      <td>String</td>
      <td>The action peformed on the process, current only create is produced.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Process.Path</td>
      <td>String</td>
      <td>The location of the executable which spawned the process.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Process.Platform.Name</td>
      <td>String</td>
      <td>Name of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Process.Platform.OS</td>
      <td>String</td>
      <td>OS of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Process.Platform.Version</td>
      <td>String</td>
      <td>Version of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Registry.Time</td>
      <td>Date</td>
      <td>The relative time at which the evidence was observed during sandboxing.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Registry.Malicious</td>
      <td>String</td>
      <td>whether the evidence was used to reach a malicious verdict.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Registry.Display</td>
      <td>String</td>
      <td>A friendly display string.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Registry.Name</td>
      <td>String</td>
      <td>Optional, the name of the registry entry being created or set.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Registry.Action</td>
      <td>String</td>
      <td>The registry change made (create or set).</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Registry.Key</td>
      <td>String</td>
      <td>The location of the registry key being modified.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Registry.Value</td>
      <td>String</td>
      <td>Optional, the contents of the key being created or set.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Registry.Platform.Name</td>
      <td>String</td>
      <td>Name of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Registry.Platform.OS</td>
      <td>String</td>
      <td>OS of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.Registry.Platform.Version</td>
      <td>String</td>
      <td>Version of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.Time</td>
      <td>Date</td>
      <td>The relative time at which the evidence was observed during sandboxing.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.Malicious</td>
      <td>String</td>
      <td>whether the evidence was used to reach a malicious verdict.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.Display</td>
      <td>String</td>
      <td>A friendly display string.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.URL</td>
      <td>String</td>
      <td>The URL which was observed.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.Blacklisted</td>
      <td>Boolean</td>
      <td>Optional, whether the URL was listed on a blacklist.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.SHA256</td>
      <td>String</td>
      <td>Optional, the sha256 value of the file downloaded from the URL.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.MD5</td>
      <td>String</td>
      <td>Optional, the md5 value of the file downloaded from the URL.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.Size</td>
      <td>Number</td>
      <td>Optional, the size in bytes of the file retrieved from the URL.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.HTTPStatus</td>
      <td>Number</td>
      <td>Optional, the HTTP status code which was produced when our sandbox visited the URL.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.IP</td>
      <td>String</td>
      <td>Optional, the IP address that was resolved to the hostname by the sandbox.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.Platform.Name</td>
      <td>String</td>
      <td>Name of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.Platform.OS</td>
      <td>String</td>
      <td>OS of the platform.</td>
    </tr>
    <tr>
      <td>Proofpoint.Report.URL.Platform.Version</td>
      <td>String</td>
      <td>Version of the platform.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!proofpoint-get-forensics threatId=threatId</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Proofpoint.Report": [
        {
            "Attachment": [
                {
                    "Display": "string",
                    "MD5": "string",
                    "Malicious": "string",
                    "Offset": "integer",
                    "Platform": [
                        {
                            "Name": "windows 7 sp1",
                            "OS": "windows 7",
                            "Version": "4.5.661"
                        }
                    ],
                    "SHA256": "string",
                    "Size": "integer",
                    "Time": "string"
                }
            ],
            "Cookie": [
                {
                    "Action": "string",
                    "Display": "string",
                    "Domain": "string",
                    "Key": "string",
                    "Malicious": "string",
                    "Platform": [
                        {
                            "Name": "windows 7 sp1",
                            "OS": "windows 7",
                            "Version": "4.5.661"
                        }
                    ],
                    "Time": "string",
                    "Value": "string"
                }
            ],
            "DNS": [
                {
                    "CNames": [
                        "string1",
                        "string2"
                    ],
                    "Display": "string",
                    "Host": "string",
                    "IP": [
                        "string1",
                        "string2"
                    ],
                    "Malicious": "string",
                    "NameServers": [
                        "string1",
                        "string2"
                    ],
                    "NameServersList": [
                        "string1",
                        "string2"
                    ],
                    "Platform": [
                        {
                            "Name": "windows 7 sp1",
                            "OS": "windows 7",
                            "Version": "4.5.661"
                        }
                    ],
                    "Time": "string"
                }
            ],
            "Dropper": [
                {
                    "Display": "string",
                    "Malicious": "string",
                    "Path": "string",
                    "Platform": [
                        {
                            "Name": "windows 7 sp1",
                            "OS": "windows 7",
                            "Version": "4.5.661"
                        }
                    ],
                    "Rule": "string",
                    "Time": "string",
                    "URL": "string"
                }
            ],
            "File": [
                {
                    "Action": "string",
                    "Display": "string",
                    "MD5": "string",
                    "Malicious": "string",
                    "Path": "string",
                    "Platform": [
                        {
                            "Name": "windows 7 sp1",
                            "OS": "windows 7",
                            "Version": "4.5.661"
                        }
                    ],
                    "SHA256": "string",
                    "Size": "integer",
                    "Time": "string"
                }
            ],
            "ID": "threatId",
            "IDS": [
                {
                    "Display": "string",
                    "Malicious": "string",
                    "Name": "string",
                    "Platform": [
                        {
                            "Name": "windows 7 sp1",
                            "OS": "windows 7",
                            "Version": "4.5.661"
                        }
                    ],
                    "SignatureID": "integer",
                    "Time": "string"
                }
            ],
            "Mutex": [
                {
                    "Display": "string",
                    "Malicious": "string",
                    "Name": "string",
                    "Path": "string",
                    "Platform": [
                        {
                            "Name": "windows 7 sp1",
                            "OS": "windows 7",
                            "Version": "4.5.661"
                        }
                    ],
                    "Time": "string"
                }
            ],
            "Network": [
                {
                    "Action": "string",
                    "Display": "string",
                    "IP": "string",
                    "Malicious": "string",
                    "Platform": [
                        {
                            "Name": "windows 7 sp1",
                            "OS": "windows 7",
                            "Version": "4.5.661"
                        }
                    ],
                    "Port": "string",
                    "Protocol": "string",
                    "Time": "string"
                }
            ],
            "Process": [
                {
                    "Action": "string",
                    "Display": "string",
                    "Malicious": "string",
                    "Path": "string",
                    "Platform": [
                        {
                            "Name": "windows 7 sp1",
                            "OS": "windows 7",
                            "Version": "4.5.661"
                        }
                    ],
                    "Time": "string"
                }
            ],
            "Registry": [
                {
                    "Action": "string",
                    "Display": "string",
                    "Key": "string",
                    "Malicious": "string",
                    "Name": "string",
                    "Platform": [
                        {
                            "Name": "windows 7 sp1",
                            "OS": "windows 7",
                            "Version": "4.5.661"
                        }
                    ],
                    "Time": "string",
                    "Value": "string"
                }
            ],
            "Scope": "string",
            "Type": "string",
            "URL": [
                {
                    "Blacklisted": "boolean",
                    "Display": "string",
                    "HTTPStatus": "string",
                    "IP": "string",
                    "MD5": "string",
                    "Malicious": "string",
                    "Platform": [
                        {
                            "Name": "windows 7 sp1",
                            "OS": "windows 7",
                            "Version": "4.5.661"
                        }
                    ],
                    "SHA256": "string",
                    "Size": "integer",
                    "Time": "string",
                    "URL": "string"
                }
            ]
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Forensic results from ProofPoint for ID: threatId</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Scope</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> threatId </td>
      <td> string </td>
      <td> string </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h2>Additional Information</h2><h2>Known Limitations</h2><h2>Troubleshooting</h2>

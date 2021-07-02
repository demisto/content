<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the Freshdesk integration to manage and create Freshdesk tickets from Cortex XSOAR.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Create a Freshdesk ticket from Cortex XSOAR</li>
<li>Update a Freshdesk ticket from Cortex XSOAR</li>
<li>Get information from a Freshdesk ticket</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="configure-freshdesk-on-demisto">Configure Freshdesk on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Freshdesk.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL https://demistohelp.freshdesk.com )</strong></li>
<li><strong>API Token. (You must enter either the API token or your Freshdesk credentials)</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy</strong></li>
<li><strong>First fetch timestamp ( <time>, e.g., 12 hours, 7 days)</time></strong></li>
<li><strong>Username</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#create-a-ticket">Create a ticket: fd-create-ticket</a></li>
<li><a href="#get-ticket-details">Get ticket details: fd-get-ticket</a></li>
<li><a href="#update-a-ticket">Update a ticket: fd-update-ticket</a></li>
<li><a href="#get-a-list-of-all-contacts">Get a list of all contacts: fd-list-contacts</a></li>
<li><a href="#get-contact-details">Get contact details: fd-get-contact</a></li>
<li><a href="#get-a-list-of-all-canned-responst-folders">Get a list of all canned response folders: fd-list-canned-response-folders</a></li>
<li><a href="#get-a-list-of-details-for-all-canned-responses-in-a-folder">Get a list of details for all canned responses in a folder: fd-get-canned-response-folder</a></li>
<li><a href="#get-a-list-of-all-groups">Get a list of all groups: fd-list-groups</a></li>
<li><a href="#add-a-reply-to-a-ticket">Add a reply to a ticket: fd-ticket-reply</a></li>
<li><a href="#get-a-list-of-all-replies-and-notes-for-a-ticket">Get a list of all replies and notes for a ticket: fd-get-ticket-conversations</a></li>
<li><a href="#get-a-list-of-all-agents">Get a list of all agents: fd-list-agents</a></li>
<li><a href="#create-a-note-for-a-ticket">Create a note for a ticket: fd-create-ticket-note</a></li>
<li><a href="#delete-a-ticket">Delete a ticket: fd-delete-ticket</a></li>
<li><a href="#search-tickets">Search tickets: fd-search-tickets</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="create-a-ticket">1. Create a ticket</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Creates a new Freshdesk ticket.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-create-ticket</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 744px;">
<thead>
<tr>
<th style="width: 566px;"><strong>Argument Name</strong></th>
<th style="width: 103px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 566px;">subject</td>
<td style="width: 103px;">Subject of the ticket</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 566px;">description</td>
<td style="width: 103px;">Details of the issue that you are creating a ticket for</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 566px;">priority</td>
<td style="width: 103px;">Priority of the ticket. Each number has a corresponding value. 1 - Low, 2 - Medium, 3 - High, 4 - Urgent.<br> This argument accepts the priority number or string.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 566px;">status</td>
<td style="width: 103px;">Status of the ticket. Each number has a corresponding value. 2 - Open, 3 - Pending, 4 - Resolved, 5 - Closed, 6 - Waiting on Customer, 7 - Waiting on Third Party.<br> This argument accepts the ticket status number or string.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 566px;">identifier</td>
<td style="width: 103px;">Email address or a Twitter handle of the requesting user.<br> If an email address is entered and no contact exists with this email address in Freshdesk, it will be added as a new contact. If a Twitter handle is entered and no contact exists with this handle in Freshdesk, it will be added as a new contact.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 566px;">responder</td>
<td style="width: 103px;">ID or name of the group or agent to assign the ticket to.<br> Use the <code>fd-list-groups</code> command to find potential assignees.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 566px;">attachments</td>
<td style="width: 103px;">CSV list of entry IDs of files to attach to the ticket.<br> For example: “468@73f988d1-bda2-4adc-8e02-926f02190070,560@73f988d1-bda2-4adc-8e02-926f02190070”.<br> The total size of these attachments cannot exceed 15MB.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 566px;">additional_fields</td>
<td style="width: 103px;">Additional, optional ticket fields.<br> Format - “field=value” where field value pairs are delimited from subsequent pairs by a semicolon symbol ‘;’ and where values that are lists are delimited by commas ‘,’.<br> For example: “name=Jeffrey Collins;email=jeffrey.collins@gmail.com;tags=new,attention needed,billing related”</td>
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
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 316px;"><strong>Path</strong></th>
<th style="width: 70px;"><strong>Type</strong></th>
<th style="width: 354px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.ID</td>
<td style="width: 70px;">Number</td>
<td style="width: 354px;">ID number of the ticket</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.Priority</td>
<td style="width: 70px;">Number</td>
<td style="width: 354px;">Ticket priority</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.DueBy</td>
<td style="width: 70px;">Date</td>
<td style="width: 354px;">Timestamp that denotes when the ticket is due to be resolved</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.Subject</td>
<td style="width: 70px;">String</td>
<td style="width: 354px;">Ticket subject</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.Status</td>
<td style="width: 70px;">Number</td>
<td style="width: 354px;">Status of the ticket</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.RequesterID</td>
<td style="width: 70px;">Number</td>
<td style="width: 354px;">User ID of the requester</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.Tag</td>
<td style="width: 70px;">Unknown</td>
<td style="width: 354px;">Tags associated with the ticket</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.GroupID</td>
<td style="width: 70px;">Number</td>
<td style="width: 354px;">ID of the group the ticket was assigned to</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.Source</td>
<td style="width: 70px;">Number</td>
<td style="width: 354px;">The channel through which the ticket was created</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.CreatedAt</td>
<td style="width: 70px;">Date</td>
<td style="width: 354px;">Ticket creation timestamp</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.ResponderID</td>
<td style="width: 70px;">Number</td>
<td style="width: 354px;">ID of the agent the ticket was assigned to</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.FrDueBy</td>
<td style="width: 70px;">Date</td>
<td style="width: 354px;">Timestamp that denotes when the first response is due</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.AdditionalFields</td>
<td style="width: 70px;">Unknown</td>
<td style="width: 354px;">Additional fields and values that were entered using the ‘additional_fields’ arguments</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.Attachment.AttachmentURL</td>
<td style="width: 70px;">String</td>
<td style="width: 354px;">URL to download the file attached to the ticket to your local machine</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.Attachment.Name</td>
<td style="width: 70px;">Unknown</td>
<td style="width: 354px;">The name of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.Attachment.ContentType</td>
<td style="width: 70px;">String</td>
<td style="width: 354px;">Content type of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.Attachment.ID</td>
<td style="width: 70px;">Unknown</td>
<td style="width: 354px;">ID number for the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 316px;">Freshdesk.Ticket.Attachment.Size</td>
<td style="width: 70px;">String</td>
<td style="width: 354px;">Size of the file attached to the ticket</td>
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
<pre>!fd-create-ticket subject="Demonstrate Ticket Creation" description="&lt;em&gt;Here&lt;/em&gt; we are demonstrating the freshdesk integration ticket creation command" identifier="jeffrey.collins@gmail.com" priority="High" additional_fields="name=Jeffrey Collins;email=jeffrey.collins@gmail.com;tags=new,attention needed,billing related"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Ticket": {
        "Status": 2, 
        "DueBy": "2019-02-07T09:00:00Z", 
        "FrDueBy": "2019-02-06T10:00:00Z", 
        "Priority": 3, 
        "Source": 2, 
        "Tag": [
            "attention needed", 
            "billing related", 
            "new"
        ], 
        "RequesterID": 2043024010476, 
        "UpdatedAt": "2019-02-05T15:55:35Z", 
        "AdditionalFields": {
            "DescriptionHTML": "&lt;em&gt;Here&lt;/em&gt; we are demonstrating the freshdesk integration ticket creation command", 
            "DescriptionText": "Here we are demonstrating the freshdesk integration ticket creation command", 
            "Email": "jeffrey.collins@gmail.com", 
            "Name": "Jeffrey Collins"
        }, 
        "ID": 108, 
        "CreatedAt": "2019-02-05T15:55:35Z", 
        "Subject": "Demonstrate Ticket Creation"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="newly-created-ticket-108">Newly Created Ticket #108</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 1152px;">
<thead>
<tr>
<th style="width: 51px;">Status</th>
<th style="width: 103px;">DueBy</th>
<th style="width: 103px;">FrDueBy</th>
<th style="width: 62px;">Priority</th>
<th style="width: 52px;">Source</th>
<th style="width: 64px;">Tag</th>
<th style="width: 116px;">RequesterID</th>
<th style="width: 103px;">UpdatedAt</th>
<th style="width: 240px;">AdditionalFields</th>
<th style="width: 27px;">ID</th>
<th style="width: 103px;">CreatedAt</th>
<th style="width: 92px;">Subject</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 51px;">2</td>
<td style="width: 103px;">2019-02-07T09:00:00Z</td>
<td style="width: 103px;">2019-02-06T10:00:00Z</td>
<td style="width: 62px;">3</td>
<td style="width: 52px;">2</td>
<td style="width: 64px;">attention needed,<br> billing related,<br> new</td>
<td style="width: 116px;">2043024010476</td>
<td style="width: 103px;">2019-02-05T15:55:35Z</td>
<td style="width: 240px;">DescriptionHTML: <em>Here</em>we are demonstrating the freshdesk integration ticket creation command<br> DescriptionText: Here we are demonstrating the freshdesk integration ticket creation command<br> Name: Jeffrey Collins<br> Email: jeffrey.collins@gmail.com</td>
<td style="width: 27px;">108</td>
<td style="width: 103px;">2019-02-05T15:55:35Z</td>
<td style="width: 92px;">Demonstrate Ticket Creation</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-ticket-details">2. Get ticket details</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets details of a ticket, specified by the ticket ID number.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-get-ticket</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 153px;"><strong>Argument Name</strong></th>
<th style="width: 516px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153px;">id</td>
<td style="width: 516px;">ID number of the ticket to fetch</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">include_requester</td>
<td style="width: 516px;">If set to <code>true</code>, the ticket requester’s ID, email address, mobile number, name, and phone number will be included in the ticket’s output. Note that this is not set by default because setting this to ‘true’ will consume an additional API credit per API call.<br> For more information, see the <a href="https://developers.freshdesk.com/api/#embedding" target="_blank" rel="noopener">Freshdesk API documentation</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">include_stats</td>
<td style="width: 516px;">If set to <code>true</code> then the ticket’s closed_at, resolved_at and first_responded_at time will be included in the response. Note that this is not set by default because setting this to ‘true’ will consume an additional API credit per API call.<br> For more information, see the <a href="https://developers.freshdesk.com/api/#embedding" target="_blank" rel="noopener">Freshdesk API documentation</a>.</td>
<td style="width: 71px;">Optional</td>
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
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 321px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 354px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.ID</td>
<td style="width: 65px;">Number</td>
<td style="width: 354px;">ID number of the fetched ticket</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.Priority</td>
<td style="width: 65px;">Number</td>
<td style="width: 354px;">Ticket priority</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.DueBy</td>
<td style="width: 65px;">Date</td>
<td style="width: 354px;">Timestamp that denotes when the ticket is due to be resolved</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.Subject</td>
<td style="width: 65px;">String</td>
<td style="width: 354px;">Ticket subject</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.Status</td>
<td style="width: 65px;">Number</td>
<td style="width: 354px;">Ticket status</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.RequesterID</td>
<td style="width: 65px;">Number</td>
<td style="width: 354px;">User ID of the requester</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.Tag</td>
<td style="width: 65px;">Unknown</td>
<td style="width: 354px;">Tags associated with the ticket</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.GroupID</td>
<td style="width: 65px;">Number</td>
<td style="width: 354px;">ID of the group the ticket was assigned to</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.Source</td>
<td style="width: 65px;">Number</td>
<td style="width: 354px;">The channel through which the ticket was created</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.CreatedAt</td>
<td style="width: 65px;">Date</td>
<td style="width: 354px;">Ticket creation timestamp</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.ResponderID</td>
<td style="width: 65px;">Number</td>
<td style="width: 354px;">ID of the agent the ticket was assigned to</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.FrDueBy</td>
<td style="width: 65px;">Date</td>
<td style="width: 354px;">Timestamp that denotes when the first response is due</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.Conversation</td>
<td style="width: 65px;">Unknown</td>
<td style="width: 354px;">Conversations associated with this ticket</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.Attachment.AttachmentURL</td>
<td style="width: 65px;">Unknown</td>
<td style="width: 354px;">URL to download the file attached to the ticket to your local machine</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.Attachment.Name</td>
<td style="width: 65px;">Unknown</td>
<td style="width: 354px;">The name of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.Attachment.ContentType</td>
<td style="width: 65px;">String</td>
<td style="width: 354px;">Content type of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.Attachment.ID</td>
<td style="width: 65px;">Unknown</td>
<td style="width: 354px;">ID number of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.Attachment.Size</td>
<td style="width: 65px;">String</td>
<td style="width: 354px;">Size of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 321px;">Freshdesk.Ticket.UpdatedAt</td>
<td style="width: 65px;">Date</td>
<td style="width: 354px;">Ticket update timestamp</td>
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
<pre>!fd-get-ticket id=108 include_requester=true include_stats=true</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Ticket": {
        "Status": 2, 
        "DueBy": "2019-02-07T09:00:00Z", 
        "FrDueBy": "2019-02-06T10:00:00Z", 
        "Priority": 3, 
        "Source": 2, 
        "Tag": [
            "attention needed", 
            "billing related", 
            "new"
        ], 
        "RequesterID": 2043024010476, 
        "UpdatedAt": "2019-02-05T15:55:35Z", 
        "AdditionalFields": {
            "Stats": {
                "StatusUpdatedAt": "2019-02-05T15:55:35Z"
            }, 
            "IsEscalated": false, 
            "Deleted": false, 
            "Spam": false, 
            "FrEscalated": false, 
            "Requestor": {
                "Name": "Jeffrey Collins", 
                "Email": "jeffrey.collins@gmail.com", 
                "Id": 2043024010476
            }, 
            "DescriptionHTML": "&lt;em&gt;Here&lt;/em&gt; we are demonstrating the freshdesk integration ticket creation command", 
            "DescriptionText": "Here we are demonstrating the freshdesk integration ticket creation command"
        }, 
        "ID": 108, 
        "CreatedAt": "2019-02-05T15:55:35Z", 
        "Subject": "Demonstrate Ticket Creation"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="viewing-ticket-108">Viewing Ticket #108</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 1099px;">
<thead>
<tr>
<th style="width: 51px;">Status</th>
<th style="width: 103px;">DueBy</th>
<th style="width: 103px;">FrDueBy</th>
<th style="width: 59px;">Priority</th>
<th style="width: 55px;">Source</th>
<th style="width: 64px;">Tag</th>
<th style="width: 116px;">RequesterID</th>
<th style="width: 101px;">UpdatedAt</th>
<th style="width: 189px;">AdditionalFields</th>
<th style="width: 27px;">ID</th>
<th style="width: 103px;">CreatedAt</th>
<th style="width: 92px;">Subject</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 51px;">2</td>
<td style="width: 103px;">2019-02-07T09:00:00Z</td>
<td style="width: 103px;">2019-02-06T10:00:00Z</td>
<td style="width: 59px;">3</td>
<td style="width: 55px;">2</td>
<td style="width: 64px;">attention needed,<br> billing related,<br> new</td>
<td style="width: 116px;">2043024010476</td>
<td style="width: 101px;">2019-02-05T15:55:35Z</td>
<td style="width: 189px;">DescriptionHTML: <em>Here</em> we are demonstrating the freshdesk integration ticket creation command<br> IsEscalated: false<br> DescriptionText: Here we are demonstrating the freshdesk integration ticket creation command<br> Spam: false<br> FrEscalated: false</td>
<td style="width: 27px;">108</td>
<td style="width: 103px;">2019-02-05T15:55:35Z</td>
<td style="width: 92px;">Demonstrate Ticket Creation</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="update-a-ticket">3. Update a ticket</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Updates a ticket specified by the ID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-update-ticket</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 169px;"><strong>Argument Name</strong></th>
<th style="width: 492px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 169px;">subject</td>
<td style="width: 492px;">Subject of the ticket</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 169px;">status</td>
<td style="width: 492px;">Status of the ticket. Each number has a corresponding value.<br> 2 is Open, 3 is Pending, 4 is Resolved, 5 is Closed, 6 is Waiting on Customer, 7 is Waiting on Third Party.<br> Acceptable values for this command argument are the digits 2,3,4,5,6,7, or their corresponding strings ‘Open’,‘Pending’,‘Resolved’,‘Closed’,‘Waiting on Customer’,‘Waiting on Third Party’.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 169px;">priority</td>
<td style="width: 492px;">Priority of the ticket. Each number has a corresponding value.<br> 1 is Low, 2 is Medium, 3 is High, 4 is Urgent.<br> Acceptable values for this command argument are the digits 1,2,3,4, or their corresponding strings ‘Low’,‘Medium’,‘High’,‘Urgent’.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 169px;">description</td>
<td style="width: 492px;">HTML content of the ticket.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 169px;">id</td>
<td style="width: 492px;">ID number of the ticket to update</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 169px;">assigned_agent</td>
<td style="width: 492px;">Update which agent is assigned to respond to this ticket by entering either their unique agent ID, name, or email.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 169px;">assigned_group</td>
<td style="width: 492px;">Update the group assigned to respond to this ticket by entering the group’s unique ID or the name of the group.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 169px;">additional_fields</td>
<td style="width: 492px;">Fields not included in the default command arguments that you wish to enter the value for.<br> Format - “field=value” where field value pairs are delimited from subsequent pairs by a semicolon symbol ‘;’ and where values that are lists are delimited by commas ‘,’.<br> For example: “name=Jeffrey Collins;email=jeffrey.collins@gmail.com;tags=new,attention needed,billing related”</td>
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
<th style="width: 315px;"><strong>Path</strong></th>
<th style="width: 71px;"><strong>Type</strong></th>
<th style="width: 354px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.ID</td>
<td style="width: 71px;">Number</td>
<td style="width: 354px;">ID of the updated ticket</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.Priority</td>
<td style="width: 71px;">Number</td>
<td style="width: 354px;">Ticket priority</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.DueBy</td>
<td style="width: 71px;">Date</td>
<td style="width: 354px;">Timestamp that denotes when the ticket is due to be resolved</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.Subject</td>
<td style="width: 71px;">String</td>
<td style="width: 354px;">Ticket subject</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.Status</td>
<td style="width: 71px;">Number</td>
<td style="width: 354px;">Ticket status</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.RequesterID</td>
<td style="width: 71px;">Number</td>
<td style="width: 354px;">User ID of the requester</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.Tag</td>
<td style="width: 71px;">Unknown</td>
<td style="width: 354px;">Tags associated with the ticket</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.GroupID</td>
<td style="width: 71px;">Number</td>
<td style="width: 354px;">ID of the group assigned to the ticket</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.Source</td>
<td style="width: 71px;">Number</td>
<td style="width: 354px;">The channel through which the ticket was created</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.CreatedAt</td>
<td style="width: 71px;">Date</td>
<td style="width: 354px;">Ticket creation timestamp</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.ResponderId</td>
<td style="width: 71px;">Number</td>
<td style="width: 354px;">ID of the agent the ticket was assigned to</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.FrDueBy</td>
<td style="width: 71px;">Date</td>
<td style="width: 354px;">Timestamp that denotes when the first response is due</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.UpdatedAt</td>
<td style="width: 71px;">Date</td>
<td style="width: 354px;">Ticket update timestamp</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.AdditionalFields</td>
<td style="width: 71px;">Unknown</td>
<td style="width: 354px;">Additional fields and values that were updated using the ‘additional_fields’ argument</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.Attachment.AttachmentURL</td>
<td style="width: 71px;">Unknown</td>
<td style="width: 354px;">URL to download the file attached to the ticket to your local machine</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.Attachment.Name</td>
<td style="width: 71px;">Unknown</td>
<td style="width: 354px;">The name of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.Attachment.ContentType</td>
<td style="width: 71px;">String</td>
<td style="width: 354px;">Content type of the attached file</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.Attachment.ID</td>
<td style="width: 71px;">Unknown</td>
<td style="width: 354px;">ID number for the attached file</td>
</tr>
<tr>
<td style="width: 315px;">Freshdesk.Ticket.Attachment.Size</td>
<td style="width: 71px;">String</td>
<td style="width: 354px;">Size of the attached file in bytes</td>
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
<pre>!fd-update-ticket id=108 priority=Medium subject="Demonstrating Ticket Updating" assigned_agent=jeffrey.collins@gmail.com additional_fields="tags=almost completed,yep;attachments=2@5a0be47f-748f-4d60-8f46-81feb8f0c438"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Ticket": {
        "Status": 2, 
        "ResponderID": 2043022085976, 
        "DueBy": "2019-02-06T15:00:00Z", 
        "FrDueBy": "2019-02-06T14:00:00Z", 
        "Priority": 2, 
        "Source": 2, 
        "Tag": [
            "almost completed", 
            "yep"
        ], 
        "Attachment": [
            {
                "Name": "sample_attachment.md", 
                "Size": 76, 
                "ContentType": "application/octet-stream", 
                "ID": 2043010708407, 
                "AttachmentURL": "https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708407/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155538Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=05dfe20c475c01763766b71ee0d4f0e808cef5fa116cede418eabafce4802947&amp;X-Amz-SignedHeaders=Host"
            }
        ], 
        "RequesterID": 2043024010476, 
        "UpdatedAt": "2019-02-05T15:55:37Z", 
        "AdditionalFields": {
            "DescriptionHTML": "&lt;em&gt;Here&lt;/em&gt; we are demonstrating the freshdesk integration ticket creation command", 
            "DescriptionText": "Here we are demonstrating the freshdesk integration ticket creation command"
        }, 
        "ID": 108, 
        "CreatedAt": "2019-02-05T15:55:35Z", 
        "Subject": "Demonstrating Ticket Updating"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="ticket-108-updated">Ticket #108 Updated</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 2344px;">
<thead>
<tr>
<th style="width: 51px;">Status</th>
<th style="width: 116px;">ResponderID</th>
<th style="width: 106px;">DueBy</th>
<th style="width: 100px;">FrDueBy</th>
<th style="width: 59px;">Priority</th>
<th style="width: 55px;">Source</th>
<th style="width: 78px;">Tag</th>
<th style="width: 1096px;">Attachment</th>
<th style="width: 116px;">RequesterID</th>
<th style="width: 103px;">UpdatedAt</th>
<th style="width: 187px;">AdditionalFields</th>
<th style="width: 27px;">ID</th>
<th style="width: 103px;">CreatedAt</th>
<th style="width: 105px;">Subject</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 51px;">2</td>
<td style="width: 116px;">2043022085976</td>
<td style="width: 106px;">2019-02-06T15:00:00Z</td>
<td style="width: 100px;">2019-02-06T14:00:00Z</td>
<td style="width: 59px;">2</td>
<td style="width: 55px;">2</td>
<td style="width: 78px;">almost completed,<br> yep</td>
<td style="width: 1096px;">ID: 2043010708407, Size: 76, ContentType: application/octet-stream, Name: sample_attachment.md, AttachmentURL: <a href="https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708407/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155538Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=05dfe20c475c01763766b71ee0d4f0e808cef5fa116cede418eabafce4802947&amp;X-Amz-SignedHeaders=Host">https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708407/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155538Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=05dfe20c475c01763766b71ee0d4f0e808cef5fa116cede418eabafce4802947&amp;X-Amz-SignedHeaders=Host</a>
</td>
<td style="width: 116px;">2043024010476</td>
<td style="width: 103px;">2019-02-05T15:55:37Z</td>
<td style="width: 187px;">DescriptionHTML: <em>Here</em> we are demonstrating the freshdesk integration ticket creation command<br> DescriptionText: Here we are demonstrating the freshdesk integration ticket creation command</td>
<td style="width: 27px;">108</td>
<td style="width: 103px;">2019-02-05T15:55:35Z</td>
<td style="width: 105px;">Demonstrating Ticket Updating</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-all-contacts">4. Get a list of all contacts</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of all contacts matching the specified filters. If no filters are provided then all unblocked and undeleted contacts will be returned.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-list-contacts</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 531px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">mobile</td>
<td style="width: 531px;">mobile number to filter the contacts by</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">phone</td>
<td style="width: 531px;">phone number to filter contacts by</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">state</td>
<td style="width: 531px;">The state of contacts by which you want to filter the contacts</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">updated_since</td>
<td style="width: 531px;">Return contacts that have been updated after the timestamp given as this argument value. Acceptable format is ‘YYYY-MM-DDTHH:MM:SSZ’<br> For example: ‘2018-01-19T02:00:00Z’.</td>
<td style="width: 71px;">Optional</td>
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
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 259px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 415px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 259px;">Freshdesk.Contact.Active</td>
<td style="width: 66px;">Boolean</td>
<td style="width: 415px;">Set to true if the contact has been verified</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.Address</td>
<td style="width: 66px;">String</td>
<td style="width: 415px;">Address of the contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.CompanyID</td>
<td style="width: 66px;">Number</td>
<td style="width: 415px;">ID of the primary company to which this contact belongs</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.ViewAllTickets</td>
<td style="width: 66px;">Boolean</td>
<td style="width: 415px;">Set to true if the contact can see all tickets that are associated with the company to which s/he belong</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.Deleted</td>
<td style="width: 66px;">Boolean</td>
<td style="width: 415px;">Set to true if the contact has been deleted</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.Description</td>
<td style="width: 66px;">String</td>
<td style="width: 415px;">A short description of the contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.Email</td>
<td style="width: 66px;">String</td>
<td style="width: 415px;">Primary email address of the contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.ID</td>
<td style="width: 66px;">Number</td>
<td style="width: 415px;">ID of the contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.JobTitle</td>
<td style="width: 66px;">String</td>
<td style="width: 415px;">Job Title of the contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.Language</td>
<td style="width: 66px;">String</td>
<td style="width: 415px;">Language of the contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.Mobile</td>
<td style="width: 66px;">Number</td>
<td style="width: 415px;">Mobile number of the contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.Name</td>
<td style="width: 66px;">String</td>
<td style="width: 415px;">Name of the contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.Phone</td>
<td style="width: 66px;">Number</td>
<td style="width: 415px;">Telephone number of the contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.Tag</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 415px;">Tags associated with this contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.TimeZone</td>
<td style="width: 66px;">String</td>
<td style="width: 415px;">Time zone in which the contact resides</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.TwitterID</td>
<td style="width: 66px;">String</td>
<td style="width: 415px;">Twitter handle of the contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.UniqueExternalID</td>
<td style="width: 66px;">String</td>
<td style="width: 415px;">External ID of the contact</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.CreatedAt</td>
<td style="width: 66px;">Date</td>
<td style="width: 415px;">Contact creation stamp</td>
</tr>
<tr>
<td style="width: 259px;">Freshdesk.Contact.UpdatedAt</td>
<td style="width: 66px;">Date</td>
<td style="width: 415px;">Contact updated timestamp</td>
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
<pre>!fd-list-contacts updated_since=2018-01-19T02:00:00Z</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Contact": [
        {
            "Name": "Bob Tree", 
            "Language": "en", 
            "CompanyID": 44000302032, 
            "Mobile": "+972501231231", 
            "JobTitle": "Security Researcher", 
            "UpdatedAt": "2019-01-20T09:51:11Z", 
            "UniqueExternalID": "12345", 
            "Email": "bob.tree@freshdesk.com", 
            "Phone": "+972501231231", 
            "Address": "Rothchild 45", 
            "TimeZone": "Athens", 
            "ID": 2043022085984, 
            "CreatedAt": "2019-01-20T09:06:33Z"
        }, 
        {
            "Name": "Clarice Boone", 
            "Language": "en", 
            "ID": 2043022085990, 
            "UpdatedAt": "2019-01-20T09:06:34Z", 
            "TimeZone": "Athens", 
            "Email": "clboone@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:34Z"
        }, 
        {
            "Name": "Emily Dean", 
            "Language": "en", 
            "ID": 2043022085989, 
            "UpdatedAt": "2019-01-20T09:06:34Z", 
            "TimeZone": "Athens", 
            "Email": "emily.dean@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:34Z"
        }, 
        {
            "Name": "Finch Hoot", 
            "Language": "en", 
            "ID": 2043022085991, 
            "UpdatedAt": "2019-01-20T09:06:34Z", 
            "TimeZone": "Athens", 
            "Email": "finchhoot1@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:34Z"
        }, 
        {
            "Name": "James Dean", 
            "Language": "en", 
            "ID": 2043022085977, 
            "UpdatedAt": "2019-01-20T09:06:32Z", 
            "TimeZone": "Athens", 
            "Email": "james@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:32Z"
        }, 
        {
            "Name": "Jeffrey Collins", 
            "Language": "en", 
            "ID": 2043024010476, 
            "UpdatedAt": "2019-02-05T10:30:16Z", 
            "TimeZone": "Athens", 
            "Email": "jeffrey.collins@gmail.com", 
            "CreatedAt": "2019-02-05T10:30:16Z"
        }, 
        {
            "Name": "Joe Mathew", 
            "Language": "en", 
            "ID": 2043022085982, 
            "UpdatedAt": "2019-01-20T09:06:33Z", 
            "TimeZone": "Athens", 
            "Email": "joe.mathew@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:33Z"
        }, 
        {
            "Name": "Johnny Appleseed", 
            "Language": "en", 
            "ID": 2043022085986, 
            "UpdatedAt": "2019-01-20T09:06:33Z", 
            "TimeZone": "Athens", 
            "Email": "johnny.appleseed@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:33Z"
        }, 
        {
            "Name": "Lewis Clarke", 
            "Language": "en", 
            "ID": 2043022085987, 
            "UpdatedAt": "2019-01-20T09:06:33Z", 
            "TimeZone": "Athens", 
            "Email": "lewis.clarke@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:33Z"
        }, 
        {
            "Name": "Maria Von Trapp", 
            "Language": "en", 
            "ID": 2043022085988, 
            "UpdatedAt": "2019-01-20T09:06:33Z", 
            "TimeZone": "Athens", 
            "Email": "soundofmusic@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:33Z"
        }, 
        {
            "Name": "Mark Colbert", 
            "Language": "en", 
            "ID": 2043022085992, 
            "UpdatedAt": "2019-01-20T09:06:34Z", 
            "TimeZone": "Athens", 
            "Email": "mark.colbert@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:34Z"
        }, 
        {
            "Name": "Matt Rogers", 
            "Language": "en", 
            "ID": 2043022085980, 
            "UpdatedAt": "2019-01-20T09:06:32Z", 
            "TimeZone": "Athens", 
            "Email": "matt.rogers@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:32Z"
        }, 
        {
            "Name": "Pedro Martinez", 
            "ID": 2043023084321, 
            "UpdatedAt": "2019-01-28T14:16:49Z", 
            "TimeZone": "Athens", 
            "Email": "pedmart@gmail.com", 
            "CreatedAt": "2019-01-28T14:16:49Z"
        }, 
        {
            "Name": "Phileas Fogg", 
            "Language": "en", 
            "ID": 2043022085985, 
            "UpdatedAt": "2019-01-20T09:06:33Z", 
            "TimeZone": "Athens", 
            "Email": "aroundtheworld80@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:33Z"
        }, 
        {
            "Name": "Rachel Doe", 
            "Language": "en", 
            "ID": 2043022085978, 
            "Phone": "1 866 832 3090", 
            "UpdatedAt": "2019-01-20T09:06:32Z", 
            "TimeZone": "Athens", 
            "Email": "rachel@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:32Z"
        }, 
        {
            "Name": "Sam Kart", 
            "Language": "en", 
            "ID": 2043022085983, 
            "UpdatedAt": "2019-01-20T09:06:33Z", 
            "TimeZone": "Athens", 
            "Email": "sam.kart@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:33Z"
        }, 
        {
            "Name": "Sam Osborne", 
            "Language": "en", 
            "ID": 2043022085995, 
            "UpdatedAt": "2019-01-20T09:06:47Z", 
            "TimeZone": "Athens", 
            "Email": "sam.ozzy@freshdesk.com", 
            "CreatedAt": "2019-01-20T09:06:47Z"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="contacts-filtered-by-_updated_since-2018-01-19t020000z">Contacts Filtered by _updated_since: 2018-01-19T02:00:00Z</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 649px;">
<thead>
<tr>
<th style="width: 73px;">Name</th>
<th style="width: 77px;">Language</th>
<th style="width: 81px;">TwitterID</th>
<th style="width: 100px;">UpdatedAt</th>
<th style="width: 78px;">TimeZone</th>
<th style="width: 116px;">ID</th>
<th style="width: 103px;">CreatedAt</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 73px;">Bob Tree</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:51:11Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085984</td>
<td style="width: 103px;">2019-01-20T09:06:33Z</td>
</tr>
<tr>
<td style="width: 73px;">Clarice Boone</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:34Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085990</td>
<td style="width: 103px;">2019-01-20T09:06:34Z</td>
</tr>
<tr>
<td style="width: 73px;">Emily Dean</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:34Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085989</td>
<td style="width: 103px;">2019-01-20T09:06:34Z</td>
</tr>
<tr>
<td style="width: 73px;">Finch Hoot</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:34Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085991</td>
<td style="width: 103px;">2019-01-20T09:06:34Z</td>
</tr>
<tr>
<td style="width: 73px;">James Dean</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:32Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085977</td>
<td style="width: 103px;">2019-01-20T09:06:32Z</td>
</tr>
<tr>
<td style="width: 73px;">Jeffrey Collins</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-02-05T10:30:16Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043024010476</td>
<td style="width: 103px;">2019-02-05T10:30:16Z</td>
</tr>
<tr>
<td style="width: 73px;">Joe Mathew</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:33Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085982</td>
<td style="width: 103px;">2019-01-20T09:06:33Z</td>
</tr>
<tr>
<td style="width: 73px;">Johnny Appleseed</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:33Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085986</td>
<td style="width: 103px;">2019-01-20T09:06:33Z</td>
</tr>
<tr>
<td style="width: 73px;">Lewis Clarke</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:33Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085987</td>
<td style="width: 103px;">2019-01-20T09:06:33Z</td>
</tr>
<tr>
<td style="width: 73px;">Maria Von Trapp</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:33Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085988</td>
<td style="width: 103px;">2019-01-20T09:06:33Z</td>
</tr>
<tr>
<td style="width: 73px;">Mark Colbert</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:34Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085992</td>
<td style="width: 103px;">2019-01-20T09:06:34Z</td>
</tr>
<tr>
<td style="width: 73px;">Matt Rogers</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:32Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085980</td>
<td style="width: 103px;">2019-01-20T09:06:32Z</td>
</tr>
<tr>
<td style="width: 73px;">Pedro Martinez</td>
<td style="width: 77px;"> </td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-28T14:16:49Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043023084321</td>
<td style="width: 103px;">2019-01-28T14:16:49Z</td>
</tr>
<tr>
<td style="width: 73px;">Phileas Fogg</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:33Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085985</td>
<td style="width: 103px;">2019-01-20T09:06:33Z</td>
</tr>
<tr>
<td style="width: 73px;">Rachel Doe</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:32Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085978</td>
<td style="width: 103px;">2019-01-20T09:06:32Z</td>
</tr>
<tr>
<td style="width: 73px;">Sam Kart</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:33Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085983</td>
<td style="width: 103px;">2019-01-20T09:06:33Z</td>
</tr>
<tr>
<td style="width: 73px;">Sam Osborne</td>
<td style="width: 77px;">en</td>
<td style="width: 81px;"> </td>
<td style="width: 100px;">2019-01-20T09:06:47Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 116px;">2043022085995</td>
<td style="width: 103px;">2019-01-20T09:06:47Z</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-contact-details">5. Get contact details</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>View a contact’s details specified by the ID number.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-get-contact</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 139px;"><strong>Argument Name</strong></th>
<th style="width: 530px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">id</td>
<td style="width: 530px;">ID of the contact you wish to view the details of. To find ID numbers for your contacts try executing the <code>fd-list-contacts</code> command.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">mobile</td>
<td style="width: 530px;">Mobile number of the contact you wish to view the details of</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">email</td>
<td style="width: 530px;">Email address of the contact you wish to view the details of</td>
<td style="width: 71px;">Optional</td>
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
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 258px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 415px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 258px;">Freshdesk.Contact.Active</td>
<td style="width: 67px;">Boolean</td>
<td style="width: 415px;">Set to true if the contact has been verified</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.Address</td>
<td style="width: 67px;">String</td>
<td style="width: 415px;">Address of the contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.CompanyID</td>
<td style="width: 67px;">Number</td>
<td style="width: 415px;">ID of the primary company to which this contact belongs</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.ViewAllTickets</td>
<td style="width: 67px;">Boolean</td>
<td style="width: 415px;">Set to true if the contact can see all tickets that are associated with the company to which s/he belong</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.Deleted</td>
<td style="width: 67px;">Boolean</td>
<td style="width: 415px;">Set to true if the contact has been deleted</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.Description</td>
<td style="width: 67px;">String</td>
<td style="width: 415px;">A short description of the contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.Email</td>
<td style="width: 67px;">String</td>
<td style="width: 415px;">Primary email address of the contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.Id</td>
<td style="width: 67px;">Number</td>
<td style="width: 415px;">ID of the contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.JobTitle</td>
<td style="width: 67px;">String</td>
<td style="width: 415px;">Job Title of the contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.Language</td>
<td style="width: 67px;">String</td>
<td style="width: 415px;">Language of the contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.Mobile</td>
<td style="width: 67px;">Number</td>
<td style="width: 415px;">Mobile number of the contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.Name</td>
<td style="width: 67px;">String</td>
<td style="width: 415px;">Name of the contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.Phone</td>
<td style="width: 67px;">Number</td>
<td style="width: 415px;">Telephone number of the contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.Tag</td>
<td style="width: 67px;">Unknown</td>
<td style="width: 415px;">Tags associated with this contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.TimeZone</td>
<td style="width: 67px;">String</td>
<td style="width: 415px;">Time zone in which the contact resides</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.TwitterID</td>
<td style="width: 67px;">String</td>
<td style="width: 415px;">Twitter handle of the contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.UniqueExternalID</td>
<td style="width: 67px;">String</td>
<td style="width: 415px;">External ID of the contact</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.CreatedAt</td>
<td style="width: 67px;">Date</td>
<td style="width: 415px;">Contact creation timestamp</td>
</tr>
<tr>
<td style="width: 258px;">Freshdesk.Contact.UpdatedAt</td>
<td style="width: 67px;">Date</td>
<td style="width: 415px;">Contact updated timestamp</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!fd-get-contact id=2043022085984</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-4">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Contact": {
        "Name": "Bob Tree", 
        "Language": "en", 
        "CompanyID": 44000302032, 
        "Mobile": "+972501231231", 
        "JobTitle": "Security Researcher", 
        "UpdatedAt": "2019-01-20T09:51:11Z", 
        "UniqueExternalID": "12345", 
        "Email": "bob.tree@freshdesk.com", 
        "Phone": "+972501231231", 
        "Tag": [
            "security"
        ], 
        "Address": "Rothchild 45", 
        "TimeZone": "Athens", 
        "ID": 2043022085984, 
        "CreatedAt": "2019-01-20T09:06:33Z"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="viewing-contact-2043022085984">Viewing Contact #2043022085984</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 1419px;">
<thead>
<tr>
<th style="width: 66px;">Address</th>
<th style="width: 77px;">Language</th>
<th style="width: 98px;">CompanyID</th>
<th style="width: 122px;">Mobile</th>
<th style="width: 76px;">JobTitle</th>
<th style="width: 141px;">UniqueExternalID</th>
<th style="width: 116px;">ID</th>
<th style="width: 119px;">Phone</th>
<th style="width: 56px;">Tag</th>
<th style="width: 103px;">UpdatedAt</th>
<th style="width: 78px;">TimeZone</th>
<th style="width: 176px;">Email</th>
<th style="width: 103px;">CreatedAt</th>
<th style="width: 46px;">Name</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 66px;">Rothchild 45</td>
<td style="width: 77px;">en</td>
<td style="width: 98px;">44000302032</td>
<td style="width: 122px;">+972501231231</td>
<td style="width: 76px;">Security Researcher</td>
<td style="width: 141px;">12345</td>
<td style="width: 116px;">2043022085984</td>
<td style="width: 119px;">+972501231231</td>
<td style="width: 56px;">security</td>
<td style="width: 103px;">2019-01-20T09:51:11Z</td>
<td style="width: 78px;">Athens</td>
<td style="width: 176px;"><a href="mailto:bob.tree@freshdesk.com">bob.tree@freshdesk.com</a></td>
<td style="width: 103px;">2019-01-20T09:06:33Z</td>
<td style="width: 46px;">Bob Tree</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-all-canned-responst-folders">6. Get a list of all canned response folders</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of all canned response folders (only users with Admin privileges).</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-list-canned-response-folders</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<p>There is no input for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 283px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 388px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 283px;">Freshdesk.CRFolder.ID</td>
<td style="width: 69px;">Number</td>
<td style="width: 388px;">Unique ID of the canned response folder</td>
</tr>
<tr>
<td style="width: 283px;">Freshdesk.CRFolder.Name</td>
<td style="width: 69px;">String</td>
<td style="width: 388px;">Name of the canned response folder</td>
</tr>
<tr>
<td style="width: 283px;">Freshdesk.CRFolder.Personal</td>
<td style="width: 69px;">Boolean</td>
<td style="width: 388px;">Set true if the folder can only be accessed by you</td>
</tr>
<tr>
<td style="width: 283px;">Freshdesk.CRFolder.ResponsesCount</td>
<td style="width: 69px;">Number</td>
<td style="width: 388px;">Number of canned responses in the folder</td>
</tr>
<tr>
<td style="width: 283px;">Freshdesk.CRFolder.CreatedAt</td>
<td style="width: 69px;">Date</td>
<td style="width: 388px;">Canned Response Folder’s creation timestamp</td>
</tr>
<tr>
<td style="width: 283px;">Freshdesk.CRFolder.UpdatedAt</td>
<td style="width: 69px;">Date</td>
<td style="width: 388px;">Canned Response Folder’s updated timestamp</td>
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
<pre>!fd-list-canned-response-folders</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-5">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.CRFolder": [
        {
            "Personal": true, 
            "ResponsesCount": 1, 
            "ID": 2043000174274, 
            "Name": "Personal"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="all-canned-response-folders">All Canned Response Folders</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 387px;">
<thead>
<tr>
<th style="width: 70px;">Personal</th>
<th style="width: 59px;">Name</th>
<th style="width: 116px;">ID</th>
<th style="width: 130px;">ResponsesCount</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 70px;">true</td>
<td style="width: 59px;">Personal</td>
<td style="width: 116px;">2043000174274</td>
<td style="width: 130px;">1</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-details-for-all-canned-responses-in-a-folder">7. Get a list of details for all canned responses in a folder</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of details for all canned responses in a folder.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-get-canned-response-folder</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 140px;"><strong>Argument Name</strong></th>
<th style="width: 529px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 140px;">id</td>
<td style="width: 529px;">ID of the Folder containing the Canned Responses you wish to view the details of. To find ID numbers for your Canned Response folders try executing the <code>fd-list-canned-response-folders</code> command.</td>
<td style="width: 71px;">Required</td>
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
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 363px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 319px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 363px;">Freshdesk.CRFolder.CR.ID</td>
<td style="width: 58px;">Number</td>
<td style="width: 319px;">Unique ID of the canned response</td>
</tr>
<tr>
<td style="width: 363px;">Freshdesk.CRFolder.CR.Title</td>
<td style="width: 58px;">String</td>
<td style="width: 319px;">Title of the canned response</td>
</tr>
<tr>
<td style="width: 363px;">Freshdesk.CRFolder.CR.FolderID</td>
<td style="width: 58px;">Number</td>
<td style="width: 319px;">ID of the containing folder</td>
</tr>
<tr>
<td style="width: 363px;">Freshdesk.CRFolder.CR.Content</td>
<td style="width: 58px;">String</td>
<td style="width: 319px;">Plaintext version of the canned response content</td>
</tr>
<tr>
<td style="width: 363px;">Freshdesk.CRFolder.CR.ContentHTML</td>
<td style="width: 58px;">String</td>
<td style="width: 319px;">HTML version of the canned response content</td>
</tr>
<tr>
<td style="width: 363px;">Freshdesk.CRFolder.CR.Attachment.AttachmentURL</td>
<td style="width: 58px;">String</td>
<td style="width: 319px;">URL to download the file attached to the ticket to your local machine</td>
</tr>
<tr>
<td style="width: 363px;">Freshdesk.CRFolder.CR.Attachment.Name</td>
<td style="width: 58px;">String</td>
<td style="width: 319px;">The name of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 363px;">Freshdesk.CRFolder.CR.Attachment.ContentType</td>
<td style="width: 58px;">String</td>
<td style="width: 319px;">Content type of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 363px;">Freshdesk.CRFolder.CR.Attachment.ID</td>
<td style="width: 58px;">Number</td>
<td style="width: 319px;">ID number for the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 363px;">Freshdesk.CRFolder.CR.Attachment.Size</td>
<td style="width: 58px;">Number</td>
<td style="width: 319px;">Size of the file attached to the file</td>
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
<pre>!fd-get-canned-response-folder id=2043000174274</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-6">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.CRFolder": [
        {
            "Content": "Thank you for reaching out to us. Our team will look into your request and get back to you shortly. \n       \n       \n      You can check the status of your request and add comments here:\n       \n      {{ticket.url}}\n       \n       \n      Regards, \n      {{ticket.agent.name}}", 
            "FolderID": 2043000174274, 
            "ContentHTML": "&lt;div dir=\"ltr\"&gt;\n      Thank you for reaching out to us. Our team will look into your request and get back to you shortly. \n      &lt;br&gt;\n      &lt;br&gt;\n      You can check the status of your request and add comments here:\n      &lt;br&gt;\n      {{ticket.url}}\n      &lt;br&gt;\n      &lt;br&gt;\n      Regards,&lt;br&gt;\n      {{ticket.agent.name}}\n    &lt;/div&gt;\n  ", 
            "ID": 2043000056698, 
            "Title": "We\u2019ve received your request"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="details-of-canned-responses-in-cr-folder-2043000174274">Details of Canned Responses in CR Folder #2043000174274</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 649px;">
<thead>
<tr>
<th style="width: 178px;">Content</th>
<th style="width: 112px;">FolderID</th>
<th style="width: 168px;">ContentHTML</th>
<th style="width: 116px;">ID</th>
<th style="width: 60px;">Title</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 178px;">Thank you for reaching out to us. Our team will look into your request and get back to you shortly.<br> <br> <br> You can check the status of your request and add comments here:<br> <br> {{ticket.url}}<br> <br> <br> Regards,<br> {{ticket.agent.name}}</td>
<td style="width: 112px;">2043000174274</td>
<td style="width: 168px;">
<div dir="ltr">
<br> Thank you for reaching out to us. Our team will look into your request and get back to you shortly.<br> <br> <br> <br> <br> You can check the status of your request and add comments here:<br> <br> <br> {{ticket.url}}<br> <br> <br> <br> <br> Regards,<br> <br> {{ticket.agent.name}}</div>
</td>
<td style="width: 116px;">2043000056698</td>
<td style="width: 60px;">We’ve received your request</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-all-groups">8. Get a list of all groups</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of all groups.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-list-groups</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-7">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 253px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 429px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 253px;">Freshdesk.Group.AgentID</td>
<td style="width: 58px;">Unknown</td>
<td style="width: 429px;">Array of agent user IDs separated by commas</td>
</tr>
<tr>
<td style="width: 253px;">Freshdesk.Group.AutoTicketAssign</td>
<td style="width: 58px;">Boolean</td>
<td style="width: 429px;">Set to true when automatic ticket assignment was enabled. Automatic ticket assignment is only available on certain plans</td>
</tr>
<tr>
<td style="width: 253px;">Freshdesk.Group.BusinessHourID</td>
<td style="width: 58px;">Number</td>
<td style="width: 429px;">Unique ID of the business hour associated with the group</td>
</tr>
<tr>
<td style="width: 253px;">Freshdesk.Group.Description</td>
<td style="width: 58px;">String</td>
<td style="width: 429px;">Description of the group</td>
</tr>
<tr>
<td style="width: 253px;">Freshdesk.Group.EscalateTo</td>
<td style="width: 58px;">Number</td>
<td style="width: 429px;">The ID of the user that an escalation email is sent to if a ticket is unassigned</td>
</tr>
<tr>
<td style="width: 253px;">Freshdesk.Group.ID</td>
<td style="width: 58px;">Number</td>
<td style="width: 429px;">Unique ID of the group</td>
</tr>
<tr>
<td style="width: 253px;">Freshdesk.Group.Name</td>
<td style="width: 58px;">String</td>
<td style="width: 429px;">Name of the group</td>
</tr>
<tr>
<td style="width: 253px;">Freshdesk.Group.UnassignedFor</td>
<td style="width: 58px;">String</td>
<td style="width: 429px;">The time after which an escalation email is sent if a ticket remains unassigned</td>
</tr>
<tr>
<td style="width: 253px;">Freshdesk.Group.CreatedAt</td>
<td style="width: 58px;">Date</td>
<td style="width: 429px;">Group creation timestamp</td>
</tr>
<tr>
<td style="width: 253px;">Freshdesk.Group.UpdatedAt</td>
<td style="width: 58px;">Date</td>
<td style="width: 429px;">Grup updated timestamp</td>
</tr>
<tr>
<td style="width: 253px;">Freshdesk.Group.GroupType</td>
<td style="width: 58px;">String</td>
<td style="width: 429px;">Group Type of the group</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-7">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!fd-list-groups</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-7">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Group": [
        {
            "GroupType": "support_agent_group", 
            "Name": "Account managers", 
            "UpdatedAt": "2019-01-20T09:06:49Z", 
            "ID": 2043000867330, 
            "CreatedAt": "2019-01-20T09:06:49Z", 
            "Description": "Account managers"
        }, 
        {
            "GroupType": "support_agent_group", 
            "Name": "Billing", 
            "UpdatedAt": "2019-01-20T09:06:31Z", 
            "ID": 2043000867325, 
            "CreatedAt": "2019-01-20T09:06:31Z", 
            "Description": "Members of the Billing team belong to this group"
        }, 
        {
            "GroupType": "support_agent_group", 
            "Name": "Customer Support", 
            "UpdatedAt": "2019-01-20T09:06:47Z", 
            "ID": 2043000867327, 
            "CreatedAt": "2019-01-20T09:06:47Z", 
            "Description": "Customer Support"
        }, 
        {
            "GroupType": "support_agent_group", 
            "Name": "Development", 
            "UpdatedAt": "2019-01-20T09:06:49Z", 
            "ID": 2043000867329, 
            "CreatedAt": "2019-01-20T09:06:49Z", 
            "Description": "Development"
        }, 
        {
            "GroupType": "support_agent_group", 
            "Name": "Escalations", 
            "UpdatedAt": "2019-01-20T09:06:31Z", 
            "ID": 2043000867326, 
            "CreatedAt": "2019-01-20T09:06:31Z", 
            "Description": "Team to handle Customer escalations"
        }, 
        {
            "GroupType": "support_agent_group", 
            "Name": "Login and security", 
            "UpdatedAt": "2019-01-20T09:06:47Z", 
            "ID": 2043000867328, 
            "CreatedAt": "2019-01-20T09:06:47Z", 
            "Description": "Login and security"
        }, 
        {
            "GroupType": "support_agent_group", 
            "Name": "Product Management", 
            "UpdatedAt": "2019-01-20T09:06:31Z", 
            "ID": 2043000867322, 
            "CreatedAt": "2019-01-20T09:06:31Z", 
            "Description": "Product Management group"
        }, 
        {
            "GroupType": "support_agent_group", 
            "Name": "QA", 
            "UpdatedAt": "2019-01-20T09:06:31Z", 
            "ID": 2043000867323, 
            "CreatedAt": "2019-01-20T09:06:31Z", 
            "Description": "Members of the QA team belong to this group"
        }, 
        {
            "GroupType": "support_agent_group", 
            "Name": "Sales", 
            "UpdatedAt": "2019-01-20T09:06:31Z", 
            "ID": 2043000867324, 
            "CreatedAt": "2019-01-20T09:06:31Z", 
            "Description": "People in the Sales team are members of this group"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-7">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="all-groups">All Groups</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 681px;">
<thead>
<tr>
<th style="width: 156px;">GroupType</th>
<th style="width: 91px;">Description</th>
<th style="width: 103px;">UpdatedAt</th>
<th style="width: 116px;">ID</th>
<th style="width: 103px;">CreatedAt</th>
<th style="width: 94px;">Name</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 156px;">support_agent_group</td>
<td style="width: 91px;">Account managers</td>
<td style="width: 103px;">2019-01-20T09:06:49Z</td>
<td style="width: 116px;">2043000867330</td>
<td style="width: 103px;">2019-01-20T09:06:49Z</td>
<td style="width: 94px;">Account managers</td>
</tr>
<tr>
<td style="width: 156px;">support_agent_group</td>
<td style="width: 91px;">Members of the Billing team belong to this group</td>
<td style="width: 103px;">2019-01-20T09:06:31Z</td>
<td style="width: 116px;">2043000867325</td>
<td style="width: 103px;">2019-01-20T09:06:31Z</td>
<td style="width: 94px;">Billing</td>
</tr>
<tr>
<td style="width: 156px;">support_agent_group</td>
<td style="width: 91px;">Customer Support</td>
<td style="width: 103px;">2019-01-20T09:06:47Z</td>
<td style="width: 116px;">2043000867327</td>
<td style="width: 103px;">2019-01-20T09:06:47Z</td>
<td style="width: 94px;">Customer Support</td>
</tr>
<tr>
<td style="width: 156px;">support_agent_group</td>
<td style="width: 91px;">Development</td>
<td style="width: 103px;">2019-01-20T09:06:49Z</td>
<td style="width: 116px;">2043000867329</td>
<td style="width: 103px;">2019-01-20T09:06:49Z</td>
<td style="width: 94px;">Development</td>
</tr>
<tr>
<td style="width: 156px;">support_agent_group</td>
<td style="width: 91px;">Team to handle Customer escalations</td>
<td style="width: 103px;">2019-01-20T09:06:31Z</td>
<td style="width: 116px;">2043000867326</td>
<td style="width: 103px;">2019-01-20T09:06:31Z</td>
<td style="width: 94px;">Escalations</td>
</tr>
<tr>
<td style="width: 156px;">support_agent_group</td>
<td style="width: 91px;">Login and security</td>
<td style="width: 103px;">2019-01-20T09:06:47Z</td>
<td style="width: 116px;">2043000867328</td>
<td style="width: 103px;">2019-01-20T09:06:47Z</td>
<td style="width: 94px;">Login and security</td>
</tr>
<tr>
<td style="width: 156px;">support_agent_group</td>
<td style="width: 91px;">Product Management group</td>
<td style="width: 103px;">2019-01-20T09:06:31Z</td>
<td style="width: 116px;">2043000867322</td>
<td style="width: 103px;">2019-01-20T09:06:31Z</td>
<td style="width: 94px;">Product Management</td>
</tr>
<tr>
<td style="width: 156px;">support_agent_group</td>
<td style="width: 91px;">Members of the QA team belong to this group</td>
<td style="width: 103px;">2019-01-20T09:06:31Z</td>
<td style="width: 116px;">2043000867323</td>
<td style="width: 103px;">2019-01-20T09:06:31Z</td>
<td style="width: 94px;">QA</td>
</tr>
<tr>
<td style="width: 156px;">support_agent_group</td>
<td style="width: 91px;">People in the Sales team are members of this group</td>
<td style="width: 103px;">2019-01-20T09:06:31Z</td>
<td style="width: 116px;">2043000867324</td>
<td style="width: 103px;">2019-01-20T09:06:31Z</td>
<td style="width: 94px;">Sales</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="add-a-reply-to-a-ticket">9. Add a reply to a ticket</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds a reply to a specified ticket.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-8">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-ticket-reply</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-8">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 518px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">ticket_id</td>
<td style="width: 518px;">ID of the ticket to add a reply to</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">body</td>
<td style="width: 518px;">Content of the reply (in HTML format)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">from_email</td>
<td style="width: 518px;">The email address from which the reply is sent. By default, the global support email is used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">user_id</td>
<td style="width: 518px;">ID of the agent who is adding the reply to the ticket</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">cc_emails</td>
<td style="width: 518px;">CSV list of email addresses to add to the ‘cc’ field of the outgoing ticket email, e.g., "example1@gmail.com,example2@gmail.com"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">bcc_emails</td>
<td style="width: 518px;">CSV list of email addresses to add to the ‘bcc’ field of the outgoing ticket email, e.g., "example1@gmail.com,example2@gmail.com"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">attachments</td>
<td style="width: 518px;">CSV list of Entry IDs of files to attach to the reply, e.g., “468@73f988d1-bda2-4adc-8e02-926f02190070,560@73f988d1-bda2-4adc-8e02-926f02190070”. The total size of these attachments cannot exceed 15MB.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-8">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 403px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 257px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.BodyHTML</td>
<td style="width: 80px;">String</td>
<td style="width: 257px;">Content of the conversation (in HTML format)</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.BodyText</td>
<td style="width: 80px;">String</td>
<td style="width: 257px;">Content of the conversation (in plain text format)</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.ID</td>
<td style="width: 80px;">Number</td>
<td style="width: 257px;">ID of the conversation</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.Incoming</td>
<td style="width: 80px;">Boolean</td>
<td style="width: 257px;">Set to true when a particular conversation should appear as being created outside of the web portal</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.ToEmail</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 257px;">Array of email addresses of agents/users who need to be notified about this conversation</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.Private</td>
<td style="width: 80px;">Boolean</td>
<td style="width: 257px;">Set to true if the note is private</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.Source</td>
<td style="width: 80px;">Number</td>
<td style="width: 257px;">Denotes the type of conversation</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.SupportEmail</td>
<td style="width: 80px;">String</td>
<td style="width: 257px;">Email address from which the reply is sent. For notes</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.TicketID</td>
<td style="width: 80px;">Number</td>
<td style="width: 257px;">ID of the ticket that the conversation was added to</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.UserID</td>
<td style="width: 80px;">Number</td>
<td style="width: 257px;">ID of the agent/user who added the conversation</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.CreatedAt</td>
<td style="width: 80px;">Date</td>
<td style="width: 257px;">Conversation creation timestamp</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.UpdatedAt</td>
<td style="width: 80px;">Date</td>
<td style="width: 257px;">Conversation updated timestamp</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.FromEmail</td>
<td style="width: 80px;">String</td>
<td style="width: 257px;">The email address that the reply was sent from. By default</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.Attachment.AttachmentURL</td>
<td style="width: 80px;">String</td>
<td style="width: 257px;">URL of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.Attachment.Name</td>
<td style="width: 80px;">String</td>
<td style="width: 257px;">The name of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.Attachment.ContentType</td>
<td style="width: 80px;">String</td>
<td style="width: 257px;">Content type of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.Attachment.ID</td>
<td style="width: 80px;">Number</td>
<td style="width: 257px;">ID number of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 403px;">Freshdesk.Ticket.Conversation.Attachment.Size</td>
<td style="width: 80px;">Number</td>
<td style="width: 257px;">Size of the file attached to the ticket</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-8">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!fd-ticket-reply ticket_id=108 body="Demonstrating the Ticket Reply Command" attachments=2@5a0be47f-748f-4d60-8f46-81feb8f0c438 cc_emails=example1@gmail.com,example2@gmail.com,example3@gmail.com</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-8">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Ticket": {
        "Conversation": {
            "BodyText": "Demonstrating the Ticket Reply Command", 
            "UserID": 2043022085976, 
            "Attachment": [
                {
                    "Name": "sample_attachment.md", 
                    "Size": 76, 
                    "ContentType": "application/octet-stream", 
                    "ID": 2043010708409, 
                    "AttachmentURL": "https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708409/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155542Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=9b19a5795e98af94f5b878a62db473b943986d59496e91f046ab4368b0b4f461&amp;X-Amz-SignedHeaders=Host"
                }
            ], 
            "UpdatedAt": "2019-02-05T15:55:42Z", 
            "AdditionalFields": {
                "CCEmail": [
                    "example1@gmail.com", 
                    "example2@gmail.com", 
                    "example3@gmail.com"
                ], 
                "BodyHTML": "&lt;div&gt;Demonstrating the Ticket Reply Command&lt;/div&gt;", 
                "ToEmail": [
                    "example@gmail.com"
                ], 
                "TicketID": 108, 
                "FromEmail": "Demisto &lt;support@demistohelp.freshdesk.com&gt;"
            }, 
            "ID": 44007154227, 
            "CreatedAt": "2019-02-05T15:55:42Z"
        }, 
        "ID": 108
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-8">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="reply-to-ticket-108">Reply to Ticket #108</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 1966px;">
<thead>
<tr>
<th style="width: 105px;">BodyText</th>
<th style="width: 120px;">UserID</th>
<th style="width: 1092px;">Attachment</th>
<th style="width: 103px;">UpdatedAt</th>
<th style="width: 324px;">AdditionalFields</th>
<th style="width: 98px;">ID</th>
<th style="width: 103px;">CreatedAt</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 105px;">Demonstrating the Ticket Reply Command</td>
<td style="width: 120px;">2043022085976</td>
<td style="width: 1092px;">ID: 2043010708409, Size: 76, ContentType: application/octet-stream, Name: sample_attachment.md, AttachmentURL: <a href="https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708409/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155542Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=9b19a5795e98af94f5b878a62db473b943986d59496e91f046ab4368b0b4f461&amp;X-Amz-SignedHeaders=Host">https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708409/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155542Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=9b19a5795e98af94f5b878a62db473b943986d59496e91f046ab4368b0b4f461&amp;X-Amz-SignedHeaders=Host</a>
</td>
<td style="width: 103px;">2019-02-05T15:55:42Z</td>
<td style="width: 324px;">CCEmail: <a href="mailto:example1@gmail.com">example1@gmail.com</a>,<br> <a href="mailto:example2@gmail.com">example2@gmail.com</a>,<br> <a href="mailto:example3@gmail.com">example3@gmail.com</a><br> TicketID: 108<br> BodyHTML:
<div>Demonstrating the Ticket Reply Command</div>
<br> ToEmail: <a href="mailto:example@gmail.com">example@gmail.com</a><br> FromEmail: Demisto <a href="mailto:support@demistohelp.freshdesk.com">support@demistohelp.freshdesk.com</a>
</td>
<td style="width: 98px;">44007154227</td>
<td style="width: 103px;">2019-02-05T15:55:42Z</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-all-replies-and-notes-for-a-ticket">10. Get a list of all replies and notes for a ticket</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of all replies and notes for a specified ticket.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-9">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-get-ticket-conversations</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-9">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 512px;"><strong>Description</strong></th>
<th style="width: 77px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">ticket_id</td>
<td style="width: 512px;">ID of the ticket that you want to list all conversations for</td>
<td style="width: 77px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-9">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 412px;"><strong>Path</strong></th>
<th style="width: 71px;"><strong>Type</strong></th>
<th style="width: 257px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.BodyHTML</td>
<td style="width: 71px;">String</td>
<td style="width: 257px;">Content of the conversation (in HTML format)</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.BodyText</td>
<td style="width: 71px;">String</td>
<td style="width: 257px;">Content of the conversation (in plain text format)</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.ID</td>
<td style="width: 71px;">Number</td>
<td style="width: 257px;">ID of the conversation</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.Incoming</td>
<td style="width: 71px;">Boolean</td>
<td style="width: 257px;">Set to true when a particular conversation should appear as being created outside of the web portal</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.ToEmail</td>
<td style="width: 71px;">Unknown</td>
<td style="width: 257px;">Array of email addresses of agents/users who need to be notified about this conversation</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.Private</td>
<td style="width: 71px;">Boolean</td>
<td style="width: 257px;">Set to true if the note is private</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.Source</td>
<td style="width: 71px;">Number</td>
<td style="width: 257px;">Denotes the type of conversation</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.SupportEmail</td>
<td style="width: 71px;">String</td>
<td style="width: 257px;">Email address from which the reply is sent. For notes</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.TicketID</td>
<td style="width: 71px;">Number</td>
<td style="width: 257px;">ID of the ticket that the conversation was added to</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.UserID</td>
<td style="width: 71px;">Number</td>
<td style="width: 257px;">ID of the agent/user who added the conversation</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.CreatedAt</td>
<td style="width: 71px;">Date</td>
<td style="width: 257px;">Conversation creation timestamp</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.UpdatedAt</td>
<td style="width: 71px;">Date</td>
<td style="width: 257px;">Conversation updated timestamp</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.FromEmail</td>
<td style="width: 71px;">String</td>
<td style="width: 257px;">The email address that the reply was sent from. By default</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.Attachment.AttachmentURL</td>
<td style="width: 71px;">String</td>
<td style="width: 257px;">URL of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.Attachment.Name</td>
<td style="width: 71px;">String</td>
<td style="width: 257px;">The name of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.Attachment.ContentType</td>
<td style="width: 71px;">String</td>
<td style="width: 257px;">Content type of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.Attachment.ID</td>
<td style="width: 71px;">Number</td>
<td style="width: 257px;">ID number of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 412px;">Freshdesk.Ticket.Conversation.Attachment.Size</td>
<td style="width: 71px;">Number</td>
<td style="width: 257px;">Size of the file attached to the ticket</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-9">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!fd-get-ticket-conversations ticket_id=108</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-9">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Ticket": {
        "Conversation": [
            {
                "Category": 3, 
                "BodyText": "Demonstrating the Ticket Reply Command", 
                "UserID": 2043022085976, 
                "Attachment": [
                    {
                        "Name": "sample_attachment.md", 
                        "Size": 76, 
                        "ContentType": "application/octet-stream", 
                        "ID": 2043010708409, 
                        "AttachmentURL": "https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708409/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155543Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=f26a2ab003aa5a9a0862389ae1c4a44470bf06ba0acd0e60c742ca164c16dff2&amp;X-Amz-SignedHeaders=Host"
                    }
                ], 
                "UpdatedAt": "2019-02-05T15:55:42Z", 
                "AdditionalFields": {
                    "TicketID": 108, 
                    "CCEmail": [
                        "example1@gmail.com", 
                        "example2@gmail.com", 
                        "example3@gmail.com"
                    ], 
                    "BodyHTML": "&lt;div&gt;Demonstrating the Ticket Reply Command&lt;/div&gt;", 
                    "ToEmail": [
                        "example@gmail.com"
                    ], 
                    "FromEmail": "Demisto &lt;support@demistohelp.freshdesk.com&gt;", 
                    "SupportEmail": "support@demistohelp.freshdesk.com"
                }, 
                "ID": 44007154227, 
                "CreatedAt": "2019-02-05T15:55:42Z"
            }
        ], 
        "ID": 108
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-9">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="conversations-of-ticket-108">Conversations of Ticket #108</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 2083px;">
<thead>
<tr>
<th style="width: 71px;">Category</th>
<th style="width: 105px;">BodyText</th>
<th style="width: 120px;">UserID</th>
<th style="width: 1092px;">Attachment</th>
<th style="width: 103px;">UpdatedAt</th>
<th style="width: 367px;">AdditionalFields</th>
<th style="width: 98px;">ID</th>
<th style="width: 103px;">CreatedAt</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 71px;">3</td>
<td style="width: 105px;">Demonstrating the Ticket Reply Command</td>
<td style="width: 120px;">2043022085976</td>
<td style="width: 1092px;">ID: 2043010708409, Size: 76, ContentType: application/octet-stream, Name: sample_attachment.md, AttachmentURL: <a href="https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708409/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155543Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=f26a2ab003aa5a9a0862389ae1c4a44470bf06ba0acd0e60c742ca164c16dff2&amp;X-Amz-SignedHeaders=Host">https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708409/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155543Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=f26a2ab003aa5a9a0862389ae1c4a44470bf06ba0acd0e60c742ca164c16dff2&amp;X-Amz-SignedHeaders=Host</a>
</td>
<td style="width: 103px;">2019-02-05T15:55:42Z</td>
<td style="width: 367px;">FromEmail: Demisto <a href="mailto:support@demistohelp.freshdesk.com">support@demistohelp.freshdesk.com</a><br> BodyHTML:
<div>Demonstrating the Ticket Reply Command</div>
<br> SupportEmail: <a href="mailto:support@demistohelp.freshdesk.com">support@demistohelp.freshdesk.com</a><br> CCEmail: <a href="mailto:example1@gmail.com">example1@gmail.com</a>,<br> <a href="mailto:example2@gmail.com">example2@gmail.com</a>,<br> <a href="mailto:example3@gmail.com">example3@gmail.com</a><br> TicketID: 108<br> ToEmail: <a href="mailto:example@gmail.com">example@gmail.com</a>
</td>
<td style="width: 98px;">44007154227</td>
<td style="width: 103px;">2019-02-05T15:55:42Z</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-all-agents">11. Get a list of all agents</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of agents that match the filter criteria.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-10">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-list-agents</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-10">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">mobile</td>
<td style="width: 526px;">Mobile phone number to filter agents by. Enter the number without dashes or spaces between the numbers.<br> Numbers should be entered as they appear in your Freshdesk web portal. If the number appears in your web portal with a plus sign and country code, then that is how you should enter here, e.g., ‘+972501231231’.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">phone</td>
<td style="width: 526px;">Telephone number to filter agents by. Enter the number without dashes or spaces between the numbers.<br> Numbers should be entered as they appear in your Freshdesk web portal. If the number appears in your web portal with a plus sign and country code, then that is how you should enter it here, e.g., ‘+972501231231’.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">state</td>
<td style="width: 526px;">List all agents who are either ‘fulltime’ or ‘occasional’</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-10">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 266px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 410px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Available</td>
<td style="width: 64px;">Boolean</td>
<td style="width: 410px;">Set to <code>true</code> when the agent is in a group that has enabled “Automatic Ticket Assignment” and is accepting new tickets</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.AvailableSince</td>
<td style="width: 64px;">Date</td>
<td style="width: 410px;">Timestamp that denotes when the agent became available/unavailable (depending on the value of the ‘available’ attribute)</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.ID</td>
<td style="width: 64px;">Number</td>
<td style="width: 410px;">User ID of the agent</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Occasional</td>
<td style="width: 64px;">Boolean</td>
<td style="width: 410px;">Set to true when the agent is an occasional agent (true =&gt; occasional</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Signature</td>
<td style="width: 64px;">String</td>
<td style="width: 410px;">Signature of the agent (in HTML format)</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.TicketScope</td>
<td style="width: 64px;">Number</td>
<td style="width: 410px;">Ticket permission of the agent</td>
</tr>
<tr>
<td style="width: 266px;">(1 - Global Access, 2 - Group Access, 3 - Restricted Access)</td>
<td style="width: 64px;"> </td>
<td style="width: 410px;"> </td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.GroupID</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 410px;">Group IDs associated with the agent</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.RoleID</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 410px;">Role IDs associated with the agent</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.CreatedAt</td>
<td style="width: 64px;">Date</td>
<td style="width: 410px;">Agent creation timestamp</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.UpdatedAt</td>
<td style="width: 64px;">Date</td>
<td style="width: 410px;">Agent updated timestamp</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Contact.Active</td>
<td style="width: 64px;">Boolean</td>
<td style="width: 410px;">Set to true when the agent is verified</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Contact.Email</td>
<td style="width: 64px;">String</td>
<td style="width: 410px;">Email Address of the agent</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Contact.JobTitle</td>
<td style="width: 64px;">String</td>
<td style="width: 410px;">Job title of the agent</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Contact.Language</td>
<td style="width: 64px;">String</td>
<td style="width: 410px;">Language of the agent. Default language is “en”</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Contact.LastLoginAt</td>
<td style="width: 64px;">Date</td>
<td style="width: 410px;">Timestamp of the agent’s last successful login</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Contact.Mobile</td>
<td style="width: 64px;">Number</td>
<td style="width: 410px;">Mobile number of the agent</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Contact.Name</td>
<td style="width: 64px;">String</td>
<td style="width: 410px;">Name of the agent</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Contact.Phone</td>
<td style="width: 64px;">Number</td>
<td style="width: 410px;">Telephone number of the agent</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Contact.TimeZone</td>
<td style="width: 64px;">String</td>
<td style="width: 410px;">Time zone of the agent</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Contact.CreatedAt</td>
<td style="width: 64px;">Date</td>
<td style="width: 410px;">Contact creation timestamp</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Contact.UpdatedAt</td>
<td style="width: 64px;">Date</td>
<td style="width: 410px;">Contact updated timestamp</td>
</tr>
<tr>
<td style="width: 266px;">Freshdesk.Agent.Type</td>
<td style="width: 64px;">String</td>
<td style="width: 410px;">Type of agent</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-10">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!fd-list-agents state=fulltime</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-10">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Agent": [
        {
            "TicketScope": 1, 
            "Contact": {
                "Name": "Jeffrey Collins", 
                "Language": "en", 
                "LastLoginAt": "2019-01-23T09:05:34Z", 
                "Phone": "506912312", 
                "UpdatedAt": "2019-01-20T09:14:26Z", 
                "Active": true, 
                "TimeZone": "Athens", 
                "Email": "jeffrey.collins@gmail.com", 
                "CreatedAt": "2019-01-20T09:06:31Z"
            }, 
            "UpdatedAt": "2019-02-04T17:12:33Z", 
            "Type": "support_agent", 
            "ID": 2043022085976, 
            "CreatedAt": "2019-01-20T09:06:31Z"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-10">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="all-agents">All Agents</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 736px;">
<thead>
<tr>
<th style="width: 95px;">TicketScope</th>
<th style="width: 199px;">Contact</th>
<th style="width: 102px;">UpdatedAt</th>
<th style="width: 103px;">Type</th>
<th style="width: 116px;">ID</th>
<th style="width: 103px;">CreatedAt</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 95px;">1</td>
<td style="width: 199px;">Name: Jeffrey Collins<br> Language: en<br> LastLoginAt: 2019-01-23T09:05:34Z<br> Phone: 506912312<br> UpdatedAt: 2019-01-20T09:14:26Z<br> Active: true<br> TimeZone: Athens<br> Email: jeffrey.collins@gmail.com<br> CreatedAt: 2019-01-20T09:06:31Z</td>
<td style="width: 102px;">2019-02-04T17:12:33Z</td>
<td style="width: 103px;">support_agent</td>
<td style="width: 116px;">2043022085976</td>
<td style="width: 103px;">2019-01-20T09:06:31Z</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="create-a-note-for-a-ticket">12. Create a note for a ticket</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Creates a note for a specified ticket. By default, notes are private. To make a note public, set the ‘private’ argument to false.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-11">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-create-ticket-note</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-11">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 172px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 172px;">ticket_id</td>
<td style="width: 497px;">ID of the ticket to make a note for</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 172px;">body</td>
<td style="width: 497px;">Content of the note (in HTML format)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 172px;">private</td>
<td style="width: 497px;">Set to false if the note is public</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">user_id</td>
<td style="width: 497px;">ID of the agent who is adding the note.<br> To find agent ID numbers, run the ‘fd-list-agents’ command.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">notify_emails</td>
<td style="width: 497px;">CSV list of agent email addresses to be notify about this note, e.g., "example1@gmail.com,example2@gmail.com,example3@gmail.com"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">incoming</td>
<td style="width: 497px;">Set to true if a particular note should appear as being created outside of the web portal</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">attachments</td>
<td style="width: 497px;">CSV list of entry IDs of files to attach to the note, e.g., “468@73f988d1-bda2-4adc-8e02-926f02190070,560@73f988d1-bda2-4adc-8e02-926f02190070”. The total size of these attachments cannot exceed 15MB.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-11">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 418px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 257px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.BodyHTML</td>
<td style="width: 65px;">String</td>
<td style="width: 257px;">Content of the conversation (in HTML)</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.BodyText</td>
<td style="width: 65px;">String</td>
<td style="width: 257px;">Content of the conversation (in plain text)</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.ID</td>
<td style="width: 65px;">Number</td>
<td style="width: 257px;">ID of the conversation</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.Incoming</td>
<td style="width: 65px;">Boolean</td>
<td style="width: 257px;">Set to true when a particular conversation should appear as being created outside of the web portal</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.ToEmail</td>
<td style="width: 65px;">Unknown</td>
<td style="width: 257px;">List of agent/user email addresses of agents/users who need to be notified about this conversation</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.Private</td>
<td style="width: 65px;">Boolean</td>
<td style="width: 257px;">Is the conversation private</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.Source</td>
<td style="width: 65px;">Number</td>
<td style="width: 257px;">Conversation type</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.SupportEmail</td>
<td style="width: 65px;">String</td>
<td style="width: 257px;">Email address the reply is sent from. For notes</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.TicketID</td>
<td style="width: 65px;">Number</td>
<td style="width: 257px;">ID of the ticket the conversation was added to</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.UserID</td>
<td style="width: 65px;">Number</td>
<td style="width: 257px;">ID of the agent/user who added the conversation</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.CreatedAt</td>
<td style="width: 65px;">Date</td>
<td style="width: 257px;">Conversation creation timestamp</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.UpdatedAt</td>
<td style="width: 65px;">Date</td>
<td style="width: 257px;">Conversation updated timestamp</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.FromEmail</td>
<td style="width: 65px;">String</td>
<td style="width: 257px;">The email address that the reply/note was sent from. By default</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.Attachment.AttachmentURL</td>
<td style="width: 65px;">String</td>
<td style="width: 257px;">URL of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.Attachment.Name</td>
<td style="width: 65px;">String</td>
<td style="width: 257px;">The name of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.Attachment.ContentType</td>
<td style="width: 65px;">String</td>
<td style="width: 257px;">Content type of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.Attachment.ID</td>
<td style="width: 65px;">Number</td>
<td style="width: 257px;">ID number of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 418px;">Freshdesk.Ticket.Conversation.Attachment.Size</td>
<td style="width: 65px;">Number</td>
<td style="width: 257px;">ize of the file attached to the ticket</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-11">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!fd-create-ticket-note ticket_id=108 body="Demonstrating the Ticket Reply Command" attachments=2@5a0be47f-748f-4d60-8f46-81feb8f0c438 incoming=true private=false</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-11">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Ticket": {
        "Conversation": {
            "BodyText": "Demonstrating the Ticket Reply Command", 
            "Incoming": true, 
            "UserID": 2043022085976, 
            "Attachment": [
                {
                    "Name": "sample_attachment.md", 
                    "Size": 76, 
                    "ContentType": "application/octet-stream", 
                    "ID": 2043010708410, 
                    "AttachmentURL": "https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708410/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155545Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=db5ba2faa0753ffbe06b5b575500eb3bf55eb6460feab531cc4a723ce9e15512&amp;X-Amz-SignedHeaders=Host"
                }
            ], 
            "UpdatedAt": "2019-02-05T15:55:45Z", 
            "AdditionalFields": {
                "BodyHTML": "&lt;div&gt;Demonstrating the Ticket Reply Command&lt;/div&gt;", 
                "TicketID": 108
            }, 
            "ID": 44007154233, 
            "CreatedAt": "2019-02-05T15:55:45Z"
        }, 
        "ID": 108
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-11">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="note-for-ticket-108">Note for Ticket #108</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 1847px;">
<thead>
<tr>
<th style="width: 105px;">BodyText</th>
<th style="width: 80px;">Incoming</th>
<th style="width: 111px;">UserID</th>
<th style="width: 1096px;">Attachment</th>
<th style="width: 103px;">UpdatedAt</th>
<th style="width: 127px;">AdditionalFields</th>
<th style="width: 98px;">ID</th>
<th style="width: 103px;">CreatedAt</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 105px;">Demonstrating the Ticket Reply Command</td>
<td style="width: 80px;">true</td>
<td style="width: 111px;">2043022085976</td>
<td style="width: 1096px;">ID: 2043010708410, Size: 76, ContentType: application/octet-stream, Name: sample_attachment.md, AttachmentURL: <a href="https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708410/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155545Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=db5ba2faa0753ffbe06b5b575500eb3bf55eb6460feab531cc4a723ce9e15512&amp;X-Amz-SignedHeaders=Host">https://s3.amazonaws.com/cdn.freshdesk.com/data/helpdesk/attachments/production/2043010708410/original/sample_attachment.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAJ2JSYZ7O3I4JO6DA%2F20190205%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20190205T155545Z&amp;X-Amz-Expires=86400&amp;X-Amz-Signature=db5ba2faa0753ffbe06b5b575500eb3bf55eb6460feab531cc4a723ce9e15512&amp;X-Amz-SignedHeaders=Host</a>
</td>
<td style="width: 103px;">2019-02-05T15:55:45Z</td>
<td style="width: 127px;">TicketID: 108<br> BodyHTML:
<div>Demonstrating the Ticket Reply Command</div>
</td>
<td style="width: 98px;">44007154233</td>
<td style="width: 103px;">2019-02-05T15:55:45Z</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="delete-a-ticket">13. Delete a ticket</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes a ticket, specified by ID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-12">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-delete-ticket</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-12">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 246px;"><strong>Argument Name</strong></th>
<th style="width: 352px;"><strong>Description</strong></th>
<th style="width: 142px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 246px;">id</td>
<td style="width: 352px;">ID of the ticket to delete</td>
<td style="width: 142px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-12">Context Output</h5>
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<div class="table-wrapper"> </div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-12">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!fd-delete-ticket id=108</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-12">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Ticket": {
        "AdditionalFields": {
            "Deleted": true
        }, 
        "ID": 108
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-12">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Soft-Deleted Ticket #108</p>
</div>
<div class="cl-preview-section">
<h3 id="search-tickets">14. Search tickets</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of all tickets that match the filter criteria. If no filters are specified, all tickets from the last 30 days are returned.<br> Note that this command can consume multiple API credits. This can occur if the count of tickets resulting from your query exceeds 30. In that instance this command makes additional calls to the API to retrieve additional tickets matching your query.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-13">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fd-search-tickets</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-13">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 520px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">filter</td>
<td style="width: 520px;">Predefined filters for filtering tickets. The options are:<br> ‘new_and_my_open’ - New and my open tickets.<br> ‘watching’ - Tickets I’m watching.<br> ‘spam’ - Tickets that have been marked as spam.<br> ‘deleted’ - Tickets that have been soft-deleted, aka moved to Trash.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">requester</td>
<td style="width: 520px;">Filter results by the ticket requester’s email address or ID. To find your contacts’ ID numbers or email addresses, run the <code>fd-list-contacts</code> command.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">updated_since</td>
<td style="width: 520px;">By default, tickets created within the previous 30 days are returned. For older tickets, use this filter (“2015-01-19T02:00:00Z”)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">order_by</td>
<td style="width: 520px;">Field for ordering the list of tickets. The default sort order uses the ‘created_at’ field.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">order_type</td>
<td style="width: 520px;">Return list results in ascending or descending order according to the order_by value, default is descending</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">include_stats</td>
<td style="width: 520px;">If set to ‘true’ then ticket’s closed_at, resolved_at and first_responded_at time will be included. Note that this is not set by default because setting this to ‘true’ will consume an additional 2 API credits per API call. To see more details, see the <a href="https://developers.freshdesk.com/api/#embedding" target="_self">Freshdesk API documentation</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">include_requester</td>
<td style="width: 520px;">If set to ‘true’ then the ticket requester’s ID, email address, mobile number, name, and phone number are included in the ticket’s output for each ticket. Note that this is not set by default because setting this to ‘true’ will consume an additional 2 API credits per API call. To see more details, see the <a href="https://developers.freshdesk.com/api/#embedding" target="_self">Freshdesk API documentation</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">include_description</td>
<td style="width: 520px;">If set to ‘true’ then the ticket’s description and description_text are included the tickets’ outputs. Note that this is not set by default because setting this to ‘true’ will consume an additional 2 API credits per API call. To see more details, see the <a href="https://developers.freshdesk.com/api/#embedding" target="_self">Freshdesk API documentation</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">custom_query</td>
<td style="width: 520px;">Filter tickets using a custom query.<br> <br> Format - "(ticket_field:integer OR ticket_field:‘string’) AND ticket_field:boolean"<br> Example - "(type:‘Question’ OR type:‘Problem’) AND (due_by:&gt;‘2017-10-01’ AND due_by:&lt;‘2017-10-07’)"<br> For more examples, see the <a href="https://developers.freshdesk.com/api/#filter_tickets" target="_self">Freshdesk API documentation</a>.<br> <br> Note that the custom_query argument cannot be used in conjunction with this command’s other arguments.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-13">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 317px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 354px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.ID</td>
<td style="width: 69px;">Number</td>
<td style="width: 354px;">ID number of the fetched ticket</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.Priority</td>
<td style="width: 69px;">Number</td>
<td style="width: 354px;">Ticket priority</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.DueBy</td>
<td style="width: 69px;">Date</td>
<td style="width: 354px;">Timestamp that denotes when the ticket is due to be resolved</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.Subject</td>
<td style="width: 69px;">String</td>
<td style="width: 354px;">Ticket subject</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.Status</td>
<td style="width: 69px;">Number</td>
<td style="width: 354px;">Ticket status</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.RequesterID</td>
<td style="width: 69px;">Number</td>
<td style="width: 354px;">User ID of the requester</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.Tag</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 354px;">Tags associated with the ticket</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.GroupID</td>
<td style="width: 69px;">Number</td>
<td style="width: 354px;">ID of the group the ticket was assigned to</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.Source</td>
<td style="width: 69px;">Number</td>
<td style="width: 354px;">The channel through which the ticket was created</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.CreatedAt</td>
<td style="width: 69px;">Date</td>
<td style="width: 354px;">Ticket creation timestamp</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.ResponderID</td>
<td style="width: 69px;">Number</td>
<td style="width: 354px;">ID of the agent the ticket was assigned to</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.FrDueBy</td>
<td style="width: 69px;">Date</td>
<td style="width: 354px;">Timestamp that denotes when the first response is due</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.Conversation</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 354px;">Conversations associated with this ticket</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.Attachment.AttachmentURL</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 354px;">URL to download the file attached to the ticket to your local machine</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.Attachment.Name</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 354px;">The name of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.Attachment.ContentType</td>
<td style="width: 69px;">String</td>
<td style="width: 354px;">Content type of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.Attachment.ID</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 354px;">ID number of the file attached to the ticket</td>
</tr>
<tr>
<td style="width: 317px;">Freshdesk.Ticket.Attachment.Size</td>
<td style="width: 69px;">String</td>
<td style="width: 354px;">Size of the file attached to the ticket</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-13">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!fd-search-tickets updated_since=2019-02-05T08:30:00Z</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-13">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Freshdesk.Ticket": [
        {
            "Status": 2, 
            "ResponderID": null, 
            "DueBy": "2019-02-06T13:30:16Z", 
            "FrDueBy": "2019-02-05T14:30:16Z", 
            "GroupID": null, 
            "Priority": 3, 
            "Source": 2, 
            "Tag": [
                "new", 
                "attention needed", 
                "billing related"
            ], 
            "RequesterID": 2043024010476, 
            "UpdatedAt": "2019-02-05T14:32:44Z", 
            "AdditionalFields": {}, 
            "ID": 105, 
            "CreatedAt": "2019-02-05T10:30:16Z", 
            "Subject": "Demonstrate Ticket Creation"
        }, 
        {
            "Status": 2, 
            "ResponderID": 2043022085976, 
            "DueBy": "2019-02-05T11:05:48Z", 
            "FrDueBy": "2019-02-05T08:05:50Z", 
            "GroupID": 2043000867326, 
            "Priority": 4, 
            "Source": 2, 
            "Tag": [], 
            "RequesterID": 2043023521956, 
            "UpdatedAt": "2019-02-05T13:07:54Z", 
            "AdditionalFields": {}, 
            "ID": 97, 
            "CreatedAt": "2019-02-05T07:05:48Z", 
            "Subject": "Testing Ticket Update"
        }, 
        {
            "Status": 2, 
            "ResponderID": null, 
            "DueBy": "2019-02-05T10:00:00Z", 
            "FrDueBy": "2019-02-05T07:00:00Z", 
            "GroupID": 2043000867326, 
            "Priority": 4, 
            "Source": 2, 
            "Tag": [], 
            "RequesterID": 2043023521956, 
            "UpdatedAt": "2019-02-05T12:08:05Z", 
            "AdditionalFields": {}, 
            "ID": 96, 
            "CreatedAt": "2019-02-04T21:09:31Z", 
            "Subject": "Testing Ticket Update"
        }, 
        {
            "Status": 2, 
            "ResponderID": null, 
            "DueBy": "2019-02-05T10:00:00Z", 
            "FrDueBy": "2019-02-05T07:00:00Z", 
            "GroupID": 2043000867326, 
            "Priority": 4, 
            "Source": 2, 
            "Tag": [], 
            "RequesterID": 2043023521956, 
            "UpdatedAt": "2019-02-05T12:08:03Z", 
            "AdditionalFields": {}, 
            "ID": 95, 
            "CreatedAt": "2019-02-04T21:03:46Z", 
            "Subject": "Testing Ticket Update"
        }, 
        {
            "Status": 2, 
            "ResponderID": null, 
            "DueBy": "2019-02-07T15:00:00Z", 
            "FrDueBy": "2019-02-05T15:00:00Z", 
            "GroupID": null, 
            "Priority": 1, 
            "Source": 2, 
            "Tag": [], 
            "RequesterID": 2043023521956, 
            "UpdatedAt": "2019-02-05T15:00:49Z", 
            "AdditionalFields": {}, 
            "ID": 94, 
            "CreatedAt": "2019-02-04T21:00:41Z", 
            "Subject": "Testing Ticket Creation"
        }, 
        {
            "Status": 2, 
            "ResponderID": null, 
            "DueBy": "2019-02-07T15:00:00Z", 
            "FrDueBy": "2019-02-05T15:00:00Z", 
            "GroupID": null, 
            "Priority": 1, 
            "Source": 2, 
            "Tag": [], 
            "RequesterID": 2043023521956, 
            "UpdatedAt": "2019-02-05T15:00:48Z", 
            "AdditionalFields": {}, 
            "ID": 93, 
            "CreatedAt": "2019-02-04T20:19:19Z", 
            "Subject": "Testing Ticket Creation"
        }, 
        {
            "Status": 2, 
            "ResponderID": null, 
            "DueBy": "2019-02-05T13:20:08Z", 
            "FrDueBy": "2019-02-01T13:20:08Z", 
            "GroupID": null, 
            "Priority": 1, 
            "Source": 2, 
            "Tag": [], 
            "RequesterID": 2043023521956, 
            "UpdatedAt": "2019-02-05T13:33:04Z", 
            "AdditionalFields": {}, 
            "ID": 61, 
            "CreatedAt": "2019-01-31T13:20:08Z", 
            "Subject": "Testing Ticket Creation"
        }, 
        {
            "Status": 2, 
            "ResponderID": null, 
            "DueBy": "2019-02-05T12:56:02Z", 
            "FrDueBy": "2019-02-01T12:56:02Z", 
            "GroupID": 2043000867326, 
            "Priority": 1, 
            "Source": 2, 
            "Tag": [], 
            "RequesterID": 2043023521956, 
            "UpdatedAt": "2019-02-05T15:08:34Z", 
            "AdditionalFields": {}, 
            "ID": 60, 
            "CreatedAt": "2019-01-31T12:56:02Z", 
            "Subject": "Testing Ticket Creation"
        }, 
        {
            "Status": 2, 
            "ResponderID": null, 
            "DueBy": "2019-02-05T12:53:29Z", 
            "FrDueBy": "2019-02-01T12:53:29Z", 
            "GroupID": 2043000867326, 
            "Priority": 1, 
            "Source": 2, 
            "Tag": [], 
            "RequesterID": 2043023528657, 
            "UpdatedAt": "2019-02-05T15:08:33Z", 
            "AdditionalFields": {}, 
            "ID": 59, 
            "CreatedAt": "2019-01-31T12:53:29Z", 
            "Subject": "Lets see RawJson"
        }, 
        {
            "Status": 2, 
            "ResponderID": null, 
            "DueBy": "2019-02-05T12:51:35Z", 
            "FrDueBy": "2019-02-01T12:51:35Z", 
            "GroupID": 2043000867326, 
            "Priority": 1, 
            "Source": 2, 
            "Tag": [], 
            "RequesterID": 2043023521956, 
            "UpdatedAt": "2019-02-05T15:08:33Z", 
            "AdditionalFields": {}, 
            "ID": 58, 
            "CreatedAt": "2019-01-31T12:51:35Z", 
            "Subject": "Testing Ticket Creation"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-13">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="viewing-all-requested-tickets">Viewing All Requested Tickets</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 1028px;">
<thead>
<tr>
<th style="width: 27px;">ID</th>
<th style="width: 59px;">Priority</th>
<th style="width: 51px;">Status</th>
<th style="width: 97px;">Subject</th>
<th style="width: 98px;">DueBy</th>
<th style="width: 103px;">FrDueBy</th>
<th style="width: 116px;">RequesterID</th>
<th style="width: 116px;">GroupID</th>
<th style="width: 55px;">Source</th>
<th style="width: 103px;">CreatedAt</th>
<th style="width: 103px;">UpdatedAt</th>
<th style="width: 64px;">Tag</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 27px;">105</td>
<td style="width: 59px;">3</td>
<td style="width: 51px;">2</td>
<td style="width: 97px;">Demonstrate Ticket Creation</td>
<td style="width: 98px;">2019-02-06T13:30:16Z</td>
<td style="width: 103px;">2019-02-05T14:30:16Z</td>
<td style="width: 116px;">2043024010476</td>
<td style="width: 116px;"> </td>
<td style="width: 55px;">2</td>
<td style="width: 103px;">2019-02-05T10:30:16Z</td>
<td style="width: 103px;">2019-02-05T14:32:44Z</td>
<td style="width: 64px;">new,<br> attention needed,<br> billing related</td>
</tr>
<tr>
<td style="width: 27px;">97</td>
<td style="width: 59px;">4</td>
<td style="width: 51px;">2</td>
<td style="width: 97px;">Testing Ticket Update</td>
<td style="width: 98px;">2019-02-05T11:05:48Z</td>
<td style="width: 103px;">2019-02-05T08:05:50Z</td>
<td style="width: 116px;">2043023521956</td>
<td style="width: 116px;">2043000867326</td>
<td style="width: 55px;">2</td>
<td style="width: 103px;">2019-02-05T07:05:48Z</td>
<td style="width: 103px;">2019-02-05T13:07:54Z</td>
<td style="width: 64px;"> </td>
</tr>
<tr>
<td style="width: 27px;">96</td>
<td style="width: 59px;">4</td>
<td style="width: 51px;">2</td>
<td style="width: 97px;">Testing Ticket Update</td>
<td style="width: 98px;">2019-02-05T10:00:00Z</td>
<td style="width: 103px;">2019-02-05T07:00:00Z</td>
<td style="width: 116px;">2043023521956</td>
<td style="width: 116px;">2043000867326</td>
<td style="width: 55px;">2</td>
<td style="width: 103px;">2019-02-04T21:09:31Z</td>
<td style="width: 103px;">2019-02-05T12:08:05Z</td>
<td style="width: 64px;"> </td>
</tr>
<tr>
<td style="width: 27px;">95</td>
<td style="width: 59px;">4</td>
<td style="width: 51px;">2</td>
<td style="width: 97px;">Testing Ticket Update</td>
<td style="width: 98px;">2019-02-05T10:00:00Z</td>
<td style="width: 103px;">2019-02-05T07:00:00Z</td>
<td style="width: 116px;">2043023521956</td>
<td style="width: 116px;">2043000867326</td>
<td style="width: 55px;">2</td>
<td style="width: 103px;">2019-02-04T21:03:46Z</td>
<td style="width: 103px;">2019-02-05T12:08:03Z</td>
<td style="width: 64px;"> </td>
</tr>
<tr>
<td style="width: 27px;">94</td>
<td style="width: 59px;">1</td>
<td style="width: 51px;">2</td>
<td style="width: 97px;">Testing Ticket Creation</td>
<td style="width: 98px;">2019-02-07T15:00:00Z</td>
<td style="width: 103px;">2019-02-05T15:00:00Z</td>
<td style="width: 116px;">2043023521956</td>
<td style="width: 116px;"> </td>
<td style="width: 55px;">2</td>
<td style="width: 103px;">2019-02-04T21:00:41Z</td>
<td style="width: 103px;">2019-02-05T15:00:49Z</td>
<td style="width: 64px;"> </td>
</tr>
<tr>
<td style="width: 27px;">93</td>
<td style="width: 59px;">1</td>
<td style="width: 51px;">2</td>
<td style="width: 97px;">Testing Ticket Creation</td>
<td style="width: 98px;">2019-02-07T15:00:00Z</td>
<td style="width: 103px;">2019-02-05T15:00:00Z</td>
<td style="width: 116px;">2043023521956</td>
<td style="width: 116px;"> </td>
<td style="width: 55px;">2</td>
<td style="width: 103px;">2019-02-04T20:19:19Z</td>
<td style="width: 103px;">2019-02-05T15:00:48Z</td>
<td style="width: 64px;"> </td>
</tr>
<tr>
<td style="width: 27px;">61</td>
<td style="width: 59px;">1</td>
<td style="width: 51px;">2</td>
<td style="width: 97px;">Testing Ticket Creation</td>
<td style="width: 98px;">2019-02-05T13:20:08Z</td>
<td style="width: 103px;">2019-02-01T13:20:08Z</td>
<td style="width: 116px;">2043023521956</td>
<td style="width: 116px;"> </td>
<td style="width: 55px;">2</td>
<td style="width: 103px;">2019-01-31T13:20:08Z</td>
<td style="width: 103px;">2019-02-05T13:33:04Z</td>
<td style="width: 64px;"> </td>
</tr>
<tr>
<td style="width: 27px;">60</td>
<td style="width: 59px;">1</td>
<td style="width: 51px;">2</td>
<td style="width: 97px;">Testing Ticket Creation</td>
<td style="width: 98px;">2019-02-05T12:56:02Z</td>
<td style="width: 103px;">2019-02-01T12:56:02Z</td>
<td style="width: 116px;">2043023521956</td>
<td style="width: 116px;">2043000867326</td>
<td style="width: 55px;">2</td>
<td style="width: 103px;">2019-01-31T12:56:02Z</td>
<td style="width: 103px;">2019-02-05T15:08:34Z</td>
<td style="width: 64px;"> </td>
</tr>
<tr>
<td style="width: 27px;">59</td>
<td style="width: 59px;">1</td>
<td style="width: 51px;">2</td>
<td style="width: 97px;">Lets see RawJson</td>
<td style="width: 98px;">2019-02-05T12:53:29Z</td>
<td style="width: 103px;">2019-02-01T12:53:29Z</td>
<td style="width: 116px;">2043023528657</td>
<td style="width: 116px;">2043000867326</td>
<td style="width: 55px;">2</td>
<td style="width: 103px;">2019-01-31T12:53:29Z</td>
<td style="width: 103px;">2019-02-05T15:08:33Z</td>
<td style="width: 64px;"> </td>
</tr>
<tr>
<td style="width: 27px;">58</td>
<td style="width: 59px;">1</td>
<td style="width: 51px;">2</td>
<td style="width: 97px;">Testing Ticket Creation</td>
<td style="width: 98px;">2019-02-05T12:51:35Z</td>
<td style="width: 103px;">2019-02-01T12:51:35Z</td>
<td style="width: 116px;">2043023521956</td>
<td style="width: 116px;">2043000867326</td>
<td style="width: 55px;">2</td>
<td style="width: 103px;">2019-01-31T12:51:35Z</td>
<td style="width: 103px;">2019-02-05T15:08:33Z</td>
<td style="width: 64px;"> </td>
</tr>
</tbody>
</table>
</div>
</div>
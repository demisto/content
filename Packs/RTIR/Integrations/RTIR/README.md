<!-- HTML_DOC -->
<p>Use the Request Tracker for Incident Response (RTIR) integration to manage tickets and incidents.</p>
<p>This integration was integrated and tested with RTIR v4.4.2, using the SDK python-rtir v1.0.11.</p>
<h2>Use Cases</h2>
<ul>
<li>Create new tickets.</li>
<li>Resolve existing tickets.</li>
<li>Search for tickets using filters.</li>
<li>Edit tickets.</li>
<li>Get ticket data.</li>
</ul>
<h2>Known Limitations</h2>
<ul>
<li>This integration does not support the lifecycle <code>countermeasures</code>.</li>
<li>Custom fields cannot be created through this integration, but custom fields created on RTIR can be filled when creating a new ticket.</li>
</ul>
<h2>Configure RTIR on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for RTIR.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: A textual name for the integration instance.</li>
<li>
<strong>Server URL</strong> (for example: https://192.168.0.1)</li>
<li><strong>Username</strong></li>
<li><strong>Password</strong></li>
<li><strong>Token</strong></li>
<li><strong>Certificate</strong></li>
<li><strong>Private Key</strong></li>
<li>
<strong>Trust any certificate </strong>(not secure)</li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Fetch incidents with priority greater or equal to</strong></li>
<li><strong>Fetch incidents of the following status</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Referer request header</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and token.</li>
</ol>
<hr>
<h2>Fetched Incidents Data</h2>
<p>The integration fetches newly created tickets. The tickets are fetched by ID in ascending order, starting from 0 at the first fetch. The fetch is filtered by priority and status, which can be set in the integration settings. The initial fetch interval is one minute.</p>
<p>The following data is fetched for each ticket:</p>
<ul>
<li>General ticket information: ID, priority, created date, subject, queue, custom fields, and so on.</li>
<li>Ticket history.</li>
<li>Ticket attachments.</li>
</ul>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_223841975661532264365113">Create a new ticket: rtir-create-ticket</a></li>
<li><a href="#h_8934498871321532264376929">Search for tickets: rtir-search-ticket</a></li>
<li><a href="#h_6126183221961532264386562">Close a resolved ticket: rtir-resolve-ticket</a></li>
<li><a href="#h_4447458482601532264395385">Edit a ticket: rtir-edit-ticket</a></li>
<li><a href="#h_8852730923231532264405845">Get the history of a ticket: rtir-ticket-history</a></li>
<li><a href="#h_4810339493851532264419656">Get ticket details: rtir-get-ticket</a></li>
<li><a href="#h_3837565114461532264434464">Get ticket attachments: rtir-ticket-attachments</a></li>
<li><a href="#h_1765878985061532264445957">Add a comment to a ticket: rtir-add-comment</a></li>
</ol>
<hr>
<h3 id="h_223841975661532264365113">1. Create a new ticket</h3>
<p>Creates a new ticket in RFIR.</p>
<h5>Base Command</h5>
<p><code>rtir-create-ticket</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 132px;"><strong>Argument Name</strong></td>
<td style="width: 589px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 132px;">queue</td>
<td style="width: 589px;">Where to create the ticket.</td>
</tr>
<tr>
<td style="width: 132px;">subject</td>
<td style="width: 589px;">Subject of the ticket.</td>
</tr>
<tr>
<td style="width: 132px;">requestor</td>
<td style="width: 589px;">Email address of the requester.</td>
</tr>
<tr>
<td style="width: 132px;">cc</td>
<td style="width: 589px;">Sends a carbon-copy (cc) of this update to a comma separated list of email addresses. These people will also receive future updates.</td>
</tr>
<tr>
<td style="width: 132px;">admin-cc</td>
<td style="width: 589px;">Sends a carbon-copy (cc) of this update to a comma separated list of administrative email addresses. These people will also receive future updates.</td>
</tr>
<tr>
<td style="width: 132px;">owner</td>
<td style="width: 589px;">Ticket owner</td>
</tr>
<tr>
<td style="width: 132px;">status</td>
<td style="width: 589px;">Ticket status</td>
</tr>
<tr>
<td style="width: 132px;">priority</td>
<td style="width: 589px;">Ticket priority</td>
</tr>
<tr>
<td style="width: 132px;">text</td>
<td style="width: 589px;">The ticket content</td>
</tr>
<tr>
<td style="width: 132px;">initial-priority</td>
<td style="width: 589px;">Initial priority of ticket</td>
</tr>
<tr>
<td style="width: 132px;">final-priority</td>
<td style="width: 589px;">Final priority of ticket</td>
</tr>
<tr>
<td style="width: 132px;">member-of</td>
<td style="width: 589px;">Ticket MembersOF links</td>
</tr>
<tr>
<td style="width: 132px;">members</td>
<td style="width: 589px;">Ticket Members links</td>
</tr>
<tr>
<td style="width: 132px;">attachment</td>
<td style="width: 589px;">
<p>Comma separated list of entry IDs of attachment to add to the ticket (for example: entryID1,entryID2).</p>
</td>
</tr>
<tr>
<td style="width: 132px;">customfields</td>
<td style="width: 589px;">
<p>Ticket custom fields, in the following format: field1=value1,field2=value2.</p>
<p>For example: IP=8.8.8.8,HowReported=Email.</p>
<p>Note: This command does not create custom fields, these should be created on RTIR.</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>RTIR.Ticket.ID</td>
<td>Ticket ID.</td>
</tr>
<tr>
<td>RTIR.Ticket.InitialPriority</td>
<td>Ticket initial priority 0-100).</td>
</tr>
<tr>
<td>RTIR.Ticket.Priority</td>
<td>Ticket priority (0-100).</td>
</tr>
<tr>
<td>RTIR.Ticket.FinalPriority</td>
<td>Ticket final priority (0-100).</td>
</tr>
<tr>
<td>RTIR.Ticket.Owner</td>
<td>Ticket owner.</td>
</tr>
<tr>
<td>RTIR.Ticket.Subject</td>
<td>Ticket subject.</td>
</tr>
<tr>
<td>RTIR.Ticket.Creator</td>
<td>Ticket creator.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!rtir-create-ticket subject=NewTicket queue="Incident Reports" priority=70 requestor=root@localhost customfields="IP=8.8.8.8,How Reported=Email"</pre>
<h5>Raw Output</h5>
<blockquote>Ticket 121 was created successfully.</blockquote>
<h5>Context Example</h5>
<pre>{
    "RTIR": {
     "Ticket": {
        "CF_How Reported": "Email",
        "CF_IP": "8.8.8.8",
        "Priority": 70,
        "Requestor": "root@localhost",
        "Subject": "NewTicket"
      }
    }
}</pre>
<hr>
<h3 id="h_8934498871321532264376929">2. Search for tickets</h3>
<p>Searches for tickets in RTIR using specified filters.</p>
<h5>Base Command</h5>
<p><code>rtir-search-ticket</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>ticket-id</td>
<td>Ticket ID</td>
</tr>
<tr>
<td>subject</td>
<td>Ticket subject</td>
</tr>
<tr>
<td>queue</td>
<td>
<p>CSV list of ticket queues.</p>
<p>For example: General,Incident reports,Incidents</p>
</td>
</tr>
<tr>
<td>status</td>
<td>Ticket status</td>
</tr>
<tr>
<td>creator</td>
<td>Ticket creator</td>
</tr>
<tr>
<td>priority-equal-to</td>
<td>Ticket priority (range 0-100)</td>
</tr>
<tr>
<td>priority-greater-than</td>
<td>Ticket priority (range 0-100)</td>
</tr>
<tr>
<td>created-after</td>
<td>
<p>Date after which the ticket was created, in the following format: YYYY-MM-DD.</p>
<p>For example: 2011-02-24</p>
</td>
</tr>
<tr>
<td>created-on</td>
<td>
<p>Date the ticket was created, in the following format: YYYY-MM-DD.</p>
<p>For example: 2011-02-24</p>
</td>
</tr>
<tr>
<td>created-before</td>
<td>
<p>Date before which the ticket was created, in the following format: YYYY-MM-DD.</p>
<p>For example: 2011-02-24</p>
</td>
</tr>
<tr>
<td>owner</td>
<td>Ticket owner</td>
</tr>
<tr>
<td>due</td>
<td>
<p>Ticket due date, in the following format: YYYY-MM-DD.</p>
<p>For example: 2011-02-24</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>RTIR.Ticket.ID</td>
<td>Ticket ID.</td>
</tr>
<tr>
<td>RTIR.Ticket.State</td>
<td>Ticket state.</td>
</tr>
<tr>
<td>RTIR.Ticket.Creator</td>
<td>Ticket creator.</td>
</tr>
<tr>
<td>RTIR.Ticket.Subject</td>
<td>Ticket subject.</td>
</tr>
<tr>
<td>RTIR.Ticket.Created</td>
<td>Ticket creation date.</td>
</tr>
<tr>
<td>RTIR.Ticket.Priority</td>
<td>Ticket priority (0-100).</td>
</tr>
<tr>
<td>RTIR.Ticket.InitialPriority</td>
<td>Ticket initial priority (0-100).</td>
</tr>
<tr>
<td>RTIR.Ticket.FinalPriority</td>
<td>Ticket final priority (0-100).</td>
</tr>
<tr>
<td>RTIR.Ticket.Queue</td>
<td>Ticket queue.</td>
</tr>
<tr>
<td>RTIR.Ticket.Owner</td>
<td>Ticket owner.</td>
</tr>
<tr>
<td>RTIR.Ticket.IP</td>
<td>Ticket custom field - IP address.</td>
</tr>
<tr>
<td>RTIR.Ticket.HowReported</td>
<td>Ticket custom field - How ticket was reported.</td>
</tr>
<tr>
<td>RTIR.Ticket.Customer</td>
<td>Ticket custom field - Customer.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!rtir-search-ticket queue=General created-after=2018-07-10 priority-greater-than=10 status=new</pre>
<pre>[
    {
        "Created": "Thu Jul 12 03:56:06 2018",
        "Creator": "root",
        "Due": "Not set",
        "FinalPriority": "0",
        "InitialPriority": "0",
        "LastUpdated": "Thu Jul 12 03:56:06 2018",
        "Owner": "Nobody",
        "Priority": "12",
        "Queue": "General",
        "Requestors": [
            ""
        ],
        "Resolved": "Not set",
        "Started": "Not set",
        "Starts": "Not set",
        "Status": "new",
        "Subject": "unbelievable",
        "TimeEstimated": "0",
        "TimeLeft": "0",
        "TimeWorked": "0",
        "Told": "Not set",
        "id": "ticket/21"
    }
  }
]</pre>
<h5>Context Example</h5>
<pre>{
    "RTIR": {
       "Ticket": {
        {
            "Created": "Thu Jul 12 03:56:06 2018",
            "Creator": "root",
            "FinalPriority": 0,
            "ID": 21,
            "InitialPriority": 0,
            "Owner": "Nobody",
            "Priority": 12,
            "Queue": "General",
            "State": "new",
            "Subject": "unbelievable"
       }
   }
}</pre>
<hr>
<h3 id="h_6126183221961532264386562">3. Close a resolved ticket</h3>
<p>Closes a ticket that has been resolved.</p>
<h5>Base Command</h5>
<p><code>rtir-resolve-ticket</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>ticket-id</td>
<td>Ticket ID of the ticket to close.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 373px;"><strong>Path</strong></td>
<td style="width: 348px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 373px;">RTIR.Ticket.ID</td>
<td style="width: 348px;">Ticket ID.</td>
</tr>
<tr>
<td style="width: 373px;">RTIR.Ticket.State</td>
<td style="width: 348px;">Ticket state.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!rtir-resolve-ticket ticket-id=121</pre>
<h5>Raw Output</h5>
<p><code>Ticket 121 was closed successfully.</code></p>
<h5>Context Example</h5>
<pre>{  
   "RTIR":{  
      "Ticket":{  
         "ID":"121",
         "State":"resolved"
      }
   }
}</pre>
<hr>
<h3 id="h_4447458482601532264395385">4. Edit a ticket</h3>
<p>Edit a specific ticket. Ticket ID specifies which ticket to edit.</p>
<h5>Base Command</h5>
<p><code>rtir-edit-ticket</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Input Parameter</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>ticket-id</td>
<td>Ticket ID of the ticket you want to edit.</td>
</tr>
<tr>
<td>subject</td>
<td>Modified ticket subject.</td>
</tr>
<tr>
<td>priority</td>
<td>Modified ticket priority (0-100).</td>
</tr>
<tr>
<td>final-priority</td>
<td>Modified ticket final priority (0-100).</td>
</tr>
<tr>
<td>owner</td>
<td>Modified ticket owner.</td>
</tr>
<tr>
<td>status</td>
<td>Modified ticket status.</td>
</tr>
<tr>
<td style="width: 132px;">member-of</td>
<td style="width: 589px;">Modified ticket MembersOF ID</td>
</tr>
<tr>
<td style="width: 132px;">members</td>
<td style="width: 589px;">Modified ticket Members ID</td>
</tr>
<tr>
<td style="width: 132px;">depends-on</td>
<td style="width: 589px;">Modified ticket DependedOn ID</td>
</tr>
<tr>
<td style="width: 132px;">depended-on-by</td>
<td style="width: 589px;">Modified ticket DependedOnBy ID</td>
</tr>
<tr>
<td style="width: 132px;">refers-to</td>
<td style="width: 589px;">Modified ticket RefersTo ID</td>
</tr>
<tr>
<td style="width: 132px;">referred-to-by</td>
<td style="width: 589px;">Modified ticket ReferredToBy ID</td>
</tr>
<tr>
<td>due</td>
<td>
<p>Modified ticket due date, in the following format: YYYY-MM-DD.</p>
<p>For example: 2011-02-24</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>RTIR.Ticket.ID</td>
<td>Ticket ID.</td>
</tr>
<tr>
<td>RTIR.Ticket.FinalPriority</td>
<td>Ticket final priority (0-100).</td>
</tr>
<tr>
<td>RTIR.Ticket.Priority</td>
<td>Ticket priority (0-100).</td>
</tr>
<tr>
<td>RTIR.Ticket.Owner</td>
<td>Ticket owner.</td>
</tr>
<tr>
<td>RTIR.Ticket.State</td>
<td>Ticket state.</td>
</tr>
<tr>
<td>RTIR.Ticket.Subject</td>
<td>Ticket subject.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!rtir-edit-ticket ticket-id=115 final-priority=100 status=open subject=NewTicketSubject</pre>
<h5>Raw Output</h5>
<blockquote>Ticket 115 was edited successfully.</blockquote>
<h5>Context Example</h5>
<pre>{
    "RTIR": {
      "Ticket": {
        "FinalPriority": 100,
        "ID": 115,
        "Owner": "root",
        "Priority": 0,
        "State": "open",
        "Subject": "NewTicketSubject"
       }
    }
}</pre>
<hr>
<h3 id="h_8852730923231532264405845">5. Get the history of a ticket</h3>
<p>Get the history of a specified ticket.</p>
<h5>Base Command</h5>
<p><code>rtir-ticket-history</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 331px;"><strong>Input Parameter</strong></td>
<td style="width: 390px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 331px;">ticket-id</td>
<td style="width: 390px;">Ticket ID for which to retrieve the history.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>RTIR.Ticket.ID</td>
<td>Ticket ID.</td>
</tr>
<tr>
<td>RTIR.Ticket.History.Content</td>
<td>Ticket history content.</td>
</tr>
<tr>
<td>RTIR.Ticket.History.Created</td>
<td>Ticket history creation date.</td>
</tr>
<tr>
<td>RTIR.Ticket.History.Creator</td>
<td>Ticket history creator.</td>
</tr>
<tr>
<td>RTIR.Ticket.History.Description</td>
<td>Ticket history description.</td>
</tr>
<tr>
<td>RTIR.Ticket.History.NewValue</td>
<td>Value updated in history transaction.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!rtir-ticket-history ticket-id=1</pre>
<h5>Raw Output</h5>
<pre>[
    {
        "Attachments": [
            [
                1,
                "untitled (4b)"
            ]
        ],
        "Content": "test\n",
        "Created": "2018-07-09 07:25:47",
        "Creator": "root",
        "Data": "",
        "Description": "Ticket created by root",
        "Field": "",
        "NewValue": "",
        "OldValue": "",
        "Ticket": "1",
        "TimeTaken": "0",
        "Type": "Create",
        "id": "54"
    }
]</pre>
<h5>Context Example</h5>
<pre>{
    "RTIR": {
     "Ticket": {
        "History": [
            {
                "Content": "test\n",
                "Created": "2018-07-09 07:25:47",
                "Creator": "root",
                "Description": "Ticket created by root"
            }
        ],
        "ID": 1
     }
    }
}</pre>
<hr>
<h3 id="h_4810339493851532264419656">6. Get ticket details</h3>
<p>Get the details of a specific ticket.</p>
<h5>Base Command</h5>
<p><code>rtir-get-ticket</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 244px;"><strong>Input Parameter</strong></td>
<td style="width: 477px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 244px;">ticket-id</td>
<td style="width: 477px;">Ticket ID for which to retrieve details.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>RTIR.Ticket.LinkedTo.ID</td>
<td>Linked ticket ID.</td>
</tr>
<tr>
<td>RTIR.Ticket.ID</td>
<td>Ticket ID.</td>
</tr>
<tr>
<td>RTIR.Ticket.State</td>
<td>Ticket state.</td>
</tr>
<tr>
<td>RTIR.Ticket.Creator</td>
<td>Ticket creator.</td>
</tr>
<tr>
<td>RTIR.Ticket.Subject</td>
<td>Ticket subject.</td>
</tr>
<tr>
<td>RTIR.Ticket.Created</td>
<td>Ticket creation date.</td>
</tr>
<tr>
<td>RTIR.Ticket.Priority</td>
<td>Ticket priority (0-100).</td>
</tr>
<tr>
<td>RTIR.Ticket.InitialPriority</td>
<td>Ticket initial priority (0-100).</td>
</tr>
<tr>
<td>RTIR.Ticket.FinalPriority</td>
<td>Ticket final priority (0-100).</td>
</tr>
<tr>
<td>RTIR.Ticket.Queue</td>
<td>Ticket queue.</td>
</tr>
<tr>
<td>RTIR.Ticket.Owner</td>
<td>Ticket owner.</td>
</tr>
<tr>
<td>RTIR.Ticket.IP</td>
<td>Ticket custom field - IP address.</td>
</tr>
<tr>
<td>RTIR.Ticket.HowReported</td>
<td>Ticket custom field - How the ticket was reported.</td>
</tr>
<tr>
<td>RTIR.Ticket.Customer</td>
<td>Ticket custom field - Customer.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!rtir-get-ticket ticket-id=1</pre>
<h5>Raw Output</h5>
<pre>{
    "CF.{Customer}": "",
    "CF.{How Reported}": "Email",
    "CF.{IP}": "8.8.8.8",
    "CF.{Reporter Type}": "",
    "Created": "Mon Jul 09 03:25:47 2018",
    "Creator": "root",
    "Due": "Thu Jul 19 07:47:05 2018",
    "FinalPriority": "0",
    "InitialPriority": "0",
    "LastUpdated": "Thu Jul 12 10:20:02 2018",
    "Owner": "root",
    "Priority": "0",
    "Queue": "Incident Reports",
    "Requestors": [
        ""
    ],
    "Resolved": "Not set",
    "Started": "Thu Jul 19 00:00:00 2018",
    "Starts": "Not set",
    "Status": "open",
    "Subject": "test",
    "TimeEstimated": "0",
    "TimeLeft": "0",
    "TimeWorked": "0",
    "Told": "Not set",
    "id": "ticket/1"
}</pre>
<h5>Context Example</h5>
<pre>{
    "RTIR": {
      "Ticket":
        "Created": "Mon Jul 09 03:25:47 2018",
        "Creator": "root",
        "Due": "Thu Jul 19 07:47:05 2018",
        "FinalPriority": 0,
        "HowReported": "Email",
        "ID": 1,
        "IP": "8.8.8.8",
        "InitialPriority": 0,
        "LinkedTo": [
            {
                "ID": 15
            }
        ],
        "Owner": "root",
        "Priority": 0,
        "Queue": "Incident Reports",
        "State": "open",
        "Subject": "test"
      }
    }
}
</pre>
<hr>
<h3 id="h_3837565114461532264434464">7. Get ticket attachments</h3>
<p>Returns the attachment details of the specified ticket, and the attachment files to download from the War Room.</p>
<h5>Base Command</h5>
<p><code>rtir-ticket-attachments</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 315px;"><strong>Input Parameter</strong></td>
<td style="width: 406px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 315px;">ticket-id</td>
<td style="width: 406px;">Ticket ID for which to retrieve attachments.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 316px;"><strong>Path</strong></td>
<td style="width: 405px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 316px;">RTIR.Ticket.ID</td>
<td style="width: 405px;">Ticket ID.</td>
</tr>
<tr>
<td style="width: 316px;">RTIR.Ticket.Attachment.ID</td>
<td style="width: 405px;">Attachment ID.</td>
</tr>
<tr>
<td style="width: 316px;">RTIR.Ticket.Attachment.Name</td>
<td style="width: 405px;">Attachment file name.</td>
</tr>
<tr>
<td style="width: 316px;">RTIR.Ticket.Attachment.Size</td>
<td style="width: 405px;">Attachment file size.</td>
</tr>
<tr>
<td style="width: 316px;">RTIR.Ticket.Attachment.Type</td>
<td style="width: 405px;">Attachment file type.</td>
</tr>
<tr>
<td style="width: 316px;">File.EntryID</td>
<td style="width: 405px;">Cortex XSOAR entry ID of the attachment.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!rtir-ticket-attachments ticket-id=41</pre>
<h5>Raw Output</h5>
<pre>[
    {
        "ID": 77,
        "Name": "pdf.pdf",
        "Size": "423.8k",
        "Type": "application/octet-stream"
    },
    {
        "ID": 78,
        "Name": "SampleTextFile_10kb.txt",
        "Size": "9.2k",
        "Type": "text/plain"
    }
]</pre>
<h5>Context Example</h5>
<pre>{
    "RTIR": {
      "Ticket": {
        "Attachment": [
            {
                "ID": 77,
                "Name": "pdf.pdf",
                "Size": "423.8k",
                "Type": "application/octet-stream"
            },
            {
                "ID": 78,
                "Name": "SampleTextFile_10kb.txt",
                "Size": "9.2k",
                "Type": "text/plain"
            }
        ],
        "ID": 41
      }
    }
}</pre>
<hr>
<h3 id="h_1765878985061532264445957">8. Add a comment to a ticket</h3>
<p>Add a textual comment to a specified ticket.</p>
<h5>Base Command</h5>
<p><code>rtir-add-comment</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Input Parameter</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>ticket-id</td>
<td>Ticket ID to add a comment to.</td>
</tr>
<tr>
<td>text</td>
<td>Text of the comment.</td>
</tr>
<tr>
<td>attachment</td>
<td>
<p>CSV list of attachment entry IDs to add to the ticket.</p>
<p>For example: entryID1,entryID2</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command. </p>
<h5>Command Example</h5>
<pre>!rtir-add-comment text=CommentText ticket-id=113 attachment=1336@cc6f4232-d87e-496e-82b5-6bbeab422243</pre>
<h5>Raw Output</h5>
<blockquote>Added comment to ticket 113 successfully.</blockquote>
<h5>Context Example</h5>
<p>There is no context example for this command.</p>

<hr>
<h3 id="h_1765878985061532264445957">9. Add a reply to a ticket</h3>
<p>Add a textual reply to a specified ticket.</p>
<h5>Base Command</h5>
<p><code>rtir-add-reply</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Input Parameter</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>ticket-id</td>
<td>Ticket ID to add a comment to.</td>
</tr>
<tr>
<td>text</td>
<td>Text of the comment.</td>
</tr>
<tr>
<td>cc</td>
<td>
<p>Email of the user to send the reply.</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command. </p>
<h5>Command Example</h5>
<pre>!rtir-add-reply text=replyText ticket-id=113</pre>
<h5>Raw Output</h5>
<blockquote>Added reply to ticket 113 successfully.</blockquote>
<h5>Context Example</h5>
<p>There is no context example for this command.</p>
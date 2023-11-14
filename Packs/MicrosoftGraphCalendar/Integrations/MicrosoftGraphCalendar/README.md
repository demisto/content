<!-- HTML_DOC -->
<p>Use the O365 Outlook Calendar integration to create, and manage different calendars and events according to your requirements.</p>

<h2>Authentication</h2>
For more details about the authentication used in this integration, see <a href="https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication">Microsoft Integrations - Authentication</a>.

<h3>Required Permissions</h3>
<ul>
<li>Directory.ReadWrite.All - Delegated</li>
<li>Directory.ReadWrite.All - Application</li>
<li>Group.ReadWrite.All - Application</li>
<li>Calendars.Read - Delegated</li>
<li>Calendars.Read - Application</li>
<li>Calendars.ReadWrite - Delegated</li>
<li>Calendars.ReadWrite - Application</li>
</ul>
<h2>Configure O365 Outlook Calendar on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong>  &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for O365 Outlook Calendar.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL</strong></li>
<li><strong>ID for more details see cortex xsoar platform when configuring the integration instance</strong></li>
<li><strong>Token for more details see cortex xsoar platform when configuring the integration instance</strong></li>
<li><strong>Key for more details see cortex xsoar platform when configuring the integration instance</strong></li>
<li><strong>Certificate Thumbprint</strong></li>
<li><strong>Private Key</strong></li>
<li><strong>Default user</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the new instance.</li>
</ol>

<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#msgraph-calendar-list-calendars" target="_self">Get all calendars for a user: msgraph-calendar-list-calendars</a></li>
<li><a href="#msgraph-calendar-get-calendar" target="_self">Get one user's calendar: msgraph-calendar-get-calendar</a></li>
<li><a href="#msgraph-calendar-list-events" target="_self">Get a calendar's list of events: msgraph-calendar-list-events</a></li>
<li><a href="#msgraph-calendar-get-event" target="_self">Get an event by ID: msgraph-calendar-get-event</a></li>
<li><a href="#msgraph-calendar-create-event" target="_self">Create a new event: msgraph-calendar-create-event</a></li>
<li><a href="#msgraph-calendar-update-event" target="_self">Update an existing event: msgraph-calendar-update-event</a></li>
<li><a href="#msgraph-calendar-delete-event" target="_self">Delete an existing event: msgraph-calendar-delete-event</a></li>
</ol>
<h3 id="msgraph-calendar-list-calendars">1. Get all calendars for a user</h3>
<hr>
<p>Gets all calendars of a user.</p>
<h5>Base Command</h5>
<p><code>msgraph-calendar-list-calendars</code></p>
<h5>Input</h5>
<table style="width: 747px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 492px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">user</td>
<td style="width: 492px;">The user ID or userPrincipalName.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">order_by</td>
<td style="width: 492px;">Sorts the order of the returned items from Microsoft Graph.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">next_link</td>
<td style="width: 492px;">The link for the next page of results, if it exists. Follow this <a href="https://docs.microsoft.com/en-us/graph/api/resources/calendar?view=graph-rest-1.0" target="_self">link</a> for more details.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">top</td>
<td style="width: 492px;">Specifies the page size of the result set.</td>
<td style="width: 73px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 339px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 305px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 339px;">MSGraphCalendar.Calendar.Name</td>
<td style="width: 72px;">String</td>
<td style="width: 305px;">The name of the calendar.</td>
</tr>
<tr>
<td style="width: 339px;">MSGraphCalendar.Calendar.CanShare</td>
<td style="width: 72px;">Boolean</td>
<td style="width: 305px;">Whether the user has permission to share the calendar. Only the user who created the calendar can share.</td>
</tr>
<tr>
<td style="width: 339px;">MSGraphCalendar.Calendar.CanEdit</td>
<td style="width: 72px;">Boolean</td>
<td style="width: 305px;">Whether the user can write to the calendar (this is true for the user who created the calendar and for a user who has been granted access to a shared calendar).</td>
</tr>
<tr>
<td style="width: 339px;">MSGraphCalendar.Calendar.ChangeKey</td>
<td style="width: 72px;">String</td>
<td style="width: 305px;">Identifies the version of the calendar object. Every time the calendar is changed, the changeKey changes as well. This allows the exchange to apply changes to the correct version of the object. Read-only.</td>
</tr>
<tr>
<td style="width: 339px;">MSGraphCalendar.Calendar.Owner</td>
<td style="width: 72px;">Unknown</td>
<td style="width: 305px;">The user who created or added the calendar.</td>
</tr>
<tr>
<td style="width: 339px;">MSGraphCalendar.Calendar.ID</td>
<td style="width: 72px;">String</td>
<td style="width: 305px;">The unique ID of the calendar. Read-only.</td>
</tr>
<tr>
<td style="width: 339px;">MSGraphCalendar.Calendar.CanViewPrivateItems</td>
<td style="width: 72px;">Boolean</td>
<td style="width: 305px;">Whether the user can read calendar items that have been marked private.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!msgraph-calendar-list-calendars user=someemail@domain.com</pre>
<h5>Context Example</h5>
<pre>{
    "MSGraphCalendar.Calendar": [
        {
            "CanEdit": true,
            "CanShare": true,
            "CanViewPrivateItems": true,
            "ChangeKey": "Some_Change_Key",
            "ID": "Some_ID",
            "Name": "Calendar",
            "Owner": {
                "address": "someemail@domain.com",
                "name": "User Name"
            }
        },
        {
            "CanEdit": false,
            "CanShare": false,
            "CanViewPrivateItems": true,
            "ChangeKey": "Some_Change_Key",
            "ID": "Some_ID",
            "Name": "United States holidays",
            "Owner": {
                "address": "someemail@domain.com",
                "name": "User Name"
            }
        },
        {
            "CanEdit": false,
            "CanShare": false,
            "CanViewPrivateItems": true,
            "ChangeKey": "Some_Change_Key",
            "ID": "Some_ID",
            "Name": "Birthdays",
            "Owner": {
                "address": "someemail@domain.com",
                "name": "User Name"
            }
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Calendar:</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 233px;"><strong>Name</strong></th>
<th style="width: 132px;"><strong>Owner Name</strong></th>
<th style="width: 245px;"><strong>Owner Address</strong></th>
<th style="width: 95px;"><strong>ID</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 233px;">Calendar</td>
<td style="width: 132px;">User Name</td>
<td style="width: 245px;">someemail@domain.com</td>
<td style="width: 95px;">Some_ID</td>
</tr>
<tr>
<td style="width: 233px;">United States holidays</td>
<td style="width: 132px;">User Name</td>
<td style="width: 245px;">someemail@domain.com</td>
<td style="width: 95px;">Some_ID</td>
</tr>
<tr>
<td style="width: 233px;">Birthdays</td>
<td style="width: 132px;">User Name</td>
<td style="width: 245px;">someemail@domain.com</td>
<td style="width: 95px;">Some_ID</td>
</tr>
</tbody>
</table>
<h3 id="msgraph-calendar-get-calendar">2. Get one user's calendar</h3>
<hr>
<p>Returns a specific user's calendar.</p>
<h5>Base Command</h5>
<p><code>msgraph-calendar-get-calendar</code></p>
<h5>Input</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 122px;"><strong>Argument Name</strong></th>
<th style="width: 521px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 122px;">user</td>
<td style="width: 521px;">The user's ID or the userPrincipalName.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 122px;">calendar_id</td>
<td style="width: 521px;">The calendar's ID or name. If not specified, it retrieves the user's default calendar.</td>
<td style="width: 73px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 320px;"><strong>Path</strong></th>
<th style="width: 91px;"><strong>Type</strong></th>
<th style="width: 305px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 320px;">MSGraphCalendar.Calendar.Name</td>
<td style="width: 91px;">String</td>
<td style="width: 305px;">The calendar's name.</td>
</tr>
<tr>
<td style="width: 320px;">MSGraphCalendar.Calendar.CanShare</td>
<td style="width: 91px;">Boolean</td>
<td style="width: 305px;">Whether the user has permission to share the calendar. Only the user who created the calendar can share it.</td>
</tr>
<tr>
<td style="width: 320px;">MSGraphCalendar.Calendar.CanEdit</td>
<td style="width: 91px;">Boolean</td>
<td style="width: 305px;">Whether the user can write to the calendar (true for the user who created the calendar and for a user who has been shared a calendar and granted write access).</td>
</tr>
<tr>
<td style="width: 320px;">MSGraphCalendar.Calendar.ChangeKey</td>
<td style="width: 91px;">String</td>
<td style="width: 305px;">Identifies the version of the calendar object. Every time the calendar is changed, the changeKey changes as well. This allows the exchange to apply changes to the correct version of the object. Read-only.</td>
</tr>
<tr>
<td style="width: 320px;">MSGraphCalendar.Calendar.Owner</td>
<td style="width: 91px;">Unknown</td>
<td style="width: 305px;">The user who created or added the calendar.</td>
</tr>
<tr>
<td style="width: 320px;">MSGraphCalendar.Calendar.ID</td>
<td style="width: 91px;">String</td>
<td style="width: 305px;">The unique ID of the calendar. Read-only.</td>
</tr>
<tr>
<td style="width: 320px;">MSGraphCalendar.Calendar.CanViewPrivateItems</td>
<td style="width: 91px;">unknown</td>
<td style="width: 305px;">Whether the user can read calendar items that have been marked private.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!msgraph-calendar-get-calendar</pre>
<h5>Human Readable Output</h5>
<h3 id="msgraph-calendar-list-events">3. Get a calendar's list of events</h3>
<hr>
<p>Returns a list of events from a calendar.</p>
<h5>Base Command</h5>
<p><code>msgraph-calendar-list-events</code></p>
<h5>Input</h5>
<table style="width: 747px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 157px;"><strong>Argument Name</strong></th>
<th style="width: 486px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 157px;">user</td>
<td style="width: 486px;">The user's ID or userPrincipalName.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">calendar_id</td>
<td style="width: 486px;">The calendar ID or name. If not provided, the default calendar is used.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">order_by</td>
<td style="width: 486px;">Sorts the order of the items returned from Microsoft Graph.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">next_link</td>
<td style="width: 486px;">Link for the next page of results, if it exists. Follow this <a href="https://docs.microsoft.com/en-us/graph/api/resources/calendar?view=graph-rest-1.0" target="_self">link</a> for more details.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">top</td>
<td style="width: 486px;">Specifies the page size of the result set.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">filter_by</td>
<td style="width: 486px;">Filter Results. Follow this <a href="https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter" target="_self">link</a> for more details.</td>
<td style="width: 73px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 300px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 336px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 300px;">MSGraphCalendar.ID</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 336px;">The user's ID.</td>
</tr>
<tr>
<td style="width: 300px;">MSGraphCalendar.DisplayName</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 336px;">The display name of the user.</td>
</tr>
<tr>
<td style="width: 300px;">MSGraphCalendar.GivenName</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 336px;">The given name of the user.</td>
</tr>
<tr>
<td style="width: 300px;">MSGraphCalendar.BusinessPhones</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 336px;">The business phone numbers of the user.</td>
</tr>
<tr>
<td style="width: 300px;">MSGraphCalendar.JobTitle</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 336px;">The job title of the user.</td>
</tr>
<tr>
<td style="width: 300px;">MSGraphCalendar.Mail</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 336px;">The mail address of the user.</td>
</tr>
<tr>
<td style="width: 300px;">MSGraphCalendar.MobilePhone</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 336px;">The mobile phone number of the user.</td>
</tr>
<tr>
<td style="width: 300px;">MSGraphCalendar.OfficeLocation</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 336px;">The location of the office of the user.</td>
</tr>
<tr>
<td style="width: 300px;">MSGraphCalendar.PreferredLanguage</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 336px;">The user's preferred language.</td>
</tr>
<tr>
<td style="width: 300px;">MSGraphCalendar.Surname</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 336px;">The user's surname.</td>
</tr>
<tr>
<td style="width: 300px;">MSGraphCalendar.UserPrincipalName</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 336px;">The user's principal name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!msgraph-calendar-list-events</pre>
<h5>Human Readable Output</h5>
<h3 id="msgraph-calendar-get-event">4. Get an event by ID</h3>
<hr>
<p>Returns an event based on its ID.</p>
<h5>Base Command</h5>
<p><code>msgraph-calendar-get-event</code></p>
<h5>Input</h5>
<table style="width: 747px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 217px;"><strong>Argument Name</strong></th>
<th style="width: 386px;"><strong>Description</strong></th>
<th style="width: 113px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 217px;">user</td>
<td style="width: 386px;">The user's ID or the userPrincipalName.</td>
<td style="width: 113px;">Optional</td>
</tr>
<tr>
<td style="width: 217px;">event_id</td>
<td style="width: 386px;">The ID of the event.</td>
<td style="width: 113px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 368px;"><strong>Path</strong></th>
<th style="width: 75px;"><strong>Type</strong></th>
<th style="width: 273px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.OriginalStartTimeZone</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;"><span>The start time zone that was set when the event was created.</span></td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.HasAttachments</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether the event has attachments.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ResponseRequested</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether the sender requests a response when the event is accepted or declined.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.WebLink</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The URL used to open the event in Outlook on the web.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Recurrence</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The recurrence pattern for the event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Start</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The starting date, time, and time zone of the event. By default, the start time is in UTC.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.End</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The date, time, and time zone that the event ends. By default, the end time is in UTC.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Location</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The location of the event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Attendees</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The list of attendees for the event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Type</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The event type. For example, singleInstance, occurrence, exception, seriesMaster. Read-only.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ResponseStatus.response</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">Indicates the response type sent in response to an event message.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Importance</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The importance of the event. For example, low, normal, high.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ICalUId</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">A unique identifier that is shared by all instances of an event across different calendars.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.IsCancelled</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether the event has been canceled.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.IsAllDay</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether the event lasts all day.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ReminderMinutesBeforeStart</td>
<td style="width: 75px;">Number</td>
<td style="width: 273px;">The number of minutes before the event start time of the reminder alert.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.LastModifiedDateTime</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The last time the event was modified, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2014 is '2014-01-01T00:00:00Z'</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.OriginalEndTimeZone</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;"><span>The end time zone that was set when the event was created. </span></td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.CreatedDateTime</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The date the event was created using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2014 would be: '2014-01-01T00:00:00Z'</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ChangeKey</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">Identifies the version of the event object. Every time the event is changed, the ChangeKey changes as well. This allows the Exchange to apply changes to the correct version of the object.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ID</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The ID of the event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.IsOrganizer</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether the message sender is also the organizer.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Sensitivity</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The sensitivity of the event. Possible values are: normal, personal, private, confidential.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.IsReminderOn</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether an alert is set to remind the user of the event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Organizer</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The organizer of the event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Subject</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The text of the event's subject line.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.OnlineMeetingUrl</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">A URL for an online meeting, which is used when an organizer specifies an event as an online meeting, such as a Skype meeting. Read-only.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!msgraph-calendar-get-event user="someemail@domain.com" event_id=Some_ID</pre>
<h5>Context Example</h5>
<pre>{
    "MSGraphCalendar.Event": [
        {
            "@Odata.Context": "https://graph.microsoft.com/v1.0/$metadata#users('oren%40demistodev.onmicrosoft.com')/calendar/events/$entity",
            "Attendees": [
                {
                    "emailAddress": {
                        "address": "someemail@domain.com",
                        "name": "User Name"
                    },
                    "status": {
                        "response": "none",
                        "time": "0001-01-01T00:00:00Z"
                    },
                    "type": "required"
                }
            ],
            "Body": {
                "content": "\r\n<!-- converted from text -->\r\n\r\n\r\n</pre>
<div class='\"PlainText\"'>This event was created by MSGraph integration</div>
<pre>\r\n\r\n\r\n", "contentType": "html" }, "BodyPreview": "This event was created by MSGraph integration", "Categories": [], "ChangeKey": "Some_Change_Key", "CreatedDateTime": "2019-12-30T14:16:47.4108451Z", "End": { "dateTime": "2022-11-11T15:30:00.0000000", "timeZone": "UTC" }, "HasAttachments": false, "ICalUId": "040000008200E00074C5B7101A82E00800000000373066C51BBFD501000000000000000010000000D3EB65FAAFB082478A64C036CFE6783A", "ID": "Some_ID", "Importance": "normal", "IsAllDay": false, "IsCancelled": false, "IsOrganizer": true, "IsReminderOn": true, "LastModifiedDateTime": "2019-12-30T14:16:48.5891688Z", "Location": { "displayName": "Tel Aviv", "locationType": "default", "uniqueId": "Tel Aviv", "uniqueIdType": "private" }, "Locations": [ { "displayName": "Tel Aviv", "locationType": "default", "uniqueId": "Tel Aviv", "uniqueIdType": "private" } ], "OnlineMeetingUrl": null, "Organizer": { "emailAddress": { "address": "someemail@domain.com", "name": "User Name" } }, "OriginalEndTimeZone": "Asia/Jerusalem", "OriginalStartTimeZone": "Asia/Jerusalem", "Recurrence": null, "ReminderMinutesBeforeStart": 15, "ResponseRequested": true, "ResponseStatus": { "response": "organizer", "time": "0001-01-01T00:00:00Z" }, "Sensitivity": "normal", "SeriesMasterId": null, "ShowAs": "busy", "Start": { "dateTime": "2022-11-11T15:00:00.0000000", "timeZone": "UTC" }, "Subject": "test - delete", "Type": "singleInstance", "WebLink": "https://outlook.office365.com/owa/?itemid=AAMkADMzZWNjMjBkLTE2ZGQtNDE1NS05OTg3LTI5ZTRlY2Q5YjFiMgBGAAAAAACtWsHs6cTlRYm91jJyqUgDBwCPVsAqlO3YRKNF6ZoON8u7AAAAAAENAACPVsAqlO3YRKNF6ZoON8u7AACqxAGGAAA%3D&amp;exvsurl=1&amp;path=/calendar/item" } ] }</pre>
<h5>Human Readable Output</h5>
<h3>Event - test - delete</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 94px;"><strong>Subject</strong></th>
<th style="width: 60px;"><strong>Organizer</strong></th>
<th style="width: 82px;"><strong>Attendees</strong></th>
<th style="width: 190px;"><strong>Start</strong></th>
<th style="width: 191px;"><strong>End</strong></th>
<th style="width: 66px;"><strong>ID</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 94px;">test - delete</td>
<td style="width: 60px;">User Name</td>
<td style="width: 82px;">User Name</td>
<td style="width: 190px;">2022-11-11T15:00:00.0000000</td>
<td style="width: 191px;">2022-11-11T15:30:00.0000000</td>
<td style="width: 66px;">Some_ID</td>
</tr>
</tbody>
</table>
<h3 id="msgraph-calendar-create-event">5. Create a new event</h3>
<hr>
<p>Creates a new event.</p>
<h5>Base Command</h5>
<p><code>msgraph-calendar-create-event</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 179px;"><strong>Argument Name</strong></th>
<th style="width: 464px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 179px;">user</td>
<td style="width: 464px;">The user's ID or userPrincipalName.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">calendar_id</td>
<td style="width: 464px;">The unique ID of the calendar or name. If not provided, the default calendar is used.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">attendees</td>
<td style="width: 464px;">The collection of attendees for the event.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">body</td>
<td style="width: 464px;">The body of the message associated with the event in HTML or text format.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">subject</td>
<td style="width: 464px;">The text of the event's subject line.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">location</td>
<td style="width: 464px;">The location of the event for an online meeting, such as a Skype meeting. Read-only.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">end</td>
<td style="width: 464px;">The date and time the event ends. For example, '2017-05-28T12:00:00'. By default, the start time is in UTC.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">original_end_time_zone</td>
<td style="width: 464px;"><span>The end time zone that was set when the event was created.</span></td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">original_start</td>
<td style="width: 464px;">The original start time of the calendar item using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2014 is '2014-01-01T00:00:00Z'</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">start</td>
<td style="width: 464px;">The date and time the event starts at, for example '2017-05-28T12:00:00'. By default, the start time is in UTC.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">time_zone</td>
<td style="width: 464px;">Represents a time zone. For example, 'Pacific Standard Time'. Follow this <a href="https://docs.microsoft.com/en-us/graph/api/resources/datetimetimezone?view=graph-rest-1.0" target="_self">link</a> for more information.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">original_start_time_zone</td>
<td style="width: 464px;"><span>The start time zone that was set when the event was created.</span></td>
<td style="width: 73px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 354px;"><strong>Path</strong></th>
<th style="width: 89px;"><strong>Type</strong></th>
<th style="width: 273px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.OriginalStartTimeZone</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;"><span>The start time zone that was set when the event was created.</span></td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.HasAttachments</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 273px;">Whether the event has attachments.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.ResponseRequested</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 273px;">Whether the sender would like a response when the event is accepted or declined.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.WebLink</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;"><span>The URL used to open the event in Outlook on the web.</span></td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.Recurrence</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 273px;">The recurrence pattern for the event.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.Start</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 273px;">The date, time, and time zone that the event starts. By default, the start time is in UTC.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.End</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 273px;"><span>The starting date, time, and time zone of the event. By default, the start time is in UTC.</span></td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.Location</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 273px;">The location of the event.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.Attendees</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 273px;">The collection of attendees for the event.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.Type</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;">The event type. For example, singleInstance, occurrence, exception, seriesMaster. Read-only.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.ResponseStatus.response</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 273px;">Indicates the type of response sent in response to an event message.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.Importance</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;">The importance of the event. For example, low, normal, high.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.ICalUId</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;">A unique identifier that is shared by all instances of an event across different calendars.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.IsCancelled</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 273px;">Whether the event has been canceled.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.IsAllDay</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 273px;">Whether the event lasts all day.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.ReminderMinutesBeforeStart</td>
<td style="width: 89px;">Number</td>
<td style="width: 273px;">The number of minutes before the event start time of the reminder alert.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.LastModifiedDateTime</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;">Last modified time and date of the event using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2014 is '2014-01-01T00:00:00Z'</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.OriginalEndTimeZone</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;">The end time zone that was set when the event was created.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.CreatedDateTime</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;">The time and date the event was created using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2014 is '2014-01-01T00:00:00Z'</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.ChangeKey</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;">Identifies the version of the event object. Every time the event is changed, the ChangeKey changes as well. This allows the exchange to apply changes to the correct version of the object.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.ID</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;">The event's ID.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.IsOrganizer</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 273px;">Whether the message sender is also the organizer.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.Sensitivity</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;">The sensitivity of the event. Possible values are: normal, personal, private, confidential.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.IsReminderOn</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 273px;">Whether an alert is set to remind the user of the event.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.Organizer</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 273px;">The organizer of the event.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.Subject</td>
<td style="width: 89px;">String</td>
<td style="width: 273px;">The text of the event's subject line.</td>
</tr>
<tr>
<td style="width: 354px;">MSGraphCalendar.Event.OnlineMeetingUrl</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 273px;">A URL for an online meeting, which is used only when an organizer specifies an event as an online meeting, such as a Skype meeting. Read-only.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!msgraph-calendar-create-event user="someemail@domain.com" calendar_id="Calendar" attendees="someemail@domain.com" body="This event was created by MSGraph integration" subject="test - delete" location="Tel Aviv" end="2022-12-11T17:30:00" start="2022-12-11T17:00:00" time_zone="Asia/Jerusalem"</pre>
<h5>Context Example</h5>
<pre>{
    "MSGraphCalendar.Event": [
        {
            "@Odata.Context": "https://graph.microsoft.com/v1.0/$metadata#users('oren%40demistodev.onmicrosoft.com')/calendars('Calendar')/events/$entity",
            "Attendees": [
                {
                    "emailAddress": {
                        "address": "someemail@domain.com",
                        "name": "User Name"
                    },
                    "status": {
                        "response": "none",
                        "time": "0001-01-01T00:00:00Z"
                    },
                    "type": "required"
                }
            ],
            "Body": {
                "content": "This event was created by MSGraph integration",
                "contentType": "text"
            },
            "BodyPreview": "This event was created by MSGraph integration",
            "Categories": [],
            "ChangeKey": "Some_Change_Key",
            "CreatedDateTime": "2019-12-30T14:19:48.7510847Z",
            "End": {
                "dateTime": "2022-12-11T17:30:00.0000000",
                "timeZone": "Asia/Jerusalem"
            },
            "HasAttachments": false,
            "ICalUId": "040000008200E00074C5B7101A82E0080000000055837C311CBFD501000000000000000010000000C8489B38018FA74DA3FD6E7D67B7DC54",
            "ID": "Some_ID",
            "Importance": "normal",
            "IsAllDay": false,
            "IsCancelled": false,
            "IsOrganizer": true,
            "IsReminderOn": true,
            "LastModifiedDateTime": "2019-12-30T14:19:48.7900629Z",
            "Location": {
                "displayName": "Tel Aviv",
                "locationType": "default",
                "uniqueId": "Tel Aviv",
                "uniqueIdType": "private"
            },
            "Locations": [
                {
                    "displayName": "Tel Aviv",
                    "locationType": "default",
                    "uniqueId": "Tel Aviv",
                    "uniqueIdType": "private"
                }
            ],
            "OnlineMeetingUrl": null,
            "Organizer": {
                "emailAddress": {
                    "address": "someemail@domain.com",
                    "name": "User Name"
                }
            },
            "OriginalEndTimeZone": "Asia/Jerusalem",
            "OriginalStartTimeZone": "Asia/Jerusalem",
            "Recurrence": null,
            "ReminderMinutesBeforeStart": 15,
            "ResponseRequested": true,
            "ResponseStatus": {
                "response": "organizer",
                "time": "0001-01-01T00:00:00Z"
            },
            "Sensitivity": "normal",
            "SeriesMasterId": null,
            "ShowAs": "busy",
            "Start": {
                "dateTime": "2022-12-11T17:00:00.0000000",
                "timeZone": "Asia/Jerusalem"
            },
            "Subject": "test - delete",
            "Type": "singleInstance",
            "WebLink": "https://outlook.office365.com/owa/?itemid=AAMkADMzZWNjMjBkLTE2ZGQtNDE1NS05OTg3LTI5ZTRlY2Q5YjFiMgBGAAAAAACtWsHs6cTlRYm91jJyqUgDBwCPVsAqlO3YRKNF6ZoON8u7AAAAAAENAACPVsAqlO3YRKNF6ZoON8u7AACqxAGJAAA%3D&amp;exvsurl=1&amp;path=/calendar/item"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Event was created successfully:</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Subject</strong></th>
<th><strong>Organizer</strong></th>
<th><strong>Attendees</strong></th>
<th><strong>Start</strong></th>
<th><strong>End</strong></th>
<th><strong>ID</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>test - delete</td>
<td>User Name</td>
<td>User Name</td>
<td>2022-12-11T17:00:00.0000000</td>
<td>2022-12-11T17:30:00.0000000</td>
<td>Some_ID</td>
</tr>
</tbody>
</table>
<h3 id="msgraph-calendar-update-event">6. Update an existing event</h3>
<hr>
<p>Updates an existing event.</p>
<h5>Base Command</h5>
<p><code>msgraph-calendar-update-event</code></p>
<h5>Input</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 180px;"><strong>Argument Name</strong></th>
<th style="width: 463px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">user</td>
<td style="width: 463px;">The user's ID or userPrincipalName.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">event_id</td>
<td style="width: 463px;">The event's ID.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 180px;">attendees</td>
<td style="width: 463px;">The collection of attendees for the event.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">body</td>
<td style="width: 463px;">The body of the message associated with the event. It can be in HTML or text format.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">subject</td>
<td style="width: 463px;">The text of the event's subject line.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">location</td>
<td style="width: 463px;">The location of the event for an online meeting, such as a Skype meeting. Read-only.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">end</td>
<td style="width: 463px;">The date and time the event ends. For example '2017-05-28T12:00:00'. By default, the start time is in UTC.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">original_end_time_zone</td>
<td style="width: 463px;">The end time zone when the event was created.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">start</td>
<td style="width: 463px;">The date and time the event starts. For example '2017-05-28T12:00:00'. By default, the start time is in UTC.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">time_zone</td>
<td style="width: 463px;">Represents a time zone, for example, 'Pacific Standard Time'. For more information, see https://docs.microsoft.com/en-us/graph/api/resources/datetimetimezone?view=graph-rest-1.0</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">original_start</td>
<td style="width: 463px;">The original start time of the calendar item, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2014 is '2014-01-01T00:00:00Z'</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">original_start_time_zone</td>
<td style="width: 463px;">The start time zone when the event was created.</td>
<td style="width: 73px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 374px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 273px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.OriginalStartTimeZone</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;">
<span>The start time zone that was set when the event was created</span>.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.HasAttachments</td>
<td style="width: 69px;">Boolean</td>
<td style="width: 273px;">Whether the event has attachments.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.ResponseRequested</td>
<td style="width: 69px;">Boolean</td>
<td style="width: 273px;">Whether the sender requests a response when the event is accepted or declined.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.WebLink</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;"><span>The URL used to open the event in Outlook on the web.</span></td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.Recurrence</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 273px;">The recurrence pattern for the event.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.Start</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 273px;">The date, time, and time zone that the event starts. By default, the start time is in UTC.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.End</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 273px;">The date, time, and time zone that the event ends. By default, the end time is in UTC.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.Location</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 273px;">The location of the event.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.Attendees</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 273px;">The collection of attendees for the event.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.Type</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;">The event type. For example, singleInstance, occurrence, exception, seriesMaster. Read-only.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.ResponseStatus.response</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 273px;">Indicates the type of response sent in response to an event message.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.Importance</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;">The importance of the event. For example, low, normal, high.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.ICalUId</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;">A unique identifier that is shared by all instances of an event across different calendars.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.IsCancelled</td>
<td style="width: 69px;">Boolean</td>
<td style="width: 273px;">Whether the event has been canceled.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.IsAllDay</td>
<td style="width: 69px;">Boolean</td>
<td style="width: 273px;">Whether the event lasts all day.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.ReminderMinutesBeforeStart</td>
<td style="width: 69px;">Number</td>
<td style="width: 273px;">The number of minutes before the event start time of the reminder alert.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.LastModifiedDateTime</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;">The last time and date the event was modified using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2014 is '2014-01-01T00:00:00Z'</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.OriginalEndTimeZone</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;"><span>The end time zone that was set when the event was created.</span></td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.CreatedDateTime</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;">The date and time the event was created using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2014 is '2014-01-01T00:00:00Z'</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.ChangeKey</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;">Identifies the version of the event object. Every time the event is changed, the ChangeKey changes as well. This allows the exchange to apply changes to the correct version of the object.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.ID</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;">The ID of the event.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.IsOrganizer</td>
<td style="width: 69px;">Boolean</td>
<td style="width: 273px;">Whether the message sender is also the organizer.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.Sensitivity</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;">The sensitivity of the event. Possible values are: normal, personal, private, confidential.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.IsReminderOn</td>
<td style="width: 69px;">Boolean</td>
<td style="width: 273px;">Whether an alert is set to remind the user of the event.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.Organizer</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 273px;">The organizer of the event.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.Subject</td>
<td style="width: 69px;">String</td>
<td style="width: 273px;">The text of the event's subject line.</td>
</tr>
<tr>
<td style="width: 374px;">MSGraphCalendar.Event.OnlineMeetingUrl</td>
<td style="width: 69px;">Unknown</td>
<td style="width: 273px;">A URL for an online meeting, used only when an organizer specifies an event as an online meeting, such as a Skype meeting. Read-only.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!msgraph-calendar-update-event user="someemail@domain.com" event_id=Some_ID subject="updated"</pre>
<h5>Context Example</h5>
<pre>{
    "MSGraphCalendar": [
        {
            "@Odata.Context": "https://graph.microsoft.com/v1.0/$metadata#users('oren%40demistodev.onmicrosoft.com')/calendar/events/$entity",
            "Attendees": [
                {
                    "emailAddress": {},
                    "status": {
                        "response": "none",
                        "time": "0001-01-01T00:00:00Z"
                    },
                    "type": "required"
                }
            ],
            "Body": {
                "content": "",
                "contentType": "text"
            },
            "BodyPreview": "",
            "Categories": [],
            "ChangeKey": "Some_Change_Key",
            "CreatedDateTime": "2019-12-30T14:16:47.4108451Z",
            "End": {
                "dateTime": "2022-11-11T15:30:00.0000000",
                "timeZone": "UTC"
            },
            "HasAttachments": false,
            "ICalUId": "040000008200E00074C5B7101A82E00800000000373066C51BBFD501000000000000000010000000D3EB65FAAFB082478A64C036CFE6783A",
            "ID": "Some_ID",
            "Importance": "normal",
            "IsAllDay": false,
            "IsCancelled": false,
            "IsOrganizer": true,
            "IsReminderOn": true,
            "LastModifiedDateTime": "2019-12-30T14:19:50.1373174Z",
            "Location": {
                "address": {},
                "coordinates": {},
                "displayName": "",
                "locationType": "default",
                "uniqueIdType": "unknown"
            },
            "Locations": [],
            "OnlineMeetingUrl": null,
            "Organizer": {
                "emailAddress": {
                    "address": "someemail@domain.com",
                    "name": "User Name"
                }
            },
            "OriginalEndTimeZone": "Asia/Jerusalem",
            "OriginalStartTimeZone": "Asia/Jerusalem",
            "Recurrence": null,
            "ReminderMinutesBeforeStart": 15,
            "ResponseRequested": true,
            "ResponseStatus": {
                "response": "organizer",
                "time": "0001-01-01T00:00:00Z"
            },
            "Sensitivity": "normal",
            "SeriesMasterId": null,
            "ShowAs": "busy",
            "Start": {
                "dateTime": "2022-11-11T15:00:00.0000000",
                "timeZone": "UTC"
            },
            "Subject": "updated",
            "Type": "singleInstance",
            "WebLink": "https://outlook.office365.com/owa/?itemid=AAMkADMzZWNjMjBkLTE2ZGQtNDE1NS05OTg3LTI5ZTRlY2Q5YjFiMgBGAAAAAACtWsHs6cTlRYm91jJyqUgDBwCPVsAqlO3YRKNF6ZoON8u7AAAAAAENAACPVsAqlO3YRKNF6ZoON8u7AACqxAGGAAA%3D&amp;exvsurl=1&amp;path=/calendar/item"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Event:</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Subject</strong></th>
<th><strong>Organizer</strong></th>
<th><strong>Attendees</strong></th>
<th><strong>Start</strong></th>
<th><strong>End</strong></th>
<th><strong>ID</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>updated</td>
<td>User Name</td>
<td>None</td>
<td>2022-11-11T15:00:00.0000000</td>
<td>2022-11-11T15:30:00.0000000</td>
<td>Some_ID</td>
</tr>
</tbody>
</table>
<h3 id="msgraph-calendar-delete-event">7. Delete an existing event</h3>
<hr>
<p>Deletes an existing event.</p>
<h5>Base Command</h5>
<p><code>msgraph-calendar-delete-event</code></p>
<h5>Input</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 205px;"><strong>Argument Name</strong></th>
<th style="width: 390px;"><strong>Description</strong></th>
<th style="width: 121px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 205px;">user</td>
<td style="width: 390px;">The user ID or userPrincipalName.</td>
<td style="width: 121px;">Optional</td>
</tr>
<tr>
<td style="width: 205px;">event_id</td>
<td style="width: 390px;">The event ID.</td>
<td style="width: 121px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 368px;"><strong>Path</strong></th>
<th style="width: 75px;"><strong>Type</strong></th>
<th style="width: 273px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.OriginalStartTimeZone</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">
<span>The start time zone that was set when the event was created.</span>.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.HasAttachments</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether the event has attachments.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ResponseRequested</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether the sender receives a response when the event is accepted or declined.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.WebLink</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;"><span>The URL used to open the event in Outlook on the web.</span></td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Recurrence</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The recurrence pattern for the event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Start</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The date, time, and time zone that the event starts. By default, the start time is in UTC.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.End</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The date, time, and time zone that the event ends. By default, the end time is in UTC.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Location</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The location of the event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Attendees</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The collection of attendees for the event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Type</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The event type. For example, singleInstance, occurrence, exception, seriesMaster. Read-only.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ResponseStatus.response</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">Indicates the type of response sent in response to an event message.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Importance</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The importance of the event. For example, low, normal, high.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ICalUId</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">A unique identifier that is shared by all instances of an event across different calendars.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.IsCancelled</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether the event has been canceled.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.IsAllDay</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether the event lasts all day.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ReminderMinutesBeforeStart</td>
<td style="width: 75px;">Number</td>
<td style="width: 273px;">The number of minutes before the event start time of the reminder alert.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.LastModifiedDateTime</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The time and date the event was last modified using the ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2014 is '2014-01-01T00:00:00Z'</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.OriginalEndTimeZone</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;"><span>The end time zone that was set when the event was created.</span></td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.CreatedDateTime</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The time and date the event was created using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is '2014-01-01T00:00:00Z'.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ChangeKey</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">Identifies the version of the event object. Every time the event is changed, the ChangeKey changes as well. This allows the exchange to apply changes to the correct version of the object.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.ID</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The ID of the Event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.IsOrganizer</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether the message sender is also the organizer.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Sensitivity</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The sensitivity of the event. Possible values are: normal, personal, private, confidential.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.IsReminderOn</td>
<td style="width: 75px;">Boolean</td>
<td style="width: 273px;">Whether an alert is set to remind the user of the event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Organizer</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">The organizer of the event.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.Subject</td>
<td style="width: 75px;">String</td>
<td style="width: 273px;">The text of the event's subject line.</td>
</tr>
<tr>
<td style="width: 368px;">MSGraphCalendar.Event.OnlineMeetingUrl</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 273px;">A URL for an online meeting, used only when an organizer specifies an event as an online meeting, such as a Skype meeting. Read-only.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!msgraph-calendar-delete-event user="someemail@domain.com" event_id=Some_ID</pre>
<h5>Context Example</h5>
<pre>{
    "MSGraphCalendar.Event": {
        "@Odata.Context": "https://graph.microsoft.com/v1.0/$metadata#users('oren%40demistodev.onmicrosoft.com')/calendars('Calendar')/events/$entity",
        "Attendees": [
            {
                "emailAddress": {
                    "address": "someemail@domain.com",
                    "name": "User Name"
                },
                "status": {
                    "response": "none",
                    "time": "0001-01-01T00:00:00Z"
                },
                "type": "required"
            }
        ],
        "Body": {
            "content": "This event was created by MSGraph integration",
            "contentType": "text"
        },
        "BodyPreview": "This event was created by MSGraph integration",
        "Categories": [],
        "ChangeKey": "Some_Change_Key",
        "CreatedDateTime": "2019-12-30T14:16:47.4108451Z",
        "Deleted": true,
        "End": {
            "dateTime": "2022-11-11T17:30:00.0000000",
            "timeZone": "Asia/Jerusalem"
        },
        "HasAttachments": false,
        "ICalUId": "040000008200E00074C5B7101A82E00800000000373066C51BBFD501000000000000000010000000D3EB65FAAFB082478A64C036CFE6783A",
        "ID": "Some_ID",
        "Importance": "normal",
        "IsAllDay": false,
        "IsCancelled": false,
        "IsOrganizer": true,
        "IsReminderOn": true,
        "LastModifiedDateTime": "2019-12-30T14:16:47.4508223Z",
        "Location": {
            "displayName": "Tel Aviv",
            "locationType": "default",
            "uniqueId": "Tel Aviv",
            "uniqueIdType": "private"
        },
        "Locations": [
            {
                "displayName": "Tel Aviv",
                "locationType": "default",
                "uniqueId": "Tel Aviv",
                "uniqueIdType": "private"
            }
        ],
        "OnlineMeetingUrl": null,
        "Organizer": {
            "emailAddress": {
                "address": "someemail@domain.com",
                "name": "User Name"
            }
        },
        "OriginalEndTimeZone": "Asia/Jerusalem",
        "OriginalStartTimeZone": "Asia/Jerusalem",
        "Recurrence": null,
        "ReminderMinutesBeforeStart": 15,
        "ResponseRequested": true,
        "ResponseStatus": {
            "response": "organizer",
            "time": "0001-01-01T00:00:00Z"
        },
        "Sensitivity": "normal",
        "SeriesMasterId": null,
        "ShowAs": "busy",
        "Start": {
            "dateTime": "2022-11-11T17:00:00.0000000",
            "timeZone": "Asia/Jerusalem"
        },
        "Subject": "test - delete",
        "Type": "singleInstance",
        "WebLink": "https://outlook.office365.com/owa/?itemid=AAMkADMzZWNjMjBkLTE2ZGQtNDE1NS05OTg3LTI5ZTRlY2Q5YjFiMgBGAAAAAACtWsHs6cTlRYm91jJyqUgDBwCPVsAqlO3YRKNF6ZoON8u7AAAAAAENAACPVsAqlO3YRKNF6ZoON8u7AACqxAGGAAA%3D&amp;exvsurl=1&amp;path=/calendar/item"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>Event was deleted successfully.</p>

<h3 id="msgraph-calendar-auth-reset">8. msgraph-calendar-auth-reset</h3>
<hr>
<p>Run this command if for some reason you need to rerun the authentication process.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-calendar-auth-reset</code>
</p>

<h5>Input</h5>

<p>There are no input arguments for this command.&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
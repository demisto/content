<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Use the Zoom integration manage your Zoom users and meetings.</p>
<p>This integration was integrated and tested with Zoom v4.1.28165.0716.</p>
<p> </p>
<h2>Configure the Zoom integration on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Zoom.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong><font style="vertical-align: inherit;">apiKey</font></strong><font style="vertical-align: inherit;">: Zoom API key for a specific license</font>
</li>
<li>
<strong>apiSecret</strong>:<strong> </strong>Zoom API secret for a specific license</li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust any certificate</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>
</ol>
<p> </p>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_30899346041532346681015">Create a Zoom user: zoom-create-user</a></li>
<li><a href="#h_473319413361532347917368">Create a Zoom meeting: zoom-create-meeting</a></li>
<li><a href="#h_298016959581532348272575">Get a recorded Zoom meeting: zoom-fetch-recording</a></li>
<li><a href="#h_10266497861532348515249">Get a list of Zoom users: zoom-list-users</a></li>
<li><a href="#h_542253733281532434898368">Delete a Zoom user: zoom-delete-user</a></li>
</ol>
<p> </p>
<h3 id="h_30899346041532346681015">Create a Zoom user</h3>
<hr>
<p>Creates a single user in your Zoom account.</p>
<h5>Base Command</h5>
<p><code>zoom-create-user</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 173px;"><strong>Input Parameter</strong></td>
<td style="width: 467px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 173px;">first_name</td>
<td style="width: 467px;">First name of the user you are creating</td>
</tr>
<tr>
<td style="width: 173px;">last_name</td>
<td style="width: 467px;">Last name of the user you are creating</td>
</tr>
<tr>
<td style="width: 173px;">email</td>
<td style="width: 467px;">Email address of the user you are creating</td>
</tr>
<tr>
<td style="width: 173px;">user_type</td>
<td style="width: 467px;">
<p>Type of user account.</p>
<ul>
<li>Basic: free user account with maximum meeting of 40 minutes and 3 users</li>
<li>Pro: paid account with unlimited meetings and users on the public cloud</li>
<li>Corporate: paid account with unlimited meetings and users on the hybrid cloud</li>
</ul>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th>Path</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>Zoom.User.id</td>
<td>The ID of the created user</td>
</tr>
<tr>
<td>Zoom.User.first_name</td>
<td>First name of the created user</td>
</tr>
<tr>
<td>Zoom.User.last_name</td>
<td>Last name for the created user</td>
</tr>
<tr>
<td>Zoom.User.email</td>
<td>Email of the created user</td>
</tr>
<tr>
<td>Zoom.User.type</td>
<td>The type of the user</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!zoom-create-user email=mockmail@demistomock.com first_name=Mock last_name=Mockinson user_type=Basic</code></p>
<p> </p>
<h5>Raw Output</h5>
<pre>{
    "Zoom": {
        "User": {
            "first_name": "Mock", 
            "last_name": "Email", 
            "type": 1, 
            "email": "mockmail@demistomock.com", 
            "id": "sqTVZy--R-yfdDgzF6Iciw"
        }
    }
}</pre>
<p> </p>
<h5>War Room Output</h5>
<p><img src="https://user-images.githubusercontent.com/20818773/43066648-e799e8f0-8e6d-11e8-8d6f-ec17577fb60a.png" alt="image" width="749" height="91"></p>
<p> </p>
<h3 id="h_473319413361532347917368">Create a Zoom meeting</h3>
<hr>
<p>Creates a Zoom meeting, specifying meeting topic, invited users, meeting start time, and whether to record the meeting.</p>
<h5>Base Command</h5>
<p><code>zoom-create-meeting</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 173px;"><strong>Input Parameter</strong></td>
<td style="width: 467px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 173px;">type</td>
<td style="width: 467px;">
<p>Meeting type.</p>
<ul>
<li>Instant meeting</li>
<li>Scheduled meeting</li>
<li>Recurring meeting with no fixed time</li>
<li>Recurring meeting with fixed time</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 173px;">user</td>
<td style="width: 467px;">Email address or user ID of the user you want to invite to the meeting</td>
</tr>
<tr>
<td style="width: 173px;">topic</td>
<td style="width: 467px;">Meeting topic</td>
</tr>
<tr>
<td style="width: 173px;">auto-record-meeting</td>
<td style="width: 467px;">Whether to record the meeting</td>
</tr>
<tr>
<td style="width: 173px;">start-time</td>
<td style="width: 467px;">Meeting start time. When using a format like “yyyy-MM-dd’T'HH:mm:ss'Z’”, always use GMT time. When using a format like “yyyy-MM-dd’T'HH:mm:ss”, you should use local time and you will need to specify the time zone. Only used for scheduled meetings and recurring meetings with fixed time.</td>
</tr>
<tr>
<td style="width: 173px;">timezone</td>
<td style="width: 467px;">Timezone for the meeting start-time. For example, America/Los_Angeles. This is only for scheduled meetings.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th>Path</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>Zoom.Meeting.join_url</td>
<td>Join url for the meeting</td>
</tr>
<tr>
<td>Zoom.Meeting.id</td>
<td>Meeting id of the new meeting that is created</td>
</tr>
<tr>
<td>Zoom.Meeting.start_url</td>
<td>The URL to start the meeting</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!zoom-create-meeting type=Instant topic="Increasing documentation" user=mockmail@demistomock.com</code></p>
<p> </p>
<h5>Raw Output</h5>
<pre>{
    "Zoom": {
        "Meeting": {
            "topic": "Increasing documentation", 
            "uuid": "gsUjD/HxQmyVi5Oif4W2YQ==", 
            "settings": {
                "use_pmi": false, 
                "cn_meeting": false, 
                "alternative_hosts": "", 
                "watermark": false, 
                "approval_type": 2, 
                "mute_upon_entry": false, 
                "enforce_login": false, 
                "enforce_login_domains": "", 
                "in_meeting": false, 
                "participant_video": true, 
                "join_before_host": true, 
                "host_video": true, 
                "audio": "both", 
                "auto_recording": "none"
            }, 
            "created_at": "2018-07-23T08:49:03Z", 
            "timezone": "Asia/Jerusalem", 
            "start_url": "https://zoom.us/s/367272161?zak=eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJjbGllbnQiLCJ1aWQiOiJ1SmlaTi1PN1JwNkpwXzk5NUZwWkdnIiwiaXNzIjoid2ViIiwic3R5IjoxMDAsImNsdCI6MCwic3RrIjoiWG8xOWpNc3dUZGgyMDZ1WlFXSXQ1bVc5TG5MMzVaUzNxT1p1X213Yk5HNC5CZ1FnZVRReE1ISXpWVTk2ZG5oSE9IZFdOVEV2U2pCc1JUWjNiek5KVERNemIwWkFOalJsWXpsbE5tSTNPR1l5TkRKak5XSmhOVFJpTW1SaU16VTJNbUUzWkdFNVpEVmtaRFU0TTJJMVkyUTFaRFkwWm1ZMk5qUmlOREEzTXpVek5qUXpZUUFNTTBOQ1FYVnZhVmxUTTNNOUFBIiwiZXhwIjoxNTMyMzQyOTQzLCJpYXQiOjE1MzIzMzU3NDMsImFpZCI6ImFlS0QyQkZKUkFTdDFRVlVSV285Q0EiLCJjaWQiOiIifQ.axfvrRPnM8ATYWECdOcjWm-nwMcjFBOhszKbjRCXiD8", 
            "duration": 0, 
            "host_id": "uJiZN-O7Rp6Jp_995FpZGg", 
            "join_url": "https://zoom.us/j/367272161", 
            "type": 1, 
            "id": 367272161
        }
    }
}</pre>
<p> </p>
<h5>War Room Output</h5>
<p><img src="https://user-images.githubusercontent.com/20818773/43066722-117a9c6e-8e6e-11e8-86ba-30192dbbfbc8.png" alt="image" width="755" height="92"></p>
<p> </p>
<h3 id="h_298016959581532348272575">Get a recorded Zoom meeting</h3>
<hr>
<p>Retrieves a recorded Zoom meeting.</p>
<h5>Base Command</h5>
<p><code>zoom-fetch-recording</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 173px;"><strong>Input Parameter</strong></td>
<td style="width: 467px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 173px;">meeting_id</td>
<td style="width: 467px;">
<p>Meeting ID of the meeting you want to get the recording for.</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!zoom-fetch-recording meeting_id=154107399</code></p>
<p> </p>
<h5>Raw Output</h5>
<pre>{
    "File": [
        {
            "Info": "video/mp4", 
            "SHA1": "96f9ad9c50ace12a513de06078ad3f68114cebd8", 
            "Name": "recording_154107399_cd26753b-a192-40ee-b9c6-0360e9191bf7.mp4", 
            "Extension": "mp4", 
            "Size": 10272, 
            "EntryID": "1590@84a5132b-1001-4cb5-883e-fa82f693358d", 
            "SSDeep": "192:hX6hdPEInUOoYOBD2h6zE5ksSAEiVzMAyzsly/0/GCO3G:EE8p6D06KksfEiVQA/C3G", 
            "SHA256": "7691889f2786acdaea9d291c97f396ded33230986a9033cfbf2b45e3b5e3031b", 
            "Type": "ISO Media, MP4 v2 [ISO 14496-14]\n", 
            "MD5": "9a572f5f112aa257101f9c38bd75259b"
        }, 
        {
            "Info": "video/mp4", 
            "SHA1": "92e705ea254b2a9dd34bd07c6cab971ba534eab8", 
            "Name": "recording_154107399_abe7e541-aee8-4a16-9226-66f6508f1ec7.mp4", 
            "Extension": "mp4", 
            "Size": 1888, 
            "EntryID": "1592@84a5132b-1001-4cb5-883e-fa82f693358d", 
            "SSDeep": "12:fEb/SDSkLlYwRkq4W+R4bj8/4Vz164Jgxlsk7vZ:fc/S9tz+R48411xJ2ek7x", 
            "SHA256": "035dd853a1eff20c52e5062458c37ca2aefc3436fc4a69bb7a17814d3e0e9963", 
            "Type": "ISO Media, MP4 v2 [ISO 14496-14]\n", 
            "MD5": "b03011f54c1f843ee153ecfa6ca45f65"
        }
    ]
}</pre>
<p> </p>
<h5>War Room Output</h5>
<p><img src="https://user-images.githubusercontent.com/20818773/43075258-ee600b72-8e88-11e8-9547-8d74a1b9d5f8.png" alt="image" width="750" height="582"></p>
<p> </p>
<h3 id="h_10266497861532348515249">Get a list of Zoom users</h3>
<hr>
<p>Returns a list of all Zoom users.</p>
<h5>Base Command</h5>
<p><code>zoom-list-users</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 173px;"><strong>Input Parameter</strong></td>
<td style="width: 467px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 173px;">status</td>
<td style="width: 467px;">
<p>Status of users you want to return a list of</p>
</td>
</tr>
<tr>
<td style="width: 173px;">page-size</td>
<td style="width: 467px;">
<p>Number of users to return, maximum is 300</p>
</td>
</tr>
<tr>
<td style="width: 173px;">page-number</td>
<td style="width: 467px;">
<p>Page of results to return</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th>Path</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>Zoom.Metadata.Count</td>
<td>Total page count available</td>
</tr>
<tr>
<td>Zoom.Metadata.Number</td>
<td>Current page number</td>
</tr>
<tr>
<td>Zoom.Metadata.Size</td>
<td>Number of results in current page</td>
</tr>
<tr>
<td>Zoom.Metadata.Total</td>
<td>Total number of records</td>
</tr>
<tr>
<td>Zoom.User.id</td>
<td>ID of the user</td>
</tr>
<tr>
<td>Zoom.User.first_name</td>
<td>First name of the user</td>
</tr>
<tr>
<td>Zoom.User.last_name</td>
<td>Last name of the user</td>
</tr>
<tr>
<td>Zoom.User.email</td>
<td>Email of the user</td>
</tr>
<tr>
<td>Zoom.User.type</td>
<td>Type of user</td>
</tr>
<tr>
<td>Zoom.User.created_at</td>
<td>Date when the user was created</td>
</tr>
<tr>
<td>Zoom.User.dept</td>
<td>Department for the user</td>
</tr>
<tr>
<td>Zoom.User.verified</td>
<td>Is the user verified</td>
</tr>
<tr>
<td>Zoom.User.last_login_time</td>
<td>Last login time of the user</td>
</tr>
<tr>
<td>Zoom.User.timezone</td>
<td>Default timezone for the user</td>
</tr>
<tr>
<td>Zoom.User.pmi</td>
<td>PMI of user</td>
</tr>
<tr>
<td>Zoom.User.group_ids</td>
<td>Groups user belongs to</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!zoom-list-users</code></p>
<p> </p>
<h5>Raw Output</h5>
<pre>{
    "Zoom": {
        "User": [
            {
                "first_name": "admin", 
                "last_name": "zoom", 
                "verified": 1, 
                "last_login_time": "2018-07-23T08:31:34Z", 
                "created_at": "2018-07-19T05:54:18Z", 
                "email": "admin@demistodev.com", 
                "pmi": 9409768194, 
                "timezone": "Asia/Jerusalem", 
                "type": 2, 
                "id": "uJiZN-O7Rp6Jp_995FpZGg"
            }
        ], 
        "Metadata": {
            "Count": 1, 
            "Total": 1, 
            "Number": 1, 
            "Size": 30
        }
    }
}</pre>
<p> </p>
<h5>War Room Output</h5>
<p><img src="https://user-images.githubusercontent.com/20818773/43067857-5b911802-8e71-11e8-9a16-2425bd249aa3.png" alt="image" width="750" height="620"></p>
<p> </p>
<h3 id="h_542253733281532434898368">Delete a Zoom user</h3>
<hr>
<p>Deletes a specified Zoom user.</p>
<h5>Base Command</h5>
<p><code>zoom-delete-user</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 173px;"><strong>Input Parameter</strong></td>
<td style="width: 467px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 173px;">status</td>
<td style="width: 467px;">
<p>Status of users you want to return a list of</p>
</td>
</tr>
<tr>
<td style="width: 173px;">page-size</td>
<td style="width: 467px;">
<p>Number of users to return, maximum is 300</p>
</td>
</tr>
<tr>
<td style="width: 173px;">page-number</td>
<td style="width: 467px;">
<p>Page of results to return</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!zoom-delete-user user="mockmail@demistomock.com" action="disassociate"</code></p>
<p> </p>
<h5>Raw Output</h5>
<p>There is no raw output for this command</p>
<p> </p>
<h5>War Room Output</h5>
<p><img src="https://user-images.githubusercontent.com/20818773/43068043-eeea920e-8e71-11e8-99cd-00bca140e9fe.png" alt="image" width="752" height="107"></p>
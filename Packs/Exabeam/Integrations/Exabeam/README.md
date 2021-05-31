<p>
The Exabeam Security Management Platform provides end-to-end detection, User Event Behavioral Analytics, and SOAR.

</p>

<h2>Configure Exabeam on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Exabeam.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Server URL (e.g https://192.168.0.1:{port})</strong></li>
   <li><strong>Username</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Use system proxy settings</strong></li>
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
  <li><a href="#exabeam-get-notable-users" target="_self">Returns notable users in a period of time: exabeam-get-notable-users</a></li>
  <li><a href="#exabeam-get-watchlists" target="_self">Returns all watchlist IDs and titles: exabeam-get-watchlists</a></li>
  <li><a href="#exabeam-get-peer-groups" target="_self">Returns all peer groups: exabeam-get-peer-groups</a></li>
  <li><a href="#exabeam-get-user-info" target="_self">Returns user information data for the username: exabeam-get-user-info</a></li>
  <li><a href="#exabeam-get-user-labels" target="_self">Returns all labels of the user: exabeam-get-user-labels</a></li>
  <li><a href="#exabeam-get-user-sessions" target="_self">Returns sessions for the given username and time range: exabeam-get-user-sessions</a></li>
  <li><a href="#exabeam-delete-watchlist" target="_self">Deletes a watchlist: exabeam-delete-watchlist</a></li>
  <li><a href="#exabeam-get-asset-data" target="_self">Returns asset data: exabeam-get-asset-data</a></li>
</ol>
<h3 id="exabeam-get-notable-users">1. exabeam-get-notable-users</h3>
<hr>
<p>Returns notable users in a period of time.</p>
<h5>Base Command</h5>
<p>
  <code>exabeam-get-notable-users</code>
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
      <td>time_period</td>
      <td>The time period for which to fetch notable users, such as 3 months, 2 days, 4 hours, 1 year, and so on.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The maximum number of returned results.</td>
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
      <td>Exabeam.User.RiskScore</td>
      <td>Number</td>
      <td>The risk score of the notable user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.UserFullName</td>
      <td>String</td>
      <td>The full name of the user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.AverageRiskScore</td>
      <td>Number</td>
      <td>The average risk score of the user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.FirstSeen</td>
      <td>Date</td>
      <td>The date the user was first seen.</td>
    </tr>
    <tr>
      <td>Exabeam.User.NotableSessionIds</td>
      <td>String</td>
      <td>The ID of the notable session.</td>
    </tr>
    <tr>
      <td>Exabeam.User.AccountsNumber</td>
      <td>Number</td>
      <td>The number of accounts.</td>
    </tr>
    <tr>
      <td>Exabeam.User.LastSeen</td>
      <td>Date</td>
      <td>The date the user was last seen.</td>
    </tr>
    <tr>
      <td>Exabeam.User.Location</td>
      <td>String</td>
      <td>The location of the user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.UserName</td>
      <td>String</td>
      <td>The name of the user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.Labels</td>
      <td>String</td>
      <td>The labels of the user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.LastActivityType</td>
      <td>String</td>
      <td>The last activity type of the user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.NotableUser</td>
      <td>Boolean</td>
      <td>Whether the user is a notable user.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!exabeam-get-notable-users limit=3 time_period="1 year"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Exabeam.User": [
        {
            "Department": "IT",
            "EmployeeType": "employee",
            "FirstSeen": "2018-08-01T11:50:16",
            "HighestRiskSession": {
                "accounts": [
                    "account_name"
                ],
                "endTime": 1535991695000,
                "initialRiskScore": 9,
                "label": "",
                "loginHost": "login_host",
                "numOfAccounts": 1,
                "numOfAssets": 5,
                "numOfEvents": 6,
                "numOfReasons": 9,
                "numOfSecurityEvents": 0,
                "numOfZones": 0,
                "riskScore": 265,
                "sessionId": "session_id",
                "startTime": 1535973498000,
                "username": "username",
                "zones": []
            },
            "Labels": [
                "privileged_user"
            ],
            "LastActivity": "Account is active",
            "LastSeen": "2018-09-09T16:36:13",
            "Location": "Atlanta",
            "NotableSessionIds": [
                "session_id"
            ],
            "NotableUser": true,
            "RiskScore": null,
            "Title": "Network Engineer",
            "UserFullName": "full_name",
            "UserName": "username"
        },
        {
            "Department": "HR",
            "EmployeeType": "employee",
            "FirstSeen": "2018-07-03T14:26:26",
            "HighestRiskSession": {
                "accounts": [
                    "account_name"
                ],
                "endTime": 1538233298000,
                "initialRiskScore": 14,
                "label": "vpn-in",
                "loginHost": "login_host",
                "numOfAccounts": 2,
                "numOfAssets": 14,
                "numOfEvents": 15,
                "numOfReasons": 9,
                "numOfSecurityEvents": 1,
                "numOfZones": 0,
                "riskScore": 169,
                "sessionId": "session_id",
                "startTime": 1538222645000,
                "username": "username",
                "zones": []
            },
            "Labels": [],
            "LastActivity": "Account is active",
            "LastSeen": "2018-09-30T16:27:01",
            "Location": "Chicago",
            "NotableSessionIds": [
                "session_id"
            ],
            "NotableUser": true,
            "RiskScore": null,
            "Title": "Human Resources Coordinator",
            "UserFullName": "full name",
            "UserName": "username"
        },
        {
            "Department": "Sales",
            "EmployeeType": "employee",
            "FirstSeen": "2018-08-10T15:55:25",
            "HighestRiskSession": {
                "accounts": [
                    "hosborne"
                ],
                "endTime": 1538281057000,
                "initialRiskScore": 0,
                "label": "",
                "loginHost": "",
                "numOfAccounts": 1,
                "numOfAssets": 3,
                "numOfEvents": 62,
                "numOfReasons": 8,
                "numOfSecurityEvents": 1,
                "numOfZones": 0,
                "riskScore": 132,
                "sessionId": "session_id",
                "startTime": 1538250305000,
                "username": "username",
                "zones": []
            },
            "Labels": [
                "privileged_user"
            ],
            "LastActivity": "Account is active",
            "LastSeen": "2018-09-30T16:27:01",
            "Location": "Atlanta",
            "NotableSessionIds": [
                "session_id"
            ],
            "NotableUser": true,
            "RiskScore": null,
            "Title": "Sales Representative",
            "UserFullName": "fullname",
            "UserName": "username"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Exabeam Notable Users:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>UserName</strong></th>
      <th><strong>UserFullName</strong></th>
      <th><strong>Title</strong></th>
      <th><strong>Department</strong></th>
      <th><strong>Labels</strong></th>
      <th><strong>NotableSessionIds</strong></th>
      <th><strong>EmployeeType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
      <th><strong>LastActivity</strong></th>
      <th><strong>Location</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> username </td>
      <td> fullname </td>
      <td> Network Engineer </td>
      <td> IT </td>
      <td> privileged_user </td>
      <td> session_id </td>
      <td> employee </td>
      <td> 2018-08-01T11:50:16 </td>
      <td> 2018-09-09T16:36:13 </td>
      <td> Account is active </td>
      <td> Atlanta </td>
    </tr>
    <tr>
      <td> username </td>
      <td> fullname </td>
      <td> Human Resources Coordinator </td>
      <td> HR </td>
      <td>  </td>
      <td> session_id </td>
      <td> employee </td>
      <td> 2018-07-03T14:26:26 </td>
      <td> 2018-09-30T16:27:01 </td>
      <td> Account is active </td>
      <td> Chicago </td>
    </tr>
    <tr>
      <td> username </td>
      <td> fullname </td>
      <td> Sales Representative </td>
      <td> Sales </td>
      <td> privileged_user </td>
      <td> session_id </td>
      <td> employee </td>
      <td> 2018-08-10T15:55:25 </td>
      <td> 2018-09-30T16:27:01 </td>
      <td> Account is active </td>
      <td> Atlanta </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="exabeam-get-watchlists">2. exabeam-get-watchlists</h3>
<hr>
<p>Returns all watchlist IDs and titles.</p>
<h5>Base Command</h5>
<p>
  <code>exabeam-get-watchlists</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
<h5>Input</h5>
There are no input arguments for this command.
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
      <td>Exabeam.Watchlist.Category</td>
      <td>String</td>
      <td>The watchlist category.</td>
    </tr>
    <tr>
      <td>Exabeam.Watchlist.Title</td>
      <td>String</td>
      <td>The watchlist title.</td>
    </tr>
    <tr>
      <td>Exabeam.Watchlist.WatchlistID</td>
      <td>String</td>
      <td>The watchlist ID.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!exabeam-get-watchlists</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Exabeam.Watchlist": [
        {
            "Category": "UserLabels",
            "Title": "Executive Users",
            "WatchlistID": "5c869ab0315c745d905a26d9"
        },
        {
            "Category": "UserLabels",
            "Title": "Service Accounts",
            "WatchlistID": "5c869ab0315c745d905a26da"
        },
        {
            "Category": "Users",
            "Title": "user watchlist",
            "WatchlistID": "5dbaba2dd4e62a0009dd7ae4"
        },
        {
            "Category": "PeerGroups",
            "Title": "VP Operations",
            "WatchlistID": "5d8751723b72ea000830066a"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Exabeam Watchlists:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>WatchlistID</strong></th>
      <th><strong>Title</strong></th>
      <th><strong>Category</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 5c869ab0315c745d905a26d9 </td>
      <td> Executive Users </td>
      <td> UserLabels </td>
    </tr>
    <tr>
      <td> 5c869ab0315c745d905a26da </td>
      <td> Service Accounts </td>
      <td> UserLabels </td>
    </tr>
    <tr>
      <td> 5dbaba2dd4e62a0009dd7ae4 </td>
      <td> user watchlist </td>
      <td> Users </td>
    </tr>
    <tr>
      <td> 5d8751723b72ea000830066a </td>
      <td> VP Operations </td>
      <td> PeerGroups </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="exabeam-get-peer-groups">3. exabeam-get-peer-groups</h3>
<hr>
<p>Returns all peer groups.</p>
<h5>Base Command</h5>
<p>
  <code>exabeam-get-peer-groups</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
<h5>Input</h5>
There are no input arguments for this command.
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
      <td>Exabeam.PeerGroup.Name</td>
      <td>String</td>
      <td>The name of the peer group.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!exabeam-get-peer-groups</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Exabeam.PeerGroup": [
        {
            "Name": "Marketing"
        },
        {
            "Name": "usa"
        },
        {
            "Name": "101"
        },
        {
            "Name": "Program Manager"
        },
        {
            "Name": "Channel Administrator"
        },
        {
            "Name": "Chief Marketing Officer"
        },
        {
            "Name": ""
        },
        {
            "Name": "Chief Strategy Officer"
        },
        {
            "Name": "CN=Andrew Bautista,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "BitLockerUsersComputers"
        },
        {
            "Name": "trinet"
        },
        {
            "Name": "Admin Operations"
        },
        {
            "Name": "118"
        },
        {
            "Name": "Corp"
        },
        {
            "Name": "102"
        },
        {
            "Name": "CN=Emery Santiago,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "105"
        },
        {
            "Name": "Computer Scientist"
        },
        {
            "Name": "Electrical Engineer"
        },
        {
            "Name": "VP Business Development"
        },
        {
            "Name": "Hardware Engineer"
        },
        {
            "Name": "Executive Assistant"
        },
        {
            "Name": "GenCouncil"
        },
        {
            "Name": "Consulting"
        },
        {
            "Name": "109"
        },
        {
            "Name": "Legal Secretary"
        },
        {
            "Name": "VP Operations"
        },
        {
            "Name": "106"
        },
        {
            "Name": "Washington"
        },
        {
            "Name": "Operations Director"
        },
        {
            "Name": "Process Engineer"
        },
        {
            "Name": "104"
        },
        {
            "Name": "Account Manager"
        },
        {
            "Name": "Shop Floor Supervisor"
        },
        {
            "Name": "IT Operations"
        },
        {
            "Name": "VP Marketing"
        },
        {
            "Name": "HR"
        },
        {
            "Name": "design,milling"
        },
        {
            "Name": "superUsers"
        },
        {
            "Name": "WIFI IL"
        },
        {
            "Name": "ProgramMgmt"
        },
        {
            "Name": "Engagement Manager"
        },
        {
            "Name": "InfoSec"
        },
        {
            "Name": "Sales Operations"
        },
        {
            "Name": "Security Systems Engineer"
        },
        {
            "Name": "design"
        },
        {
            "Name": "CN=Tracee Weber,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "sap"
        },
        {
            "Name": "CN=May Mcconnell,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "jobvite"
        },
        {
            "Name": "Sales"
        },
        {
            "Name": "partners"
        },
        {
            "Name": "CN=Emely Blanchard,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "Corporate Marketing Strategist"
        },
        {
            "Name": "Web Developer"
        },
        {
            "Name": "Domain Admins"
        },
        {
            "Name": "VP Information Systems"
        },
        {
            "Name": "CN=Raelene Thompson,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "VP Engineering"
        },
        {
            "Name": "Marketing Coordinator"
        },
        {
            "Name": "VP Sales"
        },
        {
            "Name": "103"
        },
        {
            "Name": "Product Manager"
        },
        {
            "Name": "Welder"
        },
        {
            "Name": "milling"
        },
        {
            "Name": "VP Human Resources"
        },
        {
            "Name": "Partner Corrdinator"
        },
        {
            "Name": "execs"
        },
        {
            "Name": "117"
        },
        {
            "Name": "Engineering"
        },
        {
            "Name": "Seattle"
        },
        {
            "Name": "107"
        },
        {
            "Name": "Program Director"
        },
        {
            "Name": "Chief Council"
        },
        {
            "Name": "Machinist"
        },
        {
            "Name": "Software Developer"
        },
        {
            "Name": "Office365-Users"
        },
        {
            "Name": "CN=Harris Oliver,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "CN=Tu Petersen,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "ITServiceUsersDomainAdmins"
        },
        {
            "Name": "root"
        },
        {
            "Name": "IT"
        },
        {
            "Name": "Atlanta"
        },
        {
            "Name": "autocad"
        },
        {
            "Name": "Building Engineer"
        },
        {
            "Name": "Dallas"
        },
        {
            "Name": "Security Security Coordinator"
        },
        {
            "Name": "salesforce"
        },
        {
            "Name": "Software Engineer"
        },
        {
            "Name": "110"
        },
        {
            "Name": "Saless"
        },
        {
            "Name": "CN=Marianne Hughes,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "Civil Engineer"
        },
        {
            "Name": "CN=Vince Andrade,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "Security Analyst"
        },
        {
            "Name": "Sales Representative"
        },
        {
            "Name": "Operations"
        },
        {
            "Name": "Jobvite-users"
        },
        {
            "Name": "Chicago"
        },
        {
            "Name": "Los Angeles"
        },
        {
            "Name": "New York"
        },
        {
            "Name": "councilApp"
        },
        {
            "Name": "VP Information Security"
        },
        {
            "Name": "Direct Support"
        },
        {
            "Name": "MA/DCG"
        },
        {
            "Name": "orch_admins"
        },
        {
            "Name": "Chief Operating Officer"
        },
        {
            "Name": "ITInfraAdmins"
        },
        {
            "Name": "Manager, IT Corporate Services"
        },
        {
            "Name": "VP Council"
        },
        {
            "Name": "CN=Felipe Pennington,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "CN=May Mcconnell,OU=US,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local"
        },
        {
            "Name": "Public Relations Officer"
        },
        {
            "Name": "Human Resources Coordinator"
        },
        {
            "Name": "Chief Information Secuity Officer"
        },
        {
            "Name": "Marketing Strategist"
        },
        {
            "Name": "Front Desk Receptionist"
        },
        {
            "Name": "CEO"
        },
        {
            "Name": "IT Administrator"
        },
        {
            "Name": "Sales Coordinator"
        },
        {
            "Name": "Network Engineer"
        },
        {
            "Name": "108"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Exabeam Peer Groups:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> Marketing </td>
    </tr>
    <tr>
      <td> usa </td>
    </tr>
    <tr>
      <td> 101 </td>
    </tr>
    <tr>
      <td> Program Manager </td>
    </tr>
    <tr>
      <td> Channel Administrator </td>
    </tr>
    <tr>
      <td> Chief Marketing Officer </td>
    </tr>
    <tr>
      <td>  </td>
    </tr>
    <tr>
      <td> Chief Strategy Officer </td>
    </tr>
    <tr>
      <td> CN=Andrew Bautista,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> BitLockerUsersComputers </td>
    </tr>
    <tr>
      <td> trinet </td>
    </tr>
    <tr>
      <td> Admin Operations </td>
    </tr>
    <tr>
      <td> 118 </td>
    </tr>
    <tr>
      <td> Corp </td>
    </tr>
    <tr>
      <td> 102 </td>
    </tr>
    <tr>
      <td> CN=Emery Santiago,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> 105 </td>
    </tr>
    <tr>
      <td> Computer Scientist </td>
    </tr>
    <tr>
      <td> Electrical Engineer </td>
    </tr>
    <tr>
      <td> VP Business Development </td>
    </tr>
    <tr>
      <td> Hardware Engineer </td>
    </tr>
    <tr>
      <td> Executive Assistant </td>
    </tr>
    <tr>
      <td> GenCouncil </td>
    </tr>
    <tr>
      <td> Consulting </td>
    </tr>
    <tr>
      <td> 109 </td>
    </tr>
    <tr>
      <td> Legal Secretary </td>
    </tr>
    <tr>
      <td> VP Operations </td>
    </tr>
    <tr>
      <td> 106 </td>
    </tr>
    <tr>
      <td> Washington </td>
    </tr>
    <tr>
      <td> Operations Director </td>
    </tr>
    <tr>
      <td> Process Engineer </td>
    </tr>
    <tr>
      <td> 104 </td>
    </tr>
    <tr>
      <td> Account Manager </td>
    </tr>
    <tr>
      <td> Shop Floor Supervisor </td>
    </tr>
    <tr>
      <td> IT Operations </td>
    </tr>
    <tr>
      <td> VP Marketing </td>
    </tr>
    <tr>
      <td> HR </td>
    </tr>
    <tr>
      <td> design,milling </td>
    </tr>
    <tr>
      <td> superUsers </td>
    </tr>
    <tr>
      <td> WIFI IL </td>
    </tr>
    <tr>
      <td> ProgramMgmt </td>
    </tr>
    <tr>
      <td> Engagement Manager </td>
    </tr>
    <tr>
      <td> InfoSec </td>
    </tr>
    <tr>
      <td> Sales Operations </td>
    </tr>
    <tr>
      <td> Security Systems Engineer </td>
    </tr>
    <tr>
      <td> design </td>
    </tr>
    <tr>
      <td> CN=Tracee Weber,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> sap </td>
    </tr>
    <tr>
      <td> CN=May Mcconnell,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> jobvite </td>
    </tr>
    <tr>
      <td> Sales </td>
    </tr>
    <tr>
      <td> partners </td>
    </tr>
    <tr>
      <td> CN=Emely Blanchard,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> Corporate Marketing Strategist </td>
    </tr>
    <tr>
      <td> Web Developer </td>
    </tr>
    <tr>
      <td> Domain Admins </td>
    </tr>
    <tr>
      <td> VP Information Systems </td>
    </tr>
    <tr>
      <td> CN=Raelene Thompson,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> VP Engineering </td>
    </tr>
    <tr>
      <td> Marketing Coordinator </td>
    </tr>
    <tr>
      <td> VP Sales </td>
    </tr>
    <tr>
      <td> 103 </td>
    </tr>
    <tr>
      <td> Product Manager </td>
    </tr>
    <tr>
      <td> Welder </td>
    </tr>
    <tr>
      <td> milling </td>
    </tr>
    <tr>
      <td> VP Human Resources </td>
    </tr>
    <tr>
      <td> Partner Corrdinator </td>
    </tr>
    <tr>
      <td> execs </td>
    </tr>
    <tr>
      <td> 117 </td>
    </tr>
    <tr>
      <td> Engineering </td>
    </tr>
    <tr>
      <td> Seattle </td>
    </tr>
    <tr>
      <td> 107 </td>
    </tr>
    <tr>
      <td> Program Director </td>
    </tr>
    <tr>
      <td> Chief Council </td>
    </tr>
    <tr>
      <td> Machinist </td>
    </tr>
    <tr>
      <td> Software Developer </td>
    </tr>
    <tr>
      <td> Office365-Users </td>
    </tr>
    <tr>
      <td> CN=Harris Oliver,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> CN=Tu Petersen,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> ITServiceUsersDomainAdmins </td>
    </tr>
    <tr>
      <td> root </td>
    </tr>
    <tr>
      <td> IT </td>
    </tr>
    <tr>
      <td> Atlanta </td>
    </tr>
    <tr>
      <td> autocad </td>
    </tr>
    <tr>
      <td> Building Engineer </td>
    </tr>
    <tr>
      <td> Dallas </td>
    </tr>
    <tr>
      <td> Security Security Coordinator </td>
    </tr>
    <tr>
      <td> salesforce </td>
    </tr>
    <tr>
      <td> Software Engineer </td>
    </tr>
    <tr>
      <td> 110 </td>
    </tr>
    <tr>
      <td> Saless </td>
    </tr>
    <tr>
      <td> CN=Marianne Hughes,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> Civil Engineer </td>
    </tr>
    <tr>
      <td> CN=Vince Andrade,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> Security Analyst </td>
    </tr>
    <tr>
      <td> Sales Representative </td>
    </tr>
    <tr>
      <td> Operations </td>
    </tr>
    <tr>
      <td> Jobvite-users </td>
    </tr>
    <tr>
      <td> Chicago </td>
    </tr>
    <tr>
      <td> Los Angeles </td>
    </tr>
    <tr>
      <td> New York </td>
    </tr>
    <tr>
      <td> councilApp </td>
    </tr>
    <tr>
      <td> VP Information Security </td>
    </tr>
    <tr>
      <td> Direct Support </td>
    </tr>
    <tr>
      <td> MA/DCG </td>
    </tr>
    <tr>
      <td> orch_admins </td>
    </tr>
    <tr>
      <td> Chief Operating Officer </td>
    </tr>
    <tr>
      <td> ITInfraAdmins </td>
    </tr>
    <tr>
      <td> Manager, IT Corporate Services </td>
    </tr>
    <tr>
      <td> VP Council </td>
    </tr>
    <tr>
      <td> CN=Felipe Pennington,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> CN=May Mcconnell,OU=US,OU=Users,OU=Ktenergy,DC=ktenergy,DC=local </td>
    </tr>
    <tr>
      <td> Public Relations Officer </td>
    </tr>
    <tr>
      <td> Human Resources Coordinator </td>
    </tr>
    <tr>
      <td> Chief Information Secuity Officer </td>
    </tr>
    <tr>
      <td> Marketing Strategist </td>
    </tr>
    <tr>
      <td> Front Desk Receptionist </td>
    </tr>
    <tr>
      <td> CEO </td>
    </tr>
    <tr>
      <td> IT Administrator </td>
    </tr>
    <tr>
      <td> Sales Coordinator </td>
    </tr>
    <tr>
      <td> Network Engineer </td>
    </tr>
    <tr>
      <td> 108 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="exabeam-get-user-info">4. exabeam-get-user-info</h3>
<hr>
<p>Returns user information data for the username.</p>
<h5>Base Command</h5>
<p>
  <code>exabeam-get-user-info</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>username</td>
      <td>The username of the user to fetch.</td>
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
      <td>Exabeam.User.RiskScore</td>
      <td>Number</td>
      <td>The risk score of the user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.AverageRiskScore</td>
      <td>Number</td>
      <td>The average risk score.</td>
    </tr>
    <tr>
      <td>Exabeam.User.PeerGroupFieldName</td>
      <td>String</td>
      <td>The field name of the peer group.</td>
    </tr>
    <tr>
      <td>Exabeam.User.FirstSeen</td>
      <td>Date</td>
      <td>The date when the user was first seen.</td>
    </tr>
    <tr>
      <td>Exabeam.User.PeerGroupDisplayName</td>
      <td>String</td>
      <td>The display name of the Peer group.</td>
    </tr>
    <tr>
      <td>Exabeam.User.LastSeen</td>
      <td>Date</td>
      <td>The date the user was last seen.</td>
    </tr>
    <tr>
      <td>Exabeam.User.PeerGroupFieldValue</td>
      <td>String</td>
      <td>The field value of the peer group.</td>
    </tr>
    <tr>
      <td>Exabeam.User.Label</td>
      <td>String</td>
      <td>The labels of the user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.Username</td>
      <td>String</td>
      <td>The name of the user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.PeerGroupType</td>
      <td>String</td>
      <td>The type of the peer group.</td>
    </tr>
    <tr>
      <td>Exabeam.User.LastSessionID</td>
      <td>String</td>
      <td>The last session ID of the user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.LastActivityType</td>
      <td>String</td>
      <td>The last activity type of the user.</td>
    </tr>
    <tr>
      <td>Exabeam.User.AccountNames</td>
      <td>String</td>
      <td>The account name of the user.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!exabeam-get-user-info username={username}</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Exabeam.User": {
        "AccountNames": [
            "account_name"
        ],
        "AverageRiskScore": 102.53,
        "FirstSeen": "2018-08-01T11:50:16",
        "Label": [
            "privileged_user"
        ],
        "LastActivityType": "Account is active",
        "LastSeen": "2018-09-09T16:36:13",
        "LastSessionID": "session_id",
        "PeerGroupDisplayName": "root",
        "PeerGroupFieldName": "Peer Groups",
        "PeerGroupFieldValue": "root",
        "PeerGroupType": "Group",
        "RiskScore": 163,
        "Username": "username"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>User jmontoya information:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Username</strong></th>
      <th><strong>RiskScore</strong></th>
      <th><strong>AverageRiskScore</strong></th>
      <th><strong>LastSessionID</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>LastSeen</strong></th>
      <th><strong>LastActivityType</strong></th>
      <th><strong>AccountNames</strong></th>
      <th><strong>PeerGroupFieldName</strong></th>
      <th><strong>PeerGroupFieldValue</strong></th>
      <th><strong>PeerGroupDisplayName</strong></th>
      <th><strong>PeerGroupType</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> {username} </td>
      <td> 163 </td>
      <td> 102.53 </td>
      <td> {session_id} </td>
      <td> 2018-08-01T11:50:16 </td>
      <td> 2018-09-09T16:36:13 </td>
      <td> Account is active </td>
      <td> {account_name} </td>
      <td> Peer Groups </td>
      <td> root </td>
      <td> root </td>
      <td> Group </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="exabeam-get-user-labels">5. exabeam-get-user-labels</h3>
<hr>
<p>Returns all labels of the user.</p>
<h5>Base Command</h5>
<p>
  <code>exabeam-get-user-labels</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
<h5>Input</h5>
There are no input arguments for this command.
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
      <td>Exabeam.UserLabel.Label</td>
      <td>String</td>
      <td>The label of the user.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!exabeam-get-user-labels</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Exabeam.UserLabel": [
        {
            "Label": "privileged_user"
        },
        {
            "Label": "service_account"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Exabeam User Labels:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Label</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> privileged_user </td>
    </tr>
    <tr>
      <td> service_account </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="exabeam-get-user-sessions">6. exabeam-get-user-sessions</h3>
<hr>
<p>Returns sessions for the given username and time range.</p>
<h5>Base Command</h5>
<p>
  <code>exabeam-get-user-sessions</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>username</td>
      <td>The username for which to fetch data.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>start_time</td>
      <td>The Start time of the time range. For example, 2018-08-01T11:50:16).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>end_time</td>
      <td>The end time of the time range. For example, 2018-08-01T11:50:16.</td>
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
      <td>Exabeam.User.Session.EndTime</td>
      <td>Date</td>
      <td>The end time of the session.</td>
    </tr>
    <tr>
      <td>Exabeam.User.Session.InitialRiskScore</td>
      <td>Number</td>
      <td>The initial risk score of the session.</td>
    </tr>
    <tr>
      <td>Exabeam.User.Session.Label</td>
      <td>String</td>
      <td>The label of the session.</td>
    </tr>
    <tr>
      <td>Exabeam.User.Session.LoginHost</td>
      <td>String</td>
      <td>The login host.</td>
    </tr>
    <tr>
      <td>Exabeam.User.Session.RiskScore</td>
      <td>Number</td>
      <td>The risk score of the session.</td>
    </tr>
    <tr>
      <td>Exabeam.User.Session.SessionID</td>
      <td>String</td>
      <td>The ID of the session.</td>
    </tr>
    <tr>
      <td>Exabeam.User.Session.StartTime</td>
      <td>Date</td>
      <td>The start time of the session.</td>
    </tr>
    <tr>
      <td>Exabeam.User.Username</td>
      <td>String</td>
      <td>The username of the session.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!exabeam-get-user-sessions username={username} start_time=2018-08-01T11:50:16</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Exabeam.User": {
        "Session": [
            {
                "EndTime": "2018-08-01T20:00:17",
                "InitialRiskScore": 0,
                "Label": "",
                "LoginHost": "login_host",
                "RiskScore": 0,
                "SessionID": "session_id",
                "StartTime": "2018-08-01T14:05:46"
            },
            {
                "EndTime": "2018-08-02T02:37:51",
                "InitialRiskScore": 0,
                "Label": "vpn-in",
                "LoginHost": "login_host",
                "RiskScore": 0,
                "SessionID": "seesion_id",
                "StartTime": "2018-08-01T23:17:00"
            },
        ],
        "Username": "username"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>User {username} sessions information:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>SessionID</strong></th>
      <th><strong>RiskScore</strong></th>
      <th><strong>InitialRiskScore</strong></th>
      <th><strong>StartTime</strong></th>
      <th><strong>EndTime</strong></th>
      <th><strong>LoginHost</strong></th>
      <th><strong>Label</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> session_id </td>
      <td> 0 </td>
      <td> 0 </td>
      <td> 2018-08-01T14:05:46 </td>
      <td> 2018-08-01T20:00:17 </td>
      <td> login_host </td>
      <td>  </td>
    </tr>
    <tr>
      <td> session_id </td>
      <td> 0 </td>
      <td> 0 </td>
      <td> 2018-08-01T23:17:00 </td>
      <td> 2018-08-02T02:37:51 </td>
      <td> login_host </td>
      <td> vpn-in </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="exabeam-delete-watchlist">7. exabeam-delete-watchlist</h3>
<hr>
<p>Deletes a watchlist.</p>
<h5>Base Command</h5>
<p>
  <code>exabeam-delete-watchlist</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>watchlist_id</td>
      <td>The watchlist ID.</td>
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
  <code>!exabeam-delete-watchlist watchlist_id=5de50f82088c6a000865408d</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
The watchlist 5de50f82088c6a000865408d was deleted successfully.
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="exabeam-get-asset-data">8. exabeam-get-asset-data</h3>
<hr>
<p>Returns asset data.</p>
<h5>Base Command</h5>
<p>
  <code>exabeam-get-asset-data</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>asset_name</td>
      <td>The name of the asset.</td>
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
      <td>Exabeam.Asset.HostName</td>
      <td>String</td>
      <td>The host name of the asset.</td>
    </tr>
    <tr>
      <td>Exabeam.Asset.IPAddress</td>
      <td>String</td>
      <td>The IP address of the asset.</td>
    </tr>
    <tr>
      <td>Exabeam.Asset.AssetType</td>
      <td>String</td>
      <td>Thr type of the asset.</td>
    </tr>
    <tr>
      <td>Exabeam.Asset.FirstSeen</td>
      <td>Date</td>
      <td>The date the asset was first seen.</td>
    </tr>
    <tr>
      <td>Exabeam.Asset.LastSeen</td>
      <td>String</td>
      <td>The date the asset was last seen.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!exabeam-get-asset-data asset_name={host_name}</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Exabeam.Asset": {
        "AssetType": "Windows",
        "FirstSeen": "2018-07-03T14:21:00",
        "HostName": "host_name",
        "IPAddress": "ip_address",
        "Labels": null,
        "LastSeen": "2018-09-30T16:23:17"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Exabeam Asset Data:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>AssetType</strong></th>
      <th><strong>FirstSeen</strong></th>
      <th><strong>HostName</strong></th>
      <th><strong>IPAddress</strong></th>
      <th><strong>LastSeen</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> Windows </td>
      <td> 2018-07-03T14:21:00 </td>
      <td> host_name </td>
      <td> ip_address </td>
      <td> 2018-09-30T16:23:17 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
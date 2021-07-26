<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the EasyVista integration to search for incidents and requests, and retrieve their status and information.</p>
<p>This integration was integrated and tested with EasyVista v2016.1.300.2. For more information, visit the <a href="https://wiki.easyvista.com/xwiki/bin/view/Documentation/WebService+REST">EasyVista REST API documentation</a>.</p>
<hr>
<h2>Use Cases</h2>
<p>Search for incidents and requests.</p>
<hr>
<h2>Prerequisites</h2>
<p>The account you use must be the account Service Manager used, for example, 50004: Production base; 50005: Sandbox base.</p>
<hr>
<h2>Configure EasyVista on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for EasyVista.</li>
<li>Click <strong>Add instance</strong><span class="wysiwyg-color-black"> to create and configure a new integration instance.</span>
<ul>
<li>
<strong>Name:</strong> a textual name for the integration instance</li>
<li>
<strong>Server URL</strong> (example: https://your_company.easyvista.com)</li>
<li><strong>Username</strong></li>
<li><strong>Do not validate server certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>
</ol>
<hr>
<h2>Commands</h2>
<ul>
<li><a href="#h_78777276751528718297700">Search: easy-vista-search</a></li>
</ul>
<hr>
<h3 id="h_78777276751528718297700">Search: easy-vista-search</h3>
<p>Search for Incidents and requests.</p>
<h5>Basic Command</h5>
<p><code>!easy-vista-search</code></p>
<h5>Input</h5>
<table style="height: 95px; width: 781px;" border="6" cellpadding="2">
<tbody>
<tr>
<td style="width: 139px;"><strong>Parameter</strong></td>
<td style="width: 647px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 139px;">asset</td>
<td style="width: 647px;">
<p>Asset to search for (example: requestor)</p>
</td>
</tr>
<tr>
<td style="width: 139px;">attribute</td>
<td style="width: 647px;">
<p>Attribute to search for (example: last_name)</p>
</td>
</tr>
<tr>
<td style="width: 139px;">value</td>
<td style="width: 647px;">
<p>Value to search (example: "Morley, Gaby")</p>
</td>
</tr>
<tr>
<td style="width: 139px;">request</td>
<td style="width: 647px;">
<p>Integrated request of assets, attributes, and values (example: requestor.last_name:"Morley, Gaby").</p>
<p>This parameter replaces the other parameters given separately.</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5> Context Output</h5>
<table style="height: 84px; width: 779px;" border="6" cellpadding="2">
<tbody>
<tr>
<td style="width: 295px;"><strong>Path</strong></td>
<td style="width: 489px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.CatalogRequest.CatalogRequestPath</td>
<td style="width: 489px;">Catalog request path</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.CatalogRequest.Code</td>
<td style="width: 489px;">Catalog request code</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.CatalogRequest.SdCatalogId</td>
<td style="width: 489px;">SD catalog ID</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.CatalogRequest.TitleEn</td>
<td style="width: 489px;">Request title</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Department.DepartmentCode</td>
<td style="width: 489px;">Department code</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Department.DepartmentEn</td>
<td style="width: 489px;">Department name</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Department.DepartmentId</td>
<td style="width: 489px;">Department ID</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Department.DepratmentLabel</td>
<td style="width: 489px;">Department label</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Department.DepartmentPath</td>
<td style="width: 489px;">Department path</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.KnownProblem.KnownProblemPath</td>
<td style="width: 489px;">Known problem path</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.KnownProblem.KnownProblemsId</td>
<td style="width: 489px;">Known problems ID</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.KnownProblem.KpNumber</td>
<td style="width: 489px;">Number of known problems</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.KnownProblem.QuestionEn</td>
<td style="width: 489px;">Known problem question</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Location.City</td>
<td style="width: 489px;">City</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Location.LocationCode</td>
<td style="width: 489px;">Location code</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Location.LocationEn</td>
<td style="width: 489px;">Location name</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Location.LocationId</td>
<td style="width: 489px;">Location ID</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Location.LocationPath</td>
<td style="width: 489px;">Location path</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Recipient.BeginOfContract</td>
<td style="width: 489px;">Date of beginning of contract</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Recipient.CellularNumber</td>
<td style="width: 489px;">Cellular number of recipient</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Recipient.DerpartmentPath</td>
<td style="width: 489px;">Department path of recipient</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Recipient.EMail</td>
<td style="width: 489px;">Email address of recipient</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Recipient.EmployeeId</td>
<td style="width: 489px;">Employee ID of recipient</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Recipient.LastName</td>
<td style="width: 489px;">Last name of recipient</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Recipient.LocationPath</td>
<td style="width: 489px;">Location of recipient</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Recipient.PhoneNumber</td>
<td style="width: 489px;">Phone number of recipient</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Status.StatusEn</td>
<td style="width: 489px;">Status of request</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Status.StatusGuid</td>
<td style="width: 489px;">Request GUID</td>
</tr>
<tr>
<td style="width: 295px;">EasyVista.Records.Status.StatusId</td>
<td style="width: 489px;">Request ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p> <code>!easy-vista-search asset=requestor attribute=last_name value="Morley, Gaby"</code></p>
<p>or</p>
<p><code>!easy-vista-search request=requestor.last_name:"Morley, Gaby"</code></p>
<h5>Raw Output</h5>
<pre>{  
   "CATALOG_REQUEST":{  
      "CATALOG_REQUEST_PATH":"Incidents/Equipment/Desktop*/Diskette Drive",
      "CODE":"70",
      "SD_CATALOG_ID":"4710",
      "TITLE_EN":"Diskette Drive"
   },
   "COMMENT":{  

   },
   "DEPARTMENT":{  
      "DEPARTMENT_CODE":"",
      "DEPARTMENT_EN":"Customer Support",
      "DEPARTMENT_ID":"22",
      "DEPARTMENT_LABEL":"",
      "DEPARTMENT_PATH":"Sales/Direct/Customer Support",

   },
   "KNOWN_PROBLEM":{  
      "KNOWN_PROBLEMS_ID":"",
      "KNOWN_PROBLEM_PATH":"",
      "KP_NUMBER":"",
      "QUESTION_EN":""
   },
   "LOCATION":{  
      "CITY":"",
      "LOCATION_CODE":"",
      "LOCATION_EN":"337",
      "LOCATION_ID":"7091",
      "LOCATION_PATH":"Europe/United Kingdom/Plymouth/Bldg 1/Floor 03/337"
   },
   "MAX_RESOLUTION_DATE_UT":"2011-03-15T20:00:00.000-04:00",
   "RECIPIENT":{  
      "BEGIN_OF_CONTRACT":"1988-04-01",
      "CELLULAR_NUMBER":"788-853-418",
      "DEPARTMENT_PATH":"Sales/Direct/Customer Support",
      "EMPLOYEE_ID":"14412",
      "E_MAIL":"test@example.com",
      "LAST_NAME":"Ernst, Walter",
      "LOCATION_PATH":"Europe/United Kingdom/Plymouth/Bldg 1/Floor 03/337",
      "PHONE_NUMBER":"+441442200573"
   },
   "REQUESTOR":{  
      "BEGIN_OF_CONTRACT":"1988-04-01",
      "CELLULAR_NUMBER":"788-853-418",
      "DEPARTMENT_PATH":"Sales/Direct/Customer Support",
      "EMPLOYEE_ID":"14412",
      "E_MAIL":"test@example.com",
      "LAST_NAME":"Ernst, Walter",
      "LOCATION_PATH":"Europe/United Kingdom/Plymouth/Bldg 1/Floor 03/337",
      "PHONE_NUMBER":"+441442200573"
   },
   "RFC_NUMBER":"000216",
   "STATUS":{  
      "STATUS_EN":"Reopened",
      "STATUS_GUID":"{67FC30D6-06DC-4B75-976F-69BE4CE6BDDD}",
      "STATUS_ID":"16"
   },
   "SUBMIT_DATE_UT":"2012-03-12T20:00:00.000-04:00"
}
</pre>

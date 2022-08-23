<h2>Overview</h2>
<p>
Designed for networking and security teams, CS Enterprise is a collaboration
platform focused on network packet capture (PCAP) analysis. CS Enterprise
delivers secure storage, organization, access control, and powerful analysis
tools in an elegant, responsive browser-based interface.
</p>
<h2>Use Cases</h2>
<ul>
<li>Upload a network capture for analysis in your browser</li>
<li>Collaborate on network pcap analysis by easily sharing captures with others via a URL</li>
<li>Collect meta-information about a capture file</li>
<li>Manage and organize capture files in CS Enterprise</li>
</ul>
<h2>To set up CS Enterprise to work with Cortex XSOAR</h2>
You will need the following before setting up the CS Enterprise integration on
Cortex XSOAR:
<ul>
<li><b>CS Enterprise URL</b> The URL of your CS Enterprise instance</li>
<li><b><a href="https://support.cloudshark.io/api/">API Token</a>:</b> An API Token from
CloudShark with upload, info, download, and delete permissions enabled on it</li>
</ul>
<h2> Configure the CS Enterprise Integration on Cortex XSOAR</h2>
<ol type="1">
  <li>Go to <b>Settings > Integrations > Servers & Services</b></li>
  <li>Search for CloudShark</li>
  <li>Click Add instance to create and configure a new integration
  instance</li>
  <ul>
    <li><b>Name:</b> a textual name for the integration instance</li>
    <li><b>CS Enterprise URL:</b> The URL of your CS Enterprise Instance</li>
    <li><b>API Token:</b> Your API token</li>
  </ul>
  <li>Click <b>Test</b> to validate the URL</li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>cloudshark-upload: cloudshark-upload</li>
  <li>cloudshark-info: cloudshark-info</li>
  <li>cloudshark-download: cloudshark-download</li>
  <li>cloudshark-delete: cloudshark-delete</li>
</ol>
<h3>1. cloudshark-upload</h3>
<hr>
<p>Upload a capture file into CS Enterprise</p>
<h5>Base Command</h5>
<p>
  <code>cloudshark-upload</code>
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
      <td>file</td>
      <td>EntryID of the capture to upload</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>additional_tags</td>
      <td>A comma-separated list of tags to apply to the capture file</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>filename</td>
      <td>The filename of the capture in CS Enterprise</td>
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
      <td>URL.Data</td>
      <td>string</td>
      <td>URL of the capture file in CS Enterprise</td>
    </tr>
    <tr>
      <td>CloudShark.CaptureID</td>
      <td>string</td>
      <td>Capture ID of the capture in CS Enterprise</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!cloudshark-upload file=494@1e6024f1-485b-4d1a-8ee3-b6bf51e8ca1a filename=demisto.pcapng additional_tags=demisto,cloudshark,test</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "CloudShark": {
        "CaptureID": "5277a3a64076"
    },
    "URL": {
        "Data": "CLOUDSHARK_URL/captures/5277a3a64076"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
Open Capture in CloudShark
</p>
</p>

<h3>2. cloudshark-info</h3>
<hr>
<p>Retrieve meta-information about a capture file from CS Enterprise</p>
<h5>Base Command</h5>
<p>
  <code>cloudshark-info</code>
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
      <td>capture_id</td>
      <td>Capture ID of the capture in CS Enterprise</td>
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
      <td>CloudShark.CaptureInfo</td>
      <td>unknown</td>
      <td>Meta-information of capture file</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!cloudshark-info capture_id=ccaa62cbbb06</code>
</p>
<h5>Context Example</h5>
<!-- disable-secrets-detection-start -->
<pre>
{
    "CloudShark": {
        "CaptureInfo": {
            "avg_packet_rate": "3.24",
            "avg_packet_size": "70.19",
            "cap_file_id": 165174,
            "comments": "",
            "created_at": "2019-11-06T21:18:30+00:00",
            "data_bit_rate": "1817.36",
            "data_byte_rate": "227.17",
            "data_size": 4071908,
            "disable_autodelete": false,
            "duration": "17924.501967",
            "encapsulation": "Ethernet",
            "end_time": "2019-07-26T23:20:44+00:00",
            "file": "/var/www/cloudshark/current/uploads/2019/11/05/16/13172ab4-61a7-4439-aa27-292306c062c0.cap",
            "file_source": "upload",
            "file_type": "Wireshark/tcpdump/... - pcap",
            "filename": "capture.pcapng",
            "group": "",
            "group_write?": false,
            "id": "ccaa62cbbb06",
            "last_accessed": "2019-11-07T15:42:07+00:00",
            "num_packets": 58009,
            "public?": false,
            "sha1_hash": "e871eee9d85a9898d1f7aec37f22f291fb1d1971",
            "size": 5000076,
            "start_time": "2019-07-26T18:22:00+00:00",
            "tag_list": "",
            "truncated": "No",
        }
    }
}
</pre>
<!-- disable-secrets-detection-end -->
<h5>Human Readable Output</h5>
<p>
<h3>Capture file info</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>avg_packet_rate</strong></th>
      <th><strong>avg_packet_size</strong></th>
      <th><strong>cap_file_id</strong></th>
      <th><strong>comments</strong></th>
      <th><strong>created_at</strong></th>
      <th><strong>data_bit_rate</strong></th>
      <th><strong>data_byte_rate</strong></th>
      <th><strong>data_size</strong></th>
      <th><strong>disable_autodelete</strong></th>
      <th><strong>duration</strong></th>
      <th><strong>encapsulation</strong></th>
      <th><strong>end_time</strong></th>
      <th><strong>file</strong></th>
      <th><strong>file_source</strong></th>
      <th><strong>file_type</strong></th>
      <th><strong>filename</strong></th>
      <th><strong>group</strong></th>
      <th><strong>group_write?</strong></th>
      <th><strong>id</strong></th>
      <th><strong>last_accessed</strong></th>
      <th><strong>num_packets</strong></th>
      <th><strong>public?</strong></th>
      <th><strong>sha1_hash</strong></th>
      <th><strong>size</strong></th>
      <th><strong>start_time</strong></th>
      <th><strong>tag_list</strong></th>
      <th><strong>truncated</strong></th>
      <th><strong>user</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 3.24 </td>
      <td> 70.19 </td>
      <td> 165174 </td>
      <td>  </td>
      <td> 2019-11-06T21:18:30+00:00 </td>
      <td> 1817.36 </td>
      <td> 227.17 </td>
      <td> 4071908 </td>
      <td> false </td>
      <td> 17924.501967 </td>
      <td> Ethernet </td>
      <td> 2019-07-26T23:20:44+00:00 </td>
      <td> /var/www/cloudshark/current/uploads/2019/11/05/16/13172ab4-61a7-4439-aa27-292306c062c0.cap </td>
      <td> upload </td>
      <td> Wireshark/tcpdump/... - pcap </td>
      <td> capture.pcapng </td>
      <td>  </td>
      <td> false </td>
      <td> ccaa62cbbb06 </td>
      <td> 2019-11-07T15:42:07+00:00 </td>
      <td> 58009 </td>
      <td> false </td>
      <td> e871eee9d85a9898d1f7aec37f22f291fb1d1971 </td>
      <td> 5000076 </td>
      <td> 2019-07-26T18:22:00+00:00 </td>
      <td>  </td>
      <td> No </td>
    </tr>
  </tbody>
</table>
</p>

<h3>3. cloudshark-download</h3>
<hr>
<p>Download a capture file from CS Enterprise</p>
<h5>Base Command</h5>
<p>
  <code>cloudshark-download</code>
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
      <td>capture_id</td>
      <td>Capture ID of the capture in CS Enterprise</td>
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
      <td>File</td>
      <td>unknown</td>
      <td>File downloaded from CloudShark</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!cloudshark-download capture_id=ccaa62cbbb06</code>
</p>

<h5>Human Readable Output</h5>

<h3>4. cloudshark-delete</h3>
<hr>
<p>Delete a capture file from CS Enterprise</p>
<h5>Base Command</h5>
<p>
  <code>cloudshark-delete</code>
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
      <td>capture_id</td>
      <td>Delete a capture file from CS Enterprise</td>
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
      <td>CloudShark.Result</td>
      <td>unknown</td>
      <td>Result of delete command</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!cloudshark-delete capture_id=ccaa62cbbb06</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "CloudShark": {
        "Result": {
            "id": "5277a3a64076",
            "message": "Capture deleted successfully.",
            "status": 200
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Result</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Response</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> id: ccaa62cbbb06<br>status: 200<br>message: Capture deleted successfully. </td>
    </tr>
  </tbody>
</table>
</p>
<!-- <h2>Additional Information</h2><h2>Known Limitations</h2><h2>Troubleshooting</h2> -->

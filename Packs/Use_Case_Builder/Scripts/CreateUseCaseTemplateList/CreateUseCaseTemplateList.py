import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

usecasetemplatelist = """<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
<style>
    .reportheader1 {
        margin: 0;
        display: inline;
        float: left;
        margin-left: 50px;
    }

    .reportheader2 {
        margin:0;
        display: inline;
        float: left;
        color: green;
    }

    .imgcenter {
        display: block;
        margin-left: auto;
        margin-right: auto;
        width: 40%;
    }

    .h1center {
        text-align:center;
    }

    .h1left {
        text-align:left;
        margin-left: 350px;
        color: rgba(112, 112, 112, 0.993)
    }

    .ucdparagraph {
        text-align: center;
        font-size: 24px
    }

    table, th, td {
        border:1px solid black;
        border-spacing: 0px;
        table-layout: fixed;
        text-align: left;
        margin-left: auto;
        margin-right: auto;
        word-wrap: break-word;
        width: 600px;
        font-family: Arial, Helvetica, sans-serif;
        font-size: 18px;
        white-space: pre-wrap;
    }

    ul {
        font-size: 16px;
        color:rgba(58, 58, 58, 0.993)
    }

    th, td {
        padding: 15px;
    }
</style>
</head>
<body>
    <p class="reportheader1">Report Created By:</p><p class="reportheader2"><strong>${Use Case Definition.Answers.name}</strong></p>
        <br><br>
    <p class="reportheader1">Report Created On:</p><p class="reportheader2"><strong>${incident.created}</strong></p>
        <br><br>
    <img src="https://www.paloaltonetworks.com/content/dam/pan/en_US/images/logos/brand/cortex-primary/Cortex-logo.png?imwidth=1920" alt="Cortex Logo" class="imgcenter"/>
    <div>
        <h1 class="h1center">Use Case Definition</h1>
        <p class="ucdparagraph">This document provides a template for defining a use case to be implemented in XSOAR.</p>
        <p class="ucdparagraph">The Use Case is defined by the process, logic, and tasks that are being done as part of an Incident Response process for a specific incident type.</p>
    </div>
    <br>
    <div>
        <h1 class="h1left">Use Case Definition</h1>
        <table class="use_case_table">
            <tr>
                <th>License Requirements<ul><li><a href="https://www.paloaltonetworks.com/resources/datasheets/cortex-xsoar">XSOAR</a> or <a href="https://www.paloaltonetworks.com/resources/datasheets/cortex-xsoar-threat-intelligence-management">TIM</a></ul></th>
                <td>XSOAR</td>
            </tr>
            <tr>
                <th>Use Case Name <ul><li>Name of Use Case</li><li>Maps into the incident type</li><li>Example: Phishing or Failed Log in</li></ul></th>
                <td><strong>Use Case Name: </strong>${.="${MarkdownToHTML.HTML.[0]}"}<br><br><strong>Use Case Purpose: </strong>${.="${MarkdownToHTML.HTML.[1]}"}</td>
            </tr>
            <tr>
                <th>Trigger <ul><li>How do incidents get triggered inside XSOAR?</li><li>Example: Phishing incident can be triggered by receiving incoming email</li></ul></th>
                <td>${.="${MarkdownToHTML.HTML.[3]}"}</td>
            </tr>
            <tr>
                <th>Incident Structure and Mapping <ul><li>Incident fields that are required as part of the incident response process</li><li>Example: Sender, Account, Details, etc.</li></ul></th>
                <td>${.="${MarkdownToHTML.HTML.[4]}"}</td>
            </tr>
            <tr>
                <th>Incident Response Process <ul><li>Overall response process and logic</li><li>Use numbered steps for reference</li><li>Example: Check IP address for the location, act according to the country, increase severity, block IP, manually investigate further, close incident</li></ul></th>
                <td>${.="${MarkdownToHTML.HTML.[5]}"}</td>
            </tr>
            <tr>
                <th>Use Case Enrichment Actions <ul><li>Enriching of IOCs from threat intel, or from internal sources</li><li>Example: Enriching URLs and IP addresses from cloud threat intel services, enriching event with raw data, etc.</li></ul></th>
                <td>${.="${MarkdownToHTML.HTML.[6]}"}</td>
            </tr>
            <tr>
                <th>Manual Steps <ul><li>Any manual investigation steps that need to be performed by the analyst</li><li>Example: Blocking of IP addresses, carrying actions that cannot be automated, etc.</li></ul></th>
                <td>${.="${MarkdownToHTML.HTML.[7]}"}</td>
            </tr>
            <tr>
                <th>End User Interactiveness <ul><li>Interactive steps that require input from end users to complete the investigation</li><li>Example: Asking questions to end users via email, asking management approval via email, etc.</li></ul></th>
                <td>${.="${MarkdownToHTML.HTML.[8]}"}</td>
            </tr>
            <tr>
                <th>Deduplication Logic <ul><li>Logic to deduplicate incoming incidents</li><li>Example: Find active incidents with a similar subject line and sender, and then close the incident as a duplicate if found</li></ul></th>
                <td>${.="${MarkdownToHTML.HTML.[9]}"}</td>
            </tr>
            <tr>
                <th>3rd Party Integrations <ul><li>Product Category</li><ul><li>Type of product</li></ul></ul><ul><li>Product Name & Version</li><ul><li>Exact product name and version</li></ul></ul><ul><li>Actions Needed</li><ul><li>Reference the logic steps above</li></ul></ul></th>
                <td>${.="${MarkdownToHTML.HTML.[10]}"}</td>
            </tr>
            <tr>
                <th>Incident Structure (Custom Field) <ul><li>Field Name</li><ul><li>Ex: Sender Email</li></ul></ul><ul><li>Field Type</li><ul><li>Ex: Short Text</li></ul></ul><ul><li>Comments and Values</li></ul><ul><li>Layout Placement</li><ul><li>Ex: New/Edit/Close/Summary</li></ul></ul></th>
                <td>${.="${MarkdownToHTML.HTML.[2]}"}</td>
            </tr>
        </table>
        <br>
    </div>
</body>
</html>
"""  # noqa: E501

demisto.executeCommand("setList", {"listName": "UseCaseTemplate", "listData": usecasetemplatelist})

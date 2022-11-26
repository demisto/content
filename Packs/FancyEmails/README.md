
## What does this pack do?
A content pack to generate professional, eye-catching emails. Useful for increasing user engagement with XSOAR.

## Features
- Ready to use out of the box but Fully customizable
- Automated generation of email HTML, tables, and CSS
- Easy implementation and embeding of organization logo into emails 
- Automatic Time Formatting to a human-readable local time stampe
- Customizable headers, footers, and Warning/Classified banners
- Default configuration produces emails with ADA compliant readability [High Contrast, Element Spacing, Screen Reader Compatible]
- Includes scripts to send fancy emails using the 'send-mail command'
- Include scripts to generate certain common emails and elements
  - Generate an HTML indicator table (MakeFancyEmailIndicatorTable)
  - Generate a table based on incident fields (MakeFancyEmailIncidentTable)
  - Generate a table filled with notes from an incident
    

## Instructions
### Pre-Requisites
You must have an email integration configured to support the 'send-mail' command

### Integration Configuration
1. Configure the Fancy Email Integration
2. Modify integration settings.

### Example Send Email Command
Basic example of sending an email using Fancy Emails
```
!SendFancyEmail to=me@mycompany.com subject="Check Out This Fancy Email" body="Hello World" body_header="Important Email" banner="Classified"
```

### Example: Sending an email with an Indicator Table
_Scenario: Send an email containing an email with a table of malicious URLs linked to an incident. Use the alt link format, to use a seperate text area to link to the indicator rather than using the indicator name/value._

From within an incident:
```
!MakeFancyEMailIndicatorTable query="incident.id=${incident.id} verdict=Malicious type:URL" use_alt_link=True max_name_chars=40
```

This outputs to the FancyEmails.IndicatorTable.html context the raw_html for the table. You can embed it into a fancy email by:
```
!SendFancyEmail to=me@mycompany.com subject="Check Out These Malicious Indicators" html_body=${FancyEmails.IndicatorTable.html} body_header="Malicious Indicators related to ${incident.id}" banner="Classified" 
```

## Default CSS
```
body{
    font-family: arial;
}

table {
      border: 1px solid {BACKGROUND_COLOR};
      border-collapse: collapse;
      width: 100%;
}

th {
    background-color:  {BACKGROUND_COLOR};
    border: none;
    color: {FOREGROUND_COLOR};
    text-align: left;
    padding: 0.5em;
}

tr{
    text-align: left;
}

td{
    padding: 0.5em;
}

.banner{
    text-align:center;
    color: {BANNER_TEXT_COLOR};
    background-color: {BANNER_COLOR};
    width: 100%;
    display: block;
    font-size:1.2em
}

.data-header {
    padding: 0.5em;
}

.data-cell {
    padding:0.5em;
}

.footer {
    background-color:   {BACKGROUND_COLOR};
    width: 100%;
    color:  {FOREGROUND_COLOR};
    border-collapse: collapsed;
    border: none;
    padding: 0.5em;
}

.footer-cell {

}

.footer-row {
    background-color:   {BACKGROUND_COLOR};
    width: 100%;
    text-align: center;
    font-size: 0.75em;
}

.header {
    background-color:  {BACKGROUND_COLOR};
    width: 100%;
    text-align: center;
    color:  {FOREGROUND_COLOR};
    padding: 0.5em;

}

.header-text {
    background-color:  {BACKGROUND_COLOR};
    width: 100%;
    text-align: center;

    margin: auto;
}

.logo{
    margin: 1em;

}

.logo-container{
    width: 100%;
    margin-top: 1em;
    text-align: {ALIGNLOGO};
}
```
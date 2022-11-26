# Fancy Emails
A content pack to generate professional, eye-catching emails.

## Features
- Ready to use out of box
- Automated generation of email HTML, tables, and CSS
- Easy implementation and embeding of organization logo into emails 
- Automatic Time Formatting to a human readable local time stampe
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
```
!SendFancyEmail to=me@mycompany.com subject="Check Out This Fancy Email" body="Hello World" body_header="Important Email" banner="Classified"
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
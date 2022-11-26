Templating Engine for  emails.

## Configure Fancy Emails on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Fancy Emails.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Top Footer Line | Can be either plain text or HTML | False |
    | Bottom Footer Line | Can be either plain text or HTML | False |
    | Background Color | Background color for the headers and other layout elements | False |
    | Foreground Color | Color of foreground of layout elements with a background \(Usually text\) | False |
    | Custom CSS | Additional CSS to modify layout elements. \(See integration code for default CSS\) | False |
    | Time Zone | Used for converting UTC time stamps to easily read local time string. See Docs here for list of supported timezones: https://gist.github.com/heyalexej/8bf688fd67d7199be4a1682b3eec7568 | False |
    | Banner Text Color | Text color of the warning banner | False |
    | Banner Background Color | Background color of the warning banner | False |
    | Align Logo | Where to align the logo: 'left', 'center' or 'right' | False |
    | Base 64 Logo | Your logo in a base 64 img src format. Convert your logo at https://www.base64-image.de/ | False |
    | Logo Height | Logo Height in Pixels  \(Needed to support logo rendering outlook\) | False |
    | Logo Width | Logo Width in Pixels \(Needed to support logo rendering outlook\) | False |

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fancy-email-make-table
***
Take a list of objects and converts it to html. This command permits custom HTML.


#### Base Command

`fancy-email-make-table`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| items | List of objects to conver to table. | Optional | 
| name | Name of the table. | Optional | 
| headers | List of strings (keys) to use when extracting table from items list. | Optional | 
| include_css | Include CSS Styling [only needs to be done if the table is being used outside the email template]. | Optional | 
| print_to_warroom | Print the HTML to the warroom. Deafult is False. | Optional | 
| vertical_table | Headers will display in the first column of the table, instead of the First Row. Good key:value type data. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FancyEmails.Table.name | String | Name of the table provided on input | 
| FancyEmails.Table.html | String | Generated HTML for the table | 

### fancy-email-make-email
***
Make an email body


#### Base Command

`fancy-email-make-email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| body | Body between header and footer. Should be Plain text or HTML. | Required | 
| header | Header text, Can be Plain Text or HTML. | Optional | 
| banner | Text to appear in warning banner at top and bottom of email. | Optional | 
| include_logo | Include logo html at top of page. You must attach the logo file to the email as filename  email_logo and mark it as attachID and attachCID. Default is False. | Optional | 
| custom_css | Override or include CSS to include with the email body. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FancyEmails.Email.name | String | Name of the email header provided on input | 
| FancyEmails.Email.html | String | Generated HTML for the email | 

### fancy-email-make-timestring
***
Format a Generic ISO timestamp to an easy to read string


#### Base Command

`fancy-email-make-timestring`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | UTC Time stamp string in ISO format. | Optional | 
| name | Name Field (only used in context}. | Optional | 
| include_raw | Include Raw time stamp wrapped in &lt;small&gt; html tags. Possible values are: True, False. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FancyEmails.TimeString.name | String | Name of the time string provided on input | 
| FancyEmails.TimeString.html | String | Generated HTML for the time string | 

### fancy-email-make-logo
***
Return div and img html tags with Logo embeded as a base64 string


#### Base Command

`fancy-email-make-logo`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
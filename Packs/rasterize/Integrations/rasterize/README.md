Converts URLs, PDF files, and emails to an image file or PDF file.
## Configure Rasterize on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Rasterize.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| with_error | Return Errors.  | False |
| wait_time | Time to wait before taking a screenshot \(in seconds\). | False |
| max_page_load_time | Maximum amount of time to wait for a page to load \(in seconds\). | False |
| chrome_options | Chrome options \(Advanced. Click \[?\]\ for details.) | False |
| proxy | Use system proxy settings. | False |

4. Click **Test** to validate the URLs, token, and connection.

**Configuration Notes:**
* Return Errors: If this checkbox is not selected, a warning will be returned instead of an error.
* Use system proxy settings: Select this checkbox to use the system's proxy settings. **Important**: This integration does not support proxies which require authentication.
* Chrome options: A comma-separated list of Chrome options to add or remove for rasterization.  If a value contains a comma (for example, when setting the user agent value), escape it with the backslash (**\\**) character. To remove a default option that is used, put the option in square brackets. For example, to add the option *--disable-auto-reload* and remove the option *--disable-dev-shm-usage*, set the following value:
```
--disable-auto-reload,[--disable-dev-shm-usage]
```

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### rasterize
***
Converts the contents of a URL to an image file or a PDF file.


#### Base Command

`rasterize`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| wait_time | Time to wait before taking a screenshot (in seconds ). | Optional | 
| max_page_load_time | Maximum time to wait for a page to load (in seconds). | Optional | 
| url | The URL to rasterize. Must be the full URL, including the http prefix. | Required | 
| width | The page width, for example, 1024px. Specify with or without the px suffix. | Optional | 
| height | The page height, for example, 800px. Specify with or without the px suffix. | Optional | 
| type | The file type to which to convert the contents of the URL. Can be "pdf" or "png". Default is "png". | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!rasterize url=http://google.com```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "922@6e069bc4-2a1e-43ea-8ed3-ea558e377751",
        "Extension": "png",
        "Info": "image/png",
        "Name": "url.png",
        "Size": 29909,
        "Type": "PNG image data, 1024 x 800, 8-bit/color RGBA, non-interlaced"
    }
}
```

#### Human Readable Output
[!image](https://raw.githubusercontent.com/demisto/content/6bdd1b0ca11b977db6d1c652063b71b8697794c2/Packs/rasterize/Integrations/rasterize/doc_files/rasterize_url_command_output.png)


### rasterize-email
***
Converts the body of an email to an image file or a PDF file.


#### Base Command

`rasterize-email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| htmlBody | The HTML body of the email. | Required | 
| width | The HTML page width, for example, 600px. Specify with or without the px suffix. | Optional | 
| height | The HTML page height, for example, 800px. Specify with or without the px suffix. | Optional | 
| type | The file type to which to convert the email body. Can be "pdf" or "png". Default is "png". | Optional | 
| offline | If "true", will block all outgoing communication. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!rasterize-email htmlBody="<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\"></head><body><br>---------- TEST FILE ----------<br></body></html>"```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "926@6e069bc4-2a1e-43ea-8ed3-ea558e377751",
        "Extension": "png",
        "Info": "image/png",
        "Name": "email.png",
        "Size": 5243,
        "Type": "PNG image data, 600 x 800, 8-bit/color RGBA, non-interlaced"
    }
}
```

#### Human Readable Output

[!image](https://raw.githubusercontent.com/demisto/content/6bdd1b0ca11b977db6d1c652063b71b8697794c2/Packs/rasterize/Integrations/rasterize/doc_files/rasterize_email_command_output.png)


### rasterize-image
***
Converts an image file to a PDF file.


#### Base Command

`rasterize-image`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EntryID | The entry ID of the image file. | Required | 
| width | The image width, for example, 600px. Specify with or without the px suffix. | Optional | 
| height | The image height, for example, 800px. Specify with or without the px suffix. If empty, the height is the entire image. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!rasterize-image EntryID=889@6e069bc4-2a1e-43ea-8ed3-ea558e377751```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "930@6e069bc4-2a1e-43ea-8ed3-ea558e377751",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "889@6e069bc4-2a1e-43ea-8ed3-ea558e377751.pdf",
        "Size": 21856,
        "Type": "PDF document, version 1.4"
    }
}
```

#### Human Readable Output



### rasterize-pdf
***
Converts a PDF file to an image file.


#### Base Command

`rasterize-pdf`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EntryID | The entry ID of PDF file. | Required | 
| maxPages | The maximum number of pages to render. Default is "3". | Optional | 
| pdfPassword | The password to access the PDF. | Optional | 
| horizontal | Whether to stack the pages horizontally. If "true", will stack the pages horizontally. If "false", will stack the pages vertically. Default is "false". | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!rasterize-pdf EntryID=897@6e069bc4-2a1e-43ea-8ed3-ea558e377751```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "934@6e069bc4-2a1e-43ea-8ed3-ea558e377751",
        "Extension": "jpeg",
        "Info": "image/jpeg",
        "Name": "image.jpeg",
        "Size": 77514,
        "Type": "JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 1700x2200, components 3"
    }
}
```

#### Human Readable Output



Converts URLs, PDF files, and emails to an image file or PDF file.
## Docker Security Recommendations
     
If you are using the integration to rasterize un-trusted URLs or HTML content, such as those obtained via external emails, we recommend following the instructions at the [Network Hardening Guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Network-Hardening) or [Docker network hardening Guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker network hardening Guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) under the Block Internal Network Access section.

## Configure Rasterize in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| with_error | Return Errors.  | False |
| wait_time | Time to wait before taking a screenshot \(in seconds\). | False |
| max_page_load_time | Maximum amount of time to wait for a page to load \(in seconds\). | False |
| chrome_options | Chrome options (Advanced. See `Configuration Notes`.) | False |
| is_https | Use secure requests protocol \(HTTPS\). | False |
| proxy | Use system proxy settings. | False |
| rasterize_mode | Rasterize Mode. (See `Configuration Notes`.) | False |


**Configuration Notes:**
* Return Errors: If this checkbox is not selected, a warning will be returned instead of an error.
* Chrome options: A comma-separated list of Chrome options to add or remove for rasterization. Use for advanced troubleshooting. If a value contains a comma (for example, when setting the user agent value), escape it with the backslash (**\\**) character. To remove a default option that is used, put the option in square brackets. For example, to add the option *--disable-auto-reload* and remove the option *--disable-dev-shm-usage*, set the following value:
    ```
    --disable-auto-reload,[--disable-dev-shm-usage]
    ```

    To set a language for the browser, add the *--accept-lang* argument followed by the desired language code in IETF BCP 47 format. For example, `--accept-lang=de-DE`.
If you want to set the language to en-US, use en-GB instead.
* Rasterize Mode: It is possible to rasterize either via Chrome WebDriver or Chrome Headless CLI. WebDriver supports more options than Headless CLI. Such as support for the `offline` option in the `rasterize-emails` command. There are some urls that do not rasterize well with WebDriver and may succeed with Headless CLI. Thus, it is recommended to use the `WebDriver - Preferred` mode, which will use WebDriver as a start and fallback to Headless CLI if it fails.
* Use system proxy settings: Select this checkbox to use the system's proxy settings. **Important**: this integration does not support proxies which require authentication.


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| file_name | The name the file will be saved as. Default is "url". | Optional |
| full_screen | Get the full page. The actual page width and height will be auto calculated up to a max value of 8000px. (Marking full_screen as true means that the values for width and height arguments might not be respected). | Optional | 
| mode | Rasterize mode to use (WebDriver or Headless CLI). If not specified, will use according to the integration instance settings. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | File entry ID. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE" | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 

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
| file_name | The name the file will be saved as. Default is "email". | Optional |
| full_screen | Get the full page. The actual page width and height will be auto calculated up to a max value of 8000px. (Marking full_screen as true means that the values for width and height arguments might not be respected). | Optional | 
| mode | Rasterize mode to use (WebDriver or Headless CLI). If not specified, will use according to the integration instance settings. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | File entry ID. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE" | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 

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
| file_name | The name the file will be saved as. Default is the EntryID. | Optional |
| full_screen | Get the full page. The actual page width and height will be auto calculated up to a max value of 8000px. (Marking full_screen as true means that the values for width and height arguments might not be respected). | Optional | 
| mode | Rasterize mode to use (WebDriver or Headless CLI). If not specified, will use according to the integration instance settings. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | File entry ID. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE" | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. |

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
| file_name | The name the file will be saved as. Default is "image". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | File entry ID. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE" | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. |

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



### rasterize-html
***
Converts an html file to a PDF or PNG file.


#### Base Command

`rasterize-html`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EntryID | The entry ID of the html file. | Required | 
| width | The html file width, for example, 600px. Specify with or without the px suffix. | Optional | 
| height | The html file height, for example, 800px. Specify with or without the px suffix. If empty, the height is the entire image. | Optional | 
| file_name | The name the file will be saved as. Default is the EntryID. | Optional | 
| type | The file type to which to convert the html file. Can be "pdf" or "png". Default is "png". | Optional | 
| full_screen | Get the full page. The actual page width and height will be auto calculated up to a max value of 8000px. (Marking full_screen as true means that the values for width and height arguments might not be respected). | Optional |
| wait_time | Time to wait before taking a screenshot (in seconds ). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | File entry ID. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE" | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. |

#### Command Example
```!rasterize-html EntryID=889@6e069bc4-2a1e-43ea-8ed3-ea558e4586751```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "930@6e069bc4-2a1e-43ea-8ed3-ea558e458651",
        "Extension": "png",
        "Info": "application/png",
        "Name": "image.png",
        "Size": 21856,
        "Type": "png document, version 1.4"
    }
}
```

#### Human Readable Output
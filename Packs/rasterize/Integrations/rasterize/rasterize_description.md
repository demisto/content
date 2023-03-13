## Rasterize
Create an image or PDF file from a URL or HTML body.

**Security Note:**
If you are using the integration to rasterize un-trusted URLs or HTML content, such as those obtained via external emails, we recommend following the instructions at the [Docker Network Hardening](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Docker-Network-Hardening) under the Block Internal Network Access section.


**Configuration Notes:**
* Return Errors: If this checkbox is not selected, a warning will be returned instead of an error entry.
* Chrome options: Add or remove Chrome options used to rasterize. Use for advanced troubleshooting. Supports a comma-separated list. If a value contains a comma (for example, when setting the user agent value), escape it with the backslash (**\\**) character. To remove a default option being used, put the option in square brackets. For example, to add the option *--disable-auto-reload* and remove the option *--disable-dev-shm-usage*, set the following value:
```
--disable-auto-reload,[--disable-dev-shm-usage]
```
* Rasterize Mode: It is possible to rasterize either via Chrome WebDriver or Chrome Headless CLI. WebDriver supports more options than Headless CLI. Such as support for the `offline` option in the `rasterize-emails` command. There are some urls that do not rasterize well with WebDriver and may succeed with Headless CLI. Thus, it is recommended to use the `WebDriver - Preferred` mode, which will use WebDriver as a start and fallback to Headless CLI if it fails.
* Use system proxy settings: Select this checkbox to use the system's proxy settings. **Important**: this integration does not support proxies which require authentication.

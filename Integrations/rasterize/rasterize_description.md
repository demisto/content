## Rasterize
Create an image or PDF file from a URL or HTML body.

**Configuration Notes:**
* Return Errors: If this checkbox is not selected, a warning will be returned instead of an error entry.
* Use system proxy settings: Select this checkbox to use the system's proxy settings. **Important**: this integration does not support proxies which require authentication.
* Chrome options: Add or remove Chrome options used to rasterize. Supports a comma-separated list. If a value contains a comma (for example, when setting the user agent value), escape it with the backslash (**\\**) character. To remove a default option being used, put the option in square brackets. For example, to add the option *--disable-auto-reload* and remove the option *--disable-dev-shm-usage*, set the following value:
```
--disable-auto-reload,[--disable-dev-shm-usage]
```

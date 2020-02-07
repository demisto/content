## Rasterize
Create an image or PDF file from a URL or HTML body.

**Notes:**
* Return Errors: If this checkbox is not selected, a warning will be returned instead of an error entry.
* Chrome options: Add or remove Chrome options used to rasterize (supports comma-seperated list). To remove a default option being used, put the option in square brackets. For example, to add the option *--disable-auto-reload* and remove the option *--disable-dev-shm-usage*, set the following value:
```
--disable-auto-reload,[--disable-dev-shm-usage]
```

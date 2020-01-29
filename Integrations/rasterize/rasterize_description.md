## Rasterize
Take a URL or HTML body and create an image or PDF out of it.

**Notes:**
* Return Errors: if the checkbox is not marked, a warning will be returned instead of an error entry.
* Chrome options: add or remove chrome options used for rasterize. Comma seperated list. To remove a default option being used put the option in square brackets. For example to add the option *--disable-auto-reload* and remove the option *--disable-dev-shm-usage*, set the following value:
```
--disable-auto-reload,[--disable-dev-shm-usage]
```

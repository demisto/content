## [Unreleased]
  - Fixed the setting: **Use system proxy settings**, so proxies are ignored when not enabled.
  - Fixed an issue with the ***rasterize*** command in which child processes were defunct when using a proxy server.

## [20.2.3] - 2020-02-18
  - Updated Chromium to version 80.
  - Added support for specifying a maximum page load time (default is set to 180 seconds).
  - Changed the default user agent to match the Chrome user agent.

## [20.2.0] - 2020-02-04
  - Added support for specifying advanced Chrome options.
  - Improved rendering of large HTML files.

## [20.1.0] - 2020-01-07
-

## [19.12.1] - 2019-12-25
Fixed an issue with the ***rasterize*** command in which child processes were defunct.

## [19.11.0] - 2019-11-12
Added support for the *px* suffix in the _width_ and _height_ parameters.

## [19.10.2] - 2019-10-29
  - Added the ___rasterize-pdf___ command, which converts a PDF file to an image file.
  - ___rasterize-email___ now available in offline mode. 
  - Added the _wait_time_ - parameter to the ___rasterize___ command and to the instance configuration, which sets the time to wait before taking a screenshot.
  
## [19.10.1] - 2019-10-15
  - Updated to use Chrome driver instead of phantomJS (requires Demisto 5.0).
  - Improved control over the window size of the output.

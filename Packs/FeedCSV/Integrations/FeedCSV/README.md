## Overview
---


Fetch indicators from a CSV feed. The integration allows a great amount of user configuration to support different types of CSV feeds.


## Configure CSV Feed on Demisto
---


1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for CSVFeed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __URL__: Server URL where the feed is.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Reliability__: Reliability of the feed. 
    * __Username__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Request Timeout__: Time (in seconds) before HTTP requests timeout.
    * __Ignore Regex__: Python regular expression for lines that should be ignored.
    * __Field Names__: Name of the field names in the CSV. If several are given, will use
    "indicator" as the indicator value field.
    * __Delimiter__: A one-character string used to separate fields.
    * __Double quote__: Controls how instances of quote character appearing inside a field should themselves be quoted. When True, the character is doubled. When False, the escapechar is used as a prefix to the quotechar. It defaults to True.
    * __Escape character__: A one-character string used by the writer to escape the delimiter.
    * __Quote Character__: A one-character string used to quote fields containing special characters.
    * __Skip Initial Space__: When True, whitespace immediately following the delimiter is ignored.
4. Click __Test__ to validate the URLs, token, and connection.



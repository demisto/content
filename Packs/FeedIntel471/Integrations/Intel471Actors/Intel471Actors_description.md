Fetch indicators from Intel471 Malware Indicator Stream feed..

* **Auto detect indicator type** - If checked, a type auto detection mechanism will take place for each indicator.
* **Indicator Type** - Type of the indicator in the feed. Relevant only if Auto detect is not checked.
* **Username + Password** - Credentials to access feeds that require basic authentication. 
These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the **Username** field and the header value in the **Password** field.
* **JMESPath Extractor** - JMESPath expression for extracting the indicators from. You can check the expression in 
the [JMESPath site](http://jmespath.org/) to verify this expression will return the following array of objects.
* **JSON Indicator Attribute** - JSON attribute whose value is the indicator. Default is 'indicator'.

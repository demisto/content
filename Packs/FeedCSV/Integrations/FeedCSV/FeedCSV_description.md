Fetch indicators from a CSV feed. The integration allows a great amount of user configuration to support different types of CSV feeds.
* **Server URL** - URL where the feed is.
* **Username + Password** - Access feeds that require basic authentication.
* **Ignore Regex** - Python regular expression for lines that should be ignored.
* **Field Names** - Name of the field names in the CSV. If several are given, will use
    "indicator" as the indicator value field.
* **Double Quote** - Controls how instances of quotechar appearing inside a field should themselves be quoted. When True, the character is doubled. When False, the escapechar is used as a prefix to the quotechar. It defaults to True.
* **Delimiter** -  A one-character string used to separate fields.
* **Doubequote** - Controls how instances of quotechar appearing inside a field should
    themselves be quoted. When True, the character is doubled.
* **Delimiter** - A one-character string used to separate fields.
* **Quote Character** - A one-character string used to quote fields containing special characters.
* **Escape character** - A one-character string used by the writer to escape the delimiter.
* **Skip Initial Space** - When True, whitespace immediately following the delimiter is ignored.

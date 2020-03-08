# Silence Progress STDOUT (e.g. long http request download progress)
$progressPreference = 'silentlyContinue'
function tableToMarkdown {
<#
.DESCRIPTION

Converts a demisto table in JSON form to a Markdown table

.PARAMETER name (required)

The name of the table

.PARAMETER t (required)

The JSON table - List of dictionaries with the same keys or a single dictionary

.PARAMATER headers

A list of headers to be presented in the output table (by order).
If string will be passed then table will have single header. Default will include all available headers.

.PARAMATER headerTransform

A function that formats the original data headers

.PARAMATER removeNull

Remove empty columns from the table.

.PARAMATER metadata

Metadata about the table contents
#>

}

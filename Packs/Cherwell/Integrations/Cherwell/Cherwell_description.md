Integration with Cherwell Service Management. You can create, read update, and delete business objects, together with 
attachments and relations operations. 

In order to create, query, get, update, delete, and link business objects, we recommend duplicating Cherwell example 
scripts and edit them using the instructions within each script. 

To use an advanced query when fetching incidents, add your query in the advanced query parameter. 
The  query should be a CSV list of filters, such that each filter is of the form: 
`["FieldName","Operator","Value"]` and operator is one of: 'eq'=equal, 'gt'=grater-than, 'lt'=less-than, 'contains', 
'startwith'. nSpecial characters should be escaped. Example: 
`[["CreatedDateTime","gt","4/10/2019 3:10:12 PM"],["Priority","eq","1"]]` 
NOTE: If received multiple filters for the same field name, an 'OR' operation between the filters will be performed, 
if the field names are different an 'AND' operation will be performed.
##Creating a Service Account
1. Go to the [Google documentation](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount) and follow the procedure in the Creating a Service Account section. After you create a service account, a Service Account Private Key file is downloaded. You will need this file when configuring an instance of the integration.
2. Grant the Compute Admin permission to the Service Account to enable the Service Account to perform certain Google Cloud API commands.
3. In Cortex XSOAR, configure an instance of the Google Cloud Compute integration. For the Service Account Private Key parameter, add the Service Account Private Key file contents (JSON).
##Create document command:
Creates a blank document. It's not possible to pass body arguments.
That's a limitation by the google api. For inserting content you should the update document command.
##Update document command:  
Update a document based upon it's ID. Actions to perform are passed in the following format:
* action1{param1,param2,...};action2{param1,param2,...}...
It is then converted to:  
* action1(param1,param2,...), action2(param1,param2),...
where action1 is the function name to be called and param1 and param2 are the parameters  
For example:  
insertText(5,hello)  
insertTable(5,7,7);insertText(5,hello)  
###List of allowed actions:
-createNamedRange(start_index, end_index, name, segment_id(optional))  
-createParagraphBullets(start_index, end_index, bullet_type, segment_id(optional))  
-deleteContentRange(start_index, end_index, segment_id(optional))  
-deleteNamedRangeByName(name)  
-deleteNamedRangeById(named_range_id)
-deleteParagraphBullets(start_index, end_index, segment_id(optional))  
-deletePositionedObject(object_id)  
-deleteTableColumn(index, row_index, column_index, segment_id(optional))  
-deleteTableRow(index, row_index, column_index, segment_id(optional))  
-insertInlineImage(index, uri, width, height, segment_id(optional))  
-insertPageBreak(index, segment_id(optional))  
-insertTable(index, rows, columns, segment_id(optional))  
-insertTableColumn(index, row_index, column_index, insert_below, segment_id(optional))  
-insertTableRow(index, row_index, column_index, insert_below, segment_id(optional))  
-insertText(index, text, segment_id(optional))  
-replaceAllText(source, target, match_case)

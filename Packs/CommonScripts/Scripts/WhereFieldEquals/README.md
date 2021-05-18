Returns all items from the list where their given `field` attribute is equal to the `equalTo` argument.

For example, `!WhereFieldEquals` with the following arguments:
 - value=[{ name: '192.1,0.82', type: 'IP' }, {  name: 'myFile.txt, type: 'File'  }, { name: '172.0.0.2', type: 'IP' }]
 - field='type'
 - equalTo='IP'
 - getField='name' 

This will return all item names where field `type` equals `IP` - ['192.1,0.82', '172.0.0.2'].

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | transformer, general, entirelist |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The list to apply the transformer to. |
| field | The attribute in the collection items to check equality against `equalTo`. |
| equalTo | The value to filter all items by in the collection. |
| getField | The field to extract from each item (Optional). |
| stringify | Whether the argument should be saved as a string (Optional). |

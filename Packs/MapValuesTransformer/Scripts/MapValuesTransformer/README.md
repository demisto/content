# MapValuesTransformer

This transformer script takes the input value and translates it based on 2 list arguments.

The script that takes 2 arguments:

`input_values` and `mapped_values`

Both arguments are comma separated values. The total number of values for each input must be the same. For example:

`input_values = "1,2,3,4"`

`mapped_values = "4,3,2,1"`

If the length of each list is not the same, the script will error.

### Example use

`value = "3"` *(not specified by the user)*

`input_values = "1,2,3,4"`

`mapped_values = "4,3,2,1"`

The resulting output would be "2". The mapping looks up the value in the `input_values` and returns the value in
 `mapped_values` at the same index.

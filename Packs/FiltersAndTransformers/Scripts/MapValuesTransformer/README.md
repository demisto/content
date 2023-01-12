# MapValuesTransformer

This transformer script takes the input value and translates it based on two list arguments.

The script that takes two arguments:

`input_values` and `mapped_values`

Both arguments are comma-separated values. The total number of values for each input must be the same. For example:

`input_values = "1,2,3,4"`

`mapped_values = "4,3,2,1"`

If the length of each list is not the same, the script will error.

### Example use 1

`value = "3"` *(not specified by the user)*

`input_values = "1,2,3,4"`

`mapped_values = "4,3,2,1"`

The resulting output would be "2". The mapping looks up the value in the `input_values` and returns the value in
 `mapped_values` at the same index.

### Example use 2

`value = {"testkey1": "testvalue1", "testkey2": "testvalue2"}` *(not specified by the user)*

`input_values = "key1: value1, testkey2: testvalue2"`

`mapped_values = "value1changed,testvalue2changed"`

The resulting output would be `{"key1": "value1", "key2": "testvalue2changed"}`. Because the `input_values` can be
parsed as a JSON dictionary, it will match the key: value pair, but only alter the value in the pair.

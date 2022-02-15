Given a list of objects and a key found in each of those objects, return a unique list of values associated with that key. Returns error if the objects provided do not contain the key of interest. 

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| object_list | List of objects \(dictionaries\). |
| key_of_interest | String representing key from which unique values should be retrieved. Use dot notation to access subkeys \(e.g. 'key.subkey'\) |
| keep_none | Default is False. If set to True, will return None in the unique list if the key is not found |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DeduplicatedValues | List of unique values for the specified key | Unknown |

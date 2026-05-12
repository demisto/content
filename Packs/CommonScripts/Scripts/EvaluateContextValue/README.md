The script is for use with GenericPolling, which checks the completion condition. It uses a DT to retrieve a value from the context data and evaluates it using another DT.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | evaluation, polling |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| id | The ID to identify the output value. |
| dt_encoding | The encoding scheme for the value_dt and eval_dt parameters. This can be useful for those parameters that contain special characters and require complex escaping. |
| value_dt | The DT expression for retrieving a value from the context data. |
| eval_dt | The DT expression for retrieving data for the evaluation from the value. |
| eval_key | The key name that is associated with the value before it's passed to eval_dt. If this parameter is provided, eval_dt receives a key-value pair \(the key name and the value for the evaluation\) in a dictionary. |
| playbook_id | The sub-playbook ID to get its local context from the context data. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EvaluateContextValue.id | The ID given to the argument parameters. | string |
| EvaluateContextValue.ok | The result of the evaluation by 'eval_dt'. | boolean |

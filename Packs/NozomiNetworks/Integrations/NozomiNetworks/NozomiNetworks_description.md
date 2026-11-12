## Nozomi Networks

This integration utilizes the **Nozomi Networks Universal Open API**.

## Prerequisites

To retrieve the `key_name` and `key_token`, please refer to the instructions provided in the **Nozomi Networks Products Technical Documentation**.

For detailed setup instructions, consult the technical documentation provided by Nozomi Networks.

### Custom incident name

By default, the incident name is `{name}_{id}`, built from the Nozomi alert name and ID.

To build the name from other alert fields, set the **Custom incident name pattern** parameter, for example `{type_id}_{id} - {description}`. Each `{field}` placeholder is replaced with the value of that alert field. Missing fields are rendered as empty, and the name is limited to 76 characters. If the parameter is empty, or the resulting name is empty, the default name is used.

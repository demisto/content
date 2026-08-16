# Cortex - Get User Defined Parsing Rules

This pack provides the **Cortex - Get User Defined Parsing Rules** Agentix action.

The action retrieves the full user-defined XQL parsing rules file configured under Dataset Management, returning its content hash, the complete rules text, and the last modification time. It takes no inputs.

## When to use

Trigger this action when the current user-defined parsing rules are needed, for example:

- The user reports they are not receiving expected data, or a dataset looks empty or malformed, and the parsing logic must be inspected.
- The user asks to validate or correct XQL parsing rule syntax and the existing rules are needed as the source of truth.

If no user-defined parsing rules are configured, the action returns the message `No user-defined parsing rules are defined.` and does not populate `Core.ParsingRule`.

## Outputs

| Path | Description | Type |
| --- | --- | --- |
| `Core.ParsingRule.hash` | The content hash of the user-defined parsing rules file. | string |
| `Core.ParsingRule.text` | The complete user-defined XQL parsing rules text. | string |
| `Core.ParsingRule.last_update` | The last modification time of the user-defined parsing rules, in epoch milliseconds. | number |

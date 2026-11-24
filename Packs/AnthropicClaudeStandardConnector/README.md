
# Anthropic Claude (Standard Connector)

## What does this pack do?

This pack contains the integration behind the Cortex XSOAR handler of the Claude connector. The integration provides:

- **Automation and Remediation.** All Anthropic Claude commands:
  - Compliance actions: the directory, chat and project read commands, and the irreversible chat file and project document delete commands. These use the Compliance Access Key.
  - Claude model commands: send a message, check email headers and bodies, and create SOC email templates. These use the Messages API key.
- **Log Collection.** The Compliance API Activity Feed, collected into the *anthropic_claude_raw* dataset.

The integration shares all of its code with the Anthropic Claude pack through the `AnthropicClaudeApiModule`.

This pack is configured automatically as part of the Claude connector. Do **not** configure the integration directly. Set it up from the connector page instead.

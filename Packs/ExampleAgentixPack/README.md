## Example Agentix Pack

An example Agentix pack that demonstrates how an **agent**, an **action**, and a **skill** work together.

### Contents

- **Agent** - `Example Weather` ([`ExampleWeatherAgent`](AgentixAgents/ExampleWeatherAgent/ExampleWeatherAgent.yml)): answers natural-language questions about the current weather in a city.
- **Action** - `Example - Get Weather` ([`ExampleGetWeather`](AgentixActions/ExampleGetWeather/ExampleGetWeather.yml)): retrieves the current weather for a given city.
- **Skill** - `Example Weather Reporting` ([`ExampleWeatherReporting`](AgentixSkills/ExampleWeatherReporting/ExampleWeatherReporting_skill.md)): rules for choosing the action arguments and presenting the result.

### How it fits together

The agent registers the action via `actionids` and the skill via `skillids`. When a user asks about the weather, the agent consults the skill to build the `city` and `units` arguments, calls the `ExampleGetWeather` action, and reports the returned conditions back to the user.

This pack is intended as a structural reference for building Agentix content; the underlying weather script is a placeholder and is not implemented.

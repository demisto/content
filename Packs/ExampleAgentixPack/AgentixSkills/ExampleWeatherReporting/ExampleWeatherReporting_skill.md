# Example Weather Reporting

You build the `city` (required) and `units` (optional) arguments for the <action=ExampleGetWeather> action and present its result to the user. Use when the user asks about current weather. Rules below are the only source of truth.

## Skill

**Scope guard.** Current weather conditions ONLY. For forecasts, historical weather, or climate data, do NOT call the action; tell the user only current weather is supported.

**Workflow.** Extract the city from the user's request; build the `city` argument; set `units` only if the user explicitly requested a unit system, else OMIT; call the action once; report the result.

**city argument.** A single city name as a plain string. Strip qualifiers like "the weather in" or "right now". If the user names a region or country without a city, ask once which city they mean. Never guess a city the user did not mention.

**units argument.** `metric` for Celsius, `imperial` for Fahrenheit. Map explicit phrases: "in Celsius"/"metric" -> `metric`; "in Fahrenheit"/"imperial" -> `imperial`. If the user gives no unit preference, OMIT the argument (do NOT pass `""`/`null`); the action defaults to `metric`.

**Presenting the result.** Report `Example.Weather.city`, `Example.Weather.temperature` (with the unit symbol matching the requested/default units), and `Example.Weather.conditions` in one concise sentence. Example: "It's currently 18C and partly cloudy in London."

**When to ask the user.** Ask ONCE in natural language, then call the action on reply. Triggers: (1) No city resolvable from the request. (2) Ambiguous city (e.g. multiple well-known cities share the name) -- quote the name and offer the likely options. (3) Contradictory unit requests -- ask which unit system to use.

# TypeSafe Jev

This integration connects Cortex XSIAM/XSOAR playbooks to TypeSafe's Jev
System One API.

## Configure the integration

| Parameter | Required | Description |
| --- | --- | --- |
| Server URL | Yes | TypeSafe API base URL. Keep `https://api.typesafe.ai`. |
| API Key | Yes | TypeSafe API key. Stored as a password-type parameter. |
| Model | No | Defaults to `jev-latest`. Pin a version if thresholds were tuned against it. |
| Request timeout | Yes | HTTP request timeout in seconds. |
| Trust any certificate | No | Disables TLS verification. Not recommended. |
| Use system proxy settings | No | Uses the Cortex proxy configuration. |

Click **Test** to validate the API key and connection.

## Commands

### jev-evaluate

Evaluates text or JSON state against a JSON map of TypeSafe questions. This is
the most flexible command and supports several questions in one request.

### jev-noul

Evaluates one yes/no judgment. The `probability` output is the probability of
yes on a scale from 0 to 1. Noul does not have a separate confidence value.

### jev-choice

Selects one option from the supplied JSON object. Returns the selected option,
the full probability distribution, and confidence.

### jev-score

Scores state against an ordered JSON array of two to ten level descriptions.
Returns the probability-weighted score, legend, full distribution, and
confidence.

### jev-list-models

Lists model aliases available to the configured TypeSafe account.

## Command examples

Run the commands from a case or Playground War Room after enabling an
integration instance.

### Evaluate multiple typed questions

```text
!jev-evaluate state="{\"alert\":{\"name\":\"Impossible travel\",\"severity\":\"high\"}}" questions="{\"needs_review\":{\"type\":\"noul\",\"instructions\":\"Does `alert` require analyst review?\"},\"response_route\":{\"type\":\"choice\",\"instructions\":\"Which route best fits `alert`?\",\"criteria\":{\"investigate\":\"Suspicious activity requiring investigation\",\"close\":\"Expected or benign activity\"}}}"
```

### Evaluate a yes/no judgment

```text
!jev-noul state="Suspicious PowerShell launched from Microsoft Word" instructions="Does this activity strongly indicate malicious execution?"
```

### Select one response route

```text
!jev-choice state="A user reports a duplicate credit card charge" instructions="Which response queue should receive this incident?" criteria="{\"fraud\":\"Unauthorized or suspicious payment activity\",\"billing\":\"Duplicate or incorrect legitimate charge\",\"other\":\"None of the above\"}"
```

### Score security risk

```text
!jev-score state="Repeated failed logins followed by a successful login from a new country" instructions="Rate the security risk" criteria="[\"Low risk\",\"Moderate risk\",\"High risk\",\"Critical risk\"]"
```

### List available models

```text
!jev-list-models
```

The War Room CLI requires double quotes around values containing spaces. For a
JSON argument, escape its inner double quotes as `\"`. In a playbook task,
enter the JSON directly in the argument field without CLI escaping.

## Copy-ready XSIAM playbook example

After configuring and testing the integration instance, add an **Automation**
task to a playbook and select `jev-choice`. A separate automation script is not
required.

Create a playbook input named `IncidentText` and map it to the incident field
Jev should examine, such as the incident details. Set the command arguments:

| Argument | Value |
| --- | --- |
| `state` | `${inputs.IncidentText}` |
| `instructions` | `Which response route best matches the security incident described in the state?` |
| `criteria` | `{"isolate_endpoint":"Strong evidence of active endpoint compromise requiring containment","investigate":"Suspicious activity requiring analyst investigation","close_benign":"Expected or clearly benign activity","manual_review":"Evidence is insufficient, ambiguous, or does not fit another option"}` |
| `model` | `jev-1.13.0` (optional; pin after validating thresholds) |

Use these context outputs in the following conditional tasks:

```text
TypeSafeJev.Choice.choice
TypeSafeJev.Choice.probabilities
TypeSafeJev.Choice.confidence
TypeSafeJev.Choice.model
TypeSafeJev.Choice.usage
```

Example policy:

```text
IF TypeSafeJev.Choice.choice == "isolate_endpoint"
AND TypeSafeJev.Choice.confidence >= 0.90
    -> request approval, then run containment

ELSE IF TypeSafeJev.Choice.choice == "investigate"
AND TypeSafeJev.Choice.confidence >= 0.70
    -> continue investigation

ELSE
    -> analyst review
```

The schema is predictable: `choice` is one of the supplied criteria keys,
`probabilities` contains the distribution over those keys, and `confidence` is
between 0 and 1. The judgment is probabilistic; validate thresholds on your own
incidents and retain analyst approval for high-impact actions.

### Test from the War Room

```text
!jev-choice state="Suspicious PowerShell launched by Microsoft Word" instructions="Which response route best matches this security incident?" criteria="{\"isolate_endpoint\":\"Strong evidence of active endpoint compromise requiring containment\",\"investigate\":\"Suspicious activity requiring analyst investigation\",\"close_benign\":\"Expected or clearly benign activity\",\"manual_review\":\"Insufficient or ambiguous evidence\"}"
```

## Playbook guidance

- Keep deterministic rules and remediation actions in the playbook.
- Ask one narrow judgment per question and batch independent questions that use
  the same state.
- Use explicit thresholds tested on your own incidents.
- Route uncertain and high-impact cases to an analyst.
- Do not send secrets or unnecessary incident data to the API.

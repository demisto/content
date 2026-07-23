# Cortex/Demisto Playbook Structure (LLM Reference)

Purpose: a dense, machine-oriented reference describing the YAML structure of a Cortex XSOAR / XSIAM playbook, with emphasis on how command and script INPUTS and OUTPUTS are wired. All examples are verbatim from real playbooks in this repo.

Reference playbooks used:
- `Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_Malware_-_Incident_Enrichment.yml` (~1430 lines)
- `Packs/ctf01/Playbooks/playbook-Cortex_XDR_-_Possible_External_RDP_Brute-Force_CTF.yml` (~1389 lines)

## 1. Schema Skeleton

```yaml
id: <string>                 # stable unique id, often equals name
name: <string>               # display name
version: -1                  # internal content version, almost always -1
description: |-              # multiline; supports \n and markdown
  <text>
starttaskid: '0'             # id of the entry task in the tasks map (always "0")
tasks:                       # MAP (not list) of stringified-int id -> task object
  '0':
    id: '0'
    taskid: <uuid>
    type: start              # start | title | regular | condition | playbook | collection
    task:                    # reusable task definition
      id: <uuid>
      version: -1
      name: <string>
      description: <string>
      type: <same enum>
      iscommand: <bool>      # true = integration command
      brand: <string>        # integration brand, or ""
      script: '<brand>|||<command>'   # for commands/scripts
      scriptName: <name>     # for automation scripts (alt to script)
      playbookName: <name>   # for type: playbook (sub-playbook)
    nexttasks:               # branch label -> list of next task ids
      '#none#':
      - '2'
    scriptarguments:         # INPUTS to the command/script
      <argName>:
        simple: <literal or ${DTexpr}>
    separatecontext: false
    continueonerrortype: ""
    view: |-                 # canvas node position (JSON)
      {"position": {"x": 0, "y": 0}}
inputs:                      # playbook-level inputs (list)
- key: <name>
  value: {}                  # {} | {simple: ...} | {complex: {...}}
  required: false
  description: <string>
  playbookInputQuery:
outputs:                     # playbook-level outputs (list)
- contextPath: <ContextPath>
  type: <string|unknown|...>
  description: <string>
fromversion: 6.5.0
tests:
- <test playbook name>       # or "- No tests"
contentitemexportablefields:
  contentitemfields: {}
system: true
marketplaces:
- xsoar
```

## 2. Top-Level Keys

| Key | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Stable unique id, often equals `name`. |
| `name` | string | yes | Display name. |
| `version` | int | yes | Internal content version; almost always `-1` in source. |
| `description` | multiline string | no | Supports `\n`, markdown. |
| `starttaskid` | string | yes | Id of entry task in `tasks`. Always `"0"`. |
| `tasks` | map | yes | Map of stringified-int taskID -> task object. NOT a list. |
| `inputs` | list | no | Playbook-level input parameters. |
| `outputs` | list | no | Playbook-level outputs published to context. |
| `fromversion` | string | no | Minimum platform version, e.g. `6.5.0`. |
| `tests` | list | yes | Linked test playbook names, or `- No tests`. |
| `contentitemexportablefields` | map | no | Usually `contentitemfields: {}`. |
| `view` | string (JSON) | no | Canvas layout metadata. |
| `system` | bool | no | Marks OOTB/system playbook. |
| `marketplaces` | list | no | e.g. `- xsoar`, `- marketplacev2`. |
| `quiet`, `inputSections`, `outputSections` | bool/list | no | Optional playbook-wide quiet mode / UI grouping. |

## 3. The `tasks` Map and a Task Entry

`tasks` is a MAP keyed by string ids (`'0'`, `'2'`, `"27"`). Each value is a task object.

### Task-level keys (siblings of `task:`)

| Key | Type | Meaning |
|---|---|---|
| `id` | string | Duplicate of the map key. |
| `taskid` | uuid string | Global unique instance id (matches `task.id`). |
| `type` | string | `start` \| `title` \| `regular` \| `condition` \| `playbook` \| `collection`. Mirrors `task.type`. |
| `task` | map | Reusable task definition (see below). |
| `nexttasks` | map | Branch label -> list of next task ids. |
| `scriptarguments` | map | INPUTS to the command/script. |
| `conditions` | list | Only on condition tasks with explicit logic. |
| `fieldMapping` | list | Maps command outputs -> incident fields. |
| `message` / `form` | map | Only on collection tasks. |
| `loop` | map | `exitCondition`, `iscommand`, `max`, `wait`. |
| `separatecontext` | bool | Run in isolated sub-context (sub-playbooks/loops). |
| `continueonerror` / `continueonerrortype` | bool / string | Error handling. |
| `reputationcalc` | int | Reputation calc mode. |
| `timertriggers` | list | SLA timers; usually `[]`. |
| `view` | string (JSON) | Node canvas position. |
| `note`, `quietmode`, `ignoreworker`, `skipunavailable`, `isoversize`, `isautoswitchedtoquietmode` | bool/int | Editor/runtime flags. |

### Inner `task:` sub-object

| Key | Type | Meaning |
|---|---|---|
| `id` | uuid | Matches outer `taskid`. |
| `version` | int | Usually `-1`. |
| `name` | string | Step display name. |
| `description` | string | Step description. |
| `type` | string | Same enum as outer `type`. |
| `iscommand` | bool | `true` if integration command; `false` for scripts / sub-playbooks / titles / conditions. |
| `brand` | string | Integration brand providing the command (e.g. `Cortex XDR - IR`, `Builtin`), or `""`. |
| `script` | string | For commands/scripts: `brand\|\|\|command`. |
| `scriptName` | string | Alt to `script` for AUTOMATION SCRIPTS by name (e.g. `isError`, `SetGridField`). |
| `playbookName` | string | For `type: playbook`: sub-playbook name. |

## 4. Input/Output Wiring (Centerpiece)

### 4.1 `scriptarguments` (inputs to a step)

`scriptarguments` is a map `argumentName -> valueObject`. Each `valueObject` is EXACTLY ONE of `{simple: ...}` or `{complex: {...}}`.

`simple` form: a literal string or a string with DT expressions `${...}`:

```yaml
scriptarguments:
  incident_id:
    simple: ${inputs.IncidentID}
```

Simple values can be plain literals or comma-separated lists:

```yaml
scriptarguments:
  columns:
    simple: Alert Name,Hostname,File Name,Process ID
  context_path:
    simple: PaloAltoNetworksXDR.Incident.alerts
```

`complex` form: reference a context path AND filter/transform before passing. Sub-keys:

| Sub-key | Meaning |
|---|---|
| `root` | Base context path (e.g. `incident`, `Account`, `Endpoint`, `PaloAltoNetworksXDR.Incident.alerts.actor_process_image_md5`). |
| `accessor` | Optional sub-field under `root` (e.g. `root: incident` + `accessor: agentsid`). |
| `filters` | List-of-lists of filter clauses. Outer list = AND groups; inner list = OR within a group. Each clause has `operator`, `left`, optional `right`. Context operands use `iscontext: true`. |
| `transformers` | Ordered list of transformer ops; each has `operator` and `args`. |

complex with accessor + transformer:

```yaml
scriptarguments:
  id:
    complex:
      accessor: agentsid
      root: incident
      transformers:
      - operator: uniq
```

complex with filters + chained transformers (canonical "first non-empty or default" pattern):

```yaml
scriptarguments:
  md5:
    complex:
      root: PaloAltoNetworksXDR.Incident.alerts.actor_process_image_md5
      filters:
      - - operator: isNotEmpty
          left:
            value:
              simple: PaloAltoNetworksXDR.Incident.alerts.actor_process_image_md5
            iscontext: true
      transformers:
      - operator: FirstArrayElement
      - operator: SetIfEmpty
        args:
          applyIfEmpty: {}
          defaultValue:
            value:
              simple: 'Null'
```

### 4.2 Referencing a command vs script vs sub-playbook

| Kind | Fields | Example |
|---|---|---|
| Integration command | `iscommand: true`, `script: '<brand>\|\|\|<command>'` | `script: "Cortex XDR - IR\|\|\|endpoint"`, `brand: "Cortex XDR - IR"` |
| Brand-agnostic command | `script: '\|\|\|<command>'`, `brand: ""` | `script: "\|\|\|xdr-get-incident-extra-data"` (any enabled integration exposing it) |
| Built-in command | `script: 'Builtin\|\|\|<command>'` | `script: "Builtin\|\|\|setIncident"` |
| Automation script | `iscommand: false`, `scriptName: <name>` | `scriptName: isError` |
| Sub-playbook | `type: playbook`, `playbookName: <name>` | `playbookName: Mitre Attack - Extract Technique Information From ID` |

### 4.3 Outputs are IMPLICIT (context flow)

There is NO explicit "outputs" declaration on a regular command task. A command/script writes its results into the shared CONTEXT automatically (the integration's own YAML defines its output context paths). Later tasks consume those results via context path.

- DT expression in a `simple` value: `${ContextPath}`. Supports `${inputs.X}`, `${incident.field}`, `${ContextPath}`, and array indexing `${Endpoint.[0].ID}`.
- `complex` reference: `root` (+ optional `accessor`) is a non-`${}` context path the engine resolves, then filters/transforms.
- `iscontext: true` on an operand means "this `value.simple` string is a context path, not a literal."

Concrete output -> consume chain: `xdr-get-incident-extra-data` populates `PaloAltoNetworksXDR.Incident.*`; the `endpoint` command populates `Endpoint.*`; a later `setIncident` task consumes it:

```yaml
scriptarguments:
  deviceid:
    simple: ${Endpoint.[0].ID}
  devicename:
    simple: ${Endpoint.[0].Hostname}
  deviceosname:
    simple: ${Endpoint.[0].OS}
```

### 4.4 `fieldMapping` (output shortcut)

`fieldMapping` is a task-level shortcut that maps a command's context output straight into incident fields (same `simple`/`complex` value shapes):

```yaml
fieldMapping:
- incidentfield: Hostnames
  output:
    simple: ${PaloAltoNetworksXDR.Incident.alerts.host_name}
```

## 5. Playbook-Level Inputs and Outputs

### 5.1 `inputs` (list)

Each element: `key` (name, referenced as `${inputs.<key>}`), `value` (value object: `{}` / `{simple: ...}` / `{complex: {...}}`), `required` (bool), `description` (string), `playbookInputQuery` (optional query, usually null).

```yaml
inputs:
- key: Username
  value: {}
  required: false
  description: RDP connection username.
  playbookInputQuery:
- key: AutoRemediation
  value:
    simple: "false"
  required: false
  description: Set to "true" to enable auto remediation.
  playbookInputQuery:
- key: IncidentID
  value:
    simple: ${incident.externalsystemid}
  required: false
  description: The incident ID to be enriched.
  playbookInputQuery:
```

### 5.2 `outputs` (list)

Each element: `contextPath` (context key the playbook publishes), `description` (string), `type` (optional: `string`, `unknown`, etc). No outputs -> `outputs: []`.

```yaml
outputs:
- contextPath: PaloAltoNetworksXDR.Incident
  type: unknown
  description: Cortex XDR incident information.
- contextPath: Endpoint.Hostname
  description: The host name mapped to this endpoint.
- contextPath: AttackPattern
  type: string
  description: Array of attack pattern names and IDs.
```

## 6. Condition Tasks and Branching

`condition` tasks branch execution. `nexttasks` uses branch LABELS as keys, each mapping to a list of next task ids. Special labels: `'#none#'` (unconditional next), `'#default#'` (else/fallback), and custom labels from `conditions`.

Flavor A - script-based: `task.scriptName` runs, its result selects the branch (e.g. `isError` returns `yes`):

```yaml
'18':
  type: condition
  nexttasks:
    '#default#':
    - '14'
    yes:
    - '17'
  scriptarguments:
    entryId:
      simple: ${lastCompletedTaskEntries}
  task:
    name: Is there only one endpoint?
    scriptName: isError
    type: condition
```

Flavor B - explicit `conditions` block: a `conditions` list defines logic inline. Each element: `label` (branch name, matches a `nexttasks` key), `condition` (list-of-lists: outer = AND groups, inner = OR clauses). Each clause: `operator` (`isEqualString`, `isNotEmpty`, `containsGeneral`, `greaterThanOrEqual`, etc), `left` (`{value: {simple: <path> | complex: {root, accessor}}, iscontext: true}`), `right` (`{value: {simple: <literal>}}`, omitted for unary operators like `isNotEmpty`).

Unary condition:

```yaml
'24':
  type: condition
  conditions:
  - label: yes
    condition:
    - - operator: isNotEmpty
        left:
          value:
            simple: ${incident.mitretechniqueid}
          iscontext: true
  nexttasks:
    '#default#':
    - '14'
    yes:
    - '22'
  task:
    name: Check If there is a Mitre technique
    type: condition
```

Multi-branch, multi-OR (left = context, right = literal):

```yaml
conditions:
- label: 0 or 1
  condition:
  - - operator: isEqualString
      left:
        value:
          complex: {root: incident, accessor: ipreputation}
        iscontext: true
      right:
        value:
          simple: "0"
    - operator: isEqualString
      left:
        value:
          complex: {root: incident, accessor: ipreputation}
        iscontext: true
      right:
        value:
          simple: "1"
nexttasks:
  0 or 1:
  - "143"
  2 or 3:
  - "144"
```

## 7. Collection (Data Collection / Survey) Task

`collection` tasks add `message` (recipients `to`, `subject`, `body`, `methods`, `timings`) and `form` (questions). Message fields use the same `simple`/`complex`/`${...}` shapes.

```yaml
'13':
  type: collection
  task:
    name: User Communication
    type: collection
    iscommand: false
  message:
    to:
      complex:
        root: ActiveDirectory.Users
        accessor: mail
    subject:
      simple: Was the following action performed by you?
    body:
      simple: |-
        RDP Brute force attempt by ${inputs.Username} from ${inputs.ExternalIP}.
    methods:
    - email
    timings:
      retriescount: 2
      completeafterreplies: 1
  form:
    questions:
    - id: "0"
      labelarg:
        simple: Was the following action performed by you?
      type: singleSelect
      optionsarg:
      - simple: Authorized
      - simple: Unauthorized
```

## 8. Cheat-Sheet / Rules

1. Inputs to a step always live under `scriptarguments: { <argName>: <valueObject> }`.
2. `valueObject` is EXACTLY ONE of `{simple: ...}` or `{complex: {...}}`.
3. `simple` = literal or `${DTexpression}`: `${inputs.X}`, `${incident.field}`, `${ContextPath}`, `${Path.[0].Field}` indexing.
4. `complex` = `root` (+ optional `accessor`) + optional `filters` (list-of-lists = AND-of-ORs; clauses have `operator`/`left`/`right`; context operands need `iscontext: true`) + ordered `transformers` (`operator` + `args`; args reuse the `value`/`iscontext` operand shape).
5. A command is named `brand|||command` in `task.script` (empty brand `|||cmd` = any provider). An automation script is named in `task.scriptName`. A sub-playbook in `task.playbookName`.
6. Outputs are IMPLICIT: commands write to context per their integration YAML; downstream tasks read via `${...}` or `complex.root`. There is no per-task output declaration; only the playbook-level `outputs` list declares what the whole playbook publishes.
7. Branching: `condition` tasks + `nexttasks` keyed by branch label. `'#none#'` = unconditional, `'#default#'` = else, custom labels come from `conditions[].label`. Condition logic = `conditions[].condition` list-of-lists (AND-of-ORs) with `operator`/`left`/`right`.
8. `fieldMapping` = task-level shortcut writing command outputs straight into incident fields.

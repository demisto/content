Mitre Caldera can be used to test endpoint security solutions and assess a network's security posture against the common post-compromise adversarial techniques contained in the ATT&CK model. CALDERA leverages the ATT&CK model to identify and replicate adversary behaviors as if a real intrusion is occurring.
This integration was integrated and tested with version 4.0.0 of MitreCaldera

## Configure MitreCaldera in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://www.example.com:8888) | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### caldera-create-fact
***
Create a Fact


#### Base Command

`caldera-create-fact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fact_name | Fact name. | Optional | 
| fact_links | Fact links (CSV of IDs). | Optional | 
| fact_relationships | Fact relationships (CSV of IDs). | Optional | 
| fact_origin_type | Fact origin type. | Optional | 
| fact_limit_count | Fact limit count. | Optional | 
| fact_technique_id | Fact technique ID. | Optional | 
| fact_trait | Fact trait. | Required | 
| fact_source | Fact source. | Optional | 
| fact_score | Fact score. | Optional | 
| fact_value | Fact value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Facts.unique | String |  | 
| MitreCaldera.Facts.name | String |  | 
| MitreCaldera.Facts.created | String |  | 
| MitreCaldera.Facts.limit_count | Number |  | 
| MitreCaldera.Facts.technique_id | String |  | 
| MitreCaldera.Facts.trait | String |  | 
| MitreCaldera.Facts.source | String |  | 
| MitreCaldera.Facts.score | Number |  | 

### caldera-create-fact-source
***
Create a Fact Source.


#### Base Command

`caldera-create-fact-source`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name. | Optional | 
| adjustments | Adjustments (array of adjustment objects). | Optional | 
| relationships | Relationships (array of relationship objects). | Optional | 
| rules | Rules (array of rule objects). | Optional | 
| facts | Facts (array of fact objects). | Optional | 
| plugin | Plugin. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Sources.name | String |  | 
| MitreCaldera.Sources.adjustments.ability_id | String |  | 
| MitreCaldera.Sources.adjustments.offset | Number |  | 
| MitreCaldera.Sources.adjustments.trait | String |  | 
| MitreCaldera.Sources.adjustments.value | String |  | 
| MitreCaldera.Sources.relationships.unique | String |  | 
| MitreCaldera.Sources.relationships.origin | String |  | 
| MitreCaldera.Sources.relationships.edge | String |  | 
| MitreCaldera.Sources.relationships.score | Number |  | 
| MitreCaldera.Sources.id | String |  | 
| MitreCaldera.Sources.rules.trait | String |  | 
| MitreCaldera.Sources.rules.match | String |  | 
| MitreCaldera.Sources.facts.unique | String |  | 
| MitreCaldera.Sources.facts.name | String |  | 
| MitreCaldera.Sources.facts.created | String |  | 
| MitreCaldera.Sources.facts.limit_count | Number |  | 
| MitreCaldera.Sources.facts.technique_id | String |  | 
| MitreCaldera.Sources.facts.trait | String |  | 
| MitreCaldera.Sources.facts.source | String |  | 
| MitreCaldera.Sources.facts.score | Number |  | 
| MitreCaldera.Sources.plugin | String |  | 

### caldera-create-adversary
***
Create a new adversary


#### Base Command

`caldera-create-adversary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Adversary name. | Optional | 
| tags | Tags (CSV of tag names). | Optional | 
| objective | Objective. | Optional | 
| atomic_ordering | Atomic ordering (CSV of ability IDs). | Optional | 
| plugin | Plugin. | Optional | 
| description | Description. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Adversaries.name | String |  | 
| MitreCaldera.Adversaries.objective | String |  | 
| MitreCaldera.Adversaries.adversary_id | String |  | 
| MitreCaldera.Adversaries.has_repeatable_abilities | Boolean |  | 
| MitreCaldera.Adversaries.plugin | String |  | 
| MitreCaldera.Adversaries.description | String |  | 

### caldera-create-agent
***
Create a new agent


#### Base Command

`caldera-create-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchdog | Watchdog timer. | Optional | 
| deadman_enabled | Deadman enabled (true or false). Possible values are: false, true. Default is false. | Optional | 
| ppid | PPID. | Optional | 
| pid | PID. | Optional | 
| proxy_receivers | Proxy Receivers (JSON dict). | Optional | 
| origin_link_id | Origin link ID. | Optional | 
| available_contacts | Available contacts (CSV of contact IDs). | Optional | 
| platform | Platform. | Optional | 
| host | Host. | Optional | 
| group | Group. | Optional | 
| location | Location. | Optional | 
| display_name | Display name. | Optional | 
| upstream_dest | Upstream destination. | Optional | 
| host_ip_addrs | Host IP addresses (CSV of IP addresses). | Optional | 
| sleep_max | Sleep maximum. | Optional | 
| architecture | Architecture. | Optional | 
| sleep_min | Sleep minimum. | Optional | 
| server | Server. | Optional | 
| contact | Contact. | Optional | 
| exeutors | Executors (CSV of executor IDs). | Optional | 
| privilege | Privilege. | Optional | 
| username | Username. | Optional | 
| trusted | Trusted. Possible values are: false, true. Default is true. | Optional | 
| proxy_chain | Proxy chain (array of proxy arrays). | Optional | 
| paw | Agent PAW. | Optional | 
| exe_name | EXE name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Agents.watchdog | Number |  | 
| MitreCaldera.Agents.links.relationships.unique | String |  | 
| MitreCaldera.Agents.links.relationships.origin | String |  | 
| MitreCaldera.Agents.links.relationships.edge | String |  | 
| MitreCaldera.Agents.links.relationships.score | Number |  | 
| MitreCaldera.Agents.links.id | String |  | 
| MitreCaldera.Agents.links.collect | String |  | 
| MitreCaldera.Agents.links.pid | String |  | 
| MitreCaldera.Agents.links.finish | String |  | 
| MitreCaldera.Agents.links.pin | Number |  | 
| MitreCaldera.Agents.links.jitter | Number |  | 
| MitreCaldera.Agents.links.agent_reported_time | String |  | 
| MitreCaldera.Agents.links.deadman | Boolean |  | 
| MitreCaldera.Agents.links.used.unique | String |  | 
| MitreCaldera.Agents.links.used.name | String |  | 
| MitreCaldera.Agents.links.used.created | String |  | 
| MitreCaldera.Agents.links.used.limit_count | Number |  | 
| MitreCaldera.Agents.links.used.technique_id | String |  | 
| MitreCaldera.Agents.links.used.trait | String |  | 
| MitreCaldera.Agents.links.used.source | String |  | 
| MitreCaldera.Agents.links.used.score | Number |  | 
| MitreCaldera.Agents.links.host | String |  | 
| MitreCaldera.Agents.links.status | Number |  | 
| MitreCaldera.Agents.links.score | Number |  | 
| MitreCaldera.Agents.links.command | String |  | 
| MitreCaldera.Agents.links.unique | String |  | 
| MitreCaldera.Agents.links.cleanup | Number |  | 
| MitreCaldera.Agents.links.decide | String |  | 
| MitreCaldera.Agents.links.facts.unique | String |  | 
| MitreCaldera.Agents.links.facts.name | String |  | 
| MitreCaldera.Agents.links.facts.created | String |  | 
| MitreCaldera.Agents.links.facts.limit_count | Number |  | 
| MitreCaldera.Agents.links.facts.technique_id | String |  | 
| MitreCaldera.Agents.links.facts.trait | String |  | 
| MitreCaldera.Agents.links.facts.source | String |  | 
| MitreCaldera.Agents.links.facts.score | Number |  | 
| MitreCaldera.Agents.links.paw | String |  | 
| MitreCaldera.Agents.links.output | String |  | 
| MitreCaldera.Agents.deadman_enabled | Boolean |  | 
| MitreCaldera.Agents.ppid | Number |  | 
| MitreCaldera.Agents.pid | Number |  | 
| MitreCaldera.Agents.created | String |  | 
| MitreCaldera.Agents.origin_link_id | String |  | 
| MitreCaldera.Agents.last_seen | String |  | 
| MitreCaldera.Agents.platform | String |  | 
| MitreCaldera.Agents.pending_contact | String |  | 
| MitreCaldera.Agents.host | String |  | 
| MitreCaldera.Agents.group | String |  | 
| MitreCaldera.Agents.location | String |  | 
| MitreCaldera.Agents.display_name | String |  | 
| MitreCaldera.Agents.upstream_dest | String |  | 
| MitreCaldera.Agents.sleep_max | Number |  | 
| MitreCaldera.Agents.architecture | String |  | 
| MitreCaldera.Agents.sleep_min | Number |  | 
| MitreCaldera.Agents.server | String |  | 
| MitreCaldera.Agents.contact | String |  | 
| MitreCaldera.Agents.privilege | String |  | 
| MitreCaldera.Agents.username | String |  | 
| MitreCaldera.Agents.trusted | Boolean |  | 
| MitreCaldera.Agents.proxy_chain | String |  | 
| MitreCaldera.Agents.paw | String |  | 
| MitreCaldera.Agents.exe_name | String |  | 

### caldera-create-operation
***
Create a new CALDERA operation record


#### Base Command

`caldera-create-operation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Operation name. | Required | 
| autonomous | Autonomous (autonomous or manual). Possible values are: autonomous, manual. Default is autonomous. | Optional | 
| objective_id | Objective ID. | Optional | 
| visibility | How visible should the operation be to the defense (1-100), default is 51. | Optional | 
| state | State. Possible values are: running, paused, run_one_link. Default is running. | Optional | 
| group | Group. | Optional | 
| host_group | Host group. | Optional | 
| planner_id | Planner ID. | Required | 
| obfuscator | Obfuscator. Possible values are: base64, base64jumble, base64noPadding, caesar cipher, plain-text, steganography. Default is plain-text. | Optional | 
| use_learning_parsers | Use learning parsers. Possible values are: false, true. Default is false. | Optional | 
| source_id | Source ID. | Required | 
| jitter | Jitter is defined as a fraction (default is "2/8"). | Optional | 
| adversary_id | adversary id. | Required | 
| auto_close | Auto close. Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Operations.name | String |  | 
| MitreCaldera.Operations.autonomous | Number |  | 
| MitreCaldera.Operations.id | String |  | 
| MitreCaldera.Operations.visibility | Number |  | 
| MitreCaldera.Operations.state | String |  | 
| MitreCaldera.Operations.group | String |  | 
| MitreCaldera.Operations.host_group.watchdog | Number |  | 
| MitreCaldera.Operations.host_group.links.relationships.unique | String |  | 
| MitreCaldera.Operations.host_group.links.relationships.origin | String |  | 
| MitreCaldera.Operations.host_group.links.relationships.edge | String |  | 
| MitreCaldera.Operations.host_group.links.relationships.score | Number |  | 
| MitreCaldera.Operations.host_group.links.id | String |  | 
| MitreCaldera.Operations.host_group.links.collect | String |  | 
| MitreCaldera.Operations.host_group.links.pid | String |  | 
| MitreCaldera.Operations.host_group.links.finish | String |  | 
| MitreCaldera.Operations.host_group.links.pin | Number |  | 
| MitreCaldera.Operations.host_group.links.jitter | Number |  | 
| MitreCaldera.Operations.host_group.links.agent_reported_time | String |  | 
| MitreCaldera.Operations.host_group.links.deadman | Boolean |  | 
| MitreCaldera.Operations.host_group.links.used.unique | String |  | 
| MitreCaldera.Operations.host_group.links.used.name | String |  | 
| MitreCaldera.Operations.host_group.links.used.created | String |  | 
| MitreCaldera.Operations.host_group.links.used.limit_count | Number |  | 
| MitreCaldera.Operations.host_group.links.used.technique_id | String |  | 
| MitreCaldera.Operations.host_group.links.used.trait | String |  | 
| MitreCaldera.Operations.host_group.links.used.source | String |  | 
| MitreCaldera.Operations.host_group.links.used.score | Number |  | 
| MitreCaldera.Operations.host_group.links.host | String |  | 
| MitreCaldera.Operations.host_group.links.status | Number |  | 
| MitreCaldera.Operations.host_group.links.score | Number |  | 
| MitreCaldera.Operations.host_group.links.command | String |  | 
| MitreCaldera.Operations.host_group.links.unique | String |  | 
| MitreCaldera.Operations.host_group.links.cleanup | Number |  | 
| MitreCaldera.Operations.host_group.links.decide | String |  | 
| MitreCaldera.Operations.host_group.links.facts.unique | String |  | 
| MitreCaldera.Operations.host_group.links.facts.name | String |  | 
| MitreCaldera.Operations.host_group.links.facts.created | String |  | 
| MitreCaldera.Operations.host_group.links.facts.limit_count | Number |  | 
| MitreCaldera.Operations.host_group.links.facts.technique_id | String |  | 
| MitreCaldera.Operations.host_group.links.facts.trait | String |  | 
| MitreCaldera.Operations.host_group.links.facts.source | String |  | 
| MitreCaldera.Operations.host_group.links.facts.score | Number |  | 
| MitreCaldera.Operations.host_group.links.paw | String |  | 
| MitreCaldera.Operations.host_group.links.output | String |  | 
| MitreCaldera.Operations.host_group.deadman_enabled | Boolean |  | 
| MitreCaldera.Operations.host_group.ppid | Number |  | 
| MitreCaldera.Operations.host_group.pid | Number |  | 
| MitreCaldera.Operations.host_group.created | String |  | 
| MitreCaldera.Operations.host_group.origin_link_id | String |  | 
| MitreCaldera.Operations.host_group.last_seen | String |  | 
| MitreCaldera.Operations.host_group.platform | String |  | 
| MitreCaldera.Operations.host_group.pending_contact | String |  | 
| MitreCaldera.Operations.host_group.host | String |  | 
| MitreCaldera.Operations.host_group.group | String |  | 
| MitreCaldera.Operations.host_group.location | String |  | 
| MitreCaldera.Operations.host_group.display_name | String |  | 
| MitreCaldera.Operations.host_group.upstream_dest | String |  | 
| MitreCaldera.Operations.host_group.sleep_max | Number |  | 
| MitreCaldera.Operations.host_group.architecture | String |  | 
| MitreCaldera.Operations.host_group.sleep_min | Number |  | 
| MitreCaldera.Operations.host_group.server | String |  | 
| MitreCaldera.Operations.host_group.contact | String |  | 
| MitreCaldera.Operations.host_group.privilege | String |  | 
| MitreCaldera.Operations.host_group.username | String |  | 
| MitreCaldera.Operations.host_group.trusted | Boolean |  | 
| MitreCaldera.Operations.host_group.proxy_chain | String |  | 
| MitreCaldera.Operations.host_group.paw | String |  | 
| MitreCaldera.Operations.host_group.exe_name | String |  | 
| MitreCaldera.Operations.obfuscator | String |  | 
| MitreCaldera.Operations.use_learning_parsers | Boolean |  | 
| MitreCaldera.Operations.jitter | String |  | 
| MitreCaldera.Operations.start | String |  | 
| MitreCaldera.Operations.auto_close | Boolean |  | 

### caldera-create-objective
***
Create a new objective


#### Base Command

`caldera-create-objective`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Objective name. | Optional | 
| goals | Goals (array of objective objects). | Optional | 
| description | Description. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Objectives.name | String |  | 
| MitreCaldera.Objectives.id | String |  | 
| MitreCaldera.Objectives.percentage | Unknown |  | 
| MitreCaldera.Objectives.goals.count | Number |  | 
| MitreCaldera.Objectives.goals.achieved | Boolean |  | 
| MitreCaldera.Objectives.goals.operator | String |  | 
| MitreCaldera.Objectives.goals.value | String |  | 
| MitreCaldera.Objectives.goals.target | String |  | 
| MitreCaldera.Objectives.description | String |  | 

### caldera-create-relationship
***
Create a Relationship


#### Base Command

`caldera-create-relationship`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| relationship_unique | . | Optional | 
| relationship_origin | . | Optional | 
| relationship_edge | . | Optional | 
| relationship_source_unique | relationship_source unique. | Optional | 
| relationship_source_name | relationship_source name. | Optional | 
| relationship_source_links | relationship_source links. | Optional | 
| relationship_source_relationships | relationship_source relationships. | Optional | 
| relationship_source_origin_type | relationship_source origin_type. | Optional | 
| relationship_source_created | relationship_source created. | Optional | 
| relationship_source_limit_count | relationship_source limit_count. | Optional | 
| relationship_source_technique_id | relationship_source technique_id. | Optional | 
| relationship_source_trait | relationship_source trait. | Required | 
| relationship_source_source | relationship_source source. | Optional | 
| relationship_source_score | relationship_source score. | Optional | 
| relationship_source_value | relationship_source value. | Optional | 
| relationship_source_collected_by | relationship_source collected_by. | Optional | 
| relationship_score | . | Optional | 
| relationship_target | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Relationship.unique | String |  | 
| MitreCaldera.Relationship.origin | String |  | 
| MitreCaldera.Relationship.edge | String |  | 
| MitreCaldera.Relationship.score | Number |  | 

### caldera-create-ability
***
Creates a new ability.


#### Base Command

`caldera-create-ability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ability_ability_id | . | Optional | 
| ability_name | . | Optional | 
| ability_buckets | . | Optional | 
| ability_technique_id | . | Optional | 
| ability_delete_payload | . | Optional | 
| ability_executors | . | Optional | 
| ability_privilege | . | Optional | 
| ability_requirements | . | Optional | 
| ability_plugin | . | Optional | 
| ability_access | . | Optional | 
| ability_tactic | . | Optional | 
| ability_additional_info | . | Optional | 
| ability_singleton | . | Optional | 
| ability_technique_name | . | Optional | 
| ability_repeatable | . | Optional | 
| ability_description | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Abilities.ability_id | String |  | 
| MitreCaldera.Abilities.name | String |  | 
| MitreCaldera.Abilities.technique_id | String |  | 
| MitreCaldera.Abilities.delete_payload | Boolean |  | 
| MitreCaldera.Abilities.executors.name | String |  | 
| MitreCaldera.Abilities.executors.platform | String |  | 
| MitreCaldera.Abilities.executors.language | String |  | 
| MitreCaldera.Abilities.executors.variations.command | String |  | 
| MitreCaldera.Abilities.executors.variations.description | String |  | 
| MitreCaldera.Abilities.executors.build_target | String |  | 
| MitreCaldera.Abilities.executors.timeout | Number |  | 
| MitreCaldera.Abilities.executors.parsers.module | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.edge | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.source | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.target | String |  | 
| MitreCaldera.Abilities.executors.command | String |  | 
| MitreCaldera.Abilities.executors.code | String |  | 
| MitreCaldera.Abilities.privilege | String |  | 
| MitreCaldera.Abilities.requirements.module | String |  | 
| MitreCaldera.Abilities.plugin | String |  | 
| MitreCaldera.Abilities.tactic | String |  | 
| MitreCaldera.Abilities.singleton | Boolean |  | 
| MitreCaldera.Abilities.technique_name | String |  | 
| MitreCaldera.Abilities.repeatable | Boolean |  | 
| MitreCaldera.Abilities.description | String |  | 

### caldera-create-potential-link
***
Creates a potential Link


#### Base Command

`caldera-create-potential-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | UUID of the operation object for the link to be created on. | Required | 
| link_relationships | . | Optional | 
| link_id | . | Optional | 
| link_collect | . | Optional | 
| link_pid | . | Optional | 
| link_visibility_adjustments | link_visibility adjustments. | Optional | 
| link_visibility_score | link_visibility score. | Optional | 
| link_finish | . | Optional | 
| link_pin | . | Optional | 
| link_jitter | . | Optional | 
| link_agent_reported_time | . | Optional | 
| link_deadman | . | Optional | 
| link_used | . | Optional | 
| link_host | . | Optional | 
| link_ability_ability_id | link_ability ability_id. | Optional | 
| link_ability_name | link_ability name. | Optional | 
| link_ability_buckets | link_ability buckets. | Optional | 
| link_ability_technique_id | link_ability technique_id. | Optional | 
| link_ability_delete_payload | link_ability delete_payload. | Optional | 
| link_ability_executors | link_ability executors. | Optional | 
| link_ability_privilege | link_ability privilege. | Optional | 
| link_ability_requirements | link_ability requirements. | Optional | 
| link_ability_plugin | link_ability plugin. | Optional | 
| link_ability_access | link_ability access. | Optional | 
| link_ability_tactic | link_ability tactic. | Optional | 
| link_ability_additional_info | link_ability additional_info. | Optional | 
| link_ability_singleton | link_ability singleton. | Optional | 
| link_ability_technique_name | link_ability technique_name. | Optional | 
| link_ability_repeatable | link_ability repeatable. | Optional | 
| link_ability_description | link_ability description. | Optional | 
| link_status | . | Optional | 
| link_score | . | Optional | 
| link_command | . | Optional | 
| link_unique | . | Optional | 
| link_cleanup | . | Optional | 
| link_decide | . | Optional | 
| link_facts | . | Optional | 
| link_executor_name | link_executor name. | Optional | 
| link_executor_cleanup | link_executor cleanup. | Optional | 
| link_executor_platform | link_executor platform. | Optional | 
| link_executor_language | link_executor language. | Optional | 
| link_executor_uploads | link_executor uploads. | Optional | 
| link_executor_variations | link_executor variations. | Optional | 
| link_executor_build_target | link_executor build_target. | Optional | 
| link_executor_payloads | link_executor payloads. | Optional | 
| link_executor_timeout | link_executor timeout. | Optional | 
| link_executor_parsers | link_executor parsers. | Optional | 
| link_executor_command | link_executor command. | Optional | 
| link_executor_additional_info | link_executor additional_info. | Optional | 
| link_executor_code | link_executor code. | Optional | 
| link_paw | . | Optional | 
| link_output | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Links.relationships.unique | String |  | 
| MitreCaldera.Links.relationships.origin | String |  | 
| MitreCaldera.Links.relationships.edge | String |  | 
| MitreCaldera.Links.relationships.score | Number |  | 
| MitreCaldera.Links.id | String |  | 
| MitreCaldera.Links.collect | String |  | 
| MitreCaldera.Links.pid | String |  | 
| MitreCaldera.Links.finish | String |  | 
| MitreCaldera.Links.pin | Number |  | 
| MitreCaldera.Links.jitter | Number |  | 
| MitreCaldera.Links.agent_reported_time | String |  | 
| MitreCaldera.Links.deadman | Boolean |  | 
| MitreCaldera.Links.used.unique | String |  | 
| MitreCaldera.Links.used.name | String |  | 
| MitreCaldera.Links.used.created | String |  | 
| MitreCaldera.Links.used.limit_count | Number |  | 
| MitreCaldera.Links.used.technique_id | String |  | 
| MitreCaldera.Links.used.trait | String |  | 
| MitreCaldera.Links.used.source | String |  | 
| MitreCaldera.Links.used.score | Number |  | 
| MitreCaldera.Links.host | String |  | 
| MitreCaldera.Links.status | Number |  | 
| MitreCaldera.Links.score | Number |  | 
| MitreCaldera.Links.command | String |  | 
| MitreCaldera.Links.unique | String |  | 
| MitreCaldera.Links.cleanup | Number |  | 
| MitreCaldera.Links.decide | String |  | 
| MitreCaldera.Links.facts.unique | String |  | 
| MitreCaldera.Links.facts.name | String |  | 
| MitreCaldera.Links.facts.created | String |  | 
| MitreCaldera.Links.facts.limit_count | Number |  | 
| MitreCaldera.Links.facts.technique_id | String |  | 
| MitreCaldera.Links.facts.trait | String |  | 
| MitreCaldera.Links.facts.source | String |  | 
| MitreCaldera.Links.facts.score | Number |  | 
| MitreCaldera.Links.paw | String |  | 
| MitreCaldera.Links.output | String |  | 

### caldera-create-schedule
***
Create Schedule


#### Base Command

`caldera-create-schedule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_schedule | . | Required | 
| schedule_task_name | schedule_task name. | Optional | 
| schedule_task_autonomous | schedule_task autonomous. | Optional | 
| schedule_task_id | schedule_task id. | Optional | 
| schedule_task_objective | schedule_task objective. | Optional | 
| schedule_task_visibility | schedule_task visibility. | Optional | 
| schedule_task_state | schedule_task state. | Optional | 
| schedule_task_group | schedule_task group. | Optional | 
| schedule_task_host_group | schedule_task host_group. | Optional | 
| schedule_task_planner | schedule_task planner. | Optional | 
| schedule_task_obfuscator | schedule_task obfuscator. | Optional | 
| schedule_task_chain | schedule_task chain. | Optional | 
| schedule_task_use_learning_parsers | schedule_task use_learning_parsers. | Optional | 
| schedule_task_source | schedule_task source. | Optional | 
| schedule_task_jitter | schedule_task jitter. | Optional | 
| schedule_task_start | schedule_task start. | Optional | 
| schedule_task_adversary | schedule_task adversary. | Optional | 
| schedule_task_auto_close | schedule_task auto_close. | Optional | 
| schedule_id | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Schedule.schedule | String |  | 
| MitreCaldera.Schedule.id | String |  | 

### caldera-delete-agent
***
Delete an Agent


#### Base Command

`caldera-delete-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| paw | paw of the Agent to be deleted. | Required | 


#### Context Output

There is no context output for this command.
### caldera-delete-fact-source
***
Delete an existing Fact Source.


#### Base Command

`caldera-delete-fact-source`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fact_source_id | The id of the Fact Source to be deleted. | Required | 


#### Context Output

There is no context output for this command.
### caldera-delete-operation
***
Delete an operation by operation id


#### Base Command

`caldera-delete-operation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | UUID of the Operation object to be retrieved. | Required | 


#### Context Output

There is no context output for this command.
### caldera-delete-facts
***
Delete One or More Facts


#### Base Command

`caldera-delete-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fact_unique | . | Optional | 
| fact_name | . | Optional | 
| fact_links | . | Optional | 
| fact_relationships | . | Optional | 
| fact_origin_type | . | Optional | 
| fact_created | . | Optional | 
| fact_limit_count | . | Optional | 
| fact_technique_id | . | Optional | 
| fact_trait | . | Optional | 
| fact_source | . | Optional | 
| fact_score | . | Optional | 
| fact_value | . | Optional | 
| fact_collected_by | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Facts.unique | String |  | 
| MitreCaldera.Facts.name | String |  | 
| MitreCaldera.Facts.created | String |  | 
| MitreCaldera.Facts.limit_count | Number |  | 
| MitreCaldera.Facts.technique_id | String |  | 
| MitreCaldera.Facts.trait | String |  | 
| MitreCaldera.Facts.source | String |  | 
| MitreCaldera.Facts.score | Number |  | 

### caldera-delete-relationships
***
Delete One or More Relationships


#### Base Command

`caldera-delete-relationships`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| relationship_unique | . | Optional | 
| relationship_origin | . | Optional | 
| relationship_edge | . | Optional | 
| relationship_source_unique | relationship_source unique. | Optional | 
| relationship_source_name | relationship_source name. | Optional | 
| relationship_source_links | relationship_source links. | Optional | 
| relationship_source_relationships | relationship_source relationships. | Optional | 
| relationship_source_origin_type | relationship_source origin_type. | Optional | 
| relationship_source_created | relationship_source created. | Optional | 
| relationship_source_limit_count | relationship_source limit_count. | Optional | 
| relationship_source_technique_id | relationship_source technique_id. | Optional | 
| relationship_source_trait | relationship_source trait. | Optional | 
| relationship_source_source | relationship_source source. | Optional | 
| relationship_source_score | relationship_source score. | Optional | 
| relationship_source_value | relationship_source value. | Optional | 
| relationship_source_collected_by | relationship_source collected_by. | Optional | 
| relationship_score | . | Optional | 
| relationship_target | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Relationship.unique | String |  | 
| MitreCaldera.Relationship.origin | String |  | 
| MitreCaldera.Relationship.edge | String |  | 
| MitreCaldera.Relationship.score | Number |  | 

### caldera-delete-ability
***
Deletes an ability.


#### Base Command

`caldera-delete-ability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ability_id | UUID of the Ability to be deleted. | Required | 


#### Context Output

There is no context output for this command.
### caldera-delete-adversary
***
Deletes an adversary.


#### Base Command

`caldera-delete-adversary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adversary_id | UUID of the adversary to be deleted. | Required | 


#### Context Output

There is no context output for this command.
### caldera-delete-schedule
***
Delete Schedule


#### Base Command

`caldera-delete-schedule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_id | UUID of the Schedule to be deleted. | Required | 


#### Context Output

There is no context output for this command.
### caldera-get-abilities
***
Get all Abilities with optional ability ID.


#### Base Command

`caldera-get-abilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ability_id | Optional UUID of the Ability to be retrieved. | Optional | 
| sort | Results are sorted if no Ability ID is provided. | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Abilities.ability_id | String |  | 
| MitreCaldera.Abilities.name | String |  | 
| MitreCaldera.Abilities.technique_id | String |  | 
| MitreCaldera.Abilities.delete_payload | Boolean |  | 
| MitreCaldera.Abilities.executors.name | String |  | 
| MitreCaldera.Abilities.executors.platform | String |  | 
| MitreCaldera.Abilities.executors.language | String |  | 
| MitreCaldera.Abilities.executors.variations.command | String |  | 
| MitreCaldera.Abilities.executors.variations.description | String |  | 
| MitreCaldera.Abilities.executors.build_target | String |  | 
| MitreCaldera.Abilities.executors.timeout | Number |  | 
| MitreCaldera.Abilities.executors.parsers.module | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.edge | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.source | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.target | String |  | 
| MitreCaldera.Abilities.executors.command | String |  | 
| MitreCaldera.Abilities.executors.code | String |  | 
| MitreCaldera.Abilities.privilege | String |  | 
| MitreCaldera.Abilities.requirements.module | String |  | 
| MitreCaldera.Abilities.plugin | String |  | 
| MitreCaldera.Abilities.tactic | String |  | 
| MitreCaldera.Abilities.singleton | Boolean |  | 
| MitreCaldera.Abilities.technique_name | String |  | 
| MitreCaldera.Abilities.repeatable | Boolean |  | 
| MitreCaldera.Abilities.description | String |  | 

### caldera-get-adversaries
***
Get all Adversaries with optional Adversary ID


#### Base Command

`caldera-get-adversaries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adversary_id | Optional UUID of the adversary to be retrieved. | Optional | 
| sort | Results are sorted if no Adversary ID is provided. | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Adversaries.name | String |  | 
| MitreCaldera.Adversaries.objective | String |  | 
| MitreCaldera.Adversaries.adversary_id | String |  | 
| MitreCaldera.Adversaries.has_repeatable_abilities | Boolean |  | 
| MitreCaldera.Adversaries.plugin | String |  | 
| MitreCaldera.Adversaries.description | String |  | 

### caldera-get-agents
***
Retrieves all agents with optional Agent PAW


#### Base Command

`caldera-get-agents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| paw | Optioanl PAW ID of the Agent to retrieve information about. | Optional | 
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Agents.watchdog | Number |  | 
| MitreCaldera.Agents.links.relationships.unique | String |  | 
| MitreCaldera.Agents.links.relationships.origin | String |  | 
| MitreCaldera.Agents.links.relationships.edge | String |  | 
| MitreCaldera.Agents.links.relationships.score | Number |  | 
| MitreCaldera.Agents.links.id | String |  | 
| MitreCaldera.Agents.links.collect | String |  | 
| MitreCaldera.Agents.links.pid | String |  | 
| MitreCaldera.Agents.links.finish | String |  | 
| MitreCaldera.Agents.links.pin | Number |  | 
| MitreCaldera.Agents.links.jitter | Number |  | 
| MitreCaldera.Agents.links.agent_reported_time | String |  | 
| MitreCaldera.Agents.links.deadman | Boolean |  | 
| MitreCaldera.Agents.links.used.unique | String |  | 
| MitreCaldera.Agents.links.used.name | String |  | 
| MitreCaldera.Agents.links.used.created | String |  | 
| MitreCaldera.Agents.links.used.limit_count | Number |  | 
| MitreCaldera.Agents.links.used.technique_id | String |  | 
| MitreCaldera.Agents.links.used.trait | String |  | 
| MitreCaldera.Agents.links.used.source | String |  | 
| MitreCaldera.Agents.links.used.score | Number |  | 
| MitreCaldera.Agents.links.host | String |  | 
| MitreCaldera.Agents.links.status | Number |  | 
| MitreCaldera.Agents.links.score | Number |  | 
| MitreCaldera.Agents.links.command | String |  | 
| MitreCaldera.Agents.links.unique | String |  | 
| MitreCaldera.Agents.links.cleanup | Number |  | 
| MitreCaldera.Agents.links.decide | String |  | 
| MitreCaldera.Agents.links.facts.unique | String |  | 
| MitreCaldera.Agents.links.facts.name | String |  | 
| MitreCaldera.Agents.links.facts.created | String |  | 
| MitreCaldera.Agents.links.facts.limit_count | Number |  | 
| MitreCaldera.Agents.links.facts.technique_id | String |  | 
| MitreCaldera.Agents.links.facts.trait | String |  | 
| MitreCaldera.Agents.links.facts.source | String |  | 
| MitreCaldera.Agents.links.facts.score | Number |  | 
| MitreCaldera.Agents.links.paw | String |  | 
| MitreCaldera.Agents.links.output | String |  | 
| MitreCaldera.Agents.deadman_enabled | Boolean |  | 
| MitreCaldera.Agents.ppid | Number |  | 
| MitreCaldera.Agents.pid | Number |  | 
| MitreCaldera.Agents.created | String |  | 
| MitreCaldera.Agents.origin_link_id | String |  | 
| MitreCaldera.Agents.last_seen | String |  | 
| MitreCaldera.Agents.platform | String |  | 
| MitreCaldera.Agents.pending_contact | String |  | 
| MitreCaldera.Agents.host | String |  | 
| MitreCaldera.Agents.group | String |  | 
| MitreCaldera.Agents.location | String |  | 
| MitreCaldera.Agents.display_name | String |  | 
| MitreCaldera.Agents.upstream_dest | String |  | 
| MitreCaldera.Agents.sleep_max | Number |  | 
| MitreCaldera.Agents.architecture | String |  | 
| MitreCaldera.Agents.sleep_min | Number |  | 
| MitreCaldera.Agents.server | String |  | 
| MitreCaldera.Agents.contact | String |  | 
| MitreCaldera.Agents.privilege | String |  | 
| MitreCaldera.Agents.username | String |  | 
| MitreCaldera.Agents.trusted | Boolean |  | 
| MitreCaldera.Agents.proxy_chain | String |  | 
| MitreCaldera.Agents.paw | String |  | 
| MitreCaldera.Agents.exe_name | String |  | 

### caldera-get-config
***
Retrieve Config


#### Base Command

`caldera-get-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the configuration file to be retrieved (example: main). Default is main. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Name | String | Config name | 
| MitreCaldera.Config | Unknown | Config settings | 

### caldera-get-contacts
***
Retrieve a List of all available Contact reports


#### Base Command

`caldera-get-contacts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Optional name of the contact to get beacons for, e.g. HTTP, TCP, et cetera. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Contacts | Unknnown | List of contacts | 

### caldera-get-deploy-commands
***
Retrieve deploy commands with optional Ability ID


#### Base Command

`caldera-get-deploy-commands`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ability_id | ID of the ability to retrieve deploy commands for. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.DeployCommands.command | String | Command | 
| MitreCaldera.DeployCommands.description | String | Description | 
| MitreCaldera.DeployCommands.executor | String | Executor | 
| MitreCaldera.DeployCommands.name | String | Name | 
| MitreCaldera.DeployCommands.platform | String | Platform | 
| MitreCaldera.DeployCommands.variations.command | String | Command | 
| MitreCaldera.DeployCommands.variations.description | String | Description | 

### caldera-get-facts
***
Retrieve Facts with optional Operation ID


#### Base Command

`caldera-get-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 
| operation_id | Optional Operation ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Facts.unique | String |  | 
| MitreCaldera.Facts.name | String |  | 
| MitreCaldera.Facts.created | String |  | 
| MitreCaldera.Facts.limit_count | Number |  | 
| MitreCaldera.Facts.technique_id | String |  | 
| MitreCaldera.Facts.trait | String |  | 
| MitreCaldera.Facts.source | String |  | 
| MitreCaldera.Facts.score | Number |  | 

### caldera-get-health
***
Health endpoints returns the status of CALDERA


#### Base Command

`caldera-get-health`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.CalderaInfo.application | String |  | 
| MitreCaldera.CalderaInfo.version | String |  | 
| MitreCaldera.CalderaInfo.plugins.name | String |  | 
| MitreCaldera.CalderaInfo.plugins.enabled | Boolean |  | 
| MitreCaldera.CalderaInfo.plugins.description | String |  | 
| MitreCaldera.CalderaInfo.plugins.address | String |  | 

### caldera-get-obfuscators
***
Retrieve obfuscators with optional name


#### Base Command

`caldera-get-obfuscators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the Obfuscator. | Optional | 
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Obfuscators.name | String |  | 
| MitreCaldera.Obfuscators.module | String |  | 
| MitreCaldera.Obfuscators.description | String |  | 

### caldera-get-objectives
***
Retrieve objectives with optional Objective ID


#### Base Command

`caldera-get-objectives`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Optional UUID of the objective to be retrieved. | Optional | 
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Objectives.name | String |  | 
| MitreCaldera.Objectives.id | String |  | 
| MitreCaldera.Objectives.percentage | Unknown |  | 
| MitreCaldera.Objectives.goals.count | Number |  | 
| MitreCaldera.Objectives.goals.achieved | Boolean |  | 
| MitreCaldera.Objectives.goals.operator | String |  | 
| MitreCaldera.Objectives.goals.value | String |  | 
| MitreCaldera.Objectives.goals.target | String |  | 
| MitreCaldera.Objectives.description | String |  | 

### caldera-get-operations
***
Retrieve operations


#### Base Command

`caldera-get-operations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Optional UUID of the Operation object to be retrieved. | Optional | 
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Operations.name | String |  | 
| MitreCaldera.Operations.autonomous | Number |  | 
| MitreCaldera.Operations.id | String |  | 
| MitreCaldera.Operations.visibility | Number |  | 
| MitreCaldera.Operations.state | String |  | 
| MitreCaldera.Operations.group | String |  | 
| MitreCaldera.Operations.host_group.watchdog | Number |  | 
| MitreCaldera.Operations.host_group.links.relationships.unique | String |  | 
| MitreCaldera.Operations.host_group.links.relationships.origin | String |  | 
| MitreCaldera.Operations.host_group.links.relationships.edge | String |  | 
| MitreCaldera.Operations.host_group.links.relationships.score | Number |  | 
| MitreCaldera.Operations.host_group.links.id | String |  | 
| MitreCaldera.Operations.host_group.links.collect | String |  | 
| MitreCaldera.Operations.host_group.links.pid | String |  | 
| MitreCaldera.Operations.host_group.links.finish | String |  | 
| MitreCaldera.Operations.host_group.links.pin | Number |  | 
| MitreCaldera.Operations.host_group.links.jitter | Number |  | 
| MitreCaldera.Operations.host_group.links.agent_reported_time | String |  | 
| MitreCaldera.Operations.host_group.links.deadman | Boolean |  | 
| MitreCaldera.Operations.host_group.links.used.unique | String |  | 
| MitreCaldera.Operations.host_group.links.used.name | String |  | 
| MitreCaldera.Operations.host_group.links.used.created | String |  | 
| MitreCaldera.Operations.host_group.links.used.limit_count | Number |  | 
| MitreCaldera.Operations.host_group.links.used.technique_id | String |  | 
| MitreCaldera.Operations.host_group.links.used.trait | String |  | 
| MitreCaldera.Operations.host_group.links.used.source | String |  | 
| MitreCaldera.Operations.host_group.links.used.score | Number |  | 
| MitreCaldera.Operations.host_group.links.host | String |  | 
| MitreCaldera.Operations.host_group.links.status | Number |  | 
| MitreCaldera.Operations.host_group.links.score | Number |  | 
| MitreCaldera.Operations.host_group.links.command | String |  | 
| MitreCaldera.Operations.host_group.links.unique | String |  | 
| MitreCaldera.Operations.host_group.links.cleanup | Number |  | 
| MitreCaldera.Operations.host_group.links.decide | String |  | 
| MitreCaldera.Operations.host_group.links.facts.unique | String |  | 
| MitreCaldera.Operations.host_group.links.facts.name | String |  | 
| MitreCaldera.Operations.host_group.links.facts.created | String |  | 
| MitreCaldera.Operations.host_group.links.facts.limit_count | Number |  | 
| MitreCaldera.Operations.host_group.links.facts.technique_id | String |  | 
| MitreCaldera.Operations.host_group.links.facts.trait | String |  | 
| MitreCaldera.Operations.host_group.links.facts.source | String |  | 
| MitreCaldera.Operations.host_group.links.facts.score | Number |  | 
| MitreCaldera.Operations.host_group.links.paw | String |  | 
| MitreCaldera.Operations.host_group.links.output | String |  | 
| MitreCaldera.Operations.host_group.deadman_enabled | Boolean |  | 
| MitreCaldera.Operations.host_group.ppid | Number |  | 
| MitreCaldera.Operations.host_group.pid | Number |  | 
| MitreCaldera.Operations.host_group.created | String |  | 
| MitreCaldera.Operations.host_group.origin_link_id | String |  | 
| MitreCaldera.Operations.host_group.last_seen | String |  | 
| MitreCaldera.Operations.host_group.platform | String |  | 
| MitreCaldera.Operations.host_group.pending_contact | String |  | 
| MitreCaldera.Operations.host_group.host | String |  | 
| MitreCaldera.Operations.host_group.group | String |  | 
| MitreCaldera.Operations.host_group.location | String |  | 
| MitreCaldera.Operations.host_group.display_name | String |  | 
| MitreCaldera.Operations.host_group.upstream_dest | String |  | 
| MitreCaldera.Operations.host_group.sleep_max | Number |  | 
| MitreCaldera.Operations.host_group.architecture | String |  | 
| MitreCaldera.Operations.host_group.sleep_min | Number |  | 
| MitreCaldera.Operations.host_group.server | String |  | 
| MitreCaldera.Operations.host_group.contact | String |  | 
| MitreCaldera.Operations.host_group.privilege | String |  | 
| MitreCaldera.Operations.host_group.username | String |  | 
| MitreCaldera.Operations.host_group.trusted | Boolean |  | 
| MitreCaldera.Operations.host_group.proxy_chain | String |  | 
| MitreCaldera.Operations.host_group.paw | String |  | 
| MitreCaldera.Operations.host_group.exe_name | String |  | 
| MitreCaldera.Operations.obfuscator | String |  | 
| MitreCaldera.Operations.use_learning_parsers | Boolean |  | 
| MitreCaldera.Operations.jitter | String |  | 
| MitreCaldera.Operations.start | String |  | 
| MitreCaldera.Operations.auto_close | Boolean |  | 

### caldera-get-operation-links
***
Get Links from Operation with optional Link ID


#### Base Command

`caldera-get-operation-links`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | . | Required | 
| link_id | Optional UUID of the Link with the operation. | Optional | 
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.OperationLinks.relationships.unique | String |  | 
| MitreCaldera.OperationLinks.relationships.origin | String |  | 
| MitreCaldera.OperationLinks.relationships.edge | String |  | 
| MitreCaldera.OperationLinks.relationships.score | Number |  | 
| MitreCaldera.OperationLinks.id | String |  | 
| MitreCaldera.OperationLinks.collect | String |  | 
| MitreCaldera.OperationLinks.pid | String |  | 
| MitreCaldera.OperationLinks.finish | String |  | 
| MitreCaldera.OperationLinks.pin | Number |  | 
| MitreCaldera.OperationLinks.jitter | Number |  | 
| MitreCaldera.OperationLinks.agent_reported_time | String |  | 
| MitreCaldera.OperationLinks.deadman | Boolean |  | 
| MitreCaldera.OperationLinks.used.unique | String |  | 
| MitreCaldera.OperationLinks.used.name | String |  | 
| MitreCaldera.OperationLinks.used.created | String |  | 
| MitreCaldera.OperationLinks.used.limit_count | Number |  | 
| MitreCaldera.OperationLinks.used.technique_id | String |  | 
| MitreCaldera.OperationLinks.used.trait | String |  | 
| MitreCaldera.OperationLinks.used.source | String |  | 
| MitreCaldera.OperationLinks.used.score | Number |  | 
| MitreCaldera.OperationLinks.host | String |  | 
| MitreCaldera.OperationLinks.status | Number |  | 
| MitreCaldera.OperationLinks.score | Number |  | 
| MitreCaldera.OperationLinks.command | String |  | 
| MitreCaldera.OperationLinks.unique | String |  | 
| MitreCaldera.OperationLinks.cleanup | Number |  | 
| MitreCaldera.OperationLinks.decide | String |  | 
| MitreCaldera.OperationLinks.facts.unique | String |  | 
| MitreCaldera.OperationLinks.facts.name | String |  | 
| MitreCaldera.OperationLinks.facts.created | String |  | 
| MitreCaldera.OperationLinks.facts.limit_count | Number |  | 
| MitreCaldera.OperationLinks.facts.technique_id | String |  | 
| MitreCaldera.OperationLinks.facts.trait | String |  | 
| MitreCaldera.OperationLinks.facts.source | String |  | 
| MitreCaldera.OperationLinks.facts.score | Number |  | 
| MitreCaldera.OperationLinks.paw | String |  | 
| MitreCaldera.OperationLinks.output | String |  | 

### caldera-get-operation-links-result
***
Retrieve the result of a link


#### Base Command

`caldera-get-operation-links-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | UUID of the operation object to be retrieved. | Required | 
| link_id | UUID of the link object to retrieve results of. | Required | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.OperationLinks.relationships.unique | String |  | 
| MitreCaldera.OperationLinks.relationships.origin | String |  | 
| MitreCaldera.OperationLinks.relationships.edge | String |  | 
| MitreCaldera.OperationLinks.relationships.score | Number |  | 
| MitreCaldera.OperationLinks.id | String |  | 
| MitreCaldera.OperationLinks.collect | String |  | 
| MitreCaldera.OperationLinks.pid | String |  | 
| MitreCaldera.OperationLinks.finish | String |  | 
| MitreCaldera.OperationLinks.pin | Number |  | 
| MitreCaldera.OperationLinks.jitter | Number |  | 
| MitreCaldera.OperationLinks.agent_reported_time | String |  | 
| MitreCaldera.OperationLinks.deadman | Boolean |  | 
| MitreCaldera.OperationLinks.used.unique | String |  | 
| MitreCaldera.OperationLinks.used.name | String |  | 
| MitreCaldera.OperationLinks.used.created | String |  | 
| MitreCaldera.OperationLinks.used.limit_count | Number |  | 
| MitreCaldera.OperationLinks.used.technique_id | String |  | 
| MitreCaldera.OperationLinks.used.trait | String |  | 
| MitreCaldera.OperationLinks.used.source | String |  | 
| MitreCaldera.OperationLinks.used.score | Number |  | 
| MitreCaldera.OperationLinks.host | String |  | 
| MitreCaldera.OperationLinks.status | Number |  | 
| MitreCaldera.OperationLinks.score | Number |  | 
| MitreCaldera.OperationLinks.command | String |  | 
| MitreCaldera.OperationLinks.unique | String |  | 
| MitreCaldera.OperationLinks.cleanup | Number |  | 
| MitreCaldera.OperationLinks.decide | String |  | 
| MitreCaldera.OperationLinks.facts.unique | String |  | 
| MitreCaldera.OperationLinks.facts.name | String |  | 
| MitreCaldera.OperationLinks.facts.created | String |  | 
| MitreCaldera.OperationLinks.facts.limit_count | Number |  | 
| MitreCaldera.OperationLinks.facts.technique_id | String |  | 
| MitreCaldera.OperationLinks.facts.trait | String |  | 
| MitreCaldera.OperationLinks.facts.source | String |  | 
| MitreCaldera.OperationLinks.facts.score | Number |  | 
| MitreCaldera.OperationLinks.paw | String |  | 
| MitreCaldera.OperationLinks.output | String |  | 

### caldera-get-operations-potential-links
***
Retrieve potential links for an operation with optional PAW.


#### Base Command

`caldera-get-operations-potential-links`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | UUID of the operation object to retrieve links for. | Required | 
| paw | Optional Agent paw for the specified operation. | Optional | 
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.OperationLinks.relationships.unique | String |  | 
| MitreCaldera.OperationLinks.relationships.origin | String |  | 
| MitreCaldera.OperationLinks.relationships.edge | String |  | 
| MitreCaldera.OperationLinks.relationships.score | Number |  | 
| MitreCaldera.OperationLinks.id | String |  | 
| MitreCaldera.OperationLinks.collect | String |  | 
| MitreCaldera.OperationLinks.pid | String |  | 
| MitreCaldera.OperationLinks.finish | String |  | 
| MitreCaldera.OperationLinks.pin | Number |  | 
| MitreCaldera.OperationLinks.jitter | Number |  | 
| MitreCaldera.OperationLinks.agent_reported_time | String |  | 
| MitreCaldera.OperationLinks.deadman | Boolean |  | 
| MitreCaldera.OperationLinks.used.unique | String |  | 
| MitreCaldera.OperationLinks.used.name | String |  | 
| MitreCaldera.OperationLinks.used.created | String |  | 
| MitreCaldera.OperationLinks.used.limit_count | Number |  | 
| MitreCaldera.OperationLinks.used.technique_id | String |  | 
| MitreCaldera.OperationLinks.used.trait | String |  | 
| MitreCaldera.OperationLinks.used.source | String |  | 
| MitreCaldera.OperationLinks.used.score | Number |  | 
| MitreCaldera.OperationLinks.host | String |  | 
| MitreCaldera.OperationLinks.status | Number |  | 
| MitreCaldera.OperationLinks.score | Number |  | 
| MitreCaldera.OperationLinks.command | String |  | 
| MitreCaldera.OperationLinks.unique | String |  | 
| MitreCaldera.OperationLinks.cleanup | Number |  | 
| MitreCaldera.OperationLinks.decide | String |  | 
| MitreCaldera.OperationLinks.facts.unique | String |  | 
| MitreCaldera.OperationLinks.facts.name | String |  | 
| MitreCaldera.OperationLinks.facts.created | String |  | 
| MitreCaldera.OperationLinks.facts.limit_count | Number |  | 
| MitreCaldera.OperationLinks.facts.technique_id | String |  | 
| MitreCaldera.OperationLinks.facts.trait | String |  | 
| MitreCaldera.OperationLinks.facts.source | String |  | 
| MitreCaldera.OperationLinks.facts.score | Number |  | 
| MitreCaldera.OperationLinks.paw | String |  | 
| MitreCaldera.OperationLinks.output | String |  | 

### caldera-get-planners
***
Retrieve planners with optional Planner ID


#### Base Command

`caldera-get-planners`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| planner_id | UUID of the Planner object to be retrieved. | Optional | 
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Planners.name | String |  | 
| MitreCaldera.Planners.allow_repeatable_abilities | Boolean |  | 
| MitreCaldera.Planners.stopping_conditions.unique | String |  | 
| MitreCaldera.Planners.stopping_conditions.name | String |  | 
| MitreCaldera.Planners.stopping_conditions.created | String |  | 
| MitreCaldera.Planners.stopping_conditions.limit_count | Number |  | 
| MitreCaldera.Planners.stopping_conditions.technique_id | String |  | 
| MitreCaldera.Planners.stopping_conditions.trait | String |  | 
| MitreCaldera.Planners.stopping_conditions.source | String |  | 
| MitreCaldera.Planners.stopping_conditions.score | Number |  | 
| MitreCaldera.Planners.id | String |  | 
| MitreCaldera.Planners.plugin | String |  | 
| MitreCaldera.Planners.module | String |  | 
| MitreCaldera.Planners.description | String |  | 

### caldera-get-plugins
***
Retrieve plugins with optional Name


#### Base Command

`caldera-get-plugins`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the plugin. | Optional | 
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Plugins.name | String |  | 
| MitreCaldera.Plugins.enabled | Boolean |  | 
| MitreCaldera.Plugins.address | String |  | 
| MitreCaldera.Plugins.access | Number |  | 
| MitreCaldera.Plugins.data_dir | String |  | 
| MitreCaldera.Plugins.description | String |  | 

### caldera-get-relationships
***
Retrieve Relationships with optional Operation ID


#### Base Command

`caldera-get-relationships`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | . | Optional | 
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Relationships.unique | String |  | 
| MitreCaldera.Relationships.origin | String |  | 
| MitreCaldera.Relationships.edge | String |  | 
| MitreCaldera.Relationships.score | Number |  | 

### caldera-get-schedules
***
Retrieve Schedules with optional Schedule ID


#### Base Command

`caldera-get-schedules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_id | Optional UUID of the Schedule to be retrieved. | Optional | 
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Schedules.schedule | String |  | 
| MitreCaldera.Schedules.id | String |  | 

### caldera-get-sources
***
Retrieve all Fact Sources with optional Fact Source ID


#### Base Command

`caldera-get-sources`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_id | The id of the Fact Source. | Optional | 
| sort | . | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Sources.name | String |  | 
| MitreCaldera.Sources.adjustments.ability_id | String |  | 
| MitreCaldera.Sources.adjustments.offset | Number |  | 
| MitreCaldera.Sources.adjustments.trait | String |  | 
| MitreCaldera.Sources.adjustments.value | String |  | 
| MitreCaldera.Sources.relationships.unique | String |  | 
| MitreCaldera.Sources.relationships.origin | String |  | 
| MitreCaldera.Sources.relationships.edge | String |  | 
| MitreCaldera.Sources.relationships.score | Number |  | 
| MitreCaldera.Sources.id | String |  | 
| MitreCaldera.Sources.rules.trait | String |  | 
| MitreCaldera.Sources.rules.match | String |  | 
| MitreCaldera.Sources.facts.unique | String |  | 
| MitreCaldera.Sources.facts.name | String |  | 
| MitreCaldera.Sources.facts.created | String |  | 
| MitreCaldera.Sources.facts.limit_count | Number |  | 
| MitreCaldera.Sources.facts.technique_id | String |  | 
| MitreCaldera.Sources.facts.trait | String |  | 
| MitreCaldera.Sources.facts.source | String |  | 
| MitreCaldera.Sources.facts.score | Number |  | 
| MitreCaldera.Sources.plugin | String |  | 

### caldera-get-operation-event-logs
***
Get Operation Event Logs


#### Base Command

`caldera-get-operation-event-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | . | Required | 
| enable_agent_output | Whether to enable the agent output. Possible values are: false, true. Default is false. | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Operations.EventLogs.id | String |  | 
| MitreCaldera.Operations.EventLogs.collected_timestamp | String |  | 
| MitreCaldera.Operations.EventLogs.ability_metadata | Unknown |  | 
| MitreCaldera.Operations.EventLogs.attack_metadata | Unknown |  | 
| MitreCaldera.Operations.EventLogs.operation_metadata | Unknown |  | 
| MitreCaldera.Operations.EventLogs.finished_timestamp | String |  | 
| MitreCaldera.Operations.EventLogs.agent_metadata | Unknown |  | 
| MitreCaldera.Operations.EventLogs.pid | Number |  | 
| MitreCaldera.Operations.EventLogs.command | String |  | 
| MitreCaldera.Operations.EventLogs.status | Number |  | 
| MitreCaldera.Operations.EventLogs.platform | String |  | 
| MitreCaldera.Operations.EventLogs.executor | String |  | 
| MitreCaldera.Operations.EventLogs.delegated_timestamp | String |  | 

### caldera-get-operation-report
***
Get Operation Report


#### Base Command

`caldera-get-operation-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | . | Required | 
| enable_agent_output | Whether to enable the agent output. Possible values are: false, true. Default is false. | Optional | 
| include | . | Optional | 
| exclude | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Operations.OperationReport.id | String |  | 
| MitreCaldera.Operations.OperationReport.start | String |  | 
| MitreCaldera.Operations.OperationReport.steps | Unknown |  | 
| MitreCaldera.Operations.OperationReport.facts | Unknown |  | 
| MitreCaldera.Operations.OperationReport.host_group | Unknown |  | 
| MitreCaldera.Operations.OperationReport.name | String |  | 
| MitreCaldera.Operations.OperationReport.jitter | String |  | 
| MitreCaldera.Operations.OperationReport.planner | String |  | 
| MitreCaldera.Operations.OperationReport.finish | String |  | 
| MitreCaldera.Operations.OperationReport.adversary | Unknown |  | 
| MitreCaldera.Operations.OperationReport.skipped_abilities | Unknown |  | 
| MitreCaldera.Operations.OperationReport.objectives | Unknown |  | 

### caldera-replace-ability
***
Replaces an existing ability.


#### Base Command

`caldera-replace-ability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ability_id | UUID of the Ability to be retrieved. | Required | 
| ability_name | . | Optional | 
| ability_buckets | . | Optional | 
| ability_technique_id | . | Optional | 
| ability_delete_payload | . | Optional | 
| ability_executors | . | Optional | 
| ability_privilege | . | Optional | 
| ability_requirements | . | Optional | 
| ability_plugin | . | Optional | 
| ability_access | . | Optional | 
| ability_tactic | . | Optional | 
| ability_additional_info | . | Optional | 
| ability_singleton | . | Optional | 
| ability_technique_name | . | Optional | 
| ability_repeatable | . | Optional | 
| ability_description | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Abilities.id | String |  | 
| MitreCaldera.Abilities.name | String |  | 
| MitreCaldera.Abilities.technique_id | String |  | 
| MitreCaldera.Abilities.delete_payload | Boolean |  | 
| MitreCaldera.Abilities.executors.name | String |  | 
| MitreCaldera.Abilities.executors.platform | String |  | 
| MitreCaldera.Abilities.executors.language | String |  | 
| MitreCaldera.Abilities.executors.variations.command | String |  | 
| MitreCaldera.Abilities.executors.variations.description | String |  | 
| MitreCaldera.Abilities.executors.build_target | String |  | 
| MitreCaldera.Abilities.executors.timeout | Number |  | 
| MitreCaldera.Abilities.executors.parsers.module | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.edge | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.source | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.target | String |  | 
| MitreCaldera.Abilities.executors.command | String |  | 
| MitreCaldera.Abilities.executors.code | String |  | 
| MitreCaldera.Abilities.privilege | String |  | 
| MitreCaldera.Abilities.requirements.module | String |  | 
| MitreCaldera.Abilities.plugin | String |  | 
| MitreCaldera.Abilities.tactic | String |  | 
| MitreCaldera.Abilities.singleton | Boolean |  | 
| MitreCaldera.Abilities.technique_name | String |  | 
| MitreCaldera.Abilities.repeatable | Boolean |  | 
| MitreCaldera.Abilities.description | String |  | 

### caldera-replace-schedule
***
Replace Schedule


#### Base Command

`caldera-replace-schedule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_id | UUID of the Schedule to be replaced. | Required | 
| partial_schedule_schedule | . | Optional | 
| partial_schedule_task_name | partial_schedule_task name. | Optional | 
| partial_schedule_task_autonomous | partial_schedule_task autonomous. | Optional | 
| partial_schedule_task_id | partial_schedule_task id. | Optional | 
| partial_schedule_task_objective | partial_schedule_task objective. | Optional | 
| partial_schedule_task_visibility | partial_schedule_task visibility. | Optional | 
| partial_schedule_task_state | partial_schedule_task state. | Optional | 
| partial_schedule_task_group | partial_schedule_task group. | Optional | 
| partial_schedule_task_host_group | partial_schedule_task host_group. | Optional | 
| partial_schedule_task_planner | partial_schedule_task planner. | Optional | 
| partial_schedule_task_obfuscator | partial_schedule_task obfuscator. | Optional | 
| partial_schedule_task_chain | partial_schedule_task chain. | Optional | 
| partial_schedule_task_use_learning_parsers | partial_schedule_task use_learning_parsers. | Optional | 
| partial_schedule_task_source | partial_schedule_task source. | Optional | 
| partial_schedule_task_jitter | partial_schedule_task jitter. | Optional | 
| partial_schedule_task_start | partial_schedule_task start. | Optional | 
| partial_schedule_task_adversary | partial_schedule_task adversary. | Optional | 
| partial_schedule_task_auto_close | partial_schedule_task auto_close. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Schedules.schedule | String |  | 
| MitreCaldera.Schedules.id | String |  | 

### caldera-update-agent-config
***
Update Agent Config


#### Base Command

`caldera-update-agent-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchdog | . | Optional | 
| sleep_min | . | Optional | 
| deployments | . | Optional | 
| deadman_abilities | . | Optional | 
| untrusted_timer | . | Optional | 
| bootstrap_abilities | . | Optional | 
| sleep_max | . | Optional | 
| implant_name | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.AgentConfig.watchdog | Number |  | 
| MitreCaldera.AgentConfig.sleep_min | Number |  | 
| MitreCaldera.AgentConfig.untrusted_timer | Number |  | 
| MitreCaldera.AgentConfig.sleep_max | Number |  | 
| MitreCaldera.AgentConfig.implant_name | String |  | 

### caldera-update-adversary
***
Update an adversary


#### Base Command

`caldera-update-adversary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adversary_id | UUID of the adversary to be updated. | Required | 
| adversaryname | . | Optional | 
| adversarytags | . | Optional | 
| adversaryobjective | . | Optional | 
| adversaryhas_repeatable_abilities | . | Optional | 
| adversaryatomic_ordering | . | Optional | 
| adversaryplugin | . | Optional | 
| adversarydescription | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Adversaries.name | String |  | 
| MitreCaldera.Adversaries.objective | String |  | 
| MitreCaldera.Adversaries.adversary_id | String |  | 
| MitreCaldera.Adversaries.has_repeatable_abilities | Boolean |  | 
| MitreCaldera.Adversaries.plugin | String |  | 
| MitreCaldera.Adversaries.description | String |  | 

### caldera-update-agent
***
Update an Agent


#### Base Command

`caldera-update-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| paw | ID of the Agent to update. | Required | 
| watchdog | . | Optional | 
| sleep_min | . | Optional | 
| trusted | . | Optional | 
| sleep_max | . | Optional | 
| pending_contact | . | Optional | 
| group | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Agents.watchdog | Number |  | 
| MitreCaldera.Agents.links.relationships.unique | String |  | 
| MitreCaldera.Agents.links.relationships.origin | String |  | 
| MitreCaldera.Agents.links.relationships.edge | String |  | 
| MitreCaldera.Agents.links.relationships.score | Number |  | 
| MitreCaldera.Agents.links.id | String |  | 
| MitreCaldera.Agents.links.collect | String |  | 
| MitreCaldera.Agents.links.pid | String |  | 
| MitreCaldera.Agents.links.finish | String |  | 
| MitreCaldera.Agents.links.pin | Number |  | 
| MitreCaldera.Agents.links.jitter | Number |  | 
| MitreCaldera.Agents.links.agent_reported_time | String |  | 
| MitreCaldera.Agents.links.deadman | Boolean |  | 
| MitreCaldera.Agents.links.used.unique | String |  | 
| MitreCaldera.Agents.links.used.name | String |  | 
| MitreCaldera.Agents.links.used.created | String |  | 
| MitreCaldera.Agents.links.used.limit_count | Number |  | 
| MitreCaldera.Agents.links.used.technique_id | String |  | 
| MitreCaldera.Agents.links.used.trait | String |  | 
| MitreCaldera.Agents.links.used.source | String |  | 
| MitreCaldera.Agents.links.used.score | Number |  | 
| MitreCaldera.Agents.links.host | String |  | 
| MitreCaldera.Agents.links.status | Number |  | 
| MitreCaldera.Agents.links.score | Number |  | 
| MitreCaldera.Agents.links.command | String |  | 
| MitreCaldera.Agents.links.unique | String |  | 
| MitreCaldera.Agents.links.cleanup | Number |  | 
| MitreCaldera.Agents.links.decide | String |  | 
| MitreCaldera.Agents.links.facts.unique | String |  | 
| MitreCaldera.Agents.links.facts.name | String |  | 
| MitreCaldera.Agents.links.facts.created | String |  | 
| MitreCaldera.Agents.links.facts.limit_count | Number |  | 
| MitreCaldera.Agents.links.facts.technique_id | String |  | 
| MitreCaldera.Agents.links.facts.trait | String |  | 
| MitreCaldera.Agents.links.facts.source | String |  | 
| MitreCaldera.Agents.links.facts.score | Number |  | 
| MitreCaldera.Agents.links.paw | String |  | 
| MitreCaldera.Agents.links.output | String |  | 
| MitreCaldera.Agents.deadman_enabled | Boolean |  | 
| MitreCaldera.Agents.ppid | Number |  | 
| MitreCaldera.Agents.pid | Number |  | 
| MitreCaldera.Agents.created | String |  | 
| MitreCaldera.Agents.origin_link_id | String |  | 
| MitreCaldera.Agents.last_seen | String |  | 
| MitreCaldera.Agents.platform | String |  | 
| MitreCaldera.Agents.pending_contact | String |  | 
| MitreCaldera.Agents.host | String |  | 
| MitreCaldera.Agents.group | String |  | 
| MitreCaldera.Agents.location | String |  | 
| MitreCaldera.Agents.display_name | String |  | 
| MitreCaldera.Agents.upstream_dest | String |  | 
| MitreCaldera.Agents.sleep_max | Number |  | 
| MitreCaldera.Agents.architecture | String |  | 
| MitreCaldera.Agents.sleep_min | Number |  | 
| MitreCaldera.Agents.server | String |  | 
| MitreCaldera.Agents.contact | String |  | 
| MitreCaldera.Agents.privilege | String |  | 
| MitreCaldera.Agents.username | String |  | 
| MitreCaldera.Agents.trusted | Boolean |  | 
| MitreCaldera.Agents.proxy_chain | String |  | 
| MitreCaldera.Agents.paw | String |  | 
| MitreCaldera.Agents.exe_name | String |  | 

### caldera-update-fact-source
***
Update an existing Fact Source.


#### Base Command

`caldera-update-fact-source`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fact_source_id | The id of the Fact Source. | Required | 
| source_name | . | Optional | 
| source_adjustments | . | Optional | 
| source_relationships | . | Optional | 
| source_id | . | Optional | 
| source_rules | . | Optional | 
| source_facts | . | Optional | 
| source_plugin | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Sources.name | String |  | 
| MitreCaldera.Sources.adjustments.ability_id | String |  | 
| MitreCaldera.Sources.adjustments.offset | Number |  | 
| MitreCaldera.Sources.adjustments.trait | String |  | 
| MitreCaldera.Sources.adjustments.value | String |  | 
| MitreCaldera.Sources.relationships.unique | String |  | 
| MitreCaldera.Sources.relationships.origin | String |  | 
| MitreCaldera.Sources.relationships.edge | String |  | 
| MitreCaldera.Sources.relationships.score | Number |  | 
| MitreCaldera.Sources.id | String |  | 
| MitreCaldera.Sources.rules.trait | String |  | 
| MitreCaldera.Sources.rules.match | String |  | 
| MitreCaldera.Sources.facts.unique | String |  | 
| MitreCaldera.Sources.facts.name | String |  | 
| MitreCaldera.Sources.facts.created | String |  | 
| MitreCaldera.Sources.facts.limit_count | Number |  | 
| MitreCaldera.Sources.facts.technique_id | String |  | 
| MitreCaldera.Sources.facts.trait | String |  | 
| MitreCaldera.Sources.facts.source | String |  | 
| MitreCaldera.Sources.facts.score | Number |  | 
| MitreCaldera.Sources.plugin | String |  | 

### caldera-update-objective
***
Update an objective


#### Base Command

`caldera-update-objective`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objective_id | UUID of the Objective to be updated. | Required | 
| name | . | Optional | 
| goals | . | Optional | 
| description | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Objectives.name | String |  | 
| MitreCaldera.Objectives.id | String |  | 
| MitreCaldera.Objectives.percentage | Unknown |  | 
| MitreCaldera.Objectives.goals.count | Number |  | 
| MitreCaldera.Objectives.goals.achieved | Boolean |  | 
| MitreCaldera.Objectives.goals.operator | String |  | 
| MitreCaldera.Objectives.goals.value | String |  | 
| MitreCaldera.Objectives.goals.target | String |  | 
| MitreCaldera.Objectives.description | String |  | 

### caldera-update-operation-fields
***
Update fields within an operation


#### Base Command

`caldera-update-operation-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | UUID of the Operation object to be retrieved. | Required | 
| obfuscator | . | Optional | 
| autonomous | . | Optional | 
| state | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Operations.name | String |  | 
| MitreCaldera.Operations.autonomous | Number |  | 
| MitreCaldera.Operations.id | String |  | 
| MitreCaldera.Operations.visibility | Number |  | 
| MitreCaldera.Operations.state | String |  | 
| MitreCaldera.Operations.group | String |  | 
| MitreCaldera.Operations.host_group.watchdog | Number |  | 
| MitreCaldera.Operations.host_group.links.relationships.unique | String |  | 
| MitreCaldera.Operations.host_group.links.relationships.origin | String |  | 
| MitreCaldera.Operations.host_group.links.relationships.edge | String |  | 
| MitreCaldera.Operations.host_group.links.relationships.score | Number |  | 
| MitreCaldera.Operations.host_group.links.id | String |  | 
| MitreCaldera.Operations.host_group.links.collect | String |  | 
| MitreCaldera.Operations.host_group.links.pid | String |  | 
| MitreCaldera.Operations.host_group.links.finish | String |  | 
| MitreCaldera.Operations.host_group.links.pin | Number |  | 
| MitreCaldera.Operations.host_group.links.jitter | Number |  | 
| MitreCaldera.Operations.host_group.links.agent_reported_time | String |  | 
| MitreCaldera.Operations.host_group.links.deadman | Boolean |  | 
| MitreCaldera.Operations.host_group.links.used.unique | String |  | 
| MitreCaldera.Operations.host_group.links.used.name | String |  | 
| MitreCaldera.Operations.host_group.links.used.created | String |  | 
| MitreCaldera.Operations.host_group.links.used.limit_count | Number |  | 
| MitreCaldera.Operations.host_group.links.used.technique_id | String |  | 
| MitreCaldera.Operations.host_group.links.used.trait | String |  | 
| MitreCaldera.Operations.host_group.links.used.source | String |  | 
| MitreCaldera.Operations.host_group.links.used.score | Number |  | 
| MitreCaldera.Operations.host_group.links.host | String |  | 
| MitreCaldera.Operations.host_group.links.status | Number |  | 
| MitreCaldera.Operations.host_group.links.score | Number |  | 
| MitreCaldera.Operations.host_group.links.command | String |  | 
| MitreCaldera.Operations.host_group.links.unique | String |  | 
| MitreCaldera.Operations.host_group.links.cleanup | Number |  | 
| MitreCaldera.Operations.host_group.links.decide | String |  | 
| MitreCaldera.Operations.host_group.links.facts.unique | String |  | 
| MitreCaldera.Operations.host_group.links.facts.name | String |  | 
| MitreCaldera.Operations.host_group.links.facts.created | String |  | 
| MitreCaldera.Operations.host_group.links.facts.limit_count | Number |  | 
| MitreCaldera.Operations.host_group.links.facts.technique_id | String |  | 
| MitreCaldera.Operations.host_group.links.facts.trait | String |  | 
| MitreCaldera.Operations.host_group.links.facts.source | String |  | 
| MitreCaldera.Operations.host_group.links.facts.score | Number |  | 
| MitreCaldera.Operations.host_group.links.paw | String |  | 
| MitreCaldera.Operations.host_group.links.output | String |  | 
| MitreCaldera.Operations.host_group.deadman_enabled | Boolean |  | 
| MitreCaldera.Operations.host_group.ppid | Number |  | 
| MitreCaldera.Operations.host_group.pid | Number |  | 
| MitreCaldera.Operations.host_group.created | String |  | 
| MitreCaldera.Operations.host_group.origin_link_id | String |  | 
| MitreCaldera.Operations.host_group.last_seen | String |  | 
| MitreCaldera.Operations.host_group.platform | String |  | 
| MitreCaldera.Operations.host_group.pending_contact | String |  | 
| MitreCaldera.Operations.host_group.host | String |  | 
| MitreCaldera.Operations.host_group.group | String |  | 
| MitreCaldera.Operations.host_group.location | String |  | 
| MitreCaldera.Operations.host_group.display_name | String |  | 
| MitreCaldera.Operations.host_group.upstream_dest | String |  | 
| MitreCaldera.Operations.host_group.sleep_max | Number |  | 
| MitreCaldera.Operations.host_group.architecture | String |  | 
| MitreCaldera.Operations.host_group.sleep_min | Number |  | 
| MitreCaldera.Operations.host_group.server | String |  | 
| MitreCaldera.Operations.host_group.contact | String |  | 
| MitreCaldera.Operations.host_group.privilege | String |  | 
| MitreCaldera.Operations.host_group.username | String |  | 
| MitreCaldera.Operations.host_group.trusted | Boolean |  | 
| MitreCaldera.Operations.host_group.proxy_chain | String |  | 
| MitreCaldera.Operations.host_group.paw | String |  | 
| MitreCaldera.Operations.host_group.exe_name | String |  | 
| MitreCaldera.Operations.obfuscator | String |  | 
| MitreCaldera.Operations.use_learning_parsers | Boolean |  | 
| MitreCaldera.Operations.jitter | String |  | 
| MitreCaldera.Operations.start | String |  | 
| MitreCaldera.Operations.auto_close | Boolean |  | 

### caldera-update-main-config
***
Update Main Config


#### Base Command

`caldera-update-main-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| property | . | Required | 
| value | . | Required | 


#### Context Output

There is no context output for this command.
### caldera-update-facts
***
Update One or More Facts


#### Base Command

`caldera-update-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| unique | partial_factupdaterequest_updates unique. | Optional | 
| name | partial_factupdaterequest_updates name. | Optional | 
| links | partial_factupdaterequest_updates links. | Optional | 
| relationships | partial_factupdaterequest_updates relationships. | Optional | 
| origin_type | partial_factupdaterequest_updates origin_type. | Optional | 
| created | partial_factupdaterequest_updates created. | Optional | 
| limit_count | partial_factupdaterequest_updates limit_count. | Optional | 
| technique_id | partial_factupdaterequest_updates technique_id. | Optional | 
| trait | partial_factupdaterequest_updates trait. | Optional | 
| source | partial_factupdaterequest_updates source. | Optional | 
| score | partial_factupdaterequest_updates score. | Optional | 
| value | partial_factupdaterequest_updates value. | Optional | 
| collected_by | partial_factupdaterequest_updates collected_by. | Optional | 
| criteria_unique | partial_factupdaterequest_criteria unique. | Optional | 
| criteria_name | partial_factupdaterequest_criteria name. | Optional | 
| criteria_links | partial_factupdaterequest_criteria links. | Optional | 
| criteria_relationships | partial_factupdaterequest_criteria relationships. | Optional | 
| criteria_origin_type | partial_factupdaterequest_criteria origin_type. | Optional | 
| criteria_created | partial_factupdaterequest_criteria created. | Optional | 
| criteria_limit_count | partial_factupdaterequest_criteria limit_count. | Optional | 
| criteria_technique_id | partial_factupdaterequest_criteria technique_id. | Optional | 
| criteria_trait | partial_factupdaterequest_criteria trait. | Optional | 
| criteria_source | partial_factupdaterequest_criteria source. | Optional | 
| criteria_score | partial_factupdaterequest_criteria score. | Optional | 
| criteria_value | partial_factupdaterequest_criteria value. | Optional | 
| criteria_collected_by | partial_factupdaterequest_criteria collected_by. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Facts.unique | String |  | 
| MitreCaldera.Facts.name | String |  | 
| MitreCaldera.Facts.created | String |  | 
| MitreCaldera.Facts.limit_count | Number |  | 
| MitreCaldera.Facts.technique_id | String |  | 
| MitreCaldera.Facts.trait | String |  | 
| MitreCaldera.Facts.source | String |  | 
| MitreCaldera.Facts.score | Number |  | 

### caldera-update-relationships
***
Update One or More Relationships


#### Base Command

`caldera-update-relationships`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| unique | partial_relationshipupdate_updates unique. | Optional | 
| origin | partial_relationshipupdate_updates origin. | Optional | 
| edge | partial_relationshipupdate_updates edge. | Optional | 
| source | partial_relationshipupdate_updates source. | Optional | 
| score | partial_relationshipupdate_updates score. | Optional | 
| target | partial_relationshipupdate_updates target. | Optional | 
| criteria_unique | partial_relationshipupdate_criteria unique. | Optional | 
| criteria_origin | partial_relationshipupdate_criteria origin. | Optional | 
| criteria_edge | partial_relationshipupdate_criteria edge. | Optional | 
| criteria_source | partial_relationshipupdate_criteria source. | Optional | 
| criteria_score | partial_relationshipupdate_criteria score. | Optional | 
| criteria_target | partial_relationshipupdate_criteria target. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Relationships.unique | String |  | 
| MitreCaldera.Relationships.origin | String |  | 
| MitreCaldera.Relationships.edge | String |  | 
| MitreCaldera.Relationships.score | Number |  | 

### caldera-update-ability
***
Updates an existing ability.


#### Base Command

`caldera-update-ability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ability_id | UUID of the Ability to be retrieved. | Required | 
| name | . | Optional | 
| buckets | . | Optional | 
| technique_id | . | Optional | 
| delete_payload | . | Optional | 
| executors | . | Optional | 
| privilege | . | Optional | 
| technique_name | . | Optional | 
| tactic | . | Optional | 
| singleton | . | Optional | 
| plugin | . | Optional | 
| repeatable | . | Optional | 
| description | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Abilities.ability_id | String |  | 
| MitreCaldera.Abilities.name | String |  | 
| MitreCaldera.Abilities.technique_id | String |  | 
| MitreCaldera.Abilities.delete_payload | Boolean |  | 
| MitreCaldera.Abilities.executors.name | String |  | 
| MitreCaldera.Abilities.executors.platform | String |  | 
| MitreCaldera.Abilities.executors.language | String |  | 
| MitreCaldera.Abilities.executors.variations.command | String |  | 
| MitreCaldera.Abilities.executors.variations.description | String |  | 
| MitreCaldera.Abilities.executors.build_target | String |  | 
| MitreCaldera.Abilities.executors.timeout | Number |  | 
| MitreCaldera.Abilities.executors.parsers.module | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.edge | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.source | String |  | 
| MitreCaldera.Abilities.executors.parsers.parserconfigs.target | String |  | 
| MitreCaldera.Abilities.executors.command | String |  | 
| MitreCaldera.Abilities.executors.code | String |  | 
| MitreCaldera.Abilities.privilege | String |  | 
| MitreCaldera.Abilities.requirements.module | String |  | 
| MitreCaldera.Abilities.plugin | String |  | 
| MitreCaldera.Abilities.tactic | String |  | 
| MitreCaldera.Abilities.singleton | Boolean |  | 
| MitreCaldera.Abilities.technique_name | String |  | 
| MitreCaldera.Abilities.repeatable | Boolean |  | 
| MitreCaldera.Abilities.description | String |  | 

### caldera-update-schedule
***
Update Schedule


#### Base Command

`caldera-update-schedule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_id | UUID of the Schedule to be updated. | Required | 
| schedule | . | Optional | 
| task_obfuscator | task obfuscator. | Optional | 
| task_autonomous | task autonomous. | Optional | 
| task_state | task state. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Schedules.schedule | String |  | 
| MitreCaldera.Schedules.id | String |  | 

### caldera-update-operation-link
***
Update the specified link within an operation


#### Base Command

`caldera-update-operation-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | String UUID of the Operation containing desired link. | Required | 
| link_id | String UUID of the Link with the above operation. | Required | 
| command | . | Optional | 
| status | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MitreCaldera.Links.relationships.unique | String |  | 
| MitreCaldera.Links.relationships.origin | String |  | 
| MitreCaldera.Links.relationships.edge | String |  | 
| MitreCaldera.Links.relationships.score | Number |  | 
| MitreCaldera.Links.id | String |  | 
| MitreCaldera.Links.collect | String |  | 
| MitreCaldera.Links.pid | String |  | 
| MitreCaldera.Links.finish | String |  | 
| MitreCaldera.Links.pin | Number |  | 
| MitreCaldera.Links.jitter | Number |  | 
| MitreCaldera.Links.agent_reported_time | String |  | 
| MitreCaldera.Links.deadman | Boolean |  | 
| MitreCaldera.Links.used.unique | String |  | 
| MitreCaldera.Links.used.name | String |  | 
| MitreCaldera.Links.used.created | String |  | 
| MitreCaldera.Links.used.limit_count | Number |  | 
| MitreCaldera.Links.used.technique_id | String |  | 
| MitreCaldera.Links.used.trait | String |  | 
| MitreCaldera.Links.used.source | String |  | 
| MitreCaldera.Links.used.score | Number |  | 
| MitreCaldera.Links.host | String |  | 
| MitreCaldera.Links.status | Number |  | 
| MitreCaldera.Links.score | Number |  | 
| MitreCaldera.Links.command | String |  | 
| MitreCaldera.Links.unique | String |  | 
| MitreCaldera.Links.cleanup | Number |  | 
| MitreCaldera.Links.decide | String |  | 
| MitreCaldera.Links.facts.unique | String |  | 
| MitreCaldera.Links.facts.name | String |  | 
| MitreCaldera.Links.facts.created | String |  | 
| MitreCaldera.Links.facts.limit_count | Number |  | 
| MitreCaldera.Links.facts.technique_id | String |  | 
| MitreCaldera.Links.facts.trait | String |  | 
| MitreCaldera.Links.facts.source | String |  | 
| MitreCaldera.Links.facts.score | Number |  | 
| MitreCaldera.Links.paw | String |  | 
| MitreCaldera.Links.output | String |  | 
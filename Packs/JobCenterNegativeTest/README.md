This pack contains intentionally invalid Job Center jobs for negative testing of the demisto-sdk Job Center validations.

**Do not merge this pack.** Every file in it is broken on purpose.

## What does this pack do?

This pack is intended for Cortex Agentic AI.

Each file starts from a valid interval job and breaks exactly one rule. The file name starts with the validation code that should reject it.

## Files

### Structure (ST110)

| File | Broken rule | Expected error |
| --- | --- | --- |
| ST110_UnknownJobType.yml | `jobType: agent_to_case` | ST110 |
| ST110_MissingJobType.yml | No `jobType` | ST110 |
| ST110_MissingJobName.yml | No `jobName` | ST110 |
| ST110_JobNameTooLong.yml | `jobName` is 129 characters | ST110 |
| ST110_JobNameLeadingSpace.yml | `jobName` starts with a space | ST110 |
| ST110_JobNameIllegalChar.yml | `jobName: Case@Followup` | ST110 |
| ST110_JobNameNumber.yml | `jobName: 123` (a number, not a string) | ST110 |
| ST110_MissingMetadata.yml | No `metadata` | ST110 |
| ST110_MetadataNotMapping.yml | `metadata` is a list | ST110 |
| ST110_MissingAgentId.yml | No `metadata.agent_id` | ST110 |
| ST110_EmptyPromptId.yml | `metadata.prompt_id: ""` | ST110 |
| ST110_EntityTypeWithoutEntityId.yml | `entityType` without `entityId` | ST110 |
| ST110_EntityIdWithoutEntityType.yml | `entityId` without `entityType` | ST110 |
| ST110_InvalidEntityType.yml | `entityType: incident` | ST110 |
| ST110_EntityIdNumber.yml | `entityId: 1234` (a number, not a string) | ST110 |
| ST110_InvalidStatus.yml | `status: RUNNING` | ST110 |
| ST110_MissingTriggerType.yml | No `triggerType` | ST110 |
| ST110_InvalidTriggerType.yml | `triggerType: cron` | ST110 |
| ST110_IntervalWithoutTriggerSpec.yml | Interval job without `triggerSpec` | ST110 |
| ST110_IntervalMinutesTooLow.yml | `intervalMinutes: 5` | ST110 |
| ST110_IntervalMinutesTooHigh.yml | `intervalMinutes: 121` | ST110 |
| ST110_IntervalMinutesString.yml | `intervalMinutes: "30"` | ST110 |
| ST110_CountZero.yml | `count: 0` | ST110 |
| ST110_CountTooHigh.yml | `count: 13` | ST110 |
| ST110_IntervalWithoutQueuePolicy.yml | Interval job without `queuePolicy` | ST110 |
| ST110_InvalidQueuePolicy.yml | `queuePolicy: drop` | ST110 |
| ST110_OnetimeTriggerSpecNotMapping.yml | One-time job with `triggerSpec: soon` | ST110 |
| ST110_UniquenessKeyEmpty.yml | `uniquenessKey: ""` | ST110 |
| ST110_UniquenessKeyTooLong.yml | `uniquenessKey` is 257 characters | ST110 |
| ST110_MissingName.yml | No `name` | ST110 (reported as BA102, see note 1) |
| ST110_MissingId.yml | No `commonfields.id` | ST110 (reported as BA102, see note 1) |
| ST110_SystemNotBool.yml | `system: maybe` | ST110 (reported as BA102, see note 1) |
| ST110_SystemStringTrue.yml | `system: "true"` (a string, not a boolean) | ST110 (not reported, see note 2) |

### Basic (BA)

| File | Broken rule | Expected error |
| --- | --- | --- |
| BA100_VersionNotMinusOne.yml | `commonfields.version: 3` | BA100 |
| BA105_IdWithSlash.yml | `id: job/case-followup` | BA105 |
| BA106_FromVersionTooLow.yml | `fromversion: 8.9.0` | BA106 |
| BA113_NameTrailingSpace.yml | `name: "Case Followup "` | BA113 |
| BA118_ToVersionLowerThanFromVersion.yml | `toversion: 8.9.0` is lower than `fromversion: 8.10.0` | BA118 |
| BA131_InvalidSupportedModule.yml | `supportedModules: [not_a_module]` | BA131 |

### Graph (requires graph)

These two files need the content graph (neo4j) to be checked.

| File | Broken rule | Expected error |
| --- | --- | --- |
| GR105_DuplicateIdA.yml | Uses the same ID as GR105_DuplicateIdB.yml (`job-duplicate`) | GR105 |
| GR105_DuplicateIdB.yml | Uses the same ID as GR105_DuplicateIdA.yml (`job-duplicate`) | GR105 |

### Content path

`validate-content-path` (pre-commit) rejects these files. The `validate` command does not.

| File | Broken rule | Expected error |
| --- | --- | --- |
| Nested/NestedJob.yml | Job in a subfolder under `JobCenters` | validate-content-path: JobCenter files must be placed directly under JobCenters |
| WrongSuffix.yaml | `.yaml` suffix instead of `.yml` | validate-content-path: This file's suffix is not allowed |

## Notes

1. The SDK rejects these files when it loads them, before ST110 runs. The error is BA102 ("The given file is not supported in the validate command") together with a pydantic error that names the field.
2. The SDK accepts `system: "true"` because it converts the string to a boolean. The same happens with `system: 1` and `locked: "yes"`.
3. Because of note 1, running `validate` on the whole pack stops with a pydantic error. Validate one file at a time.

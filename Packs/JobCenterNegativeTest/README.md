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
| ST110_MissingMetadata.yml | No `metadata` | ST110 |
| ST110_MetadataNotMapping.yml | `metadata` is a list | ST110 |
| ST110_MissingAgentId.yml | No `metadata.agent_id` | ST110 |
| ST110_EmptyPromptId.yml | `metadata.prompt_id: ""` | ST110 |
| ST110_EntityTypeWithoutEntityId.yml | `entityType` without `entityId` | ST110 |
| ST110_EntityIdWithoutEntityType.yml | `entityId` without `entityType` | ST110 |
| ST110_InvalidEntityType.yml | `entityType: incident` | ST110 |
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

## Removed cases

These files were removed because they are not useful negative tests for Job Center:

| File | Reason |
| --- | --- |
| ST110_MissingName.yml | A missing `name` crashes `demisto-sdk validate -g` for every content type. This is generic SDK behavior, not specific to Job Center. |
| ST110_MissingId.yml | A missing `commonfields.id` crashes `demisto-sdk validate -g` for every content type. |
| ST110_SystemNotBool.yml | A boolean that cannot be converted crashes `demisto-sdk validate -g` for every content type. |
| ST110_SystemStringTrue.yml | Every content type converts `system: "true"` to `true`, so the file passes. |
| Nested/NestedJob.yml | Fails the pre-commit `validate-content-paths` hook by design. Already proven in CI. |
| WrongSuffix.yaml | Fails the pre-commit `validate-content-paths` hook by design. Already proven in CI. |
| ST110_JobNameNumber.yml | Job Center now converts numbers in text fields to strings, like other content types, so `jobName: 123` passes. |
| ST110_EntityIdNumber.yml | Job Center now converts numbers in text fields to strings, so `entityId: 1234` passes. |

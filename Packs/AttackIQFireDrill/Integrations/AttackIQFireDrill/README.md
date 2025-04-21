Use the AttackIQ integration to simulate a platform that provides validations for security controls, responses, and remediation exercises.

This integration was integrated and tested with AttackIQ FireDrill v2.15.96.

## Use Cases

*   Retrieves a list of testing scenarios.
*   Executes testing of penetration assessments.
*   Retrieves detailed assessment results.
*   Triggers other playbook-based assessment results.

## Configure AttackIQ Platform in Cortex


| **Parameter** | **Description** | **Example** |
| ---------             | -----------           | -------            |
| Name | A meaningful name for the integration instance. | AttackIQFireDrill_instance_2 |
| Server URL | The URL to the Proofpoint server, including the scheme.  |  https:/<span></span>/example.net |
|  API Token | Account's private token (as appears in attackIQ UI). | N/A  |
| Trust any certificate (not secure) | When selected, certificates are not checked. | N/A |
| Use System Proxy Settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. |  https:/<span></span>/proxyserver.com |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get assessment information by ID

* * *

Returns all assessment information by ID.

##### Base Command

`attackiq-get-assessment-by-id`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | The ID of the assessment to return. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AttackIQ.Assessment.Id | String | The ID of the assessment. |
| AttackIQ.Assessment.Name | String | The name of the assessment. |
| AttackIQ.Assessment.Description | String | The description of the assessment. |
| AttackIQ.Assessment.StartDate | Date | The start date of the assessment. |
| AttackIQ.Assessment.EndDate | Date | The end date of the assessment. |
| AttackIQ.Assessment.AssessmentState | String | The state of the assessment. Can be, "Active" or "Inactive". |
| AttackIQ.Assessment.DefaultSchedule | String | The default schedule timing (cron) of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateId | String | The template ID of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateName | String | The template name of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateDescription | String | The template description of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateDefaultSchedule | Unknown | The assessment's template default schedule timing (cron). |
| AttackIQ.Assessment.AssessmentTemplateCompany | String | The owner of the template. |
| AttackIQ.Assessment.AssessmentTemplateCreated | Date | The date that the template was created. |
| AttackIQ.Assessment.AssessmentTemplateModified | Date | The date the template was last modified. |
| AttackIQ.Assessment.Creator | String | The user who created the assessment. |
| AttackIQ.Assessment.Owner | String | The user who owns the assessment. |
| AttackIQ.Assessment.User | String | The user who ran the assessment. |
| AttackIQ.Assessment.Created | String | The time that the assessment was created. |
| AttackIQ.Assessment.Modified | String | The time that the assessment was last modified. |
| AttackIQ.Assessment.Users | String | The user IDs that can access the assessment. |
| AttackIQ.Assessment.Groups | String | The user groups who can access the assessment. |
| AttackIQ.Assessment.DefaultAssetCount | Number | The number of machines (assets) that are connected to the assessment. |
| AttackIQ.Assessment.DefaultAssetGroupCount | Number | The number of asset groups that are connected to the assessment. |
| AttackIQ.Assessment.MasterJobCount | Number | The number of tests that ran in the assessment. |
| AttackIQ.Assessment.Count | Number | The total number of assessments. |
| AttackIQ.Assessment.RemainingPages | Number | The number of remaining pages to return. For example, if the total number of pages is 6, and the last fetch was page 5, the value is 1. |

##### Command Example
```
!attackiq-get-assessment-by-id assessment_id=c4e352ae-1506-4c74-bd90-853f02dd765a
```

##### Context Example
```
{
    "AttackIQ.Assessment": {
        "AssessmentState": "Active",
        "AssessmentTemplateCompany": "906d5ec6-101c-4ae6-8906-b93ce0529060",
        "AssessmentTemplateCreated": "2016-07-01T20:26:43.494459Z",
        "AssessmentTemplateDefaultSchedule": null,
        "AssessmentTemplateDescription": "Variety of common ransomware variants",
        "AssessmentTemplateId": "59d35f4a-2da0-4c4a-a08a-c30cb41dae6b",
        "AssessmentTemplateModified": "2019-02-19T03:31:54.393885Z",
        "AssessmentTemplateName": "Ransomware Project",
        "Created": "2019-08-27T10:17:09.809036Z",
        "Creator": "foo@test.com",
        "DefaultAssetCount": 1,
        "DefaultAssetGroupCount": 0,
        "DefaultSchedule": "41;8;*;*;1",
        "Description": "Test of common ransomware variants",
        "EndDate": null,
        "Groups": [],
        "Id": "c4e352ae-1506-4c74-bd90-853f02dd765a",
        "MasterJobCount": 3,
        "Modified": "2019-09-18T08:16:23.079961Z",
        "Name": "Arseny's ransomware project",
        "Owner": "foo@test.com",
        "StartDate": null,
        "User": "foo@test.com",
        "Users": [
            "71e92cf9-5159-466c-8050-142d1ba279ea"
        ]
    }
}
```

##### Human Readable Output

##### AttackIQ Assessment c4e352ae-1506-4c74-bd90-853f02dd765a

| **Id** | **Name** | **Description** | **User** | **Created** | **Modified** |
| --- | --- | --- | --- | --- | --- |
| c4e352ae-1506-4c74-bd90-853f02dd765a | Arseny's ransomware project | Test of common ransomware variants | foo<span></span>@test.com | 2019-08-27T10:17:09.809036Z | 2019-09-18T08:16:23.079961Z |

### Get all assessments details by page

* * *

Returns all assessment details by page.

##### Base Command

`attackiq-list-assessments`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_number | The page number to return. | Optional |
| page_size | The number of results to return per page. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AttackIQ.Assessment.Id | String | The ID of the assessment. |
| AttackIQ.Assessment.Name | String | The name of the assessment. |
| AttackIQ.Assessment.Description | String | The description of the assessment. |
| AttackIQ.Assessment.StartDate | Date | The start date of the assessment. |
| AttackIQ.Assessment.EndDate | Date | The end date of the assessment. |
| AttackIQ.Assessment.AssessmentState | String | The state of the assessment. Can be, "Active" or "Inactive". |
| AttackIQ.Assessment.DefaultSchedule | String | The default schedule timing (cron) of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateId | String | The template ID of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateName | String | The template name of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateDescription | String | The template description of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateDefaultSchedule | Unknown | The default schedule timing (cron) of the template assessment. |
| AttackIQ.Assessment.AssessmentTemplateCompany | String | The owner of the template. |
| AttackIQ.Assessment.AssessmentTemplateCreated | Date | The date that the template was created. |
| AttackIQ.Assessment.AssessmentTemplateModified | Date | The date the template was last modified. |
| AttackIQ.Assessment.Creator | String | The user who created the assessment. |
| AttackIQ.Assessment.Owner | String | The user who owned the assessment. |
| AttackIQ.Assessment.User | String | The user that ran the assessment. |
| AttackIQ.Assessment.Created | String | The time that the assessment was created. |
| AttackIQ.Assessment.Modified | String | The time that the assessment was last modified. |
| AttackIQ.Assessment.Users | String | The User IDs that can access the assessment. |
| AttackIQ.Assessment.Groups | String | The user groups who can access the assessment. |
| AttackIQ.Assessment.DefaultAssetCount | Number | The number of machines (assets) that are connected to the assessment. |
| AttackIQ.Assessment.DefaultAssetGroupCount | Number | The number of asset groups that are connected to the assessment. |
| AttackIQ.Assessment.MasterJobCount | Number | The number of tests that ran in the assessment. |

##### Command Example
```
!attackiq-list-assessments page_size=5
```

##### Context Example
```
{
    "AttackIQ.Assessment": 11
}
```

##### Human Readable Output

##### AttackIQ Assessments Page 1/12

| **Id** | **Name** | **Description** | **User** | **Created** | **Modified** |
| --- | --- | --- | --- | --- | --- |
| c4e352ae-1506-4c74-bd90-853f02dd765a | Arseny's ransomware project | Test of common ransomware variants | foo<span></span>@test.com | 2019-08-27T10:17:09.809036Z | 2019-09-18T08:16:23.079961Z |
| f57edb34-ccb2-4695-b79c-bb739cab70a1 | Arseny's ransomware project | Test of common ransomware variants | foo<span></span>@test.com | 2019-09-02T11:52:09.915614Z | 2019-09-16T09:02:59.401994Z |
| 8978fe24-607a-4815-a36a-89fb6191b318 | ATT&CK by the Numbers @ NOVA BSides 2019 | AttackIQ’s analysis and mapping of the “ATT&CK by the Numbers” @ NOVA BSides 2019 | foo<span></span>@test.com | 2019-09-05T08:47:38.243320Z | 2019-09-10T11:16:25.619197Z |
| 5baca9b4-e55c-497f-a05a-8004b9a36efe | Custom | Custom project | goo<span></span>@test.com | 2019-09-10T08:38:55.165853Z | 2019-09-10T08:38:55.165874Z |
| 58440d47-d7b5-4f57-913f-3e13903fa2fc | Arseny's ransomware project | Test of common ransomware variants | foo<span></span>@test.com | 2019-09-02T11:52:13.933084Z | 2019-09-02T11:52:16.100942Z |

### Activate an assessment 

* * *

Deprecated, without available replacement. Activates the assessment, which is required for execution.

##### Base Command

`attackiq-activate-assessment`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | ID of the assessment to activate. | Required |

##### Command Example
```
!attackiq-activate-assessment assessment_id=c4e352ae-1506-4c74-bd90-853f02dd765a
```
##### Human Readable Output

Successfully activated project c4e352ae-1506-4c74-bd90-853f02dd765a

### Run tests in the assessment

* * *

Runs all tests in the assessment.

##### Base Command

`attackiq-run-all-tests-in-assessment`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | The ID of the assessment. | Required |
| on_demand_only | Runs only on-demand tests in the assessment. True executes tests in the assessment that are not scheduled to run. False executes all tests in the assessment including scheduled tests. The default is false. | Optional |

##### Command Example
```
!attackiq-run-all-tests-in-assessment assessment_id=8978fe24-607a-4815-a36a-89fb6191b318
```

##### Human Readable Output

Successfully started running all tests in project: ATT&CK by the Numbers @ NOVA BSides 2019

### Get an assessment execution status

* * *

Returns an assessment execution status when running an on-demand execution only.

##### Base Command

`attackiq-get-assessment-execution-status`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | The assessment to check status. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AttackIQ.Assessment.Running | Boolean | Whether the assessment is running. |
| AttackIQ.Assessment.Id | String | The ID of the assessment. |

##### Command Example
```
!attackiq-get-assessment-execution-status assessment_id=c4e352ae-1506-4c74-bd90-853f02dd765a
```

##### Context Example
```
{
    "AttackIQ.Assessment": {
        "Id": "c4e352ae-1506-4c74-bd90-853f02dd765a",
        "Running": false
    }
}
```

##### Human Readable Output

Assessment c4e352ae-1506-4c74-bd90-853f02dd765a execution is not running.

### Get a test execution status

* * *

Returns the status of the test.

##### Base Command

`attackiq-get-test-execution-status`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| test_id | The ID of the Test. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AttackIQTest.Detected | Number | The number of detections in the test. |
| AttackIQTest.Failed | Number | The number of failures in the test. |
| AttackIQTest.Finished | Boolean | Whether the test is finished. |
| AttackIQTest.Passed | Number | The number of passed tests. |
| AttackIQTest.Errored | Number | The number of tests that returned errors. |
| AttackIQTest.Total | Number | The total number of tests that ran. |
| AttackIQTest.Id | String | The ID of the assessment test. |

##### Command Example
```
!attackiq-get-test-execution-status test_id=9aed2cef-8c64-4e29-83b4-709de5963b66
```

##### Context Example
```
{
    "AttackIQTest": {
        "Detected": 0,
        "Errored": 0,
        "Failed": 9,
        "Finished": true,
        "Id": "9aed2cef-8c64-4e29-83b4-709de5963b66",
        "Passed": 1,
        "Total": 10
    }
}
```

##### Human Readable Output

##### Test 9aed2cef-8c64-4e29-83b4-709de5963b66 status

| **Detected** | **Errored** | **Failed** | **Finished** | **Id** | **Passed** | **Total** |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | 0 | 9 | true | 9aed2cef-8c64-4e29-83b4-709de5963b66 | 1 | 10 |

### Get a list of tests by assessment

* * *

Returns a list of tests by an assessment.

##### Base Command

`attackiq-list-tests-by-assessment`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | The ID of the assessment that contains the tests. | Required |
| page_size | The Maximum page size for the results. | Optional |
| page_number | The page number to return. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AttackIQTest.Id | String | The ID of the test. |
| AttackIQTest.Name | String | The name of the test. |
| AttackIQTest.Description | String | The description of the test. |
| AttackIQTest.Scenarios.Id | String | The ID of the test scenario. |
| AttackIQTest.Scenarios.Name | String | The name of the test scenario. |
| AttackIQTest.Assets.Id | String | The ID of the test asset. |
| AttackIQTest.Assets.Ipv4Address | String | The IP version 4 address of the test asset. |
| AttackIQTest.Assets.Hostname | String | The host name of the test asset. |
| AttackIQTest.Assets.ProductName | String | The product name of the test asset. |
| AttackIQTest.Assets.Modified | String | The last modified date of the test asset. |
| AttackIQTest.Assets.Status | Date | The status of the test asset. Can be, "Active" or "Inactive". |
| AttackIQTest.TotalAssetCount | Number | The number of assets in which the test ran. |
| AttackIQTest.CronExpression | String | The Cron expression of the test. |
| AttackIQTest.Runnable | Boolean | Whether the test can run. |
| AttackIQTest.LastResult | String | The last result of the test. |
| AttackIQTest.User | String | The name of the user that ran the test in the assessment. |
| AttackIQTest.Created | Date | The date that the test was created. |
| AttackIQTest.Modified | Date | The date that the test was last modified. |
| AttackIQTest.LatestInstanceId | Number | The ID of the most recent run of the test. |
| AttackIQTest.UsingDefaultAssets | Boolean | Whether the test uses default assets. |
| AttackIQTest.UsingDefaultSchedule | Boolean | Whether the test uses the default schedule. |
| AttackIQTest.RemainingPages | Number | The number of remaining pages to return. For example, if the total number of pages is 6, and the last fetch was page 5, the value is 1. |
| AttackIQTest.Count | Number | The total number of tests. |

##### Command Example
```
!attackiq-list-tests-by-assessment assessment_id=c4e352ae-1506-4c74-bd90-853f02dd765a page_size=3 page_number=1
```

##### Context Example
```
{
    "AttackIQTest": 0
}
```

##### Human Readable Output

##### Assessment c4e352ae-1506-4c74-bd90-853f02dd765a tests

##### Page 1 / 1

##### Test - Ransomware Download

| **Id** | **Name** | **Created** | **Modified** | **Runnable** | **Last Result** |
| --- | --- | --- | --- | --- | --- |
| 1c350a5a-84f2-4938-93d8-cc31f0a99482 | Ransomware Download | 2019-08-27T10:17:10.132074Z | 2019-09-02T07:08:25.237823Z | true | Failed |

##### Assets (Ransomware Download)

| **Hostname** | **Id** | **Ipv4Address** | **Modified** | **ProductName** | **Status** |
| --- | --- | --- | --- | --- | --- |
| ec2amaz-g4iu5no | 03e17460-849e-4b86-b6c6-ef0db72823ff | 172.31.39.254 | 2019-09-18T08:12:16.957300Z | Windows Server 2016 Datacenter | Active |

##### Scenarios (Ransomware Download)

| **Id** | **Name** |
| --- | --- |
| 7f188dbb-4d75-4c75-97bc-ff2d03fc0a1f | Download WannaCry Ransomware Sample |
| 35097add-888e-4916-ad25-38afef5d3b73 | Download 7ev3n Ransomware |
| c12c0cea-96e8-40b2-80af-fb897cffbe6a | Download Alpha Ransomware |
| 8b4eac5c-0475-475a-8521-dc30670d4212 | Download BlackShades Crypter Ransomware |
| 25b85e85-5255-49d3-8805-8ded910f1a63 | Download AutoLocky Ransomware |
| ce58ac59-f08a-4b72-918c-25fdfd0f7e4b | Download Bandarchor Ransomware |
| 66b167f6-acf7-491a-bfd6-ddd513d7290d | Download Bucbi Ransomware |
| b2eb8dec-1db0-46fe-b7af-bf87285d0d30 | Download BadBlock Ransomeware |
| fd81172c-f7f3-4811-a4e8-ebdf10044c85 | Download Chimera Ransomware |
| 193f6df4-aff7-44cd-8553-ed32dab8aac2 | Download CoinVault Ransomware |
| c75275eb-cf51-47d1-a031-c48e0ce8a3a1 | Download Cerber Ransomware |
| 595e522e-3ef2-4d6c-bfb0-f1e4841455aa | Download Crypren Ransomware |
| 8c89ab68-12d2-4cd8-8469-97d1a5586400 | Download Cryptolocker Ransomware |
| 0d78245f-fb7e-4a1b-a4ee-c3f06d62ec2c | Download CryptoDefense Ransomware |
| 59e127c1-4d33-4564-8df1-a4acd4c6d564 | Download CryptoWall Ransomware |
| ec3d4c58-937d-43be-9283-41ba43380f98 | Download Cryptear Ransomware |
| 3f22d898-2fa2-4824-992a-207f71fe61ce | Download CTBLocker Ransomware |
| b1c12d92-7754-45b1-bc85-e52960ba3a6c | Download CryptXXX Ransomware |
| d70c6af1-aef4-4748-8bb6-3c1414d4488c | Download DMALocker Ransomware |
| fd202846-f523-41d8-9e56-d388e50e1bcb | Download Fakben Ransomware |
| e2e94c6a-8749-4630-b2a5-a068a1cdf432 | Download GhostCrypt Ransomware |
| 3aa03297-3732-432d-b79b-7180275712d3 | Download Jigsaw Ransomware |
| 65ef68fa-d62e-4dd1-8892-1b56beb6bd1e | Download HydraCrypt Ransomware |
| 00c3d6eb-d9c3-4109-b373-8f934a84162d | Download Harasom Ransomware |
| c17581f3-6a85-4a98-8803-2a6479117769 | Download Zcrypt Ransomware |
| 264bc140-52db-4f20-a0a2-e50cd37f459a | Download Zyklon Ransomware |
| 1febae73-86d0-4e2d-9494-051f6629ed7e | Download VaultCrypt Ransomware |
| ce98ba43-4293-401e-a203-c4d04e31dacb | Download Xorist Ransomware |
| 0805f45c-ecb6-4cc2-a531-7a61e5452b2c | Download TeslaCrypt Ransomware |
| a25e0c4e-a117-48f5-b05e-39a38144c372 | Download TrueCrypt Ransomware |
| f116c1fb-9373-4b54-9c7d-3a7e50edbf70 | Download SynoLocker Ransomware |
| f1590467-b28f-4b9a-84ee-676bfbee2add | Download Sanction Ransomware |
| fc057ae4-c56d-4e9a-8c0f-9f22ec1e5576 | Download SNSLock Ransomware |
| b7425756-ab9a-4c7e-8fda-d1080c170910 | Download Rector Ransomware |
| 00a2bbf3-7faa-4a44-b125-580ebe007931 | Download Rokku Ransomware |
| 0f8097da-345d-4516-9730-8efa68b427e2 | Download Rakhni Ransomware |
| 11270129-4b0a-47f7-a019-45b45568befe | Download Powerware Ransomware |
| 43dc33fe-f7c2-4741-845c-6ce3f6d703a8 | Download Radamant Ransomware |
| 98cc1e97-9240-4bd5-8448-7d9e71b27249 | Download Petya Ransomware |
| dc07c76e-b891-43d3-9244-6992524a57f9 | Download Nemucod Ransomware |
| 366a6950-0a08-4295-a7ca-890e47f2cc9b | Download Mobef Ransomware |
| 16f39816-d245-46fd-ab5d-bd9b18c1d47d | Download Maktub Ransomware |
| 207144d0-aa40-48c4-99e6-5b246840e7e7 | Download Linux Encoder Ransomware |
| 68d41700-100e-4145-9e34-d38cfa4d75c5 | Download KeRanger Ransomware |
| 8daab70f-0b85-4f24-87a2-40d88effad87 | Download Locky Ransomware |
| 0d5e4988-cffc-4c83-b3e5-3775d0735e3d | Download Kimcilware Ransomware |
| b434bb61-67d7-4556-8ff9-99a88b52b566 | Download Lechiffre Ransomware |
| afb2d3db-7107-40d0-bf28-067c84e144e6 | Download Mischa Ransomware |
| c567a416-f320-4b9a-8268-50ad6aa0818d | Download ODCODC Ransomware |
| 5b075299-0368-48f9-a380-b46974b574ca | Download Ransom32 Ransomware |
| ef72cfc8-796c-4a35-abea-547f0d898713 | Download Coverton Ransomware |

##### Test - Locky

| **Id** | **Name** | **Created** | **Modified** | **Runnable** | **Last Result** |
| --- | --- | --- | --- | --- | --- |
| 529eebb2-a53c-4f82-9a0e-fc59763cb542 | Locky | 2019-08-27T10:17:09.968467Z | 2019-09-02T07:08:20.393468Z | true | Failed |

##### Assets (Locky)

| **Hostname** | **Id** | **Ipv4Address** | **Modified** | **ProductName** | **Status** |
| --- | --- | --- | --- | --- | --- |
| ec2amaz-g4iu5no | 03e17460-849e-4b86-b6c6-ef0db72823ff | 172.31.39.254 | 2019-09-18T08:12:16.957300Z | Windows Server 2016 Datacenter | Active |

##### Scenarios (Locky)

| **Id** | **Name** |
| --- | --- |
| 7701f8fb-a725-4a6d-b48d-1881868e24ea | Locky File Encryption |
| 874d2a63-0cc2-4700-b8b5-6fd31d151c7b | Locky Ransomware Persistence |
| 150473e3-995b-4c10-81e8-29037f877bf1 | Locky Ransomware DGA |

##### Test - Cryptolocker

| **Id** | **Name** | **Created** | **Modified** | **Runnable** | **Last Result** |
| --- | --- | --- | --- | --- | --- |
| 10413458-7bae-4d47-94e9-06197c60d156 | Cryptolocker | 2019-08-27T10:17:09.842767Z | 2019-09-02T07:08:17.069927Z | true | Failed |

##### Assets (Cryptolocker)

| **Hostname** | **Id** | **Ipv4Address** | **Modified** | **ProductName** | **Status** |
| --- | --- | --- | --- | --- | --- |
| ec2amaz-g4iu5no | 03e17460-849e-4b86-b6c6-ef0db72823ff | 172.31.39.254 | 2019-09-18T08:12:16.957300Z | Windows Server 2016 Datacenter | Active |

##### Scenarios (Cryptolocker)

| **Id** | **Name** |
| --- | --- |
| 0f45019b-817e-43f2-82c6-accb28c22b7b | Cryptolocker DGA |
| 411eb1a9-8e00-4d77-b8a1-8f204987a2d2 | CryptoLocker Persistence |

### Get the test results of an assessment

* * *

Returns the test results of an assessment.

##### Base Command

`attackiq-get-test-results`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| test_id | The ID of the test in which to show results. | Required |
| show_last_result | Shows the last result. True shows the last result. | Optional |
| page_number | The page number of the test results. | Optional |
| page_size | The maximum page size of the results. | Optional |
| outcome_filter | Filters results according to user choice. Selecting "Passed" will return only tests that passed. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AttackIQTestResult.Id | String | The ID of the test result. |
| AttackIQTestResult.Modified | Date | The date the test result was last modified. |
| AttackIQTestResult.Assessment.Id | String | The ID of the test assessment. |
| AttackIQTestResult.Assessment.Name | String | The name of the test assessment. |
| AttackIQTestResult.LastResult | String | The result of the test's last run. |
| AttackIQTestResult.Scenario.Id | String | The scenario ID of the test results. |
| AttackIQTestResult.Scenario.Name | String | The scenario name of the test results. |
| AttackIQTestResult.Scenario.Description | String | The scenario description of the test results. |
| AttackIQTestResult.Asset.Id | String | The ID of the test results asset. |
| AttackIQTestResult.Asset.Ipv4Address | String | The IP address of the test results scenario asset. |
| AttackIQTestResult.Asset.Hostname | String | The host name of the test results asset. |
| AttackIQTestResult.Asset.ProductName | String | The product name of the test results asset. |
| AttackIQTestResult.Asset.Modified | Date | The date that the asset was last modified. |
| AttackIQTestResult.AssetGroup | String | The asset group of the test. |
| AttackIQTestResult.JobState | String | The state of the job. |
| AttackIQTestResult.Outcome | String | The result outcome of the test. |
| AttackIQTestResult.RemainingPages | Number | The number of remaining pages to return. For example, if the total number pages is 6, and the last fetch was page 5, the value is 1. |
| AttackIQTestResult.Count | Number | The total number of tests. |

##### Command Example
```
!attackiq-get-test-results test_id=1c350a5a-84f2-4938-93d8-cc31f0a99482 page_number=10 page_size=5 outcome_filter=Passed
```

##### Context Example
```
{
    "AttackIQTestResult": 62
}
```

##### Human Readable Output

##### Test Results for 1c350a5a-84f2-4938-93d8-cc31f0a99482

##### Page 10/72

| **Assessment Name** | **Scenario Name** | **Hostname** | **Asset IP** | **Job State** | **Modified** | **Outcome** |
| --- | --- | --- | --- | --- | --- | --- |
| Arseny's ransomware project | Download Mischa Ransomware | ec2amaz-g4iu5no | 172.31.39.254 |   | 2019-09-16T08:41:37.542585Z |   |
| Arseny's ransomware project | Download AutoLocky Ransomware | ec2amaz-g4iu5no | 172.31.39.254 |   | 2019-09-16T08:41:32.646222Z |   |
| Arseny's ransomware project | Download Mobef Ransomware | ec2amaz-g4iu5no | 172.31.39.254 |   | 2019-09-16T08:41:23.089756Z |   |
| Arseny's ransomware project | Download BadBlock Ransomeware | ec2amaz-g4iu5no | 172.31.39.254 |   | 2019-09-16T08:41:18.225112Z |   |



### List all assessment templates

* * *

Lists all available assessment templates.

##### Base Command

`attackiq-list-assessment-templates`

##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AttackIQ.Template.ID | String | The template ID. |
| AttackIQ.Template.Name | String | The template name. |
| AttackIQ.Template.ProjectName | String | The name of the project the template is in. |
| AttackIQ.Template.Description | String | The description of the template. |
| AttackIQ.Template.ProjectDescription | String | The description of the project the template is in. |
| AttackIQ.Template.Hidden | Boolean | Whether the template is hidden. |

##### Command Example
```
!attackiq-list-assessment-templates
```

##### Context Example
```
{
    "AttackIQ.Template": [
        {
            "Description": "Custom project template",
            "Hidden": false,
            "ID": "d09d29ba-eed8-4212-bff2-4d1ee11ed80c",
            "Name": "Custom",
            "ProjectDescription": "Custom project",
            "ProjectName": "Custom"
        },
        {
            "Description": "AttackIQ\u2019s analysis and mapping of the \u201c2019 Crowdstrike Global Threat Report\u201d",
            "Hidden": false,
            "ID": "b30063b9-8f98-4f95-8f32-3a489f239dc8",
            "Name": "Crowdstrike Global Threat Report 2019",
            "ProjectDescription": "AttackIQ\u2019s analysis and mapping of the \u201c2019 Crowdstrike Global Threat Report\u201d",
            "ProjectName": "2019 Crowdstrike Global Threat Report \u2013 Top ATT&CK Techniques"
        },
        {
            "Description": "AttackIQ\u2019s analysis and mapping of the \u201cATT&CK by the Numbers\u201d @ NOVA BSides 2019",
            "Hidden": false,
            "ID": "2b118268-3fbd-42d0-9839-730c3bfa242b",
            "Name": "ATT&CK by the Numbers",
            "ProjectDescription": "AttackIQ\u2019s analysis and mapping of the \u201cATT&CK by the Numbers\u201d @ NOVA BSides 2019",
            "ProjectName": "ATT&CK by the Numbers @ NOVA BSides 2019"
        },
        {
            "Description": "AttackIQ\u2019s analysis and mapping of the \u201c2019 Red Canary Threat Detection Report \u2013 Top ATT&CK Techniques\u201d",
            "Hidden": false,
            "ID": "28933bd5-9323-4a01-8d02-3da3eb0c5d9e",
            "Name": "Red Canary Threat Detection Report 2019",
            "ProjectDescription": "AttackIQ\u2019s analysis and mapping of the \u201c2019 Red Canary Threat Detection Report \u2013 Top ATT&CK Techniques\u201d",
            "ProjectName": "2019 Red Canary Threat Detection Report \u2013 Top ATT&CK Techniques"
        },
        {
            "Description": "Test the Ransomware kill-chain for different samples: Download sample, Save it to disk and Encrypt user's files",
            "Hidden": true,
            "ID": "59d35f4a-2da0-4c4a-a08a-c30cb41dae6b",
            "Name": "Ransomware",
            "ProjectDescription": "Test the Ransomware kill-chain for different samples: Download sample, Save it to disk and Encrypt user's files",
            "ProjectName": "Ransomware"
        },
        {
            "Description": "Test your security controls by running scenarios with different user privileges (Windows only)",
            "Hidden": false,
            "ID": "f876dcbd-77bb-4321-b2a8-c279151b9490",
            "Name": "Managed Privileges",
            "ProjectDescription": "Test your security controls by running scenarios with different user privileges (Windows only)",
            "ProjectName": "Managed Privileges"
        },
        {
            "Description": "Are you a CISO joining a new company? This will help you assess the baseline of the security controls inside your network.",
            "Hidden": true,
            "ID": "6108a03e-16be-47d0-b455-7955c74a43f5",
            "Name": "Security Control Coverage",
            "ProjectDescription": "Test your security controls",
            "ProjectName": "Security Control Coverage"
        },
        {
            "Description": "Test common threats focused on cryptocurrency",
            "Hidden": true,
            "ID": "c11d1a86-df25-452d-8054-7e7cae7d4167",
            "Name": "Cryptocurrency Threats",
            "ProjectDescription": "Test common threats focused on cryptocurrency",
            "ProjectName": "Cryptocurrency Threats"
        },
        {
            "Description": "How would your security controls, processes and people respond against common attack techniques used by known threat actors?",
            "Hidden": false,
            "ID": "14908dc4-0c6f-4445-9af7-cb5438de950b",
            "Name": "MITRE Threat Assessment",
            "ProjectDescription": "Test several adversarial techniques based on MITRE ATT&CK",
            "ProjectName": "MITRE Threat Assessment"
        },
        {
            "Description": "Common techniques to obtain passwords from Windows and browsers",
            "Hidden": false,
            "ID": "c297b3fa-1c56-4e57-88bd-08ec19ec09bd",
            "Name": "Windows Credential Theft",
            "ProjectDescription": "Common techniques to obtain passwords from Windows and browsers",
            "ProjectName": "Windows Credential Theft"
        },
        {
            "Description": "Use the MITRE ATT&CK Matrix to assess your security controls.",
            "Hidden": false,
            "ID": "73599a2c-ee91-44a8-b017-febccd64b364",
            "Name": "MITRE ATT&CK",
            "ProjectDescription": "Select and test various adversarial techniques based on MITRE ATT&CK",
            "ProjectName": "MITRE ATT&CK"
        },
        {
            "Description": "Test adversarial techniques focused on command and control",
            "Hidden": true,
            "ID": "438bbcb8-c573-49b0-8ed8-31f6e7d4257e",
            "Name": "C&C",
            "ProjectDescription": "Test adversarial techniques focused on command and control",
            "ProjectName": "C&C"
        },
        {
            "Description": "Test adversarial techniques focused on discovery",
            "Hidden": false,
            "ID": "f75f1e9e-d01a-4ee2-aba3-883aaee498fe",
            "Name": "Discovery",
            "ProjectDescription": "Test adversarial techniques focused on discovery",
            "ProjectName": "Discovery"
        },
        {
            "Description": "Test adversarial techniques focused on credential access",
            "Hidden": false,
            "ID": "6386735a-9d6d-40a5-826c-635298b02acc",
            "Name": "Credential Access",
            "ProjectDescription": "Test adversarial techniques focused on credential access",
            "ProjectName": "Credential Access"
        },
        {
            "Description": "Test adversarial techniques focused on persistence",
            "Hidden": false,
            "ID": "db958dfd-2da1-440e-9c93-0dc7fd64dfbf",
            "Name": "Persistence",
            "ProjectDescription": "Test adversarial techniques focused on persistence",
            "ProjectName": "Persistence"
        },
        {
            "Description": "Test adversarial techniques focused on defense evasion",
            "Hidden": false,
            "ID": "b5e8a1a5-78fa-4003-a4c2-8b3142e42388",
            "Name": "Defense Evasion",
            "ProjectDescription": "Test adversarial techniques focused on defense evasion",
            "ProjectName": "Defense Evasion"
        },
        {
            "Description": "Test adversarial techniques focused on exfiltration",
            "Hidden": false,
            "ID": "15984ed5-b93e-4ef2-9550-8d36fd49cc58",
            "Name": "Exfiltration",
            "ProjectDescription": "Test adversarial techniques focused on exfiltration",
            "ProjectName": "Exfiltration"
        },
        {
            "Description": "Test adversarial techniques focused on execution",
            "Hidden": false,
            "ID": "6bee8a19-d997-419a-b799-64a67a71644a",
            "Name": "Execution",
            "ProjectDescription": "Test adversarial techniques focused on execution",
            "ProjectName": "Execution"
        },
        {
            "Description": "Test of data loss prevention capabilities by trying to exfiltrate credit card numbers and password patterns over HTTP, ICMP, and DNS",
            "Hidden": false,
            "ID": "517bab19-d382-4835-99f4-74dcbe428f81",
            "Name": "DLP Data Exfiltration",
            "ProjectDescription": "Test of data loss prevention capabilities by trying to exfiltrate credit card numbers and password patterns over HTTP, ICMP, and DNS",
            "ProjectName": "DLP Data Exfiltration"
        },
        {
            "Description": "Basic test of antivirus capabilities",
            "Hidden": true,
            "ID": "219a9735-2923-49c6-bde6-775db3a12655",
            "Name": "Antivirus",
            "ProjectDescription": "Basic test of antivirus capabilities",
            "ProjectName": "Antivirus"
        },
        {
            "Description": "Basic test of common ingress/egress ports",
            "Hidden": true,
            "ID": "efff3e44-eea4-4eaa-80e7-d2c5aec44e76",
            "Name": "Firewall",
            "ProjectDescription": "Basic test of common ingress/egress ports",
            "ProjectName": "Firewall"
        },
        {
            "Description": "C&C communication, circumvention by proxy services or tor, and general content filtering configuration tests",
            "Hidden": true,
            "ID": "4b7bfd88-ff3e-4949-b0b7-3268f5967084",
            "Name": "Content Filtering",
            "ProjectDescription": "C&C communication, circumvention by proxy services or tor, and general content filtering configuration tests",
            "ProjectName": "Content Filtering"
        },
        {
            "Description": "Malicious network traffic and network attacks",
            "Hidden": true,
            "ID": "5a8909d7-2e50-4a81-bab9-884005e3e824",
            "Name": "IDS/IPS",
            "ProjectDescription": "Malicious network traffic and network attacks",
            "ProjectName": "IDS/IPS"
        },
        {
            "Description": "Basic tests of advanced endpoint solutions on selected machines",
            "Hidden": false,
            "ID": "7dd68971-0448-4784-884b-3d143b3c80df",
            "Name": "Advanced Endpoint (Windows)",
            "ProjectDescription": "Basic tests of advanced endpoint solutions on selected machines",
            "ProjectName": "Advanced Endpoint (Windows)"
        }
    ]
}
```

##### Human Readable Output

| **ID** | **Name** | **Description** | **ProjectName** | **ProjectDescription** |
| --- | --- | --- | --- | --- |
| d09d29ba-eed8-4212-bff2-4d1ee11ed80c | Custom | Custom project template | Custom | Custom project |
| b30063b9-8f98-4f95-8f32-3a489f239dc8 | Crowdstrike Global Threat Report 2019 | AttackIQ’s analysis and mapping of the “2019 Crowdstrike Global Threat Report” | 2019 Crowdstrike Global Threat Report – Top ATT&CK Techniques | AttackIQ’s analysis and mapping of the “2019 Crowdstrike Global Threat Report” |
| 2b118268-3fbd-42d0-9839-730c3bfa242b | ATT&CK by the Numbers | AttackIQ’s analysis and mapping of the “ATT&CK by the Numbers” @ NOVA BSides 2019 | ATT&CK by the Numbers @ NOVA BSides 2019 | AttackIQ’s analysis and mapping of the “ATT&CK by the Numbers” @ NOVA BSides 2019 |
| 28933bd5-9323-4a01-8d02-3da3eb0c5d9e | Red Canary Threat Detection Report 2019 | AttackIQ’s analysis and mapping of the “2019 Red Canary Threat Detection Report – Top ATT&CK Techniques” | 2019 Red Canary Threat Detection Report – Top ATT&CK Techniques | AttackIQ’s analysis and mapping of the “2019 Red Canary Threat Detection Report – Top ATT&CK Techniques” |
| 59d35f4a-2da0-4c4a-a08a-c30cb41dae6b | Ransomware | Test the Ransomware kill-chain for different samples: Download sample, Save it to disk and Encrypt user's files | Ransomware | Test the Ransomware kill-chain for different samples: Download sample, Save it to disk and Encrypt user's files |
| f876dcbd-77bb-4321-b2a8-c279151b9490 | Managed Privileges | Test your security controls by running scenarios with different user privileges (Windows only) | Managed Privileges | Test your security controls by running scenarios with different user privileges (Windows only) |
| 6108a03e-16be-47d0-b455-7955c74a43f5 | Security Control Coverage | Are you a CISO joining a new company? This will help you assess the baseline of the security controls inside your network. | Security Control Coverage | Test your security controls |
| c11d1a86-df25-452d-8054-7e7cae7d4167 | Cryptocurrency Threats | Test common threats focused on cryptocurrency | Cryptocurrency Threats | Test common threats focused on cryptocurrency |
| 14908dc4-0c6f-4445-9af7-cb5438de950b | MITRE Threat Assessment | How would your security controls, processes and people respond against common attack techniques used by known threat actors? | MITRE Threat Assessment | Test several adversarial techniques based on MITRE ATT&CK |
| c297b3fa-1c56-4e57-88bd-08ec19ec09bd | Windows Credential Theft | Common techniques to obtain passwords from Windows and browsers | Windows Credential Theft | Common techniques to obtain passwords from Windows and browsers |
| 73599a2c-ee91-44a8-b017-febccd64b364 | MITRE ATT&CK | Use the MITRE ATT&CK Matrix to assess your security controls. | MITRE ATT&CK | Select and test various adversarial techniques based on MITRE ATT&CK |
| 438bbcb8-c573-49b0-8ed8-31f6e7d4257e | C&C | Test adversarial techniques focused on command and control | C&C | Test adversarial techniques focused on command and control |
| f75f1e9e-d01a-4ee2-aba3-883aaee498fe | Discovery | Test adversarial techniques focused on discovery | Discovery | Test adversarial techniques focused on discovery |
| 6386735a-9d6d-40a5-826c-635298b02acc | Credential Access | Test adversarial techniques focused on credential access | Credential Access | Test adversarial techniques focused on credential access |
| db958dfd-2da1-440e-9c93-0dc7fd64dfbf | Persistence | Test adversarial techniques focused on persistence | Persistence | Test adversarial techniques focused on persistence |
| b5e8a1a5-78fa-4003-a4c2-8b3142e42388 | Defense Evasion | Test adversarial techniques focused on defense evasion | Defense Evasion | Test adversarial techniques focused on defense evasion |
| 15984ed5-b93e-4ef2-9550-8d36fd49cc58 | Exfiltration | Test adversarial techniques focused on exfiltration | Exfiltration | Test adversarial techniques focused on exfiltration |
| 6bee8a19-d997-419a-b799-64a67a71644a | Execution | Test adversarial techniques focused on execution | Execution | Test adversarial techniques focused on execution |
| 517bab19-d382-4835-99f4-74dcbe428f81 | DLP Data Exfiltration | Test of data loss prevention capabilities by trying to exfiltrate credit card numbers and password patterns over HTTP, ICMP, and DNS | DLP Data Exfiltration | Test of data loss prevention capabilities by trying to exfiltrate credit card numbers and password patterns over HTTP, ICMP, and DNS |
| 219a9735-2923-49c6-bde6-775db3a12655 | Antivirus | Basic test of antivirus capabilities | Antivirus | Basic test of antivirus capabilities |
| efff3e44-eea4-4eaa-80e7-d2c5aec44e76 | Firewall | Basic test of common ingress/egress ports | Firewall | Basic test of common ingress/egress ports |
| 4b7bfd88-ff3e-4949-b0b7-3268f5967084 | Content Filtering | C&C communication, circumvention by proxy services or tor, and general content filtering configuration tests | Content Filtering | C&C communication, circumvention by proxy services or tor, and general content filtering configuration tests |
| 5a8909d7-2e50-4a81-bab9-884005e3e824 | IDS/IPS | Malicious network traffic and network attacks | IDS/IPS | Malicious network traffic and network attacks |
| 7dd68971-0448-4784-884b-3d143b3c80df | Advanced Endpoint (Windows) | Basic tests of advanced endpoint solutions on selected machines | Advanced Endpoint (Windows) | Basic tests of advanced endpoint solutions on selected machines |

### List all assets

* * *

Lists all assets.

##### Base Command

`attackiq-list-assets`

##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AttackIQ.Asset.ID | String | The ID of the asset. |
| AttackIQ.Asset.Description | String | The description of the asset. |
| AttackIQ.Asset.IPv4 | String | The IPv4 address of the asset. |
| AttackIQ.Asset.IPv6 | String | The IPv6 address of the asset. |
| AttackIQ.Asset.MacAddress | String | The MAC address of the asset. |
| AttackIQ.Asset.ProcessorArch | String | The processor arch of the asset. |
| AttackIQ.Asset.ProductName | String | The name of the asset. |
| AttackIQ.Asset.Hostname | String | The hostname of the asset. |
| AttackIQ.Asset.Domain | String | The domain of the asset. |
| AttackIQ.Asset.User | String | The user of the asset. |
| AttackIQ.Asset.Status | String | Status of the asset. |
| AttackIQ.Asset.Groups.ID | String | The ID of the asset's group. |
| AttackIQ.Asset.Groups.Name | String | The name of the asset's group. |

##### Command Example
```
!attackiq-list-assets
```

##### Context Example
```
{
    "AttackIQ.Asset": [
        {
            "Description": null,
            "Domain": "workgroup",
            "Groups": [
                {
                    "ID": "4fe9c3b1-2a26-487a-97bd-a098e55ea3d2",
                    "Name": "Demisto asset group"
                }
            ],
            "Hostname": "ec2amaz-g4iu5no",
            "ID": "03e17460-849e-4b86-b6c6-ef0db72823ff",
            "IPv4": "172.31.39.254",
            "IPv6": null,
            "MacAddress": "06-FB-B8-38-E2-2A",
            "ProcessorArch": "amd64",
            "ProductName": "Windows Server 2016 Datacenter",
            "Status": "Active",
            "User": "agent_7377e1fa-d49d-44bf-84ef-4e1dfb8e4748@demisto.com"
        }
    ]
}
```

##### Human Readable Output

##### Assets:

| **ID** | **Hostname** | **IPv4** | **MacAddress** | **Domain** | **Description** | **User** | **Status** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 03e17460-849e-4b86-b6c6-ef0db72823ff | ec2amaz-g4iu5no | 172.31.39.254 | 06-FB-B8-38-E2-2A | workgroup |  | agent_7377e1fa-d49d-44bf-84ef-4e1dfb8e4748<span></span>@demisto.com | Active |

### Create an assessment

* * *

Creates a new assesment.

##### Base Command

`attackiq-create-assessment`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the new assesment | Required |
| template_id | The ID of the template from which to create the assesment. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AttackIQ.Assessment.Id | String | The ID of the assessment. |
| AttackIQ.Assessment.Name | String | The name of the assessment name. |
| AttackIQ.Assessment.Description | String | The description of the assessment. |
| AttackIQ.Assessment.StartDate | Date | The start date of the assessment. |
| AttackIQ.Assessment.EndDate | Date | The end date of the assessment. |
| AttackIQ.Assessment.AssessmentState | String | The state of the assessment. Can be, "Active" or "Inactive". |
| AttackIQ.Assessment.DefaultSchedule | String | The default schedule timing (cron) of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateId | String | The template ID of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateName | String | The template name of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateDescription | String | The template description of the assessment. |
| AttackIQ.Assessment.AssessmentTemplateDefaultSchedule | Unknown | The assessment's template default schedule timing (cron). |
| AttackIQ.Assessment.AssessmentTemplateCompany | String | The owner of the template. |
| AttackIQ.Assessment.AssessmentTemplateCreated | Date | The date that the template was created. |
| AttackIQ.Assessment.AssessmentTemplateModified | Date | The date that the template was last modified. |
| AttackIQ.Assessment.Creator | String | The user who created the assessment. |
| AttackIQ.Assessment.Owner | String | The user who owns the assessment. |
| AttackIQ.Assessment.User | String | The user who ran the assessment. |
| AttackIQ.Assessment.Created | String | The date that the assessment was created. |
| AttackIQ.Assessment.Modified | String | The date that the assessment was last modified. |
| AttackIQ.Assessment.Users | String | The user IDs that can access the assessment. |
| AttackIQ.Assessment.Groups | String | The user groups that can access the assessment. |
| AttackIQ.Assessment.DefaultAssetCount | Number | The number of machines (assets) that are connected to the assessment. |
| AttackIQ.Assessment.DefaultAssetGroupCount | Number | The number of asset groups that are connected to the assessment. |
| AttackIQ.Assessment.MasterJobCount | Number | The number of tests that ran in the assessment. |
| AttackIQ.Assessment.Count | Number | The total number of assessments. |
| AttackIQ.Assessment.RemainingPages | Number | The number of remaining pages to return. For example, if the total number of pages is 6, and the last fetch was page 5, the value is 1. |

##### Command Example
```
!attackiq-create-assessment name="Assessment from test playbook" template_id="d09d29ba-eed8-4212-bff2-4d1ee11ed80c"
```

##### Context Example
```
{
    "AttackIQ.Assessment": {
        "AssessmentState": "Inactive",
        "AssessmentTemplateCompany": "906d5ec6-101c-4ae6-8906-b93ce0529060",
        "AssessmentTemplateCreated": "2017-01-18T00:05:10.032807Z",
        "AssessmentTemplateDefaultSchedule": null,
        "AssessmentTemplateDescription": "Custom project template",
        "AssessmentTemplateId": "d09d29ba-eed8-4212-bff2-4d1ee11ed80c",
        "AssessmentTemplateModified": "2018-07-10T21:38:32.040806Z",
        "AssessmentTemplateName": "Custom",
        "Created": "2019-10-29T08:37:22.187577Z",
        "Creator": "foo@test.com",
        "DefaultAssetCount": 0,
        "DefaultAssetGroupCount": 0,
        "DefaultSchedule": null,
        "Description": "Custom project",
        "EndDate": null,
        "Groups": [],
        "Id": "08023e86-3b8c-4f98-ab46-7c931d759157",
        "MasterJobCount": 0,
        "Modified": "2019-10-29T08:37:22.187603Z",
        "Name": "Assessment from test playbook",
        "Owner": "foo@test.com",
        "StartDate": null,
        "User": "foo@test.com",
        "Users": [
            "e9f58a46-31bc-4099-9bb1-624bb20a7340"
        ]
    }
}
```

##### Human Readable Output

##### Created Assessment: 08023e86-3b8c-4f98-ab46-7c931d759157 successfully.

| **Id** | **Name** | **Description** | **User** | **Created** | **Modified** |
| --- | --- | --- | --- | --- | --- |
| 08023e86-3b8c-4f98-ab46-7c931d759157 | Assessment from test playbook | Custom project | woo<span></span>@test.com | 2019-10-29T08:37:22.187577Z | 2019-10-29T08:37:22.187603Z |

### Add assets to an assesment

* * *

Adds assets or asset groups to an assesment.

##### Base Command

`attackiq-add-assets-to-assessment`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assets | A comma-seperated list of asset IDs. | Optional |
| asset_groups | A comma-seperated list of asset group IDs. | Optional |
| assessment_id | The ID of the assessment to which the assets will be added. | Required |

##### Context Output

There are no context outputs for this command.

##### Command Example
```
!attackiq-add-assets-to-assessment assets="03e17460-849e-4b86-b6c6-ef0db72823ff" assessment_id="b2fc06d4-5d0a-4924-a126-66320887dce0"
```

##### Human Readable Output

Successfully updated default assets/asset groups for project b2fc06d4-5d0a-4924-a126-66320887dce0

### Delete an assessment

* * *

Deletes an assessment.

##### Base Command

`attackiq-delete-assessment`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | The ID of the assessment to delete. | Required |

##### Context Output

There are no context outputs for this command.

##### Command Example
```
!attackiq-delete-assessment assessment_id="b2fc06d4-5d0a-4924-a126-66320887dce0"
```

##### Human Readable Output

Deleted assessment b2fc06d4-5d0a-4924-a126-66320887dce0 successfully.

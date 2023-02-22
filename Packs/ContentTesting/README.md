### Overview

This content pack provides tools for creating automated tests and test cases for XSOAR content and testing within XSOAR. Assessment tools identify potential impacts of an upgrade to a Marketplace content pack, display an XSOAR object's version history when using  **Save Version**, and list automations used in playbooks.  Playbook analysis provides average and maximum task duration across a range of incidents as well as task runnging status. Test data is created by pulling incident fields and context from existing incidents, manual updates of individual fields and context keys, and saving data to XSOAR lists for use in testing.  Test cases are defined that load appropriate test data and execute automation, playbook, and sub-playbook tests.  The **UnitTest** incident type, **UnitTestingLayout** layout, and **UnitTestingTopLevel** playbook provide an example of a content testing environment and use of the testing tools. These objects can be modified as needed for specific testing requirements or guide implementation of a custom content testing environment.

- Provide guidance for what tests are required for a change
  - Marketplace content pack updates
  - Custom content change and release to production
- Automated unit and regression testing of XSOAR content
  - automations
  - commands
  - playbooks
  - sub-playbooks
- Configure incident fields and context for testing
- Save incident fields and context for regression testing
- Define and save test cases
- Adhoc testing of content
- Tests are dymanically added to an empty testing playbook
  - Testing workplan and war room document testing performed
  - Testing results displayed in the incident layout

### Getting Started

The quickest way to get started is to create a new incident of the type **UnitTesting**. From there, execute the assessment tools, review the results in each tab of the incident layout, and from the **Content Testing** tab, exercise the content testing tools with the mock playbooks and lists. 

XSOAR prerequesits are:
  
- XSOAR API Key
- Enabled REST API integration instance
- Enabled Demisto Lock integration instance

Prior to content testing using the supplied examples, five XSOAR lists must be created:

- **UnitTestingAutomations**
- **UnitTestingSubplaybooks**
- **UnitTestCase**
- **TestFields**
- **TestContext**

Below is example content for each of the three lists.

**UnitTestingAutomations**:

    ip,{"ip":"8.8.8.8", "using":"VirusTotal (API v3)"}
    http,{"method":"GET", "url":"https://www.google.com"}

**UnitTestingSubplaybooks**:

    MockSubplaybook,{"input1":"value1", "input2":"value2"}

For the example test case, use the content testing tools to create and save XSOAR lists with incident fields and context. Two XSOAR lists to create are:

- **TestFields**
- **TestContext**

The test case XSOAR list to create for the example:

**UnitTestCase**:

    LoadFields|TestFields
    LoadContext|TestContext
    Automation|UnitTestingAutomations
    Subplaybook|UnitTestingSubplaybooks
    Playbook|MockPlaybook

### Test Environment Creation

- Determine test cases required based on upgraded content packs or updated custom content
- Create a new incident of the **UnitTesting** incident type
- From the **Content Assessment** tab, use the **Assessment Actions**
  - Review the **Content Pack Details** tab
  - Review the **Commit History** tab for history of XSOAR content local changes (when using dev to prod)
  - Review the **Playbook Automations** tab
- Update **UnitTestTopLevel** playbook or create a testing playbook with section headers where test tasks are assigned
- In the **UnitTesting** incident layout and the **Content Testing** tab 
  - In the **Execute Tests** section add buttons or multi-select fields and configure the script arguments
    - For buttons, use the **UnitTest** automation
    - For multi-select fields with an array of playbooks, use the **UnitTestMultiSelect** automation
    - For button automation, the arguments are (see the automation sections for details on each automation):
      - **addAfter** - task ID in the playbook to add the test task after, usually a section header
      - **playbook** - specific playbook to launch or allow user to input a comma separated list. Blank if **testType** is **Subplaybook**
      - **testType** - type of test being executed
        - **Playbook**
        - **Subplaybook**
        - **Multiselect**
        - **Automation**
      - **listName** - if **testType** is **Subplaybook** or **Automation**, the name of the list to read input from
    - For multi-select of playbooks to test, use the **UnitTestMultiSelect** script
    - For a multi-select field parameters
      - Edit the **unittestplaybooks** field and set the values to playbook names to test
      - See caveat below
- Load the incident fields from an existing incident
- If needed, load the context from an existing incident
- Update individual fields and context keys as needed for specific testing
- For regression testing and test cases, save incident fields and context to XSOAR lists

### Test Execution

- Create a new incident of the **UnitTesting** incident type (or a custom type)
- On the **Content Testing** tab in the **Execute Test** section
  - For each test, load incident fields and context and as needed
  - Execute the content tests using buttons and fields
  - Review the **Test Results** section, **Work Plan** tab, and **War Room** tab to verify test results

### Test Case Execution
- Create and save XSOAR lists with incident fields and context needed for the test case
  - Example uses **TestFields**
  - Example uses **TestContext**
- Define the test case in an XSOAR list (example uses **UnitTestCase**)
- The use the two action on the **Content Testing** tab in the **Execute Test Cases** section to load the incident fields and context from the test case list and then execute the testing commands
  - **Prepare Data for Test Case**
  - **Execute Test Case**

### Testing List Formats

#### Automation Unit Test List Format
- \<automation name/command name\>,\<JSON command arguments\>

#### Subplaybook Unit Test List Format
- \<subplaybook name\>,\<JSON subplaybook inputs\>

#### Test Case List Format
Test cases are defined by content testing commands in an XSOAR list. The following test commands are supported:

- **LoadFields**|\<XSOAR list name where test incident fields are saved\>
- **LoadContext**|\<XSOAR list name where test context are saved\>
- **Automation**|\<XSOAR list name with automation commands and their arguments\>
- **Subplaybook**|\<XSOAR list name with subplaybooks and their inputs\>
- **Playbook**|\<comma separated list of playbook names\>

### Caveats

- The multi-select option has a hard coded task number of where to add test tasks in the top level testing playbook.  If creating a custom testing playbook, modify the **MULTISELECT** constant in the **UnitTestMultiSelect** automation to match your playbook
- If custom fields exist required for testing but not added to all incident types, add them to the **UnitTesting** incident type, or any custom testing incident type created
- Playbooks do not return errors: the "true/false" test results displayed indicate the playbook was was successfully added and executed to the top level testing playbook. Review the testing incident's war room and work plan to assess actual results of the playbook and playbook tasks

### Content Testing Objects Included in the Content Pack

#### Playbook
- **UnitTestTopLevel**
- **MockPlaybook**
- **MockSubplaybook**

#### Incident Type
- **UnitTesting**

#### Incident Layout
- **UnitTestLayout**

#### Incident Fields

- **contenttestingcontentautomations**
- **contenttestingcontentdetails**
- **contenttestingcontentimpacts**
- **contenttestingcommithistory**
- **contenttestingcoverage**
- **contenttestingpbainfo**
- **contenttestingdependencies**
- **contenttestingunittestresults**
- **contenttestingunittestplaybooks**

#### Assessment Automations
- **ChangeHistory**
- **ListPlaybookAutomationsCommands**
- **UpgradeCheck**

#### Content Testing Automations
- **UnitTest**
- **UnitTestCase**
- **UnitTestCasePrep**
- **UnitTestCoverage**
- **UnitTestLoadContext**
- **UnitTestLoadContextList**
- **UnitTestLoadFields**
- **UnitTestLoadFieldsList**
- **UnitTestMultiSelect**
- **UnitTestResults**
- **UnitTestSaveContextList**
- **UnitTestSaveFieldsList**
- **UnitTestSetField**
- **UnitTestSubplaybookPrep**

#### Playbook Analysis Automations
- **UnitTestPBAStats**
- **UnitTestPBATaskAvg**
- **UnitTestPBATaskMax**
- **UnitTestPlaybookAnalyzer**

### Assessment Automations

#### UpgradeCheck
This automation looks at Marketplace content packs requiring updates and assesses impacts on existing custom content.  The assessment results are stored in a field (**contenttestingcontentimpacts**) and displayed in a tab of in the testing incident's layout. Upgraded content pack details are summarized in another field (**contenttestingcontentdetails**) and displayed in a tab for copying to test documentation.

##### Inputs

None

##### Outputs

None

#### ChangeHistory
This automation searchs for the version history of all current local changes in XSOAR when using dev to prod and a remote repository.  The version history is stored in a field (**contenttestingcommithistory**) and displayed in a tab of in the testing incident's layout.  Version history is created when an XSOAR object such as a playbook is saved using the **Save Version** button.

##### Inputs

None

##### Outputs

None

#### ListPlaybookAutomationsCommand
This automation searches playbooks for automation or integration commands used by a playbook and stores them in a field (**contenttestingcontentautomations**) for display in the testing incident layout. This assists identifying playbooks and automations requiring testing as part of a change to XSOAR content.

##### Inputs

None

##### Outputs

None

### Content Testing Automations

#### UnitTest
This automation runs each type of test, dynamically adds tasks to the testing playbook, and displays the results in the testing incident's layout.

##### Inputs

|Argument Name| Description |
|---|---|
|playbook| Playbook to execute, blank if testType is Subplaybook or Automation |
|addAfter| Playbook task (typically a playbook section header) numeric ID  to add this testing task after |
|testType| Type of test to run: Playbook, Subplaybook, Automation, Multiselect |
|listName| XSOAR list name to read sub-playbooks or automations and their inputs or arguments from. Blank if testType is Playbook or Multiselect |

##### Outputs

None

#### UnitTestCoverage
Looks at all the content tests that have been executed using the specified playbook and whether each executable (regular, conditional, sub-playbook, and data collection) task was executed. Places Markdown formatted results in the **contenttestingcoverage** field for display in the incident layout.

##### Inputs

|Argument Name| Description |
|---|---|
|playbook| Name of the playbook to assess test coverage  |

##### Outputs

None

#### UnitTestResults
This automation displays the results in the testing incident layout and must be executed within a Demisto lock to avoid concurrent updates the the test results grid field. It is invoked by **UnitTest**.

##### Inputs

|Argument Name| Description |
|---|---|
|cmds| Array of automation or command names or playbook names executed |
|tasks| Array of tasks names, created for each testing task|
|gridfield| The grid incident field to store test results in (**contenttestingunittestresults**) |
|status| Array of result of the command (true, false) |

##### Outputs

#### UnitTestLoadContext
This automation loads context from an existing incident into the current testing incident.

##### Inputs

|Argument Name| Description |
|---|---|
|id | Incident numeric ID to load context from |

##### Outputs

None

#### UnitTestSaveContextList
This automation saves context from the current testing incident to an XSOAR list.

##### Inputs

|Argument Name| Description |
|---|---|
|list | XSOAR list name to save context to|

##### Outputs

None

#### UnitTestLoadContextList
This automation loads context from an XSOAR list into the current testing incident.

##### Inputs

|Argument Name| Description |
|---|---|
|list | XSOAR list name to load context from |

##### Outputs

None

#### UnitTestLoadFields
This automation loads incident fields from an existing incident into the current testing incident.

##### Inputs

|Argument Name| Description |
|---|---|
|id | Incident numeric ID to load incident fields from |

##### Outputs

None

#### UnitTestSaveFieldsList
This automation saves incident fields from the current testing incident to an XSOAR list.

##### Inputs

|Argument Name| Description |
|---|---|
|list | XSOAR list name to save incident fields to|

##### Outputs

None

#### UnitTestLoadFieldsList
This automation loads incident fields from an XSOAR list into the current testing incident.

##### Inputs

|Argument Name| Description |
|---|---|
|list | XSOAR list name to load incident fields from  |

##### Outputs

None

#### UnitTestSetField
This automation sets an incident field value in the current testing incident.

##### Inputs

|Argument Name| Description |
|---|---|
|field | Incident field name to set  |
|value | Value to set incident field to  |

##### Outputs

None

#### UnitTestMultiSelect
This automation is used if a set of playbooks are provided in a multi-select incident field. The selected playbooks are passed to the **UnitTest** automation. **UnitTestMultiSelect** hard codes the testing playbook task numeric ID to add these tasks after and assumes the **TopLevelUnitTesting** playbook is used. If using another testing playbook, edit the **MULTISELECT** constant in this automation to specify the task location to add the playbook testing task. 

##### Inputs

|Argument Name| Description |
|---|---|
|new | Playbook names selected from the array in the field|

##### Outputs

None

#### UnitTestSubplaybookPrep
This automation loads context providing sub-playbook inputs.  The sub-playbook testing list used is the same as used by **UnitTesting**. Context must be preloaded since caching of context updates does not occur until an automation exits. This automation must execute prior to **UnitTesting** executing against the "Subplaybook" type of test that requires playbook inputs.

##### Inputs

|Argument Name| Description |
|---|---|
|listName | XSOAR list name to read subplaybook context inputs from |

##### Outputs

None

#### UnitTestCase
This automation is used to execute a test case defined in an XSOAR list.

##### Inputs

|Argument Name| Description |
|---|---|
|testName | Test case name (not used) |
|listName | XSOAR list name to read test case from |
|addAfter | Playbook task numeric ID to add this testing task after |

##### Outputs

None

#### UnitTestCasePrep
These automation loads context and incident fields defined in a test case XSOAR list to configure it for the test case.  Context must be preloaded since caching of context updates does not occur until an automation exits - this automation must execute prior to executing **UnitTestCase**.

##### Inputs

|Argument Name| Description |
|---|---|
|testName | Test case name (not used) |
|listName | XSOAR list name to read test case from |

##### Outputs

None

#### UnitTestLoadContext
This automation loads context from an existing incident into the current testing incident.

##### Inputs

|Argument Name| Description |
|---|---|
|id | Incident numeric ID to load context from |

##### Outputs

None

### Playbook Analyzer Automations

#### UnitTestPlaybook Analyzer

Analyzes playbook dependencies on automations and sub-playbooks as well as tasks execution metrics over a set of selected incidents. Generates minumum, average, and maximum execution times for each task in the specified playbook.  Execution statistics are stored in the **PlaybookStatistics** context key for display in the layout. Content dependencies are stored in the **contenttestingdependencies** field and task execution information is stored **contenttestingpbainfo** field for display in the layout.

##### Inputs

|Argument Name| Description |
|---|---|
|playbook| Name of the playbook to analyze  |
|occurred| Incident occurrance time and include in the analysis|

##### Outputs

None

#### UnitTestPBAStats

General dynamic section script that creates and displays a bar widget that shows the task status (running, executed, not started, waiting, and error) counts for tasks from the data in the **PlaybookStatistics** context key.

##### Inputs

None

##### Outputs

None

#### UnitTestPBATaskAvg

General dynamic section script that creates and displays a pie widget of the average task durations for each task in the playbook based on the data in the **PlaybookStatistics** context key.

##### Inputs

None

##### Outputs

None

#### UnitTestPBATaskMax

General dynamic section script that creates and displays a pie widget of the maximum task durations for each task in the playbook based on the data in the **PlaybookStatistics** context key.

##### Inputs

None

##### Outputs

None
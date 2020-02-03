## [Unreleased]


## [20.1.2] - 2020-01-22
Added 4 new commands.
  - ***attackiq-list-assessment-templates***: Lists all available assessment templates.
  - ***attackiq-list-assets***: Lists all assets.
  - ***attackiq-create-assessment***: Creates a new assessment.
  - ***attackiq-add-assets-to-assessment***: Adds assets or asset groups to an assessment.

## [19.10.0] - 2019-10-03
  - Changed the integtration name from "AttackIQ FireDrill" to "AttackIQ Platform"


## [19.9.1] - 2019-09-18
  - New Integration AttackIQ - FireDrill:
    - Command ***attackiq-get-assessment-by-id***: Get all assessments in a page or by assessment id.
    - Command ***attackiq-list-assessments***: Get all assessments in a page (up to 10 assessments per page).
    - Command ***attackiq-activate-assessment***: Activates the assessment. This is required for execution.
    - Command ***attackiq-run-all-tests-in-assessment***: Runs all of the tests in the assessment.
    - Command ***attackiq-get-assessment-execution-status***: Get assessment execution status - supports only on demand runs.
    - Command ***attackiq-get-test-execution-status***: Get test run status.
    - Command ***attackiq-list-tests-by-assessment***: Get assessment's test. Will get by default up to 10 test per call.
    - Command ***attackiq-get-test-results***: Get assessment's test result by page (by default, a page consists of 10 tests).

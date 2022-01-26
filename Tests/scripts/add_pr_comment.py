import os
from demisto_sdk.commands.test_content.execute_test_content import _add_pr_comment
from demisto_sdk.commands.test_content.execute_test_content import ParallelLoggingManager


COVERAGE_REPORT_COMMENT = 'Link to the unit tests coverage report'
JOB_ID = os.environ.get("CI_JOB_ID")
COVERAGE_LINK = f'https://xsoar.docs.pan.run/-/content/-/jobs/{JOB_ID}/artifacts/artifacts/coverage_report/html/' \
                f'index.html'


if __name__ == "__main__":
    logging_manager = ParallelLoggingManager('Run_Tests.log')
    _add_pr_comment(COVERAGE_LINK, logging_manager)

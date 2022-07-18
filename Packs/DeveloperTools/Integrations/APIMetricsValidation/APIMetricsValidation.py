import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

TEST_BANK_SCENARIO_TEN_ITEMS = '''oneone,twotwo,threethree, fourfour, fivefive,
                         sixsix, sevenseven, eighteight, ninenine, tenten'''
TEST_BANK_SCENARIO_FIVE_ITEMS = '''sixsix, sevenseven, eighteight, ninenine, tenten'''


def scenario_one():
    """
    This is a test scenario where all 10 entries succeed
    Assumptions: Command has not been run before.
    Returns:
        10 successful entries
        1 ExecutionMetrics object containing 10 success
    """
    execution_metrics = ExecutionMetrics()
    command_results: list = []

    urls = argToList(TEST_BANK_SCENARIO_TEN_ITEMS)

    for url in urls:
        # Every url will pass here
        execution_metrics.success += 1
        command_results.append(
            CommandResults(readable_output=f"Item - {url} has been processed")
        )
    command_results.append(execution_metrics.metrics)
    return command_results


def scenario_two():
    """
    This is a test scenario where 5 entries are processed and 5 are failed with QuotaError
    Assumptions: Command has not been run before.
    Returns:
        5 successful entries
        5 Scheduled entries
        1 ExecutionMetrics object containing 5 success and 5 quota errors
    """
    execution_metrics = ExecutionMetrics()
    command_results: list = []

    urls = argToList(TEST_BANK_SCENARIO_TEN_ITEMS)
    items_to_schedule = []

    for idx, url in enumerate(urls):
        # First 5 succeed
        if idx < 5:
            execution_metrics.success += 1
            command_results.append(
                CommandResults(readable_output=f"Item - {url} has been processed")
            )
        # Next 5 fail with QuotaError
        else:
            execution_metrics.quota_error += 1
            items_to_schedule.append(url)

    scheduled_command = ScheduledCommand(
        command='test-scenario-two',
        next_run_in_seconds=20,
        args={'polling': True, 'items_to_schedule': items_to_schedule},
        timeout_in_seconds=40,
        items_remaining=len(items_to_schedule),
    )
    command_results.append(CommandResults(scheduled_command=scheduled_command))
    if execution_metrics.metrics is not None:
        command_results.append(execution_metrics.metrics)
    return command_results


def scenario_three():
    """
    This is a test scenario where 5 entries failed with QuotaError
    Assumptions: Command has been run once before.
    Returns:
        5 Scheduled entries
        No ExecutionMetrics object
    """
    execution_metrics = ExecutionMetrics()
    command_results: list = []

    urls = argToList(TEST_BANK_SCENARIO_FIVE_ITEMS)
    items_to_schedule = []
    for idx, url in enumerate(urls):
        items_to_schedule.append(url)
        # All 5 items fail on retry here, and it's expected that all 5 iterations are previously scheduled
        continue

    scheduled_command = ScheduledCommand(
        command='test-scenario-three',
        next_run_in_seconds=20,
        args={'polling': True, 'items_to_schedule': items_to_schedule},
        timeout_in_seconds=40,
        items_remaining=len(items_to_schedule),
    )
    command_results.append(CommandResults(scheduled_command=scheduled_command))
    if execution_metrics.metrics is not None:
        command_results.append(execution_metrics.metrics)
    return command_results


def scenario_four():
    """
    This is a test scenario where 5 entries failed with QuotaError
    Assumptions: Command has been run once before.
    Returns:
        5 Scheduled entries
        1 ExecutionMetrics object containing 2 successful
    """
    execution_metrics = ExecutionMetrics()
    command_results: list = []

    urls = argToList(TEST_BANK_SCENARIO_FIVE_ITEMS)
    items_to_schedule = []
    if not demisto.args().get('polling'):
        for idx, url in enumerate(urls):
            if idx < 2:
                execution_metrics.success += 1
                command_results.append(
                    CommandResults(readable_output=f"Item - {url} has been processed")
                )
            else:
                items_to_schedule.append(url)
                continue

    scheduled_command = ScheduledCommand(
        command='test-scenario-four',
        next_run_in_seconds=20,
        args={'polling': True, 'items_to_schedule': items_to_schedule},
        timeout_in_seconds=40,
        items_remaining=len(items_to_schedule),
    )
    command_results.append(CommandResults(scheduled_command=scheduled_command))
    if execution_metrics.metrics is not None:
        command_results.append(execution_metrics.metrics)
    return command_results


def scenario_five():
    """
    This is a test scenario where all 10 entries succeed
    Assumptions: Command has not been run before.
    Returns:
        1 successful entry
        1 ExecutionMetrics object containing 10 success
    """
    execution_metrics = ExecutionMetrics()
    command_results: list = []

    urls = argToList(TEST_BANK_SCENARIO_TEN_ITEMS)

    execution_metrics.success += 1
    command_results.append(
        CommandResults(readable_output=f"Item - {urls} have been processed")
    )
    command_results.append(execution_metrics.metrics)
    return command_results


def scenario_six():
    """
    This is a test scenario where 10 items are in a single api call. That one api call fails and is scheduled.
    Assumptions: Command has not been run before.
    Returns:
        1 Scheduled entry
    """
    execution_metrics = ExecutionMetrics()
    command_results: list = []
    execution_metrics.quota_error += 1

    scheduled_command = ScheduledCommand(
        command='test-scenario-six',
        next_run_in_seconds=20,
        args={'polling': True, 'items_to_schedule': TEST_BANK_SCENARIO_TEN_ITEMS},
        timeout_in_seconds=40,
        items_remaining=len(TEST_BANK_SCENARIO_TEN_ITEMS),
    )
    command_results.append(CommandResults(scheduled_command=scheduled_command))
    if execution_metrics.metrics is not None:
        command_results.append(execution_metrics.metrics)
    return command_results


def scenario_seven():
    """
    This is a test scenario where 10 items are in a single api call. That one api call fails and is scheduled.
    Assumptions: Command has been run once before.
    Returns:
        1 Scheduled entries
        No ExecutionMetrics object
    """
    execution_metrics = ExecutionMetrics()
    command_results: list = []
    urls = argToList(TEST_BANK_SCENARIO_TEN_ITEMS)
    items_to_schedule = [urls]

    scheduled_command = ScheduledCommand(
        command='test-scenario-seven',
        next_run_in_seconds=20,
        args={'polling': True, 'items_to_schedule': items_to_schedule},
        timeout_in_seconds=40,
        items_remaining=len(items_to_schedule),
    )
    command_results.append(CommandResults(scheduled_command=scheduled_command))
    if execution_metrics.metrics is not None:
        command_results.append(execution_metrics.metrics)
    return command_results


def scenario_eight():
    """
    This is a test scenario where 10 items are in a single api call. That one api call fails and is scheduled.
    Assumptions: Command has been run once before. Metrics were reported the first run.
    Returns:
        1 Scheduled entries
        No ExecutionMetrics object

    Notes: To simulate that this command has been re-ran before, we are not returning _any_ metrics.
    """
    execution_metrics = ExecutionMetrics()
    command_results: list = []
    urls = argToList(TEST_BANK_SCENARIO_TEN_ITEMS)
    items_to_schedule = [urls]

    scheduled_command = ScheduledCommand(
        command='test-scenario-seven',
        next_run_in_seconds=20,
        args={'polling': True, 'items_to_schedule': items_to_schedule},
        timeout_in_seconds=40,
        items_remaining=1,
    )
    command_results.append(CommandResults(scheduled_command=scheduled_command))
    if execution_metrics.metrics is not None:
        command_results.append(execution_metrics.metrics)
    return command_results


def scenario_nine():
    """
    This is a test scenario which is ran in a playbook
    Assumptions: Command has not been run before.
    Returns:
        10 successful entries
        1 ExecutionMetrics object containing 10 success
    """
    execution_metrics = ExecutionMetrics()
    command_results: list = []
    urls = argToList(TEST_BANK_SCENARIO_FIVE_ITEMS)

    for url in urls:
        # Every url will pass here
        execution_metrics.quota_error += 1
        command_results.append(
            CommandResults(readable_output=f"Item - {url} has been processed")
        )
    command_results.append(execution_metrics.metrics)
    return command_results


def scenario_ten():
    """
    This is a test scenario which is returns only one successful entry.
    Assumptions: Ran only in a playbook
    Returns:
        1 successful entry
        1 ExecutionMetrics object containing 1 success
    """
    execution_metrics = ExecutionMetrics()
    command_results: list = []
    execution_metrics.success += 1
    command_results.append(
        CommandResults(readable_output="Item has been processed")
    )
    command_results.append(execution_metrics.metrics)
    return command_results


def main():
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    if demisto.args().get('polling') and command != 'test-scenario-four':
        # This is to isolate a scenario where the command is run in polling mode
        sys.exit(0)
    try:

        if command == 'test-scenario-one':
            results = scenario_one()
            return_results(results)

        elif command == 'test-scenario-two':
            results = scenario_two()
            return_results(results)

        elif command == 'test-scenario-three':
            results = scenario_three()
            return_results(results)

        elif command == 'test-scenario-four':
            results = scenario_four()
            return_results(results)

        elif command == 'test-scenario-five':
            results = scenario_five()
            return_results(results)

        elif command == 'test-scenario-six':
            results = scenario_six()
            return_results(results)

        elif command == 'test-scenario-seven':
            results = scenario_seven()
            return_results(results)

        elif command == 'test-scenario-eight':
            results = scenario_eight()
            return_results(results)

        elif command == 'test-scenario-nine':
            results = scenario_nine()
            return_results(results)
            return_error("This is an error")

        elif command == 'test-scenario-ten':
            results = scenario_ten()
            return_results(results)

        elif command == 'test-module':
            demisto.results('ok')
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

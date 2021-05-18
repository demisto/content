from subprocess import PIPE, Popen
from io import StringIO
import pandas as pd
import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()

# ---------- CLASSES ---------- #


class EDLPerformanceResult:
    def __init__(self, timeout: str, concurrent: str, ioc_type: str, size: str, result: str):
        self._t = timeout or ''
        self._c = concurrent or ''
        self._type = ioc_type or ''
        self._size = size or ''
        self._result = result or ''

    def to_command_results(self) -> CommandResults:
        df = pd.read_csv(StringIO(self._result), usecols=['response-time'])
        if len(df) == 0:
            max_time = 0
            avg_time = 0
            requests_num = 0
        else:
            response_times = df['response-time']
            max_time = max(response_times)
            avg_time = response_times.mean()
            requests_num = len(response_times)
        outputs = {
            'Type': self._type,
            'Size': self._size,
            "Timeout": self._t,
            "Concurrency": self._c,
            "Requests": requests_num,
            "MaxTime": max_time,
            "AverageTime": avg_time
        }
        return CommandResults(outputs=outputs, outputs_prefix="Hey.EDL")


# ---------- HELPER FUNCTIONS ---------- #

def run_command(command: str) -> str:
    """Run a bash command in the shell.

    Args:
        command (string): The string of the command you want to execute.

    Returns:
        string. The output of the command you are trying to execute.
    """
    p = Popen(command.split(), stdout=PIPE, stderr=PIPE, universal_newlines=True)
    output, err = p.communicate()
    if err:
        raise RuntimeError('Failed to run command {}\nerror details:\n{}'.format(command, err))

    return output


def hey_edl_test_command(url: str, edl_suffix: str, ioc_type: str, size: str, n: str = None, t: str = None,
                         c: str = None, z: str = None) -> CommandResults:
    edl_url = os.path.join(url, edl_suffix) + f"?q=type:{ioc_type}&n={size}"
    hey_map = assign_params(
        t=t,
        n=n,
        c=c,
        z=z + 's' if z else None
    )
    hey_query = f"hey " + " ".join(f"-{k} {v}" for k, v in hey_map.items()) + f'"{edl_url}"'
    result = run_command(hey_query)
    return EDLPerformanceResult(t, c, ioc_type, size, result).to_command_results()


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    url = params.get('url')
    if isinstance(url, str) and url.endswith("/"):
        url = url[:-1]
    try:
        demisto.debug(f'Command being called is {command}')
        if command == 'test-module':
            demisto.results('ok')
        elif command == 'hey-test-edl':
            return_results(hey_edl_test_command(url=url, **args))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

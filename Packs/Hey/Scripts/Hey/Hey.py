from io import StringIO
import subprocess
import re
from typing import Tuple

import pandas as pd
import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()


# ---------- HELPER FUNCTIONS ---------- #

def try_re(pattern: str, string: str, i: int) -> Optional[Any]:
    re_res = re.findall(pattern, string)
    if len(re_res) == i + 1:
        return re_res[i]
    return None

# ---------- CLASSES ---------- #


class HeyPerformanceResult:
    def __init__(self,
                 result: str,
                 results_map: Optional[str],
                 t: Optional[str] = None,
                 c: Optional[str] = None,
                 n: Optional[str] = None,
                 o: Optional[str] = None,
                 **args):
        self._t = int(t or 20)
        self._c = int(c or 50)
        self._n = int(n or 200)
        self._o = o
        c_in_n = self._n / self._c
        if c_in_n != int(c_in_n):
            self._n = int(c_in_n) * self._c
        self._result = result or ''
        self._ext_results_map: Dict[str, str] = {}
        if results_map:
            ext_results_map = {}
            for item in results_map.split(';'):
                if isinstance(item, str):
                    key_val = item.split('=')
                    if len(key_val) > 1:
                        ext_results_map[key_val[0]] = key_val[1]
            self._ext_results_map = ext_results_map

    @staticmethod
    def _get_summary(res: List[str]) -> Tuple[dict, int]:
        summary = {}
        i = 0
        for i in range(len(res)):
            if 'Summary' in res[i]:
                continue
            if 'Response' in res[i]:
                break
            if 'Total:' in res[i]:
                summary['TotalTime'] = try_re(r'\d+\.\d+', res[i], 0)
            if 'Slowest' in res[i]:
                summary['SlowestTime'] = try_re(r'\d+\.\d+', res[i], 0)
            if 'Fastest' in res[i]:
                summary['FastestTime'] = try_re(r'\d+\.\d+', res[i], 0)
            if 'Average' in res[i]:
                summary['AverageTime'] = try_re(r'\d+\.\d+', res[i], 0)
            if 'Requests' in res[i]:
                summary['RequestsPerSecond'] = try_re(r'\d+\.\d+', res[i], 0)
            if 'Total data' in res[i]:
                summary['TotalData'] = try_re(r'\d+ bytes', res[i], 0)
            if 'Size' in res[i]:
                summary['SizePerRequest'] = try_re(r'\d+ bytes', res[i], 0)
        return summary, i

    @staticmethod
    def _get_successful_responses(res: List[str], response_i):
        for i in range(response_i, len(res)):
            if '[200]' in res[i]:
                return try_re(r'\d+', res[i], 1) or 0
        return 0

    def human_readable_to_outputs(self):
        res = [line for line in self._result.split('\n') if line.strip() != '']
        outputs, response_i = self._get_summary(res)
        outputs['SuccessfulResponses'] = self._get_successful_responses(res, response_i)
        outputs.update({
            "TimeoutPerRequest": self._t,
            "Concurrency": self._c,
            "Requests": self._n,
        })
        if self._ext_results_map:
            outputs.update(self._ext_results_map)
        return outputs

    def to_results(self) -> CommandResults:
        outputs: Dict[str, Any]
        if self._o != 'csv':
            outputs = self.human_readable_to_outputs()
            return CommandResults(outputs=outputs, outputs_prefix="Hey", readable_output=self._result)
        df = pd.read_csv(StringIO(self._result), usecols=['response-time', 'status-code'])
        if len(df) == 0:
            max_time = 0
            avg_time = 0
            min_time = 0
            total_time = int(self._n / self._c) * self._t
            successful_responses = 0
        else:
            response_times = df['response-time']
            max_time = max(response_times)
            min_time = min(response_times)
            avg_time = response_times.mean()
            total_time = response_times.sum() / int(self._c)  # not 100% accurate
            status_codes = df.get('status-code')
            successful_responses = len(tuple(code == 200 for code in status_codes))
        outputs: Dict[str, Any] = {
            "TimeoutPerRequest": self._t,
            "Concurrency": self._c,
            "Requests": self._n,
            "SlowestTime": max_time,
            "FastestTime": min_time,
            "AverageTime": avg_time,
            "TotalTime": total_time,
            "SuccessfulResponses": successful_responses
        }
        if self._ext_results_map:
            outputs.update(self._ext_results_map)
        return CommandResults(outputs=outputs, outputs_prefix="Hey")


def run_hey_test(url: str, n: Optional[str] = None, t: Optional[str] = None, c: Optional[str] = None,
                 z: Optional[str] = None, m: Optional[str] = None, disable_compression: Optional[str] = None,
                 results_map: Optional[str] = None, output_type: Optional[str] = None) -> CommandResults:
    hey_map = assign_params(
        t=t,
        n=n,
        c=c,
        m=m,
        z=z + 's' if z else None,
        o='csv' if output_type == 'csv' else None
    )
    hey_query = "hey "
    if disable_compression == 'true':
        hey_query += '--disable-compression '
    hey_query += " ".join(f"-{k} {v}" for k, v in hey_map.items()) + f' {url}'
    result = subprocess.check_output(hey_query.split(), stderr=subprocess.STDOUT, text=True)
    return HeyPerformanceResult(result=result, results_map=results_map, **hey_map).to_results()


def main() -> None:
    args = demisto.args()
    try:
        return_results(run_hey_test(**args))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Error:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

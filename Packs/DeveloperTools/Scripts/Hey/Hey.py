import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
import subprocess

# ---------- CONSTANTS ---------- #

FLOAT_RE = r'\d+\.\d+'
INT_RE = r'\d+'
BYTES_RE = r'\d+ bytes'


# ---------- HELPER FUNCTIONS ---------- #


def try_re(pattern: str, string: str, i: int = 0) -> Optional[Any]:
    re_res = re.findall(pattern, string)
    if len(re_res) == i + 1:  # ignore cases where len is greater than expected
        return re_res[i]
    return None


def name_value_arg_to_dict(arg: Optional[str]):
    parsed_input: dict[str, str] = {}
    if arg:
        args = argToList(arg)
        for item in args:
            if isinstance(item, str):
                key_val = item.split('=')
                if len(key_val) <= 1:
                    raise DemistoException(f'Invalid arg provided {item}. expected comma separated list of "key=value"')
                else:
                    key = key_val[0]
                    val = item[len(key) + 1:]
                    parsed_input[key] = val
    return parsed_input


def construct_hey_query(url: str,
                        requests_number: Optional[str] = None,
                        timeout: Optional[str] = None,
                        concurrency: Optional[str] = None,
                        duration: Optional[str] = None,
                        method: Optional[str] = None,
                        disable_compression: Optional[str] = None,
                        headers: Optional[str] = None,
                        body: Optional[str] = None,
                        proxy: Optional[str] = None,
                        enable_http2: Optional[str] = None,
                        disable_redirects: Optional[str] = None):
    hey_map = assign_params(
        t=timeout,
        n=requests_number,
        c=concurrency,
        m=method,
        z=duration + 's' if duration else None,
        d=body,
        x=proxy
    )

    query_args = ["hey"]

    if disable_compression == 'true':
        query_args.append('--disable-compression')
    if enable_http2 == 'true':
        query_args.append('-h2')
    if disable_redirects == 'true':
        query_args.append('-disable-redirects')
    if headers:
        for header_key, header_val in name_value_arg_to_dict(headers).items():
            query_args.extend(('-H', f'{header_key}:{header_val}'))
    for k, v in hey_map.items():
        query_args.extend([f"-{k}", v])
    query_args.append(url)

    return hey_map, query_args


# ---------- CLASSES ---------- #


class HeyPerformanceResult:
    def __init__(self,
                 result: str,
                 results_map: Optional[str],
                 t: Optional[str] = None,
                 c: Optional[str] = None,
                 n: Optional[str] = None,
                 z: Optional[str] = None,
                 **args):
        self._t = int(t or 20)
        self._c = int(c or 50)
        self._z = int(z[:-1]) if z else None  # remove 's' from z before parsing int
        _n = int(n or 200)
        self._n = _n - (_n % self._c)  # remove c remainder
        self._result = result or ''
        self._ext_outputs = name_value_arg_to_dict(results_map)

    def _get_summary(self, result: List[str]) -> tuple[dict, int]:
        """Returns summary dictionary and index after the summary"""
        summary = {}
        i = 0
        for i in range(len(result)):
            if 'Summary' in result[i]:
                continue
            if 'Response' in result[i]:
                break
            if 'Total:' in result[i]:
                if self._z:
                    continue
                total_time = try_re(FLOAT_RE, result[i])
                if total_time:
                    total_time = float(total_time) / self._c
                summary['TotalTime'] = total_time
            if 'Slowest' in result[i]:
                summary['SlowestTime'] = try_re(FLOAT_RE, result[i])
            if 'Fastest' in result[i]:
                summary['FastestTime'] = try_re(FLOAT_RE, result[i])
            if 'Average' in result[i]:
                summary['AverageTime'] = try_re(FLOAT_RE, result[i])
            if 'Requests' in result[i]:
                summary['RequestsPerSecond'] = try_re(FLOAT_RE, result[i])
            if 'Total data' in result[i]:
                summary['TotalData'] = try_re(BYTES_RE, result[i])
            if 'Size' in result[i]:
                summary['SizePerRequest'] = try_re(BYTES_RE, result[i])
        return summary, i

    @staticmethod
    def _get_successful_responses(result: List[str], result_i: int) -> int:
        """Returns number of successful responses in the result"""
        for i in range(result_i, len(result)):
            if '[200]' in result[i]:
                return try_re(INT_RE, result[i], 1) or 0
        return 0

    def human_readable_to_outputs(self):
        result = [line for line in self._result.split('\n') if line.strip() != '']
        outputs, response_i = self._get_summary(result)
        outputs['SuccessfulResponses'] = self._get_successful_responses(result, response_i)
        outputs.update({
            "TimeoutPerRequest": self._t,
            "Concurrency": self._c,
            "Requests": self._n,
        })
        if self._ext_outputs:
            outputs.update(self._ext_outputs)
        return outputs

    def to_results(self) -> CommandResults:
        outputs = self.human_readable_to_outputs()
        if self._z:
            outputs['TotalTime'] = self._z
        return CommandResults(outputs=outputs, outputs_prefix="Hey", readable_output=self._result)


def run_hey_test(url: str,
                 requests_number: Optional[str] = None,
                 timeout: Optional[str] = None,
                 concurrency: Optional[str] = None,
                 duration: Optional[str] = None,
                 method: Optional[str] = None,
                 disable_compression: Optional[str] = None,
                 results_map: Optional[str] = None,
                 headers: Optional[str] = None,
                 body: Optional[str] = None,
                 proxy: Optional[str] = None,
                 enable_http2: Optional[str] = None,
                 disable_redirects: Optional[str] = None,
                 *_args, **_kwargs) -> CommandResults:
    hey_map, hey_query = construct_hey_query(url,
                                             requests_number,
                                             timeout,
                                             concurrency,
                                             duration,
                                             method,
                                             disable_compression,
                                             headers,
                                             body,
                                             proxy,
                                             enable_http2,
                                             disable_redirects)
    result = subprocess.check_output(hey_query, stderr=subprocess.STDOUT, text=True)
    return HeyPerformanceResult(result=result, results_map=results_map, **hey_map).to_results()


def main() -> None:  # pragma: no cover
    args = demisto.args()
    try:
        return_results(run_hey_test(**args))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Error:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

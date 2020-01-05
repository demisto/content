import demistomock as demisto
from CommonServerPython import *

from multiprocessing import Process
import resource
import re
import time


def big_string(size):
    s = 'a' * 1024
    while len(s) < size:
        s = s * 2
    return len(s)


def mem_size_to_bytes(mem: str) -> int:
    res = re.match(r'(\d+)\s*([gm])?b?', mem, re.IGNORECASE)
    if not res:
        raise ValueError("Failed parsing memory string: {}".format(mem))
    b = int(res.group(1))
    if res.group(2):
        b = b * 1024 * 1024  # convert to mega byte
        if res.group(2).lower() == 'g':
            b = b * 1024  # convert to giga
    return b


def check_memory(target_mem: str) -> str:
    """Check allocating memory

    Arguments:
        target_mem {str} -- target memory size. Can specify as 1g 1m and so on

    Returns:
        str -- error string if failed
    """
    size = mem_size_to_bytes(target_mem)
    LOG("starting process to check memory of size: {}".format(size))
    p = Process(target=big_string, args=(size, ))
    p.start()
    p.join()
    LOG("memory intensive process status code: {}".format(p.exitcode))
    if p.exitcode == 0:
        return ("Succeeded allocating memory of size: {}. "
                "It seems that you haven't limited the available memory to the docker container.".format(target_mem))
    return ""


def check_pids(pid_num: int) -> str:
    LOG("Starting pid check for: {}".format(pid_num))
    processes = [Process(target=time.sleep, args=(5, )) for i in range(pid_num)]
    try:
        for p in processes:
            p.start()
        return ("Succeeded creating processs of size: {}. "
                "It seems that you haven't limited the available pids to the docker container.".format(pid_num))
    except Exception as ex:
        LOG("Pool startup failed (as expected): {}".format(ex))
    finally:
        for p in processes:
            if p.is_alive():
                p.terminate()
                p.join()
    return ""


def check_fd_limits(soft, hard) -> str:
    s, h = resource.getrlimit(resource.RLIMIT_NOFILE)
    if s > soft:
        return "FD soft limit: {} is above desired limt: {}.".format(s, soft)
    if h > hard:
        return "FD hard limit: {} is above desired limit: {}.".format(h, hard)
    return ""


def check_non_root():
    uid = os.getuid()
    if uid == 0:
        return ("Running as root with uid: {}."
                " It seems that you haven't set the docker container to run with a non-root internal user.".format(uid))
    return ""


def intensive_calc(iter: int):
    i = 0
    x = 1
    while i < iter:
        x = x * 2
        i += 1
    return x


def check_cpus(num_cpus: int) -> str:
    iterval = 500 * 1000
    processes = [Process(target=intensive_calc, args=(iterval, )) for i in range(num_cpus)]
    start = time.time_ns()
    for p in processes:
        p.start()
    for p in processes:
        p.join()
    runtime = time.time_ns() - start
    LOG("cpus check runtime for {} processes time: {}".format(num_cpus, runtime))
    processes = [Process(target=intensive_calc, args=(iterval, )) for i in range(num_cpus * 2)]
    start = time.time_ns()
    for p in processes:
        p.start()
    for p in processes:
        p.join()
    runtime2 = time.time_ns() - start
    p.close()
    # runtime 2 should be 2 times slower. But we give it a safet
    LOG("cpus check runtime for {} processes time: {}".format(num_cpus * 2, runtime2))
    if runtime2 < runtime * 1.8:
        return ("CPU processing power increased significantly when increasing processes "
                "from: {} (time: {}) to: {} (time: {}).".format(num_cpus, runtime, num_cpus * 2, runtime2))
    return ""


def main():
    mem = demisto.args().get('memory', "1g")
    pids = int(demisto.args().get('pids', 256))
    fds_soft = int(demisto.args().get('fds_soft', 1024))
    fds_hard = int(demisto.args().get('fds_hard', 8192))
    cpus = int(demisto.args().get('cpus', 1))
    success = "Success"
    check = "Check"
    status = "Status"
    res = [
        {
            check: "Non-root User",
            status: check_non_root() or success,
        },
        {
            check: "Memory",
            status: check_memory(mem) or success,
        },
        {
            check: "File Descriptors",
            status: check_fd_limits(fds_soft, fds_hard) or success,
        },
        {
            check: "CPUs",
            status: check_cpus(cpus) or success,
        },
        {
            check: "PIDs",
            status: check_pids(pids) or success,
        },
    ]
    failed = False
    for v in res:
        if v[status] != success:
            failed = True
            v[status] = "Failed: " + v[status]
    table = tableToMarkdown("Docker Hardening Results Check", res, [check, status])
    return_outputs(table)
    if failed:
        return_error("Failed verifying docker hardening. "
                     "More details at: https://support.demisto.com/hc/en-us/articles/360040922194")


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

import json

import demistomock as demisto

# The test drives the real tshark binary through pyshark.FileCapture. Under the
# pytest-asyncio event loop, pyshark's asyncio subprocess teardown is occasionally
# racy and tshark is observed exiting with a non-zero code (retcode 255) having read
# 0 packets. When that happens the script escalates it to return_error -> SystemExit.
# This is a non-deterministic environment flake (the same input parses correctly on
# retry), so we retry the run a few times before treating it as a real failure.
MAX_TSHARK_ATTEMPTS = 5


def equals_object(obj1, obj2) -> bool:
    if type(obj1) is not type(obj2):
        return False
    elif isinstance(obj1, dict):
        for k1, v1 in obj1.items():
            if k1 not in obj2:
                return False
            if not equals_object(v1, obj2[k1]):
                return False
        return not (set(obj1.keys()) ^ set(obj2.keys()))
    elif isinstance(obj1, list):
        # Compare lists (ignore order)
        list2 = list(obj2)
        for _i1, v1 in enumerate(obj1):
            for i2, v2 in enumerate(list2):
                if equals_object(v1, v2):
                    list2.pop(i2)
                    break
            else:
                return False
        return not list2
    else:
        return obj1 == obj2


def side_effect_demisto_getFilePath(entry_id):
    return {"path": entry_id}


def _run_main_with_retry(mocker):
    """
    Run main() and return the results entry, retrying on the flaky tshark
    subprocess teardown crash (surfaced as SystemExit via return_error).
    """
    from PcapFileExtractStreams import main

    last_error = None
    for _attempt in range(MAX_TSHARK_ATTEMPTS):
        results_mock = mocker.patch.object(demisto, "results")
        try:
            main()
        except SystemExit as e:
            # return_error() exits with code 0 after posting an error entry.
            # Inspect the posted entry to distinguish the flaky tshark crash from
            # a genuine failure.
            last_error = ""
            if results_mock.call_args:
                entry = results_mock.call_args[0][0]
                last_error = str(entry.get("Contents", "")) if isinstance(entry, dict) else str(entry)
            if "Could not find packets" in last_error:
                # Flaky tshark teardown - reset the mock and retry.
                continue
            raise AssertionError(f"main() exited unexpectedly: {last_error}") from e
        else:
            return results_mock

    raise AssertionError(
        f"tshark repeatedly crashed after {MAX_TSHARK_ATTEMPTS} attempts (flaky pyshark/tshark teardown). "
        f"Last error: {last_error}"
    )


def test_main(mocker):
    """
    Given:
    - PCAP files are given with control parameters

    When:
    - Running PcapFileExtractStreams

    Then:
    - Validate results output that returned to CortexSOAR
    """
    mocker.patch.object(demisto, "getFilePath", side_effect=side_effect_demisto_getFilePath)

    with open("./test_data/test-1.json") as f:
        test_list = json.load(f)

    for t in test_list:
        mocker.patch.object(
            demisto,
            "args",
            return_value={
                "entry_id": t["entry_id"],
                "bin2txt_mode": t.get("bin2txt_mode"),
                "pcap_filter": t.get("pcap_filter"),
                "rsa_decrypt_key": t.get("rsa_decrypt_key"),
                "wpa_password": t.get("wpa_password"),
                "filter_keys": t.get("filter_keys"),
                "verbose": t.get("verbose"),
                "server_ports": t.get("server_ports"),
            },
        )
        results_mock = _run_main_with_retry(mocker)
        assert results_mock.call_count == 1

        results = results_mock.call_args[0][0]
        contents = results["Contents"]
        assert equals_object(contents, t["contents"])

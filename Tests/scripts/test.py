import sys
sys.path.append('../../Packs/Whois/Integrations/Whois')
import datetime
import json
import pathlib
import pickle
import socket
from typing import Any
import tempfile
import ipwhois
import pytest
import Whois
from pytest_mock import MockerFixture
from Whois import (
    WhoisInvalidDomain,
    domain_command,
    get_domain_from_query,
    get_root_server,
    increment_metric,
    ip_command,
    ipwhois_exception_mapping,
    whois_command,
    whois_exception_mapping,
)

import demistomock as demisto
from CommonServerPython import DBotScoreReliability, EntryType, ErrorTypes, ExecutionMetrics


def assert_results_ok():
    assert demisto.results.call_count == 1  # type: ignore
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]  # type: ignore
    assert len(results) == 1
    assert results[0] == 'ok'


def test_socks_proxy(mocker, request):
    mocker.patch.object(demisto, 'params', return_value={'proxy_url': 'socks5h://localhost:9980'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')
    tmp = tempfile.TemporaryFile('w+')
    microsocks = './test_data/microsocks_darwin' if 'darwin' in sys.platform else './test_data/microsocks'
    process = subprocess.Popen([microsocks, "-p", "9980"], stderr=subprocess.STDOUT, stdout=tmp)

    def cleanup():
        process.kill()

    request.addfinalizer(cleanup)
    time.sleep(1)
    Whois.main()
    assert_results_ok()
    tmp.seek(0)
    assert 'connected to' in tmp.read()  # make sure we went through microsoc

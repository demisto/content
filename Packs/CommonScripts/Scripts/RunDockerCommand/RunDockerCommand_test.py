import subprocess
from RunDockerCommand import main
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_run_docker_command(mocker):
    mocker.patch.object(demisto, 'args', return_value={
        "cmd": 'echo hi'
    })
    mocker.patch.object(subprocess, 'check_output', return_value=b'hi')
    mocker.patch.object(demisto, 'results')

    main()
    contents = demisto.results.call_args[0][0]
    assert 'hi' in contents.get('EntryContext', {}).get('CommandResults', {}).get('Results')

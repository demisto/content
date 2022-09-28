import pytest
import demistomock as demisto  # noqa: F401
from RegPathReputationBasicLists import main

LIST_ARGS = [
    (r'HKEY_CURRENT_USER\Software\Locky', 3),
    (r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", 2),
    (r'HKEY_LOCAL_MACHINE\Software\wow6432node\Microsoft\Windows\CurrentVersion\Run\vmware-tray.exe', 1),
    (r'test', 0)
]


@pytest.mark.parametrize('reg_path, score', LIST_ARGS)
def test_mimecast_find_email(reg_path, score, mocker):
    mocker.patch.object(demisto, 'args', return_value={'input': reg_path})
    mocker.patch.object(demisto, 'results')

    main()
    results = demisto.results.call_args[0][0]

    assert results.get('HumanReadable') == "The Registry Path reputation for: {} is: {}".format(reg_path.upper(), score)
    assert results.get('Contents') == score

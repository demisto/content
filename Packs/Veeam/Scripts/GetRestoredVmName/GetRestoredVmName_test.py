import pytest
import demistomock as demisto
from GetRestoredVmName import get_restored_vm_name, main
from freezegun import freeze_time


@freeze_time("2022-01-01 12:34:56")
def test_get_restored_vm_name():
    vm_name = "my_vm"
    expected_result = vm_name + "_VeeamAPA_220101123456"

    assert get_restored_vm_name(vm_name) == expected_result


@pytest.mark.parametrize(
    "args, returned_value, expected_command_results",
    [
        (
            {
                'VmName': 'vm_name'
            },
            'vm_name_VeeamAPA_220101123456',
            {
                'outputs_prefix': 'Veeam.VMNAME',
                'outputs': {'restored_vm_name': 'vm_name_VeeamAPA_220101123456'}
            }
        )
    ]
)
def test_main(mocker, args, returned_value, expected_command_results):
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch('GetRestoredVmName.get_restored_vm_name', return_value=returned_value)
    mock_return_results = mocker.patch('GetRestoredVmName.return_results')
    main()
    mock_return_results.assert_called_once()
    command_results = mock_return_results.call_args[0][0]
    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs == expected_command_results['outputs']

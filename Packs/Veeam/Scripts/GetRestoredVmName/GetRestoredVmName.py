import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime


def get_restored_vm_name(vm_name: str) -> str:
    time_now = datetime.now().strftime('%y%m%d%H%M%S')
    restored_vm_name = vm_name + '_VeeamAPA_' + time_now

    return restored_vm_name


def main() -> None:
    try:
        args = demisto.args()
        vm_name = args.get('VmName', '')

        restored_vm_name = get_restored_vm_name(vm_name)
        result = {'restored_vm_name': restored_vm_name}

        command_results = CommandResults(
            outputs_prefix='Veeam.VMNAME',
            outputs=result
        )
        return_results(command_results)

    except Exception as e:
        return_error(str(e))


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

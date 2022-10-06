from GridFieldSetup import *


def test_command(mocker):
    args = {'keys': 'IP,SRC', 'val1': '1.1.1.1', 'val2': 'AWS', 'context_path': 'temp'}
    entry = grid_field_setup_command(args)
    assert entry.outputs == [{'IP': '1.1.1.1', 'SRC': 'AWS'}]
    assert entry.outputs_prefix == args['context_path']

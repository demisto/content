from ProofpointTapTopClickers import main
import demistomock as demisto

def test_default_value(mocker):
    mocker.patch.object(demisto, 'executeCommand', return_value= \
        [{'Contents': "Unsupported Command proofpoint-get-top-clickers"}])
    return_results_mock = mocker.patch('ProofpointTapTopClickers.return_results')
    main()
    assert return_results_mock.call_args.args[0] == '[{"name": "", "data": [], "color": ""}]'
    
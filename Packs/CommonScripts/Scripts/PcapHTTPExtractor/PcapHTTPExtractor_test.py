import demistomock as demisto
import PcapHTTPExtractor


def open_file(path):
    with open(path) as f:
        return f.read()


def test_PcapHTTPExtractor(mocker):

    mocker.patch.object(demisto, 'args',
                        return_value={"entryID": "6@1", "limit": "50", "start": "0", "limitData": "512"})
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=[{'Contents': {'path': 'test_data/TestPcapPost.pcap'}, 'Type': ''}])
    demisto_res = mocker.patch.object(demisto, 'results')
    PcapHTTPExtractor.main()

    args_to_demisto_res = demisto_res.call_args.args[0]
    assert len(args_to_demisto_res.get('EntryContext', {}).get('PcapHTTPFlows', {})) == 2

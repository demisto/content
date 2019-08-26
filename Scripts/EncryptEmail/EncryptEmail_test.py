import demistomock as demisto


def test_encrypt_body(mocker):
    from EncryptEmail import main

    mocker.patch.object(demisto, 'args', return_value={'message': 'testing script'})
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './TestData/public.pem'})
    mocker.patch.object(demisto, 'results')

    main()

    demisto.results.call_args[0][0]







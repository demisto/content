import demistomock as demisto
import SanePdfReport
from SanePdfReport import *
import subprocess
import os
import http.client


def test_find_zombie_processes(mocker):
    ps_output = '''   PID  PPID S CMD
    1     0 S python /tmp/pyrunner/_script_docker_python_loop.py
   39     1 Z [soffice.bin] <defunct>
   55     1 Z [gpgconf] <defunct>
   57     1 Z [gpgconf] <defunct>Packs/Base/ReleaseNotes/1_3_20.md
   59     1 Z [gpg] <defunct>
   61     1 Z [gpgsm] <defunct>
   63     1 Z [gpgconf] <defunct>
   98     1 Z [gpgconf] <defunct>
  100     1 Z [gpgconf] <defunct>
  102     1 Z [gpg] <defunct>
'''
    mocker.patch.object(subprocess, 'check_output', return_value=ps_output)
    mocker.patch.object(os, 'getpid', return_value=1)
    zombies, output = find_zombie_processes()

    assert len(zombies) == 9
    assert output == ps_output


def test_sane_pdf_report(mocker):
    import SanePdfReport
    # changing the port number just to make sure it has no conflicts with other integrations/scripts
    mocker.patch.object(SanePdfReport, 'MD_HTTP_PORT', 10889)
    mocker.patch.object(demisto, 'args', return_value={
        'sane_pdf_report_base64':
        'W3sidHlwZSI6Im1hcmtkb3duIiwiZGF0YSI6eyJ0ZXh0IjoiaGVsbG8gd29ybGQiLCJncm91cHMiOlt7Im5hbWUiOiIiLCJkYXRhIjpbMl0s'
        'Imdyb3VwcyI6bnVsbCwiY291bnQiOjIsImZsb2F0RGF0YSI6WzJdfV19LCJsYXlvdXQiOnsiY29sdW1uUG9zIjowLCJoIjoxLCJpIjoiYjRm'
        'YzAzYTAtMTZhMi0xMWViLWFhNmUtOTMzMWU5NjVhYjA2Iiwicm93UG9zIjowLCJ3Ijo2fSwicXVlcnkiOnsidHlwZSI6ImluY2lkZW50Iiwi'
        'ZmlsdGVyIjp7InF1ZXJ5IjoiIiwicGVyaW9kIjp7ImJ5RnJvbSI6ImRheXMiLCJmcm9tVmFsdWUiOjd9fX0sImF1dG9tYXRpb24iOnsibmFt'
        'ZSI6IiIsImlkIjoiIiwiYXJncyI6bnVsbCwibm9FdmVudCI6ZmFsc2V9LCJmcm9tRGF0ZSI6IjIwMjAtMTAtMThUMTE6MTY6MzcrMDM6MDAi'
        'LCJ0aXRsZSI6IlRleHQgV2lkZ2V0IiwiZW1wdHlOb3RpZmljYXRpb24iOiJObyByZXN1bHRzIGZvdW5kIiwidGl0bGVTdHlsZSI6bnVsbH1d',
        'resourceTimeout': "60000"
    })
    mocker.patch.object(demisto, 'results')

    main()

    assert demisto.results.call_args[0][0]['HumanReadable'] == 'Successfully generated pdf'
    assert demisto.results.call_args[0][0]['Contents']


def test_markdown_image_server(mocker, capfd):
    from SanePdfReport import MD_HTTP_PORT
    with capfd.disabled():
        mocker.patch.object(demisto, 'results')
        fileName = '1234-5678-9012-3456.png'
        path = f'./TestData/{fileName}'
        mocker.patch.object(demisto, 'getFilePath', return_value={'path': path, 'name': fileName})
        mocker.patch.object(SanePdfReport, 'is_demisto_version_ge', return_value=True)

        serverThread = threading.Thread(target=startServer)
        serverThread.daemon = True
        serverThread.start()
        time.sleep(5)

        # wrong path
        conn = http.client.HTTPConnection("localhost", MD_HTTP_PORT)
        conn.request("GET", "/wrong/path")
        res1 = conn.getresponse()
        assert res1.status == 400

        # correct markdown image pat
        conn.request("GET", "/xsoar/markdown/image/1234-5678-9012-3456.png")     # Test for XSOAR 8
        res2 = conn.getresponse()
        assert res2.status == 200
        mocker.patch.object(SanePdfReport, 'is_demisto_version_ge', return_value=False)
        conn.request("GET", "/markdown/image/1234-5678-9012-3456.png")      # Test for XSOAR 6
        res2 = conn.getresponse()
        assert res2.status == 200

        # correct markdown image path with missing file
        mocker.patch.object(demisto, 'getFilePath', return_value={'path': '', 'name': ''})
        conn.request("GET", "/markdown/image/dummyFile.png")
        res3 = conn.getresponse()
        assert res3.status == 404

        # correct image with file that is not accessible (simulates permission problems)
        mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'notfound.png', 'name': 'noutfound.png'})
        conn.request("GET", "/markdown/image/dummyFile.png")
        res3 = conn.getresponse()
        assert res3.status == 404

        conn.close()
        quit_driver_and_reap_children(True)

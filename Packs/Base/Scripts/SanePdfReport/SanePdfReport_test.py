import demistomock as demisto
from SanePdfReport import *
import subprocess
import os


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
    mocker.patch.object(demisto, 'args', return_value={
        'sane_pdf_report_base64':
        'W3sidHlwZSI6Im1hcmtkb3duIiwiZGF0YSI6eyJ0ZXh0IjoiaGVsbG8gd29ybGQiLCJncm91cHMiOlt7Im5hbWUiOiIiLCJkYXRhIjpbMl0s'
        'Imdyb3VwcyI6bnVsbCwiY291bnQiOjIsImZsb2F0RGF0YSI6WzJdfV19LCJsYXlvdXQiOnsiY29sdW1uUG9zIjowLCJoIjoxLCJpIjoiYjRm'
        'YzAzYTAtMTZhMi0xMWViLWFhNmUtOTMzMWU5NjVhYjA2Iiwicm93UG9zIjowLCJ3Ijo2fSwicXVlcnkiOnsidHlwZSI6ImluY2lkZW50Iiwi'
        'ZmlsdGVyIjp7InF1ZXJ5IjoiIiwicGVyaW9kIjp7ImJ5RnJvbSI6ImRheXMiLCJmcm9tVmFsdWUiOjd9fX0sImF1dG9tYXRpb24iOnsibmFt'
        'ZSI6IiIsImlkIjoiIiwiYXJncyI6bnVsbCwibm9FdmVudCI6ZmFsc2V9LCJmcm9tRGF0ZSI6IjIwMjAtMTAtMThUMTE6MTY6MzcrMDM6MDAi'
        'LCJ0aXRsZSI6IlRleHQgV2lkZ2V0IiwiZW1wdHlOb3RpZmljYXRpb24iOiJObyByZXN1bHRzIGZvdW5kIiwidGl0bGVTdHlsZSI6bnVsbH1d'
    })
    mocker.patch.object(demisto, 'results')

    main()

    assert demisto.results.call_args[0][0]['HumanReadable'] == 'Successfully generated pdf'
    assert demisto.results.call_args[0][0]['Contents']

    zombies, output = find_zombie_processes()
    assert len(zombies) == 0

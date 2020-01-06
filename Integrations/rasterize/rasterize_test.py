from rasterize import *
from tempfile import NamedTemporaryFile
import subprocess
import os


def test_rasterize_email_image(caplog):
    with NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        rasterize(path=f'file://{path}', width=250, height=250, r_type='png')
        caplog.clear()


def test_rasterize_email_pdf(caplog):
    with NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        rasterize(path=f'file://{path}', width=250, height=250, r_type='pdf', offline_mode=False)
        caplog.clear()


def test_rasterize_email_pdf_offline(caplog):
    with NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        rasterize(path=f'file://{path}', width=250, height=250, r_type='pdf', offline_mode=True)
        caplog.clear()


def test_rasterize_no_defunct_processes(caplog):
    with NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        rasterize(path=f'file://{path}', width=250, height=250, r_type='pdf', offline_mode=False)
        process = subprocess.Popen(['ps', '-aux'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True)
        processes_str, _ = process.communicate()
        processes = processes_str.split('\n')
        defunct_process_list = [process for process in processes if 'defunct' in process]
        assert not defunct_process_list

        zombies, output = find_zombie_processes()
        assert not zombies
        assert 'defunct' not in output
        caplog.clear()


def test_find_zombie_processes(mocker):
    ps_output = '''   PID  PPID S CMD
    1     0 S python /tmp/pyrunner/_script_docker_python_loop.py
   39     1 Z [soffice.bin] <defunct>
   55     1 Z [gpgconf] <defunct>
   57     1 Z [gpgconf] <defunct>
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

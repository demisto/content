from rasterize import *
from tempfile import NamedTemporaryFile
from subprocess import *
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
        process = Popen(['ps', '-aux'], stdout=PIPE, stderr=PIPE, universal_newlines=True)
        processes_str, _ = process.communicate()
        processes = processes_str.split('\n')
        defunct_process_list = [process for process in processes if 'defunct' in process]
        assert not defunct_process_list
        caplog.clear()

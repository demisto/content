from rasterize import *
from tempfile import NamedTemporaryFile
import os


def test_rasterize_email_image():
    with NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        rasterize(path=f'file://{path}', width=250, height=250, r_type='png')


def test_rasterize_email_pdf():
    with NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        rasterize(path=f'file://{path}', width=250, height=250, r_type='pdf', offline_mode=False)


def test_rasterize_email_pdf_offline():
    with NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        rasterize(path=f'file://{path}', width=250, height=250, r_type='pdf', offline_mode=True)

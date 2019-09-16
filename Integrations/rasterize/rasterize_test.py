from rasterize import *
import os


def test_rasterize_email_image():
    with open('emailHtmlBody2.html', 'w') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
    rasterize(
        path=f'file://{path}',
        width=1000,
        height=1000,
        r_type='png'
    )
    os.remove(path)


def test_rasterize_email_pdf():
    with open('emailHtmlBody1.html', 'w') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
    rasterize(
        path=f'file://{path}',
        width=1000,
        height=1000,
        r_type='pdf'
    )
    os.remove(path)

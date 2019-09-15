from rasterize import *
import os


def test_rasterize_email_image():
    with open('emailHtmlBody2.html', 'w+') as f:
        f.write("""<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        </head><body><br>---------- TEST FILE ----------<br></body></html>""")
        path = os.path.realpath(f.name)
        output = rasterize(
            path=f'file://{path}',
            width=1000,
            height=1000,
            r_type='png'
        )
    os.remove(path)
    expected = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x03\xe8\x00\x00\x03\xe8\x08\x06\x00\x00\x00M' \
               b'\xa3\xd4\xe4\x00\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9\x00\x00\x18\tIDATx' \
               b'\x9c\xed\xd71\x01\x00 \x0c\xc00\xc0\xbf\xe7!c=\x12\x05}{gf\x0e\x00\x00\x00\xb0\xeam' \
               b'\x07\x00\x00\x00\x00\x06\x1d\x00\x00\x00\x12\x0c:\x00\x00\x00'
    print("*********" * 10)
    print('test_rasterize_email_image')
    print("*********" * 10)
    print(output[output.find(b'stream'): output.find(b'stream') + 100])
    print("*********" * 10)
    assert expected in output


def test_rasterize_url_image():
    output = rasterize(
        path='https://google.com',
        width=1000,
        height=1000,
        r_type='png'
    )

    expected = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x03\xe8\x00\x00\x03\xe8\x08\x06\x00\x00\x00M' \
               b'\xa3\xd4\xe4\x00\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9\x00\x00 \x00IDATx\x9c\xec\xddy|T' \
               b'\xe5\xa1\xff\xf1\xef9\xb3f\x0f\x84\x1d\x82\x08\xca&\xa2 "\xa2\xe2\x82\xa8\x88[\xdd\xea\xd2\xd5n' \
               b'\xb6\xb6\xd6\xf6^\xeb\xaf\xeau_'
    print("*********" * 10)
    print('test_rasterize_url_image')
    print("*********" * 10)
    print(output[output.find(b'stream'): output.find(b'stream') + 100])
    print("*********" * 10)
    assert expected in output


def test_rasterize_email_pdf():
    with open('emailHtmlBody1.html', 'w+') as f:
        f.write("""<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        </head><body><br>---------- TEST FILE ----------<br></body></html>""")
        path = os.path.realpath(f.name)
        output = rasterize(
            path=f'file://{path}',
            width=1000,
            height=1000,
            r_type='pdf'
        )
    os.remove(path)
    print("*********" * 10)
    print('test_rasterize_email_pdf')
    print("*********" * 10)
    print(output[output.find(b'stream'): output.find(b'stream') + 100])
    print("*********" * 10)
    assert expected in output


def test_rasterize_url_pdf():
    output = rasterize(
        path='https://google.com',
        width=1000,
        height=1000,
        r_type='pdf'
    )

    expected = b"stream\nx\x9c\xed]\xebs[\xc7u\x87H\x8ar\xfa\x1f\xd4\x9ei-*\x95\x12YJD\xe2AI\x14\x85\xbb\xf7^@T-w" \
               b"\xaa$\xb4f:\xfd\x10\xff'0\xee\x05@J\x8ej\xfbC\x93\xce\xf4K\xed\xcc\xb4\xe3\x89\x9ci" \
               b"\xf3\xb2\xf8\xb0j+\xcd\x97\xa83M\xf3\xb1M\xfa!\x8e\x88\x07%\xe2\r\x82\x00\xe7\xf6\x9c"
    print("*********" * 10)
    print('test_rasterize_url_pdf')
    print("*********" * 10)
    print(output[output.find(b'stream'): output.find(b'stream') + 100])
    print("*********" * 10)
    assert expected in output[output.find(b'stream'):output.find(b'stream') + 100]

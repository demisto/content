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
    print(output[:100])
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
    print(output[:100])
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
    expected = b'stream\nx\x9cm\x8d\xb1\x0e\xc20\x10C\xf7\xfb\n\xcfH\x1c\xb9s\x94K\xbe\xa03,|\x00\x82N Q\xfe_"i' \
               b'\x07:\xe0\xb7\xd8\x83mu\xb6UH\x9d\xa3\xeeb4\xc7\xed)o1+Z\x862v\xd6\xe9I+I0' \
               b'\x95\xaa\x8c\x96\xb1\xdc\xe5z\xc0\xabw\xa8\xe6QS\x94u\xf7\x97\xfeo\xf5\x1b\xc3\xe02a'

    assert expected in output


def test_rasterize_url_pdf():
    output = rasterize(
        path='https://google.com',
        width=1000,
        height=1000,
        r_type='pdf'
    )

    expected = b'stream\nx\x9c+\xe42\xd236\xb30\xb447R0\x00B\x04O\xd7\xc8X\xcf\x18\x04\xcc\x14tMM`\xcc\xe4\\.}wc' \
               b'\x85\xf4b.\xa7\x10.}7\x13\x05Cc\x85\x904.C\xb0f]C\x05#S\x05cS\x85\x90\\.\x1b\x03\x03#\x13;\x85\x90,.' \
               b'K\xa0LH\x8a\x02P\xc0\xc4\x14,`\x0e'

    assert expected in output[output.find(b'stream'):output.find(b'stream') + 100]

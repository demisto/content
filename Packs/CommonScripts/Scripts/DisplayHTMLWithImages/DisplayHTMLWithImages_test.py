import demistomock as demisto
import pytest

EMAIL_HTML = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src="cid:ii_kgjzy6yh0" alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src="cid:ii_kgjzygxz1" alt="image_2.png" width="225" height="224"><br></div></div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Some Person &lt;
<a href="mailto:some.person@demistodev.onmicrosoft.com">some.person@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""

EMAIL_HTML_NO_ALT = """
<html><head>

<meta http-equiv="Content-Type" content="text/html; charset=utf-8"><style type="text/css" style="display:none">

<!–

p

    {margin-top:0;

    margin-bottom:0}

–>

</style></head>
<body dir="ltr"><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="178792" data-outlook-trace="F:1|T:1" src="cid:89593b98-b18d-46aa-ba4f-26773138c3f7" style="max-width:100%">
</div><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="8023" data-outlook-trace="F:1|T:1" src="cid:6a65eb70-7748-4bba-aaac-fe93235f63bd" style="max-width:100%">
</div></body></html>
"""

EXPECTED_RESULT_1 = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src=/entry/download/37@119 alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src=/entry/download/38@120 alt="image_2.png" width="225" height="224"><br></div></div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Some Person &lt;
<a href="mailto:some.person@demistodev.onmicrosoft.com">some.person@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""

EXPECTED_RESULT_2 = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src=acc_test_tenant/entry/download/37@119 alt="image_1.png" width="275" height="184"><br></div></div>\
<div>image 2:
</div><div><div><img src=acc_test_tenant/entry/download/38@120 alt="image_2.png" width="225" height="224"><br></div>\
</div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Some Person &lt;
<a href="mailto:some.person@demistodev.onmicrosoft.com">some.person@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""

EXPECTED_RESULT_NO_ALT = """
<html><head>

<meta http-equiv="Content-Type" content="text/html; charset=utf-8"><style type="text/css" style="display:none">

<!–

p

    {margin-top:0;

    margin-bottom:0}

–>

</style></head>
<body dir="ltr"><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="178792" data-outlook-trace="F:1|T:1" src=acc_test_tenant/entry/download/37@119 style="max-width:100%">
</div><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="8023" data-outlook-trace="F:1|T:1" src=acc_test_tenant/entry/download/38@120 style="max-width:100%">
</div></body></html>
"""


@pytest.mark.parametrize(
    "email_html,expected",
    [
        (EMAIL_HTML, EXPECTED_RESULT_2),
        (EMAIL_HTML_NO_ALT, EXPECTED_RESULT_NO_ALT)
    ]
)
def test_main_mt(mocker, email_html, expected):
    """
        Given
        - Html contained images src
        When
        - All images were uploaded to the server
        Then
        - The images' src attribute would be replaced as expected with account tenant name
    """
    import DisplayHTMLWithImages
    from DisplayHTMLWithImages import main

    mocked_incident = {
        'CustomFields': {
            'emailbody': email_html
        },
        'attachment': [
            {'name': 'image_1.png'},
            {'name': 'image_2.png'}
        ]
    }
    mocked_files = [
        {'Name': 'image_1.png', 'EntryID': '37@119'},
        {'Name': 'image_2.png', 'EntryID': '38@120'}
    ]

    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://localhost:8443:/acc_test_tenant'})
    mocker.patch.object(demisto, 'incident', return_value=mocked_incident)
    mocker.patch.object(demisto, 'context', return_value={'File': mocked_files})
    mocker.patch.object(DisplayHTMLWithImages, 'return_results')

    main({})

    assert expected in DisplayHTMLWithImages.return_results.call_args[0][0]['Contents']

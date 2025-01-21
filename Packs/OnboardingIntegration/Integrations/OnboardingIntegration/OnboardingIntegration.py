import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
'''IMPORTS'''
from faker import Faker
from faker.providers import internet, misc, lorem, user_agent
from datetime import datetime
import json
import random
import math
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

'''SETUP'''
fake = Faker()
fake.add_provider(internet)
fake.add_provider(misc)
fake.add_provider(lorem)
fake.add_provider(user_agent)

'''GLOBAL VARS'''
PARAMS = demisto.params()
INCIDENT_TYPE = PARAMS.get('incidentType', 'PhishingDemo')
INCIDENTS_PER_MINUTE = int(PARAMS.get('incidents_per_minute', '5'))
MAX_NUM_OF_INCIDENTS = int(PARAMS.get('max_num_of_incidents', '10'))
FREQUENCY = PARAMS.get('frequency')
INDICATORS_PER_INCIDENT = 5
INDICATORS_TO_INCLUDE = ['ipv4_public', 'url', 'domain_name', 'sha1', 'sha256', 'md5']
EMAIL_PROTOCOLS = ['POP3', 'IMAP', 'SMTP', 'ESMTP', 'HTTP', 'HTTPS']
# About the drop some mean regex right now disable-secrets-detection-start
TEMPLATE_1 = '''<!doctype html>
<html>

<head>
  <meta name="viewport" content="width=device-width">
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>Simple Transactional Email</title>
</head>

<body class=""
  style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased; -webkit-text-size-adjust:100%;
        background-color:#f6f6f6; font-family:sans-serif; font-size:14px; line-height:1.4; margin:0; padding:0"
  bgcolor="#f6f6f6">
  <span class="preheader"
    style="color:transparent; display:none; height:0; max-height:0; max-width:0; mso-hide:all; opacity:0;
          overflow:hidden; visibility:hidden; width:0"
    height="0" width="0">This is preheader text. Some clients will show this
    text as a preview.</span>
  <table role="presentation" border="0" cellpadding="0" cellspacing="0"
    class="body"
    style="border-collapse:separate; mso-table-lspace:0; mso-table-rspace:0; width:100%; background-color:#f6f6f6"
    width="100%" bgcolor="#f6f6f6">
    <tr>
      <td style="font-family:sans-serif; font-size:14px; vertical-align:top"
        valign="top"></td>
      <td class="container"
        style="font-family:sans-serif; font-size:14px; vertical-align:top; display:block; max-width:580px;
              padding:10px; width:580px; margin:0 auto"
        valign="top" width="580">
        <div class="content"
          style="box-sizing:border-box; display:block; margin:0 auto; max-width:580px; padding:10px">

          <!-- START CENTERED WHITE CONTAINER -->
          <table role="presentation" class="main"
            style="border-collapse:separate; mso-table-lspace:0; mso-table-rspace:0; width:100%;
                  background:#fff; border-radius:3px"
            width="100%">

            <!-- START MAIN CONTENT AREA -->
            <tr>
              <td class="wrapper"
                style="font-family:sans-serif; font-size:14px; vertical-align:top; box-sizing:border-box; padding:20px"
                valign="top">
                <table role="presentation" border="0" cellpadding="0"
                  cellspacing="0"
                  style="border-collapse:separate; mso-table-lspace:0; mso-table-rspace:0; width:100%"
                  width="100%">
                  <tr>
                    <td
                      style="font-family:sans-serif; font-size:14px; vertical-align:top"
                      valign="top">
                      <p
                        style="font-family:sans-serif; font-size:14px;
                              font-weight:normal; margin:0; margin-bottom:15px">
                        Hi there,</p>
                      <p
                        style="font-family:sans-serif; font-size:14px; font-weight:normal;
                              margin:0; margin-bottom:15px">
                        {}</p>
                      <table role="presentation" border="0" cellpadding="0"
                        cellspacing="0" class="btn btn-primary"
                        style="border-collapse:separate; mso-table-lspace:0; mso-table-rspace:0;
                              width:100%; box-sizing:border-box"
                        width="100%">
                        <tbody>
                          <tr>
                            <td align="left"
                              style="font-family:sans-serif; font-size:14px; vertical-align:top; padding-bottom:15px"
                              valign="top">
                              <table role="presentation" border="0"
                                cellpadding="0" cellspacing="0"
                                style="border-collapse:separate; mso-table-lspace:0; mso-table-rspace:0; width:auto"
                                width="auto">
                                <tbody>
                                  <tr>
                                    <td
                                      style="font-family:sans-serif; font-size:14px; vertical-align:top;
                                            background-color:#3498db; border-radius:5px; text-align:center"
                                      valign="top" bgcolor="#3498db"
                                      align="center"> <a
                                        href="http://htmlemail.io"
                                        target="_blank"
                                        style="color:#fff; text-decoration:none; background-color:#3498db;
                                              border:solid 1px #3498db; border-radius:5px; box-sizing:border-box;
                                              cursor:pointer; display:inline-block; font-size:14px; font-weight:bold;
                                              margin:0; padding:12px 25px; text-transform:capitalize;
                                              border-color:#3498db"
                                        bgcolor="#3498db">Call To Action</a>
                                    </td>
                                  </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                      <p
                        style="font-family:sans-serif; font-size:14px; font-weight:normal;
                              margin:0; margin-bottom:15px">
                        This is a really simple email template. Its sole purpose
                        is to get the recipient to click the
                        button with no distractions.</p>
                      <p
                        style="font-family:sans-serif; font-size:14px; font-weight:normal;
                              margin:0; margin-bottom:15px">
                        Good luck! Hope it works.</p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <!-- END MAIN CONTENT AREA -->
          </table>
          <!-- END CENTERED WHITE CONTAINER -->

          <!-- START FOOTER -->
          <div class="footer"
            style="clear:both; margin-top:10px; text-align:center; width:100%"
            align="center" width="100%">
            <table role="presentation" border="0" cellpadding="0"
              cellspacing="0"
              style="border-collapse:separate; mso-table-lspace:0; mso-table-rspace:0; width:100%"
              width="100%">
              <tr>
                <td class="content-block"
                  style="font-family:sans-serif; font-size:12px; vertical-align:top; padding-bottom:10px;
                        padding-top:10px; color:#999; text-align:center"
                  valign="top" align="center">
                  <span class="apple-link"
                    style="color:#999; font-size:12px; text-align:center"
                    align="center">Company
                    Inc, 3 Abbey Road, San Francisco CA 94102</span>
                  <br> Don't like these emails? <a
                    href="http://i.imgur.com/CScmqnj.gif"
                    style="color:#999; text-decoration:underline; font-size:12px; text-align:center"
                    align="center">Unsubscribe</a>.
                </td>
              </tr>
              <tr>
                <td class="content-block powered-by"
                  style="font-family:sans-serif; font-size:12px; vertical-align:top; padding-bottom:10px;
                        padding-top:10px; color:#999; text-align:center"
                  valign="top" align="center">
                  Powered by <a href="http://htmlemail.io"
                    style="color:#999; text-decoration:none; font-size:12px; text-align:center"
                    align="center">HTMLemail</a>.
                </td>
              </tr>
            </table>
          </div>
          <!-- END FOOTER -->

        </div>
      </td>
      <td style="font-family:sans-serif; font-size:14px; vertical-align:top"
        valign="top"></td>
    </tr>
  </table>
</body>

</html>
'''
TEMPLATE_2 = '''<html xmlns="http://www.w3.org/1999/xhtml">

<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0;">
    <meta name="format-detection" content="telephone=no">

    <!-- Responsive Mobile-First Email Template by Konstantin Savchenko, 2015.
    https://github.com/konsav/email-templates/  -->

    <!-- MESSAGE SUBJECT -->
    <title>Responsive HTML email templates</title>

</head>

<!-- BODY -->
<!-- Set message background color (twice) and text color (twice) -->

<body topmargin="0" rightmargin="0" bottommargin="0" leftmargin="0"
      marginwidth="0" marginheight="0" width="100%"
      style="margin:0; min-width:100%; padding:0; -ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
            -webkit-text-size-adjust:100%; line-height:100%; text-size-adjust:100%; height:100%; width:100%;
            background-color:#2D3445; border-collapse:collapse; border-spacing:0; color:#FFF"
      bgcolor="#2D3445" text="#FFFFFF" height="100%">

    <!-- SECTION / BACKGROUND -->
    <!-- Set message background color one again -->
    <table width="100%" align="center" border="0" cellpadding="0"
           cellspacing="0"
           style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased; -webkit-text-size-adjust:100%;
                 line-height:100%; text-size-adjust:100%; border-spacing:0; mso-table-lspace:0; mso-table-rspace:0;
                 border-collapse:collapse; margin:0; padding:0; width:100%"
           class="background">
        <tr>
            <td align="center" valign="top"
                style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased; -webkit-text-size-adjust:100%;
                      line-height:100%; text-size-adjust:100%; border-spacing:0; mso-table-lspace:0;
                      mso-table-rspace:0; border-collapse:collapse; margin:0; padding:0"
                bgcolor="#2D3445">

                <!-- WRAPPER -->
                <!-- Set wrapper width (twice) -->
                <table border="0" cellpadding="0" cellspacing="0" align="center"
                       width="inherit"
                       style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                             -webkit-text-size-adjust:100%; line-height:100%; text-size-adjust:100%;
                             border-spacing:0; mso-table-lspace:0; mso-table-rspace:0; border-collapse:collapse;
                             max-width:500px; padding:0; width:inherit"
                       class="wrapper">

                    <tr>
                        <td align="center" valign="top"
                            style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                  -webkit-text-size-adjust:100%; line-height:100%; text-size-adjust:100%;
                                  border-spacing:0; mso-table-lspace:0; mso-table-rspace:0; border-collapse:collapse;
                                  margin:0; padding:0; padding-bottom:20px; padding-left:6.25%; padding-right:6.25%;
                                  padding-top:20px; width:87.5%"
                            width="87.5%">

                            <!-- PREHEADER -->
                            <!-- Set text color to background color -->
                            <div style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                       -webkit-text-size-adjust:100%; line-height:1px; text-size-adjust:100%;
                                       color:#2D3445; display:none; font-size:1px; height:0; max-height:0; max-width:0;
                                       opacity:0; overflow:hidden; visibility:hidden"
                                 class="preheader" height="0">
                                Available on GitHub and CodePen. Highly
                                compatible. Designer friendly. More than
                                50% of total email opens occurred on a mobile
                                device - a mobile-friendly design is a must
                                for email campaigns.</div>

                            <!-- LOGO -->
                            <!-- Image text color should be opposite to background color. Set your url, image src,
                                alt and title. Alt text should fit the image size. Real image size should be x2. -->
                            <a target="_blank"
                               style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                     -webkit-text-size-adjust:100%; line-height:100%; text-size-adjust:100%;
                                     color:#FFF; text-decoration:none"
                               href="https://github.com/konsav/email-templates/"><img
                                     border="0" vspace="0" hspace="0"
                                     src="https://raw.githubusercontent.com/konsav/
                                         email-templates/master/images/logo-white.png"
                                     width="100" height="30" alt="Logo"
                                     title="Logo"
                                     style="-ms-interpolation-mode:bicubic; border:none; line-height:100%;
                                           outline:none; text-decoration:none; color:#FFF; display:block;
                                           font-size:10px; margin:0; padding:0"></a>

                        </td>
                    </tr>

                    <!-- HERO IMAGE -->
                    <!-- Image text color should be opposite to background color. Set your url, image src,
                         alt and title. Alt text should fit the image size. Real image size should be x2
                         (wrapper x2). Do not set height for flexible images (including "auto"). -->
                    <tr>
                        <td align="center" valign="top"
                            style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                  -webkit-text-size-adjust:100%; line-height:100%; text-size-adjust:100%;
                                  border-spacing:0; mso-table-lspace:0; mso-table-rspace:0; border-collapse:collapse;
                                  margin:0; padding:0; padding-top:0"
                            class="hero"><a target="_blank"
                               style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                     -webkit-text-size-adjust:100%; line-height:100%; text-size-adjust:100%;
                                     color:#FFF; text-decoration:none"
                               href="https://github.com/konsav/email-templates/"><img
                                     border="0" vspace="0" hspace="0"
                                     src="https://raw.githubusercontent.com/konsav/
                                         email-templates/master/images/hero-block.png"
                                     alt="Please enable images to view this content"
                                     title="Hero Image" width="87.5%"
                                     style="-ms-interpolation-mode:bicubic; border:none;
                                           line-height:100%; outline:none; text-decoration:none;
                                           color:#FFF; display:block; font-size:13px; margin:0;
                                           max-width:340px; padding:0; width:87.5%"></a>
                        </td>
                    </tr>

                    <!-- SUPHEADER -->
                    <!-- Set text color and font family ("sans-serif" or "Georgia, serif") -->
                    <tr>
                        <td align="center" valign="top"
                            style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                  -webkit-text-size-adjust:100%; line-height:150%; text-size-adjust:100%;
                                  border-spacing:0; mso-table-lspace:0; mso-table-rspace:0; border-collapse:collapse;
                                  color:#FFF; font-family:sans-serif; font-size:14px; font-weight:400;
                                  letter-spacing:2px; margin:0; padding:0; padding-bottom:0; padding-left:6.25%;
                                  padding-right:6.25%; padding-top:27px; width:87.5%"
                            class="supheader" width="87.5%">
                            INTRODUCING
                        </td>
                    </tr>

                    <!-- HEADER -->
                    <!-- Set text color and font family ("sans-serif" or "Georgia, serif") -->
                    <tr>
                        <td align="center" valign="top"
                            style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                  -webkit-text-size-adjust:100%; line-height:130%; text-size-adjust:100%;
                                  border-spacing:0; mso-table-lspace:0; mso-table-rspace:0; border-collapse:collapse;
                                  color:#FFF; font-family:sans-serif; font-size:24px; font-weight:bold; margin:0;
                                  padding:0; padding-left:6.25%; padding-right:6.25%; padding-top:5px; width:87.5%"
                            class="header" width="87.5%">
                            Responsive HTML email templates
                        </td>
                    </tr>

                    <!-- PARAGRAPH -->
                    <!-- Set text color and font family ("sans-serif" or "Georgia, serif").
                        Duplicate all text styles in links, including line-height -->
                    <tr>
                        <td align="center" valign="top"
                            style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                  -webkit-text-size-adjust:100%; line-height:160%; text-size-adjust:100%;
                                  border-spacing:0; mso-table-lspace:0; mso-table-rspace:0; border-collapse:collapse;
                                  color:#FFF; font-family:sans-serif; font-size:17px; font-weight:400; margin:0;
                                  padding:0; padding-left:6.25%; padding-right:6.25%; padding-top:15px; width:87.5%"
                            class="paragraph" width="87.5%">
                            {}
                        </td>
                    </tr>

                    <!-- BUTTON -->
                    <!-- Set button background color at TD, link/text color at A and TD, font family ("sans-serif"
                         or "Georgia, serif") at TD. For verification codes add "letter-spacing: 5px;". -->
                    <tr>
                        <td align="center" valign="top"
                            style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                  -webkit-text-size-adjust:100%; line-height:100%; text-size-adjust:100%;
                                  border-spacing:0; mso-table-lspace:0; mso-table-rspace:0; border-collapse:collapse;
                                  margin:0; padding:0; padding-bottom:5px; padding-left:6.25%; padding-right:6.25%;
                                  padding-top:25px; width:87.5%"
                            class="button" width="87.5%"><a
                               href="https://github.com/konsav/email-templates/"
                               target="_blank"
                               style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                     -webkit-text-size-adjust:100%; line-height:100%; text-size-adjust:100%;
                                     color:#FFF; text-decoration:underline">
                            </a>
                            <table border="0" cellpadding="0" cellspacing="0"
                                   align="center"
                                   style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                         -webkit-text-size-adjust:100%; line-height:100%; text-size-adjust:100%;
                                         border-spacing:0; mso-table-lspace:0; mso-table-rspace:0;
                                         border-collapse:collapse; max-width:240px; min-width:120px; padding:0">
                                <tr>
                                    <td align="center" valign="middle"
                                        style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                              -webkit-text-size-adjust:100%; line-height:100%; text-size-adjust:100%;
                                              border-spacing:0; mso-table-lspace:0; mso-table-rspace:0;
                                              border-collapse:collapse; -khtml-border-radius:4px;
                                              -moz-border-radius:4px; -webkit-border-radius:4px; border-radius:4px;
                                              margin:0; padding:12px 24px; text-decoration:underline"
                                        bgcolor="#E9703E"><a target="_blank"
                                           style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                                 -webkit-text-size-adjust:100%; line-height:120%;
                                                 text-size-adjust:100%; color:#FFF; font-family:sans-serif;
                                                 font-size:17px; font-weight:400; text-decoration:underline"
                                           href="https://github.com/konsav/email-templates/">
                                            View on GitHub
                                        </a>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- LINE -->
                    <!-- Set line color -->
                    <tr>
                        <td align="center" valign="top"
                            style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                  -webkit-text-size-adjust:100%; line-height:100%; text-size-adjust:100%;
                                  border-spacing:0; mso-table-lspace:0; mso-table-rspace:0;
                                  border-collapse:collapse; margin:0; padding:0; padding-left:6.25%;
                                  padding-right:6.25%; padding-top:30px; width:87.5%"
                            class="line" width="87.5%">
                            <hr color="#565F73" align="center" width="100%"
                                size="1" noshade style="margin: 0; padding: 0;">
                        </td>
                    </tr>

                    <!-- FOOTER -->
                    <!-- Set text color and font family ("sans-serif" or "Georgia, serif").
                        Duplicate all text styles in links, including line-height -->
                    <tr>
                        <td align="center" valign="top"
                            style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                  -webkit-text-size-adjust:100%; line-height:150%; text-size-adjust:100%;
                                  border-spacing:0; mso-table-lspace:0; mso-table-rspace:0;
                                  border-collapse:collapse; color:#828999; font-family:sans-serif;
                                  font-size:13px; font-weight:400; margin:0; padding:0; padding-bottom:20px;
                                  padding-left:6.25%; padding-right:6.25%; padding-top:10px; width:87.5%"
                            class="footer" width="87.5%">

                            This email template was sent to you becouse we want
                            to make the world a better place. You could change
                            your <a
                               href="https://github.com/konsav/email-templates/"
                               target="_blank"
                               style="-ms-text-size-adjust:100%; -webkit-font-smoothing:antialiased;
                                     -webkit-text-size-adjust:100%; line-height:150%; text-size-adjust:100%;
                                     color:#828999; font-family:sans-serif; font-size:13px; font-weight:400;
                                     text-decoration:underline">subscription
                                settings</a> anytime.

                            <!-- ANALYTICS -->
                            <img width="1" height="1" border="0" vspace="0"
                                 hspace="0"
                                 style="-ms-interpolation-mode:bicubic; border:none; line-height:100%; outline:none;
                                       text-decoration:none; display:block; margin:0; padding:0"
                                 src="https://raw.githubusercontent.com/
                                     konsav/email-templates/master/images/tracker.png">

                        </td>
                    </tr>

                    <!-- End of WRAPPER -->
                </table>

                <!-- End of SECTION / BACKGROUND -->
            </td>
        </tr>
    </table>

</body>

</html>
'''
# Drops the mic disable-secrets-detection-end
EMAIL_TEMPLATES = [TEMPLATE_1, TEMPLATE_2]


'''HELPER FUNCTIONS'''


def update_parameters():
    """
    Check and see if the integration parameters changed and if so update global vars
    """
    params = demisto.params()
    incidents_per_minute = int(params.get('incidents_per_minute', '5'))
    max_num_of_incidents = int(params.get('max_num_of_incidents', '10'))
    frequency = int(params.get('frequency')) if params.get('frequency') else None
    global INCIDENTS_PER_MINUTE
    if incidents_per_minute != INCIDENTS_PER_MINUTE:
        INCIDENTS_PER_MINUTE = incidents_per_minute
    global MAX_NUM_OF_INCIDENTS
    if max_num_of_incidents != MAX_NUM_OF_INCIDENTS:
        MAX_NUM_OF_INCIDENTS = max_num_of_incidents
    global FREQUENCY
    if frequency != FREQUENCY:
        FREQUENCY = frequency


def generate_dbot_score(indicator):
    """ Arbitrary (but consistent) scoring method

    Assign a dbot score according to the last digit of the hash of the indicator.

    parameter: (string) indicator
        The indicator for which we need to generate a dbot score

    returns:
        Dbot score (0,1,2, or 3)
    """
    the_hash = hash(indicator)
    last_digit = abs(the_hash) % 10
    if last_digit == 0:
        return 0
    elif last_digit < 5:
        return 1
    elif last_digit < 8:
        return 2
    else:
        return 3


def create_content():
    """
    Generate fake content to populate the email with

    Generates textual contents that are randomly generated and defined to include 5 random IPs, 5 random URLs,
    5 random sha1 hashes, 5 random sha256 hashes, 5 random md5 hashes, 5 random email addresses, 5 random domains
    and 100 random words.

    returns:
        The randomly generated data as a string
    """
    details = fake.text(600)  # pylint: disable=no-member
    details += '\n'
    for _ in range(INDICATORS_PER_INCIDENT):
        ipv4, url, domain = fake.ipv4_public(), fake.url(), fake.domain_name()  # pylint: disable=no-member
        sha1, sha256, md5 = fake.sha1(), fake.sha256(), fake.md5()  # pylint: disable=no-member
        details += str(ipv4) + ' ' + str(url) + ' ' + str(domain) + ' ' + str(sha1) + ' ' + str(sha256) + ' ' + str(md5) + '\n'

    emails = [fake.email() for _ in range(INDICATORS_PER_INCIDENT)]  # pylint: disable=no-member
    details += ' '.join(emails)
    return details


def inject_content_into_template(plaintext):
    """
    Choose an email html template at random and populate the main textual component with randomly generated
    content passed in the 'plaintext' parameter

    parameter: (string) plaintext
        The randomly generated content to be used in the email html

    returns:
        The html template populated with the randomly generated content
    """
    # Choose random email html template
    choice = random.randint(0, len(EMAIL_TEMPLATES) - 1)
    chosen_template = EMAIL_TEMPLATES[choice]
    html = chosen_template.format(plaintext)
    return html


def create_email():
    """
    Create message object using template and random data

    returns:
        email.Message object and the email as a standard dictionary
    """
    sender = fake.email()  # pylint: disable=no-member
    recipient = fake.email()  # pylint: disable=no-member
    cc = [fake.email() for _ in range(random.randint(0, 2))]  # pylint: disable=no-member
    bcc = [fake.email() for _ in range(random.randint(0, 2))]  # pylint: disable=no-member
    the_time = datetime.now()
    received = 'from ' + fake.hostname() + ' (' + fake.ipv4_public()  # pylint: disable=no-member
    received += ')' + 'by ' + fake.domain_word() + '.'  # pylint: disable=no-member
    received += fake.free_email_domain() + ' with '  # pylint: disable=no-member
    received += EMAIL_PROTOCOLS[random.randint(0, len(EMAIL_PROTOCOLS) - 1)]
    received += '; ' + the_time.strftime('%c')
    msg = MIMEMultipart('alternative')
    msg['Subject'] = fake.sentence()  # pylint: disable=no-member
    msg['From'] = sender
    msg['Reply-To'] = sender
    msg['To'] = recipient
    msg['Message-ID'] = str(fake.uuid4())  # pylint: disable=no-member
    msg['CC'] = ', '.join(cc) if cc else ''
    msg['BCC'] = ', '.join(bcc) if bcc else ''
    msg['User-Agent'] = fake.user_agent()  # pylint: disable=no-member
    msg['Date'] = the_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    msg['Received'] = received

    plaintext = create_content()
    html = inject_content_into_template(plaintext)
    part1 = MIMEText(plaintext, 'plain')
    part2 = MIMEText(html, 'html')
    msg.attach(part1)
    msg.attach(part2)
    email_object = {}
    for key, val in msg.items():
        email_object[key] = val
    email_object['Text'] = plaintext
    email_object['Body'] = html
    return msg, email_object


def generate_incidents(last_run):
    """
    Determines how many incidents to create and generates them

    parameter: (number) last_run
        The number of incidents generated in the last fetch

    returns:
        The number of incidents generated in the current call to fetch_incidents and the incidents themselves
    """
    if last_run > 0 and last_run > MAX_NUM_OF_INCIDENTS:
        demisto.info('last_run is greater than MAX_NUM_OF_INCIDENTS')
        return 0, []

    incidents = []
    num_of_incidents_left_to_create = MAX_NUM_OF_INCIDENTS - last_run

    if num_of_incidents_left_to_create > INCIDENTS_PER_MINUTE:
        num_of_incident_to_create = INCIDENTS_PER_MINUTE
    else:
        num_of_incident_to_create = num_of_incidents_left_to_create

    for _ in range(num_of_incident_to_create):
        email, email_object = create_email()
        incidents.append({
            'name': email_object.get('Subject'),
            'details': email.as_string(),
            'occurred': email_object.get('Date'),
            'type': INCIDENT_TYPE,
            'rawJSON': json.dumps(email_object)
        })
    return num_of_incident_to_create, incidents


'''MAIN FUNCTIONS'''


def fetch_incidents():
    """
    Generates and fetches phishing email-like incidents

    Generates phishing email-like incidents, with the number of incidents, the
    speed of generation and the recurring time period all set by the values
    entered in the integration instance parameters. This method operates
    under the assumption that fetch-incidents is called once per minute.

    returns:
        Email-like incidents
    """
    try:
        update_parameters()
        minutes_of_generation = MAX_NUM_OF_INCIDENTS / float(INCIDENTS_PER_MINUTE)
        if not FREQUENCY or minutes_of_generation > FREQUENCY:  # Run once
            last_run = 0 if not demisto.getLastRun() else demisto.getLastRun().get('numOfIncidentsCreated', 0)

            num_of_incidents_created, incidents = generate_incidents(last_run)

            demisto.incidents(incidents)
            demisto.setLastRun({'numOfIncidentsCreated': last_run + num_of_incidents_created})
            return
        else:
            run_counter = 0 if not demisto.getLastRun() else demisto.getLastRun().get('run_count', 0)
            last_run = 0 if not demisto.getLastRun() else demisto.getLastRun().get('numOfIncidentsCreated', 0)
            should_run = run_counter % FREQUENCY
            if should_run < math.ceil(minutes_of_generation):  # then should run
                if should_run == 0:
                    last_run = 0

                num_of_incidents_created, incidents = generate_incidents(last_run)
                demisto.incidents(incidents)

                total_incidents_created = last_run + num_of_incidents_created
                updated_run_count = run_counter + 1
                demisto.setLastRun({
                    'numOfIncidentsCreated': total_incidents_created,
                    'run_count': updated_run_count
                })
                return
            else:
                updated_run_count = run_counter + 1
                demisto.setLastRun({
                    'numOfIncidentsCreated': last_run,
                    'run_count': updated_run_count
                })
                demisto.incidents([])
    except Exception:
        raise


def demo_ip_command():
    """
    Returns the reputation generated by this integration for the IP address passed as an argument

    demisto param: (string) ip
        The IP address to get the reputation of

    returns:
        IP Reputation to the context
    """
    ip = demisto.args().get('ip')
    dbotscore = generate_dbot_score(ip)

    dbotscore_output = {
        'Indicator': ip,
        'Type': 'ip',
        'Vendor': 'OnboardingIntegration',
        'Score': dbotscore
    }

    standard_ip_output = {
        'Address': ip
    }

    if dbotscore == 3:
        standard_ip_output['Malicious'] = {
            'Vendor': 'OnboardingIntegration',
            'Description': 'Indicator was found to be malicious.'
        }

    context = {
        'DBotScore': dbotscore_output,
        outputPaths['ip']: standard_ip_output
    }

    title = f'OnboardingIntegration IP Reputation - {ip}'
    human_readable = tableToMarkdown(title, dbotscore_output)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


def demo_url_command():
    """
    Returns the reputation generated by this integration for the URL passed as an argument

    demisto param: (string) url
        The URL to get the reputation of

    returns:
        URL Reputation to the context
    """
    url = demisto.args().get('url')
    dbotscore = generate_dbot_score(url)

    dbotscore_output = {
        'Indicator': url,
        'Type': 'url',
        'Vendor': 'OnboardingIntegration',
        'Score': dbotscore
    }

    standard_url_output = {
        'Data': url
    }

    if dbotscore == 3:
        standard_url_output['Malicious'] = {
            'Vendor': 'OnboardingIntegration',
            'Description': 'Indicator was found to be malicious.'
        }

    context = {
        'DBotScore': dbotscore_output,
        outputPaths['url']: standard_url_output
    }

    title = f'OnboardingIntegration URL Reputation - {url}'
    human_readable = tableToMarkdown(title, dbotscore_output)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


def demo_domain_command():
    """
    Returns the reputation generated by this integration for the domain passed as an argument

    demisto param: (string) domain
        The domain to get the reputation of

    returns:
        Domain Reputation to the context
    """
    domain = demisto.args().get('domain')
    dbotscore = generate_dbot_score(domain)

    dbotscore_output = {
        'Indicator': domain,
        'Type': 'domain',
        'Vendor': 'OnboardingIntegration',
        'Score': dbotscore
    }

    standard_domain_output = {
        'Name': domain
    }

    if dbotscore == 3:
        standard_domain_output['Malicious'] = {
            'Vendor': 'OnboardingIntegration',
            'Description': 'Indicator was found to be malicious.'
        }

    context = {
        'DBotScore': dbotscore_output,
        outputPaths['domain']: standard_domain_output
    }

    title = f'OnboardingIntegration Domain Reputation - {domain}'
    human_readable = tableToMarkdown(title, dbotscore_output)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


def demo_file_command():
    """
    Returns the reputation generated by this integration for the file hash passed as an argument

    demisto param: (string) file
        The file hash to get the reputation of

    returns:
        File-Hash Reputation to the context
    """
    file = demisto.args().get('file')
    hash_type = get_hash_type(file).upper()
    dbotscore = generate_dbot_score(file)

    dbotscore_output = {
        'Indicator': file,
        'Type': 'file',
        'Vendor': 'OnboardingIntegration',
        'Score': dbotscore
    }

    standard_file_output = {
        hash_type: file
    }

    if dbotscore == 3:
        standard_file_output['Malicious'] = {
            'Vendor': 'OnboardingIntegration',
            'Description': 'Indicator was found to be malicious.'
        }

    context = {
        'DBotScore': dbotscore_output,
        outputPaths['file']: standard_file_output
    }

    title = f'OnboardingIntegration File Reputation - {file}'
    human_readable = tableToMarkdown(title, dbotscore_output)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


def demo_email_command():
    """
    Returns the reputation generated by this integration for the email address passed as an argument

    demisto param: (string) email
        The email address to get the reputation of

    returns:
        Email Reputation to the context
    """
    email = demisto.args().get('email')
    dbotscore = generate_dbot_score(email)

    dbotscore_output = {
        'Indicator': email,
        'Type': 'email',
        'Vendor': 'OnboardingIntegration',
        'Score': dbotscore
    }

    standard_email_output = {
        'Address': email
    }

    if dbotscore == 3:
        standard_email_output['Malicious'] = {
            'Vendor': 'OnboardingIntegration',
            'Description': 'Indicator was found to be malicious.'
        }

    context = {
        'DBotScore': dbotscore_output,
        outputPaths['email']: standard_email_output
    }

    title = f'OnboardingIntegration Email Reputation - {email}'
    human_readable = tableToMarkdown(title, dbotscore_output)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


''' COMMANDS MANAGER / SWITCH PANEL '''

COMMANDS = {
    'demo-url': demo_url_command,
    'demo-ip': demo_ip_command,
    'demo-email': demo_email_command,
    'demo-file': demo_file_command,
    'demo-domain': demo_domain_command,
    'fetch-incidents': fetch_incidents
}


def main():
    try:
        if demisto.command() == 'test-module':
            demisto.results('ok')
        elif demisto.command() in COMMANDS:
            COMMANDS[demisto.command()]()
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtin s
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *

# set omp
import os
import multiprocessing
os.environ['OMP_NUM_THREADS'] = multiprocessing.cpu_count()

import dateutil  # type: ignore
import pandas as pd
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import CountVectorizer
from numpy import dot
from numpy.linalg import norm
from email.utils import parseaddr
import tldextract
from urllib.parse import urlparse
import re
from FormatURLApiModule import *  # noqa: E402

no_fetch_extract = tldextract.TLDExtract(suffix_list_urls=[], cache_dir=None)
pd.options.mode.chained_assignment = None  # default='warn'

SIMILARITY_THRESHOLD = float(demisto.args().get('threshold', 0.97))
CLOSE_TO_SIMILAR_DISTANCE = 0.2

EMAIL_BODY_FIELD = 'emailbody'
EMAIL_SUBJECT_FIELD = 'emailsubject'
EMAIL_HTML_FIELD = 'emailbodyhtml'
FROM_FIELD = 'emailfrom'
FROM_DOMAIN_FIELD = 'fromdomain'
PREPROCESSED_EMAIL_BODY = 'preprocessedemailbody'
PREPROCESSED_EMAIL_SUBJECT = 'preprocessedemailsubject'
MERGED_TEXT_FIELD = 'mereged_text'
MIN_TEXT_LENGTH = 50
DEFAULT_ARGS = {
    'limit': '1000',
    'incidentTypes': 'Phishing',
    'existingIncidentsLookback': '100 days ago',
}
FROM_POLICY_TEXT_ONLY = 'TextOnly'
FROM_POLICY_EXACT = 'Exact'
FROM_POLICY_DOMAIN = 'Domain'

FROM_POLICY = FROM_POLICY_TEXT_ONLY
URL_REGEX = r'(?:(?:https?|ftp|hxxps?):\/\/|www\[?\.\]?|ftp\[?\.\]?)(?:[-\w\d]+\[?\.\]?)+[-\w\d]+(?::\d+)?' \
            r'(?:(?:\/|\?)[-\w\d+&@#\/%=~_$?!\-:,.\(\);]*[\w\d+&@#\/%=~_$\(\);])?'

IGNORE_INCIDENT_TYPE_VALUE = 'None'

INCIDENTS = '''
[
    {
        "account": "",
        "activated": "0001-01-01T00:00:00Z",
        "attachment": [
            {
                "description": "",
                "isTempPath": false,
                "name": "Christmas packages need confirmation.eml",
                "path": "275_424ca709-bd35-4d6d-815b-6bc593622e57_Christmas_packages_need_confirmation.eml",
                "showMediaFile": false,
                "type": "message/rfc822"
            }
        ],
        "autime": 1730203605766000000,
        "cacheVersn": 0,
        "canvases": null,
        "category": "",
        "closeNotes": "",
        "closeReason": "",
        "closed": "0001-01-01T00:00:00Z",
        "closingUserId": "",
        "created": "2024-10-29T12:06:45.766Z",
        "custom_status": "",
        "dbotCreatedBy": "jlevy@paloaltonetworks.com",
        "dbotCurrentDirtyFields": null,
        "dbotDirtyFields": null,
        "dbotMirrorDirection": "",
        "dbotMirrorId": "",
        "dbotMirrorInstance": "",
        "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
        "dbotMirrorTags": null,
        "details": "",
        "droppedCount": 0,
        "dueDate": "2024-11-08T12:06:45.766932611Z",
        "feedBased": false,
        "id": "275",
        "investigationId": "275",
        "isDebug": false,
        "isPlayground": false,
        "labels": [
            {
                "type": "Instance",
                "value": "jlevy@paloaltonetworks.com"
            },
            {
                "type": "Brand",
                "value": "Manual"
            }
        ],
        "lastJobRunTime": "0001-01-01T00:00:00Z",
        "lastOpen": "0001-01-01T00:00:00Z",
        "linkedCount": 0,
        "linkedIncidents": null,
        "modified": "2024-10-29T12:14:36.018Z",
        "name": "jl-phishing",
        "notifyTime": "2024-10-29T12:14:35.963541548Z",
        "occurred": "2024-10-29T12:06:45.76692823Z",
        "openDuration": 0,
        "owner": "jlevy@paloaltonetworks.com",
        "parent": "",
        "parentXDRIncident": "",
        "phase": "",
        "playbookId": "Phishing - Generic v3",
        "rawCategory": "",
        "rawCloseReason": "",
        "rawJSON": "",
        "rawName": "jl-phishing",
        "rawPhase": "",
        "rawType": "Phishing",
        "reason": "",
        "reminder": "0001-01-01T00:00:00Z",
        "resolution_status": "",
        "retained": false,
        "runStatus": "error",
        "severity": 0,
        "sizeInBytes": 0,
        "sla": 0,
        "sortValues": [
            "1"
        ],
        "sourceBrand": "Manual",
        "sourceInstance": "jlevy@paloaltonetworks.com",
        "status": 1,
        "type": "Phishing",
        "version": -1,
        "clickedurls": [
            {}
        ],
        "containmentsla": {
            "accumulatedPause": 0,
            "breachTriggered": false,
            "dueDate": "0001-01-01T00:00:00Z",
            "endDate": "0001-01-01T00:00:00Z",
            "lastPauseDate": "0001-01-01T00:00:00Z",
            "runStatus": "idle",
            "sla": 30,
            "slaStatus": -1,
            "startDate": "0001-01-01T00:00:00Z",
            "totalDuration": 0
        },
        "criticalassets": [
            {}
        ],
        "detectionsla": {
            "accumulatedPause": 0,
            "breachTriggered": false,
            "dueDate": "2024-10-29T12:26:55.089352396Z",
            "endDate": "0001-01-01T00:00:00Z",
            "lastPauseDate": "0001-01-01T00:00:00Z",
            "runStatus": "running",
            "sla": 20,
            "slaStatus": 0,
            "startDate": "2024-10-29T12:06:55.089352396Z",
            "totalDuration": 0
        },
        "emailbody": "",
        "emailbodyhtml": "<a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\">\n<strong>ATTENTION NEEDED: Package Delivery Issue Please update your info</strong><br><br>\n<img src=\"https://files.constantcontact.com/473b1db4901/c6ab20c4-0640-4a69-a07c-876816087800.png\" width=\"100%\" height=\"100%\">\n<img src=\"//files.constantcontact.com/473b1db4901/c6ab20c4-0640-4a69-a07c-876816087800.png\" width=\"100%\" height=\"100%\"><br></a>\n<div id=\"Wrapper\" style=\"padding: 0;margin: 0 auto;text-align: center;font-family: Arial, Helvetica, sans-serif;\">\n\n\n\n    \n    \n    \n    \n    \n    \n\n\n    \n        \n        <table cellpadding=\"0\" cellspacing=\"0\" bgcolor=\"#ececf8\n\" width=\"100%\" height=\"100%\">\n            \n            <tr>\n                <td style=\"height: 24px;\"></td>\n            </tr>\n            <tr>\n                \n                <td style=\"text-align: center;\">\n                   \n                </td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n                \n                <td style=\"font-size: 22px;color: #6600cc;font-family: Arial, Helvetica, sans-serif; line-height: 1.3; text-align: center;\"><h1><a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"><p style=\"color:rgb(255, 102, 0);\">  Christmas packages need confirmation</p></a></td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n                <td>\n                    <table>\n                        <tr>\n                            \n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\n                            \n                            <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"><h1><p style=\"color:rgb(255, 102, 0);\">We have been trying to reach you, your reward is waiting!<br><br>\nWe&#39;ve seen your loyalty and now it&#39;s time for us to give thanks<br><h2><p style=\"color:rgb(0, 0, 255);\">\n\n <h1><p style=\"color:rgb(0, 0, 0);\"><p style=\"color:rgb(0, 0, 0);\">\n\n\n\n</a></td>\n                            \n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\n                        </tr>\n                    </table>\n                </td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n               <td style=\"text-align: center;font-family: Arial, Helvetica, sans-serif;height: 47px;\">\n                    \n                   <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" class=\"btn_cta\" target=\"_blank\" rel=\"nofollow noopener\">\n                        <span>Schedule Your Delivery</span>\n                    </a>\n                </td>\n            </tr>\n\n            <tr>\n                <td style=\"height: 24px;\"></td>\n            </tr>\n        </table>\n        \n        <table cellpadding=\"0\" cellspacing=\"0\" bgcolor=\"#ffffff\" width=\"100%\" height=\"100%\">\n            \n            <tr>\n                <td style=\"height: 24px;\"></td>\n            </tr>\n            <tr>\n                \n                <td style=\"text-align: center;\">\n                  \n                </td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n              \n               <td style=\"font-size: 22px;color: #6600cc;font-family: Arial, Helvetica, sans-serif; line-height: 1.3; text-align: center;\"><h1><a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"><p style=\"color:rgb(102, 0, 204)\n;\">  ATTENTION NEEDED: Package Delivery Issue Please update your info</p></a></td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n                <td>\n                    <table>\n                        <tr>\n                            \n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\n                           \n                            <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"><h1><p style=\"color:rgb(102, 0, 204);\">Congratulations! Complete The Short Survey.<br>This limited one - time offer expires in 03:42 minutes! \t<br> <br>We Need Your Confirmation To Ship Your Order\n\n\n\n\n\n\n<strong><br> \t\n\n\n\n\n \n\n\n<h1><p style=\"color:rgb(0, 38, 77);\">\n    </h1><h1><p style=\"color:rgb(0, 38, 77)\n;\">\n                            \n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\n                        </tr>\n                    </table>\n                </td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n                <td style=\"text-align: center;font-family: Arial, Helvetica, sans-serif;height: 47px;\">\n                    \n                   <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" class=\"btn_cta1\" target=\"_blank\" rel=\"nofollow noopener\">\n                        <span> Confirm </span>\n                    </a>\n                </td>\n            </tr>\n\n            <tr>\n                <td style=\"height: 24px;\"></td>\n            </tr>\n        </table>\n    <br><p style=\"text-align:center;font-family: &#39;Open Sans&#39;,&#39;Arial&#39;,&#39;Helvetica&#39;,sans-serif;font-size:15px;\"><br><br>\nIf you no longer wish to receive these emails, you may unsubscribe by <a href=\"https://bit.ly/3DeJDIq#oop/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"> clicking here</a>\n<br/><br><br><br><br><br><br><br>\n<p style=\"text-align:center;font-family: &#39;Open Sans&#39;,&#39;Arial&#39;,&#39;Helvetica&#39;,sans-serif;font-size:9px;\"><br><br>\ntest@demisto.com If you no longer wish to receive these emails, you may unsubscribe by  <a href=\"https://bit.ly/3DeJDIq#un/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"> clicking here </a><br>\n<br>\n<br>\n</p>\n\n\n<img src=\"//bit.ly/3f5hUSN/#op/94468_md/1/35353/5610/487/51623\" style=\"visibility:hidden;\"> <br>\n<img src=\"https://bit.ly/3f5hUSN/#op/94468_md/1/35353/5610/487/51623\" style=\"visibility:hidden;\"><br>\n\u00a0<table align=\"center\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" bgcolor=\"white\" style=\"border:2px solid black;\">\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<tbody>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<tr>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<td align=\"center\">\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<br/>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<table align=\"center\" border=\"0\" cellpadding=\"0\" class=\"col-550\" width=\"550\">\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<tbody>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</tbody>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</table>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</td>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</tr>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</tbody>\n\u00a0\u00a0\u00a0\u00a0</table>\n",
        "emailcc": "",
        "emailfrom": "geeksquad@emailinfo.geeksquad.com",
        "emailheaders": [
            {
                "headername": "Authentication-Results",
                "headervalue": "spf=none (sender IP is 52.232.106.214) smtp.mailfrom=2EZjo7SsIi.com; dkim=none (message not signed) header.d=none;dmarc=fail action=quarantine header.from=emailinfo.geeksquad.com;compauth=fail reason=000"
            }
        ],
        "emailhtml": "<!DOCTYPE html><center><a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\">\r\n<strong><font color=\"black\">ATTENTION NEEDED: Package Delivery Issue Please update your info</font></strong><br><br>\r\n<ImG sRc=\"https://files.constantcontact.com/473b1db4901/c6ab20c4-0640-4a69-a07c-876816087800.png\" width=\"100%\" height=\"100%\">\r\n<img src=\"//files.constantcontact.com/473b1db4901/c6ab20c4-0640-4a69-a07c-876816087800.png\" width=\"100%\" height=\"100%\"><br></a>\r\n<center><div id=\"Wrapper\" style=\"padding: 0;margin: 0 auto;text-align: center;font-family: Arial, Helvetica, sans-serif;\"><!DOCTYPE html>\r\n<html lang=\"en\">\r\n\r\n<head>\r\n    <head>\r\n    <meta charset=\"UTF-8\">\r\n    <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\r\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\r\n    <title>Christmas packages need confirmation</title>\r\n    <style>\r\n        * {\r\n            box-sizing: border-box;\r\n        }\r\n        \r\n        body {\r\n            margin: 0;\r\n            padding: 0;\r\n        }\r\n        \r\n        a {\r\n            text-decoration: none;\r\n           \r\n        }\r\n        \r\n        .btn_cta {\r\n            color: #ffffff;\r\n            text-decoration: none;\r\n            background-color: #6600cc;\r\n            border: 1px solid #6600cc;\r\n            border-radius: 5px;\r\n            padding: 22px 15px;\r\n            font-weight: 500;\r\n            transition: all .3s ease;\r\n            position: relative;\r\n            min-width: 160px;\r\n            min-height: 47px;\r\n            display: inline-block;\r\n        }\r\n        \r\n        .btn_cta span {\r\n            position: absolute;\r\n            top: 0;\r\n            bottom: 0;\r\n            left: 0;\r\n            right: 0;\r\n            width: max-content;\r\n            height: max-content;\r\n            margin: auto;\r\n            transition: all .3s ease;\r\n            /* If you want to change the blinking speed */\r\n            /* change 0.6s value */\r\n            /* increment will slow down */\r\n            animation: blink 0.6s ease infinite;\r\n        }\r\n        \r\n        .btn_cta:hover {\r\n            background-color:#ffcc66;\r\n            border-color: #ffcc66;\r\n            transition: all .3s ease;\r\n        }\r\n        \r\n        @keyframes blink {\r\n            from {\r\n                opacity: 0;\r\n                transform: scale(0, 0);\r\n            }\r\n            to {\r\n                opacity: 1;\r\n                transform: scale(1, 1);\r\n            }\r\n        }\r\n        /* Mobile Title Spacing */\r\n        \r\n        @media (max-width: 768px) {\r\n            .mobSpacing {\r\n                width: 10px !important;\r\n            }\r\n        }\r\n    </style>\r\n</head>\r\n<body>\r\n    <center>\r\n        <!-- If you want to change the table background-color -->\r\n        <table cellpadding=\"0\" cellspacing=\"0\" bgColor=\"#ececf8\r\n\" width=\"100%\" height=\"100%\">\r\n            <!-- If you want to change the Vertical Gap between Elements -->\r\n            <tr>\r\n                <td style=\"height: 24px;\"></td>\r\n            </tr>\r\n            <tr>\r\n                <!-- If you want to change the Logo -->\r\n                <td style=\"text-align: center;\">\r\n                   \r\n                </td>\r\n            </tr>\r\n            <tr>\r\n                <td style=\"height: 12px;\"></td>\r\n            </tr>\r\n            <tr>\r\n                <!-- If you want to change the Title Color -->\r\n                <td style=\"font-size: 22px;color: #6600cc;font-family: Arial, Helvetica, sans-serif; line-height: 1.3; text-align: center;\"><h1><a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\"><p style=\"color:rgb(255, 102, 0);\">  Christmas packages need confirmation</p></a></td>\r\n            </tr>\r\n            <tr>\r\n                <td style=\"height: 12px;\"></td>\r\n            </tr>\r\n            <tr>\r\n                <td>\r\n                    <table>\r\n                        <tr>\r\n                            <!-- If you want to change the Text Left Spacing -->\r\n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\r\n                            <!-- If you want to change the Text Color -->\r\n                            <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\"><center><h1><p style=\"color:rgb(255, 102, 0);\">We have been trying to reach you, your reward is waiting!<br><br>\r\nWe've seen your loyalty and now it's time for us to give thanks<br><h2><p style=\"color:rgb(0, 0, 255);\">\r\n\r\n <h1><p style=\"color:rgb(0, 0, 0);\"><p style=\"color:rgb(0, 0, 0);\">\r\n\r\n\r\n\r\n</p</h2></a></td>\r\n                            <!-- If you want to change the Text Right Spacing -->\r\n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\r\n                        </tr>\r\n                    </table>\r\n                </td>\r\n            </tr>\r\n            <tr>\r\n                <td style=\"height: 12px;\"></td>\r\n            </tr>\r\n            <tr>\r\n               <td style=\"text-align: center;font-family: Arial, Helvetica, sans-serif;height: 47px;\">\r\n                    <!-- If you want to change the button text -->\r\n                   <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" class=\"btn_cta\">\r\n                        <span>Schedule Your Delivery</span>\r\n                    </a>\r\n                </td>\r\n            </tr>\r\n\r\n            <tr>\r\n                <td style=\"height: 24px;\"></td>\r\n            </tr>\r\n        </table><style>\r\n        * {\r\n            box-sizing: border-box;\r\n        }\r\n        \r\n        body {\r\n            margin: 0;\r\n            padding: 0;\r\n        }\r\n        \r\n        a {\r\n            text-decoration: none;\r\n           \r\n        }\r\n        \r\n        .btn_cta1 {\r\n            color: #ffffff;\r\n            text-decoration: none;\r\n            background-color: #ff6600;\r\n            border: 1px solid #ff6600;\r\n            border-radius: 5px;\r\n            padding: 22px 15px;\r\n            font-weight: 500;\r\n            transition: all .3s ease;\r\n            position: relative;\r\n            min-width: 160px;\r\n            min-height: 47px;\r\n            display: inline-block;\r\n        }\r\n        \r\n        .btn_cta1 span {\r\n            position: absolute;\r\n            top: 0;\r\n            bottom: 0;\r\n            left: 0;\r\n            right: 0;\r\n            width: max-content;\r\n            height: max-content;\r\n            margin: auto;\r\n            transition: all .3s ease;\r\n            /* If you want to change the blinking speed */\r\n            /* change 0.6s value */\r\n            /* increment will slow down */\r\n            animation: blink 0.6s ease infinite;\r\n        }\r\n        \r\n        .btn_cta1:hover {\r\n            background-color: #ffcc00;\r\n            border-color: #ffcc00;\r\n            transition: all .3s ease;\r\n        }\r\n        \r\n        @keyframes blink {\r\n            from {\r\n                opacity: 0;\r\n                transform: scale(0, 0);\r\n            }\r\n            to {\r\n                opacity: 1;\r\n                transform: scale(1, 1);\r\n            }\r\n        }\r\n        /* Mobile Title Spacing */\r\n        \r\n        @media (max-width: 768px) {\r\n            .mobSpacing {\r\n                width: 10px !important;\r\n            }\r\n        }\r\n    </style>\r\n        <!-- If you want to change the table background-color -->\r\n        <table cellpadding=\"0\" cellspacing=\"0\" bgColor=\"#ffffff\"  width=\"100%\" height=\"100%\">\r\n            <!-- If you want to change the Vertical Gap between Elements -->\r\n            <tr>\r\n                <td style=\"height: 24px;\"></td>\r\n            </tr>\r\n            <tr>\r\n                <!-- If you want to change the Logo -->\r\n                <td style=\"text-align: center;\">\r\n                  \r\n                </td>\r\n            </tr>\r\n            <tr>\r\n                <td style=\"height: 12px;\"></td>\r\n            </tr>\r\n            <tr>\r\n              \r\n               <td style=\"font-size: 22px;color: #6600cc;font-family: Arial, Helvetica, sans-serif; line-height: 1.3; text-align: center;\"><h1><a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\"><p style=\"color:rgb(102, 0, 204)\r\n;\">  ATTENTION NEEDED: Package Delivery Issue Please update your info</p></a></td>\r\n            </tr>\r\n            <tr>\r\n                <td style=\"height: 12px;\"></td>\r\n            </tr>\r\n            <tr>\r\n                <td>\r\n                    <table>\r\n                        <tr>\r\n                            <!-- If you want to change the Text Left Spacing -->\r\n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\r\n                           \r\n                            <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\"><center><h1><p style=\"color:rgb(102, 0, 204);\">Congratulations! Complete The Short Survey.<br>This limited one - time offer expires in 03:42 minutes! \t<br> <br>We Need Your Confirmation To Ship Your Order\r\n\r\n\r\n\r\n\r\n\r\n\r\n<strong><br> \t\r\n\r\n\r\n\r\n\r\n \r\n\r\n\r\n<h1><p style=\"color:rgb(0, 38, 77);\">\r\n    </h1><h1><p style=\"color:rgb(0, 38, 77)\r\n;\">\r\n                            <!-- If you want to change the Text Right Spacing -->\r\n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\r\n                        </tr>\r\n                    </table>\r\n                </td>\r\n            </tr>\r\n            <tr>\r\n                <td style=\"height: 12px;\"></td>\r\n            </tr>\r\n            <tr>\r\n                <td style=\"text-align: center;font-family: Arial, Helvetica, sans-serif;height: 47px;\">\r\n                    <!-- If you want to change the button text -->\r\n                   <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" class=\"btn_cta1\">\r\n                        <span> Confirm </span>\r\n                    </a>\r\n                </td>\r\n            </tr>\r\n\r\n            <tr>\r\n                <td style=\"height: 24px;\"></td>\r\n            </tr>\r\n        </table>\r\n    </center><br><p style=\"text-align:center;font-family: 'Open Sans','Arial','Helvetica',sans-serif;font-size:15px;\"><br><br>\r\nIf you no longer wish to receive these emails, you may unsubscribe by <a href=\"https://bit.ly/3DeJDIq#oop/94468_md/1/35353/5610/487/51623\"> clicking here</a>\r\n<br/><br><br><br><br><br><br><br>\r\n<p style=\"text-align:center;font-family: 'Open Sans','Arial','Helvetica',sans-serif;font-size:9px;\"><br><br>\r\ntest@demisto.com If you no longer wish to receive these emails, you may unsubscribe by  <a href=\"https://bit.ly/3DeJDIq#un/94468_md/1/35353/5610/487/51623\"> clicking here </a><br>\r\n<br>\r\n<br>\r\n</p>\r\n\r\n</body>\r\n<imG sRc=\"//bit.ly/3f5hUSN/#op/94468_md/1/35353/5610/487/51623\"  width=\"1px\" height=\"1px\" style=\"visibility:hidden\"> <br>\r\n<img src=\"https://bit.ly/3f5hUSN/#op/94468_md/1/35353/5610/487/51623\"  width=\"1px\" height=\"1px\" style=\"visibility:hidden\"><br>\r\n\u00a0<table align=\"center\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\"\u00a0\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0width=\"550\" bgcolor=\"white\" style=\"border:2px solid black\">\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<tbody>\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<tr>\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<td align=\"center\">\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<br />\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<table align=\"center\" border=\"0\" cellpadding=\"0\"\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0cellspacing=\"0\" class=\"col-550\" width=\"550\">\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<tbody>\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<!-- content goes here -->\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</tbody>\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</table>\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</td>\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</tr>\r\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</tbody>\r\n\u00a0\u00a0\u00a0\u00a0</table>\r\n</html>",
        "emailmessageid": "<aa01368e-40fc-4366-8e4b-87a2f0ee912a@MW2NAM10FT083.eop-nam10.prod.protection.outlook.com>",
        "emailrecipientscount": 1,
        "emailreturnpath": "PIDKXh1S@2EZjo7SsIi.com",
        "emailsubject": "Christmas packages need confirmation",
        "emailto": "test@demisto.com",
        "emailtocount": "16",
        "endpoint": [
            {}
        ],
        "externalid": "275",
        "filerelationships": [
            {},
            {},
            {}
        ],
        "incidentduration": {
            "accumulatedPause": 0,
            "breachTriggered": false,
            "dueDate": "0001-01-01T00:00:00Z",
            "endDate": "0001-01-01T00:00:00Z",
            "lastPauseDate": "0001-01-01T00:00:00Z",
            "runStatus": "idle",
            "sla": 0,
            "slaStatus": -1,
            "startDate": "0001-01-01T00:00:00Z",
            "totalDuration": 0
        },
        "remediationsla": {
            "accumulatedPause": 0,
            "breachTriggered": false,
            "dueDate": "0001-01-01T00:00:00Z",
            "endDate": "0001-01-01T00:00:00Z",
            "lastPauseDate": "0001-01-01T00:00:00Z",
            "runStatus": "idle",
            "sla": 7200,
            "slaStatus": -1,
            "startDate": "0001-01-01T00:00:00Z",
            "totalDuration": 0
        },
        "renderedhtml": "<a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\">\n<strong>ATTENTION NEEDED: Package Delivery Issue Please update your info</strong><br><br>\n<img src=\"https://files.constantcontact.com/473b1db4901/c6ab20c4-0640-4a69-a07c-876816087800.png\" width=\"100%\" height=\"100%\">\n<img src=\"//files.constantcontact.com/473b1db4901/c6ab20c4-0640-4a69-a07c-876816087800.png\" width=\"100%\" height=\"100%\"><br></a>\n<div id=\"Wrapper\" style=\"padding: 0;margin: 0 auto;text-align: center;font-family: Arial, Helvetica, sans-serif;\">\n\n\n\n    \n    \n    \n    \n    \n    \n\n\n    \n        \n        <table cellpadding=\"0\" cellspacing=\"0\" bgcolor=\"#ececf8\n\" width=\"100%\" height=\"100%\">\n            \n            <tr>\n                <td style=\"height: 24px;\"></td>\n            </tr>\n            <tr>\n                \n                <td style=\"text-align: center;\">\n                   \n                </td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n                \n                <td style=\"font-size: 22px;color: #6600cc;font-family: Arial, Helvetica, sans-serif; line-height: 1.3; text-align: center;\"><h1><a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"><p style=\"color:rgb(255, 102, 0);\">  Christmas packages need confirmation</p></a></td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n                <td>\n                    <table>\n                        <tr>\n                            \n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\n                            \n                            <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"><h1><p style=\"color:rgb(255, 102, 0);\">We have been trying to reach you, your reward is waiting!<br><br>\nWe&#39;ve seen your loyalty and now it&#39;s time for us to give thanks<br><h2><p style=\"color:rgb(0, 0, 255);\">\n\n <h1><p style=\"color:rgb(0, 0, 0);\"><p style=\"color:rgb(0, 0, 0);\">\n\n\n\n</a></td>\n                            \n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\n                        </tr>\n                    </table>\n                </td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n               <td style=\"text-align: center;font-family: Arial, Helvetica, sans-serif;height: 47px;\">\n                    \n                   <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" class=\"btn_cta\" target=\"_blank\" rel=\"nofollow noopener\">\n                        <span>Schedule Your Delivery</span>\n                    </a>\n                </td>\n            </tr>\n\n            <tr>\n                <td style=\"height: 24px;\"></td>\n            </tr>\n        </table>\n        \n        <table cellpadding=\"0\" cellspacing=\"0\" bgcolor=\"#ffffff\" width=\"100%\" height=\"100%\">\n            \n            <tr>\n                <td style=\"height: 24px;\"></td>\n            </tr>\n            <tr>\n                \n                <td style=\"text-align: center;\">\n                  \n                </td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n              \n               <td style=\"font-size: 22px;color: #6600cc;font-family: Arial, Helvetica, sans-serif; line-height: 1.3; text-align: center;\"><h1><a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"><p style=\"color:rgb(102, 0, 204)\n;\">  ATTENTION NEEDED: Package Delivery Issue Please update your info</p></a></td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n                <td>\n                    <table>\n                        <tr>\n                            \n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\n                           \n                            <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"><h1><p style=\"color:rgb(102, 0, 204);\">Congratulations! Complete The Short Survey.<br>This limited one - time offer expires in 03:42 minutes! \t<br> <br>We Need Your Confirmation To Ship Your Order\n\n\n\n\n\n\n<strong><br> \t\n\n\n\n\n \n\n\n<h1><p style=\"color:rgb(0, 38, 77);\">\n    </h1><h1><p style=\"color:rgb(0, 38, 77)\n;\">\n                            \n                            <td style=\"width: 28%;\" class=\"mobSpacing\"></td>\n                        </tr>\n                    </table>\n                </td>\n            </tr>\n            <tr>\n                <td style=\"height: 12px;\"></td>\n            </tr>\n            <tr>\n                <td style=\"text-align: center;font-family: Arial, Helvetica, sans-serif;height: 47px;\">\n                    \n                   <a href=\"https://bit.ly/3DeJDIq#cl/94468_md/1/35353/5610/487/51623\" class=\"btn_cta1\" target=\"_blank\" rel=\"nofollow noopener\">\n                        <span> Confirm </span>\n                    </a>\n                </td>\n            </tr>\n\n            <tr>\n                <td style=\"height: 24px;\"></td>\n            </tr>\n        </table>\n    <br><p style=\"text-align:center;font-family: &#39;Open Sans&#39;,&#39;Arial&#39;,&#39;Helvetica&#39;,sans-serif;font-size:15px;\"><br><br>\nIf you no longer wish to receive these emails, you may unsubscribe by <a href=\"https://bit.ly/3DeJDIq#oop/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"> clicking here</a>\n<br/><br><br><br><br><br><br><br>\n<p style=\"text-align:center;font-family: &#39;Open Sans&#39;,&#39;Arial&#39;,&#39;Helvetica&#39;,sans-serif;font-size:9px;\"><br><br>\ntest@demisto.com If you no longer wish to receive these emails, you may unsubscribe by  <a href=\"https://bit.ly/3DeJDIq#un/94468_md/1/35353/5610/487/51623\" target=\"_blank\" rel=\"nofollow noopener\"> clicking here </a><br>\n<br>\n<br>\n</p>\n\n\n<img src=\"//bit.ly/3f5hUSN/#op/94468_md/1/35353/5610/487/51623\" style=\"visibility:hidden;\"> <br>\n<img src=\"https://bit.ly/3f5hUSN/#op/94468_md/1/35353/5610/487/51623\" style=\"visibility:hidden;\"><br>\n\u00a0<table align=\"center\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" bgcolor=\"white\" style=\"border:2px solid black;\">\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<tbody>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<tr>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<td align=\"center\">\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<br/>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<table align=\"center\" border=\"0\" cellpadding=\"0\" class=\"col-550\" width=\"550\">\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0<tbody>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</tbody>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</table>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</td>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</tr>\n\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0</tbody>\n\u00a0\u00a0\u00a0\u00a0</table>\n",
        "reportedemailcc": "",
        "reportedemailfrom": "geeksquad@emailinfo.geeksquad.com",
        "reportedemailmessageid": "<aa01368e-40fc-4366-8e4b-87a2f0ee912a@MW2NAM10FT083.eop-nam10.prod.protection.outlook.com>",
        "reportedemailorigin": "Attached",
        "reportedemailsubject": "Christmas packages need confirmation",
        "reportedemailto": "test@demisto.com"
    }
]
'''


def get_existing_incidents(input_args, current_incident_type):
    global DEFAULT_ARGS
    get_incidents_args = {}
    get_incidents_args['limit'] = input_args.get('limit', DEFAULT_ARGS['limit'])
    if 'existingIncidentsLookback' in input_args:
        get_incidents_args['fromDate'] = input_args['existingIncidentsLookback']
    elif 'existingIncidentsLookback' in DEFAULT_ARGS:
        get_incidents_args['fromDate'] = DEFAULT_ARGS['existingIncidentsLookback']
    status_scope = input_args.get('statusScope', 'All')
    query_components = []
    if 'query' in input_args and input_args['query']:
        query_components.append(input_args['query'])
    if status_scope == 'ClosedOnly':
        query_components.append('status:closed')
    elif status_scope == 'NonClosedOnly':
        query_components.append('-status:closed')
    elif status_scope == 'All':
        pass
    else:
        return_error(f'Unsupported statusScope: {status_scope}')
    type_values = input_args.get('incidentTypes', current_incident_type)
    if type_values != IGNORE_INCIDENT_TYPE_VALUE:
        type_field = input_args.get('incidentTypeFieldName', 'type')
        type_query = generate_incident_type_query_component(type_field, type_values)
        query_components.append(type_query)
    if len(query_components) > 0:
        get_incidents_args['query'] = ' and '.join(f'({c})' for c in query_components)

    fields = [EMAIL_BODY_FIELD, EMAIL_SUBJECT_FIELD, EMAIL_HTML_FIELD, FROM_FIELD, FROM_DOMAIN_FIELD, 'created', 'id',
              'name', 'status', 'emailto', 'emailcc', 'emailbcc', 'removedfromcampaigns']

    if 'populateFields' in input_args and input_args['populateFields'] is not None:
        get_incidents_args['populateFields'] = ','.join([','.join(fields), input_args['populateFields']])
    else:
        get_incidents_args['populateFields'] = ','.join(fields)

    demisto.debug(f'Calling GetIncidentsByQuery with {get_incidents_args=}')
    incidents_query_res = demisto.executeCommand('GetIncidentsByQuery', get_incidents_args)
    if is_error(incidents_query_res):
        return_error(get_error(incidents_query_res))
    incidents_query_contents = '{}'

    for res in incidents_query_res:
        if res['Contents']:
            incidents_query_contents = res['Contents']
    incidents = json.loads(incidents_query_contents)
    return incidents


def generate_incident_type_query_component(type_field_arg, type_values_arg):
    type_field = type_field_arg.strip()
    type_values = [x.strip() for x in type_values_arg.split(',')]
    types_unions = ' '.join(f'"{t}"' for t in type_values)
    return f'{type_field}:({types_unions})'


def extract_domain(address):
    global no_fetch_extract
    if address == '':
        return ''
    demisto.debug(f'Going to extract domain from {address=}')
    email_address = parseaddr(address)[1]
    ext = no_fetch_extract(email_address)
    return f'{ext.domain}.{ext.suffix}'


def get_text_from_html(html):
    soup = BeautifulSoup(html, features="html.parser")
    # kill all script and style elements
    for script in soup(["script", "style"]):
        script.extract()  # rip it out
    # get text
    text = soup.get_text()
    # break into lines and remove leading and trailing space on each
    lines = (line.strip() for line in text.splitlines())
    # break multi-headlines into a line each
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    # drop blank lines
    text = '\n'.join(chunk for chunk in chunks if chunk)
    return text


def eliminate_urls_extensions(text):
    urls_list = re.findall(URL_REGEX, text)
    if len(urls_list) == 0:
        return text
    formatted_urls_list = format_urls(urls_list)
    for url, formatted_url in zip(urls_list, formatted_urls_list):
        parsed_uri = urlparse(formatted_url)
        url_with_no_path = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
        text = text.replace(url, url_with_no_path)
    return text


def preprocess_email_body(incident):
    email_body = email_html = ''
    if EMAIL_BODY_FIELD in incident:
        email_body = incident[EMAIL_BODY_FIELD]
    if EMAIL_HTML_FIELD in incident:
        email_html = incident[EMAIL_HTML_FIELD]
    if isinstance(email_html, float):
        email_html = ''
    if email_body is None or isinstance(email_body, float) or email_body.strip() == '':
        email_body = get_text_from_html(email_html)
    return eliminate_urls_extensions(email_body)


def preprocess_email_subject(incident):
    email_subject = ''
    if EMAIL_SUBJECT_FIELD in incident:
        email_subject = incident[EMAIL_SUBJECT_FIELD]
    if isinstance(email_subject, float):
        email_subject = ''
    return eliminate_urls_extensions(email_subject)


def concatenate_subject_body(row):
    return f'{row[PREPROCESSED_EMAIL_SUBJECT]}\n{row[PREPROCESSED_EMAIL_BODY]}'


def preprocess_incidents_df(existing_incidents):
    global MERGED_TEXT_FIELD, FROM_FIELD, FROM_DOMAIN_FIELD
    incidents_df = pd.DataFrame(existing_incidents)
    if 'CustomFields' in incidents_df.columns:
        incidents_df['CustomFields'] = incidents_df['CustomFields'].fillna(value={})
        custom_fields_df = incidents_df['CustomFields'].apply(pd.Series)
        unique_keys = [k for k in custom_fields_df if k not in incidents_df]
        custom_fields_df = custom_fields_df[unique_keys]
        incidents_df = pd.concat([incidents_df.drop('CustomFields', axis=1),
                                  custom_fields_df], axis=1).reset_index()
    incidents_df[PREPROCESSED_EMAIL_SUBJECT] = incidents_df.apply(lambda x: preprocess_email_subject(x), axis=1)
    incidents_df[PREPROCESSED_EMAIL_BODY] = incidents_df.apply(lambda x: preprocess_email_body(x), axis=1)
    incidents_df[MERGED_TEXT_FIELD] = incidents_df.apply(concatenate_subject_body, axis=1)
    incidents_df = incidents_df[incidents_df[MERGED_TEXT_FIELD].str.len() >= MIN_TEXT_LENGTH]
    incidents_df = incidents_df.reset_index()
    if FROM_FIELD in incidents_df:
        incidents_df[FROM_FIELD] = incidents_df[FROM_FIELD].fillna(value='')
    else:
        incidents_df[FROM_FIELD] = ''
    incidents_df[FROM_FIELD] = incidents_df[FROM_FIELD].apply(lambda x: x.strip())
    incidents_df[FROM_DOMAIN_FIELD] = incidents_df[FROM_FIELD].apply(lambda address: extract_domain(address))
    incidents_df['created'] = incidents_df['created'].apply(lambda x: dateutil.parser.parse(x))  # type: ignore
    return incidents_df


def incident_has_text_fields(incident):
    text_fields = [EMAIL_SUBJECT_FIELD, EMAIL_HTML_FIELD, EMAIL_BODY_FIELD]
    custom_fields = incident.get('CustomFields', []) or []
    if any(field in incident for field in text_fields):
        return True
    elif 'CustomFields' in incident and any(field in custom_fields for field in text_fields):
        return True
    return False


def filter_out_same_incident(existing_incidents_df, new_incident):
    same_id_mask = existing_incidents_df['id'] == new_incident['id']
    existing_incidents_df = existing_incidents_df[~same_id_mask]
    return existing_incidents_df


def filter_newer_incidents(existing_incidents_df, new_incident):
    new_incident_datetime = dateutil.parser.parse(new_incident['created'])  # type: ignore
    earlier_incidents_mask = existing_incidents_df['created'] < new_incident_datetime
    return existing_incidents_df[earlier_incidents_mask]


def vectorize(text, vectorizer):
    return vectorizer.transform([text]).toarray()[0]


def cosine_sim(a, b):
    return dot(a, b) / (norm(a) * norm(b))


def find_duplicate_incidents(new_incident, existing_incidents_df, max_incidents_to_return):
    global MERGED_TEXT_FIELD, FROM_POLICY
    new_incident_text = new_incident[MERGED_TEXT_FIELD]
    text = [new_incident_text] + existing_incidents_df[MERGED_TEXT_FIELD].tolist()
    vectorizer = CountVectorizer(token_pattern=r"(?u)\b\w\w+\b|!|\?|\"|\'").fit(text)
    new_incident_vector = vectorize(new_incident_text, vectorizer)
    existing_incidents_df['vector'] = existing_incidents_df[MERGED_TEXT_FIELD].apply(lambda x: vectorize(x, vectorizer))
    existing_incidents_df['similarity'] = existing_incidents_df['vector'].apply(
        lambda x: cosine_sim(x, new_incident_vector))
    if FROM_POLICY == FROM_POLICY_DOMAIN:
        mask = (existing_incidents_df[FROM_DOMAIN_FIELD] != '') & \
               (existing_incidents_df[FROM_DOMAIN_FIELD] == new_incident[FROM_DOMAIN_FIELD])
        existing_incidents_df = existing_incidents_df[mask]
    elif FROM_POLICY == FROM_POLICY_EXACT:
        mask = (existing_incidents_df[FROM_FIELD] != '') & \
               (existing_incidents_df[FROM_FIELD] == new_incident[FROM_FIELD])
        existing_incidents_df = existing_incidents_df[mask]
    existing_incidents_df['distance'] = existing_incidents_df['similarity'].apply(lambda x: 1 - x)
    tie_breaker_col = 'id'
    try:
        existing_incidents_df['int_id'] = existing_incidents_df['id'].astype(int)
        tie_breaker_col = 'int_id'
    except Exception:
        pass
    existing_incidents_df = existing_incidents_df.sort_values(by=['distance', 'created', tie_breaker_col])
    return existing_incidents_df.head(max_incidents_to_return)


def return_entry(message, duplicate_incidents_df=None, new_incident=None):
    if duplicate_incidents_df is None:
        duplicate_incident = {}
        all_duplicate_incidents = []
        full_incidents = []
    else:
        most_similar_incident = duplicate_incidents_df.iloc[0]
        duplicate_incident = format_incident_context(most_similar_incident)
        all_duplicate_incidents = [format_incident_context(row) for _, row in duplicate_incidents_df.iterrows()]
        new_incident['created'] = new_incident['created'].astype(str)
        duplicate_incidents_df['created'] = duplicate_incidents_df['created'].astype(str)
        duplicate_incidents_df = duplicate_incidents_df.drop('vector', axis=1)
        full_incidents = new_incident.to_dict(orient='records') + duplicate_incidents_df.to_dict(orient='records')
    outputs = {
        'duplicateIncident': duplicate_incident,
        'isDuplicateIncidentFound': duplicate_incidents_df is not None,
        'allDuplicateIncidents': all_duplicate_incidents
    }
    return_outputs(message, outputs, raw_response=json.dumps(full_incidents))


def format_incident_context(df_row):
    duplicate_incident = {
        'rawId': df_row['id'],
        'id': df_row['id'],
        'name': df_row.get('name'),
        'similarity': df_row.get('similarity'),
    }
    return duplicate_incident


def close_new_incident_and_link_to_existing(new_incident, duplicate_incidents_df):
    mask = duplicate_incidents_df['similarity'] >= SIMILARITY_THRESHOLD
    duplicate_incidents_df = duplicate_incidents_df[mask]
    most_similar_incident = duplicate_incidents_df.iloc[0]
    max_similarity = duplicate_incidents_df.iloc[0]['similarity']
    min_similarity = duplicate_incidents_df.iloc[-1]['similarity']
    formatted_incident, headers = format_incident_hr(duplicate_incidents_df)
    incident = 'incidents' if len(duplicate_incidents_df) > 1 else 'incident'

    if max_similarity > min_similarity:
        title = "Duplicate {} found with similarity {:.1f}%-{:.1f}%".format(incident, min_similarity * 100,
                                                                            max_similarity * 100)
    else:
        title = "Duplicate {} found with similarity {:.1f}%".format(incident, max_similarity * 100)
    message = tableToMarkdown(title,
                              formatted_incident, headers)
    if demisto.args().get('closeAsDuplicate', 'true') == 'true':
        res = demisto.executeCommand("CloseInvestigationAsDuplicate", {
            'duplicateId': most_similar_incident['id']})
        if is_error(res):
            return_error(res)
        message += 'This incident (#{}) will be closed and linked to #{}.'.format(new_incident.iloc[0]['id'],
                                                                                  most_similar_incident['id'])
    return_entry(message, duplicate_incidents_df, new_incident)


def create_new_incident():
    return_entry('This incident is not a duplicate of an existing incident.')


def format_incident_hr(duplicate_incidents_df):
    incidents_list = duplicate_incidents_df.to_dict('records')
    json_lists = []
    status_map = {'0': 'Pending', '1': 'Active', '2': 'Closed', '3': 'Archive'}
    for incident in incidents_list:
        json_lists.append({'Id': "[{}](#/Details/{})".format(incident['id'], incident['id']),
                           'Name': incident['name'],
                           'Status': status_map[str(incident.get('status'))],
                           'Time': str(incident['created']),
                           'Email From': incident.get(demisto.args().get(FROM_FIELD)),
                           'Text Similarity': "{:.1f}%".format(incident['similarity'] * 100),
                           })
    headers = ['Id', 'Name', 'Status', 'Time', 'Email From', 'Text Similarity']
    return json_lists, headers


def create_new_incident_low_similarity(duplicate_incidents_df):
    message = '## This incident is not a duplicate of an existing incident.\n'
    similarity = duplicate_incidents_df.iloc[0]['similarity']
    if similarity > SIMILARITY_THRESHOLD - CLOSE_TO_SIMILAR_DISTANCE:
        mask = duplicate_incidents_df['similarity'] >= SIMILARITY_THRESHOLD - CLOSE_TO_SIMILAR_DISTANCE
        duplicate_incidents_df = duplicate_incidents_df[mask]
        formatted_incident, headers = format_incident_hr(duplicate_incidents_df)
        message += tableToMarkdown("Most similar incidents found", formatted_incident, headers=headers)
        message += 'The threshold for considering 2 incidents as duplicate is a similarity ' \
                   'of {:.1f}%.\n'.format(SIMILARITY_THRESHOLD * 100)
        message += 'Therefore these 2 incidents will not be considered as duplicate and the current incident ' \
                   'will remain active.\n'
    return_entry(message)


def create_new_incident_no_text_fields():
    text_fields = [EMAIL_BODY_FIELD, EMAIL_HTML_FIELD, EMAIL_SUBJECT_FIELD]
    message = 'No text fields were found within this incident: {}.\n'.format(','.join(text_fields))
    message += 'Incident will remain active.'
    return_entry(message)


def create_new_incident_too_short():
    return_entry('Incident text after preprocessing is too short for deduplication. Incident will remain active.')


def main():
    global EMAIL_BODY_FIELD, EMAIL_SUBJECT_FIELD, EMAIL_HTML_FIELD, FROM_FIELD, MIN_TEXT_LENGTH, FROM_POLICY
    input_args = demisto.args()
    EMAIL_BODY_FIELD = input_args.get('emailBody', EMAIL_BODY_FIELD)
    EMAIL_SUBJECT_FIELD = input_args.get('emailSubject', EMAIL_SUBJECT_FIELD)
    EMAIL_HTML_FIELD = input_args.get('emailBodyHTML', EMAIL_HTML_FIELD)
    FROM_FIELD = input_args.get('emailFrom', FROM_FIELD)
    FROM_POLICY = input_args.get('fromPolicy', FROM_POLICY)
    max_incidents_to_return = input_args.get('maxIncidentsToReturn', '20')
    try:
        max_incidents_to_return = int(max_incidents_to_return)
    except Exception:
        return_error('Illegal value of arguement "maxIncidentsToReturn": {}. '
                     'Value should be an integer'.format(max_incidents_to_return))
    new_incident = demisto.incidents()[0]
    type_field = input_args.get('incidentTypeFieldName', 'type')
    existing_incidents = json.loads(INCIDENTS) * 1000 #  get_existing_incidents(input_args, new_incident.get(type_field, IGNORE_INCIDENT_TYPE_VALUE))
    demisto.debug(f'found {len(existing_incidents)} incidents by query')
    if len(existing_incidents) == 0:
        create_new_incident()
        return None
    if not incident_has_text_fields(new_incident):
        create_new_incident_no_text_fields()
        return None
    new_incident_df = preprocess_incidents_df([new_incident])
    if len(new_incident_df) == 0:  # len(new_incident_df)==0 means new incident is too short
        create_new_incident_too_short()
        return None
    existing_incidents_df = preprocess_incidents_df(existing_incidents)
    # existing_incidents_df = filter_out_same_incident(existing_incidents_df, new_incident)
    # existing_incidents_df = filter_newer_incidents(existing_incidents_df, new_incident)
    if len(existing_incidents_df) == 0:
        create_new_incident()
        return None
    new_incident_preprocessed = new_incident_df.iloc[0].to_dict()
    duplicate_incidents_df = find_duplicate_incidents(new_incident_preprocessed,
                                                      existing_incidents_df, max_incidents_to_return)
    if len(duplicate_incidents_df) == 0:
        create_new_incident()
        return None
    if duplicate_incidents_df.iloc[0]['similarity'] < SIMILARITY_THRESHOLD:
        create_new_incident_low_similarity(duplicate_incidents_df)
        return None
    else:
        return close_new_incident_and_link_to_existing(new_incident_df, duplicate_incidents_df)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

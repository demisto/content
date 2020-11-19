import demistomock as demisto
from CommonServerPython import *

from email import message_from_string
from email.header import decode_header
import base64
from base64 import b64decode

import email.utils
from email.parser import HeaderParser
import traceback
import tempfile
import sys

# -*- coding: utf-8 -*-
# !/usr/bin/env python
# Based on MS-OXMSG protocol specification
# ref:https://blogs.msdn.microsoft.com/openspecification/2010/06/20/msg-file-format-rights-managed-email-message-part-2/
# ref:https://msdn.microsoft.com/en-us/library/cc463912(v=EXCHG.80).aspx
import email
import re
# -*- coding: utf-8 -*-
import codecs
import os
import unicodedata
from email import encoders
from email.header import Header
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import getaddresses

from olefile import OleFileIO, isOleFile

# coding=utf-8
from datetime import datetime, timedelta
from struct import unpack
import chardet

reload(sys)
sys.setdefaultencoding('utf8')  # pylint: disable=no-member

MAX_DEPTH_CONST = 3

"""
https://github.com/vikramarsid/msg_parser

Copyright (c) 2009-2018 Vikram Arsid <vikramarsid@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
   of conditions and the following disclaimer in the documentation and/or other materials
   provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.

"""

DATA_TYPE_MAP = {
    "0x0000": "PtypUnspecified",
    "0x0001": "PtypNull",
    "0x0002": "PtypInteger16",
    "0x0003": "PtypInteger32",
    "0x0004": "PtypFloating32",
    "0x0005": "PtypFloating64",
    "0x0006": "PtypCurrency",
    "0x0007": "PtypFloatingTime",
    "0x000A": "PtypErrorCode",
    "0x000B": "PtypBoolean",
    "0x000D": "PtypObject",
    "0x0014": "PtypInteger64",
    "0x001E": "PtypString8",
    "0x001F": "PtypString",
    "0x0040": "PtypTime",
    "0x0048": "PtypGuid",
    "0x00FB": "PtypServerId",
    "0x00FD": "PtypRestriction",
    "0x00FE": "PtypRuleAction",
    "0x0102": "PtypBinary",
    "0x1002": "PtypMultipleInteger16",
    "0x1003": "PtypMultipleInteger32",
    "0x1004": "PtypMultipleFloating32",
    "0x1005": "PtypMultipleFloating64",
    "0x1006": "PtypMultipleCurrency",
    "0x1007": "PtypMultipleFloatingTime",
    "0x1014": "PtypMultipleInteger64",
    "0x101F": "PtypMultipleString",
    "0x101E": "PtypMultipleString8",
    "0x1040": "PtypMultipleTime",
    "0x1048": "PtypMultipleGuid",
    "0x1102": "PtypMultipleBinary"
}


class DataModel(object):

    def __init__(self):
        self.data_type_name = None

    @staticmethod
    def lookup_data_type_name(data_type):
        return DATA_TYPE_MAP.get(data_type)

    def get_value(self, data_value, data_type_name=None, data_type=None):

        if data_type_name:
            self.data_type_name = data_type_name
        elif data_type:
            self.data_type_name = self.lookup_data_type_name(data_type)
        else:
            raise Exception("required arguments not provided to the constructor of the class.")

        if not hasattr(self, self.data_type_name):
            return None
        value = getattr(self, self.data_type_name)(data_value)
        return value

    @staticmethod
    def PtypUnspecified(data_value):
        return data_value

    @staticmethod
    def PtypNull(data_value):
        return None

    @staticmethod
    def PtypInteger16(data_value):
        return int(data_value.encode('hex'), 16)

    @staticmethod
    def PtypInteger32(data_value):
        return int(data_value.encode('hex'), 32)

    @staticmethod
    def PtypFloating32(data_value):
        return unpack('f', data_value)[0]

    @staticmethod
    def PtypFloating64(data_value):
        return unpack('d', data_value)[0]

    @staticmethod
    def PtypCurrency(data_value):
        return data_value

    @staticmethod
    def PtypFloatingTime(data_value):
        return data_value

    @staticmethod
    def PtypErrorCode(data_value):
        return unpack('I', data_value)[0]

    @staticmethod
    def PtypBoolean(data_value):
        return unpack('B', data_value[0])[0] != 0

    @staticmethod
    def PtypObject(data_value):
        if data_value and '\x00' in data_value:
            pass
            # data_value = data_value.replace('\x00', '')
        return data_value

    @staticmethod
    def PtypInteger64(data_value):
        return unpack('q', data_value)[0]

    @staticmethod
    def PtypString8(data_value):
        if data_value and '\x00' in data_value:
            data_value = data_value.replace('\x00', '')
        return data_value

    @staticmethod
    def PtypString(data_value):
        if data_value:
            try:
                res = chardet.detect(data_value)
                enc = res['encoding'] or 'ascii'  # in rare cases chardet fails to detect and return None as encoding
                data_value = data_value.decode(enc, errors='ignore').replace('\x00', '')
            except UnicodeDecodeError:
                data_value = data_value.decode("utf-16-le", errors="ignore").replace('\x00', '')

        return data_value

    @staticmethod
    def PtypTime(data_value):
        return get_time(data_value)

    @staticmethod
    def PtypGuid(data_value):
        return data_value

    @staticmethod
    def PtypServerId(data_value):
        return data_value

    @staticmethod
    def PtypRestriction(data_value):
        return data_value

    @staticmethod
    def PtypRuleAction(data_value):
        return data_value

    @staticmethod
    def PtypBinary(data_value):
        if data_value and '\x00' in data_value:
            data_value = data_value.replace('\x00', '')
        return data_value

    @staticmethod
    def PtypMultipleInteger16(data_value):
        entry_count = len(data_value) / 2
        return [unpack('h', data_value[i * 2:(i + 1) * 2])[0] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleInteger32(data_value):
        entry_count = len(data_value) / 4
        return [unpack('i', data_value[i * 4:(i + 1) * 4])[0] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleFloating32(data_value):
        entry_count = len(data_value) / 4
        return [unpack('f', data_value[i * 4:(i + 1) * 4])[0] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleFloating64(data_value):
        entry_count = len(data_value) / 8
        return [unpack('d', data_value[i * 8:(i + 1) * 8])[0] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleCurrency(data_value):
        return data_value

    @staticmethod
    def PtypMultipleFloatingTime(data_value):
        entry_count = len(data_value) / 8
        return [get_floating_time(data_value[i * 8:(i + 1) * 8]) for i in range(entry_count)]

    @staticmethod
    def PtypMultipleInteger64(data_value):
        entry_count = len(data_value) / 8
        return [unpack('q', data_value[i * 8:(i + 1) * 8])[0] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleString(data_value):
        # string_list = []
        # for item_bytes in data_value:
        #     if item_bytes and '\x00' in item_bytes:
        #         item_bytes = item_bytes.replace('\x00', '')
        #     string_list.append(item_bytes.decode('utf-16-le'))
        return data_value

    @staticmethod
    def PtypMultipleString8(data_value):
        return data_value

    @staticmethod
    def PtypMultipleTime(data_value):
        entry_count = len(data_value) / 8
        return [get_time(data_value[i * 8:(i + 1) * 8]) for i in range(entry_count)]

    @staticmethod
    def PtypMultipleGuid(data_value):
        entry_count = len(data_value) / 16
        return [data_value[i * 16:(i + 1) * 16] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleBinary(data_value):
        return data_value


def get_floating_time(data_value):
    return datetime(
        year=1899, month=12, day=30
    ) + timedelta(
        days=unpack('d', data_value)[0]
    )


def get_time(data_value):
    return datetime(
        year=1601, month=1, day=1
    ) + timedelta(
        microseconds=unpack('q', data_value)[0] / 10.0
    )


def get_multi_value_offsets(data_value):
    ul_count = unpack('I', data_value[:4])[0]

    if ul_count == 1:
        rgul_data_offsets = [8]
    else:
        rgul_data_offsets = [unpack('Q', data_value[4 + i * 8:4 + (i + 1) * 8])[0] for i in range(ul_count)]

    rgul_data_offsets.append(len(data_value))

    return ul_count, rgul_data_offsets


class EmailFormatter(object):
    def __init__(self, msg_object):
        self.msg_obj = msg_object
        self.message = MIMEMultipart()
        self.message.set_charset('utf-8')

    def build_email(self):

        # Setting Message ID
        self.message.set_param("Message-ID", self.msg_obj.message_id)

        # Encoding for unicode subject
        self.message['Subject'] = Header(self.msg_obj.subject, charset='UTF-8')

        # Setting Date Time
        # Returns a date string as specified by RFC 2822, e.g.: Fri, 09 Nov 2001 01:08:47 -0000
        self.message['Date'] = str(self.msg_obj.sent_date)

        # At least one recipient is required
        # Required fromAddress
        from_address = flatten_list(self.msg_obj.sender)
        if from_address:
            self.message['From'] = from_address

        to_address = flatten_list(self.msg_obj.header_dict.get("To"))
        if to_address:
            self.message['To'] = to_address

        cc_address = flatten_list(self.msg_obj.header_dict.get("CC"))
        if cc_address:
            self.message['CC'] = cc_address

        bcc_address = flatten_list(self.msg_obj.header_dict.get("BCC"))
        if bcc_address:
            self.message['BCC'] = bcc_address

        # Add reply-to
        reply_to = flatten_list(self.msg_obj.reply_to)
        if reply_to:
            self.message.add_header('reply-to', reply_to)
        else:
            self.message.add_header('reply-to', from_address)

        # Required Email body content
        body_content = self.msg_obj.body
        if body_content:
            if "<html>" in body_content:
                body_type = 'html'
            else:
                body_type = 'plain'

            body = MIMEText(_text=body_content, _subtype=body_type, _charset="UTF-8")
            self.message.attach(body)
        else:
            raise KeyError("Missing email body")

        # Add message preamble
        self.message.preamble = 'You will not see this in a MIME-aware mail reader.\n'

        # Optional attachments
        attachments = self.msg_obj.attachments
        if attachments:
            self._process_attachments(self.msg_obj.attachments)

        # composed email
        composed = self.message.as_string()

        return composed

    def save_file(self, file_path):

        eml_content = self.build_email()

        file_name = str(self.message['Subject']) + ".eml"

        eml_file_path = os.path.join(file_path, file_name)

        with codecs.open(eml_file_path, mode="wb+", encoding="utf-8") as eml_file:
            eml_file.write(eml_content.decode("utf-8"))

        return eml_file_path

    def _process_attachments(self, attachments):
        for attachment in attachments:
            ctype = attachment.AttachMimeTag
            data = attachment.data
            filename = attachment.DisplayName
            maintype, subtype = ctype.split('/', 1)

            if maintype == 'text' or "message" in maintype:
                attach = MIMEText(data, _subtype=subtype)
            elif maintype == 'image':
                attach = MIMEImage(data, _subtype=subtype)  # type: ignore[assignment]
            elif maintype == 'audio':
                attach = MIMEAudio(data, _subtype=subtype)  # type: ignore[assignment]
            else:
                attach = MIMEBase(maintype, subtype)  # type: ignore[assignment]
                attach.set_payload(data)

                # Encode the payload using Base64
                encoders.encode_base64(attach)
            # Set the filename parameter
            base_filename = os.path.basename(filename)
            attach.add_header('Content-ID', '<{}>'.format(base_filename))
            attach.add_header('Content-Disposition', 'attachment', filename=base_filename)
            self.message.attach(attach)


def flatten_list(string_list):
    if string_list and isinstance(string_list, list):
        string = ",".join(string_list)
        return string
    return None


def normalize(input_str):
    if not input_str:
        return input_str
    try:
        if isinstance(input_str, list):
            input_str = [s.decode('ascii') for s in input_str]
        else:
            input_str.decode('ascii')
        return input_str
    except UnicodeError:
        if not isinstance(input_str, unicode):
            input_str = str(input_str).decode("utf-8", "replace")
        normalized = unicodedata.normalize('NFKD', input_str)
        if not normalized.strip():
            normalized = input_str.encode('unicode-escape').decode('utf-8')

        return normalized


# coding=utf-8
# autogenerated using ms_props_generator.py
PROPS_ID_MAP = {
    "0x0001": {
        "data_type": "0x0102",
        "name": "TemplateData"
    },
    "0x0002": {
        "data_type": "0x000B",
        "name": "AlternateRecipientAllowed"
    },
    "0x0004": {
        "data_type": "0x0102",
        "name": "ScriptData"
    },
    "0x0005": {
        "data_type": "0x000B",
        "name": "AutoForwarded"
    },
    "0x000F": {
        "data_type": "0x0040",
        "name": "DeferredDeliveryTime"
    },
    "0x0010": {
        "data_type": "0x0040",
        "name": "DeliverTime"
    },
    "0x0015": {
        "data_type": "0x0040",
        "name": "ExpiryTime"
    },
    "0x0017": {
        "data_type": "0x0003",
        "name": "Importance"
    },
    "0x001A": {
        "data_type": "0x001F",
        "name": "MessageClass"
    },
    "0x0023": {
        "data_type": "0x000B",
        "name": "OriginatorDeliveryReportRequested"
    },
    "0x0025": {
        "data_type": "0x0102",
        "name": "ParentKey"
    },
    "0x0026": {
        "data_type": "0x0003",
        "name": "Priority"
    },
    "0x0029": {
        "data_type": "0x000B",
        "name": "ReadReceiptRequested"
    },
    "0x002A": {
        "data_type": "0x0040",
        "name": "ReceiptTime"
    },
    "0x002B": {
        "data_type": "0x000B",
        "name": "RecipientReassignmentProhibited"
    },
    "0x002E": {
        "data_type": "0x0003",
        "name": "OriginalSensitivity"
    },
    "0x0030": {
        "data_type": "0x0040",
        "name": "ReplyTime"
    },
    "0x0031": {
        "data_type": "0x0102",
        "name": "ReportTag"
    },
    "0x0032": {
        "data_type": "0x0040",
        "name": "ReportTime"
    },
    "0x0036": {
        "data_type": "0x0003",
        "name": "Sensitivity"
    },
    "0x0037": {
        "data_type": "0x001F",
        "name": "Subject"
    },
    "0x0039": {
        "data_type": "0x0040",
        "name": "ClientSubmitTime"
    },
    "0x003A": {
        "data_type": "0x001F",
        "name": "ReportName"
    },
    "0x003B": {
        "data_type": "0x0102",
        "name": "SentRepresentingSearchKey"
    },
    "0x003D": {
        "data_type": "0x001F",
        "name": "SubjectPrefix"
    },
    "0x003F": {
        "data_type": "0x0102",
        "name": "ReceivedByEntryId"
    },
    "0x0040": {
        "data_type": "0x001F",
        "name": "ReceivedByName"
    },
    "0x0041": {
        "data_type": "0x0102",
        "name": "SentRepresentingEntryId"
    },
    "0x0042": {
        "data_type": "0x001F",
        "name": "SentRepresentingName"
    },
    "0x0043": {
        "data_type": "0x0102",
        "name": "ReceivedRepresentingEntryId"
    },
    "0x0044": {
        "data_type": "0x001F",
        "name": "ReceivedRepresentingName"
    },
    "0x0045": {
        "data_type": "0x0102",
        "name": "ReportEntryId"
    },
    "0x0046": {
        "data_type": "0x0102",
        "name": "ReadReceiptEntryId"
    },
    "0x0047": {
        "data_type": "0x0102",
        "name": "MessageSubmissionId"
    },
    "0x0049": {
        "data_type": "0x001F",
        "name": "OriginalSubject"
    },
    "0x004B": {
        "data_type": "0x001F",
        "name": "OriginalMessageClass"
    },
    "0x004C": {
        "data_type": "0x0102",
        "name": "OriginalAuthorEntryId"
    },
    "0x004D": {
        "data_type": "0x001F",
        "name": "OriginalAuthorName"
    },
    "0x004E": {
        "data_type": "0x0040",
        "name": "OriginalSubmitTime"
    },
    "0x004F": {
        "data_type": "0x0102",
        "name": "ReplyRecipientEntries"
    },
    "0x0050": {
        "data_type": "0x001F",
        "name": "ReplyRecipientNames"
    },
    "0x0051": {
        "data_type": "0x0102",
        "name": "ReceivedBySearchKey"
    },
    "0x0052": {
        "data_type": "0x0102",
        "name": "ReceivedRepresentingSearchKey"
    },
    "0x0053": {
        "data_type": "0x0102",
        "name": "ReadReceiptSearchKey"
    },
    "0x0054": {
        "data_type": "0x0102",
        "name": "ReportSearchKey"
    },
    "0x0055": {
        "data_type": "0x0040",
        "name": "OriginalDeliveryTime"
    },
    "0x0057": {
        "data_type": "0x000B",
        "name": "MessageToMe"
    },
    "0x0058": {
        "data_type": "0x000B",
        "name": "MessageCcMe"
    },
    "0x0059": {
        "data_type": "0x000B",
        "name": "MessageRecipientMe"
    },
    "0x005A": {
        "data_type": "0x001F",
        "name": "OriginalSenderName"
    },
    "0x005B": {
        "data_type": "0x0102",
        "name": "OriginalSenderEntryId"
    },
    "0x005C": {
        "data_type": "0x0102",
        "name": "OriginalSenderSearchKey"
    },
    "0x005D": {
        "data_type": "0x001F",
        "name": "OriginalSentRepresentingName"
    },
    "0x005E": {
        "data_type": "0x0102",
        "name": "OriginalSentRepresentingEntryId"
    },
    "0x005F": {
        "data_type": "0x0102",
        "name": "OriginalSentRepresentingSearchKey"
    },
    "0x0060": {
        "data_type": "0x0040",
        "name": "StartDate"
    },
    "0x0061": {
        "data_type": "0x0040",
        "name": "EndDate"
    },
    "0x0062": {
        "data_type": "0x0003",
        "name": "OwnerAppointmentId"
    },
    "0x0063": {
        "data_type": "0x000B",
        "name": "ResponseRequested"
    },
    "0x0064": {
        "data_type": "0x001F",
        "name": "SentRepresentingAddressType"
    },
    "0x0065": {
        "data_type": "0x001F",
        "name": "SentRepresentingEmailAddress"
    },
    "0x0066": {
        "data_type": "0x001F",
        "name": "OriginalSenderAddressType"
    },
    "0x0067": {
        "data_type": "0x001F",
        "name": "OriginalSenderEmailAddress"
    },
    "0x0068": {
        "data_type": "0x001F",
        "name": "OriginalSentRepresentingAddressType"
    },
    "0x0069": {
        "data_type": "0x001F",
        "name": "OriginalSentRepresentingEmailAddress"
    },
    "0x0070": {
        "data_type": "0x001F",
        "name": "ConversationTopic"
    },
    "0x0071": {
        "data_type": "0x0102",
        "name": "ConversationIndex"
    },
    "0x0072": {
        "data_type": "0x001F",
        "name": "OriginalDisplayBcc"
    },
    "0x0073": {
        "data_type": "0x001F",
        "name": "OriginalDisplayCc"
    },
    "0x0074": {
        "data_type": "0x001F",
        "name": "OriginalDisplayTo"
    },
    "0x0075": {
        "data_type": "0x001F",
        "name": "ReceivedByAddressType"
    },
    "0x0076": {
        "data_type": "0x001F",
        "name": "ReceivedByEmailAddress"
    },
    "0x0077": {
        "data_type": "0x001F",
        "name": "ReceivedRepresentingAddressType"
    },
    "0x0078": {
        "data_type": "0x001F",
        "name": "ReceivedRepresentingEmailAddress"
    },
    "0x007D": {
        "data_type": "0x001F",
        "name": "TransportMessageHeaders"
    },
    "0x007F": {
        "data_type": "0x0102",
        "name": "TnefCorrelationKey"
    },
    "0x0080": {
        "data_type": "0x001F",
        "name": "ReportDisposition"
    },
    "0x0081": {
        "data_type": "0x001F",
        "name": "ReportDispositionMode"
    },
    "0x0807": {
        "data_type": "0x0003",
        "name": "AddressBookRoomCapacity"
    },
    "0x0809": {
        "data_type": "0x001F",
        "name": "AddressBookRoomDescription"
    },
    "0x0C04": {
        "data_type": "0x0003",
        "name": "NonDeliveryReportReasonCode"
    },
    "0x0C05": {
        "data_type": "0x0003",
        "name": "NonDeliveryReportDiagCode"
    },
    "0x0C06": {
        "data_type": "0x000B",
        "name": "NonReceiptNotificationRequested"
    },
    "0x0C08": {
        "data_type": "0x000B",
        "name": "OriginatorNonDeliveryReportRequested"
    },
    "0x0C15": {
        "data_type": "0x0003",
        "name": "RecipientType"
    },
    "0x0C17": {
        "data_type": "0x000B",
        "name": "ReplyRequested"
    },
    "0x0C19": {
        "data_type": "0x0102",
        "name": "SenderEntryId"
    },
    "0x0C1A": {
        "data_type": "0x001F",
        "name": "SenderName"
    },
    "0x0C1B": {
        "data_type": "0x001F",
        "name": "SupplementaryInfo"
    },
    "0x0C1D": {
        "data_type": "0x0102",
        "name": "SenderSearchKey"
    },
    "0x0C1E": {
        "data_type": "0x001F",
        "name": "SenderAddressType"
    },
    "0x0C1F": {
        "data_type": "0x001F",
        "name": "SenderEmailAddress"
    },
    "0x0C21": {
        "data_type": "0x001F",
        "name": "RemoteMessageTransferAgent"
    },
    "0x0E01": {
        "data_type": "0x000B",
        "name": "DeleteAfterSubmit"
    },
    "0x0E02": {
        "data_type": "0x001F",
        "name": "DisplayBcc"
    },
    "0x0E03": {
        "data_type": "0x001F",
        "name": "DisplayCc"
    },
    "0x0E04": {
        "data_type": "0x001F",
        "name": "DisplayTo"
    },
    "0x0E06": {
        "data_type": "0x0040",
        "name": "MessageDeliveryTime"
    },
    "0x0E07": {
        "data_type": "0x0003",
        "name": "MessageFlags"
    },
    "0x0E08": {
        "data_type": "0x0014",
        "name": "MessageSizeExtended"
    },
    "0x0E09": {
        "data_type": "0x0102",
        "name": "ParentEntryId"
    },
    "0x0E0F": {
        "data_type": "0x000B",
        "name": "Responsibility"
    },
    "0x0E12": {
        "data_type": "0x000D",
        "name": "MessageRecipients"
    },
    "0x0E13": {
        "data_type": "0x000D",
        "name": "MessageAttachments"
    },
    "0x0E17": {
        "data_type": "0x0003",
        "name": "MessageStatus"
    },
    "0x0E1B": {
        "data_type": "0x000B",
        "name": "HasAttachments"
    },
    "0x0E1D": {
        "data_type": "0x001F",
        "name": "NormalizedSubject"
    },
    "0x0E1F": {
        "data_type": "0x000B",
        "name": "RtfInSync"
    },
    "0x0E20": {
        "data_type": "0x0003",
        "name": "AttachSize"
    },
    "0x0E21": {
        "data_type": "0x0003",
        "name": "AttachNumber"
    },
    "0x0E28": {
        "data_type": "0x001F",
        "name": "PrimarySendAccount"
    },
    "0x0E29": {
        "data_type": "0x001F",
        "name": "NextSendAcct"
    },
    "0x0E2B": {
        "data_type": "0x0003",
        "name": "ToDoItemFlags"
    },
    "0x0E2C": {
        "data_type": "0x0102",
        "name": "SwappedToDoStore"
    },
    "0x0E2D": {
        "data_type": "0x0102",
        "name": "SwappedToDoData"
    },
    "0x0E69": {
        "data_type": "0x000B",
        "name": "Read"
    },
    "0x0E6A": {
        "data_type": "0x001F",
        "name": "SecurityDescriptorAsXml"
    },
    "0x0E79": {
        "data_type": "0x0003",
        "name": "TrustSender"
    },
    "0x0E84": {
        "data_type": "0x0102",
        "name": "ExchangeNTSecurityDescriptor"
    },
    "0x0E99": {
        "data_type": "0x0102",
        "name": "ExtendedRuleMessageActions"
    },
    "0x0E9A": {
        "data_type": "0x0102",
        "name": "ExtendedRuleMessageCondition"
    },
    "0x0E9B": {
        "data_type": "0x0003",
        "name": "ExtendedRuleSizeLimit"
    },
    "0x0FF4": {
        "data_type": "0x0003",
        "name": "Access"
    },
    "0x0FF5": {
        "data_type": "0x0003",
        "name": "RowType"
    },
    "0x0FF6": {
        "data_type": "0x0102",
        "name": "InstanceKey"
    },
    "0x0FF7": {
        "data_type": "0x0003",
        "name": "AccessLevel"
    },
    "0x0FF8": {
        "data_type": "0x0102",
        "name": "MappingSignature"
    },
    "0x0FF9": {
        "data_type": "0x0102",
        "name": "RecordKey"
    },
    "0x0FFB": {
        "data_type": "0x0102",
        "name": "StoreEntryId"
    },
    "0x0FFE": {
        "data_type": "0x0003",
        "name": "ObjectType"
    },
    "0x0FFF": {
        "data_type": "0x0102",
        "name": "EntryId"
    },
    "0x1000": {
        "data_type": "0x001F",
        "name": "Body"
    },
    "0x1001": {
        "data_type": "0x001F",
        "name": "ReportText"
    },
    "0x1009": {
        "data_type": "0x0102",
        "name": "RtfCompressed"
    },
    "0x1013": {
        "data_type": "0x0102",
        "name": "Html"
    },
    "0x1014": {
        "data_type": "0x001F",
        "name": "BodyContentLocation"
    },
    "0x1015": {
        "data_type": "0x001F",
        "name": "BodyContentId"
    },
    "0x1016": {
        "data_type": "0x0003",
        "name": "NativeBody"
    },
    "0x1035": {
        "data_type": "0x001F",
        "name": "InternetMessageId"
    },
    "0x1039": {
        "data_type": "0x001F",
        "name": "InternetReferences"
    },
    "0x1042": {
        "data_type": "0x001F",
        "name": "InReplyToId"
    },
    "0x1043": {
        "data_type": "0x001F",
        "name": "ListHelp"
    },
    "0x1044": {
        "data_type": "0x001F",
        "name": "ListSubscribe"
    },
    "0x1045": {
        "data_type": "0x001F",
        "name": "ListUnsubscribe"
    },
    "0x1046": {
        "data_type": "0x001F",
        "name": "OriginalMessageId"
    },
    "0x1080": {
        "data_type": "0x0003",
        "name": "IconIndex"
    },
    "0x1081": {
        "data_type": "0x0003",
        "name": "LastVerbExecuted"
    },
    "0x1082": {
        "data_type": "0x0040",
        "name": "LastVerbExecutionTime"
    },
    "0x1090": {
        "data_type": "0x0003",
        "name": "FlagStatus"
    },
    "0x1091": {
        "data_type": "0x0040",
        "name": "FlagCompleteTime"
    },
    "0x1095": {
        "data_type": "0x0003",
        "name": "FollowupIcon"
    },
    "0x1096": {
        "data_type": "0x0003",
        "name": "BlockStatus"
    },
    "0x10C3": {
        "data_type": "0x0040",
        "name": "ICalendarStartTime"
    },
    "0x10C4": {
        "data_type": "0x0040",
        "name": "ICalendarEndTime"
    },
    "0x10C5": {
        "data_type": "0x0040",
        "name": "CdoRecurrenceid"
    },
    "0x10CA": {
        "data_type": "0x0040",
        "name": "ICalendarReminderNextTime"
    },
    "0x10F4": {
        "data_type": "0x000B",
        "name": "AttributeHidden"
    },
    "0x10F6": {
        "data_type": "0x000B",
        "name": "AttributeReadOnly"
    },
    "0x3000": {
        "data_type": "0x0003",
        "name": "Rowid"
    },
    "0x3001": {
        "data_type": "0x001F",
        "name": "DisplayName"
    },
    "0x3002": {
        "data_type": "0x001F",
        "name": "AddressType"
    },
    "0x3003": {
        "data_type": "0x001F",
        "name": "EmailAddress"
    },
    "0x3004": {
        "data_type": "0x001F",
        "name": "Comment"
    },
    "0x3005": {
        "data_type": "0x0003",
        "name": "Depth"
    },
    "0x3007": {
        "data_type": "0x0040",
        "name": "CreationTime"
    },
    "0x3008": {
        "data_type": "0x0040",
        "name": "LastModificationTime"
    },
    "0x300B": {
        "data_type": "0x0102",
        "name": "SearchKey"
    },
    "0x3010": {
        "data_type": "0x0102",
        "name": "TargetEntryId"
    },
    "0x3013": {
        "data_type": "0x0102",
        "name": "ConversationId"
    },
    "0x3016": {
        "data_type": "0x000B",
        "name": "ConversationIndexTracking"
    },
    "0x3018": {
        "data_type": "0x0102",
        "name": "ArchiveTag"
    },
    "0x3019": {
        "data_type": "0x0102",
        "name": "PolicyTag"
    },
    "0x301A": {
        "data_type": "0x0003",
        "name": "RetentionPeriod"
    },
    "0x301B": {
        "data_type": "0x0102",
        "name": "StartDateEtc"
    },
    "0x301C": {
        "data_type": "0x0040",
        "name": "RetentionDate"
    },
    "0x301D": {
        "data_type": "0x0003",
        "name": "RetentionFlags"
    },
    "0x301E": {
        "data_type": "0x0003",
        "name": "ArchivePeriod"
    },
    "0x301F": {
        "data_type": "0x0040",
        "name": "ArchiveDate"
    },
    "0x340D": {
        "data_type": "0x0003",
        "name": "StoreSupportMask"
    },
    "0x340E": {
        "data_type": "0x0003",
        "name": "StoreState"
    },
    "0x3600": {
        "data_type": "0x0003",
        "name": "ContainerFlags"
    },
    "0x3601": {
        "data_type": "0x0003",
        "name": "FolderType"
    },
    "0x3602": {
        "data_type": "0x0003",
        "name": "ContentCount"
    },
    "0x3603": {
        "data_type": "0x0003",
        "name": "ContentUnreadCount"
    },
    "0x3609": {
        "data_type": "0x000B",
        "name": "Selectable"
    },
    "0x360A": {
        "data_type": "0x000B",
        "name": "Subfolders"
    },
    "0x360C": {
        "data_type": "0x001F",
        "name": "Anr"
    },
    "0x360E": {
        "data_type": "0x000D",
        "name": "ContainerHierarchy"
    },
    "0x360F": {
        "data_type": "0x000D",
        "name": "ContainerContents"
    },
    "0x3610": {
        "data_type": "0x000D",
        "name": "FolderAssociatedContents"
    },
    "0x3613": {
        "data_type": "0x001F",
        "name": "ContainerClass"
    },
    "0x36D0": {
        "data_type": "0x0102",
        "name": "IpmAppointmentEntryId"
    },
    "0x36D1": {
        "data_type": "0x0102",
        "name": "IpmContactEntryId"
    },
    "0x36D2": {
        "data_type": "0x0102",
        "name": "IpmJournalEntryId"
    },
    "0x36D3": {
        "data_type": "0x0102",
        "name": "IpmNoteEntryId"
    },
    "0x36D4": {
        "data_type": "0x0102",
        "name": "IpmTaskEntryId"
    },
    "0x36D5": {
        "data_type": "0x0102",
        "name": "RemindersOnlineEntryId"
    },
    "0x36D7": {
        "data_type": "0x0102",
        "name": "IpmDraftsEntryId"
    },
    "0x36D8": {
        "data_type": "0x1102",
        "name": "AdditionalRenEntryIds"
    },
    "0x36D9": {
        "data_type": "0x0102",
        "name": "AdditionalRenEntryIdsEx"
    },
    "0x36DA": {
        "data_type": "0x0102",
        "name": "ExtendedFolderFlags"
    },
    "0x36E2": {
        "data_type": "0x0003",
        "name": "OrdinalMost"
    },
    "0x36E4": {
        "data_type": "0x1102",
        "name": "FreeBusyEntryIds"
    },
    "0x36E5": {
        "data_type": "0x001F",
        "name": "DefaultPostMessageClass"
    },
    "0x3701": {
        "data_type": "0x000D",
        "name": "AttachDataObject"
    },
    "0x3702": {
        "data_type": "0x0102",
        "name": "AttachEncoding"
    },
    "0x3703": {
        "data_type": "0x001F",
        "name": "AttachExtension"
    },
    "0x3704": {
        "data_type": "0x001F",
        "name": "AttachFilename"
    },
    "0x3705": {
        "data_type": "0x0003",
        "name": "AttachMethod"
    },
    "0x3707": {
        "data_type": "0x001F",
        "name": "AttachLongFilename"
    },
    "0x3708": {
        "data_type": "0x001F",
        "name": "AttachPathname"
    },
    "0x3709": {
        "data_type": "0x0102",
        "name": "AttachRendering"
    },
    "0x370A": {
        "data_type": "0x0102",
        "name": "AttachTag"
    },
    "0x370B": {
        "data_type": "0x0003",
        "name": "RenderingPosition"
    },
    "0x370C": {
        "data_type": "0x001F",
        "name": "AttachTransportName"
    },
    "0x370D": {
        "data_type": "0x001F",
        "name": "AttachLongPathname"
    },
    "0x370E": {
        "data_type": "0x001F",
        "name": "AttachMimeTag"
    },
    "0x370F": {
        "data_type": "0x0102",
        "name": "AttachAdditionalInformation"
    },
    "0x3711": {
        "data_type": "0x001F",
        "name": "AttachContentBase"
    },
    "0x3712": {
        "data_type": "0x001F",
        "name": "AttachContentId"
    },
    "0x3713": {
        "data_type": "0x001F",
        "name": "AttachContentLocation"
    },
    "0x3714": {
        "data_type": "0x0003",
        "name": "AttachFlags"
    },
    "0x3719": {
        "data_type": "0x001F",
        "name": "AttachPayloadProviderGuidString"
    },
    "0x371A": {
        "data_type": "0x001F",
        "name": "AttachPayloadClass"
    },
    "0x371B": {
        "data_type": "0x001F",
        "name": "TextAttachmentCharset"
    },
    "0x3900": {
        "data_type": "0x0003",
        "name": "DisplayType"
    },
    "0x3902": {
        "data_type": "0x0102",
        "name": "Templateid"
    },
    "0x3905": {
        "data_type": "0x0003",
        "name": "DisplayTypeEx"
    },
    "0x39FE": {
        "data_type": "0x001F",
        "name": "SmtpAddress"
    },
    "0x39FF": {
        "data_type": "0x001F",
        "name": "AddressBookDisplayNamePrintable"
    },
    "0x3A00": {
        "data_type": "0x001F",
        "name": "Account"
    },
    "0x3A02": {
        "data_type": "0x001F",
        "name": "CallbackTelephoneNumber"
    },
    "0x3A05": {
        "data_type": "0x001F",
        "name": "Generation"
    },
    "0x3A06": {
        "data_type": "0x001F",
        "name": "GivenName"
    },
    "0x3A07": {
        "data_type": "0x001F",
        "name": "GovernmentIdNumber"
    },
    "0x3A08": {
        "data_type": "0x001F",
        "name": "BusinessTelephoneNumber"
    },
    "0x3A09": {
        "data_type": "0x001F",
        "name": "HomeTelephoneNumber"
    },
    "0x3A0A": {
        "data_type": "0x001F",
        "name": "Initials"
    },
    "0x3A0B": {
        "data_type": "0x001F",
        "name": "Keyword"
    },
    "0x3A0C": {
        "data_type": "0x001F",
        "name": "Language"
    },
    "0x3A0D": {
        "data_type": "0x001F",
        "name": "Location"
    },
    "0x3A0F": {
        "data_type": "0x001F",
        "name": "MessageHandlingSystemCommonName"
    },
    "0x3A10": {
        "data_type": "0x001F",
        "name": "OrganizationalIdNumber"
    },
    "0x3A11": {
        "data_type": "0x001F",
        "name": "Surname"
    },
    "0x3A12": {
        "data_type": "0x0102",
        "name": "OriginalEntryId"
    },
    "0x3A15": {
        "data_type": "0x001F",
        "name": "PostalAddress"
    },
    "0x3A16": {
        "data_type": "0x001F",
        "name": "CompanyName"
    },
    "0x3A17": {
        "data_type": "0x001F",
        "name": "Title"
    },
    "0x3A18": {
        "data_type": "0x001F",
        "name": "DepartmentName"
    },
    "0x3A19": {
        "data_type": "0x001F",
        "name": "OfficeLocation"
    },
    "0x3A1A": {
        "data_type": "0x001F",
        "name": "PrimaryTelephoneNumber"
    },
    "0x3A1B": {
        "data_type": "0x101F",
        "name": "Business2TelephoneNumbers"
    },
    "0x3A1C": {
        "data_type": "0x001F",
        "name": "MobileTelephoneNumber"
    },
    "0x3A1D": {
        "data_type": "0x001F",
        "name": "RadioTelephoneNumber"
    },
    "0x3A1E": {
        "data_type": "0x001F",
        "name": "CarTelephoneNumber"
    },
    "0x3A1F": {
        "data_type": "0x001F",
        "name": "OtherTelephoneNumber"
    },
    "0x3A20": {
        "data_type": "0x001F",
        "name": "TransmittableDisplayName"
    },
    "0x3A21": {
        "data_type": "0x001F",
        "name": "PagerTelephoneNumber"
    },
    "0x3A22": {
        "data_type": "0x0102",
        "name": "UserCertificate"
    },
    "0x3A23": {
        "data_type": "0x001F",
        "name": "PrimaryFaxNumber"
    },
    "0x3A24": {
        "data_type": "0x001F",
        "name": "BusinessFaxNumber"
    },
    "0x3A25": {
        "data_type": "0x001F",
        "name": "HomeFaxNumber"
    },
    "0x3A26": {
        "data_type": "0x001F",
        "name": "Country"
    },
    "0x3A27": {
        "data_type": "0x001F",
        "name": "Locality"
    },
    "0x3A28": {
        "data_type": "0x001F",
        "name": "StateOrProvince"
    },
    "0x3A29": {
        "data_type": "0x001F",
        "name": "StreetAddress"
    },
    "0x3A2A": {
        "data_type": "0x001F",
        "name": "PostalCode"
    },
    "0x3A2B": {
        "data_type": "0x001F",
        "name": "PostOfficeBox"
    },
    "0x3A2C": {
        "data_type": "0x001F; PtypMultipleBinary, 0x1102",
        "name": "TelexNumber"
    },
    "0x3A2D": {
        "data_type": "0x001F",
        "name": "IsdnNumber"
    },
    "0x3A2E": {
        "data_type": "0x001F",
        "name": "AssistantTelephoneNumber"
    },
    "0x3A2F": {
        "data_type": "0x101F",
        "name": "Home2TelephoneNumbers"
    },
    "0x3A30": {
        "data_type": "0x001F",
        "name": "Assistant"
    },
    "0x3A40": {
        "data_type": "0x000B",
        "name": "SendRichInfo"
    },
    "0x3A41": {
        "data_type": "0x0040",
        "name": "WeddingAnniversary"
    },
    "0x3A42": {
        "data_type": "0x0040",
        "name": "Birthday"
    },
    "0x3A43": {
        "data_type": "0x001F",
        "name": "Hobbies"
    },
    "0x3A44": {
        "data_type": "0x001F",
        "name": "MiddleName"
    },
    "0x3A45": {
        "data_type": "0x001F",
        "name": "DisplayNamePrefix"
    },
    "0x3A46": {
        "data_type": "0x001F",
        "name": "Profession"
    },
    "0x3A47": {
        "data_type": "0x001F",
        "name": "ReferredByName"
    },
    "0x3A48": {
        "data_type": "0x001F",
        "name": "SpouseName"
    },
    "0x3A49": {
        "data_type": "0x001F",
        "name": "ComputerNetworkName"
    },
    "0x3A4A": {
        "data_type": "0x001F",
        "name": "CustomerId"
    },
    "0x3A4B": {
        "data_type": "0x001F",
        "name": "TelecommunicationsDeviceForDeafTelephoneNumber"
    },
    "0x3A4C": {
        "data_type": "0x001F",
        "name": "FtpSite"
    },
    "0x3A4D": {
        "data_type": "0x0002",
        "name": "Gender"
    },
    "0x3A4E": {
        "data_type": "0x001F",
        "name": "ManagerName"
    },
    "0x3A4F": {
        "data_type": "0x001F",
        "name": "Nickname"
    },
    "0x3A50": {
        "data_type": "0x001F",
        "name": "PersonalHomePage"
    },
    "0x3A51": {
        "data_type": "0x001F",
        "name": "BusinessHomePage"
    },
    "0x3A57": {
        "data_type": "0x001F",
        "name": "CompanyMainTelephoneNumber"
    },
    "0x3A58": {
        "data_type": "0x101F",
        "name": "ChildrensNames"
    },
    "0x3A59": {
        "data_type": "0x001F",
        "name": "HomeAddressCity"
    },
    "0x3A5A": {
        "data_type": "0x001F",
        "name": "HomeAddressCountry"
    },
    "0x3A5B": {
        "data_type": "0x001F",
        "name": "HomeAddressPostalCode"
    },
    "0x3A5C": {
        "data_type": "0x001F",
        "name": "HomeAddressStateOrProvince"
    },
    "0x3A5D": {
        "data_type": "0x001F",
        "name": "HomeAddressStreet"
    },
    "0x3A5E": {
        "data_type": "0x001F",
        "name": "HomeAddressPostOfficeBox"
    },
    "0x3A5F": {
        "data_type": "0x001F",
        "name": "OtherAddressCity"
    },
    "0x3A60": {
        "data_type": "0x001F",
        "name": "OtherAddressCountry"
    },
    "0x3A61": {
        "data_type": "0x001F",
        "name": "OtherAddressPostalCode"
    },
    "0x3A62": {
        "data_type": "0x001F",
        "name": "OtherAddressStateOrProvince"
    },
    "0x3A63": {
        "data_type": "0x001F",
        "name": "OtherAddressStreet"
    },
    "0x3A64": {
        "data_type": "0x001F",
        "name": "OtherAddressPostOfficeBox"
    },
    "0x3A70": {
        "data_type": "0x1102",
        "name": "UserX509Certificate"
    },
    "0x3A71": {
        "data_type": "0x0003",
        "name": "SendInternetEncoding"
    },
    "0x3F08": {
        "data_type": "0x0003",
        "name": "InitialDetailsPane"
    },
    "0x3FDE": {
        "data_type": "0x0003",
        "name": "InternetCodepage"
    },
    "0x3FDF": {
        "data_type": "0x0003",
        "name": "AutoResponseSuppress"
    },
    "0x3FE0": {
        "data_type": "0x0102",
        "name": "AccessControlListData"
    },
    "0x3FE3": {
        "data_type": "0x000B",
        "name": "DelegatedByRule"
    },
    "0x3FE7": {
        "data_type": "0x0003",
        "name": "ResolveMethod"
    },
    "0x3FEA": {
        "data_type": "0x000B",
        "name": "HasDeferredActionMessages"
    },
    "0x3FEB": {
        "data_type": "0x0003",
        "name": "DeferredSendNumber"
    },
    "0x3FEC": {
        "data_type": "0x0003",
        "name": "DeferredSendUnits"
    },
    "0x3FED": {
        "data_type": "0x0003",
        "name": "ExpiryNumber"
    },
    "0x3FEE": {
        "data_type": "0x0003",
        "name": "ExpiryUnits"
    },
    "0x3FEF": {
        "data_type": "0x0040",
        "name": "DeferredSendTime"
    },
    "0x3FF0": {
        "data_type": "0x0102",
        "name": "ConflictEntryId"
    },
    "0x3FF1": {
        "data_type": "0x0003",
        "name": "MessageLocaleId"
    },
    "0x3FF8": {
        "data_type": "0x001F",
        "name": "CreatorName"
    },
    "0x3FF9": {
        "data_type": "0x0102",
        "name": "CreatorEntryId"
    },
    "0x3FFA": {
        "data_type": "0x001F",
        "name": "LastModifierName"
    },
    "0x3FFB": {
        "data_type": "0x0102",
        "name": "LastModifierEntryId"
    },
    "0x3FFD": {
        "data_type": "0x0003",
        "name": "MessageCodepage"
    },
    "0x401A": {
        "data_type": "0x0003",
        "name": "SentRepresentingFlags"
    },
    "0x4029": {
        "data_type": "0x001F",
        "name": "ReadReceiptAddressType"
    },
    "0x402A": {
        "data_type": "0x001F",
        "name": "ReadReceiptEmailAddress"
    },
    "0x402B": {
        "data_type": "0x001F",
        "name": "ReadReceiptName"
    },
    "0x4076": {
        "data_type": "0x0003",
        "name": "ContentFilterSpamConfidenceLevel"
    },
    "0x4079": {
        "data_type": "0x0003",
        "name": "SenderIdStatus"
    },
    "0x4082": {
        "data_type": "0x0040",
        "name": "HierRev"
    },
    "0x4083": {
        "data_type": "0x001F",
        "name": "PurportedSenderDomain"
    },
    "0x5902": {
        "data_type": "0x0003",
        "name": "InternetMailOverrideFormat"
    },
    "0x5909": {
        "data_type": "0x0003",
        "name": "MessageEditorFormat"
    },
    "0x5D01": {
        "data_type": "0x001F",
        "name": "SenderSmtpAddress"
    },
    "0x5D02": {
        "data_type": "0x001F",
        "name": "SentRepresentingSmtpAddress"
    },
    "0x5D05": {
        "data_type": "0x001F",
        "name": "ReadReceiptSmtpAddress"
    },
    "0x5D07": {
        "data_type": "0x001F",
        "name": "ReceivedBySmtpAddress"
    },
    "0x5D08": {
        "data_type": "0x001F",
        "name": "ReceivedRepresentingSmtpAddress"
    },
    "0x5FDF": {
        "data_type": "0x0003",
        "name": "RecipientOrder"
    },
    "0x5FE1": {
        "data_type": "0x000B",
        "name": "RecipientProposed"
    },
    "0x5FE3": {
        "data_type": "0x0040",
        "name": "RecipientProposedStartTime"
    },
    "0x5FE4": {
        "data_type": "0x0040",
        "name": "RecipientProposedEndTime"
    },
    "0x5FF6": {
        "data_type": "0x001F",
        "name": "RecipientDisplayName"
    },
    "0x5FF7": {
        "data_type": "0x0102",
        "name": "RecipientEntryId"
    },
    "0x5FFB": {
        "data_type": "0x0040",
        "name": "RecipientTrackStatusTime"
    },
    "0x5FFD": {
        "data_type": "0x0003",
        "name": "RecipientFlags"
    },
    "0x5FFF": {
        "data_type": "0x0003",
        "name": "RecipientTrackStatus"
    },
    "0x6100": {
        "data_type": "0x0003",
        "name": "JunkIncludeContacts"
    },
    "0x6101": {
        "data_type": "0x0003",
        "name": "JunkThreshold"
    },
    "0x6102": {
        "data_type": "0x0003",
        "name": "JunkPermanentlyDelete"
    },
    "0x6103": {
        "data_type": "0x0003",
        "name": "JunkAddRecipientsToSafeSendersList"
    },
    "0x6107": {
        "data_type": "0x000B",
        "name": "JunkPhishingEnableLinks"
    },
    "0x64F0": {
        "data_type": "0x0102",
        "name": "MimeSkeleton"
    },
    "0x65C2": {
        "data_type": "0x0102",
        "name": "ReplyTemplateId"
    },
    "0x65E0": {
        "data_type": "0x0102",
        "name": "SourceKey"
    },
    "0x65E1": {
        "data_type": "0x0102",
        "name": "ParentSourceKey"
    },
    "0x65E2": {
        "data_type": "0x0102",
        "name": "ChangeKey"
    },
    "0x65E3": {
        "data_type": "0x0102",
        "name": "PredecessorChangeList"
    },
    "0x65E9": {
        "data_type": "0x0003",
        "name": "RuleMessageState"
    },
    "0x65EA": {
        "data_type": "0x0003",
        "name": "RuleMessageUserFlags"
    },
    "0x65EB": {
        "data_type": "0x001F",
        "name": "RuleMessageProvider"
    },
    "0x65EC": {
        "data_type": "0x001F",
        "name": "RuleMessageName"
    },
    "0x65ED": {
        "data_type": "0x0003",
        "name": "RuleMessageLevel"
    },
    "0x65EE": {
        "data_type": "0x0102",
        "name": "RuleMessageProviderData"
    },
    "0x65F3": {
        "data_type": "0x0003",
        "name": "RuleMessageSequence"
    },
    "0x6619": {
        "data_type": "0x0102",
        "name": "UserEntryId"
    },
    "0x661B": {
        "data_type": "0x0102",
        "name": "MailboxOwnerEntryId"
    },
    "0x661C": {
        "data_type": "0x001F",
        "name": "MailboxOwnerName"
    },
    "0x661D": {
        "data_type": "0x000B",
        "name": "OutOfOfficeState"
    },
    "0x6622": {
        "data_type": "0x0102",
        "name": "SchedulePlusFreeBusyEntryId"
    },
    "0x6638": {
        "data_type": "0x0102",
        "name": "SerializedReplidGuidMap"
    },
    "0x6639": {
        "data_type": "0x0003",
        "name": "Rights"
    },
    "0x663A": {
        "data_type": "0x000B",
        "name": "HasRules"
    },
    "0x663B": {
        "data_type": "0x0102",
        "name": "AddressBookEntryId"
    },
    "0x663E": {
        "data_type": "0x0003",
        "name": "HierarchyChangeNumber"
    },
    "0x6645": {
        "data_type": "0x0102",
        "name": "ClientActions"
    },
    "0x6646": {
        "data_type": "0x0102",
        "name": "DamOriginalEntryId"
    },
    "0x6647": {
        "data_type": "0x000B",
        "name": "DamBackPatched"
    },
    "0x6648": {
        "data_type": "0x0003",
        "name": "RuleError"
    },
    "0x6649": {
        "data_type": "0x0003",
        "name": "RuleActionType"
    },
    "0x664A": {
        "data_type": "0x000B",
        "name": "HasNamedProperties"
    },
    "0x6650": {
        "data_type": "0x0003",
        "name": "RuleActionNumber"
    },
    "0x6651": {
        "data_type": "0x0102",
        "name": "RuleFolderEntryId"
    },
    "0x666A": {
        "data_type": "0x0003",
        "name": "ProhibitReceiveQuota"
    },
    "0x666C": {
        "data_type": "0x000B",
        "name": "InConflict"
    },
    "0x666D": {
        "data_type": "0x0003",
        "name": "MaximumSubmitMessageSize"
    },
    "0x666E": {
        "data_type": "0x0003",
        "name": "ProhibitSendQuota"
    },
    "0x6671": {
        "data_type": "0x0014",
        "name": "MemberId"
    },
    "0x6672": {
        "data_type": "0x001F",
        "name": "MemberName"
    },
    "0x6673": {
        "data_type": "0x0003",
        "name": "MemberRights"
    },
    "0x6674": {
        "data_type": "0x0014",
        "name": "RuleId"
    },
    "0x6675": {
        "data_type": "0x0102",
        "name": "RuleIds"
    },
    "0x6676": {
        "data_type": "0x0003",
        "name": "RuleSequence"
    },
    "0x6677": {
        "data_type": "0x0003",
        "name": "RuleState"
    },
    "0x6678": {
        "data_type": "0x0003",
        "name": "RuleUserFlags"
    },
    "0x6679": {
        "data_type": "0x00FD",
        "name": "RuleCondition"
    },
    "0x6680": {
        "data_type": "0x00FE",
        "name": "RuleActions"
    },
    "0x6681": {
        "data_type": "0x001F",
        "name": "RuleProvider"
    },
    "0x6682": {
        "data_type": "0x001F",
        "name": "RuleName"
    },
    "0x6683": {
        "data_type": "0x0003",
        "name": "RuleLevel"
    },
    "0x6684": {
        "data_type": "0x0102",
        "name": "RuleProviderData"
    },
    "0x668F": {
        "data_type": "0x0040",
        "name": "DeletedOn"
    },
    "0x66A1": {
        "data_type": "0x0003",
        "name": "LocaleId"
    },
    "0x66A8": {
        "data_type": "0x0003",
        "name": "FolderFlags"
    },
    "0x66C3": {
        "data_type": "0x0003",
        "name": "CodePageId"
    },
    "0x6704": {
        "data_type": "0x000D",
        "name": "AddressBookManageDistributionList"
    },
    "0x6705": {
        "data_type": "0x0003",
        "name": "SortLocaleId"
    },
    "0x6709": {
        "data_type": "0x0040",
        "name": "LocalCommitTime"
    },
    "0x670A": {
        "data_type": "0x0040",
        "name": "LocalCommitTimeMax"
    },
    "0x670B": {
        "data_type": "0x0003",
        "name": "DeletedCountTotal"
    },
    "0x670E": {
        "data_type": "0x001F",
        "name": "FlatUrlName"
    },
    "0x6740": {
        "data_type": "0x00FB",
        "name": "SentMailSvrEID"
    },
    "0x6741": {
        "data_type": "0x00FB",
        "name": "DeferredActionMessageOriginalEntryId"
    },
    "0x6748": {
        "data_type": "0x0014",
        "name": "FolderId"
    },
    "0x6749": {
        "data_type": "0x0014",
        "name": "ParentFolderId"
    },
    "0x674A": {
        "data_type": "0x0014",
        "name": "Mid"
    },
    "0x674D": {
        "data_type": "0x0014",
        "name": "InstID"
    },
    "0x674E": {
        "data_type": "0x0003",
        "name": "InstanceNum"
    },
    "0x674F": {
        "data_type": "0x0014",
        "name": "AddressBookMessageId"
    },
    "0x67A4": {
        "data_type": "0x0014",
        "name": "ChangeNumber"
    },
    "0x67AA": {
        "data_type": "0x000B",
        "name": "Associated"
    },
    "0x6800": {
        "data_type": "0x001F",
        "name": "OfflineAddressBookName"
    },
    "0x6801": {
        "data_type": "0x0003",
        "name": "VoiceMessageDuration"
    },
    "0x6802": {
        "data_type": "0x001F",
        "name": "SenderTelephoneNumber"
    },
    "0x6803": {
        "data_type": "0x001F",
        "name": "VoiceMessageSenderName"
    },
    "0x6804": {
        "data_type": "0x001E",
        "name": "OfflineAddressBookDistinguishedName"
    },
    "0x6805": {
        "data_type": "0x001F",
        "name": "VoiceMessageAttachmentOrder"
    },
    "0x6806": {
        "data_type": "0x001F",
        "name": "CallId"
    },
    "0x6820": {
        "data_type": "0x001F",
        "name": "ReportingMessageTransferAgent"
    },
    "0x6834": {
        "data_type": "0x0003",
        "name": "SearchFolderLastUsed"
    },
    "0x683A": {
        "data_type": "0x0003",
        "name": "SearchFolderExpiration"
    },
    "0x6841": {
        "data_type": "0x0003",
        "name": "SearchFolderTemplateId"
    },
    "0x6842": {
        "data_type": "0x0102",
        "name": "WlinkGroupHeaderID"
    },
    "0x6843": {
        "data_type": "0x000B",
        "name": "ScheduleInfoDontMailDelegates"
    },
    "0x6844": {
        "data_type": "0x0102",
        "name": "SearchFolderRecreateInfo"
    },
    "0x6845": {
        "data_type": "0x0102",
        "name": "SearchFolderDefinition"
    },
    "0x6846": {
        "data_type": "0x0003",
        "name": "SearchFolderStorageType"
    },
    "0x6847": {
        "data_type": "0x0003",
        "name": "WlinkSaveStamp"
    },
    "0x6848": {
        "data_type": "0x0003",
        "name": "SearchFolderEfpFlags"
    },
    "0x6849": {
        "data_type": "0x0003",
        "name": "WlinkType"
    },
    "0x684A": {
        "data_type": "0x0003",
        "name": "WlinkFlags"
    },
    "0x684B": {
        "data_type": "0x0102",
        "name": "WlinkOrdinal"
    },
    "0x684C": {
        "data_type": "0x0102",
        "name": "WlinkEntryId"
    },
    "0x684D": {
        "data_type": "0x0102",
        "name": "WlinkRecordKey"
    },
    "0x684E": {
        "data_type": "0x0102",
        "name": "WlinkStoreEntryId"
    },
    "0x684F": {
        "data_type": "0x0102",
        "name": "WlinkFolderType"
    },
    "0x6850": {
        "data_type": "0x0102",
        "name": "WlinkGroupClsid"
    },
    "0x6851": {
        "data_type": "0x001F",
        "name": "WlinkGroupName"
    },
    "0x6852": {
        "data_type": "0x0003",
        "name": "WlinkSection"
    },
    "0x6853": {
        "data_type": "0x0003",
        "name": "WlinkCalendarColor"
    },
    "0x6854": {
        "data_type": "0x0102",
        "name": "WlinkAddressBookEID"
    },
    "0x6855": {
        "data_type": "0x1003",
        "name": "ScheduleInfoMonthsAway"
    },
    "0x6856": {
        "data_type": "0x1102",
        "name": "ScheduleInfoFreeBusyAway"
    },
    "0x6868": {
        "data_type": "0x0040",
        "name": "FreeBusyRangeTimestamp"
    },
    "0x6869": {
        "data_type": "0x0003",
        "name": "FreeBusyCountMonths"
    },
    "0x686A": {
        "data_type": "0x0102",
        "name": "ScheduleInfoAppointmentTombstone"
    },
    "0x686B": {
        "data_type": "0x1003",
        "name": "DelegateFlags"
    },
    "0x686C": {
        "data_type": "0x0102",
        "name": "ScheduleInfoFreeBusy"
    },
    "0x686D": {
        "data_type": "0x000B",
        "name": "ScheduleInfoAutoAcceptAppointments"
    },
    "0x686E": {
        "data_type": "0x000B",
        "name": "ScheduleInfoDisallowRecurringAppts"
    },
    "0x686F": {
        "data_type": "0x000B",
        "name": "ScheduleInfoDisallowOverlappingAppts"
    },
    "0x6890": {
        "data_type": "0x0102",
        "name": "WlinkClientID"
    },
    "0x6891": {
        "data_type": "0x0102",
        "name": "WlinkAddressBookStoreEID"
    },
    "0x6892": {
        "data_type": "0x0003",
        "name": "WlinkROGroupType"
    },
    "0x7001": {
        "data_type": "0x0102",
        "name": "ViewDescriptorBinary"
    },
    "0x7002": {
        "data_type": "0x001F",
        "name": "ViewDescriptorStrings"
    },
    "0x7006": {
        "data_type": "0x001F",
        "name": "ViewDescriptorName"
    },
    "0x7007": {
        "data_type": "0x0003",
        "name": "ViewDescriptorVersion"
    },
    "0x7C06": {
        "data_type": "0x0003",
        "name": "RoamingDatatypes"
    },
    "0x7C07": {
        "data_type": "0x0102",
        "name": "RoamingDictionary"
    },
    "0x7C08": {
        "data_type": "0x0102",
        "name": "RoamingXmlStream"
    },
    "0x7C24": {
        "data_type": "0x000B",
        "name": "OscSyncEnabled"
    },
    "0x7D01": {
        "data_type": "0x000B",
        "name": "Processed"
    },
    "0x7FF9": {
        "data_type": "0x0040",
        "name": "ExceptionReplaceTime"
    },
    "0x7FFA": {
        "data_type": "0x0003",
        "name": "AttachmentLinkId"
    },
    "0x7FFB": {
        "data_type": "0x0040",
        "name": "ExceptionStartTime"
    },
    "0x7FFC": {
        "data_type": "0x0040",
        "name": "ExceptionEndTime"
    },
    "0x7FFD": {
        "data_type": "0x0003",
        "name": "AttachmentFlags"
    },
    "0x7FFE": {
        "data_type": "0x000B",
        "name": "AttachmentHidden"
    },
    "0x7FFF": {
        "data_type": "0x000B",
        "name": "AttachmentContactPhoto"
    },
    "0x8004": {
        "data_type": "0x001F",
        "name": "AddressBookFolderPathname"
    },
    "0x8005": {
        "data_type": "0x001F",
        "name": "AddressBookManagerDistinguishedName"
    },
    "0x8006": {
        "data_type": "0x001E",
        "name": "AddressBookHomeMessageDatabase"
    },
    "0x8008": {
        "data_type": "0x001E",
        "name": "AddressBookIsMemberOfDistributionList"
    },
    "0x8009": {
        "data_type": "0x000D",
        "name": "AddressBookMember"
    },
    "0x800C": {
        "data_type": "0x000D",
        "name": "AddressBookOwner"
    },
    "0x800E": {
        "data_type": "0x000D",
        "name": "AddressBookReports"
    },
    "0x800F": {
        "data_type": "0x101F",
        "name": "AddressBookProxyAddresses"
    },
    "0x8011": {
        "data_type": "0x001F",
        "name": "AddressBookTargetAddress"
    },
    "0x8015": {
        "data_type": "0x000D",
        "name": "AddressBookPublicDelegates"
    },
    "0x8024": {
        "data_type": "0x000D",
        "name": "AddressBookOwnerBackLink"
    },
    "0x802D": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute1"
    },
    "0x802E": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute2"
    },
    "0x802F": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute3"
    },
    "0x8030": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute4"
    },
    "0x8031": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute5"
    },
    "0x8032": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute6"
    },
    "0x8033": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute7"
    },
    "0x8034": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute8"
    },
    "0x8035": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute9"
    },
    "0x8036": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute10"
    },
    "0x803C": {
        "data_type": "0x001F",
        "name": "AddressBookObjectDistinguishedName"
    },
    "0x806A": {
        "data_type": "0x0003",
        "name": "AddressBookDeliveryContentLength"
    },
    "0x8073": {
        "data_type": "0x000D",
        "name": "AddressBookDistributionListMemberSubmitAccepted"
    },
    "0x8170": {
        "data_type": "0x101F",
        "name": "AddressBookNetworkAddress"
    },
    "0x8C57": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute11"
    },
    "0x8C58": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute12"
    },
    "0x8C59": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute13"
    },
    "0x8C60": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute14"
    },
    "0x8C61": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute15"
    },
    "0x8C6A": {
        "data_type": "0x1102",
        "name": "AddressBookX509Certificate"
    },
    "0x8C6D": {
        "data_type": "0x0102",
        "name": "AddressBookObjectGuid"
    },
    "0x8C8E": {
        "data_type": "0x001F",
        "name": "AddressBookPhoneticGivenName"
    },
    "0x8C8F": {
        "data_type": "0x001F",
        "name": "AddressBookPhoneticSurname"
    },
    "0x8C90": {
        "data_type": "0x001F",
        "name": "AddressBookPhoneticDepartmentName"
    },
    "0x8C91": {
        "data_type": "0x001F",
        "name": "AddressBookPhoneticCompanyName"
    },
    "0x8C92": {
        "data_type": "0x001F",
        "name": "AddressBookPhoneticDisplayName"
    },
    "0x8C93": {
        "data_type": "0x0003",
        "name": "AddressBookDisplayTypeExtended"
    },
    "0x8C94": {
        "data_type": "0x000D",
        "name": "AddressBookHierarchicalShowInDepartments"
    },
    "0x8C96": {
        "data_type": "0x101F",
        "name": "AddressBookRoomContainers"
    },
    "0x8C97": {
        "data_type": "0x000D",
        "name": "AddressBookHierarchicalDepartmentMembers"
    },
    "0x8C98": {
        "data_type": "0x001E",
        "name": "AddressBookHierarchicalRootDepartment"
    },
    "0x8C99": {
        "data_type": "0x000D",
        "name": "AddressBookHierarchicalParentDepartment"
    },
    "0x8C9A": {
        "data_type": "0x000D",
        "name": "AddressBookHierarchicalChildDepartments"
    },
    "0x8C9E": {
        "data_type": "0x0102",
        "name": "ThumbnailPhoto"
    },
    "0x8CA0": {
        "data_type": "0x0003",
        "name": "AddressBookSeniorityIndex"
    },
    "0x8CA8": {
        "data_type": "0x001F",
        "name": "AddressBookOrganizationalUnitRootDistinguishedName"
    },
    "0x8CAC": {
        "data_type": "0x101F",
        "name": "AddressBookSenderHintTranslations"
    },
    "0x8CB5": {
        "data_type": "0x000B",
        "name": "AddressBookModerationEnabled"
    },
    "0x8CC2": {
        "data_type": "0x0102",
        "name": "SpokenName"
    },
    "0x8CD8": {
        "data_type": "0x000D",
        "name": "AddressBookAuthorizedSenders"
    },
    "0x8CD9": {
        "data_type": "0x000D",
        "name": "AddressBookUnauthorizedSenders"
    },
    "0x8CDA": {
        "data_type": "0x000D",
        "name": "AddressBookDistributionListMemberSubmitRejected"
    },
    "0x8CDB": {
        "data_type": "0x000D",
        "name": "AddressBookDistributionListRejectMessagesFromDLMembers"
    },
    "0x8CDD": {
        "data_type": "0x000B",
        "name": "AddressBookHierarchicalIsHierarchicalGroup"
    },
    "0x8CE2": {
        "data_type": "0x0003",
        "name": "AddressBookDistributionListMemberCount"
    },
    "0x8CE3": {
        "data_type": "0x0003",
        "name": "AddressBookDistributionListExternalMemberCount"
    },
    "0xFFFB": {
        "data_type": "0x000B",
        "name": "AddressBookIsMaster"
    },
    "0xFFFC": {
        "data_type": "0x0102",
        "name": "AddressBookParentEntryId"
    },
    "0xFFFD": {
        "data_type": "0x0003",
        "name": "AddressBookContainerId"
    }
}

''' HELPER FUNCTION '''


def recursive_convert_to_unicode(replace_to_utf):
    """Converts object into UTF-8 characters
    ignores errors
    Args:
        replace_to_utf (object): any object

    Returns:
        object converted to UTF-8
    """
    try:
        if isinstance(replace_to_utf, dict):
            return {recursive_convert_to_unicode(k): recursive_convert_to_unicode(v) for k, v in replace_to_utf.items()}
        if isinstance(replace_to_utf, list):
            return [recursive_convert_to_unicode(i) for i in replace_to_utf if i]
        if isinstance(replace_to_utf, str):
            return unicode(replace_to_utf, encoding='utf-8', errors='ignore')
        if not replace_to_utf:
            return replace_to_utf
        return replace_to_utf
    except TypeError:
        return replace_to_utf


TOP_LEVEL_HEADER_SIZE = 32
RECIPIENT_HEADER_SIZE = 8
ATTACHMENT_HEADER_SIZE = 8
EMBEDDED_MSG_HEADER_SIZE = 24
CONTROL_CHARS = re.compile(r'[\n\r\t]')


class Message(object):
    """
     Class to store Message properties
    """

    def __init__(self, directory_entries, parent_directory_path=None):

        if parent_directory_path is None:
            parent_directory_path = []

        self._streams = self._process_directory_entries(directory_entries)
        self.embedded_messages = []  # type: list
        self._data_model = DataModel()
        self._parent_directory_path = parent_directory_path
        self._nested_attachments_depth = 0
        self.properties = self._get_properties()
        self.attachments = self._get_attachments()
        self.recipients = self._get_recipients()

        self._set_properties()
        self._set_attachments()
        self._set_recipients()

    def _get_attachments_names(self):
        names = []
        for attachment in self.attachments:
            names.append(attachment.DisplayName)

        return names

    def get_all_attachments(self):
        attachments = self.attachments

        for embedded_message in self.embedded_messages:
            attachments.extend(embedded_message.get_all_attachments())

        return attachments

    def as_dict(self, max_depth):
        if max_depth == 0:
            return None

        def join(arr):
            if isinstance(arr, list):
                arr = [item for item in arr if item is not None]
                return ",".join(arr)

            return ""

        cc = None
        if self.cc is not None:
            cc = join([extract_address(cc) for cc in self.cc])  # noqa: F812

        bcc = None
        if self.bcc is not None:
            bcc = join([extract_address(bcc) for bcc in self.bcc])  # noqa

        recipients = None
        if self.to is not None:
            recipients = join([extract_address(recipient.EmailAddress) for recipient in self.recipients])  # noqa

        sender = None
        if self.sender is not None:
            sender = join([extract_address(sender) for sender in self.sender])  # noqa

        html = self.html
        if not html:
            html = self.body

        message_dict = {
            'Attachments': join(self._get_attachments_names()),
            'CC': cc,
            'BCC': bcc,
            'To': recipients,
            'From': sender,
            'Subject': self.subject,
            'Text': self.body,
            'HTML': html,
            'Headers': str(self.header) if self.header is not None else None,
            'HeadersMap': self.header_dict,
            'Depth': MAX_DEPTH_CONST - max_depth
        }

        return message_dict

    def get_attached_emails_hierarchy(self, max_depth):
        if max_depth == 0:
            return []

        attached_emails = []
        for embedded_message in self.embedded_messages:
            attached_emails.append(embedded_message.as_dict(max_depth))
            attached_emails.extend(embedded_message.get_attached_emails_hierarchy(max_depth - 1))

        return attached_emails

    def _set_property_stream_info(self, ole_file, header_size):
        property_dir_entry = ole_file.openstream('__properties_version1.0')
        version_stream_data = property_dir_entry.read()

        if not version_stream_data:
            raise Exception("Invalid MSG file provided, 'properties_version1.0' stream data is empty.")

        if version_stream_data:

            if header_size >= EMBEDDED_MSG_HEADER_SIZE:

                properties_metadata = unpack('8sIIII', version_stream_data[:24])
                if not properties_metadata or not len(properties_metadata) >= 5:
                    raise Exception("'properties_version1.0' stream data is corrupted.")
                self.next_recipient_id = properties_metadata[1]
                self.next_attachment_id = properties_metadata[2]
                self.recipient_count = properties_metadata[3]
                self.attachment_count = properties_metadata[4]

            if (len(version_stream_data) - header_size) % 16 != 0:
                raise Exception('Property Stream size less header is not exactly divisible by 16')

            self.property_entries_count = (len(version_stream_data) - header_size) / 16

    @staticmethod
    def _process_directory_entries(directory_entries):

        streams = {
            "properties": {},
            "recipients": {},
            "attachments": {}
        }  # type: dict
        for name, stream in directory_entries.iteritems():
            # collect properties
            if "__substg1.0_" in name:
                streams["properties"][name] = stream

            # collect attachments
            elif "__attach_" in name:
                streams["attachments"][name] = stream.kids

            # collect recipients
            elif "__recip_" in name:
                streams["recipients"][name] = stream.kids

            # unknown stream name
            else:
                continue

        return streams

    def _get_properties(self):

        directory_entries = self._streams.get("properties")
        directory_name_filter = "__substg1.0_"
        property_entries = {}
        for directory_name, directory_entry in directory_entries.iteritems():

            if directory_name_filter not in directory_name:
                continue

            if not directory_entry:
                continue

            if isinstance(directory_entry, list):
                directory_values = {}  # type: dict
                for property_entry in directory_entry:
                    property_data = self._get_property_data(directory_name, property_entry, is_list=True)
                    if property_data:
                        directory_values.update(property_data)

                property_entries[directory_name] = directory_values
            else:
                property_data = self._get_property_data(directory_name, directory_entry)
                if property_data:
                    property_entries.update(property_data)
        return property_entries

    def _get_recipients(self):

        directory_entries = self._streams.get("recipients")
        directory_name_filter = "__recip_version1.0_"
        recipient_entries = {}
        for directory_name, directory_entry in directory_entries.iteritems():

            if directory_name_filter not in directory_name:
                continue

            if not directory_entry:
                continue

            if isinstance(directory_entry, list):
                directory_values = {}  # type: dict
                for property_entry in directory_entry:
                    property_data = self._get_property_data(directory_name, property_entry, is_list=True)
                    if property_data:
                        directory_values.update(property_data)

                recipient_address = directory_values.get(
                    'EmailAddress', directory_values.get('SmtpAddress', directory_name)
                )
                recipient_entries[recipient_address] = directory_values
            else:
                property_data = self._get_property_data(directory_name, directory_entry)
                if property_data:
                    recipient_entries.update(property_data)
        return recipient_entries

    def _get_attachments(self):
        directory_entries = self._streams.get("attachments")
        directory_name_filter = "__attach_version1.0_"
        attachment_entries = {}
        for directory_name, directory_entry in directory_entries.iteritems():
            if directory_name_filter not in directory_name:
                continue

            if not directory_entry:
                continue

            if isinstance(directory_entry, list):
                directory_values = {}
                for property_entry in directory_entry:

                    kids = property_entry.kids
                    if kids:
                        embedded_message = Message(
                            property_entry.kids_dict,
                            self._parent_directory_path + [directory_name, property_entry.name]
                        )

                        directory_values["EmbeddedMessage"] = {
                            "properties": embedded_message.properties,
                            "recipients": embedded_message.recipients,
                            "attachments": embedded_message.attachments
                        }
                        self.embedded_messages.append(embedded_message)

                    property_data = self._get_property_data(directory_name, property_entry, is_list=True)
                    if property_data:
                        directory_values.update(property_data)

                attachment_entries[directory_name] = directory_values

            else:
                property_data = self._get_property_data(directory_name, directory_entry)
                if property_data:
                    attachment_entries.update(property_data)
        return attachment_entries

    def _get_property_data(self, directory_name, directory_entry, is_list=False):
        directory_entry_name = directory_entry.name
        if is_list:
            stream_name = [directory_name, directory_entry_name]
        else:
            stream_name = [directory_entry_name]

        if self._parent_directory_path:
            stream_name = self._parent_directory_path + stream_name

        ole_file = directory_entry.olefile
        property_details = self._get_canonical_property_name(directory_entry_name)
        if not property_details:
            return None

        property_name = property_details.get("name")
        property_type = property_details.get("data_type")
        if not property_type:
            return None

        try:
            raw_content = ole_file.openstream(stream_name).read()
        except IOError:
            raw_content = None
        property_value = self._data_model.get_value(raw_content, data_type=property_type)
        if property_value:
            property_detail = {property_name: property_value}
        else:
            property_detail = None  # type: ignore[assignment]

        return property_detail

    @staticmethod
    def _get_canonical_property_name(dir_entry_name):
        if not dir_entry_name:
            return None

        if "__substg1.0_" in dir_entry_name:
            name = dir_entry_name.replace("__substg1.0_", "")
            prop_name_id = "0x" + name[0:4]
            prop_details = PROPS_ID_MAP.get(prop_name_id)
            return prop_details

        return None

    def _set_properties(self):
        property_values = self.properties

        # setting generally required properties to easily access using MsOxMessage instance.
        self.subject = property_values.get("Subject")

        header = property_values.get("TransportMessageHeaders")
        self.header = parse_email_headers(header, True)
        self.header_dict = parse_email_headers(header) or {}

        self.created_date = property_values.get("CreationTime")
        self.received_date = property_values.get("ReceiptTime")

        sent_date = property_values.get("DeliverTime")
        if not sent_date:
            sent_date = self.header_dict.get("Date")
        self.sent_date = sent_date

        sender_address = self.header_dict.get("From")
        if not sender_address:
            sender_address = property_values.get("SenderRepresentingSmtpAddress")
        self.sender = sender_address

        reply_to_address = self.header_dict.get("Reply-To")
        if not reply_to_address:
            reply_to_address = property_values.get("ReplyRecipientNames")
        self.reply_to = reply_to_address

        self.message_id = property_values.get("InternetMessageId")

        to_address = self.header_dict.get("To")
        if not to_address:
            to_address = property_values.get("ReceivedRepresentingSmtpAddress")
            if not to_address:
                to_address = property_values.get("DisplayTo")

        self.to = to_address
        to_smpt_address = property_values.get("ReceivedRepresentingSmtpAddress")
        if not to_smpt_address:
            to_smpt_address = [value for key, value in self.recipients.iteritems()]
        self.to_address = to_smpt_address

        cc_address = self.header_dict.get("CC")
        # if cc_address:
        #     cc_address = [CONTROL_CHARS.sub(" ", cc_add) for cc_add in cc_address.split(",")]
        self.cc = cc_address

        bcc_address = self.header_dict.get("BCC")
        self.bcc = bcc_address

        # prefer HTMl over plain text
        self.html = property_values.get("Html")
        self.body = property_values.get("Body")

        if not self.body and "RtfCompressed" in property_values:
            try:
                import compressed_rtf
            except ImportError:
                compressed_rtf = None
            if compressed_rtf:
                compressed_rtf_body = property_values['RtfCompressed']
                self.body = compressed_rtf.decompress(compressed_rtf_body)

    def _set_recipients(self):
        recipients = self.recipients
        self.recipients = []
        for recipient_name, recipient in recipients.items():

            if self.to and recipient_name in self.to:
                recipient["RecipientType"] = "TO"

            if self.cc and recipient_name in self.cc:
                recipient["RecipientType"] = "CC"

            if self.bcc and recipient_name in self.bcc:
                recipient["RecipientType"] = "BCC"

            if self.reply_to and recipient_name in self.reply_to:
                recipient["RecipientType"] = "ReplyTo"

            self.recipients.append(Recipient(recipient))

    def _set_attachments(self):
        attachments = self.attachments
        self.attachments = [Attachment(attach) for attach in attachments.values()]

    def __repr__(self):
        return u'Message [%s]' % self.properties.get('InternetMessageId', self.properties.get("Subject"))


class Recipient(object):
    """
     class to store recipient attributes
    """

    def __init__(self, recipients_properties):
        self.AddressType = recipients_properties.get("AddressType")
        self.Account = recipients_properties.get("Account")
        self.EmailAddress = recipients_properties.get("SmtpAddress")
        self.DisplayName = recipients_properties.get("DisplayName")
        self.ObjectType = recipients_properties.get("ObjectType")
        self.RecipientType = recipients_properties.get("RecipientType")

    def __repr__(self):
        return '%s (%s)' % (self.DisplayName, self.EmailAddress)


class Attachment(object):
    """
     class to store attachment attributes
    """

    def __init__(self, attachment_properties):

        self.DisplayName = attachment_properties.get("DisplayName")
        self.AttachEncoding = attachment_properties.get("AttachEncoding")
        self.AttachContentId = attachment_properties.get("AttachContentId")
        self.AttachMethod = attachment_properties.get("AttachMethod")
        self.AttachmentSize = format_size(attachment_properties.get("AttachmentSize"))
        self.AttachFilename = attachment_properties.get("AttachFilename")
        self.AttachLongFilename = attachment_properties.get("AttachLongFilename")
        if self.AttachLongFilename:
            self.Filename = self.AttachLongFilename
        else:
            self.Filename = self.AttachFilename
        if self.Filename:
            self.Filename = os.path.basename(self.Filename)
        else:
            self.Filename = '[NoFilename_Method%s]' % self.AttachMethod
        self.data = attachment_properties.get("AttachDataObject")
        self.AttachMimeTag = attachment_properties.get("AttachMimeTag", "application/octet-stream")
        self.AttachExtension = attachment_properties.get("AttachExtension")

    def __repr__(self):
        return '%s (%s / %s)' % (self.Filename, self.AttachmentSize, len(self.data or []))


class MsOxMessage(object):
    """
     Base class for Microsoft Message Object
    """

    def __init__(self, msg_file_path):
        self.msg_file_path = msg_file_path
        self.include_attachment_data = False

        if not self.is_valid_msg_file():
            raise Exception("Invalid file provided, please provide valid Microsoft Outlook MSG file.")

        ole_file = None
        try:
            ole_file = OleFileIO(msg_file_path)

            # process directory entries
            ole_root = ole_file.root
            kids_dict = ole_root.kids_dict

            self._message = Message(kids_dict)

        finally:
            if ole_file is not None:
                ole_file.close()

    def as_dict(self, max_depth):
        return self._message.as_dict(max_depth)

    def get_email_mime_content(self):
        email_obj = EmailFormatter(self)
        return email_obj.build_email()

    def save_email_file(self, file_path):
        email_obj = EmailFormatter(self)
        email_obj.save_file(file_path)
        return True

    def get_attached_emails_hierarchy(self, max_depth):
        return self._message.get_attached_emails_hierarchy(max_depth)

    def is_valid_msg_file(self):
        if not os.path.exists(self.msg_file_path):
            return False

        if not isOleFile(self.msg_file_path):
            return False

        return True

    def get_all_attachments(self):
        return self._message.get_all_attachments()


def format_size(num, suffix='B'):
    if not num:
        return "unknown"
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


def parse_email_headers(header, raw=False):
    if not header:
        return None

    headers = email.message_from_string(header)
    if raw:
        return headers

    email_address_headers = {  # type: ignore[var-annotated]
        "To": [],
        "From": [],
        "CC": [],
        "BCC": [],
        "Reply-To": [],
    }

    for addr in email_address_headers.keys():
        for (name, email_address) in email.utils.getaddresses(headers.get_all(addr, [])):
            email_address_headers[addr].append("{} <{}>".format(name, email_address))

    parsed_headers = dict(headers)
    parsed_headers.update(email_address_headers)

    return parsed_headers


def get_msg_mail_format(msg_dict):
    try:
        return msg_dict.get('Headers', 'Content-type:').split('Content-type:')[1].split(';')[0]
    except Exception as e:
        demisto.debug('Got exception while trying to get msg mail format - {}'.format(str(e)))
        return ''


def is_valid_header_to_parse(header):
    return len(header) > 0 and not header == ' ' and 'From nobody' not in header


def create_headers_map(msg_dict_headers):
    headers = list()  # type: list
    headers_map = dict()  # type: dict

    if not msg_dict_headers:
        return headers, headers_map

    header_key = 'initial key'
    header_value = 'initial header'
    for header in msg_dict_headers.split('\n'):
        if is_valid_header_to_parse(header):
            if not header[0] == ' ' and not header[0] == '\t':
                if header_value != 'initial header':
                    header_value = convert_to_unicode(header_value)
                    headers.append(
                        {
                            'name': header_key,
                            'value': header_value
                        }
                    )

                    if header_key in headers_map:
                        # in case there is already such header
                        # then add that header value to value array
                        if not isinstance(headers_map[header_key], list):
                            # convert the existing value to array
                            headers_map[header_key] = [headers_map[header_key]]

                        # add the new value to the value array
                        headers_map[header_key].append(header_value)
                    else:
                        headers_map[header_key] = header_value

                header_words = header.split(' ', 1)

                header_key = header_words[0][:-1]
                header_value = ' '.join(header_words[1:])
                if not header_value == '' and header_value[-1] == ' ':
                    header_value = header_value[:-1]

            else:
                header_value += header[:-1] if header[-1:] == ' ' else header

    return headers, headers_map


########################################################################################################################
ENCODINGS_TYPES = set(['utf-8', 'iso8859-1'])
REGEX_EMAIL = r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"


def extract_address(s):
    if type(s) not in [str, unicode]:
        return s
    res = re.findall(REGEX_EMAIL, s)
    if res:
        return ', '.join(res)
    else:
        return s


def get_email_address(eml, entry):
    """
    This function gets email addresses from an eml object, i.e eml[entry].
    Args:
        eml : Email object.
        entry (str) : entry to look for in the email. i.e ('To', 'CC', 'From')
    Returns:
        res (str) : string of all required email addresses.
    """
    gel_all_values_from_email_by_entry = eml.get_all(entry, [])
    addresses = getaddresses(gel_all_values_from_email_by_entry)
    if addresses:
        res = [item[1] for item in addresses]
        res = ', '.join(res)
        return res
    return ''


def extract_address_eml(eml, entry):
    """
    This function calls get_email_address in order to get required email addresses from email object.
    In addition, this function handles an edge case of '\r\n' in eml['from'] (as explained below).
    Args:
        eml : Email object.
        entry (str) : entry to look for in the email. i.e ('To', 'CC', 'From')
    Returns:
        res (str) : string of all required email addresses.
    """
    email_address = get_email_address(eml, entry)
    if email_address:
        if entry == 'from' and not re.search(REGEX_EMAIL, email_address):
            # this condition refers only to ['from'] header that does not have a valid email
            # fixed an issue where email['From'] had '\r\n'.
            # in order to solve, used replace_header() on email object,
            # and did again get_all() on the new format of ['from']
            original_value = eml['from']
            eml.replace_header('from', ' '.join(eml["from"].splitlines()))
            email_address = get_email_address(eml, entry)
            eml.replace_header('from', original_value)  # replace again to the original header (keep on BC)
        return email_address
    else:
        return ''


def data_to_md(email_data, email_file_name=None, parent_email_file=None, print_only_headers=False):
    email_data = recursive_convert_to_unicode(email_data)
    email_file_name = recursive_convert_to_unicode(email_file_name)
    parent_email_file = recursive_convert_to_unicode(parent_email_file)

    md = u"### Results:\n"
    if email_file_name:
        md = u"### {}\n".format(email_file_name)

    if print_only_headers:
        return tableToMarkdown("Email Headers: " + email_file_name, email_data.get('HeadersMap'))

    if parent_email_file:
        md += u"### Containing email: {}\n".format(parent_email_file)

    md += u"* {0}:\t{1}\n".format('From', email_data.get('From') or "")
    md += u"* {0}:\t{1}\n".format('To', email_data.get('To') or "")
    md += u"* {0}:\t{1}\n".format('CC', email_data.get('CC') or "")
    md += u"* {0}:\t{1}\n".format('Subject', email_data.get('Subject') or "")
    if email_data.get('Text'):
        text = email_data['Text'].replace('<', '[').replace('>', ']')
        md += u"* {0}:\t{1}\n".format('Body/Text', text or "")
    if email_data.get('HTML'):
        md += u"* {0}:\t{1}\n".format('Body/HTML', email_data['HTML'] or "")

    md += u"* {0}:\t{1}\n".format('Attachments', email_data.get('Attachments') or "")
    md += u"\n\n" + tableToMarkdown('HeadersMap', email_data.get('HeadersMap'))
    return md


def save_attachments(attachments, root_email_file_name, max_depth):
    attached_emls = []
    for attachment in attachments:
        if attachment.data is not None:
            display_name = attachment.DisplayName if attachment.DisplayName else attachment.AttachFilename
            display_name = display_name if display_name else ''
            demisto.results(fileResult(display_name, attachment.data))
            name_lower = display_name.lower()
            if max_depth > 0 and (name_lower.endswith(".eml") or name_lower.endswith('.p7m')):
                tf = tempfile.NamedTemporaryFile(delete=False)

                try:
                    tf.write(attachment.data)
                    tf.close()

                    inner_eml, attached_inner_emails = handle_eml(tf.name, file_name=root_email_file_name,
                                                                  max_depth=max_depth)
                    if inner_eml:
                        return_outputs(
                            readable_output=data_to_md(inner_eml, attachment.DisplayName, root_email_file_name),
                            outputs=None)
                        attached_emls.append(inner_eml)
                    if attached_inner_emails:
                        attached_emls.extend(attached_inner_emails)
                finally:
                    os.remove(tf.name)

    return attached_emls


def get_utf_string(text, field):
    if text is None:
        text = ''

    try:
        utf_string = text.encode('utf-8')
    except Exception as ex:
        utf_string = text.decode('utf-8', 'ignore').encode('utf-8')
        temp = demisto.uniqueFile()

        with open(demisto.investigation()['id'] + '_' + temp, 'wb') as f:
            f.write(text)

        demisto.results({
            'Contents': str(ex) + '\n\nOpen HEX viewer to review.',
            'ContentsFormat': formats['text'],
            'Type': entryTypes['file'],
            'File': field,
            'FileID': temp
        })

    return utf_string


def convert_to_unicode(s):
    global ENCODINGS_TYPES
    try:
        res = ''  # utf encoded result
        for decoded_s, encoding in decode_header(s):  # return a list of pairs(decoded, charset)
            if encoding:
                res += decoded_s.decode(encoding).encode('utf-8')
                ENCODINGS_TYPES.add(encoding)
            else:
                res += decoded_s
        return res.strip()
    except Exception:
        for file_data in ENCODINGS_TYPES:
            try:
                s = s.decode(file_data).encode('utf-8').strip()
                break
            except:  # noqa: E722
                pass

    return s


def handle_msg(file_path, file_name, parse_only_headers=False, max_depth=3):
    if max_depth == 0:
        return None, []

    msg = MsOxMessage(file_path)
    if not msg:
        raise Exception("Could not parse msg file!")

    msg_dict = msg.as_dict(max_depth)
    mail_format_type = get_msg_mail_format(msg_dict)
    headers, headers_map = create_headers_map(msg_dict.get('Headers'))

    email_data = {
        'To': msg_dict['To'],
        'CC': msg_dict['CC'],
        'From': msg_dict['From'],
        'Subject': headers_map.get('Subject'),
        'HTML': msg_dict['HTML'],
        'Text': msg_dict['Text'],
        'Headers': headers,
        'HeadersMap': headers_map,
        'Attachments': '',
        'Format': mail_format_type,
        'Depth': MAX_DEPTH_CONST - max_depth
    }

    if parse_only_headers:
        return {"HeadersMap": email_data.get("HeadersMap")}, []

    attached_emails_emls = save_attachments(msg.get_all_attachments(), file_name, max_depth - 1)
    # add eml attached emails

    attached_emails_msg = msg.get_attached_emails_hierarchy(max_depth - 1)
    for attached_email in attached_emails_msg:
        return_outputs(readable_output=data_to_md(attached_email, None, file_name), outputs=None)

    return email_data, attached_emails_emls + attached_emails_msg


def unfold(s):
    r"""
    Remove folding whitespace from a string by converting line breaks (and any
    whitespace adjacent to line breaks) to a single space and removing leading
    & trailing whitespace.
    From: https://github.com/jwodder/headerparser/blob/master/headerparser/types.py#L39
    unfold('This is a \n folded string.\n')
    'This is a folded string.'
    :param string s: a string to unfold
    :rtype: string
    """
    return re.sub(r'[ \t]*[\r\n][ \t\r\n]*', ' ', s).strip(' ')


def decode_content(mime):
    """
      Decode content
    """
    charset = mime.get_content_charset()
    payload = mime.get_payload(decode=True)
    try:
        if payload:
            if charset:
                return payload.decode(charset)
            else:
                return payload.decode()
        else:
            return ''
    except Exception:
        return payload


def handle_eml(file_path, b64=False, file_name=None, parse_only_headers=False, max_depth=3, bom=False):
    global ENCODINGS_TYPES

    if max_depth == 0:
        return None, []

    with open(file_path, 'rb') as emlFile:

        file_data = emlFile.read()
        if b64:
            file_data = b64decode(file_data)
        if bom:
            # decode bytes taking into account BOM and re-encode to utf-8
            file_data = file_data.decode("utf-8-sig").encode("utf-8")

        parser = HeaderParser()
        headers = parser.parsestr(file_data)

        header_list = []
        headers_map = {}  # type: dict
        for item in headers.items():
            value = unfold(convert_to_unicode(item[1]))
            item_dict = {
                "name": item[0],
                "value": value
            }

            # old way to map headers
            header_list.append(item_dict)

            # new way to map headers - dictionary
            if item[0] in headers_map:
                # in case there is already such header
                # then add that header value to value array
                if not isinstance(headers_map[item[0]], list):
                    # convert the existing value to array
                    headers_map[item[0]] = [headers_map[item[0]]]

                # add the new value to the value array
                headers_map[item[0]].append(value)
            else:
                headers_map[item[0]] = value

        eml = message_from_string(file_data)
        if not eml:
            raise Exception("Could not parse eml file!")

        if parse_only_headers:
            return {"HeadersMap": headers_map}, []

        html = ''
        text = ''
        attachment_names = []

        attached_emails = []
        parts = [eml]

        while parts:
            part = parts.pop()
            if (part.is_multipart() or part.get_content_type().startswith('multipart')) \
                    and "attachment" not in part.get("Content-Disposition", ""):
                parts += [part_ for part_ in part.get_payload() if isinstance(part_, email.message.Message)]

            elif part.get_filename() or "attachment" in part.get("Content-Disposition", ""):

                attachment_file_name = convert_to_unicode(part.get_filename())
                if attachment_file_name is None and part.get('filename'):
                    attachment_file_name = os.path.normpath(part.get('filename'))
                    if os.path.isabs(attachment_file_name):
                        attachment_file_name = os.path.basename(attachment_file_name)

                if "message/rfc822" in part.get("Content-Type", "") \
                        or ("application/octet-stream" in part.get("Content-Type", "")
                            and attachment_file_name.endswith(".eml")):

                    # .eml files
                    file_content = ""  # type: str
                    base64_encoded = "base64" in part.get("Content-Transfer-Encoding", "")

                    if isinstance(part.get_payload(), list) and len(part.get_payload()) > 0:
                        if attachment_file_name is None or attachment_file_name == "" or attachment_file_name == 'None':
                            # in case there is no filename for the eml
                            # we will try to use mail subject as file name
                            # Subject will be in the email headers
                            attachment_name = part.get_payload()[0].get('Subject', "no_name_mail_attachment")
                            attachment_file_name = convert_to_unicode(attachment_name) + '.eml'

                        file_content = part.get_payload()[0].as_string()
                        if base64_encoded:
                            try:
                                file_content = b64decode(file_content)

                            except TypeError:
                                pass  # In case the file is a string, decode=True for get_payload is not working

                    elif isinstance(part.get_payload(), basestring) and base64_encoded:
                        file_content = part.get_payload(decode=True)
                    else:
                        demisto.debug("found eml attachment with Content-Type=message/rfc822 but has no payload")

                    if file_content:
                        # save the eml to war room as file entry
                        demisto.results(fileResult(attachment_file_name, file_content))

                    if file_content and max_depth - 1 > 0:
                        f = tempfile.NamedTemporaryFile(delete=False)
                        try:
                            f.write(file_content)
                            f.close()
                            inner_eml, inner_attached_emails = handle_eml(file_path=f.name,
                                                                          file_name=attachment_file_name,
                                                                          max_depth=max_depth - 1)
                            attached_emails.append(inner_eml)
                            attached_emails.extend(inner_attached_emails)
                            # if we are outter email is a singed attachment it is a wrapper and we don't return the output of
                            # this inner email as it will be returned as part of the main result
                            if 'multipart/signed' not in eml.get_content_type():
                                return_outputs(readable_output=data_to_md(inner_eml, attachment_file_name, file_name),
                                               outputs=None)
                        finally:
                            os.remove(f.name)
                    attachment_names.append(attachment_file_name)
                else:
                    # .msg and other files (png, jpeg)
                    if part.is_multipart() and max_depth - 1 > 0:
                        # email is DSN
                        msgs = part.get_payload()  # human-readable section
                        i = 0
                        for indiv_msg in msgs:
                            msg = indiv_msg.get_payload()
                            attachment_file_name = indiv_msg.get_filename()
                            try:
                                # In some cases the body content is empty and cannot be decoded.
                                msg_info = base64.b64decode(msg).decode('utf-8')
                            except TypeError:
                                msg_info = str(msg)
                            attached_emails.append(msg_info)
                            if attachment_file_name is None:
                                attachment_file_name = "unknown_file_name{}".format(i)
                            demisto.results(fileResult(attachment_file_name, msg_info))
                            attachment_names.append(attachment_file_name)
                            i += 1

                    else:
                        file_content = part.get_payload(decode=True)
                        # fileResult will return an error if file_content is None.
                        if file_content and not attachment_file_name.endswith('.p7s'):
                            demisto.results(fileResult(attachment_file_name, file_content))

                        if attachment_file_name.endswith(".msg") and max_depth - 1 > 0:
                            f = tempfile.NamedTemporaryFile(delete=False)
                            try:
                                f.write(file_content)
                                f.close()
                                inner_msg, inner_attached_emails = handle_msg(f.name, attachment_file_name, False,
                                                                              max_depth - 1)
                                attached_emails.append(inner_msg)
                                attached_emails.extend(inner_attached_emails)

                                # will output the inner email to the UI
                                return_outputs(
                                    readable_output=data_to_md(inner_msg, attachment_file_name, file_name),
                                    outputs=None)
                            finally:
                                os.remove(f.name)

                        attachment_names.append(attachment_file_name)
                demisto.setContext('AttachmentName', attachment_file_name)

            elif part.get_content_type() == 'text/html':
                # This line replaces a new line that starts with `..` to a newline that starts with `.`
                # This is because SMTP duplicate dots for lines that start with `.` and get_payload() doesn't format
                # this correctly
                part._payload = part._payload.replace('=\r\n..', '=\r\n.')
                html = get_utf_string(decode_content(part), 'HTML')

            elif part.get_content_type() == 'text/plain':
                text = get_utf_string(decode_content(part), 'TEXT')
        email_data = None
        # if we are parsing a signed attachment there can be one of two options:
        # 1. it is 'multipart/signed' so it is probably a wrapper and we can ignore the outer "email"
        # 2. if it is 'multipart/signed' but has 'to' address so it is actually a real mail.
        if 'multipart/signed' not in eml.get_content_type() \
                or ('multipart/signed' in eml.get_content_type() and extract_address_eml(eml, 'to')):
            email_data = {
                'To': extract_address_eml(eml, 'to'),
                'CC': extract_address_eml(eml, 'cc'),
                'From': extract_address_eml(eml, 'from'),
                'Subject': convert_to_unicode(eml['Subject']),
                'HTML': convert_to_unicode(html),
                'Text': convert_to_unicode(text),
                'Headers': header_list,
                'HeadersMap': headers_map,
                'Attachments': ','.join(attachment_names) if attachment_names else '',
                'AttachmentNames': attachment_names if attachment_names else [],
                'Format': eml.get_content_type(),
                'Depth': MAX_DEPTH_CONST - max_depth
            }
        return email_data, attached_emails


def create_email_output(email_data, attached_emails):
    # for backward compatibility if there are no attached files we return single dict
    # if there are attached files then we will return array of all the emails
    res = []
    if email_data:
        res.append(email_data)
    if len(attached_emails) > 0:
        res.extend(attached_emails)
    if len(res) == 0:
        return None
    if len(res) == 1:
        return res[0]
    return res


def is_email_data_populated(email_data):
    # checks if email data has any item populated to it
    if email_data:
        for key, val in email_data.iteritems():
            if val:
                return True
    return False


def main():
    file_type = ''
    entry_id = demisto.args()['entryid']
    max_depth = int(demisto.args().get('max_depth', '3'))

    # we use the MAX_DEPTH_CONST to calculate the depth of the email
    # each level will reduce the max_depth by 1
    # not the best way to do it
    global MAX_DEPTH_CONST
    MAX_DEPTH_CONST = max_depth

    if max_depth < 1:
        return_error('Minimum max_depth is 1, the script will parse just the top email')

    parse_only_headers = demisto.args().get('parse_only_headers', 'false').lower() == 'true'
    try:
        result = demisto.executeCommand('getFilePath', {'id': entry_id})
        if is_error(result):
            return_error(get_error(result))

        file_path = result[0]['Contents']['path']
        file_name = result[0]['Contents']['name']
        result = demisto.executeCommand('getEntry', {'id': entry_id})
        if is_error(result):
            return_error(get_error(result))

        file_metadata = result[0]['FileMetadata']
        file_type = file_metadata.get('info', '') or file_metadata.get('type', '')
        if 'MIME entity text, ISO-8859 text' in file_type:
            file_type = 'application/pkcs7-mime'

    except Exception as ex:
        return_error(
            "Failed to load file entry with entry id: {}. Error: {}".format(
                entry_id, str(ex) + "\n\nTrace:\n" + traceback.format_exc()))

    try:
        file_type_lower = file_type.lower()
        if 'composite document file v2 document' in file_type_lower \
                or 'cdfv2 microsoft outlook message' in file_type_lower:
            email_data, attached_emails = handle_msg(file_path, file_name, parse_only_headers, max_depth)
            output = create_email_output(email_data, attached_emails)

        elif any(eml_candidate in file_type_lower for eml_candidate in
                 ['rfc 822 mail', 'smtp mail', 'multipart/signed', 'message/rfc822', 'application/pkcs7-mime']):
            if 'unicode (with bom) text' in file_type_lower:
                email_data, attached_emails = handle_eml(
                    file_path, False, file_name, parse_only_headers, max_depth, bom=True
                )
            else:
                email_data, attached_emails = handle_eml(file_path, False, file_name, parse_only_headers, max_depth)
            output = create_email_output(email_data, attached_emails)

        elif ('ascii text' in file_type_lower or 'unicode text' in file_type_lower
              or ('data' == file_type_lower.strip() and file_name and file_name.lower().strip().endswith('.eml'))):
            try:
                # Try to open the email as-is
                with open(file_path, 'rb') as f:
                    file_contents = f.read()

                if file_contents and 'Content-Type:'.lower() in file_contents.lower():
                    email_data, attached_emails = handle_eml(file_path, b64=False, file_name=file_name,
                                                             parse_only_headers=parse_only_headers, max_depth=max_depth)
                    output = create_email_output(email_data, attached_emails)
                else:
                    # Try a base64 decode
                    b64decode(file_contents)
                    if file_contents and 'Content-Type:'.lower() in file_contents.lower():
                        email_data, attached_emails = handle_eml(file_path, b64=True, file_name=file_name,
                                                                 parse_only_headers=parse_only_headers,
                                                                 max_depth=max_depth)
                        output = create_email_output(email_data, attached_emails)
                    else:
                        try:
                            # Try to open
                            email_data, attached_emails = handle_eml(file_path, b64=False, file_name=file_name,
                                                                     parse_only_headers=parse_only_headers,
                                                                     max_depth=max_depth)
                            is_data_populated = is_email_data_populated(email_data)
                            if not is_data_populated:
                                raise DemistoException("No email_data found")
                            output = create_email_output(email_data, attached_emails)
                        except Exception as e:
                            demisto.debug("ParseEmailFiles failed with {}".format(str(e)))
                            return_error("Could not extract email from file. Possible reasons for this error are:\n"
                                         "- Base64 decode did not include rfc 822 strings.\n"
                                         "- Email contained no Content-Type and no data.")

            except Exception as e:
                return_error("Exception while trying to decode email from within base64: {}\n\nTrace:\n{}"
                             .format(str(e), traceback.format_exc()))
        else:
            return_error("Unknown file format: [{}] for file: [{}]".format(file_type, file_name))
        output = recursive_convert_to_unicode(output)
        email = output  # output may be a single email
        if isinstance(output, list) and len(output) > 0:
            email = output[0]
        return_outputs(
            readable_output=data_to_md(email, file_name, print_only_headers=parse_only_headers),
            outputs={
                'Email': output
            },
            raw_response=output
        )

    except Exception as ex:
        demisto.error(str(ex) + "\n\nTrace:\n" + traceback.format_exc())
        return_error(str(ex) + "\n\nTrace:\n" + traceback.format_exc())


if __name__ in ('__builtin__', '__main__'):
    main()

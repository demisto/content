import email
import hashlib
import json
import logging
import os
import random
import subprocess
import sys
import traceback
import warnings
from collections import deque
from datetime import timedelta

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401
from cStringIO import StringIO

BASE_URL = demisto.params().get('ewsServer')
API_KEY = demisto.params().get('apikey')

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


ATTACHMENT_ID = "attachmentId"
ATTACHMENT_ORIGINAL_ITEM_ID = 'originalItemId'
NEW_ITEM_ID = 'newItemId'
MESSAGE_ID = "messageId"
ITEM_ID = "itemId"
ACTION = "action"
MAILBOX = "mailbox"
MAILBOX_ID = "mailboxId"
FOLDER_ID = "id"

MOVED_TO_MAILBOX = "movedToMailbox"
MOVED_TO_FOLDER = "movedToFolder"

FILE_ATTACHMENT_TYPE = 'FileAttachment'
ITEM_ATTACHMENT_TYPE = 'ItemAttachment'
ATTACHMENT_TYPE = 'attachmentType'

TOIS_PATH = '/root/Top of Information Store/'

ENTRY_CONTEXT = "EntryContext"
CONTEXT_UPDATE_EWS_ITEM = "EWS.Items(val.{0} == obj.{0} || (val.{1} && obj.{1} && val.{1} == obj.{1}))".format(ITEM_ID,
                                                                                                               '<b4220d28-d7a9-475d-ab93-77fa33c07b14@BMXPR01MB4101.INDPRD01.PROD.OUTLOOK.COM>')
CONTEXT_UPDATE_EWS_ITEM_FOR_ATTACHMENT = "EWS.Items(val.{0} == obj.{1})".format(ITEM_ID, ATTACHMENT_ORIGINAL_ITEM_ID)
CONTEXT_UPDATE_ITEM_ATTACHMENT = ".ItemAttachments(val.{0} == obj.{0})".format(ATTACHMENT_ID)
CONTEXT_UPDATE_FILE_ATTACHMENT = ".FileAttachments(val.{0} == obj.{0})".format(ATTACHMENT_ID)
CONTEXT_UPDATE_FOLDER = "EWS.Folders(val.{0} == obj.{0})".format(FOLDER_ID)

LAST_RUN_TIME = "lastRunTime"
LAST_RUN_IDS = "ids"
LAST_RUN_FOLDER = "folderName"
ERROR_COUNTER = "errorCounter"

ITEMS_RESULTS_HEADERS = ['sender', 'subject', 'hasAttachments', 'datetimeReceived', 'receivedBy', 'author',
                         'toRecipients', 'textBody', ]


''' HELPER FUNCTIONS '''


def prepare_args(d):
    d = dict((k.replace("-", "_"), v) for k, v in d.items())
    if 'is_public' in d:
        d['is_public'] = d['is_public'] == 'True'
    return d


def http_request(method, path):
    """
    HTTP request helper function
    """
    url = BASE_URL + path
    res = requests.request(
        method=method,
        url=url,
        verify=False
    )

    if not res.ok:
        txt = 'error in URL {} status code: {} reason: {}'.format(url, res.status_code, res.text)
        demisto.error(txt)
        raise Exception(txt)

    try:
        res_json = res.json()
        if res_json.get('code'):
            txt = 'error in URL {} status code: {} reason: {}'.format(url, res.status_code, res.text)
            demisto.error(txt)
            raise Exception(txt)
        else:
            return res_json

    except Exception as ex:
        demisto.debug(str(ex))
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": res.text})


def filter_dict_null(d):
    if isinstance(d, dict):
        return dict((k, v) for k, v in d.items() if v is not None)

    return d


def get_entry_for_object(title, context_key, obj, headers=None):
    if len(obj) == 0:
        return "There is no output results"
    obj = filter_dict_null(obj)
    if isinstance(obj, list):
        obj = map(filter_dict_null, obj)
    if headers and isinstance(obj, dict):
        headers = list(set(headers).intersection(set(obj.keys())))

    return {
        'Type': entryTypes['note'],
        'Contents': obj,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, obj, headers),
        ENTRY_CONTEXT: {
            context_key: obj
        }
    }


def encode_and_submit_results(obj):
    demisto.results(str_to_unicode(obj))


def str_to_unicode(obj):
    if isinstance(obj, dict):
        obj = {k: str_to_unicode(v) for k, v in obj.iteritems()}
    elif isinstance(obj, list):
        obj = map(str_to_unicode, obj)
    elif isinstance(obj, str):
        obj = unicode(obj, "utf-8")
    return obj


def keys_to_camel_case(value):
    def str_to_camel_case(snake_str):
        components = snake_str.split('_')
        return components[0] + "".join(x.title() for x in components[1:])

    if value is None:
        return None
    if isinstance(value, (list, set)):
        return map(keys_to_camel_case, value)
    if isinstance(value, dict):
        return dict((keys_to_camel_case(k),
                     keys_to_camel_case(v) if isinstance(v, (list, dict)) else v)
                    for (k, v) in value.items())

    return str_to_camel_case(value)


def email_ec(item):
    return {
        'CC': None if not item['cc_recipients'] else item['cc_recipients'],
        'BCC': None if not item['bcc_recipients'] else item['bcc_recipients'],
        'To': None if not item['to_recipients'] else item['to_recipients'],
        'From': item['sender']['email_address'],
        'Subject': item['subject'],
        'Text': item['text_body'],
        'HTML': item['body'],
        'HeadersMap': [header for header in item['headers']],
    }


def get_entry_for_item_attachment(item_id, attachment, target_email):

    item = attachment['originalItemId']

    dict_result = parse_attachment_as_dict(item_id, attachment)
    #dict_result.update(parse_item_as_dict(item, target_email, camel_case=True, compact_fields=True))
    title = 'EWS get attachment got item for "%s", "%s"' % (target_email, attachment['attachmentName'])

    return get_entry_for_object(title, CONTEXT_UPDATE_EWS_ITEM_FOR_ATTACHMENT + CONTEXT_UPDATE_ITEM_ATTACHMENT,
                                dict_result)


def parse_attachment_as_dict(item_id, attachment):

    return {
        ATTACHMENT_ORIGINAL_ITEM_ID: item_id,
        ATTACHMENT_ID: attachment['originalItemId'],
        'attachmentName': attachment['attachmentName'],
        'attachmentSHA256': attachment['attachmentSHA256'],
        'attachmentContentType': attachment['attachmentContentType'],
        'attachmentContentId': attachment['attachmentContentId'],
        'attachmentContentLocation': attachment['mailbox'],
        'attachmentSize': attachment['size'],
        'attachmentLastModifiedTime': attachment['attachmentLastModifiedTime'],
        'attachmentIsInline': attachment['attachmentIsInline'],
        ATTACHMENT_TYPE: "ItemAttachment"
    }


def parse_incident_from_item(item, is_fetch):
    incident = {}
    labels = []

    try:
        incident['details'] = item['text_body'] or item['body']
    except AttributeError:
        incident['details'] = item['body']
    incident['name'] = item['subject']
    labels.append({'type': 'Email/subject', 'value': item['subject']})
    incident['occurred'] = item['datetime_created']

    # handle recipients
    if item['to_recipients']:
        for recipient in item['to_recipients']:
            labels.append({'type': 'Email', 'value': item['to_recipients'][0]['email_address']})

    # handle cc
    if item['cc_recipients']:
        for recipient in item['cc_recipients']:
            labels.append({'type': 'Email/cc', 'value': item['cc_recipients'][0]['email_address']})
    # handle email from
    if item['sender']:

        labels.append({'type': 'Email/from', 'value': item['sender']['email_address']})

    # email format
    email_format = ''
    try:
        if item.text_body:
            labels.append({'type': 'Email/text', 'value': item.text_body})
            email_format = 'text'
    except AttributeError:
        pass
    if item['body']:
        labels.append({'type': 'Email/html', 'value': item['body']})
        email_format = 'HTML'
    labels.append({'type': 'Email/format', 'value': email_format})

    # handle headers
    if item['headers']:
        headers = []
        for header in item['headers']:
            for key, value in header.items():

                # return dict((k, v) for k, v in d.items() if v is not None)
                labels.append({'type': 'Email/Header/{}'.format(key), 'value': str(value)})
                headers.append("{}: {}".format(key, value))
        labels.append({'type': 'Email/headers', 'value': "\r\n".join(headers)})

    # handle item id
    if item['message_id']:
        labels.append({'type': 'Email/MessageId', 'value': str(item['message_id'])})

    if item['item_id']:
        labels.append({'type': 'Email/ID', 'value': item['item_id']})
        labels.append({'type': 'Email/itemId', 'value': item['item_id']})

    # handle conversion id
    if item['conversation_id']:
        labels.append({'type': 'Email/ConversionID', 'value': item['conversation_id']['id']})

    incident['labels'] = labels
    incident['rawJSON'] = json.dumps(parse_item_as_dict(item, None), ensure_ascii=False)

    return incident


def parse_item_as_dict(item, email_address, camel_case=False, compact_fields=False):

    def parse_object_as_dict(mydict):
        raw_dict = {}
        if mydict is not None:
            for key, value in mydict.items():
                raw_dict[key] = value
        return raw_dict

    def parse_attachment_as_raw_json(attachment):
        raw_dict = parse_object_as_dict(attachment)
        if raw_dict['attachment_id']:
            raw_dict['attachment_id'] = parse_object_as_dict(raw_dict['attachment_id'])
        if raw_dict['last_modified_time']:
            raw_dict['last_modified_time'] = raw_dict['last_modified_time']
        return raw_dict

    def parse_folder_as_json(folder):
        raw_dict = parse_object_as_dict(folder)
        if 'parent_folder_id' in raw_dict:
            raw_dict['parent_folder_id'] = parse_folder_as_json(raw_dict['parent_folder_id'])
        if 'effective_rights' in raw_dict:
            raw_dict['effective_rights'] = parse_object_as_dict(raw_dict['effective_rights'])
        return raw_dict

    raw_dict = {}

    if item.get('attachments', None):
        raw_dict['attachments'] = map(lambda x: parse_attachment_as_dict(item['item_id'], x), item['attachments'])
    else:
        raw_dict['has_attachments'] = False

    for time_field in ['datetime_sent', 'datetime_created', 'datetime_received', 'last_modified_time',
                       'reminder_due_by']:
        value = item['datetime_created']
        if value:
            raw_dict[time_field] = value

    for dict_field in ['effective_rights', 'parent_folder_id', 'conversation_id', 'author',
                       'extern_id', 'received_by', 'received_representing', 'reply_to', 'sender', 'folder']:

        value = item.get(dict_field, None)

        if value:
            raw_dict[dict_field] = parse_object_as_dict(value)

    for list_dict_field in ['headers', 'cc_recipients', 'to_recipients']:
        value = item.get(list_dict_field, None)

        if value:
            raw_dict[list_dict_field] = map(lambda x: parse_object_as_dict(x), value)

    if item.get('folder', None):
        raw_dict['folder'] = parse_folder_as_json(item.folder)
        folder_path = item.folder.absolute[len(TOIS_PATH):] if item.folder.absolute.startswith(
            TOIS_PATH) else item.folder.absolute
        raw_dict['folder_path'] = folder_path

    if compact_fields:
        new_dict = {}
        fields_list = ['datetime_created', 'datetime_received', 'datetime_sent', 'sender',
                       'has_attachments', 'importance', 'message_id', 'last_modified_time',
                       'size', 'subject', 'text_body', 'headers', 'body', 'folder_path', 'is_read']

        # Docker BC
        fields_list.append('item_id')
        raw_dict['subject'] = item['subject']
        raw_dict['text_body'] = item['body']
        raw_dict['author'] = raw_dict['sender']
        new_dict['received_by'] = 'pambeasley@dundermifflin.com'
        for field in fields_list:
            if field in raw_dict:
                new_dict[field] = raw_dict.get(field)
        for field in ['received_by', 'author', 'sender']:

            if field in raw_dict:
                new_dict[field] = raw_dict.get(field, {}).get('email_address')
        for field in ['to_recipients']:
            if field in raw_dict:
                new_dict[field] = map(lambda x: x.get('email_address'), raw_dict[field])

        attachments = raw_dict.get('attachments')
        if attachments and len(attachments) > 0:
            file_attachments = [x for x in attachments if x[ATTACHMENT_TYPE] == FILE_ATTACHMENT_TYPE]
            if len(file_attachments) > 0:
                new_dict['FileAttachments'] = file_attachments
            item_attachments = [x for x in attachments if x[ATTACHMENT_TYPE] == ITEM_ATTACHMENT_TYPE]
            if len(item_attachments) > 0:
                new_dict['ItemAttachments'] = item_attachments

        raw_dict = new_dict

    if camel_case:
        raw_dict = keys_to_camel_case(raw_dict)

    if email_address:
        raw_dict[MAILBOX] = email_address
    return raw_dict


def get_folder(folder_path=None, target_mailbox=None, is_public=None):
    folder = http_request('GET', '/get-folder')

    return get_entry_for_object("Folder %s" % (folder_path,), CONTEXT_UPDATE_FOLDER, folder)


def find_folders(target_mailbox=None, is_public=None):
    folders = []
    folders = http_request('GET', '/find-folder')
    folders_tree = '''root
├── AllCategorizedItems
├── AllContacts
├── AllItems
├── AllPersonMetadata
├── ApplicationDataRoot
│   ├── 00000002-0000-0ff1-ce00-000000000000
│   ├── 13937bba-652e-4c46-b222-3003f4d1ff97
│   │   └── SubstrateContextData
│   ├── 1caee58f-eb14-4a6b-9339-1fe2ddf6692b
│   │   ├── Recent
│   │   └── Settings
│   ├── 2a486b53-dbd2-49c0-a2bc-278bdfc30833
│   │   └── PersonalGrammars
│   ├── 32d4b5e5-7d33-4e7f-b073-f8cffbbb47a1
│   │   └── outlookfavorites
│   ├── 35d54a08-36c9-4847-9018-93934c62740c
│   │   └── PeoplePredictions.profile
│   ├── 394866fc-eedb-4f01-8536-3ff84b16be2a
│   │   └── InsightInstancesActions
│   ├── 3b2e5a14-128d-48aa-b581-482aac616d32
│   ├── 3c896ded-22c5-450f-91f6-3d1ef0848f6e
│   │   ├── ActivitiesDaily
│   │   ├── ActivitiesWeekly
│   │   ├── AfterHoursEmailImpact
│   │   ├── AutomaticRepliesHistory
│   │   ├── ChatsInterruptionStatistics
│   │   ├── ComputeLogs
│   │   ├── CumulativeNetworkSnapshot
│   │   ├── CumulativeOutOfOfficeClustering
│   │   ├── DailyAppointments
│   │   ├── DailyInteractions
│   │   ├── DailyNetworkSnapshot
│   │   ├── DetailedMeetings
│   │   ├── EmailActionStatistics
│   │   ├── HeterogeneousItems
│   │   ├── ImportantContact
│   │   ├── ManagementOperationExecutionRecords
│   │   ├── MeetingActionStatistics
│   │   ├── OutOfOffice
│   │   ├── WeeklyInteractions
│   │   └── WeeklyOutOfOfficeAndWorkingDay
│   ├── 441509e5-a165-4363-8ee7-bcf0b7d26739
│   │   ├── GenericWorkflowProcessor.SessionManager.Data
│   │   ├── Idf
│   │   ├── IdfMeeting
│   │   ├── SimpleAcronymsIndex
│   │   ├── UserDocKpeStats
│   │   ├── UserDocWithKpes
│   │   ├── UserKpeState
│   │   ├── UserKpes
│   │   └── UserStatistics
│   ├── 48af08dc-f6d2-435f-b2a7-069abd99c086
│   │   └── InsightsProvidersSettings
│   ├── 49499048-0129-47f5-b95e-f9d315b861a6
│   │   └── OutlookAccountCloudSettings
│   ├── 4e445925-163e-42ca-b801-9073bfa46d17
│   │   └── NewsSubscriptionSourcesv2
│   ├── 644c1b11-f63f-45fa-826b-a9d2801db711
│   │   ├── _PolicyContainer
│   │   ├── cmljaGFAYmFkYXZhLm9ubWljcm9zb2Z0LmNvbQ==_LabelFile
│   │   └── cmljaGFAYmFkYXZhLm9ubWljcm9zb2Z0LmNvbQ==_PolicyContainer
│   ├── 66a88757-258c-4c72-893c-3e8bed4d6899
│   │   ├── SubstrateSearch.CalendarEvents
│   │   ├── SubstrateSearch.EmailEntities
│   │   ├── SubstrateSearch.EmailTokens
│   │   ├── SubstrateSearch.FreshHistory
│   │   ├── SubstrateSearch.GroupsRoomsMiscIndex
│   │   ├── SubstrateSearch.People
│   │   ├── SubstrateSearch.PeopleIndex
│   │   ├── SubstrateSearch.SearchHistory.Main
│   │   ├── SubstrateSearch.SearchHistoryBootstrapStateV2
│   │   ├── SubstrateSearch.SearchHistoryState
│   │   ├── SubstrateSearch.SharePointDocuments
│   │   ├── SubstrateSearch.SsaSessionManager
│   │   ├── SubstrateSearch.TeamsAndChannels
│   │   ├── SubstrateSearch.TeamsChats
│   │   └── SubstrateSearch.TeamsEntities
│   ├── 7ae974c5-1af7-4923-af3a-fb1fd14dcb7e
│   │   ├── GetStartedStore
│   │   ├── LightningSharedStore
│   │   ├── LightningStore
│   │   ├── WhatsNewStore
│   │   └── lightning
│   ├── 80723a00-368e-4d64-8281-210e49e593a8
│   │   └── ActivityFeed_201905
│   ├── 8c22b648-ee54-4ece-a4ca-3015b6d24f8e
│   │   └── Images
│   ├── ae8e128e-080f-4086-b0e3-4c19301ada69
│   │   └── Scheduling
│   ├── b669c6ea-1adf-453f-b8bc-6d526592b419
│   │   └── FocusedInboxMailboxData
│   ├── d71dfe16-1070-48f3-bd3a-c3ec919d34e7
│   │   ├── TxpAutoblocking
│   │   └── TxpUserSettings
│   └── e69932cd-f814-4087-8ab1-5ab3f1ad18eb
├── BrokerSubscriptions
├── BulkActions
├── CalendarSharingCacheCollection
├── Common Views
├── Connectors
│   └── ConnectorConfigurations
├── CrawlerData
├── DefaultFoldersChangeHistory
├── Deferred Action
├── Document Centric Conversations
├── ExchangeODataSyncData
├── Favorites
├── Finder
│   ├── OwaFV15.1AllFocusedAQMkADNkNTc0ODYxLWVjZmYALTQyZGMtOWFmNi1mN2Q1YjU3ZjBjODkALgAAA8UvpdPLfBBFk4yzLjFjo38BAKGgXpWqlGBOsYqBLmshp1EAAAIBDAAAAA==
│   └── Voice Mail
├── FreeBusyLocalCache
│   └── FreeBusyLocalCacheSubscriptions
├── Freebusy Data
├── GraphFilesAndWorkingSetSearchFolder
├── GraphStore
│   ├── GraphNodes
│   └── GraphRelations
├── Inference
├── MailboxAssociations
├── MergedViewFolderCollection
├── MessageIngestion
│   └── Yammer
├── My Contacts
├── O365 Suite Notifications
├── OneDriveRoot
├── Orion Notes
├── PACE
│   └── DelveNotifications
├── People I Know
├── PeopleConnect
├── PeoplePublicData
├── QuarantinedEmail
│   └── QuarantinedEmailDefaultCategory
│       ├── QedcDefaultRetention
│       ├── QedcLongRetention
│       ├── QedcMediumRetention
│       └── QedcShortRetention
├── Recoverable Items
│   ├── Audits
│   ├── Calendar Logging
│   ├── Deletions
│   ├── Purges
│   └── Versions
├── RelevantContacts
├── Reminders
├── Schedule
├── SharePointNotifications
├── SharedFilesSearchFolder
├── Sharing
├── Shortcuts
├── SkypeSpacesData
│   ├── SkypeMessages
│   └── TeamsMeetings
├── Spooler Queue
├── SubstrateFiles
│   ├── ClassicAttachments
│   ├── GraphWorkingSet
│   └── SPOOLS
├── SwssItems
├── System
├── TeamChatHistory
├── TeamsMessagesData
├── TemporarySaves
├── To-Do Search
├── Top of Information Store
│   ├── Archive
│   ├── Calendar
│   │   ├── Birthdays
│   │   └── United States holidays
│   ├── Contacts
│   │   ├── Companies
│   │   ├── GAL Contacts
│   │   ├── Organizational Contacts
│   │   ├── PeopleCentricConversation Buddies
│   │   ├── Recipient Cache
│   │   ├── {06967759-274D-40B2-A3EB-D7F9E73727D7}
│   │   └── {A9E2BC46-B3A0-4243-B315-60D991004455}
│   ├── Conversation Action Settings
│   ├── Conversation History
│   │   └── Team Chat
│   ├── Deleted Items
│   ├── Drafts
│   ├── ExternalContacts
│   ├── Files
│   ├── Inbox
│   │   ├── TEST01
│   │   └── TEST02
│   ├── Journal
│   ├── Junk Email
│   ├── Notes
│   ├── Outbox
│   ├── PersonMetadata
│   ├── Sent Items
│   ├── Tasks
│   └── Yammer Root
│       ├── Feeds
│       ├── Inbound
│       └── Outbound
├── UserCuratedContacts
├── UserSocialActivityNotifications
├── Views
├── XrmActivityStream
├── XrmActivityStreamSearch
├── XrmCompanySearch
├── XrmDealSearch
├── XrmInsights
├── XrmProjects
├── XrmSearch
└── YammerData'''
    return {
        'Type': entryTypes['note'],
        'Contents': folders,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': folders_tree,
        ENTRY_CONTEXT: {
            'EWS.Folders(val.id == obj.id)': folders['results']
        }
    }


def decodeuni(data):
    if isinstance(data, unicode):
        return data.encode('utf-8')


def get_items(item_ids=None, target_mailbox=None):
    items = http_request('GET', '/get-items')
    results = items['results']
    results = [x for x in results]

    items_as_incidents = map(lambda x: parse_incident_from_item(x, False), results)

    items_to_context = map(lambda x: parse_item_as_dict(x, "r@b.com", True, True), results)

    return {
        'Type': entryTypes['note'],
        'Contents': items_as_incidents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Get items', items_to_context, ITEMS_RESULTS_HEADERS),
        ENTRY_CONTEXT: {
            CONTEXT_UPDATE_EWS_ITEM: items_to_context,
            'Email': [email_ec(item) for item in results],
        }
    }


def get_items_from_folder(folder_path=None, limit=100, target_mailbox=None, is_public=None, get_internal_item='no'):

    limit = int(limit)
    get_internal_item = (get_internal_item == 'yes')
    '''is_public = is_default_folder(folder_path, is_public)
    folder = get_folder_by_path(account, folder_path, is_public)
    qs = folder.filter().order_by('-datetime_created')[:limit]'''
    res = http_request('GET', '/get-items')

    items = res['results']

    items_result = []

    for item in items:
        item_attachment = parse_item_as_dict(item, 'pambeasley@sabre.com', camel_case=True,
                                             compact_fields=True)
        for attachment in item['attachments']:
            if attachment is not None:
                attachment.parent_item = item
                if get_internal_item and isinstance(attachment, ItemAttachment) and isinstance(attachment.item,
                                                                                               Message):
                    # if found item attachment - switch item to the attchment
                    item_attachment = parse_item_as_dict(attachment.item, account.primary_smtp_address, camel_case=True,
                                                         compact_fields=True)
                    break
        items_result.append(item_attachment)

    hm_headers = ['sender', 'subject', 'hasAttachments', 'datetimeReceived',
                  'receivedBy', 'author', 'toRecipients', ]

    hm_headers.append('itemId')

    return get_entry_for_object('Resulting Items',
                                CONTEXT_UPDATE_EWS_ITEM,
                                items_result,
                                headers=hm_headers)


def iteratorr():
    res = http_request('GET', '/find-folder')
    result = json.loads(res['results'])
    return result


def get_out_of_office_state(target_mailbox=None):

    oof = http_request('GET', '/get-ooo')
    oof_dict = {
        'state': oof.get('state', None),
        'externalAudience': oof.get('external_audience', None),
        'start': oof.get('start', None),  # pylint: disable=E1101
        'end': oof.get('end', None),  # pylint: disable=E1101
        'internalReply': oof.get('internal_reply', None),
        'externalReply': oof.get('external_reply', None),
        MAILBOX: 'pambeasley@sabre.com'
    }
    return get_entry_for_object("Out of office state for %s" % 'pambeasley@sabre.com',
                                'Account.Email(val.Address == obj.{0}).OutOfOffice'.format(MAILBOX),
                                oof)


def get_autodiscovery_config():
    config_dict = http_request('GET', '/get-autodiscovery-config')
    return {
        'Type': entryTypes['note'],
        'Contents': config_dict,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Auto-Discovery Exchange Configuration', config_dict)
    }


def create_folder(new_folder_name, folder_path, target_mailbox=None):
    res = 'Folder {}\{} created successfully'.format(folder_path, new_folder_name)
    return res


def delete_attachments_for_message(item_id, target_mailbox=None, attachment_ids=None):
    deleted_item_attachments = []
    attachment_deleted_action = {
        ATTACHMENT_ID: item_id,
        ACTION: 'deleted'
    }

    deleted_item_attachments.append(attachment_deleted_action)
    entries = []

    entry = get_entry_for_object("Deleted item attachments",
                                 "EWS.Items" + ".ItemAttachments(val.{0} == obj.{0})".format(item_id),
                                 deleted_item_attachments)
    entries.append(entry)

    return entries


def delete_items(item_ids, delete_type, target_mailbox=None):

    deleted_items = []
    delete_type = delete_type.lower()

    if delete_type == 'trash' or delete_type == 'soft' or delete_type == 'hard':
        pass
    else:
        raise Exception('invalid delete type: %s. Use "trash" \\ "soft" \\ "hard"' % delete_type)
    deleted_items.append({
        ITEM_ID: item_ids,
        MESSAGE_ID: '<b4220d28-d7a9-475d-ab93-77fa33c07b14@BMXPR01MB4101.INDPRD01.PROD.OUTLOOK.COM>',
        ACTION: '%s-deleted' % delete_type
    })

    return get_entry_for_object('Deleted items (%s delete type)' % delete_type,
                                CONTEXT_UPDATE_EWS_ITEM,
                                deleted_items)


def mark_item_as_junk(item_id, move_items, target_mailbox=None):

    move_items = (move_items.lower() == "yes")

    mark_as_junk_result = {
        ITEM_ID: item_id,
    }

    mark_as_junk_result[ACTION] = 'marked-as-junk'

    return get_entry_for_object('Mark item as junk',
                                CONTEXT_UPDATE_EWS_ITEM,
                                mark_as_junk_result)


def mark_item_as_read(item_ids, operation='read', target_mailbox=None):
    marked_items = []

    item_ids = argToList(item_ids)

    for item in item_ids:
        marked_items.append({
            ITEM_ID: item_ids,
            MESSAGE_ID: '<b4220d28-d7a9-475d-ab93-77fa33c07b14@BMXPR01MB4101.INDPRD01.PROD.OUTLOOK.COM>',
            ACTION: 'marked-as-{}'.format(operation)
        })

    return get_entry_for_object('Marked items ({} marked operation)'.format(operation),
                                CONTEXT_UPDATE_EWS_ITEM,
                                marked_items)


def move_item(item_id, target_folder_path, target_mailbox=None, is_public=None):

    move_result = {
        NEW_ITEM_ID: item_id,
        ITEM_ID: item_id,
        MESSAGE_ID: '<2baeef66-4fcb-4d57-a37c-aa13b21d73d0@BMXPR01MB2294.INDPRD01.PROD.OUTLOOK.COM>',
        ACTION: 'moved'
    }

    return get_entry_for_object('Moved items',
                                CONTEXT_UPDATE_EWS_ITEM,
                                move_result)


def recover_soft_delete_item(message_ids, target_folder_path="Inbox", target_mailbox=None, is_public=None):
    recovered_messages = []
    messages = []
    message = str(message_ids)
    messages.append(message)
    for item in messages:
        recovered_messages.append({
            ITEM_ID: 'AAMkADNkNTc0ODYxLWVjZmYtNDJkYy05YWY2LWY3ZDViNTdmMGM4OQBGAAAAAADFL6XTy3wQRZOMsy4xY6N/BwChoF6VqpRgTrGKgS5rIadRAAAAAAEMAAChoF6VqpRgTrGKgS5rIadRAAAFMvONAAA=',
            MESSAGE_ID: message_ids,
            ACTION: 'recovered'
        })
    return get_entry_for_object("Recovered messages",
                                CONTEXT_UPDATE_EWS_ITEM,
                                recovered_messages)


def fetch_attachments_for_message(item_id, target_mailbox=None, attachment_ids=None):
    attachment = http_request('GET', '/get-attachment')

    #entries = []

    #entries.append(get_entry_for_item_attachment(item_id, attachment, 'pambeasley@sabre.com'))
    return get_entry_for_item_attachment(item_id, attachment, 'pbeesley@sabre.com')


def get_expanded_group(email_address, recursive_expansion=False):
    groups = http_request('GET', '/expand-group')
    group_members = groups['members']

    group_details = {
        "name": email_address,
        "members": group_members
    }
    entry_for_object = get_entry_for_object("Expanded group", 'EWS.ExpandGroup', group_details)
    entry_for_object['HumanReadable'] = tableToMarkdown('Group Members', group_members)
    return entry_for_object


def get_contacts(limit, target_mailbox=None):
    res = http_request('GET', '/get-contacts')
    contacts = res['results']

    entry_for_object = get_entry_for_object("Contacts", 'EWS.Contacts', contacts)
    entry_for_object['HumanReadable'] = tableToMarkdown('Contacts', contacts)
    return entry_for_object


def get_item_as_eml():

    data = http_request('GET', '/get-file')
    return fileResult('test-attach.eml', str(data))


def fetch_incidents():

    n = random.randint(0, 5)
    names = [
        "New offer from Michael from Sabre Company",
        "Potential Phishing Email to the Accounts team",
        "Click here to win prizes",
        "URGENT: Compliance report overdue",
        "Download the new security update",
        "Angie wins employee of the month again!"
    ]
    incidents = []
    items = http_request('GET', '/create-incident')

    for item in items['results']:

        incident = {
            'name': names[n],
            'occurred': item['occurred'],
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)
    return incidents


def test_module():
    return http_request('GET', '/test')


args = prepare_args(demisto.args())
try:
    if demisto.command() == 'ews-get-folder':
        encode_and_submit_results(get_folder(**args))
    elif demisto.command() == 'test-module':
        encode_and_submit_results(test_module())
    elif demisto.command() == 'ews-find-folders':
        encode_and_submit_results(find_folders())
    elif demisto.command() == 'ews-get-items':
        encode_and_submit_results(get_items())
    elif demisto.command() == 'ews-get-items-from-folder':
        encode_and_submit_results(get_items_from_folder())
    elif demisto.command() == 'ews-get-autodiscovery-config':
        encode_and_submit_results(get_autodiscovery_config())
    elif demisto.command() == 'ews-get-out-of-office':
        encode_and_submit_results(get_out_of_office_state())
    elif demisto.command() == 'ews-create-folder':
        encode_and_submit_results(create_folder(**args))
    elif demisto.command() == 'ews-delete-attachment':
        encode_and_submit_results(delete_attachments_for_message(**args))
    elif demisto.command() == 'ews-delete-items':
        encode_and_submit_results(delete_items(**args))
    elif demisto.command() == 'ews-mark-item-as-junk':
        encode_and_submit_results(mark_item_as_junk(**args))
    elif demisto.command() == 'ews-mark-items-as-read':
        encode_and_submit_results(mark_item_as_read(**args))
    elif demisto.command() == 'ews-move-item':
        encode_and_submit_results(move_item(**args))
    elif demisto.command() == 'ews-move-item-between-mailboxes':
        demisto.results("Item was moved successfully.")
    elif demisto.command() == 'ews-recover-messages':
        encode_and_submit_results(recover_soft_delete_item(**args))
    elif demisto.command() == 'ews-search-mailbox':
        encode_and_submit_results(get_items_from_folder())
    elif demisto.command() == 'ews-search-mailboxes':
        encode_and_submit_results(get_items_from_folder())
    elif demisto.command() == 'ews-get-attachment':
        encode_and_submit_results(fetch_attachments_for_message(**args))
    elif demisto.command() == 'ews-expand-group':
        encode_and_submit_results(get_expanded_group(**args))
    elif demisto.command() == 'ews-get-contacts':
        encode_and_submit_results(get_contacts(**args))
    elif demisto.command() == 'ews-get-items-as-eml':
        encode_and_submit_results(get_item_as_eml())
    elif demisto.command() == 'fetch-incidents':
        incidents = fetch_incidents()
        demisto.incidents(incidents)


except Exception as e:
    return_error('Unable to perform command : {}, Reason: {}'.format(demisto.command, e))

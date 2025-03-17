import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import mimetypes
import time

import dateutil.parser
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import *  # nopycln: import

# IMPORTS

"""Process Email attachments"""


def process_attachments(message, attachIDs="", attachNames=""):
    file_entries_for_attachments = []  # type: list
    attachments_names = []  # type: list

    if attachIDs:
        file_entries_for_attachments = attachIDs if isinstance(attachIDs, list) else attachIDs.split(",")
        if attachNames:
            attachments_names = attachNames if isinstance(attachNames, list) else attachNames.split(",")
        else:
            for att_id in file_entries_for_attachments:
                att_name = demisto.getFilePath(att_id)['name']
                if isinstance(att_name, list):
                    att_name = att_name[0]
                attachments_names.append(att_name)
        if len(file_entries_for_attachments) != len(attachments_names):
            raise Exception("attachIDs and attachNames lists should be the same length")

    for i in range(0, len(file_entries_for_attachments)):
        entry_id = file_entries_for_attachments[i]
        attachment_name = attachments_names[i]
        try:
            res = demisto.getFilePath(entry_id)
        except Exception as ex:
            raise Exception(f"entry {entry_id} does not contain a file: {str(ex)}")
        file_path = res["path"]
        with open(file_path, 'rb') as f:
            f_data = f.read()
        encoded_data = base64.b64encode(f_data).decode()
        file_type = mimetypes.guess_type(attachment_name)[0]
        message.attachment = Attachment(FileContent(encoded_data),  # type: ignore[name-defined]
                                        FileName(attachment_name),  # type: ignore[name-defined]
                                        FileType(file_type),  # type: ignore[name-defined]
                                        Disposition('attachment'))  # type: ignore[name-defined]
    return 'ok'


def test_module(sg):
    """test function
    Returns:
        ok if successful
    """
    try:
        sg.client.categories.get()
    except Exception as e:
        raise DemistoException(
            f"Test failed. Please check your parameters. \n {e}")
    return 'ok'


"""Retrieve an Email list based on the query"""


def get_email_activity_list(args: dict, sg):
    params = {}
    limit = args.get('limit')
    query = args.get('query')
    headers = args.get('headers')
    if limit:
        params['limit'] = int(limit)
    if query:
        params['query'] = query
    response = sg.client.messages.get(query_params=params)
    if response.status_code == 200:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        ec = {'Sendgrid.EmailList': body['messages']}
        if headers and isinstance(headers, str):
            headers = headers.split(",")
        md = tableToMarkdown('Email List: ', body['messages'], headers)
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': body,
            'HumanReadable': md,
            'EntryContext': ec
        }
    else:
        return 'Email list fetch is failed: ' + str(response.body)


"""Create a Batch ID"""


def create_batch_id(sg):
    response = sg.client.mail.batch.post()
    if response.status_code == 201:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        ec = {'Sendgrid.BatchId': body['batch_id']}
        md = tableToMarkdown('Batch Id: ', body)
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': body,
            'HumanReadable': md,
            'EntryContext': ec
        }
    else:
        return 'Batch ID creation failed: ' + str(response.body)


"""Cancel/Pause a scheduled send"""


def scheduled_send_status_change(args: dict, sg):
    batch_id = args.get('batch_id')
    status = args.get('status')
    data = {"batch_id": batch_id, 'status': status}

    response = sg.client.user.scheduled_sends.post(request_body=data)
    if response.status_code == 201:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        ec = {'Sendgrid.ScheduledSendStatus': body}
        md = tableToMarkdown('Scheduled status changed: ', body)
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': body,
            'HumanReadable': md,
            'EntryContext': ec
        }
    else:
        return 'scheduled send status change failed: ' + str(response.body)


"""Retrieve all scheduled sends"""


def retrieve_all_scheduled_sends(args: dict, sg):
    response = sg.client.user.scheduled_sends.get()
    if response.status_code == 200:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        if not body:
            return "No scheduled sends found"
        else:
            md = tableToMarkdown('List of Scheduled sends: ', body)
            ec = {'Sendgrid.ScheduledSends': body}
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': body,
                'HumanReadable': md,
                'EntryContext': ec
            }
    else:
        return 'Retrieval of scheduled sends list is failed: ' + str(response.body)


"""Retrieve scheduled send"""


def retrieve_scheduled_send(args: dict, sg):
    batch_id = args.get("batch_id")

    response = sg.client.user.scheduled_sends._(batch_id).get()
    if response.status_code == 200:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        if not body:
            return "No scheduled sends found for the given batch id"
        else:
            md = tableToMarkdown('List of Scheduled sends for a given Batch Id: ', body)
            ec = {'Sendgrid.ScheduledSend': body}
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': body,
                'HumanReadable': md,
                'EntryContext': ec
            }
    else:
        return 'Retrieval of scheduled sends for a given batch_id is failed ' + str(response.body)


"""Update the status of a scheduled send for the given batch_id"""


def update_scheduled_send(args: dict, sg):
    batch_id = args.get("batch_id")
    status = args.get('status')
    data = {'status': status}

    response = sg.client.user.scheduled_sends._(batch_id).patch(request_body=data)
    if response.status_code == 204:
        return 'Status of a scheduled send is updated'
    else:
        return 'Update the status of a scheduled send for the given batch_id is failed ' + str(response.body)


"""Delete the cancellation/pause of a scheduled send"""


def delete_scheduled_send(args: dict, sg):
    batch_id = args.get("batch_id")

    response = sg.client.user.scheduled_sends._(batch_id).delete()
    if response.status_code == 204:
        return 'scheduled send is deleted'
    else:
        return 'Delete of a scheduled send for the given batch_id is failed ' + str(response.body)


"""Get Global Email Stats"""


def get_global_email_stats(args: dict, sg):
    params = {}
    limit = args.get('limit')
    if limit:
        params['limit'] = int(limit)
    offset = args.get('offset')
    if offset:
        params['offset'] = int(offset)
    aggregated_by = args.get('aggregated_by')
    if aggregated_by:
        params['aggregated_by'] = aggregated_by
    start_date = args.get('start_date')
    if start_date:
        params['start_date'] = start_date
    end_date = args.get('end_date')
    if end_date:
        params['end_date'] = end_date
    headers = args.get('headers')

    response = sg.client.stats.get(query_params=params)
    if response.status_code == 200:
        rBody = response.body
        res_stats = json.loads(rBody.decode("utf-8"))
        mail_stats: list = []
        for day in res_stats:
            res = {}
            res['date'] = day['date']
            metrics = day['stats'][0]['metrics']
            res['blocks'] = metrics['blocks']
            res['bounce_drops'] = metrics['bounce_drops']
            res['bounces'] = metrics['bounces']
            res['clicks'] = metrics['clicks']
            res['deferred'] = metrics['deferred']
            res['delivered'] = metrics['delivered']
            res['invalid_emails'] = metrics['invalid_emails']
            res['opens'] = metrics['opens']
            res['processed'] = metrics['processed']
            res['requests'] = metrics['requests']
            res['spam_report_drops'] = metrics['spam_report_drops']
            res['spam_reports'] = metrics['spam_reports']
            res['unique_clicks'] = metrics['unique_clicks']
            res['unique_opens'] = metrics['unique_opens']
            res['unsubscribe_drops'] = metrics['unsubscribe_drops']
            res['unsubscribes'] = metrics['unsubscribes']
            mail_stats.append(res)

        if headers and isinstance(headers, str):
            headers = headers.split(",")
        md = tableToMarkdown("Global Email Statistics", mail_stats, headers)
        ec = {'Sendgrid.GlobalEmailStats': mail_stats}
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': mail_stats,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': md,
            'EntryContext': ec
        }
    else:
        return 'Global email stat retrieval error: ' + str(response.body)


"""Get Category Stats"""


def get_category_stats(args: dict, sg):
    params = {}
    limit = args.get('limit')
    if limit:
        params['limit'] = int(limit)
    offset = args.get('offset')
    if offset:
        params['offset'] = int(offset)
    aggregated_by = args.get('aggregated_by')
    if aggregated_by:
        params['aggregated_by'] = aggregated_by
    start_date = args.get('start_date')
    if start_date:
        params['start_date'] = start_date
    end_date = args.get('end_date')
    if end_date:
        params['end_date'] = end_date
    category = args.get('category')
    if category:
        params['categories'] = category
    headers = args.get('headers')

    response = sg.client.categories.stats.get(query_params=params)
    if response.status_code == 200:
        rBody = response.body
        res_stats = json.loads(rBody.decode("utf-8"))
        cat_stats: list = []
        for day in res_stats:
            res = {}
            res['date'] = day['date']
            res['category'] = day['stats'][0]['name']
            metrics = day['stats'][0]['metrics']
            res['blocks'] = metrics['blocks']
            res['bounce_drops'] = metrics['bounce_drops']
            res['bounces'] = metrics['bounces']
            res['clicks'] = metrics['clicks']
            res['deferred'] = metrics['deferred']
            res['delivered'] = metrics['delivered']
            res['invalid_emails'] = metrics['invalid_emails']
            res['opens'] = metrics['opens']
            res['processed'] = metrics['processed']
            res['requests'] = metrics['requests']
            res['spam_report_drops'] = metrics['spam_report_drops']
            res['spam_reports'] = metrics['spam_reports']
            res['unique_clicks'] = metrics['unique_clicks']
            res['unique_opens'] = metrics['unique_opens']
            res['unsubscribe_drops'] = metrics['unsubscribe_drops']
            res['unsubscribes'] = metrics['unsubscribes']
            cat_stats.append(res)

        if headers and isinstance(headers, str):
            headers = headers.split(",")
        md = tableToMarkdown("Statistics for the Category: " + res['category'], cat_stats, headers)
        ec = {'Sendgrid.CategoryStats': cat_stats}
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': cat_stats,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': md,
            'EntryContext': ec
        }
    else:
        return 'Category stat retrieval error: ' + str(response.body)


""" Sum of email statistics for all categories """


def get_all_categories_stats(args: dict, sg):
    params = {}
    limit = args.get('limit')
    if limit:
        params['limit'] = int(limit)
    offset = args.get('offset')
    if offset:
        params['offset'] = int(offset)
    aggregated_by = args.get('aggregated_by')
    if aggregated_by:
        params['aggregated_by'] = aggregated_by
    start_date = args.get('start_date')
    if start_date:
        params['start_date'] = start_date
    end_date = args.get('end_date')
    if end_date:
        params['end_date'] = end_date
    sort_by_direction = args.get('sort_by_direction')
    if sort_by_direction:
        params['sort_by_direction'] = sort_by_direction
    sort_by_metric = args.get('sort_by_metric')
    if sort_by_metric:
        params['sort_by_metric'] = sort_by_metric
    headers = args.get('headers')

    response = sg.client.categories.stats.sums.get(query_params=params)
    if response.status_code == 200:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        if not body['stats']:
            return "No Categories Statistics found for the given date range"
        else:
            res_stats = body['stats']
            cat_stats: list = []
            for category in res_stats:
                res = {}
                res['category'] = category['name']
                metrics = category['metrics']
                res['blocks'] = metrics['blocks']
                res['bounce_drops'] = metrics['bounce_drops']
                res['bounces'] = metrics['bounces']
                res['clicks'] = metrics['clicks']
                res['deferred'] = metrics['deferred']
                res['delivered'] = metrics['delivered']
                res['invalid_emails'] = metrics['invalid_emails']
                res['opens'] = metrics['opens']
                res['processed'] = metrics['processed']
                res['requests'] = metrics['requests']
                res['spam_report_drops'] = metrics['spam_report_drops']
                res['spam_reports'] = metrics['spam_reports']
                res['unique_clicks'] = metrics['unique_clicks']
                res['unique_opens'] = metrics['unique_opens']
                res['unsubscribe_drops'] = metrics['unsubscribe_drops']
                res['unsubscribes'] = metrics['unsubscribes']
                cat_stats.append(res)

            if headers and isinstance(headers, str):
                headers = headers.split(",")
            md = tableToMarkdown("Sum of All Categories Statistics from " + body['date'], cat_stats, headers)
            ec = {'Sendgrid.AllCategoriesStats': body}
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': body,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': md,
                'EntryContext': ec
            }
    else:
        return 'Categories stat retrieval error: ' + str(response.body)


""" List of categories """


def get_categories_list(args: dict, sg):
    params = {}
    limit = args.get('limit')
    if limit:
        params['limit'] = int(limit)
    offset = args.get('offset')
    if offset:
        params['offset'] = int(offset)
    category = args.get('category')
    if category:
        params['category'] = category

    response = sg.client.categories.get(query_params=params)
    if response.status_code == 200:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        if not body:
            return "No Categories found"
        else:
            md = tableToMarkdown("List of Categories", body, ['category'])
            ec = {'Sendgrid.CategoriesList': body}
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': body,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': md,
                'EntryContext': ec
            }
    else:
        return 'Categories list retrieval error: ' + str(response.body)


def send_mail(args: dict, sg_from_email: str, sg_sender_name: str, sg):
    message = Mail()  # type: ignore[name-defined]

    attach_ids = args.get('AttachIDs')
    attach_names = args.get('AttachNames') or ""

    if attach_ids:
        process_attachments(message, attach_ids, attach_names)

    categories = args.get('Categories')
    if categories:
        categories = categories.split(",")
        for category in categories:
            message.category = Category(category)  # type: ignore[name-defined]

    batch_id = args.get('BatchID')
    if batch_id:
        message.batch_id = BatchId(batch_id)  # type: ignore[name-defined]

    send_at = args.get('SendAt')
    if send_at:
        t = dateutil.parser.parse(send_at)
        send_time = time.mktime(t.timetuple())
        message.send_at = SendAt(int(send_time))  # type: ignore[name-defined]

    asm = args.get('Asm')
    if asm:
        asm = asm if type(asm) is dict else json.loads(asm)
        message.asm = Asm(GroupId(asm["group_id"]), GroupsToDisplay(asm["groups_to_display"]))  # type: ignore[name-defined]

    custom_args = args.get('CustomArgs')
    if custom_args:
        custom_args = custom_args if type(custom_args) is dict else json.loads(custom_args)
        for key in custom_args:
            message.custom_arg = CustomArg(key, custom_args[key])  # type: ignore[name-defined]

    ip_pool_name = args.get('IPPoolName')
    if ip_pool_name:
        message.ip_pool_name = IpPoolName(ip_pool_name)  # type: ignore[name-defined]

    # Mail Tracking settings
    tracking_settings = TrackingSettings()  # type: ignore[name-defined]
    click_tracking = args.get('ClickTracking')
    if click_tracking:
        click_tracking = click_tracking if type(click_tracking) is dict else json.loads(click_tracking)
        is_enable = click_tracking["enable"] != "False"
        tracking_settings.click_tracking = ClickTracking(is_enable,  # type: ignore[name-defined]
                                                         click_tracking["enable_text"])

    open_tracking = args.get('OpenTracking')
    if open_tracking:
        open_tracking = open_tracking if type(open_tracking) is dict else json.loads(open_tracking)
        is_enable = open_tracking["enable"] != "False"
        tracking_settings.open_tracking = OpenTracking(  # type: ignore[name-defined]
            is_enable,
            OpenTrackingSubstitutionTag(open_tracking["substitution_tag"]))  # type: ignore[name-defined]

    sub_tracking = args.get('SubscriptionTracking')
    if sub_tracking:
        sub_tracking = sub_tracking if type(sub_tracking) is dict else json.loads(sub_tracking)
        is_enable = sub_tracking["enable"] != "False"
        tracking_settings.subscription_tracking = SubscriptionTracking(  # type: ignore[name-defined]
            is_enable,
            SubscriptionText(sub_tracking["text"]),  # type: ignore[name-defined]
            SubscriptionHtml(sub_tracking["html"]),  # type: ignore[name-defined]
            SubscriptionSubstitutionTag(sub_tracking["substitution_tag"]))  # type: ignore[name-defined]

    ganalytics = args.get('GAnalytics')
    if ganalytics:
        ganalytics = ganalytics if type(ganalytics) is dict else json.loads(ganalytics)
        is_enable = ganalytics["enable"] != "False"
        tracking_settings.ganalytics = Ganalytics(  # type: ignore[name-defined]
            is_enable,
            UtmSource(ganalytics["utm_source"]),  # type: ignore[name-defined]
            UtmMedium(ganalytics["utm_medium"]),  # type: ignore[name-defined]
            UtmTerm(ganalytics["utm_term"]),  # type: ignore[name-defined]
            UtmContent(ganalytics["utm_content"]),  # type: ignore[name-defined]
            UtmCampaign(ganalytics["utm_campaign"]))  # type: ignore[name-defined]

    message.tracking_settings = tracking_settings

    # Mail Settings
    mail_settings = MailSettings()  # type: ignore[name-defined]
    bcc_mail_set = args.get('BccSettings')
    if bcc_mail_set:
        bcc_mail_set = bcc_mail_set if type(bcc_mail_set) is dict else json.loads(bcc_mail_set)
        is_enable = bcc_mail_set["enable"] != "False"
        mail_settings.bcc_settings = BccSettings(  # type: ignore[name-defined]
            is_enable,
            BccSettingsEmail(bcc_mail_set["email"]))  # type: ignore[name-defined]

    footer = args.get('Footer')
    if footer:
        footer = footer if type(footer) is dict else json.loads(footer)
        is_enable = footer["enable"] != "False"
        mail_settings.footer_settings = FooterSettings(  # type: ignore[name-defined]
            is_enable,
            FooterText(footer["text"]),  # type: ignore[name-defined]
            FooterHtml(footer["html"]))  # type: ignore[name-defined]

    spam_check = args.get('SpamCheck')
    if spam_check:
        spam_check = spam_check if type(spam_check) is dict else json.loads(spam_check)
        is_enable = spam_check["enable"] != "False"
        mail_settings.spam_check = SpamCheck(  # type: ignore[name-defined]
            is_enable,
            SpamThreshold(spam_check["threshold"]),  # type: ignore[name-defined]
            SpamUrl(spam_check["post_to_url"]))  # type: ignore[name-defined]

    sandbox_mode = args.get('SandboxMode')
    if sandbox_mode:
        sandbox_mode = sandbox_mode != "False"
        mail_settings.sandbox_mode = SandBoxMode(sandbox_mode)  # type: ignore[name-defined]

    bypass_list_management = args.get('BypassListManagement')
    if bypass_list_management:
        bypass_list_management = bypass_list_management != "False"
        mail_settings.bypass_list_management = BypassListManagement(bypass_list_management)  # type: ignore[name-defined]

    message.mail_settings = mail_settings

    headers = args.get('Headers')
    if headers:
        headers = headers if type(headers) is dict else json.loads(headers)
        for key in headers:
            message.header = Header(key, headers[key])  # type: ignore[name-defined]

    template_id = args.get('TemplateID')
    if template_id:
        message.template_id = TemplateId(template_id)  # type: ignore[name-defined]

    subject = args.get('Subject')
    message.subject = Subject(subject)  # type: ignore[name-defined]

    email_body = args.get('HtmlBody')
    if email_body:
        message.content = Content(MimeType.html, email_body)  # type: ignore[name-defined]

    raw_body = args.get('RawBody')
    if raw_body:
        message.content = Content(MimeType.text, raw_body)  # type: ignore[name-defined]

    reply_to_email = args.get('ReplyTo')
    if reply_to_email:
        message.reply_to = ReplyTo(reply_to_email, None)  # type: ignore[name-defined]

    message.from_email = From(sg_from_email, sg_sender_name)  # type: ignore[name-defined]

    to_emails = args.get('ToEmails')
    to_emails = to_emails if isinstance(to_emails, list) else to_emails.split(",")  # type: ignore[union-attr]
    for email in to_emails:
        message.to = To(email, None, p=0)  # type: ignore[name-defined]

    cc_emails = args.get('Cc')
    if cc_emails:
        cc_emails = cc_emails if isinstance(cc_emails, list) else cc_emails.split(",")
        for email in cc_emails:
            message.cc = Cc(email, None, p=0)  # type: ignore[name-defined]

    bcc_emails = args.get('Bcc')
    if bcc_emails:
        bcc_emails = bcc_emails if isinstance(bcc_emails, list) else bcc_emails.split(",")
        for email in bcc_emails:
            message.bcc = Bcc(email, None, p=0)  # type: ignore[name-defined]

    response = sg.send(message)
    if response.status_code == 202:
        return "Email Sent successfully"
    else:
        return "Failed to send email " + response.status_code


def get_all_lists(args: dict, sg):
    params = {}
    pageSize = args.get('page_size')
    if pageSize:
        params['page_size'] = int(pageSize)
    pageToken = args.get('page_token')
    if pageToken:
        params['page_token'] = pageToken
    headers = args.get('headers')

    response = sg.client.marketing.lists.get(query_params=params)
    if response.status_code == 200:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        ec = {'Sendgrid.Lists.Result': body['result'], 'Sendgrid.Lists.Metadata': body['_metadata']}
        if headers and isinstance(headers, str):
            headers = headers.split(",")
        md = tableToMarkdown('Lists information was fetched successfully: ', body['result'], headers)
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': body,
            'HumanReadable': md,
            'EntryContext': ec
        }
    else:
        return 'Failed to fetch lists information: ' + str(response.body)


def get_list_by_id(args: dict, sg):
    listID = args.get('list_id')
    params = {}
    contactSample = args.get('contact_sample')
    if contactSample:
        params['contact_sample'] = contactSample != "False"

    response = sg.client.marketing.lists._(listID).get(query_params=params)
    if response.status_code == 200:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        ec = {'Sendgrid.List': body}
        md = tableToMarkdown('List details ', body)
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': body,
            'HumanReadable': md,
            'EntryContext': ec
        }
    else:
        return 'Failed to retrieve list information: ' + str(response.body)


def create_list(args: dict, sg):
    listName = args.get('list_name')
    data = {"name": listName}

    response = sg.client.marketing.lists.post(request_body=data)
    if response.status_code == 201:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        ec = {'Sendgrid.NewList': body}
        md = tableToMarkdown('New List has been successfully created ', body)
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': body,
            'HumanReadable': md,
            'EntryContext': ec
        }
    else:
        return 'Failed to create new list: ' + str(response.body)


def get_list_contact_count_by_id(args: dict, sg):
    listID = args.get('list_id')
    response = sg.client.marketing.lists._(listID).contacts.count.get()
    if response.status_code == 200:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        ec = {'Sendgrid.ListCount': body}
        md = tableToMarkdown('List contact count details ', body)
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': body,
            'HumanReadable': md,
            'EntryContext': ec
        }
    else:
        return 'Failed to retrieve contact list count information: ' + str(response.body)


def update_list_name(args: dict, sg):
    listID = args.get('list_id')
    listName = args.get('updated_list_name')
    data = {"name": listName}

    response = sg.client.marketing.lists._(listID).patch(request_body=data)
    if response.status_code == 200:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        ec = {'Sendgrid.updatedList': body}
        md = tableToMarkdown('List Name has been updated successfully ', body)
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': body,
            'HumanReadable': md,
            'EntryContext': ec
        }
    else:
        return 'Failed to update list name: ' + str(response.body)


def delete_list(args: dict, sg):
    listID = args.get('list_id')
    params = {}
    deleteContacts = args.get('delete_contacts')
    if deleteContacts:
        params['delete_contacts'] = deleteContacts != "False"

    response = sg.client.marketing.lists._(listID).delete(query_params=params)
    if response.status_code == 200:
        rBody = response.body
        body = json.loads(rBody.decode("utf-8"))
        ec = {'Sendgrid.DeleteListJobId': body['job_id']}
        md = tableToMarkdown('The delete has been accepted and is processing. \
                You can check the status using the Job ID: ', body['job_id'])
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': body,
            'HumanReadable': md,
            'EntryContext': ec
        }
    elif response.status_code == 204:
        return 'Deletion completed successfully'
    else:
        return 'Failed to delete list: ' + str(response.body)


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    sg_api_key = demisto.params().get('apiKey')
    sg_from_email = demisto.params().get('fromEmail')
    sg_sender_name = demisto.params().get('fromEmailName')

    try:
        # Passing the API key
        sg = SendGridAPIClient(api_key=sg_api_key)

        command = demisto.command()
        args = demisto.args()
        result = ""

        if command == 'test-module':
            result = test_module(sg)

        elif demisto.command() == 'sg-send-email':
            result = send_mail(args, sg_from_email, sg_sender_name, sg)

        elif demisto.command() == 'sg-get-global-email-stats':
            result = get_global_email_stats(args, sg)

        elif demisto.command() == 'sg-get-category-stats':
            result = get_category_stats(args, sg)

        elif demisto.command() == 'sg-get-all-categories-stats':
            result = get_all_categories_stats(args, sg)

        elif demisto.command() == 'sg-list-categories':
            result = get_categories_list(args, sg)

        elif demisto.command() == 'sg-create-batch-id':
            result = create_batch_id(sg)

        elif demisto.command() == 'sg-scheduled-status-change':
            result = scheduled_send_status_change(args, sg)

        elif demisto.command() == 'sg-retrieve-all-scheduled-sends':
            result = retrieve_all_scheduled_sends(args, sg)

        elif demisto.command() == 'sg-retrieve-scheduled-send':
            result = retrieve_scheduled_send(args, sg)

        elif demisto.command() == 'sg-update-scheduled-send':
            result = update_scheduled_send(args, sg)

        elif demisto.command() == 'sg-delete-scheduled-send':
            result = delete_scheduled_send(args, sg)

        elif demisto.command() == 'sg-get-email-activity-list':
            result = get_email_activity_list(args, sg)

        elif demisto.command() == 'sg-get-all-lists':
            result = get_all_lists(args, sg)

        elif demisto.command() == 'sg-get-list-by-id':
            result = get_list_by_id(args, sg)

        elif demisto.command() == 'sg-create-list':
            result = create_list(args, sg)

        elif demisto.command() == 'sg-get-list-contact-count-by-id':
            result = get_list_contact_count_by_id(args, sg)

        elif demisto.command() == 'sg-update-list-name':
            result = update_list_name(args, sg)

        elif demisto.command() == 'sg-delete-list':
            result = delete_list(args, sg)

        demisto.results(result)

    # Log exceptions
    except Exception as e:
        if repr(e) == "KeyError('email')":
            return_error(f"Failed to execute {demisto.command()} command. Please provide a valid email.")
        else:
            return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', 'builtins'):
    main()

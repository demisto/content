from itertools import count
import re
import json
import demistomock as demisto

IMG_EXTENSION = [".png",".img",".jpg",".jpeg",".gif"]

# Get Entry ID of the attachment file from war room entries search result
def get_attachment_id(attachment_name, file_entries):
    if file_entries:
        for file_entry in reversed(file_entries):
            if file_entry.get('File') == attachment_name:
                return file_entry.get('ID')
        return ''
    else:
        return ''


# Create attachment URL to embed in HTML code of the attachment
def get_attachment_url(entry_id):
    url = demisto.demistoUrls().get('server')
    url += "/entry/download/"
    url += entry_id.replace("@","%40")
    return url


# Create normal files and image files list from the war room entries search result
def get_files_list(file_entries):
    normal_file_list = []
    img_list = []
    if file_entries:
        for file_entry in file_entries:
            if all(x not in file_entry.get('File') for x in IMG_EXTENSION):
                normal_file_list.append(file_entry)
            else:
                img_list.append(file_entry)
    return normal_file_list, img_list


# Count new images in the received email
def count_new_img(email_thread):
    new_email = email_thread.split('<b>From:</b>')
    img_tags = re.findall("<img[^>]+>", new_email[1]) if len(new_email) >= 2 else []
    return len(img_tags)


# Add URL to <a> tag of the attachment name to make it downloadable
# Add URL to <img> tag of the image to display it to the layout
def convert_attachment_name_to_url(email_thread):
    file_entries = demisto.executeCommand("getEntries", {'filter': {'categories': ["attachments"]}})
    attachment_str = re.findall("(?<=<\/p>Attachments: \[)[^\]]+(?=\])",email_thread)
    img_count = count_new_img(email_thread)
    normal_file_list, img_list = get_files_list(file_entries)  # Create separate list for normal files and images
    ahref_list = []
    imgsrc_list = []
    # Get attachment name and generate url
    if attachment_str:
        attachments = attachment_str[0].replace("&#39;","").split(', ')
        if normal_file_list:
            # Loop to get attachment URLs
            for attachment in attachments:
                if all(x not in attachment for x in IMG_EXTENSION):
                    entry_id = get_attachment_id(attachment, normal_file_list)
                    url = get_attachment_url(entry_id)
                    ahref_list.append(f'<a href="{url}">{attachment}</a>')
            # Replace attachment name with a href tag
            if ahref_list:
                ahref_str = "<br>" + "<br>".join(ahref_list)
                place_ahref = re.sub("(?<=<\/p>Attachments: \[)[^\]]+(?=\])",ahref_str,email_thread,1)
                remove_bracket = re.sub("(Attachments: \[)","Attachments:",place_ahref,1)
                email_thread = remove_bracket
        if img_list:
            # Loop to get image URLs
            for attachment in attachments:
                if any(x in attachment for x in IMG_EXTENSION):
                    entry_id = get_attachment_id(attachment, img_list)
                    url = get_attachment_url(entry_id)
                    imgsrc_list.append(f'<img src={url}>')
                    #img_list.pop(-1)
            # Replace img tag with img src
            if imgsrc_list:
                len_src_list = len(imgsrc_list)
                if len_src_list > img_count:
                    for i in range(0,len_src_list - img_count):
                        first_item = imgsrc_list[0]
                        imgsrc_list.append(first_item) 
                        imgsrc_list.pop(0)
                img_tags = re.findall("<img[^>]+>", email_thread)               
                if img_tags:
                    for i, img_tag in enumerate(img_tags, start=0): email_thread = email_thread.replace(img_tag,imgsrc_list[i],1) \
                        if i <= len(imgsrc_list) - 1 else email_thread
    # Return new HTML code with URL for attachments and images
    return email_thread

# Deprecated
#def get_email_entry_id(last_email_id,incident_id):
#    email_id = str(int(re.findall("^\d+",last_email_id)[0])+1)
#    return(f"{email_id}@{incident_id}")


# Build email thread by append old emails in <blockquote> to the new email
# It will then display as a thread in the layout
def build_email_thread(emails):
    email_thread = convert_attachment_name_to_url(emails[-1]['Contents'])
    if len(emails) > 1:
        email_thread += "<hr><hr><hr>"
        emails.pop(-1)
        for email in reversed(emails):
            email_thread += '<br><br><blockquote style="margin:0px 0px 0px 0.8ex;border-left:2px solid rgb(204,204,204);padding-left:1ex;">'
            email_thread += email['Contents']
        for email in reversed(emails):
            email_thread += '</blockquote>'
    return(email_thread)


# Generate email topic from email subject input
# It must not contains [.] character because it affect the context key save
def generate_email_topic(email_subject):
    email_topic = email_subject.replace(".","[dot]").replace(" ","_") if email_subject \
        else ""
    return email_topic


def main():
    # User select topic from the dropdown list of topics field
    selected_topic = generate_email_topic(demisto.args().get('new'))

    # Email metadata is stored under EmailCommunication context key
    email_context = demisto.context().get('EmailCommunication')
    ctx = email_context.get(selected_topic) if email_context else None
    # View email content
    emails = demisto.executeCommand("getEntries", {'filter': {'tags': [selected_topic]}})
    # Prepare title of the email thread
    title_topic = demisto.args().get('new')
    title_html = "<h2>" + title_topic + "</h2><br>"

    if emails:
        if ctx:
            email_thread = build_email_thread(emails)[0]
            email_display = {
                "emailthreadhtml": re.sub('>\W+<','><', title_html + email_thread),
                "emailto": ctx.get('to'),
                "emailcc": ctx.get('cc'),
                "emailsubject": ctx.get('subject'),
                "emailentryid": emails[-1]['ID'],
                "emailbcc": ctx.get('bcc','')
            }
            if ctx.get('team'):
                email_display["emailteam"] = ctx.get('team')
            # set value to the email fields to display it to the layout
            # and to use it when user wants to send another email
            result = demisto.executeCommand("setIncident", email_display)

            # with_attachment is a tag for incoming email which is stored in War room
            # that has attachments. This check for tag and also Attachments word in the first 400 chars
            if "with_attachment" not in emails[-1]['Tags'] and "</p>Attachments:" in email_thread[0:400]:
                # Remove tag from the last email entry and tag again with the new thread after generate and modify attachment
                demisto.executeCommand("resetEntriesTags", {"entryIDs": emails[-1]['ID']})
                entries_str = json.dumps([{"Type": 1, "ContentsFormat": 'html', "Contents": email_thread, "tags": [selected_topic, "with_attachment"]}])
                demisto.executeCommand("addEntries", {"entries": entries_str})
            return result

        else:
            demisto.results("No data for this topic found")
            return None

    else:
        demisto.results("No data for this topic found")
        return None


if __name__ in ("__main__","__builtin__","builtins"):
    main()
import re
strSenderRegex = r".*From\w*:.*\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
strTargetRegex = r".*To\w*:.*\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"

body = demisto.incidents()[0]['details']
demisto.setContext('emailBody', body)

fromLines = re.match(strSenderRegex, body, re.I)
if fromLines:
    # Use the last "From" line found
    sender = fromLines[-1].group(1)
    demisto.setContext('emailOriginalSender', sender)

toLines = re.match(strSenderRegex, body, re.I)
if toLines:
    # Use the last "From" line found
    sender = fromLines[-1].group(1)
    demisto.setContext('emailOriginalSender', sender)
var toRE = /<b>To:.*href="mailto:(.*)"/ig;
var to = toRE.exec(body);
var sentRE = /<b>Sent:<\/b> (.*)<br>/ig;
var sent = sentRE.exec(body);
var subjectRE = /<b>Subject:<\/b> (.*)<o:p>/ig;
var subject = subjectRE.exec(body);
return {Contents: {From: from[1], To: to[1], Sent: sent[1], Subject: subject[1]}, ContentsFormat: formats.table, Type: entryTypes.note};

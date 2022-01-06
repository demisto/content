import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

context = demisto.context()
found_incidents = context["foundIncidents"]
# incidentbucket={"Red":[],"Orange":[],"Purple":[],"Maroon":[],"Olive":[],"Blue":[]}
incidentbucket = {"Red": [], "Orange": [], "Purple": [], "Blue": []}
# print(found_incidents)
# print(type(found_incidents))

if isinstance(found_incidents, list):
    for inc in found_incidents:

        temp_dict = {}
        temp_dict[inc["id"]] = "https://sandma.demisto.live/#/Custom/caseinfoid/" + inc["id"]

        containsladuedate = inc['CustomFields']['containsla']['dueDate']
        # print(containsladuedate)
        if containsladuedate == "0001-01-01T00:00:00Z":
            containsladuedate = "2021-00-01T01:03:27.456384423Z"
            containsladuedate = containsladuedate.split(".")[0]
        else:
            containsladuedate = containsladuedate.split(".")[0]

        resolutionsladuedate = inc['CustomFields']['resolutionsla']['dueDate']
        if resolutionsladuedate == "0001-01-01T00:00:00Z":
            resolutionsladuedate = "2021-09-01T01:03:27.456384423Z"
            resolutionsladuedate = resolutionsladuedate.split(".")[0]
        else:
            resolutionsladuedate = resolutionsladuedate.split(".")[0]

        containsladuedatedt = datetime.datetime.strptime(containsladuedate, "%Y-%m-%dT%H:%M:%S")
        resolutionsladuedatedt = datetime.datetime.strptime(resolutionsladuedate, "%Y-%m-%dT%H:%M:%S")

        timenow = datetime.datetime.utcnow()

        containbreach = -1
        resolutionbreach = -1
        if not timenow > containsladuedatedt:
            containbreach = round((containsladuedatedt - timenow).seconds / 60)
            print(containbreach)
        if not timenow > resolutionsladuedatedt:
            resolutionbreach = round((resolutionsladuedatedt - timenow).seconds / 60)
        breachedtimer = ""
        breachedtimername = ""

        if resolutionbreach < containbreach and resolutionbreach != -1:
            breachedtimer = resolutionbreach
            breachedtimername = "Resolution"
        elif containbreach == -1:
            breachedtimer = resolutionbreach
            breachedtimername = "Resolution"
        else:
            breachedtimer = containbreach
            breachedtimername = "Containment"
        #print("Contain-timenow"+str(containsladuedatedt)+" "+str(timenow))
        #print("Resolution-timenow"+str(resolutionsladuedatedt)+" "+str(timenow))
        # print(str(breachedtimer)+" "+breachedtimername+" "+inc["id"])

        if breachedtimer <= 30:
            incidentbucket["Red"].append(temp_dict)
        elif breachedtimer <= 45:
            incidentbucket["Orange"].append(temp_dict)
        elif breachedtimer <= 60:
            incidentbucket["Purple"].append(temp_dict)
        else:
            incidentbucket["Blue"].append(temp_dict)

    demisto.results({'Type': entryTypes['note'],
                     'Contents': incidentbucket,
                     'ContentsFormat': formats['json'],
                     'ReadableContentsFormat': formats['markdown'],
                     'EntryContext': {"Notification_bucket": incidentbucket}})


else:
    temp_dict = {}
    temp_dict[found_incidents["id"]] = "https://sandma.demisto.live/#/Custom/caseinfoid/" + found_incidents["id"]
    containsladuedate = found_incidents['CustomFields']['containsla']['dueDate']
    if containsladuedate == "0001-01-01T00:00:00Z":
        containsladuedate = "2021-00-01T01:03:27.456384423Z"
        containsladuedate = containsladuedate.split(".")[0]
    else:
        containsladuedate = containsladuedate.split(".")[0]

    resolutionsladuedate = found_incidents['CustomFields']['resolutionsla']['dueDate']
    if resolutionsladuedate == "0001-01-01T00:00:00Z":
        resolutionsladuedate = "2021-00-01T01:03:27.456384423Z"
        resolutionsladuedate = resolutionsladuedate.split(".")[0]
    else:
        resolutionsladuedate = resolutionsladuedate.split(".")[0]

    containsladuedatedt = datetime.datetime.strptime(containsladuedate, "%Y-%m-%dT%H:%M:%S")
    # print(resolutionsladuedate)

    resolutionsladuedatedt = datetime.datetime.strptime(resolutionsladuedate, "%Y-%m-%dT%H:%M:%S")
    # print(resolutionsladuedatedt)

    timenow = datetime.datetime.utcnow()

    containbreach = -1
    resolutionbreach = -1
    if not timenow > containsladuedatedt:
        containbreach = round((containsladuedatedt - timenow).seconds / 60)
    if not timenow > resolutionsladuedatedt:
        resolutionbreach = round((resolutionsladuedatedt - timenow).seconds / 60)
    breachedtimer = ""
    breachedtimername = ""

    if resolutionbreach < containbreach and resolutionbreach != -1:
        breachedtimer = resolutionbreach
        breachedtimername = "Resolution"
    elif containbreach == -1:
        breachedtimer = resolutionbreach
        breachedtimername = "Resolution"
    else:
        breachedtimer = containbreach
        breachedtimername = "Containment"
    #print("Contain-timenow"+str(containsladuedatedt)+" "+str(timenow))
    #print("Resolution-timenow"+str(resolutionsladuedatedt)+" "+str(timenow))
    # print(str(breachedtimer)+" "+breachedtimername+" "+found_incidents["id"])

    if breachedtimer <= 15:
        incidentbucket["Red"].append(temp_dict)
    elif breachedtimer <= 30:
        incidentbucket["Orange"].append(temp_dict)
    elif breachedtimer <= 45:
        incidentbucket["Purple"].append(temp_dict)
    else:
        incidentbucket["Blue"].append(temp_dict)

# print(incidentbucket)


demisto.results({'Type': entryTypes['note'],
                 'Contents': incidentbucket,
                 'ContentsFormat': formats['json'],
                 'ReadableContentsFormat': formats['markdown'],
                 'EntryContext': {"Notification_bucket": incidentbucket}})

# 'EntryContext' : {"test":{"Notification_bucket":incidentbucket}}})


# Finding length of the longest list in dictionary=incidentbucket
length = 0
for key, value in incidentbucket.items():
    if len(incidentbucket[key]) >= length:
        length = len(incidentbucket[key])
    # target = { 123 : None, 125 : None }
    # incidentbucket[key]=(str(incidentbucket[key]).translate(target))


# Creating list of lists
a = [[] for _ in range(length)]


# Putting list values inside incidentbucket to a
j = -1
for list in range(len(a)):
    j = j + 1
    print(a)
    print(j)
    for key, value in incidentbucket.items():
        print(key)
        if (j > (len(incidentbucket[key]) - 1) or len(incidentbucket[key]) == 0):
            a[list].append("None")
        else:
            target = {123: None, 125: None, 39: None}
            a[list].append(str(incidentbucket[key][j]).translate(target))
            # a[list].append(incidentbucket[key][j])
            print(a)

print(a)


html_1 = '<html lang="en" dir="ltr"> <head> <meta charset="utf-8"> <style> table,tr,th, td{ border: 2px solid black; border-collapse:collapse; text-align: center;padding: 2px; } </style></head> <body>'
html_1 += '<p style="color:black">The Following Incidents Will Breach in Less than 1 Hour:</p>'
html_1 += '<body><table "width:100px"; "table-layout:fixed"; overflow-y: hidden;>'
html_1 += '<thead><tr><th colspan="4"><b>Conagra SLA Risk Time</b></th></tr></thead>'
html_1 += '<thead><tr><th bgcolor="Red">15 Min</th><th bgcolor="Orange">30 Min</th><th bgcolor="Yellow">45 Min</th><th bgcolor="Green">60 Min</th></tr></thead>'

for list in a:
    html_1 += f'</tr><tr>'
    for number in list:
        html_1 += '<td>' + str(number) + '</td>'

html_1 += f'</tr>'
html_1 += '</table><br><br>'


html_4 = f'<tr style="text-align:center"><b><u>Legends</u></b></tr>'


#html_2='<html lang="en" dir="ltr"> <head> <meta charset="utf-8"> <style> table, tr,th, td{ "border: 1px solid black; border-collapse:collapse; padding: 2px; text-align: center;table-layout: fixed; width:10px" } </style></head> <body>'
html_2 = '<table "width:30%";border: 2px solid black; border-collapse:collapse><tr><th><b>SLA Risk Time</b></th></tr><tr> <td style="text-align:center" bgcolor="Red">15 Min</td></tr><tr><td style="text-align:center" bgcolor="Orange">30 Min</td></tr><tr><td style="text-align:center" bgcolor="Yellow">45 Min</td></tr><tr><td style="text-align:center" bgcolor="Green">60 Min</td></tr></table></body>'


html_3 = html_1 + html_4 + html_2
demisto.results(demisto.setContext("html1", html_3))

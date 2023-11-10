import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import re

#arrayToNotification function takes as a argument list of notification then performs an operation to the turn notification list to human readable format to report customer.
def arrayToNotification (notificationList):
    if len(notificationList) == 1 :
         return(notificationList[0] + " sonucu alarm oluşmuştur. İlgili aktivite bilginiz dahilinde midir ?")
    elif len(notificationList) == 2:
         seperator= " ve "
         return(seperator.join(notificationList)+ " sonucu alarm oluşmuştur. İlgili aktiviteler bilginiz dahilinde midir ?")
    counter = 0
    notificationString = ""
    for notification in notificationList:
        counter= counter + 1
        if counter == len(notificationList):
            notificationString = notificationString + notification + " ve "
        else:
            notificationString= notificationString + notification + ", "
    return (notificationString + " sonucu alarm oluşmuştur. İlgili aktiviteler bilginiz dahilinde midir ?")

# checkMachineOrUser function checks the account name is machine whether actual user account by checking the $ sign which is indicator of machine account.
def checkMachineOrUser (account):
    if account[-1] == "$":
        result="makine"

    else:
        result="kullanıcı"
    return (result)

# eventMapper function takes as argument EventID and utf8payload then performs action to create list of notification element each time by loop over events due to event id to produce notification string .
def eventMapper(eventID, utf8payload):
    accountName=re.findall("Account Name:\s+([^\s]+)",utf8_payload)
    groupNameList=re.findall("Group Name:\s+(.*?)(?=\s*Group Domain:)",utf8_payload)
    computerNameList=re.findall("Computer=([^\t]+)",utf8_payload)
    domainNameList= re.findall("Account Domain:\s*(.*?)\s+Logon ID:",utf8_payload)
    hostname = computerNameList[0]
    hostIpAddress= computerNameList[1]
    domainName=domainNameList[0]
    if accountName != [] : #Since the fields are mapped to the index right before if conditions , sometimes accountName has a single field on specified events. So
         saccountName=accountName[0]
         try:
              taccountName=accountName[1]
         except:
             taccountName =""

    else:
        saccountName=""
        taccountName=""
    if groupNameList !=[] :
        groupName = groupNameList[0]
    else:
        groupName =""
#affected event ID's [4722,4725,4720,4741,4727,4758,4730,4734,4726,4743,4740]
    if eventID == "EventID=4722":
        notificationString= hostname + " hostunda " +  hostIpAddress + " IP adresinde " + saccountName + " kullanıcısı tarafından " +  domainName + " domaininde " + taccountName + " " + checkMachineOrUser(taccountName) + " hesabının enable edilmesi"
    elif eventID =="EventID=4725":
        notificationString= hostname + " hostunda " +  hostIpAddress + " IP adresinde " + saccountName + " kullanıcısı tarafından " + domainName + " domaininde " + taccountName + " " + checkMachineOrUser(taccountName) + " hesabının disable edilmesi"
    elif eventID =="EventID=4720" or eventID == "EventID=4741" :
        notificationString= hostname + " hostunda " +  hostIpAddress + " IP adresinde " + saccountName + " kullanıcısı tarafından " + domainName +  " domaininde " + taccountName + " " + checkMachineOrUser(taccountName) + " hesabının oluşturulması "
    elif eventID =="EventID=4727":
        notificationString=hostname + " hostunda " +  hostIpAddress + " IP adresinde " + saccountName + " kullanıcısı tarafından " + domainName + " domaininde " + taccountName + " grubunun oluşturulması "
    elif eventID == "EventID=4758" or eventID == "EventID=4730" or eventID == "EventID=4734":
        notificationString=hostname + " hostunda " +  hostIpAddress + " IP adresinde " + saccountName + " kullanıcısı tarafından " + domainName + " domaininde " + groupName + " grubunun silinmesi "
    elif eventID == "EventID=4726" or eventID =="EventID=4743":
        notificationString=hostname + " hostunda " +  hostIpAddress + " IP adresinde " + saccountName + " kullanıcısı tarafından " + domainName + " domaininde " + taccountName + " " + checkMachineOrUser(taccountName) + " hesabının silinmesi "
    elif eventID == "EventID=4740":
        notificationString=hostname + " hostunda " + hostIpAddress + " IP adresinde " + taccountName + " kullanıcısının " + domainName + " domaininde " + "kilitlenmesi "
    else:
        notificationString=" There is no match in event id mapper"
    return (notificationString)

a=demisto.get(demisto.args(), 'qradarevents') #to take qradarevents as a input which is mandotory input selected from script settings.
#b={"categoryname_category":"User Account Changed","categoryname_highlevelcategory":"Authentication","credibility":5,"destinationgeographiclocation":"other","destinationip":"10.2.1.6","destinationport":0,"destinationv6":"0:0:0:0:0:0:0:0","devicetime":"2023-10-12T08:38:34+00:00","eventDirection":"L2L","eventcount":1,"logsourcename_logsourceid":"YSLSRV26 @ 10.2.1.6","logsourcetypename_devicetype":"Microsoft Windows Security Event Log","magnitude":3,"postNatDestinationIP":"0.0.0.0","postNatDestinationPort":0,"postNatSourceIP":"0.0.0.0","postNatSourcePort":0,"preNatDestinationPort":0,"preNatSourceIP":"0.0.0.0","preNatSourcePort":0,"protocolname_protocolid":"Reserved","qiddescription_qid":"Success Audit: A user account was enabled.","qidname_qid":"Success Audit: A user account was enabled","rulename_creEventList":["BB:DeviceDefinition: Operating System","DT0038 - AD User Account Creation|Activation","BB:UBA : Common Log Source Filters","BB:UBA : Common Event Filters"],"severity":1,"sourceMAC":"00:00:00:00:00:00","sourcegeographiclocation":"other","sourceip":"10.2.1.6","sourceport":0,"sourcev6":"0:0:0:0:0:0:0:0","starttime":"2023-10-12T08:38:38.142000+00:00","username":"ozanda","utf8_payload":"\u003c13\u003eOct 12 11:38:36 10.2.1.6 AgentDevice=WindowsLog\tAgentLogFile=Security\tPluginVersion=7.3.1.22\tSource=Microsoft-Windows-Security-Auditing\tComputer=YSLSRV26.yesilova.lc\tOriginatingComputer=10.2.1.6\tUser=\tDomain=\tEventID=4722\tEventIDCode=4722\tEventType=8\tEventCategory=13824\tRecordNumber=1083057677\tTimeGenerated=1697099914\tTimeWritten=1697099914\tLevel=Log Always\tKeywords=Audit Success\tTask=SE_ADT_ACCOUNTMANAGEMENT_USERACCOUNT\tOpcode=Info\tMessage=A user account was enabled.  Subject:  Security ID:  YESILOVA\\ozanda  Account Name:  ozanda  Account Domain:  YESILOVA  Logon ID:  0x863B4110D  Target Account:  Security ID:  YESILOVA\\CANMETALNB47$  Account Name:  CANMETALNB47$  Account Domain:  YESILOVA\n"},{"categoryname_category":"User Account Added","categoryname_highlevelcategory":"Authentication","credibility":10,"destinationgeographiclocation":"other","destinationip":"10.2.1.6","destinationport":0,"destinationv6":"0:0:0:0:0:0:0:0","devicetime":"2023-10-12T08:38:38.578000+00:00","eventDirection":"L2L","eventcount":1,"logsourcename_logsourceid":"Custom Rule Engine-8 :: qradar","logsourcetypename_devicetype":"Custom Rule Engine","magnitude":8,"postNatDestinationIP":"0.0.0.0","postNatDestinationPort":0,"postNatSourceIP":"0.0.0.0","postNatSourcePort":0,"preNatDestinationPort":0,"preNatSourceIP":"0.0.0.0","preNatSourcePort":0,"protocolname_protocolid":"Reserved","qiddescription_qid":"Event ID:4720 \"A user account was created\" \r\nEvent ID:4722 \"A user account was enabled\" \r\n\r\nEvent'leri oluştuğunda alarm üretilir. Sistem yöneticisine bildirilmelidir.","qidname_qid":"DT0038 - AD User Account Creation|Activation","rulename_creEventList":["DT0038 - AD User Account Creation|Activation","BB:UBA : User Account Created"],"severity":5,"sourceMAC":"00:00:00:00:00:00","sourcegeographiclocation":"other","sourceip":"10.2.1.6","sourceport":0,"sourcev6":"0:0:0:0:0:0:0:0","starttime":"2023-10-12T08:38:38.578000+00:00","username":"ozanda","utf8_payload":"\u003c13\u003eOct 12 11:38:36 10.2.1.6 AgentDevice=WindowsLog\tAgentLogFile=Security\tPluginVersion=7.3.1.22\tSource=Microsoft-Windows-Security-Auditing\tComputer=YSLSRV26.yesilova.lc\tOriginatingComputer=10.2.1.6\tUser=\tDomain=\tEventID=4722\tEventIDCode=4722\tEventType=8\tEventCategory=13824\tRecordNumber=1083057677\tTimeGenerated=1697099914\tTimeWritten=1697099914\tLevel=Log Always\tKeywords=Audit Success\tTask=SE_ADT_ACCOUNTMANAGEMENT_USERACCOUNT\tOpcode=Info\tMessage=A user account was enabled.  Subject:  Security ID:  YESILOVA\\ozanda  Account Name:  ozanda  Account Domain:  YESILOVA  Logon ID:  0x863B4110D  Target Account:  Security ID:  YESILOVA\\CANMETALNB47$  Account Name:  CANMETALNB47$  Account Domain:  YESILOVA\n"}
b=json.loads(a) # load json to create dictionary format to access fields.


notificationList=[]
l1noteslist =""
for events in b:
  utf8_payload=events["utf8_payload"]
  eventID= re.findall("EventID=\d+",utf8_payload)
  if eventID != [] :
    notificationString = eventMapper(eventID[0], utf8_payload)
    notificationList.append(notificationString)
    #l1noteslist += notificationString + '\n'


notificationList=list(dict.fromkeys(notificationList)) # deletes the duplicated notification because sometimes soar duplicates the single events as double to the qradarevents field. To prevent it duplicated elements has been deleted.
l1noteslist = arrayToNotification(notificationList) # l1noteslist last form of notification to report customer.
totalresult={'L1NotebyScript':l1noteslist}
result=CommandResults(outputs=totalresult)
return_results(result)





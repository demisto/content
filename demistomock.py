
import json

integrationContext = {}

exampleIncidents = [{"Brand":"Builtin","Category":"Builtin","Contents":{"data":[{"CustomFields":{},"account":"","activated":"0001-01-01T00:00:00Z","attachment":None,"autime":1550670443962164000,"canvases":None,"category":"","closeNotes":"","closeReason":"","closed":"0001-01-01T00:00:00Z","closingUserId":"","created":"2019-02-20T15:47:23.962164+02:00","details":"","droppedCount":0,"dueDate":"2019-03-02T15:47:23.962164+02:00","hasRole":False,"id":"1","investigationId":"1","isPlayground":False,"labels":[{"type":"Instance","value":"test"},{"type":"Brand","value":"Manual"}],"lastOpen":"0001-01-01T00:00:00Z","linkedCount":0,"linkedIncidents":None,"modified":"2019-02-20T15:47:27.158969+02:00","name":"1","notifyTime":"2019-02-20T15:47:27.156966+02:00","occurred":"2019-02-20T15:47:23.962163+02:00","openDuration":0,"owner":"analyst","parent":"","phase":"","playbookId":"playbook0","previousRoles":None,"rawCategory":"","rawCloseReason":"","rawJSON":"","rawName":"1","rawPhase":"","rawType":"Unclassified","reason":"","reminder":"0001-01-01T00:00:00Z","roles":None,"runStatus":"waiting","severity":0,"sla":0,"sourceBrand":"Manual","sourceInstance":"amichay","status":1,"type":"Unclassified","version":6}],"total":1},"ContentsFormat":"json","EntryContext":None,"Evidence":False,"EvidenceID":"","File":"","FileID":"","FileMetadata":None,"HumanReadable":None,"ID":"","IgnoreAutoExtract":False,"ImportantEntryContext":None,"Metadata":{"brand":"Builtin","category":"","contents":"","contentsSize":0,"created":"2019-02-24T09:44:51.992682+02:00","cronView":False,"endingDate":"0001-01-01T00:00:00Z","entryTask":None,"errorSource":"","file":"","fileID":"","fileMetadata":None,"format":"json","hasRole":False,"id":"","instance":"Builtin","investigationId":"7ab2ac46-4142-4af8-8cbe-538efb4e63d6","modified":"0001-01-01T00:00:00Z","note":False,"parentContent":"!getIncidents query=\"id:1\"","parentEntryTruncated":False,"parentId":"111@7ab2ac46-4142-4af8-8cbe-538efb4e63d6","pinned":False,"playbookId":"","previousRoles":None,"recurrent":False,"reputationSize":0,"reputations":None,"roles":None,"scheduled":False,"startDate":"0001-01-01T00:00:00Z","system":"","tags":None,"tagsRaw":None,"taskId":"","times":0,"timezoneOffset":0,"type":1,"user":"","version":0},"ModuleName":"InnerServicesModule","Note":False,"ReadableContentsFormat":"","System":"","Tags":None,"Type":1,"Version":0}]
exampleContext = [{"Brand":"Builtin","Category":"Builtin","Contents":{"context":{},"id":"1","importantKeys":None,"modified":"2019-02-24T09:50:21.798306+02:00","version":30},"ContentsFormat":"json","EntryContext":None,"Evidence":False,"EvidenceID":"","File":"","FileID":"","FileMetadata":None,"HumanReadable":None,"ID":"","IgnoreAutoExtract":False,"ImportantEntryContext":None,"Metadata":{"brand":"Builtin","category":"","contents":"","contentsSize":0,"created":"2019-02-24T09:50:28.652202+02:00","cronView":False,"endingDate":"0001-01-01T00:00:00Z","entryTask":None,"errorSource":"","file":"","fileID":"","fileMetadata":None,"format":"json","hasRole":False,"id":"","instance":"Builtin","investigationId":"7ab2ac46-4142-4af8-8cbe-538efb4e63d6","modified":"0001-01-01T00:00:00Z","note":False,"parentContent":"!getContext id=\"1\"","parentEntryTruncated":False,"parentId":"120@7ab2ac46-4142-4af8-8cbe-538efb4e63d6","pinned":False,"playbookId":"","previousRoles":None,"recurrent":False,"reputationSize":0,"reputations":None,"roles":None,"scheduled":False,"startDate":"0001-01-01T00:00:00Z","system":"","tags":None,"tagsRaw":None,"taskId":"","times":0,"timezoneOffset":0,"type":0,"user":"","version":0},"ModuleName":"InnerServicesModule","Note":False,"ReadableContentsFormat":"","System":"","Tags":None,"Type":0,"Version":0}]
exampleUsers = [{"Brand":"Builtin","Category":"Builtin","Contents":[{"accUser":False,"addedSharedDashboards":None,"canPostTicket":False,"dashboards":None,"defaultAdmin":True,"disableHyperSearch":False,"editorStyle":"","email":"admintest@demisto.com","helpSnippetDisabled":False,"homepage":"","id":"admin","image":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJAAAACQCAYAAADnRuK4AAAACXBIWXMAABYlAAAWJQFJUiTwAAAFeElEQVR42u2dO1MbVxSAj2whIZAQHlWksSrcwKAMVWjYNLhiRjOkSYXyC7z5BfE/iNKmYWlchRnNyE2oRKO0y5DGaiI3pokcbRYNelopCDNOeGmlXS269/v6BcH9dPace+4jMhwOhwIwJk/4FwACAQIBAgECASAQIBAgECAQAAIBAgECAQIBIBAgECAQIBAAAgECAQIBAgECASAQIBAgECAQAAIBAgECAQIBIBAEQfSxfJBK74NY7ZrYg4ac9huMzD1sRDOSj2XFTKzLciQW6meJhH3AlN1viNmqyknvHDM8ko7E5PXCppiJdT0Fsto1+e6iggkTsh9fFStl6JUDIY9/HHZqUrw80ycC2f2GGE5ZnGGX0feRP559K9mnKfUjkNmqIk8AFNvTj0JTF8juN0iYA6LUqasvkNV5x0gHxPtPF1P/nVOfB7IfmONJR2JSWtoRY+6LmR/QgluRw05NaWmnHoEeen1ZKWPm5WkOu1rIE0oEeoh8LDvz8hhOWZvZdHphyINAyINAyEMOpCe6z6oTgZCHCCRy1Zy1Ou9uTBNsz61IIf5CCvOryINAN6kPXMm7x3fmHye9cznpnUuxfSal1I4vzUbkUeQVVh+4kmsejZS8nvYbkmseSX3gThzpvmweIY8KAuXdY08D6Qy7knePJ5KHNUyKCGS1a2OVzaf9hljtGvJoL9AEXX2vzyKPgkn0JGuKvDxrtqry0+XvmKJiDjQNkAeBAIEAgXxme24llGdBEYEK8RehPAuqCDS/KhvRjOfnNqIZ3/tiCDSjlFI7kvZwuEA6EpNSaodRR6Arsk9TYi/vjRSJNqIZsZf3pr5zE4FmRKKDpHFrcrw9tyIHSQN5AkKZ9UCF+VVyGyIQIBAgEAACAQIBAgECASAQIBAg0AiUunVGBYHu5qHFXAW3IpXeB0ZmRph6LywXzdy7K8IZduVr5y0jQwS6I8KwGjAw0iFcvDJ1gXLRDGuSAyKMw0lDSaKLi1uhfFtUx0ys6SFQLpqR4uIWI+4j+/FVfSKQyNUCsIOkwcj7wEY0I8VkOF9ILpybcV4l1kKN5qELdA1XXo7O8ydJycezYs6vh77O+9EI9FiJ/PnzxK+XSno39LtNlcuBdEls7eU9ZeUR4ZzowDhIGlrsEkEgn1HpuioECqGc9usoYXIgDfOdSnpXu92vRCAf+GFhU14vbGr5tyPQhPmOlTJm/pI8BAqB50+SUlp6KbkxzihCIM3ZnluR0tJLped3SKID4lViTemZZSJQgOgyOYhAASTLlfSu9vkOAnmkOewq3wydFLrxQBINCAQIBAikCXa/IdmPb8a6ufAhrHZNsh/fiK3JslztkujmsCu5v36R958uRETkx8WvxEys+/Kzi5dn8n3rNxG5anXYz75RvnrTSqDmsCuGU76xaH8/vipWypjoZxfcihx2/hvRdJgC0OoVZl5Ub93xcdipieGUpTnGVd7XUv5fHpGrC37Niyo5kBLytKq3DvI1J71zMZyyp3vl6wNXDKd87562w05NzJa6EmnxCvNy6/KobQu73xDDKY98b72qfTQtIlAumhn5MAfn31fSfRWa1a55kicdiSnbR9Mmia4PXMm7x552vd5WoX1eaY2C6gvttavC8n//6mkf/ucV2m2V1n3osPBMy2bqOCJcJ9rjiKcy2nbjvb6KvODn5CQCPfLqzGxVR06GR0mWi4tbWq1a1H49kNdyfNLyH4Go0LSrtBAooApNl0oLgQKq0HSptBAogApNp0oLgXys0HSstBDIpwqN/WEINHaFJiLaVloI5EOFJiJsLkQg8Bu29QACAQIBAgECASAQIBAgECAQAAIBAgECAQIBIBAgECAQIBAAAgECAQLBLPMPFxalhUpzvrEAAAAASUVORK5CYII=","investigationPage":"","lastLogin":"0001-01-01T00:00:00Z","name":"Admin Dude","notify":["mattermost","email","slack"],"phone":"+650-123456","playgroundCleared":False,"playgroundId":"818df1a9-98dc-46df-84dc-dbd2fffc0fda","preferences":{"userPreferencesIncidentTableQueries":{"Open Jobs in the last 7 days":{"picker":{"predefinedRange":{"id":"7","name":"Last 7 days"}},"query":"-status:closed category:job"},"Open incidents in the last 7 days":{"isDefault":True,"picker":{"predefinedRange":{"id":"7","name":"Last 7 days"}},"query":"-status:closed -category:job"}},"userPreferencesWarRoomFilter":{"categories":["chats","incidentInfo","commandAndResults","notes"],"fromTime":"0001-01-01T00:00:00Z","pageSize":0,"tagsAndOperator":False,"usersAndOperator":False},"userPreferencesWarRoomFilterExpanded":False,"userPreferencesWarRoomFilterMap":{"Chats only":{"categories":["chats"],"fromTime":"0001-01-01T00:00:00Z","pageSize":0,"tagsAndOperator":False,"usersAndOperator":False},"Default Filter":{"categories":["chats","incidentInfo","commandAndResults","notes"],"fromTime":"0001-01-01T00:00:00Z","pageSize":0,"tagsAndOperator":False,"usersAndOperator":False},"Playbook results":{"categories":["playbookTaskResult","playbookErrors","justFound"],"fromTime":"0001-01-01T00:00:00Z","pageSize":0,"tagsAndOperator":False,"usersAndOperator":False}},"userPreferencesWarRoomFilterOpen":True},"roles":{"demisto":["Administrator"]},"theme":"","username":"admin","wasAssigned":False}],"ContentsFormat":"json","EntryContext":{"DemistoUsers":[{"email":"admintest@demisto.com","name":"Admin Dude","phone":"+650-123456","roles":["demisto: [Administrator]"],"username":"admin"}]},"Evidence":False,"EvidenceID":"","File":"","FileID":"","FileMetadata":None,"HumanReadable":"## Users\nUsername|Email|Name|Phone|Roles\n-|-|-|-|-\nadmin|admintest@demisto.com|Admin Dude|\\+650-123456|demisto: \\[Administrator\\]\n","ID":"","IgnoreAutoExtract":False,"ImportantEntryContext":None,"Metadata":{"brand":"Builtin","category":"","contents":"","contentsSize":0,"created":"2019-02-24T09:50:28.686449+02:00","cronView":False,"endingDate":"0001-01-01T00:00:00Z","entryTask":None,"errorSource":"","file":"","fileID":"","fileMetadata":None,"format":"json","hasRole":False,"id":"","instance":"Builtin","investigationId":"7ab2ac46-4142-4af8-8cbe-538efb4e63d6","modified":"0001-01-01T00:00:00Z","note":False,"parentContent":"!getUsers online=\"False\"","parentEntryTruncated":False,"parentId":"120@7ab2ac46-4142-4af8-8cbe-538efb4e63d6","pinned":False,"playbookId":"","previousRoles":None,"recurrent":False,"reputationSize":0,"reputations":None,"roles":None,"scheduled":False,"startDate":"0001-01-01T00:00:00Z","system":"","tags":None,"tagsRaw":None,"taskId":"","times":0,"timezoneOffset":0,"type":1,"user":"","version":0},"ModuleName":"InnerServicesModule","Note":False,"ReadableContentsFormat":"","System":"","Tags":None,"Type":1,"Version":0}]
exampleDemistoUrls = {"evidenceBoard":"https://test-address:8443/#/EvidenceBoard/7ab2ac46-4142-4af8-8cbe-538efb4e63d6","investigation":"https://test-address:8443/#/Details/7ab2ac46-4142-4af8-8cbe-538efb4e63d6","relatedIncidents":"https://test-address:8443/#/Cluster/7ab2ac46-4142-4af8-8cbe-538efb4e63d6","server":"https://test-address:8443","warRoom":"https://test-address:8443/#/WarRoom/7ab2ac46-4142-4af8-8cbe-538efb4e63d6","workPlan":"https://test-address:8443/#/WorkPlan/7ab2ac46-4142-4af8-8cbe-538efb4e63d6"}

def params():
    return {}


def args():
    return {}


def command():
    return ""


def log(msg):
    print(msg)


def get(obj, field):
    """ Get the field from the given dict using dot notation """
    parts = field.split('.')
    for part in parts:
        if obj and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


def context():
    return {}


def uniqueFile():
    return '4fa3f70d-2d5d-4482-ab73-43dc24063a18'


def getLastRun():
    return {'lastRun': "2018-10-24T14:13:20+00:00"}


def setLastRun(obj):
    return None


def info(*args):
    log(args)


def error(*args):
    log(args)


def debug(*args):
    log(args)


def results(results):
    if type(results) is dict and results.get("contents"):
        results = results.get("contents")
    print("demisto results: {}".format(json.dumps(results, indent=4, sort_keys=True)))


def credentials(credentials):
    print("credentials: {}".format(credentials))


def getFilePath(entry_id):
    return ""


def investigation():
    return {'id': '1'}


def executeCommand(command, args):
    commands = {
        "getIncidents": exampleIncidents,
        "getContext": exampleContext,
        "getUsers": exampleUsers
    }
    if commands.get(command):
        return commands.get(command)

    return ""


def getParam(param):
    return params().get(param)


def getArg(arg):
    return args().get(arg)


def setIntegrationContext(context):
    global integrationContext
    integrationContext = context


def getIntegrationContext():
    return integrationContext


def incidents(incidents):
    return results({'Type': 1, 'Contents': json.dumps(incidents), 'ContentsFormat': 'json'})


def setContext(contextPath, value):
    return {"status": True}

def demistoUrls():
    return exampleDemistoUrls

def appendContext(key, data, dedup=False):
    return None

def dt(obj=None, trnsfrm=None):
    return ""

def addEntry(id, entry, username=None, email=None, footer=None):
    return ""

def mirrorInvestigation(id, mirrorType, autoClose=False):
    return ""

def updateModuleHealth(error):
    return ""

def directMessage(message, username = None, email = None, anyoneCanOpenIncidents = None):
    return ""

def createIncidents(incidents, lastRun = None):
    return []

def findUser(username, email):
    return {}


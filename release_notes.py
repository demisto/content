import abc
import datetime
import json
import sys
import yaml

from Tests.test_utils import print_error

contentLibPath = "./"
limitedVersion = False

LAYOUT_TYPE_TO_NAME = {
    "details": "Summary",
    "edit": "New/Edit",
    "close": "Close",
}


class Content:
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        self.modifiedStore = []
        self.addedStore = []
        self.deletedStore = []

    def add(self, changeType, data):
        if changeType == "M":
            self.modifiedStore.append(data)
        elif changeType == "A":
            self.addedStore.append(data)
        elif changeType == "D":
            self.deletedStore.append(data)
        else:
            print "Unknown change type " + changeType

    @abc.abstractmethod
    def getHeader(self):
        return

    @abc.abstractmethod
    def addedReleaseNotes(self, data):
        return

    @abc.abstractmethod
    def modifiedReleaseNotes(self, data):
        return

    @abc.abstractmethod
    def loadData(self, data):
        return

    def generateRN(self):
        res = ""
        missingReleaseNotes = False

        if len(self.modifiedStore) + len(self.deletedStore) + len(self.addedStore) > 0:
            section_body = ""
            if len(self.addedStore) > 0:
                newStr = ""
                new_count = 0
                for rawContent in self.addedStore:
                    cnt = self.loadData(rawContent)

                    ans = self.addedReleaseNotes(cnt)
                    if ans is None:
                        print_error(cnt["name"] + " is missing releaseNotes entry")
                        missingReleaseNotes = True

                    if ans:
                        new_count += 1
                    newStr += ans

                if len(newStr) > 0:
                    if new_count > 1:
                        section_body += "\n#### " + str(new_count) + " New " + self.getHeader() + "\n"
                    else:
                        section_body += "\n#### New " + self.getHeader() + "\n"
                    section_body += newStr
            if len(self.modifiedStore) > 0:
                modifiedStr = ""
                modified_count = 0
                for rawContent in self.modifiedStore:
                    cnt = self.loadData(rawContent)
                    ans = self.modifiedReleaseNotes(cnt)
                    if ans is None:
                        print_error(cnt["name"] + " is missing releaseNotes entry")
                        missingReleaseNotes = True
                    elif ans is not "":
                        modifiedStr += ans
                        modified_count += 1
                if len(modifiedStr) > 0:
                    if modified_count > 1:
                        section_body += "\n#### " + str(modified_count) + " Improved " + self.getHeader() + "\n"
                    else:
                        section_body += "\n#### Improved " + self.getHeader() + "\n"
                    section_body += modifiedStr
            if len(self.deletedStore) > 0:
                section_body += "\n#### Removed " + self.getHeader() + "\n"
                for rawContent in self.deletedStore:
                    section_body += "- " + rawContent + "\n"

            if missingReleaseNotes:
                return None
            if len(section_body) > 0:
                res = "### " + self.getHeader() + "\n"
                res += section_body

        return res


class ScriptContent(Content):

    def loadData(self, data):
        return yaml.safe_load(data)

    def getHeader(self):
        return "Scripts"

    def addedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) > 0 and rn == "-":
            return ""
        res =  "- " + cnt["name"] + "\n"
        if cnt.get("comment") is not None and len(cnt.get("comment")) > 0:
            res += "-- " + cnt["comment"] + "\n"
        return res

    def modifiedReleaseNotes(self,cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            return None
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res =  "- " + cnt["name"] + "\n"
            res += "-- " + cnt["releaseNotes"] + "\n"
        return res


Content.register(ScriptContent)


class PlaybookContent(Content):
    def loadData(self, data):
        return yaml.safe_load(data)

    def getHeader(self):
        return "Playbooks"

    def addedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) > 0 and rn == "-":
            return ""
        res = "- " + cnt["name"] + "\n"
        if cnt.get("description") is not None and len(cnt.get("description")) > 0:
            res += "-- " + cnt["description"] + "\n"
        return res

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            return None
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res =  "- " + cnt["name"] + "\n"
            res += "-- " + cnt["releaseNotes"] + "\n"
        return res


Content.register(PlaybookContent)


class ReportContent(Content):
    def loadData(self, data):
        return json.loads(data)

    def getHeader(self):
        return "Reports"

    def addedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) > 0 and rn == "-":
            return ""
        res = "- " + cnt["name"] + "\n"
        if cnt.get("description") is not None and len(cnt.get("description")) > 0:
            res += "-- " + cnt["description"] + "\n"
        return res

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            return None
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res =  "- " + cnt["name"] + "\n"
            res += "-- " + cnt["releaseNotes"] + "\n"
        return res


Content.register(ReportContent)


class DashboardContent(Content):
    def loadData(self, data):
        return json.loads(data)

    def getHeader(self):
        return "Dashboards"

    def addedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) > 0 and rn == "-":
            return ""
        res = "- " + cnt["name"] + "\n"
        if cnt.get("description") is not None and len(cnt.get("description")) > 0:
            res += "-- " + cnt["description"] + "\n"
        return res

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            return None
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res =  "- " + cnt["name"] + "\n"
            res += "-- " + rn + "\n"
        return res


Content.register(DashboardContent)


class WidgetContent(Content):
    def loadData(self, data):
        return json.loads(data)

    def getHeader(self):
        return "Widgets"

    def addedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) > 0 and rn == "-":
            return ""
        res = "- " + cnt["name"] + "\n"
        if cnt.get("description") is not None and len(cnt.get("description")) > 0:
            res += "-- " + cnt["description"] + "\n"
        return res

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            return None
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res =  "- " + cnt["name"] + "\n"
            res += "-- " + rn + "\n"
        return res


Content.register(WidgetContent)


class IncidentFieldContent(Content):
    def loadData(self, data):
        return json.loads(data)

    def getHeader(self):
        return "Incident Fields"

    def addedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            return None
        res = ""

        if rn != '-':
            res += "- " + cnt["releaseNotes"] + "\n"
        return res

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            return None
        res = ""

        if rn != '-':
            res += "- " + cnt["releaseNotes"] + "\n"
        return res


Content.register(IncidentFieldContent)


class LayoutContent(Content):
    def loadData(self, data):
        return json.loads(data)

    def getHeader(self):
        return "Incident Layouts"

    def getReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")

        layout_kind = LAYOUT_TYPE_TO_NAME.get(cnt.get("kind", ""))
        if not layout_kind:
            print_error("invalid layout kind %s" % (cnt.get("kind", ""),))
            return None

        layout_type = cnt.get("typeId")
        if not layout_type:
            print_error("invalid layout kind %s" % (layout_type,))
            return None

        return "- " + layout_type + " - " + layout_kind + "\n" + "-- " + rn + "\n"

    def addedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            return None

        return self.getReleaseNotes(cnt)

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")

        if len(rn) == 0:
            return None

        if rn == "-":
            return ""

        return self.getReleaseNotes(cnt)


Content.register(LayoutContent)


class ClassifierContent(Content):
    def loadData(self, data):
        return json.loads(data)

    def getHeader(self):
        return "Classification & Mapping"

    def getReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        brand_name = cnt.get("brandName")
        if not brand_name:
            print_error("invalid classifier brand name %s" % (brand_name,))
            return None

        return "- " + brand_name + "\n" + "-- " + rn + "\n"

    def addedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            return None

        return self.getReleaseNotes(cnt)

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")

        if len(rn) == 0:
            return None

        if rn == "-":
            return ""

        return self.getReleaseNotes(cnt)


Content.register(ClassifierContent)


class ReputationContent(Content):
    def loadData(self, data):
        return json.loads(data)

    def getHeader(self):
        return "Reputations"

    def addedReleaseNotes(self, cnt):
        #This should never happen
        return ""

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            return None
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res += "- " + cnt["releaseNotes"] + "\n"
        return res


Content.register(ReputationContent)


class IntegrationContent(Content):
    def loadData(self, data):
        return yaml.safe_load(data)

    def getHeader(self):
        return "Integrations"

    def addedReleaseNotes(self, cnt):
        res =  "- " + cnt["name"] + "\n"
        if cnt.get("description") is not None and len(cnt.get("description")) > 0:
            res += "-- " + cnt["description"] + "\n"
        return res

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            return None
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res =  "- " + cnt["name"] + "\n"
            res += "-- " + cnt["releaseNotes"] + "\n"
        return res


Content.register(IntegrationContent)


releaseNoteGenerator = {
    "Integrations": IntegrationContent(),
    "Scripts": ScriptContent(),
    "Playbooks": PlaybookContent(),
    "Reports": ReportContent(),
    "Dashboards": DashboardContent(),
    "Widgets": WidgetContent(),
    "IncidentFields": IncidentFieldContent(),
    "Layouts": LayoutContent(),
    "Classifiers": ClassifierContent(),
    "Misc": ReputationContent()
}


def parseChangeList(filePath):
    with open(filePath, 'r') as f:
        data = f.read()
        return data.split("\n")
    return []


def getDeletedContent(fullFileName, data):
    startIndex = data.find(fullFileName)
    if startIndex > 0:
        nameIndex = data.find("-name:", startIndex)
        if nameIndex > 0:
            return data[nameIndex:].split("\n")[0][len("-name:"):].strip()
    return ""


def handleDeletedFiles(deleteFilePath, fullFileName):
    with open(deleteFilePath, 'r') as f:
        data = f.read()
        if "/" in fullFileName:
            fileType = fullFileName.split("/")[0]
            fileTypeMapping = releaseNoteGenerator.get(fileType)
            deletedContent = getDeletedContent(fullFileName, data)
            if fileTypeMapping is not None:
                fileTypeMapping.add("D", deletedContent)


def createFileReleaseNotes(fileName, deleteFilePath):
    if len(fileName) > 0:
        names = fileName.split("\t")
        changeType = names[0]
        fullFileName = names[1]

        if not "/" in fullFileName:
            return

        fileType = fullFileName.split("/")[0]
        fileTypeMapping = releaseNoteGenerator.get(fileType)
        if fileTypeMapping is None:
            print "Unsupported file type " + fileType
            return

        if changeType == "D":
            handleDeletedFiles(deleteFilePath, fullFileName)
        elif changeType != "R100" and changeType != "R094":
            if changeType == "R093" or changeType == "R098" or changeType == "R078":
                # handle the same as modified
                fullFileName = names[2]
                changeType = 'M'

            with open(contentLibPath + fullFileName, 'r') as f:
                data = f.read()
                fileTypeMapping.add(changeType, data)


def createContentDescriptor(version, assetId, res):
    #time format example 2017 - 06 - 11T15:25:57.0 + 00:00
    date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.0+00:00")
    release_notes = "## Demisto Content Release Notes for version " + version + " (" + assetId + ")\n"
    release_notes += "##### Published on %s\n%s" % (datetime.datetime.now().strftime("%d %B %Y"), res)
    contentDescriptor = {
        "installDate": "0001-01-01T00:00:00Z",
        "assetId": int(assetId),
        "releaseNotes": release_notes,
        "modified": date,
        "ignoreGit": False,
        "releaseDate": date,
        "version": -1,
        "release": version,
        "id": ""
    }
    with open('content-descriptor.json', 'w') as outfile:
        json.dump(contentDescriptor, outfile)

    with open('release-notes.txt', 'w') as outfile:
        outfile.write(release_notes)


def main(argv):
    if len(argv) < 4:
        print "<Release version>, <File with the full list of changes>, <Complete diff file for deleted files>, <assetID>"
        sys.exit(1)
    files = parseChangeList(argv[1])

    for file in files:
        createFileReleaseNotes(file, argv[2])

    res = ""
    missingReleaseNotes = False
    for key, value in releaseNoteGenerator.iteritems():
        if len(res) > 0:
            res += "\n\n"
        ans = value.generateRN()
        if ans is None:
            missingReleaseNotes = True
        else:
            res += ans
    if missingReleaseNotes == True:
        sys.exit(1)
    version = argv[0]
    assetId = argv[3]
    createContentDescriptor(version, assetId, res)


if __name__ == "__main__":
   main(sys.argv[1:])

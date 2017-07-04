import yaml
import json
import sys
import abc
import datetime

contentLibPath = "./"
limitedVersion = False

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
            print "Unkown change type " + changeType

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
        if len(self.modifiedStore) + len(self.deletedStore) + len(self.addedStore) > 0:
            res = "### " + self.getHeader() +"\n"
            if len(self.addedStore) > 0 :
                newStr = ""
                for rawContent in self.addedStore:
                    cnt = self.loadData(rawContent)
                    newStr += self.addedReleaseNotes(cnt)
                if len(newStr) > 0:
                    res += "#### New " + self.getHeader() + "\n"
                    res += newStr
            if len(self.modifiedStore) > 0 :
                modifiedStr = ""
                for rawContent in self.modifiedStore:
                    cnt = self.loadData(rawContent)
                    modifiedStr += self.modifiedReleaseNotes(cnt)
                if len(modifiedStr) > 0:
                    res += "#### Modified " + self.getHeader() + "\n"
                    res += modifiedStr
            if len(self.deletedStore) > 0 :
                res += "#### Removed " +  self.getHeader() +  "\n"
                for rawContent in self.deletedStore:
                    res += "- " + rawContent + "\n"
        return res


class ScriptContent(Content):

    def loadData(self, data):
        return yaml.load(data)

    def getHeader(self):
        return "Scripts"

    def addedReleaseNotes(self,cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) > 0 and rn == "-":
            return ""
        res =  "- " + cnt["name"] + "\n"
        if len(cnt.get("comment")) > 0:
            res += "-- " + cnt["comment"] + "\n"
        return res

    def modifiedReleaseNotes(self,cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            raise Exception(cnt["name"] + " missing release notes yml entry")
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res =  "- " + cnt["name"] + "\n"
            res += "-- " + cnt["releaseNotes"] + "\n"
        return res

Content.register(ScriptContent)


class PlaybookContent(Content):
    def loadData(self, data):
        return yaml.load(data)

    def getHeader(self):
        return "Playbooks"

    def addedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) > 0 and rn == "-":
            return ""
        res = "- " + cnt["name"] + "\n"
        if len(cnt.get("description")) > 0:
            res += "-- " + cnt["description"] + "\n"
        return res

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            raise Exception(cnt["name"] + "missing release notes yml entry")
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res =  "- " + cnt["name"] + "\n"
            res += "-- " + cnt["releaseNotes"] + "\n"
        return res

Content.register(PlaybookContent)


class ReportContent(Content):
    def loadData(self, data):
        return json.load(data)

    def getHeader(self):
        return "Reports"

    def addedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) > 0 and rn == "-":
            return ""
        res = "- " + cnt["name"] + "\n"
        if len(cnt.get("description")) > 0:
            res += "-- " + cnt["description"] + "\n"
        return res

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            raise Exception(cnt["name"] + "missing release notes yml entry")
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res =  "- " + cnt["name"] + "\n"
            res += "-- " + cnt["releaseNotes"] + "\n"
        return res

Content.register(ReportContent)


class ReputationContent(Content):
    def loadData(self, data):
        return json.load(data)

    def getHeader(self):
        return "Hypersearch"

    def addedReleaseNotes(self, cnt):
        #This should never happen
        return ""

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            raise Exception(cnt["details"] + "missing release notes yml entry")
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res =  "- " + cnt["details"] + "\n"
            res += "-- " + cnt["releaseNotes"] + "\n"
        return res

Content.register(ReputationContent)


class IntegrationContent(Content):
    def loadData(self, data):
        return yaml.load(data)

    def getHeader(self):
        return "Integrations"

    def addedReleaseNotes(self, cnt):
        res =  "- " + cnt["name"] + "\n"
        if len(cnt.get("description")) > 0:
            res += "-- " + cnt["description"] + "\n"
        return res

    def modifiedReleaseNotes(self, cnt):
        rn = cnt.get("releaseNotes", "")
        if len(rn) == 0:
            raise Exception(cnt["name"] + "missing release notes yml entry")
        res = ""
        #Add a comment only if there are release notes
        if rn != '-':
            res =  "- " + cnt["name"] + "\n"
            res += "-- " + cnt["releaseNotes"] + "\n"
        return res

Content.register(IntegrationContent)


releaseNoteGenerator = {
    "Scripts": ScriptContent(),
    "Integrations": IntegrationContent(),
    "Playbooks": PlaybookContent(),
    "Reports": ReportContent(),
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
        if changeType == "D":
            handleDeletedFiles(deleteFilePath, fullFileName)
        elif changeType != "R100":
            with open(contentLibPath + fullFileName, 'r') as f:
                data = f.read()
                if "/" in fullFileName:
                    fileType = fullFileName.split("/")[0]
                    fileTypeMapping = releaseNoteGenerator.get(fileType)
                    if fileTypeMapping is not None:
                        fileTypeMapping.add(changeType, data)

def createContentDescriptor(version, assetId, res):
    #time format example 2017 - 06 - 11T15:25:57.0 + 00:00
    date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.0+00:00")
    contentDescriptor = {
        "installDate": "0001-01-01T00:00:00Z",
        "assetId": int(assetId),
        "releaseNotes": "## Release Notes for version " + version + " (" + assetId + ")" + "\n\n" + res,
        "modified": date,
        "ignoreGit": False,
        "releaseDate": date,
        "version": -1,
        "release": version,
        "id": ""
    }
    with open('content-descriptor.json', 'w') as outfile:
        json.dump(contentDescriptor, outfile)


def main(argv):
    if len(argv) < 4:
        print "<Release version>, <File with the full list of changes>, <Complete diff file for deleted files>, <assetID>"
        sys.exit(1)
    files = parseChangeList(argv[1])

    for file in files:
        createFileReleaseNotes(file, argv[2])

    res = ""
    for key, value in releaseNoteGenerator.iteritems():
        if len(res) > 0:
            res += "\n\n"
        res += value.generateRN()
    version = argv[0]
    assetId = argv[3]
    createContentDescriptor(version, assetId, res)


if __name__ == "__main__":
   main(sys.argv[1:])
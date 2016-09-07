import urllib2
DELTAAVV_INI_URL = "http://update.nai.com/products/commonupdater/gdeltaavv.ini"
# Another option is to use avvdat.ini - provided here in case any additional data from that file is needed in the future
#AVVDAT_INI_URL = "http://update.nai.com/Products/CommonUpdater/avvdat.ini"

iniText = '<Could not fetch INI>'
latestDATVersion = None
try:
    iniText = urllib2.urlopen(DELTAAVV_INI_URL).read()
    contentsSection = [section for section in iniText.split('\r\n\r\n') if section.startswith('[Contents]\r\n')][0]
    demisto.log('** Extracted Contents section:\n' + contentsSection + '\n')
    latestDATVersion = [line.split('=')[1] for line in contentsSection.split('\r\n') if line.startswith('CurrentVersion=')][0]
    demisto.log('** Website ini reports latest available DAT version ' + latestDATVersion)
    demisto.setContext('latestdat', latestDATVersion)
except Exception as ex:
    demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                "Contents": "Error occurred while retrieving DAT version from updates website. Exception info:\n" + str(ex) + "\n\nRetrieved iniText for debugging:\n" + str(iniText)})

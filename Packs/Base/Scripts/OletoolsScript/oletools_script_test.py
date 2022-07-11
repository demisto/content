import demistomock as demisto
from OletoolsScript import *


def test_oleid(mocker, caplog):
    mocker.patch.object(demisto, 'getFilePath', return_value={
        'path': '/Users/okarkkatz/dev/demisto/content/Packs/Base/Scripts/OletoolsScript/'
                'Archive.2/ActiveBarcode-Demo-Bind-Text.docm',
        'name': 'ActiveBarcode-Demo-Bind-Text.docm'})
    main()
    caplog.clear()
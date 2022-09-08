import pytest
from ArcSightXML import is_dir_exists, update_case, create_file_locally, create_xml
import os

OUTPATH = "/tmp"
DNE_OUTPATH = "/dne"


def clean():
    files_in_directory = os.listdir(OUTPATH)
    filtered_files = [file for file in files_in_directory if file.endswith(".xml")]
    for file in filtered_files:
        path_to_file = os.path.join(OUTPATH, file)
        os.remove(path_to_file)


@pytest.mark.parametrize("id, name, stage, cmds_dir, expected", [
    ('1', 'system down', 'Done', OUTPATH, "Updated case 1 to stage Done."),
    ('2', 'system down 2', 'Open', OUTPATH, "Updated case 2 to stage Open.")
])
def test_update_case(id, name, stage, cmds_dir, expected):

    cmd_res = update_case(id, name, stage, cmds_dir)
    assert cmd_res.readable_output == expected

    clean()


@pytest.mark.parametrize("cmds_dir, time, expected", [
    (OUTPATH, "1234", os.path.join(OUTPATH, "ExternalEventTrackingData_1234.xml")),
    (OUTPATH, "5678", os.path.join(OUTPATH, "ExternalEventTrackingData_5678.xml"))
])
def test_create_file_locally(cmds_dir, time, expected):
    create_file_locally(cmds_dir, 'foo', 'bar', 'closed', time)

    assert os.path.isfile(expected)

    clean()


@pytest.mark.parametrize("dir, expected", [
    (OUTPATH, True),
    (DNE_OUTPATH, False)
])
def test_is_dir_exists(dir, expected):
    assert is_dir_exists(dir) == expected


@pytest.mark.parametrize("time, id, name, stage, expected", [
    ("1234", "1", "foo", "Open", """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE archive SYSTEM "../../schema/xml/archive/arcsight-archive.dtd">
<archive buildVersion="6.9.1.2195.0" buildTime="2-9-2016_19:0:8" createTime="1234">
    <ArchiveCreationParameters>
        <action>insert</action>
        <format>xml.external.case</format>
        <include>
            <list>
                <ref type="Case" uri="foo" id="1"/>
            </list>
        </include>
    </ArchiveCreationParameters>
    <Case id="1" name="foo" action="insert" >
        <stage>Open</stage>
    </Case>
</archive>"""),
    ("5678", "2", "foo", "Closed", """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE archive SYSTEM "../../schema/xml/archive/arcsight-archive.dtd">
<archive buildVersion="6.9.1.2195.0" buildTime="2-9-2016_19:0:8" createTime="5678">
    <ArchiveCreationParameters>
        <action>insert</action>
        <format>xml.external.case</format>
        <include>
            <list>
                <ref type="Case" uri="foo" id="2"/>
            </list>
        </include>
    </ArchiveCreationParameters>
    <Case id="2" name="foo" action="insert" >
        <stage>Closed</stage>
    </Case>
</archive>""")
])
def test_create_xml(time, id, name, stage, expected):
    assert create_xml(time, id, name, stage) == expected

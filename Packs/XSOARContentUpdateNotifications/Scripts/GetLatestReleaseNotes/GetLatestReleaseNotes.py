import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from distutils.version import LooseVersion


def get_relevant_versions(changelog, current_version):
    data = {}
    for version, version_info in changelog.items():
        if LooseVersion(version) > current_version:
            data[version] = version_info

    return data


def update_pack_info(pack_info):
    current_version = LooseVersion(pack_info.get('currentVersion', '1.0.0'))
    changelog = pack_info.get('changelog', {})
    pack_info['changelog'] = get_relevant_versions(changelog, current_version)


def main(args):
    content_data = args.get('content_data', [])

    for pack_info in content_data:
        update_pack_info(pack_info)

    return_results(CommandResults(
        readable_output='ContentData was modified.',
        outputs_prefix='ContentData',
        outputs_key_field='packID',
        outputs=content_data,
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main(demisto.args())

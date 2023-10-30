import pytest

from CommonServerPython import DemistoException
import demistomock as demisto


def test_update_remote_trusted_images(mocker):
    """
    Given:
        - Input arguments including remote images, local images, and group ID
    When:
        - Calling the script with the input arguments
    Then:
        - The remote trusted images list is updated successfully according to the input given
    """
    from PrismaCloudRemoteTrustedImagesListUpdate import update_remote_trusted_images

    mocker.patch.object(demisto, 'executeCommand', side_effect=[
        [{'Contents': '{"img1":"2023-10-01T12:02:07Z"}', 'Type': 'LIST'}],
        [{'HumanReadable': 'Updated successfully the trusted repository, image, and registry.', 'Type': 'NOTE'}]])

    list_name = 'List Name'
    current_trusted_images = {
        'groups': [{'_id': 'Deny All', 'images': ['img1'], 'modified': '2022-04-27T17:30:02.803Z', 'name': '', 'owner': 'admin',
                    'previousName': ''},
                   {'_id': 'TRUSTED IMAGES', 'images': ['img1', 'img2', 'img3'], 'modified': '2023-02-27T21:35:49.697Z',
                    'name': '', 'owner': 'test user', 'previousName': ''},
                   {'_id': 'test', 'images': ['img2', 'img3'], 'modified': '2023-02-28T19:53:44.491Z', 'name': '',
                    'owner': 'test user', 'previousName': ''},
                   {'_id': 'demo', 'images': ['img3'], 'modified': '2023-10-01T12:02:07.293Z', 'name': '', 'owner': 'me',
                    'previousName': ''}],
        'policy': {'_id': 'trust', 'enabled': True, 'rules': [{}]}}
    trusted_group_id = 'demo'
    args = {'list_name': list_name, 'current_trusted_images': current_trusted_images, 'trusted_group_id': trusted_group_id}

    response = update_remote_trusted_images(args)
    assert response.readable_output == 'Updated successfully the trusted repository, image, and registry.'


@pytest.mark.parametrize('list_name, get_list_response, expected', [
    ('test_list', [{'Type': 1, 'Contents': '{"key":"value"}'}], {'key': 'value'}),
    ('bad_list', [{'Type': 4, 'Contents': 'Item not found'}], DemistoException)
])
def test_get_xsoar_list(mocker, list_name, get_list_response, expected):
    """
    Given:
        - Input parameters for the list name
    When:
        - Calling the script with the list name
    Then:
        - The returned list or exception matches the expected value
    """
    from PrismaCloudRemoteTrustedImagesListUpdate import get_xsoar_list

    mocker.patch.object(demisto, 'executeCommand', return_value=get_list_response)

    if isinstance(expected, dict):
        assert get_xsoar_list(list_name) == expected
    else:
        with pytest.raises(expected):
            get_xsoar_list(list_name)


@pytest.mark.parametrize('remote_images, local_images, expected', [
    ({'img1': 'hash1'}, {'img1': 'hash1'}, True),
    ({'img1': 'hash1'}, {'img2': 'hash2'}, False),
    ({'img1': 'hash1', 'img2': 'hash2'}, {'img1': 'hash1'}, False),
    ({}, {}, True)
])
def test_current_remote_images_same_as_local(remote_images, local_images, expected):
    """
    Given:
        - Input parameters for the remote images dict and local images dict
    When:
        - Comparing the image entries in the two dicts
    Then:
        - It correctly determines whether the remote and local images are the same
    """
    from PrismaCloudRemoteTrustedImagesListUpdate import current_remote_images_same_as_local

    assert current_remote_images_same_as_local(remote_images, local_images) == expected


@pytest.mark.parametrize('remote_images, local_images, group_id, expected_updated_remote_images, expected_message', [
    (
        {'groups': [{'_id': '1', 'images': ['img1']}]},
        ['img1'],
        '1',
        False,
        'Local and remote lists were equal, not updating list.'
    ),
    (
        {'groups': [{'_id': '1', 'images': ['img1']}]},
        ['img2'],
        '1',
        {'groups': [{'_id': '1', 'images': ['img2']}]},
        ''
    ),
    (
        {'groups': [{'_id': '2', 'images': ['img1']}]},
        ['img1'],
        '1',
        False,
        'Group 1 was not found in the given trusted images groups list.'
    )
])
def test_update_group_from_images(remote_images, local_images, group_id, expected_updated_remote_images, expected_message):
    """
    Given:
        - Input parameters for remote images list, local images list, and group ID
    When:
        - Update the remote images group with the local images
    Then:
        - Remote images is updated as expected
    """
    from PrismaCloudRemoteTrustedImagesListUpdate import update_group_from_images

    updated, message = update_group_from_images(remote_images, local_images, group_id)

    if expected_updated_remote_images:
        assert remote_images == expected_updated_remote_images
    else:
        assert not updated
    assert message == expected_message


def test_update_remote_list(mocker):
    """
    Given:
        - A list to update remotly
    When:
        - Calling update_remote_list with sample remote images input
    Then:
        - The remote list is updated successfully
    """
    from PrismaCloudRemoteTrustedImagesListUpdate import update_remote_list

    mocker.patch.object(demisto, 'executeCommand', return_value=[
        {'HumanReadable': 'Updated successfully the trusted repository, image, and registry.', 'Type': 'NOTE'}])

    assert update_remote_list([{'_id': '1', 'images': ['img1']}]) == \
        'Updated successfully the trusted repository, image, and registry.'

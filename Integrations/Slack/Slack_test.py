from CommonServerPython import *
import slack
import pytest
import asyncio

USERS = '''[{
    "id": "U012A3CDE",
    "team_id": "T012AB3C4",
    "name": "spengler",
    "deleted": false,
    "color": "9f69e7",
    "real_name": "spengler",
    "tz": "America/Los_Angeles",
    "tz_label": "Pacific Daylight Time",
    "tz_offset": -25200,
    "profile": {
        "avatar_hash": "ge3b51ca72de",
        "status_text": "Print is dead",
        "status_emoji": ":books:",
        "real_name": "Egon Spengler",
        "display_name": "spengler",
        "real_name_normalized": "Egon Spengler",
        "display_name_normalized": "spengler",
        "email": "spengler@ghostbusters.example.com",
        "image_24": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "image_32": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "image_48": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "image_72": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "image_192": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "image_512": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "team": "T012AB3C4"
    },
    "is_admin": true,
    "is_owner": false,
    "is_primary_owner": false,
    "is_restricted": false,
    "is_ultra_restricted": false,
    "is_bot": false,
    "updated": 1502138686,
    "is_app_user": false,
    "has_2fa": false
},
{
    "id": "U07QCRPA4",
    "team_id": "T0G9PQBBK",
    "name": "glinda",
    "deleted": false,
    "color": "9f69e7",
    "real_name": "Glinda Southgood",
    "tz": "America/Los_Angeles",
    "tz_label": "Pacific Daylight Time",
    "tz_offset": -25200,
    "profile": {
        "avatar_hash": "8fbdd10b41c6",
        "image_24": "https://a.slack-edge.com...png",
        "image_32": "https://a.slack-edge.com...png",
        "image_48": "https://a.slack-edge.com...png",
        "image_72": "https://a.slack-edge.com...png",
        "image_192": "https://a.slack-edge.com...png",
        "image_512": "https://a.slack-edge.com...png",
        "image_1024": "https://a.slack-edge.com...png",
        "image_original": "https://a.slack-edge.com...png",
        "first_name": "Glinda",
        "last_name": "Southgood",
        "title": "Glinda the Good",
        "phone": "",
        "skype": "",
        "real_name": "Glinda Southgood",
        "real_name_normalized": "Glinda Southgood",
        "display_name": "Glinda the Fairly Good",
        "display_name_normalized": "Glinda the Fairly Good",
        "email": "glenda@south.oz.coven"
    },
    "is_admin": true,
    "is_owner": false,
    "is_primary_owner": false,
    "is_restricted": false,
    "is_ultra_restricted": false,
    "is_bot": false,
    "updated": 1480527098,
    "has_2fa": false
}]'''

CONVERSATIONS = '''[{
    "id": "C012AB3CD",
    "name": "general",
    "is_channel": true,
    "is_group": false,
    "is_im": false,
    "created": 1449252889,
    "creator": "U012A3CDE",
    "is_archived": false,
    "is_general": true,
    "unlinked": 0,
    "name_normalized": "general",
    "is_shared": false,
    "is_ext_shared": false,
    "is_org_shared": false,
    "pending_shared": [],
    "is_pending_ext_shared": false,
    "is_member": true,
    "is_private": false,
    "is_mpim": false,
    "topic": {
        "value": "Company-wide announcements and work-based matters",
        "creator": "",
        "last_set": 0
    },
    "purpose": {
        "value": "This channel is for team-wide communication and announcements. All team members are in this channel.",
        "creator": "",
        "last_set": 0
    },
    "previous_names": [],
    "num_members": 4
},
{
    "id": "C061EG9T2",
    "name": "random",
    "is_channel": true,
    "is_group": false,
    "is_im": false,
    "created": 1449252889,
    "creator": "U061F7AUR",
    "is_archived": false,
    "is_general": false,
    "unlinked": 0,
    "name_normalized": "random",
    "is_shared": false,
    "is_ext_shared": false,
    "is_org_shared": false,
    "pending_shared": [],
    "is_pending_ext_shared": false,
    "is_member": true,
    "is_private": false,
    "is_mpim": false,
    "topic": {
        "value": "Non-work banter and water cooler conversation",
        "creator": "",
        "last_set": 0
    },
    "purpose": {
        "value": "A place for non-work-related flimflam.",
        "creator": "",
        "last_set": 0
    },
    "previous_names": [],
    "num_members": 4
}]'''


BOT = '''{
    "ok": true,
    "url": "https://subarachnoid.slack.com/",
    "team": "Subarachnoid Workspace",
    "user": "grace",
    "team_id": "T12345678",
    "user_id": "W12345678"
}'''

MIRRORS = '''
   [{
     "channel_id":"GKQ86DVPH",
     "investigation_id":"681",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GKB19PA3V",
     "investigation_id":"684",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GKWBPCNQN",
     "investigation_id":"692",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GKNEJU4P9",
     "investigation_id":"713",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GL8GHC0LV",
     "investigation_id":"734",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  }]
'''


@pytest.mark.asyncio
async def test_get_slack_name(mocker):
    from Slack import get_slack_name

    # Set

    def getIntegrationContext():
        return {
            'mirrors': MIRRORS,
            'users': USERS,
            'conversations': CONVERSATIONS,
            'bot_id': 'W12345678'
        }

    async def users_info(user):
        if user != 'alexios':
            return {'user': json.loads(USERS)[0]}
        return None

    async def conversations_info(channel):
        if channel != 'lulz':
            return {'channel': json.loads(CONVERSATIONS)[0]}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=getIntegrationContext)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(slack.WebClient, 'users_info', side_effect=users_info)
    mocker.patch.object(slack.WebClient, 'conversations_info', side_effect=conversations_info)

    # Assert

    # User in integration context
    user_id = 'U012A3CDE'
    name = await get_slack_name(user_id, slack.WebClient)
    assert name == 'spengler'
    assert slack.WebClient.users_info.call_count == 0

    # User not in integration context
    unknown_user = 'USASSON'
    name = await get_slack_name(unknown_user, slack.WebClient)
    assert name == 'spengler'
    assert slack.WebClient.users_info.call_count == 1

    # User does not exist
    nonexisting_user = 'alexios'
    name = await get_slack_name(nonexisting_user, slack.WebClient)
    assert name == ''
    assert slack.WebClient.users_info.call_count == 1

    # Channel in integration context
    channel_id = 'C012AB3CD'
    name = await get_slack_name(channel_id, slack.WebClient)
    assert name == 'general'
    assert slack.WebClient.conversations_info.call_count == 0

    # Channel not in integration context
    unknown_channel = 'CSASSON'
    name = await get_slack_name(unknown_channel, slack.WebClient)
    assert name == 'general'
    assert slack.WebClient.users_info.call_count == 1

    # Channel doesn't exist
    nonexisting_channel = 'lulz'
    name = await get_slack_name(nonexisting_channel, slack.WebClient)
    assert name == ''
    assert slack.WebClient.users_info.call_count == 1


@pytest.mark.asyncio
async def test_clean_message(mocker):
    from Slack import clean_message

    # Set

    def getIntegrationContext():
        return {
            'mirrors': MIRRORS,
            'users': USERS,
            'conversations': CONVERSATIONS,
            'bot_id': 'W12345678'
        }

    async def users_info(user):
        return {'user': json.loads(USERS)[0]}

    async def conversations_info(channel):
        return {'channel': json.loads(CONVERSATIONS)[0]}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=getIntegrationContext)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(slack.WebClient, 'users_info', side_effect=users_info)
    mocker.patch.object(slack.WebClient, 'conversations_info', side_effect=conversations_info)

    user_message = 'Hello <@U012A3CDE>!'
    channel_message = 'Check <#C012AB3CD>'
    link_message = 'Go to <https://www.google.com/lulz>'

    # Arrange

    clean_user_message = await clean_message(user_message, slack.WebClient)
    clean_channel_message = await clean_message(channel_message, slack.WebClient)
    clean_link_message = await clean_message(link_message, slack.WebClient)

    # Assert

    assert clean_user_message == 'Hello spengler!'
    assert clean_channel_message == 'Check general'
    assert clean_link_message == 'Go to https://www.google.com/lulz'


def test_get_user_by_name(mocker):
    from Slack import get_user_by_name

    # Set

    def getIntegrationContext():
        return {
            'mirrors': MIRRORS,
            'users': USERS,
            'conversations': CONVERSATIONS,
            'bot_id': 'W12345678'
        }

    def users_list():
        users = {'members': json.loads(USERS)}
        new_user = {
            'name': 'perikles',
            'profile': {
                'email': 'perikles@acropoli.com',
            },
            'id': 'U012B3CUI'
        }

        users['members'].append(new_user)
        return users

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=getIntegrationContext)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(slack.WebClient, 'users_list', side_effect=users_list)

    # Assert

    # User name exists in integration context
    username = 'spengler'
    user = get_user_by_name(username, demisto.getIntegrationContext())
    assert user['id'] == 'U012A3CDE'
    assert slack.WebClient.users_list.call_count == 0

    # User email exists in integration context
    email = 'spengler@ghostbusters.example.com'
    user = get_user_by_name(email, demisto.getIntegrationContext())
    assert user['id'] == 'U012A3CDE'
    assert slack.WebClient.users_list.call_count == 0

    # User name doesn't exist in integration context
    username = 'perikles'
    user = get_user_by_name(username, demisto.getIntegrationContext())
    assert user['id'] == 'U012B3CUI'
    assert slack.WebClient.users_list.call_count == 1

    # User email doesn't exist in integration context
    email = 'perikles@acropoli.com'
    user = get_user_by_name(email, demisto.getIntegrationContext())
    assert user['id'] == 'U012B3CUI'
    assert slack.WebClient.users_list.call_count == 2

    # User doesn't exist
    username = 'alexios'
    user = get_user_by_name(username, demisto.getIntegrationContext())
    assert user == []
    assert slack.WebClient.users_list.call_count == 3


def test_mirror_investigation_new_mirror(mocker):
    from Slack import mirror_investigation

    # Set

    def getIntegrationContext():
        return {
            'mirrors': MIRRORS,
            'users': USERS,
            'conversations': CONVERSATIONS,
            'bot_id': 'W12345678'
        }

    def users_list():
        return {'members': json.loads(USERS)}

    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '999', 'users': ['spengler', 'alexios']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=getIntegrationContext)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'users_list', side_effect=users_list)
    mocker.patch.object(slack.WebClient, 'channels_create', return_value={'channel': {
        'id': 'new_channel'
    }})
    mocker.patch.object(slack.WebClient, 'groups_create', return_value={'group': {
        'id': 'new_group'
    }})
    mocker.patch.object(slack.WebClient, 'conversations_invite')

    new_mirror = {
        'channel_id': 'new_group',
        'investigation_id': '999',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': False
    }
    # Arrange

    mirror_investigation()

    # Assert

    assert slack.WebClient.groups_create.call_count == 1
    assert slack.WebClient.users_list.call_count == 1
    assert slack.WebClient.conversations_invite.call_count == 2

    error_results = demisto.results.call_args_list[0][0]
    assert error_results[0]['Contents'] == 'User alexios not found in Slack'
    success_results = demisto.results.call_args_list[1][0]
    assert success_results[0] == 'Investigation mirrored successfully'

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = json.loads(new_context['mirrors'])
    new_conversations = json.loads(new_context['conversations'])
    our_conversation_filter = list(filter(lambda c: c['id'] == 'new_group', new_conversations))
    our_conversation = our_conversation_filter[0]
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '999', new_mirrors))
    our_mirror = our_mirror_filter[0]

    assert len(our_conversation_filter) == 1
    assert len(our_mirror_filter) == 1
    assert our_conversation == {'id': 'new_group'}
    assert our_mirror == new_mirror


def test_mirror_investigation_existing_mirror(mocker):
    from Slack import mirror_investigation

    # Set

    def getIntegrationContext():
        return {
            'mirrors': MIRRORS,
            'users': USERS,
            'conversations': CONVERSATIONS,
            'bot_id': 'W12345678'
        }

    def users_list():
        return {'members': json.loads(USERS)}

    mocker.patch.object(demisto, 'args', return_value={'type': 'chat', 'autoclose': 'false',
                                                       'direction': 'FromDemisto', 'mirrorTo': 'channel'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681', 'users': ['spengler']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=getIntegrationContext)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'users_list', side_effect=users_list)
    mocker.patch.object(slack.WebClient, 'channels_create')
    mocker.patch.object(slack.WebClient, 'groups_create')
    mocker.patch.object(slack.WebClient, 'conversations_invite')

    new_mirror = {
         'channel_id': 'GKQ86DVPH',
         'investigation_id': '681',
         'mirror_type': 'chat',
         'mirror_direction': 'FromDemisto',
         'mirror_to': 'group',
         'auto_close': False,
         'mirrored': False
    }
    # Arrange

    mirror_investigation()

    # Assert

    assert slack.WebClient.groups_create.call_count == 0
    assert slack.WebClient.channels_create.call_count == 0
    assert slack.WebClient.users_list.call_count == 0
    assert slack.WebClient.conversations_invite.call_count == 2

    error_results = demisto.results.call_args_list[0][0]
    assert error_results[0]['Contents'] == 'The Slack channel type cannot be changed in this manner.'
    success_results = demisto.results.call_args_list[1][0]
    assert success_results[0] == 'Investigation mirrored successfully'

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = json.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '681', new_mirrors))
    our_mirror = our_mirror_filter[0]

    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror


def test_check_for_mirrors(mocker):
    from Slack import check_for_mirrors

    # Set
    def getIntegrationContext():
        mirrors = json.loads(MIRRORS)
        mirrors.append({
            'channel_id': 'new_group',
            'investigation_id': '999',
            'mirror_type': 'all',
            'mirror_direction': 'both',
            'mirror_to': 'group',
            'auto_close': True,
            'mirrored': False
        })

        return {
            'mirrors': json.dumps(mirrors),
            'users': USERS,
            'conversations': CONVERSATIONS,
            'bot_id': 'W12345678'
        }

    new_mirror = {
        'channel_id': 'new_group',
        'investigation_id': '999',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': True
    }

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=getIntegrationContext)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(demisto, 'mirrorInvestigation')

    # Arrange

    check_for_mirrors()

    # Assert

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = json.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '999', new_mirrors))
    our_mirror = our_mirror_filter[0]

    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror

    mirror_id = demisto.mirrorInvestigation.call_args[0][0]
    mirror_type = demisto.mirrorInvestigation.call_args[0][1]
    auto_close = demisto.mirrorInvestigation.call_args[0][2]

    assert mirror_id == '999'
    assert mirror_type == 'all'
    assert auto_close is True


@pytest.mark.asyncio
async def test_slack_loop_should_restart(mocker):
    from Slack import slack_loop

    # Set
    class MyFuture:
        @staticmethod
        def done():
            return True

        @staticmethod
        def exception():
            return None

    @asyncio.coroutine
    def yeah_im_not_going_to_run(time):
        return "sup"

    def bail():
        raise InterruptedError

    with pytest.raises(InterruptedError):
        mocker.patch.object(slack.RTMClient, 'start', side_effect=[MyFuture(), bail()])
        mocker.patch.object(demisto, 'info')
        mocker.patch.object(demisto, 'updateModuleHealth', side_effct=bail())
        mocker.patch.object(asyncio, 'sleep', side_effect=yeah_im_not_going_to_run)

        # Arrange
        await slack_loop()

        # Assert
        assert slack.RTMClient.start.call_count == 2


@pytest.mark.asyncio
async def test_handle_dm_existing_user(mocker):
    from Slack import handle_dm
    from Slack import translate_create

    # Set

    def getIntegrationContext():
        return {
            'mirrors': MIRRORS,
            'users': USERS,
            'conversations': CONVERSATIONS,
            'bot_id': 'W12345678'
        }

    async def users_info(user):
        return {'user': json.loads(USERS)[0]}

    @asyncio.coroutine
    def yeah_im_not_going_to_run(demisto_user, message):
        return "sup"

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=getIntegrationContext)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(demisto, 'findUser', return_value={'id': 'demisto_id'})
    mocker.patch.object(slack.WebClient, 'users_info', side_effect=users_info)
    mocker.patch('translate_create', side_effect=yeah_im_not_going_to_run)


















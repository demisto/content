import demistomock as demisto
import pytest
from CommonServerPython import entryTypes

def test_parse_option_text_color_and_text():
    """
    When: Running parse_option_text with the required argument.
    Then: Ensure the argument is parsed correctly to text, style.
    """
    from GoogleChatAsk.GoogleChatAsk import parse_option_text
    text, style = parse_option_text('yes#blue')
    assert text == 'yes'
    assert style == 'blue'
    
def test_parse_option_text_only_text():
    """
    When: Running parse_option_text with the required argument.
    Then: Ensure the argument is parsed correctly to text, style.
    """
    from GoogleChatAsk.GoogleChatAsk import parse_option_text
    text, style = parse_option_text('yes')
    assert text == 'yes'
    assert style is None
    
def test_parse_option_text_invalid_color():
    """
    When: Running parse_option_text with the required argument.
    Then: Raise an error since the color is invalid.
    """
    from GoogleChatAsk.GoogleChatAsk import parse_option_text
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException) as e:
        text, style = parse_option_text('yes#black')
    assert e.value.message == 'The option: yes#black has invalid color: black, the color options are red, green, blue.'

expected_card1 = {'cardId': 'survey-card', 'card': {
    'header': {'title': 'Feedback request', 'subtitle': 'Is the website easy to understand?'},
    'sections': [{'header': 'Choose one option:',
                  'collapsible': 'false',
                  'uncollapsibleWidgetsCount': 1,
                  'widgets': [{'selectionInput': {'name': 'a', 'label': 'a', 'type': 'DROPDOWN'}},
                              {'buttonList': {'buttons': [{'text': 'yes', 'color': {'red': '0', 'green': '0', 'blue': '1'},
                                                           'onClick': {'action': {'function': 'yes'}}},
                                                          {'text': 'no', 'color': {'red': '0', 'green': '0', 'blue': '0'},
                                                           'onClick': {'action': {'function': 'no'}}},
                                                          {'text': 'other', 'color': {'red': '0', 'green': '0', 'blue': '0'},
                                                           'onClick': {'action': {'function': 'other'}}}]}}]}]}}
expected_card2 = {'cardId': 'survey-card', 'card': {'header':
    {'title': 'Feedback request', 'subtitle': 'Is the website easy to understand?'},
    'sections': [{'header': 'Choose one option:',
                  'collapsible': 'false', 'uncollapsibleWidgetsCount': 1,
                  'widgets': [{'selectionInput': {'name': 'a', 'label': 'a', 'type': 'RADIO_BUTTON'}},
                              {'buttonList': {'buttons': [{'text': 'yes', 'color': {'red': '0', 'green': '0', 'blue': '0'},
                                                           'onClick': {'action': {'function': 'yes'}}},
                                                          {'text': 'no', 'color': {'red': '1', 'green': '0', 'blue': '0'},
                                                           'onClick': {'action': {'function': 'no'}}},
                                                          {'text': 'other', 'color': {'red': '0', 'green': '0', 'blue': '0'},
                                                           'onClick': {'action': {'function': 'other'}}}]}}]}]}}
@pytest.mark.parametrize(
    'message, user_options, response_type, expected_result',
    [
        ('Is the website easy to understand?', ['yes#blue', 'no', 'other'],'dropdown', expected_card1),
        ('Is the website easy to understand?', ['yes', 'no#red', 'other'],'button', expected_card2),
    ]
)
def test_create_adaptive_card(message, user_options, response_type, expected_result):
    """
    Given:
        - The card is of dropdown type.
        - The card is of button type.
    When: Running create_adaptive_card with the required argument.
    Then: Returns the desired card.
    """
    from GoogleChatAsk.GoogleChatAsk import create_adaptive_card
    assert create_adaptive_card(message, user_options, response_type) == expected_result


def execute_command(command, args):
    if command == 'addEntitlement':
        return [{
            'Type': entryTypes['note'],
            'Contents': '123456789'
        }]

    return []


def test_main(mocker):
    """
    When: Running main with the required argument.
    Then: Sends the correct args to send-notification.
    """
    from GoogleChatAsk.GoogleChatAsk import main
    import dateparser
    import datetime
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '123'})
    mocker.patch.object(demisto, 'args', return_value={
        'option1': 'Option1',
        'option2': 'Option2',
        'additional_options': 'Option3',
        'responseType': 'button',
        'lifetime': '1 day',
        'default_reply': 'Default Response',
        'message': 'Is the website helpful?',
        'task_id': '1',
        'space_id': '098'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    main()

    call_args = demisto.executeCommand.call_args[0]
    expected_args = {'entitlement': '123456789@123|1',
                     'expiry': '2019-09-26 18:38:25',
                     'adaptive_card': {'cardId': 'survey-card',
                                       'card': {
                                           'header': {
                                               'title': 'Feedback request',
                                               'subtitle': 'Is the website helpful?'},
                                           'sections': [{'header': 'Choose one option:',
                                                         'collapsible': 'false',
                                                         'uncollapsibleWidgetsCount': 1,
                                                         'widgets': [{
                                                             'selectionInput': {
                                                                 'name': 'a', 'label': 'a', 'type': 'DROPDOWN'
                                                                 }},
                                                                     {'buttonList': {
                                                                         'buttons': [{'text': 'Option1',
                                                                                      'color': {
                                                                                          'red': '0',
                                                                                          'green': '0',
                                                                                          'blue': '0'},
                                                                                      'onClick': {
                                                                                          'action': {
                                                                                              'function': 'Option1'
                                                                                              }
                                                                                          }
                                                                                      },
                                                                                     {'text': 'Option2',
                                                                                      'color': {
                                                                                          'red': '0',
                                                                                          'green': '0',
                                                                                          'blue': '0'},
                                                                                      'onClick': {
                                                                                          'action': {
                                                                                              'function': 'Option2'
                                                                                              }
                                                                                          }
                                                                                      },
                                                                                     {'text': 'Option3',
                                                                                      'color': {
                                                                                          'red': '0',
                                                                                          'green': '0',
                                                                                          'blue': '0'
                                                                                          }, 'onClick': {
                                                                                              'action': {
                                                                                                  'function': 'Option3'
                                                                                                  }
                                                                                              }
                                                                                          }
                                                                                     ]
                                                                         }
                                                                      }
                                                                     ]
                                                         }
                                                        ]
                                           }
                                       },
                     'default_reply': 'Default Response', 'message': 'no_message', 'space_id': '098'}

    assert call_args[1] == expected_args


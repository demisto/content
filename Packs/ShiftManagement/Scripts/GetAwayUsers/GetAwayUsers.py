from CommonServerPython import *


def main():
    try:
        users_command_response: Dict = demisto.executeCommand("getUsers", {})
        if is_error(users_command_response) or not users_command_response:
            raise DemistoException(f'Could not retrieve users\nError details: {get_error(users_command_response)}')
        users_info: List[Dict] = users_command_response[0]['Contents']
        away_users = [user for user in users_info if user.get('isAway', False)]
        result = CommandResults(
            outputs_key_field='id',
            outputs_prefix='CortexXSOAR.AwayUsers',
            readable_output=tableToMarkdown('Away Users', away_users,
                                            headers=['username', 'email', 'name', 'phone', 'roles', 'isAway'],
                                            headerTransform=string_to_table_header, removeNull=True),
            outputs=away_users
        )
        return_results(result)
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GetAwayUsers. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

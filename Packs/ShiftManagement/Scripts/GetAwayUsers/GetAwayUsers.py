from CommonServerPython import *


def main():
    try:
        users_command_response: Dict = demisto.executeCommand("getUsers", {})
        if is_error(users_command_response) or not users_command_response:
            raise DemistoException(f'Could not retrieve users\nError details: {get_error(users_command_response)}')
        users_info: List[Dict] = users_command_response[0]['Contents']
        away_users = [user for user in users_info if user.get('isAway', False)]
        outputs = [
            {k: v for k, v in away_user.items() if k in ['id', 'username', 'email', 'name', 'phone', 'roles']}
            for away_user in away_users]
        result = CommandResults(
            outputs_key_field='id',
            outputs_prefix='CortexXSOAR.AwayUsers',
            readable_output=tableToMarkdown('Away Users', outputs, headerTransform=string_to_table_header,
                                            removeNull=True),
            outputs=outputs
        )
        return_results(result)
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GetAwayUsers. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

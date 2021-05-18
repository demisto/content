test_connection_success = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "result": True
    }
    }

test_connection_failure = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "result": False
    }
}

test_connection_invalid_api_key = \
    {
    "HTTP Status Code" : 401,
    "HTTP Reason" : "Unauthorized",
    "HTTP Body" : {
    "msg": "Invalid API KEY"
    }
    }

test_decoy_host_true = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "result": True
    }
    }

test_decoy_host_false = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "result": False
    }
    }

test_decoy_user_true = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "result": True
    }
    }

test_decoy_user_false = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "result": False
    }
    }

test_decoy_file_true = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "result": True
    }
    }

test_decoy_file_false = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "result": False
    }
    }

test_mute_decoy_true = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "msg" : "Initiated mute of decoy",
    "rescode":0
    }
    }

test_mute_decoy_false = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "msg" : "Decoy is not present",
    "rescode": 1
    }
    }
    
test_mute_again_already_muted_decoy = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "msg" : "Initiated mute of decoy",
    "rescode":0
    }
    }

test_unmute_decoy_true = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "msg" : "Initiated unmute of decoy",
    "rescode":0
    }
    }

test_unmute_decoy_false = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "msg" : "Decoy is not present",
    "rescode": 1
    }
    }
    
test_unmute_again_already_unmuted_decoy = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "msg" : "Initiated unmute of decoy",
    "rescode":0
    }
    }

test_mute_host_true = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "msg": "Marked for mute of host",
    "rescode": 0
    }
    }

test_mute_host_false = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "msg": "No deceptions present on the endpoint",
    "rescode": 1
    }
    }
    
test_mute_already_muted_host = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "msg": "Marked for mute of host",
    "rescode": 0
    }
    }

test_unmute_host_true = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "msg": "Marked for mute of host",
    "rescode": 0
    }
    }

test_unmute_host_false = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" :
        {
    "msg": "No deceptions present on the endpoint",
    "rescode": 1
    }
    }
    
test_unmute_already_unmuted_host = \
    {
    "HTTP Status Code" : 200,
    "HTTP Reason" : "OK",
    "HTTP Body" : {
    "msg": "Marked for mute of host",
    "rescode": 0
    }
    }

test_missing_parameter = \
    {
    "HTTP Status Code" : 422,
    "HTTP Reason" : "Unprocessable Entity",
    "HTTP Body" :
        {
        "msg": "Missing required parameter"
        }
    }

test_server_error = \
    {
    "HTTP Status Code" : 500,
    "HTTP Reason" : "Error",
    "HTTP Body" :
        {
        "msg": "Internal Server Error"
        }
    }

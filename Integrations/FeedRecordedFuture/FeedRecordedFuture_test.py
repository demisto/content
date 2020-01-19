# from FeedRecordedFuture import build_request, Client
#
# IP_CONNECT_API_FEED = [
# ]
#
# IP_FUSION_FEED = [
#
# ]
#
#
#
#
# def test_say_hello():
#     client = Client(base_url='https://test.com', verify=False, auth=('test', 'test'))
#     args = {
#         'name': 'Dbot'
#     }
#     _, outputs, _ = build_request(client, args)
#
#     assert outputs['hello'] == 'Hello Dbot'
#
#
# def test_say_hello_over_http(requests_mock):
#     mock_response = {'result': 'Hello Dbot'}
#     requests_mock.get('https://test.com/hello/Dbot', json=mock_response)
#
#     client = Client(base_url='https://test.com', verify=False, auth=('test', 'test'))
#     args = {
#         'name': 'Dbot'
#     }
#     _, outputs, _ = say_hello_over_http_command(client, args)
#
#     assert outputs['hello'] == 'Hello Dbot'

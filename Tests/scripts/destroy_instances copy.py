import shutil


import demisto_client


def main():
    # client: demisto_client.demisto_api.DefaultApi = demisto_client.configure(f'http://localhost:8080/',
    #                                              verify_ssl=False,
    #                                              username='admin',
    #                                              password='admin')
    client = demisto_client.configure()
    tmp_file_path ,_, _ = client.generic_request('/log/bundle', 'GET', response_type='file')
    result = shutil.copy(tmp_file_path, 'test_1_logs.tar.gz')
    if result:
        print(result)
if __name__ == "__main__":
    main()

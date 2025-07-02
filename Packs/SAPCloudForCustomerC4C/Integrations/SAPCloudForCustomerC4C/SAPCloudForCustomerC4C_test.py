from SAPCloudForCustomerC4C import Client


SAP_CLOUD = "SAP CLOUD FOR CUSTOMER"


def mock_client():
    return Client(base_url="https://my313577.crm.ondemand.com", base64String="base64String", verify=True)

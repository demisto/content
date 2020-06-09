GET_EMPLOYEES_REQ = """
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:bsvc="urn:com.workday/bsvc">
    <soapenv:Header>
        <wsse:Security soapenv:mustUnderstand="1"
        xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <wsse:UsernameToken wsu:Id="UsernameToken-{token}">
                <wsse:Username>{username}</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0
                #PasswordText">{password}</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </soapenv:Header>
    <soapenv:Body>
        <bsvc:Get_Workers_Request bsvc:version="{api_version}">
            <bsvc:Response_Filter>
                <bsvc:Page>{page}</bsvc:Page>
                <bsvc:Count>{count}</bsvc:Count>
            </bsvc:Response_Filter>
            <bsvc:Response_Group>
                <bsvc:Include_Personal_Information>1</bsvc:Include_Personal_Information>
                <bsvc:Include_Reference>1</bsvc:Include_Reference>
                <bsvc:Include_Employment_Information>1</bsvc:Include_Employment_Information>
                <bsvc:Include_Management_Chain_Data>1</bsvc:Include_Management_Chain_Data>
                <bsvc:Include_Photo>1</bsvc:Include_Photo>
            </bsvc:Response_Group>
        </bsvc:Get_Workers_Request>
    </soapenv:Body>
</soapenv:Envelope>
"""

GET_EMPLOYEE_BY_ID = """
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:bsvc="urn:com.workday/bsvc">
    <soapenv:Header>
        <wsse:Security soapenv:mustUnderstand="1"
        xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <wsse:UsernameToken wsu:Id="UsernameToken-{token}">
                <wsse:Username>{username}</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0
                #PasswordText">{password}</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </soapenv:Header>
    <soapenv:Body>
        <bsvc:Get_Workers_Request bsvc:version="{api_version}">
            <bsvc:Request_References bsvc:Skip_Non_Existing_Instances="false">
                <bsvc:Worker_Reference>
                    <bsvc:ID bsvc:type="Employee_ID">{employee_id}</bsvc:ID>
                </bsvc:Worker_Reference>
            </bsvc:Request_References>
            <bsvc:Response_Group>
                <bsvc:Include_Personal_Information>1</bsvc:Include_Personal_Information>
                <bsvc:Include_Reference>1</bsvc:Include_Reference>
                <bsvc:Include_Employment_Information>1</bsvc:Include_Employment_Information>
                <bsvc:Include_Management_Chain_Data>1</bsvc:Include_Management_Chain_Data>
                <bsvc:Include_Photo>1</bsvc:Include_Photo>
            </bsvc:Response_Group>
        </bsvc:Get_Workers_Request>
    </soapenv:Body>
</soapenv:Envelope>
"""

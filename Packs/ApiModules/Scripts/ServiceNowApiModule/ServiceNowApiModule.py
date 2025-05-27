from CommonServerPython import *

from CommonServerUserPython import *

OAUTH_URL = "/oauth_token.do"

TRIED_ONCE = "Tried Once"

class ServiceNowClient(BaseClient):
    def __init__(
        self,
        credentials: dict,
        use_oauth: bool = False,
        client_id: str = "",
        client_secret: str = "",
        url: str = "",
        verify: bool = False,
        proxy: bool = False,
        headers: dict = None,
    ):
        """
        ServiceNow Client class. The class can use either basic authorization with username and password, or OAuth2.
        Args:
            - credentials: the username and password given by the user.
            - client_id: the client id of the application of the user.
            - client_secret - the client secret of the application of the user.
            - url: the instance url of the user, i.e: https://<instance>.service-now.com.
                   NOTE - url should be given without an API specific suffix as it is also used for the OAuth process.
            - verify: Whether the request should verify the SSL certificate.
            - proxy: Whether to run the integration using the system proxy.
            - headers: The request headers, for example: {'Accept`: `application/json`}. Can be None.
            - use_oauth: a flag indicating whether the user wants to use OAuth 2.0 or basic authorization.
        """
        self.auth = None
        self.use_oauth = use_oauth
        self.username = credentials.get("identifier", "")
        self.password = credentials.get("password", "")
        if self.use_oauth:  # if user selected the `Use OAuth` box use OAuth authorization, else use basic authorization
            self.client_id = client_id
            self.client_secret = client_secret
        else:
            self.auth = (self.username, self.password)

        if "@" in client_id:  # for use in OAuth test-playbook
            self.client_id, refresh_token = client_id.split("@")
            set_integration_context({"refresh_token": refresh_token})

        self.base_url = url
        super().__init__(base_url=self.base_url, verify=verify, proxy=proxy, headers=headers, auth=self.auth)  # type
        # : ignore[misc]

    def http_request(
        self,
        method,
        url_suffix,
        full_url=None,
        headers=None,
        json_data=None,
        params=None,
        data=None,
        files=None,
        return_empty_response=False,
        auth=None,
        timeout=None,
    ):
        ok_codes = (200, 201, 401)  # includes responses that are ok (200) and error responses that should be
        # handled by the client and not in the BaseClient
        try:
            if self.use_oauth:  # add a valid access token to the headers when using OAuth
                access_token = self.get_access_token()
                self._headers.update({"Authorization": "Bearer " + access_token})
            res = super()._http_request(
                method=method,
                url_suffix=url_suffix,
                full_url=full_url,
                resp_type="response",
                headers=headers,
                json_data=json_data,
                params=params,
                data=data,
                files=files,
                ok_codes=ok_codes,
                return_empty_response=return_empty_response,
                auth=auth,
                timeout=timeout,
            )
            if res.status_code in [200, 201]:
                try:
                    return res.json()
                except ValueError as exception:
                    raise DemistoException(f"Failed to parse json object from response: {res.content}", exception)

            if res.status_code in [401]:
                if self.use_oauth:
                    if demisto.getIntegrationContext().get("expiry_time", 0) <= date_to_timestamp(datetime.now()):
                        access_token = self.get_access_token()
                        self._headers.update({"Authorization": "Bearer " + access_token})
                        return self.http_request(method, url_suffix, full_url=full_url, params=params)
                    try:
                        err_msg = f"Unauthorized request: \n{res.json()!s}"
                    except ValueError:
                        err_msg = f"Unauthorized request: \n{res!s}"
                    raise DemistoException(err_msg)
                else:
                    raise Exception(f"Authorization failed. Please verify that the username and password are correct.\n{res}")

        except Exception as e:
            if self._verify and "SSL Certificate Verification Failed" in e.args[0]:
                return_error(
                    "SSL Certificate Verification Failed - try selecting 'Trust any certificate' "
                    "checkbox in the integration configuration."
                )
            raise DemistoException(e.args[0])

    def login(self, username: str, password: str):
        """
        Generate a refresh token using the given client credentials and save it in the integration context.
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": username,
            "password": password,
            "grant_type": "password",
        }
        try:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            res = super()._http_request(method="POST", url_suffix=OAUTH_URL, resp_type="response", headers=headers, data=data)
            try:
                res = res.json()
            except ValueError as exception:
                raise DemistoException(f"Failed to parse json object from response: {res.content}", exception)
            if "error" in res:
                return_error(
                    f"Error occurred while creating an access token. Please check the Client ID, Client Secret "
                    f"and that the given username and password are correct.\n{res}"
                )
            if res.get("refresh_token"):
                refresh_token = {"refresh_token": res.get("refresh_token")}
                set_integration_context(refresh_token)
        except Exception as e:
            return_error(
                f"Login failed. Please check the instance configuration and the given username and password.\n{e.args[0]}"
            )
    
    
    def get_access_token(self):
        """
        Get an access token that was previously created if it is still valid, else, generate a new access token from
        the client id, client secret and refresh token.
        If refresh token is expired, retry once to create new one using the login command.
        If unsuccessful flag the context and no more retry will be until sucessful login.
        """
        ok_codes = (200, 201, 401)
        ctx = get_integration_context()
        if ctx.get("access_token") and ctx.get("expiry_time") > date_to_timestamp(datetime.now()):
            demisto.debug("access token exists")
            return ctx.get("access_token")
        
        if "refresh_token" not in ctx:
            demisto.debug("refresh token not exists")
            raise Exception(
                    "Could not create an access token. User might be not logged in. Try running the oauth-login command first."
                )
            
        data = {"client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": ctx.get("refresh_token"),
                "grant_type": "refresh_token"}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        try:
            for attempt in range(2):
                demisto.debug(f"Attempt number {attempt}")
                if attempt == 1:
                    if TRIED_ONCE not in ctx:
                        demisto.debug("login retry")
                        data["refresh_token"] = self.get_refresh_token()
                    else:
                        break
                
                res = super()._http_request(
                        method="POST",
                        url_suffix=OAUTH_URL,
                        resp_type="response",
                        headers=headers,
                        data=data,
                        ok_codes=ok_codes
                    )
                demisto.debug("Requests successful")
                try:
                    res = res.json()
                except ValueError as exception:
                    raise DemistoException(f"Failed to parse json object from response: {res.content}", exception)
                
                if res.get("access_token"):
                    return self.store_access_token(res)
                
                demisto.debug(f"Creating access token failed with {str(res)}")
                if attempt == 1:
                    demisto.debug("No more retries")
                    ctx[TRIED_ONCE] = "True"
                    set_integration_context(ctx)
                    
        except DemistoException:
            return_error(
                "Error occurred while creating an access token. Please check the Client ID, Client Secret "
                "and try to run again the as it might that the credentials are wrong."
            )
            
    def get_refresh_token(self):
        demisto.debug("Get refresh token")
        try:
            self.login(self.username, self.password)
            demisto.debug("Login successful")
            ctx = get_integration_context()
            if ctx.get("refresh_token"):
                demisto.debug("New refresh token")
                return ctx.get("refresh_token")
            else:
                demisto.debug("No refresh token")
        except DemistoException as e:
            return_error(
                f"Error occurred while creating an access token. Please check the Client ID, Client Secret "
                f"and try to run again the as it might that the credentials are wrong {e}."
            )
            
    def store_access_token(self, response):
        demisto.debug("New access token received")
        expiry_time = date_to_timestamp(datetime.now(), date_format="%Y-%m-%dT%H:%M:%S")
        expiry_time += response.get("expires_in", 0) * 1000 - 10
        new_token = {
            "access_token": response.get("access_token"),
            "refresh_token": response.get("refresh_token"),
            "expiry_time": expiry_time,
        }
        set_integration_context(new_token)
        return response.get("access_token")
            
    # def get_access_token(self):
    #     """
    #     Get an access token that was previously created if it is still valid, else, generate a new access token from
    #     the client id, client secret and refresh token.
    #     """
    #     ok_codes = (200, 201, 401)
    #     ctx = get_integration_context()

    #     # Check if there is an existing valid access token
    #     if ctx.get("access_token") and ctx.get("expiry_time") > date_to_timestamp(datetime.now()):
    #         return ctx.get("access_token")
    #     else:
    #         data = {"client_id": self.client_id, "client_secret": self.client_secret}

    #         # Check if a refresh token exists. If not, raise an exception indicating to call the login function first.
    #         if ctx.get("refresh_token"):
    #             data["refresh_token"] = ctx.get("refresh_token")
    #             data["grant_type"] = "refresh_token"
    #         else:
    #             raise Exception(
    #                 "Could not create an access token. User might be not logged in. Try running the oauth-login command first."
    #             )

    #         try:
    #             headers = {"Content-Type": "application/x-www-form-urlencoded"}
    #             res = super()._http_request(
    #                 method="POST", url_suffix=OAUTH_URL, resp_type="response", headers=headers, data=data, ok_codes=ok_codes
    #             )
    #             try:
    #                 res = res.json()
    #             except ValueError as exception:
    #                 raise DemistoException(f"Failed to parse json object from response: {res.content}", exception)
    #             if "error" in res:
    #                 # If refresh token is expired try creating new one by login in
    #                 demisto.debug(f"Creating access token failed with {str(res)}")
    #                 if TRIED_ONCE not in ctx:
    #                     demisto.debug("First login retry")
    #                     try:
    #                         self.login(self.username, self.password)
    #                         demisto.debug("Login successful")
    #                         ctx = get_integration_context()
    #                         if ctx.get("refresh_token"):
    #                             data["refresh_token"] = ctx.get("refresh_token")
    #                             data["grant_type"] = "refresh_token"
    #                             demisto.debug("New refresh token")
    #                         else:
    #                             demisto.debug("No refresh token")
    #                         res = super()._http_request(
    #                         method="POST",
    #                         url_suffix=OAUTH_URL, resp_type="response", headers=headers, data=data, ok_codes=ok_codes
    #                         )
    #                         demisto.debug("Request successful")
    #                         try:
    #                             res = res.json()
    #                         except ValueError as exception:
    #                             raise DemistoException(f"Failed to parse json object from response: {res.content}", exception)
    #                     except DemistoException as e:
    #                         ctx[TRIED_ONCE] = "True"
    #                         set_integration_context(ctx)
    #                         return_error(
    #                             f"Error occurred while creating an access token. Please check the Client ID, Client Secret "
    #                             f"and try to run again the login command to generate a new refresh token as it "
    #                             f"might have expired.\n{res}"
    #                         )
    #                 else:
    #                     return_error(
    #                                 f"Error occurred while creating an access token. Please check the Client ID, Client Secret "
    #                                 f"and try to run again the login command to generate a new refresh token as it "
    #                                 f"might have expired.\n{res}"
    #                             )
                        
    #             if res.get("access_token"):
    #                 demisto.debug("New access token received")
    #                 expiry_time = date_to_timestamp(datetime.now(), date_format="%Y-%m-%dT%H:%M:%S")
    #                 expiry_time += res.get("expires_in", 0) * 1000 - 10
    #                 new_token = {
    #                     "access_token": res.get("access_token"),
    #                     "refresh_token": res.get("refresh_token"),
    #                     "expiry_time": expiry_time,
    #                 }
    #                 set_integration_context(new_token)
    #                 return res.get("access_token")
    #         except Exception as e:
    #             return_error(
    #                 f"Error occurred while creating an access token. Please check the instance configuration.\n\n{e.args[0]}"
    #             )

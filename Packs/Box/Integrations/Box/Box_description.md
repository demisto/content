Note: the following stages should be done in less than 30 seconds due to Box security.
1. Create a new Box instance
2. In your browser, copy the following line containing Demisto application client id:
https://account.box.com/api/oauth2/authorize?response_type=code&client_id=hznnisyhdf09nu9saf2eyfzupawrn9b2&state=lulubalulu
(client_id is demisto-application client id)
3. Allow access to it using your box credentials
4. You will be redirected to a non active page, with a url in this form:
https://localhost/?state=lulubalulu&code=MCTNCsN1gJIjA2cEJ72nczpXzcLVVQxJ
5. Copy the code from the url and use it the the next step
6. Run box_initiate command with access_code argument in the CLI in this form:
!box_initiate access_code=ACCESS_CODE
For additional info you may watch https://www.youtube.com/watch?v=ha26tN8amI0
Or read about box oauth2 process at https://developer.box.com/guides/authentication/oauth2
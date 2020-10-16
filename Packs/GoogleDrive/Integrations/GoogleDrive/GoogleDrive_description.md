# Configure an API account on Google Drive
Configure a Service Account and retrieve it's key in JSON format by following the steps mentioned here: [https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount) 
Provide at least one of the scopes mentioned for each command.
### Commands and it's scopes
* google-drive-create 
	*  https://www.googleapis.com/auth/drive 
* google-drive-activity-list 
	* https://www.googleapis.com/auth/drive.activity 
	* https://www.googleapis.com/auth/drive.activity.readonly 
* google-drive-changes-list 
	* https://www.googleapis.com/auth/drive   
	* https://www.googleapis.com/auth/drive.file
	* https://www.googleapis.com/auth/drive.readonly
	* https://www.googleapis.com/auth/drive.metadata.readonly 
	* https://www.googleapis.com/auth/drive.appdata
	* https://www.googleapis.com/auth/drive.metadata
	* https://www.googleapis.com/auth/drive.photos.readonly

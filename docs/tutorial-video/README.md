# Overview
This article is meant to accompany the "Getting Started" video. Follow along with the video to gain deeper insights into getting started with Demisto.

[![Getting Started](https://img.youtube.com/vi/bDntS6biazI/0.jpg)](https://youtu.be/bDntS6biazI)

## Welcome

>*First and foremost, I want to welcome you to the Demisto team. We are excited to have you and we look forward to working with you. Please note that this tutorial assumes that you have a working instance of Demisto.*

The code we will be writing will be available in segments as we go along, as well as in it's entirety at the end.

## Navigating to BYOI

![byoi](https://user-images.githubusercontent.com/42912128/50827466-30922280-1347-11e9-9eb1-cac42ed62e17.png)

>*This is the Settings dashboard and it is where we configure and create new integrations. To start, let’s click this blue button that says BYOI, or Bring Your Own Integration.*

If this option is unavailable for you, it means that you do not have the proper permissions required for this tutorial. Please reach out to your Admin for assistance.

## The Demisto IDE

>*Here we see the Demisto IDE. This more than likely looks different than other IDEs you may have previously worked with, So, let’s take a minute and point out what makes it different.*

While the Demisto IDE has many features, you may wish to pre-write your code in a standalone IDE such as Pycharm or IntelliJ.

## Script Helper

![scripthelper](https://user-images.githubusercontent.com/42912128/50827566-76e78180-1347-11e9-9dbd-b97b6b54897c.png)

>*One of the greatest tools you will have while creating your integration is the Script Helper. The script helper is a library of all of the different common server functions within Demisto. If you want to format a table, manipulate data, or post something to the war room; more often than not, there is a function for it here.*

The script helper assists you in many functions. Generally if a function you created seems trivial, or you ask yourself "Why did I need to write that?" chances are it exists in the script helper. If not, let someone know! If you have come up with a brilliantly simple way to do something, it probably is needed and should be added to the common server functions.

## Integration Settings

>*We are going to create an English to Yoda translator today.*

This is meant to be a very simple integration that calls on an API much in the same way that other integrations work. While some things may seem silly, the function of calling an API, transforming data, and posting it to the war room, are all universal within Demisto.

We use the Yoda-Speak translate API available at [FunTranslations](https://funtranslations.com/api/yoda)

![basic_settings](https://user-images.githubusercontent.com/42912128/50823272-43532a00-133c-11e9-9aed-3f4813c4df4b.png)

>In the basic section, we have the ability to name an integration, add a description of it, and tell customers what type of integration it is. I’m going to name ours “Yoda Speak” and for the description, let’s put “Creating an Integration, we are”. Now since this is a Utility, we will select “Utilities” as the type.

The description should include basic details about the integration, common troubleshooting steps, and (if needed) how to set up the instance.

![fetches_incidents](https://user-images.githubusercontent.com/42912128/50823557-ef951080-133c-11e9-9109-72017c92d22e.png)

>If you notice, we also have a checkbox for “Fetches Incidents”. This setting tells demisto that our integration has a command called “fetch-incidents” and will need to run periodically. This feature is what makes Demisto so incredibly useful for our customers since it ingests events and turns them into Incidents in Demisto.

You can read about the fetching-incidents process [here](url). For simple APIs that return enrichment data, this may not be necessary, but for SEIMs, or other tools which report incidents, the fetch function is an absolute necessity.

>Since we are just translating something today, we don’t need to use this, but we will cover this in depth in another video. The last part is the logo. When we create an integration that is open to the public, we need to use an image that looks good. We recommend an image no larger than 4kb and in the PNG format. I have one ready that we will use, so I will drag it into the box.

![drag logo](https://user-images.githubusercontent.com/42912128/50828403-f9714080-1349-11e9-9d12-58b5b7fbd12f.png)

You may also choose to navigate to the PNG file by clicking the box to open the file browser.

## Parameters

>Next, we have the parameters section. This is where we add our global variables to the configuration for the integration.

![screen shot 2019-01-08 at 13 35 55](https://user-images.githubusercontent.com/42912128/50828554-61278b80-134a-11e9-84bb-566bc0a8810a.png)

Parameters are global variables which means that every command can/will use these configurable options in order to run. Some common parameters are API keys, Usernames, Endpoints, and Proxy options.

>Since we are using an API for this integration, we need to set up the proxy settings, allow for insecure requests, and if we use an API key, get that ready as well.

>We will call the first one, “proxy” and give it the Boolean type. The initial value we are going to set as “false” and for the display name we will write “Use system proxy”. 

The following is an example of the proxy settings filled out:

![screen shot 2019-01-08 at 13 38 33](https://user-images.githubusercontent.com/42912128/50828680-b82d6080-134a-11e9-895d-224cb0420bfa.png)

>Next we will add the insecure setting called “insecure”. This will also be a boolean. Set the initial value to “false” as well and we will write “Trust any cert”.

When you are done, it should look like the following:

![screen shot 2019-01-08 at 13 41 01](https://user-images.githubusercontent.com/42912128/50828793-0f333580-134b-11e9-8a41-88d98f25a4f5.png)

>We will also add “url”. This will be a “short text” and needs to be required. For the default value, let’s use the API endpoint and write “API url” for the description.

This section should look like this:

![screen shot 2019-01-08 at 13 41 34](https://user-images.githubusercontent.com/42912128/50828824-22de9c00-134b-11e9-8822-6f8f261781e4.png)

>Lastly, we add “apikey”. This will be “encrypted” and have no default value.

![screen shot 2019-01-08 at 13 42 57](https://user-images.githubusercontent.com/42912128/50828885-53263a80-134b-11e9-8011-8a763680b04d.png)

We want to make sure that the Display Name is added to the parameter options since it is a chance to explain what the function will do.

## Command Settings

>We are now ready for our main command. Before we start coding, let’s configure it in the settings. Let’s open up settings and go to commands. Click Add command, and lets name this “yoda-speak-translate”.

Command names should follow the convention "brand-function". For example, Virus Total has a function to add a comment to a scan. That function looks like this: ```vt-comments-add```. There are some cases where a command name will be different than the code conventions. An example of this is where a integration may share the same command as other integrations as part of an enrichment command such as ```!ip ip=8.8.8.8```. This command can trigger many different integrations to fire which of course, we plan for.

![screen shot 2019-01-08 at 13 45 00](https://user-images.githubusercontent.com/42912128/50828971-9da7b700-134b-11e9-93cc-de958768e74d.png)

>It will take the argument “Text”. Let’s also mark this as mandatory and for the description write “Text to translate”

![screen shot 2019-01-08 at 13 48 43](https://user-images.githubusercontent.com/42912128/50829134-258dc100-134c-11e9-942b-9af1b86bef54.png)

Arguments are similar to Parameters in that they are configurable by a user, but unlike parameters, arguments are single use only and specific to only one command. **Arguments are not shared with other commands and must be present for each command.**

>For outputs, lets make it so that we can see the translation in the context by adding “YodaSpeak.TheForce.Translation” to the context path. We name it this way to follow the Demisto Context Convention of “Brandname.Object.Property“. For description we will write “Translation, this is” with the type set as “string”

![screen shot 2019-01-08 at 13 53 36](https://user-images.githubusercontent.com/42912128/50829327-d4ca9800-134c-11e9-89b5-a92a6def4922.png)

Context is incredibly important as it allows information to become part of the incident. When you have information stored in the context, you can begin to run playbooks and other integrations on the same incident.

>Now we are ready to write some code. Let's start with our imports. I’m going to be using JSON, Collections, as well as Requests. 

```python
import requests
import json
import collections
```
These packages are part of the standard Demisto docker image. If you would like to use python libraries that are not part of the standard Demisto image, you can create your own image. To learn how to do so, [visit this page](url)

>This part allows us to ignore certificate warnings and is part of the “insecure” setting.

```python
# disable insecure warnings
requests.packages.urllib3.disable_warnings()
```

This applies to the "insecure" parameter we created earlier and helps the OS from displaying the "Insecure" dialog box commonly present when accessing an insecure resource.

>First, I am going to add some of our global variables. Notice how they are all named in all caps. This is part of our [Demisto Code Standards](url) and is used to distinguish them from “Arguments” which are not capitalized. I can use parameters in any command within the integration which is why we call them “Global”

```python
BASE_URL = demisto.params().get('url')
INSECURE = demisto.params().get('insecure')
PROXY = demisto.params().get('proxy')
API_KEY = demisto.params().get('apikey')
URL_SUFFIX = 'yoda'
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']
```

These are the same Parameters we created earlier. See the connection between the settings and global variables here?

![params](https://user-images.githubusercontent.com/42912128/50829961-de54ff80-134e-11e9-8a85-d5b1bb24e246.png)

>Next, I put in our execution block. This part tells Demisto that when a command is called in the war room or a playbook, which specific function we need to run.

```python
''' EXECUTION '''
LOG('command is %s' % (demisto.command(), ))
try:
    if demisto.command() == 'yoda-speak-translate':
        translate_command()
except Exception, e:
    demisto.debug('The Senate? I am the Senate!')
    LOG(e.message)
    LOG.print_log()
    return_error(e.message)
```

It's important to wrap the execution block in a "try catch" as per the code standards. This bloack is what will hold every command that our integration is capable of. Even including the ```fetch incidents``` command and the ```test``` command.

>For example, when someone types ```!yoda-speak-translate```, We want the translate command to fire. So underneath the command, I will add the ```translate_command``` function. Let’s open back up the settings menu and connect some dots.

```python
def translate_command():
```

>Here in commands, we see the command name we put in earlier. This part of our code, glues together the configuration with the actual code.

![commands](https://user-images.githubusercontent.com/42912128/50830395-5cfe6c80-1350-11e9-9284-0e30836cf885.png)

The command name has to be the exact same as the name entered in the execution block. 

>Next we need our translate command and translate functions. The translate command function is where we will handle our context, pass arguments, and build a human readable output. We need a way to take an input from the war room so we can translate it. So I will create an Argument called “Text”. This is the same argument name we wrote in the settings menu.

```python
def translate_command():
    text = demisto.args().get('text')
```

>We will pass this argument back to our translate function as a variable.

This is part of the Demisto Code Convention which states that arguments are to reside only within the command function. This ensures that if other commands need to use the same code, that the arguments are always available.

```python
'''MAIN FUNCTIONS'''
def translate(text):
```

>Let’s work on the translate function. This is where we make our API calls, handle any business logic, and do any filtering of results. This function will accept the “Text” variable we created earlier and will return the response from the API.

The main function should handle all major aspects of the command and return the data needed. It is the job of the ```translate_command``` function to prepare the data for import into Demisto.

```python
'''MAIN FUNCTIONS'''
def translate(text):
    query = { 'text': text }
    search = json.dumps(query)
    r = http_request('POST', URL_SUFFIX, search)
    return r
```

>I’m going to add a helper function up here to handle the API call.

Try to separate the functions as best as possible. We don't like having duplicate code, so if necessary, create helper functions as needed.

```python
'''HELPER FUNCTIONS'''
def http_request(method, URL_SUFFIX, json=None):
    if method is 'GET':
        headers = {}
    elif method is 'POST':
        if not API_KEY:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        else:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-FunTranslations-Api-Secret': API_KEY
            }
    r = requests.request(
        method,
        BASE_URL + URL_SUFFIX,
        data=json,
        headers=headers,
        verify=INSECURE
    )
    if r.status_code is not 200:
        return_error('Error in API call [%d] - %s' % (r.status_code, r.reason))
    return r.json()
```

>Since this function could fail on a bad API call, we need to handle the errors. Typically we would raise an error, but this wouldn’t give us much information other than the stack trace. So we will use a function from the script helper called “return_error” and pass along the error message that way.

This follows the Demisto Code Convention which states that we do not "Raise" errors. The reason behind this is that if the function were to fail, a user would only see the stack trace and not the error itself.

![screen shot 2019-01-08 at 14 53 36](https://user-images.githubusercontent.com/42912128/50831927-37c02d00-1355-11e9-89eb-f58507f46027.png)

>I’ll also add in a function to make nested keys accessible here. This will help with formatting our data.

```python
# Allows nested keys to be accessible
def makehash():
    return collections.defaultdict(makehash)
```


>Now that we have data to work with, let's return to the command function and format the results.  Here we are opening two dictionaries. One for the human readable and another for the context. 

We will use the ```makehash()``` helper function for this part.

```python
def translate_command():
    text = demisto.args().get('text')
    contxt = makehash()
    human_readable = makehash()
    res = translate(text)
    contents = res['contents']
```

>Let's create a table out of the human_readable dictionary so the translation will look nice in the war room. Go to the Script Helper and let’s select tableToMarkdown. Click “Copy to Script”. We will call this table “Yoda says…” and give the function our dictionary.

tableToMarkdown accepts many different variables which can be used to transform data, remove null, and create custom headers. Learn more about this [command here](url)

```python
    ec = {'YodaSpeak.TheForce(val.Original && val.Original == obj.Original)': contxt}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': res,
        'HumanReadable': tableToMarkdown('Yoda Says...', human_readable),
        'EntryContext': ec
    })
```

>For the Context, we can make sure we only update new information by adding this part.



The ```val.Original && val.Original == obj.Original``` part works to update entries within the context. So using the example, the value of the context key "Original" is matched where the value of our context object is equal.

>Okay, it looks like we are done with our translate code, but let’s also add a test function so we can see if the integration fails. I’ll add another command in the execution block called “test-module”. You don’t need to add a command for this in the settings since it is a built in command. Since the test command does not accept arguments, we need to create a text string for the translate function to test. So I will create one here and pass it to the translate command. Since we already handled errors in this command, I don’t have to do anything special. Lastly, we return “ok”. This lets Demisto know that the integration is working correctly.

When we test an integration, we are testing for the health of the connection. Customers and users alike will usually test their integration before heading to the war room to start working. To test the health of this integration we test that the HTTP status code returns as 200.

```python
    elif demisto.command() == 'test-module':
        text = 'I have the high ground!'
        translate(text)
        demisto.results('ok')
```


>Looks like we are ready to test this out. 

Your final code should look like the following:
```python
import requests
import json
import collections
# disable insecure warnings
requests.packages.urllib3.disable_warnings()


PROXY = demisto.params().get('proxy')
INSECURE = demisto.params().get('insecure')
BASE_URL = demisto.params().get('url')
API_KEY = demisto.params().get('apikey')
URL_SUFFIX = 'yoda'
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


'''HELPER FUNCTIONS'''
def http_request(method, URL_SUFFIX, json=None):
    if method is 'GET':
        headers = {}
    elif method is 'POST':
        if not API_KEY:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        else:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-FunTranslations-Api-Secret': API_KEY
            }
    r = requests.request(
        method,
        BASE_URL + URL_SUFFIX,
        data=json,
        headers=headers,
        verify=INSECURE
    )
    if r.status_code is not 200:
        return_error('Error in API call [%d] - %s' % (r.status_code, r.reason))
    return r.json()


# Allows nested keys to be accesible
def makehash():
    return collections.defaultdict(makehash)


'''MAIN FUNCTIONS'''
def translate(text):
    query = { 'text': text }
    search = json.dumps(query)
    r = http_request('POST', URL_SUFFIX, search)
    return r


def translate_command():
    text = demisto.args().get('text')
    contxt = makehash()
    human_readable = makehash()
    res = translate(text)
    contents = res['contents']
    if 'translated' in contents:
        human_readable['Original'] = text
        human_readable['Translation'] = contents['translated']
        contxt['Original'] = text
        contxt['Translation'] = contents['translated']
    ec = {'YodaSpeak.TheForce(val.Original && val.Original == obj.Original)': contxt}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': res,
        'HumanReadable': tableToMarkdown('Yoda Says...', human_readable),
        'EntryContext': ec
    })


''' EXECUTION '''
LOG('command is %s' % (demisto.command(), ))
try:
    if demisto.command() == 'yoda-speak-translate':
        translate_command()
    elif demisto.command() == 'test-module':
        text = 'I have the high ground!'
        translate(text)
        demisto.results('ok')
except Exception, e:
    demisto.debug('The Senate? I am the Senate!')
    LOG(e.message)
    LOG.print_log()
    return_error(e.message)
```

>Click the save button and then the “X”. 

In some cases, if you had the integration open in two different tabs, you may run into an error where the changes will not be saved. The only current solution for this is to copy and save the playbook on your clipboard, close both tabs, and then open only one tab.


>Now we will search for Yoda and click “add instance”. 

![add instance](https://user-images.githubusercontent.com/42912128/50833113-e74ace80-1358-11e9-8969-b82959356bd9.png)



>We don’t need a proxy, or insecure, so we will leave them on their defaults. I do have an apikey, but since we marked the type as “Encrypted” it displays as stars here. Lastly, the url.

<img width="393" alt="screen shot 2019-01-08 at 15 21 36" src="https://user-images.githubusercontent.com/42912128/50833193-1eb97b00-1359-11e9-9d00-bf46fa52c37f.png">


>Remember the test function we put into our integration? Lets hit “test” and see if it works. 

![test](https://user-images.githubusercontent.com/42912128/50833314-70620580-1359-11e9-99cd-704f59dc67d3.png)

>Opps, looks like it failed since we entered the url incorrectly. Lets test it again. Perfect. Looks like it's working. 

![screen shot 2019-01-08 at 17 26 40](https://user-images.githubusercontent.com/42912128/50840340-efac0500-136a-11e9-9432-dc3457d7cfd1.png)

>Click done and let’s head to the war room. Type ```!yoda-speak-translate``` and lets enter “Hello, My name is Andrew. We are learning about integrations”

<img width="979" alt="screen shot 2019-01-08 at 15 25 26" src="https://user-images.githubusercontent.com/42912128/50833385-a7381b80-1359-11e9-9c3a-3b376a993d2c.png">


>Perfect! Looks like it works. Here we see our table that we created.

<img width="1339" alt="screen shot 2019-01-08 at 15 26 28" src="https://user-images.githubusercontent.com/42912128/50833437-cfc01580-1359-11e9-9880-1a53562542dc.png">


>Let’s also see the context. 

![context](https://user-images.githubusercontent.com/42912128/50840432-37cb2780-136b-11e9-8c2a-c56fa87a57b9.png)


>Notice how “YodaSpeak” is the root for “The Force”? If the translation would change the next time we fire the command, it will update the translation field here.

<img width="516" alt="screen shot 2019-01-08 at 15 27 24" src="https://user-images.githubusercontent.com/42912128/50833475-ebc3b700-1359-11e9-96f5-2f45c3eff27e.png">

>But what is an integration without a playbook? Let’s make one real quick. Click “Playbooks” and click the blue button that says “New playbook”.

![playbook_menu](https://user-images.githubusercontent.com/42912128/50833581-5248d500-135a-11e9-941f-bd27964168d8.png)

>We will call this one “Yoda Speak”. In the task library, search for “Yoda” and we should see our integration. Select it and click “Add” where it says “yoda-speak-translate”.

<img width="537" alt="screen shot 2019-01-08 at 15 32 15" src="https://user-images.githubusercontent.com/42912128/50833654-9b008e00-135a-11e9-9e08-f1d51f1dc52a.png">


>I want this playbook to translate the details field in an incident into yoda speak, so for “text” we will click the brackets right here. 

![brackets](https://user-images.githubusercontent.com/42912128/50833717-d69b5800-135a-11e9-85f5-81b6a1dd1e8c.png)

>Next select incident details and click on “Details”.

![details](https://user-images.githubusercontent.com/42912128/50833826-24b05b80-135b-11e9-8d18-3ee1d52301c1.png)

>Go ahead and click “Close” and “OK”.

This saves your changes. If you do not click close and okay, your changes will not be saved in the playbook.

>Now let’s have the playbook print the translation in the war room. In the task library search for “print” under “Utilities”.

![print_add](https://user-images.githubusercontent.com/42912128/50833982-8b357980-135b-11e9-9d0e-0d85834e3c65.png)

>For the value click the brackets. Notice how we have an entry here for the yoda speak translation? If we click it, we can select the translation context that we specified in the integration settings.

![print_settings](https://user-images.githubusercontent.com/42912128/50834106-e1a2b800-135b-11e9-892f-a00c74b949f6.png)

>Click “Close” and “OK”. Lastly, hit the save button and click the “X”.

Again we must commit our changes to the playbook.

We need to connect the two tasks together. Do so by dragging an arrow from the bottom of the translate task to the top of the print task.

![connect](https://user-images.githubusercontent.com/42912128/50840624-94c6dd80-136b-11e9-832e-0a745b2d754a.png)


>Let’s see it in action. Click “Incidents” and then press the blue button that says “New Incident”.

![incidents](https://user-images.githubusercontent.com/42912128/50834260-3cd4aa80-135c-11e9-80f7-39d80d55d7e9.png)

>I’m going to name this “That’s no moon… It’s a Space station!” and for the details, lets type “The prequel movies are more entertaining than the new Disney movies”. 

You also need to select which playbook to attach to the incident. In this case, we would attach the "yodaspeak" playbook.

<img width="1350" alt="screen shot 2019-01-08 at 15 46 39" src="https://user-images.githubusercontent.com/42912128/50834429-a6ed4f80-135c-11e9-9029-40c130be7371.png">

>Click “Create new Incident” and select the incident we just created. Navigate to “work plan” and we can see that our playbook worked!

![screen shot 2019-01-08 at 16 09 53](https://user-images.githubusercontent.com/42912128/50835627-e49fa780-135f-11e9-8c96-8c3e138d6a9b.png)
## Resources

[YodaSpeak Tutorial Pack.zip](https://github.com/demisto/etc/files/2737100/YodaSpeak.Tutorial.Pack.zip)

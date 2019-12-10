# Playbook Conventions & Standards
## Introduction
To keep playbook consistency, usability and readability, we've created some conventions and standards for our playbooks. We will also cover some common mistakes.
Please make sure your playbooks meet these standards.

## Wording
### playbooks
 - Names are **T**itle **C**ase.
 - Before specifying whether the playbook is generic or of a certain integration, add a dash (-).
 - Before adding "Test", add a (dash), but add it only at the very end of the name
 
 ![image](https://user-images.githubusercontent.com/43602124/62224827-f8742f00-b3bf-11e9-857e-5f216297aee1.png)
![image](https://user-images.githubusercontent.com/43602124/62224883-0f1a8600-b3c0-11e9-910e-03a86c7456d7.png)

-   When there is a second version (v2) playbook and you want to create a test for it, make sure the " - Test" is at the end, since you're testing a second version, and not creating a second version of a test for the older playbook


![image](https://user-images.githubusercontent.com/43602124/62225909-fa3ef200-b3c1-11e9-9e66-d96ce7fefbde.png)

-   In the descriptions of playbooks specify the supported integrations or file types.
-   File formats are always in capital letters.
-   Integration names capitalized according to **T**itle **C**ase.


![image](https://user-images.githubusercontent.com/43602124/62228872-2e68e180-b3c7-11e9-9de3-ea21c0e3c866.png)
![image](https://user-images.githubusercontent.com/43602124/62228877-3032a500-b3c7-11e9-8644-17278aa24870.png)


### Tasks
-   In task names - first letter is capitalized. The rest of the name is according to grammar rules, so capitalize the first letter of every part of an integration's name for example.
-   Verbs: use "Save" rather than "Saves" or "Saving", in the task names


![image](https://user-images.githubusercontent.com/43602124/62226474-f3fd4580-b3c2-11e9-94be-4ef28a6e5591.png)
![image](https://user-images.githubusercontent.com/43602124/62226484-f6f83600-b3c2-11e9-8e99-0cdc8117ee7e.png)

-   Conditions end with a question mark. Also - "Is there a file" is better than "are there files" or "do we have a file" or "does a file exist".


![image](https://user-images.githubusercontent.com/43602124/62226641-2a3ac500-b3c3-11e9-97b6-546aab935487.png)
![image](https://user-images.githubusercontent.com/43602124/62226647-2c9d1f00-b3c3-11e9-82d5-63a637b2c23e.png)
![image](https://user-images.githubusercontent.com/43602124/62226658-3030a600-b3c3-11e9-826a-5104ed3a1a18.png)
![image](https://user-images.githubusercontent.com/43602124/62226668-36268700-b3c3-11e9-9d71-b4479696422f.png)


-   Descriptions of tasks, unlike names of tasks use "extracts", "takes" and so on. For conditions: "Checks / Determines if / whether"). Always periods at the end.
-   We prefer to use “Determines” for “flags” - playbook inputs that affect the playbook flow / decision making. For simple conditions, usually use “Checks”.
Notice how the W in "Word" is capitalized because it's a name of a program

![image](https://user-images.githubusercontent.com/43602124/62228424-4f7d0280-b3c6-11e9-8bee-47808ec59d31.png)
![image](https://user-images.githubusercontent.com/43602124/62228435-53a92000-b3c6-11e9-9434-f1201e247f62.png)
![image](https://user-images.githubusercontent.com/43602124/62228472-628fd280-b3c6-11e9-838c-285e68ec4661.png)
![image](https://user-images.githubusercontent.com/43602124/62228481-66235980-b3c6-11e9-95da-46b12ab243ff.png)


## Mistakes / Commonly Overlooked

-   Specify `auto-extract` settings for **every possible task** in the "Advanced" tab (tasks such as conditions or section headers don't support this). Rule of thumb: set to None, unless the data printed to war room contains crucial indicators.
(! `auto-extract` is a feature in Demisto that takes all outputs from a command and extract indicators from them)


![image](https://user-images.githubusercontent.com/43602124/62229068-97505980-b3c7-11e9-9c80-18b6f84ba90c.png)
![image](https://user-images.githubusercontent.com/43602124/62229072-991a1d00-b3c7-11e9-9486-e481096bd2db.png)
![image](https://user-images.githubusercontent.com/43602124/62229081-9d463a80-b3c7-11e9-8602-ece4e593fa57.png)


-   When outputting to context in integrations or scripts, use generic descriptions. For example, "Extract Indicators From File - Generic v2" has 2 different tasks outputting to "File.Text", but in the playbook outputs we have a description for only one.


![image](https://user-images.githubusercontent.com/50324325/67759127-9622dd00-fa47-11e9-90d5-a88c616bd8fe.png)

![image](https://user-images.githubusercontent.com/50324325/67759239-c9656c00-fa47-11e9-803b-a18005c63b52.png)




-   Set defaults for playbook inputs when needed

<img src="https://user-images.githubusercontent.com/50324325/67758301-18aa9d00-fa46-11e9-84e9-cba48d639766.png" width="300" height="100">

![image](https://user-images.githubusercontent.com/50324325/67759434-121d2500-fa48-11e9-871b-dac447da1b8e.png)


-   The playbooks are used by everyone, try to avoid “programming terms" when possible.

-   When working with indicators or data that should be unique, make sure to use “Uniq” (or “Unique” in 5.0) transformers to prevent as many duplications as possible. Do it in playbook inputs as well.


![image](https://user-images.githubusercontent.com/43602124/62229766-1f832e80-b3c9-11e9-8ac3-6cb48a132c1f.png)
![image](https://user-images.githubusercontent.com/43602124/62229771-21e58880-b3c9-11e9-8d85-c82c0c895252.png)

-   Avoid using [DT](https://github.com/demisto/content/tree/master/docs) wherever things can be done without it. Use our user friendly selectors and transformers, both because it looks better, and because you can add filters / operations to it.

![image](https://user-images.githubusercontent.com/50324325/67759623-76d87f80-fa48-11e9-9dc7-3f8d5ef4341c.png)
![image](https://user-images.githubusercontent.com/50324325/67759719-a5565a80-fa48-11e9-9a91-b5ce555197d4.png)

* Also, it prevents a common mistake where data is passed by value instead of reference:

![image](https://user-images.githubusercontent.com/50324325/67759760-bb641b00-fa48-11e9-82a0-e028e50efa02.png)

One place where this won’t work, is when using `Set`, which sets a value to an output, where you cannot really “get” that key, since it doesn’t exist.

-   Use “ignore case” when checking user inputs (such as True / False in playbook inputs)
![image](https://user-images.githubusercontent.com/50324325/68272945-d4368700-006d-11ea-89a1-fea10c525186.png)

* Remember to confirm task changes in **ALL RELEVANT SUB-WINDOWS**. Do not cancel, do not switch task, or the changes won't be saved, and you won't always get a warning about it!

-   If you’re working on a playbook that has a sub-playbook, and you changed the inputs / outputs of that sub-playbook, the changes won’t be reflected in the parent playbook. You must refresh the page to see the changes. not just saving the playbook and re-opening it, using the browser refresh (F5) to refresh.

## Visualising

-   Group similar tasks
-   Align tasks / headers of the same level
-   The priority in playbook looks is: **understanding of flow > readability of lines > aesthetics**
-   Avoid headers as timer starters / stoppers
-   Align the arrows and avoid "breaks". Sometimes moving a task and putting it back where it was can fix it. If necessary, utilize section headers to assist arrangement and to keep lines readable

Example - before:


![image](https://user-images.githubusercontent.com/43602124/62230489-9240d980-b3ca-11e9-8a88-2d5928888fac.png)


Example - after (moved all endpoint products to the right, and freed space for the "Else" line):

![image](https://user-images.githubusercontent.com/43602124/62230511-9ec53200-b3ca-11e9-8d75-2f4a59b71f1a.png)



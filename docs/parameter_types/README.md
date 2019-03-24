## Integration Parameter Types

When adding a parameter to an integration in Demisto, there are numerous types to choose from.
Each type will effect the parameter behavior and interaction with the user. 

### Boolean

This type of parameter creates a check box in the integration configuration. When the check box is ticked, the value in
the integration code would be `True`, and `False` otherwise.
Example:
![image](https://user-images.githubusercontent.com/35098543/54881985-48654700-4e5e-11e9-8e1c-7a95d1b84328.png)

![image](https://user-images.githubusercontent.com/35098543/54881975-2966b500-4e5e-11e9-87c7-b9f2eadeef5d.png)

Access: `demisto.params().get('proxy')` 

### Short Text

This type of parameter is used for short input parameters, such as server URLs, ports or queries. It creates a small
sized text box in the integration configuration.

![image](https://user-images.githubusercontent.com/35098543/54881995-616df800-4e5e-11e9-8f15-475422b97066.png)

![image](https://user-images.githubusercontent.com/35098543/54882043-ac880b00-4e5e-11e9-9b59-8cb0f08594d4.png)

Access: `demisto.params().get('url')`

### Long Text

This type of parameter is used for long text inputs, such as certificates. It creates a large sized text box in the 
integration configuration.

![image](https://user-images.githubusercontent.com/35098543/54882097-4a7bd580-4e5f-11e9-80d7-4db8859bbab4.png)

![image](https://user-images.githubusercontent.com/35098543/54882114-68493a80-4e5f-11e9-89a0-1d2a7106980f.png)

Access: `demisto.params().get('cert')`

### Encrypted

This type of parameters is used for encrypted inputs, such as API tokens. This should not be used for username-password 
credentials however. It creates a small sized text box with an encrypted text, which would also be stored encrypted in
the database. 

![image](https://user-images.githubusercontent.com/35098543/54882368-f7575200-4e61-11e9-86e4-c5e33948f35e.png)

![image](https://user-images.githubusercontent.com/35098543/54882405-51581780-4e62-11e9-86a4-293c3eb59cbc.png)

Access: `demisto.params().get('token')`

### Authentication

This type of parameter is used for username-password credentials - username as plain text and an encrypted password. 
It supports retrieving credentials from the Demisto credentials store(more info on the credentials store can be found in
the Demisto support portal).

![image](https://user-images.githubusercontent.com/35098543/54882618-89f8f080-4e64-11e9-8bbc-e4974c9466a5.png)

![image](https://user-images.githubusercontent.com/35098543/54882634-ae54cd00-4e64-11e9-9194-ec7bee84ca76.png)

Access: 

Username: `demisto.params().get('credentials', {}).get('identifier')`

Password: `demisto.params().get('credentials', {}).get('password')`

### Single Select

This type of parameter is used to allow selecting a single input from a list of allowed inputs. 

![image](https://user-images.githubusercontent.com/35098543/54883090-3ee1dc00-4e6a-11e9-88b7-5bbce20702d9.png)

![image](https://user-images.githubusercontent.com/35098543/54883094-591bba00-4e6a-11e9-8066-945d82bba1e4.png)

Access: `demisto.params().get('log')`

### Multi Select

This type of parameter is used to allow selecting multiple inputs from a list of allowed inputs.

![image](https://user-images.githubusercontent.com/35098543/54883128-d810f280-4e6a-11e9-94b6-cd6dc43987e9.png)

![image](https://user-images.githubusercontent.com/35098543/54883139-f4ad2a80-4e6a-11e9-85c4-4eef17ab75ac.png)

Access: `demisto.params().get('sort')`

## Important Note

Once a parameter is set in an integration configuration, it is saved to the Demisto database, so before changing an existing
parameter you have to consider the existing values (backward compatibility).




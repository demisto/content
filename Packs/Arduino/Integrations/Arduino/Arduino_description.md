## Arduino
- To configure the integration, simply provide the IP / hostname and port number of the Arduino device that is listening. The code below is an example of what should be running on the Arduino to receive requests from XSOAR.

---

#### Example Arduino Code

---

```c
#include <SPI.h>
#include <WiFi.h>
#include "arduino_secrets.h"

char ssid[] = SECRET_AP;          // your network SSID (name) - This is defined in the "arduino_secrets.h" file
char pass[] = SECRET_KEY;         // your network password  - This is defined in the "arduino_secrets.h" file
IPAddress myAddress;

/*
   An example of the "arduino.secrets.h" file would be

  #define SECRET_AP "myWiFiNetwork"
  #define SECRET_KEY "myWiFiPassword"

*/

int status = WL_IDLE_STATUS;
int port = 9090;                  // Default port number to listen on

WiFiServer server(port);

void setup() {
  Serial.begin(9600);             // Start a Serial connection
  //while(!Serial);               // Uncomment to wait until Serial connection is available
    
  Serial.print("Attempting to connect to SSID: ");
  Serial.println(ssid);
  status = WiFi.begin(ssid, pass);
  if ( status != WL_CONNECTED) {
    Serial.println("Couldn't get a wifi connection");
    while (true);
    // don't do anything else:
  }

  Serial.print("Connected to ");
  Serial.println(ssid);
  myAddress = WiFi.localIP();
  Serial.print("My IP is: ");
  Serial.println(myAddress);
  Serial.print("Starting listener on port ");
  Serial.println(port);
  server.begin();

}

void loop() {
  WiFiClient client = server.available();
  if(client){
    if (client.connected()){
      Serial.print("Received: ");
      String received;
      int available_bytes = client.available();
      for (int x = 0; x < available_bytes; x++){
        char t = client.read();
        received = received + t;
      }
      Serial.println(received);
      handle_data(&client, &received);
    }
    client.stop();
  }
  delay(10);
}

void handle_data(WiFiClient *client, String *received){
  if (received->startsWith("test")){                    // This is required for the XSOAR "test" button
    client->print("Response:");
  }
  else if (received->startsWith("set")){                // This is required for the XSOAR arduino-set-pin command
    set_pin(client, received);
  }
  else if (received->startsWith("get")){                // This is required for the XSOAR arduino-get-pin command
    get_pin(client, received);
  }
  else {
    handle_text(client, received);                      // This is required for the XSOAR arduino-send-data command
  }
}

void set_pin(WiFiClient *client, String *received){
  int first_colon = received->indexOf(":");
  int second_colon = received->indexOf(":", first_colon + 1);
  int first_comma = received->indexOf(",");
  String pin_type = received->substring(first_colon + 1, second_colon);
  String pin_num_string = received->substring(second_colon + 1, first_comma);
  String set_value_string = received->substring(first_comma + 1);
  uint16_t set_value = set_value_string.toInt();
  int pin_number = pin_num_string.toInt();
  uint16_t pin_value;
  if (pin_type.equals("digital")){
      digitalWrite(pin_number, set_value);
  }
  else {
    analogWrite(pin_number, set_value);
  }
  client->print(set_value);
}

void get_pin(WiFiClient *client, String *received){
  int first_colon = received->indexOf(":");
  int second_colon = received->indexOf(":", first_colon + 1);
  String pin_type = received->substring(first_colon + 1, second_colon);
  String pin_num_string = received->substring(second_colon + 1);
  int pin_number = pin_num_string.toInt();
  uint16_t pin_value;
  if (pin_type.equals("digital")){
      pin_value = digitalRead(pin_number);
  }
  else {
    pin_value = analogRead(pin_number);
  }
  client->print(pin_value);
}

void handle_text(WiFiClient *client, String *received){
  /*
   * This routine will be how you handle other text based information from the sender
   * By default, this just sends the data back to the sender
   */
   client->print(*received);
}
```

---

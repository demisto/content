## Setting up a local instance of Kafka

Use https://github.com/wurstmeister/kafka-docker


```
mkdir kafka-docker
cd kafka-docker
git clone https://github.com/wurstmeister/kafka-docker .
```
<!-- disable-secrets-detection-start -->
* Edit file `docker-compose-single-broker.yml`
* Change KAFKA_ADVERTISED_HOST_NAME to your machine's IP. Use `ifconfig | grep 'inet '` to see available ips. It is recommended to use an IP which doesn't change. Otherwise you will need to bring up again the cluster every time the ip changes. You can use the IP of global protect interface: gpd0. On my machine it has a value of: `10.196.100.168`.
* Start a Kafka cluster:
```
docker-compose -f docker-compose-single-broker.yml up
```

This will startup a kafka with a default topic named `test`.

## Configure an integration instance
* For the broker, set your machine IP address, the one set as KAFKA_ADVERTISED_HOST_NAME in the previous step, with addition of the port `9092`, e.g.  `10.196.100.168:9092`.

## Creating Additional Topics for Testing 
In the `kafka-docker` dir run the following to start a shell:
```
./start-kafka-shell.sh host.docker.internal host.docker.internal:2181
```
In the shell run:
* Create topic with 4 partitions: `$KAFKA_HOME/bin/kafka-topics.sh --zookeeper $ZK --create --topic mytest-topic --partitions 4 --replication-factor 1`
* Create topic with lz4 compression: `$KAFKA_HOME/bin/kafka-topics.sh --zookeeper $ZK --create --topic test-lz4  --replication-factor 1 --config compression.type=lz4 --partitions 1`
* List topics: `$KAFKA_HOME/bin/kafka-topics.sh --zookeeper $ZK --list`

### Producing 10 messages:
```
for i in `seq 1 10`; do echo '{"id":'$i',"user":"test","date":"'`date -R`'","message":"this is a test from kafka shell"}' | $KAFKA_HOME/bin/kafka-console-producer.sh --broker-list=`broker-list.sh` --topic mytest-topic; done
```
* Test consume of the messages (ctrl+c to exit): 
```
$KAFKA_HOME/bin/kafka-console-consumer.sh --bootstrap-server=`broker-list.sh` --topic mytest-topic --from-beginning
```

Recommend utility: `kafkacat`

* Install via: `brew install kafkacat`
* Then do to get messages: `kafkacat  -b localhost:9092 -t test -J`
* To send a message run: `echo "test message" | kafkacat  -b localhost:9092 -t test -J`

Another good cmdline client: https://github.com/fgeller/kt
* Install via: go get -u github.com/fgeller/kt
  
<!-- disable-secrets-detection-end -->

## Stop the cluster
Press control+c in the terminal running `docker-compose`. 
You can later on bring up the cluster with your configured topic by running: `docker-compose -f docker-compose-single-broker.yml up`

To full delete the cluster from the disk run: `docker-compose -f docker-compose-single-broker.yml down`. 

## Setting up the instance with SSL
Make sure Java versions match.

### Configure ca root - both for brokers and for clients
Make the dir to which the certificates will be saved

```mkdir certs```

Generate root CA key

```openssl genrsa -out root.key```

Generate root CA certificate:
  * Use a certain name when asked for Common Name (e.g. myname)
  * Press enter on the rest of the questions

```openssl req -new -x509 -key root.key -out root.crt```

### Configure the kafka brokers

Generate truststore for kafka server:
  * Enter a password when asked (e.g. 'abcdefgh') & re-enter it
  * Press 'y' when asked if you trust the certificate
 
```keytool -keystore kafka.truststore.jks -alias CARoot -import -file root.crt```

Generate keystore for the kafka broker:
  * Enter the password when asked (e.g. 'abcdefgh') & re-enter it
  * When asked for the first and last name enter the KAFKA_ADVERTISED_HOST_NAME (e.g. 10.133.713.371)
 
```keytool -keystore kafka01.keystore.jks -alias localhost -validity 365 -genkey -keyalg RSA```

Export the Kafka broker's certificate so it can be signed by the root CA
    * Enter the password when asked (e.g. 'abcdefgh') 

```keytool -keystore kafka01.keystore.jks -alias localhost -certreq -file kafka01.unsigned.crt```

Sign the Kafka broker's certificate using the root CA

```openssl x509 -req -CA root.crt -CAkey root.key -in kafka01.unsigned.crt -out kafka01.signed.crt -days 365 -CAcreateserial```

Import the root CA into the broker's keystore:
  * Enter the password when asked (e.g. 'abcdefgh') 
  * Press 'y' when asked if you trust the certificate

```keytool -keystore kafka01.keystore.jks -alias CARoot -import -file root.crt```

Import the signed Kafka broker certificate into the keystore:
  * Enter the password when asked (e.g. 'abcdefgh') 
 
```keytool -keystore kafka01.keystore.jks -alias localhost -import -file kafka01.signed.crt```

You have now created the files needed to configure the broker
1. ```path_to_certs/certs/kafka.truststore.jks```
2. ```path_to_certs/certs/kafka01.keystore.jks```

Edit the `docker-compose-single-broker.yml` to support ssl and restart the docker instance.

Example of `docker-compose-single-broker.yml`:

```
version: '2'
services:
  zookeeper:
    image: wurstmeister/zookeeper
    ports:
      - "2181:2181"
  kafka:
    build: .
    ports:
      - "9092:9092"
      - "9093:9093"
    environment:
      KAFKA_ADVERTISED_HOST_NAME: 10.133.713.371 # sec
      KAFKA_CREATE_TOPICS: "test:1:1"
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_LISTENERS: PLAINTEXT://:9092,SSL://:9093
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://127.0.0.1:9092,SSL://127.0.0.1:9093
      KAFKA_BROKER_ID: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: 'true'
      KAFKA_SSL_KEYSTORE_LOCATION: '/certs/kafka01.keystore.jks'
      KAFKA_SSL_KEYSTORE_PASSWORD: 'abcdefgh'
      KAFKA_SSL_KEY_PASSWORD: 'abcdefgh'
      KAFKA_SSL_TRUSTSTORE_LOCATION: '/certs/kafka.truststore.jks'
      KAFKA_SSL_TRUSTSTORE_PASSWORD: 'abcdefgh'
      KAFKA_SSL_CLIENT_AUTH: 'none'
      KAFKA_SSL_ENDPOINT_IDENTIFICATION_ALGORITHM: ''
      KAFKA_SECURITY_INTER_BROKER_PROTOCOL: 'SSL'
      KAFKA_SSL_KEYSTORE_TYPE: 'JKS'
      KAFKA_SSL_TRUSTSTORE_TYPE: 'JKS'
      KAFKA_SSL_ENABLED_PROTOCOLS: 'TLSv1.2,TLSv1.1,TLSv1'
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - path_to_certs/certs:/certs
```


### Configure kafka client certificate

Generate a key for the kafka client:

```openssl genrsa -out client.key```

Create a certificate request:
    * Use a certain name when asked for Common Name (e.g. myname)
    * Choose a password when asked for 'A challenge password' (e.g. abcdefgh)

```openssl req -new -key client.key -out client_reqout.txt```

Sign the certificate request with the root CA:

```openssl x509 -req -in client_reqout.txt -days 3650 -sha256 -CAcreateserial -CA root.crt -CAkey root.key -out client.crt```

You have now created the 3 needed files for Client connection:
1. root.crt - Will be used in the ```CA certificate of Kafka server (.cer)``` integration configuration
2. client.key - Will be used in the ```Client certificate (.cer)``` integration configuration 
3. client.crt - Will be used in the ```Client certificate key (.key)``` integration configuration
4. The last password which was chosen - Will be used in the ```Client certificate key password (if required)``` integration configuration 

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

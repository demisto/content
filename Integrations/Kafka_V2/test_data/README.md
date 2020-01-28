## Setting up a local instance of Kafka

Use https://github.com/wurstmeister/kafka-docker

```
git clone https://github.com/wurstmeister/kafka-docker .
```
<!-- disable-secrets-detection-start -->
* Edit file `docker-compose-single-broker.yml`
* Change KAFKA_ADVERTISED_HOST_NAME to your machine's IP. use `ifconfig | grep 'inet '` to see available ips. Recommneded to use an IP which doesn't change. Otherwise you will need to bring up again the cluster everytime the ip changes. You can use the IP of global protect interface: gpd0. On my machine it has a value of: `10.196.100.168`.
* Start a Kafka cluster:
```
docker-compose -f docker-compose-single-broker.yml up
```

Setup via shell:
Run the following to start a shell:
```
./start-kafka-shell.sh host.docker.internal host.docker.internal:2181
```
In the shell run:
* Create topic with 4 partitions: `$KAFKA_HOME/bin/kafka-topics.sh --zookeeper $ZK --create --topic mytest-topic --partitions 4 --replication-factor 1`
* List topics: `$KAFKA_HOME/bin/kafka-topics.sh --zookeeper $ZK --list`
* Produce 10 messages:
```
for i in `seq 1 10`; do echo '{"id":'$i',"user":"test","date":"'`date -R`'","message":"this is a test from kafka shell"}' | $KAFKA_HOME/bin/kafka-console-producer.sh --broker-list=`broker-list.sh` --topic mytest-topic; done
```
* Test consume of the messages (ctrl+c to exit): 
```
$KAFKA_HOME/bin/kafka-console-consumer.sh --bootstrap-server=`broker-list.sh` --topic mytest-topic --from-beginning
```

Recommend utility: `kafkacat`

* Install via: `brew install kafkacat`
* Then do: `kafkacat  -b localhost:9092 -t mytest-topic`

Another good cmdline client: https://github.com/fgeller/kt
* Install via: go get -u github.com/fgeller/kt
  
<!-- disable-secrets-detection-end -->

## Stop the cluster
Press control+c in the terminal running `docker-compose`. 
You can later on brin up the cluster with your configured topic by running: `docker-compose -f docker-compose-single-broker.yml up`

To full delete the cluster from the disk run: `docker-compose -f docker-compose-single-broker.yml down`. 

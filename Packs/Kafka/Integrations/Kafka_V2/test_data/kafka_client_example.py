import pykafka
from pykafka.common import OffsetType

# Example demonstrating how to fetch 5 messages and then fetch another 5 from the point we left off
# running using: python kafka_client_example.py


def consume_messages(topic, offsets, max):
    part_offset_dict = {}

    # default consumer starts from beginning
    consumer = topic.get_simple_consumer(
        consumer_timeout_ms=1000,
        queued_max_messages=100,
    )
    offsets = [(p, offsets.get(p.id, OffsetType.EARLIEST)) for p in consumer._partitions]
    consumer.reset_offsets(offsets)

    max = 5
    i = 0
    for msg in consumer:
        i += 1
        print('msg {}: partition: {}, offest: {}, value: {}'.format(i, msg.partition_id, msg.offset, msg.value))
        if msg.offset > part_offset_dict.get(msg.partition_id, OffsetType.EARLIEST):
            part_offset_dict[msg.partition_id] = msg.offset
        if i >= max:
            print("\nreached max messages. offsets received: {}\n".format(part_offset_dict))
            break

    consumer.stop()
    return part_offset_dict


# localhost works only on mac when connecting to a docker running kafka
client = pykafka.KafkaClient(hosts='localhost:9092')
print("topics: {}".format(client.topics))
topic = client.topics['mytest-topic']

last_offsets = consume_messages(topic, {}, 5)
consume_messages(topic, last_offsets, 5)

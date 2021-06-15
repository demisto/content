import sys
import json
import redis
from time import time
import log_manager as LOG

class RedisManager:

    def __init__(self, **redis_client_kwargs):
        LOG.logging.info(f"Starting function")
        try:
            redis_client_kwargs['port'] = int(redis_client_kwargs['port'])
            self.redis = redis.StrictRedis(**redis_client_kwargs)
        except redis.exceptions.ConnectionError as e:
            LOG.logging.critical(f"Could not connect to Redis with {redis_client_kwargs}. error: {e}")
            sys.exit()
        LOG.logging.info(f"Finshed function succefully")
    
    def get_smembers(self, set_name):
        LOG.logging.info(f"Starting function, gatting set members of set {set_name}")
        try:
            result = self.redis.smembers(set_name)
        except redis.RedisError as e:
            LOG.logging.critical(f"Could not get set members {set_name}. error: {e}")
            sys.exit()
        LOG.logging.info(f"Finshed function succefully, recived {len(result)} results")
        return result
    
    def get(self, key):
        result = False
        try:
            result = self.redis.get(key)
        except redis.RedisError as e:
            LOG.logging.critical(f"Could not get value {key}. error: {e}")
        return result
    
    def set(self, key, value):
        try:
            self.redis.set(key, value)
        except redis.RedisError as e:
            LOG.logging.critical(f"Could not set {key}, {value}. error: {e}")
    
    def sadd(self, set_name, list_of_data):
        try:
            self.redis.sadd(set_name, *list_of_data)
        except redis.RedisError as e:
            LOG.logging.critical(f"Could not set value {set_name}. error: {e}")
    
    def srem(self, set_name, id_):
        try:
            self.redis.srem(set_name, id_)
        except redis.RedisError as e:
            LOG.logging.critical(f"Could not set value {set_name}. error: {e}")
    
    def delete(self, key):
        try:
            self.redis.delete(key)
        except redis.RedisError as e:
            LOG.logging.critical(f"Could not delete value {key}. error: {e}")
    
if __name__ in ['__main__']:
    # redis_host="34.216.41.3"
    # redis_port =3579
    # redis_auth="AsdcQ31utr"
    # r=redis.StrictRedis(host=redis_host,port=redis_port,password=redis_auth,db=0)
    # r.sadd("blaaaaaaaaaaa", ["blaa"])
    print("ggg")
#! /usr/bin/env python3

import configparser
import json
import gzip
from io import BytesIO
import sys
import boto3
import os
import logging
from logging.handlers import RotatingFileHandler
import urllib3
import threading
from pathlib import Path
import time
import glob
import hashlib
import pickle
import socket
#import datetime
import mmap
from google.cloud import pubsub_v1

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s — %(name)s — %(levelname)s — %(message)s")
fh = RotatingFileHandler('logshipper.log', maxBytes=2048000, backupCount=5)
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)
hostname = socket.getfqdn()

# add OS identification, hostname, ip address automatically


class CloudTrail(threading.Thread):
    def __init__(self, a_key, s_key, sqs_q, rgn, dest_url, dest_token, name="aws-cloudtrail", daemon=True):
        threading.Thread.__init__(self)
        self.name = name
        self.a_key = a_key
        self.s_key = s_key
        self.sqs_q = sqs_q
        self.rgn = rgn
        self.dest_url = dest_url
        self.dest_token = dest_token
        self.sqs = boto3.client('sqs', region_name=self.rgn, aws_access_key_id=self.a_key, aws_secret_access_key=self.s_key)
        self.s3 = boto3.client("s3", region_name=self.rgn, aws_access_key_id=self.a_key, aws_secret_access_key=self.s_key)
        self.http = urllib3.PoolManager()

    def run(self):
        logger.debug('Starting ' + self.name)
        while True:
            bucket1, key1, handle1 = self.get_location()
            logger.debug('reading file {}'.format(str(key1)))
            for record in self.get_content(bucket1, key1):
                r = self.ingest_event(json.dumps(record))
                self.delete_message(handle1)
        logger.debug('Stopping {}'.format(self.name))

    def get_location(self):
        response = self.sqs.receive_message(QueueUrl=self.sqs_q, MessageAttributeNames=[
                                            "All"], WaitTimeSeconds=10, VisibilityTimeout=300, MaxNumberOfMessages=1)
        message = json.loads(response["Messages"][0]["Body"])
        return message["Records"][0]["s3"]["bucket"]["name"], message["Records"][0]["s3"]["object"]["key"], response["Messages"][0]["ReceiptHandle"]

    def get_content(self, bucket1, key1):
        response = self.s3.get_object(Bucket=bucket1, Key=key1)
        json_file = json.load(gzip.GzipFile(None, 'rb', None, BytesIO(response['Body'].read())))
        return json_file["Records"]

    def delete_message(self, handle1):
        return self.sqs.delete_message(QueueUrl=self.sqs_q, ReceiptHandle=handle1)

    def ingest_event(self, record1):
        auth_token = ' Bearer '+self.dest_token
        return self.http.request('POST', self.dest_url, body=record1, headers={'Content-Type': 'application/json', 'Authorization': 'Bearer' + self.dest_token})


class SIEMConnector(threading.Thread):
    def __init__(self, source_loc, dest_url, dest_token, name="siem-connector", daemon=True):
        threading.Thread.__init__(self)
        self.name = name
        self.source_loc = source_loc
        self.dest_url = dest_url
        self.dest_token = dest_token
        self.http = urllib3.PoolManager()

    def run(self):
        count = 0
        logger.debug('Starting {}'.format(self.name))
        if Path(self.source_loc).is_file():
            logger.debug('filename: {}'.format(self.source_loc))
            newevent = ''
            for line in self.read_streaming_file(open(self.source_loc)):
                newevent = newevent + line.rstrip()
                if line.rstrip() == '}':
                    count = count + 1
                    r = json.loads(newevent)
                    logger.debug('Count = {}'.format(str(count)))
                    self.ingest_event(json.dumps(r)+'\n')
                    newevent = ''
        logger.debug('Stopping {}'.format(self.name))

    def read_streaming_file(self, source_loc1):
        interval = 0.2
        while True:
            where = source_loc1.tell()
            line = source_loc1.readline()
            if not line:
                logger.debug('sleeping...'+self.name)
                time.sleep(interval)
            else:
                yield line

    def ingest_event(self, event1):
        auth_token = ' Bearer '+self.dest_token
        return self.http.request('POST', self.dest_url, body=event1, headers={'Content-Type': 'application/json', 'Authorization': 'Bearer' + self.dest_token})


class Syslog(threading.Thread):
    def __init__(self, source_loc, source_cat, dest_type, dest_url, dest_token, name="syslog", daemon=True):
        threading.Thread.__init__(self)
        self.name = name
        self.source_loc = source_loc
        self.source_cat = source_cat
        self.dest_type = dest_type
        self.dest_url = dest_url
        self.dest_token = dest_token
        self.http = urllib3.PoolManager()

    def run(self):
        logger.debug('Starting {}'.format(self.name))
        if (Path(self.source_loc).is_file() and self.source_cat == 'folder') or Path(self.source_loc).is_dir() and self.source_cat == 'file':
            logger.debug(self.source_loc+' is not '+self.source_cat)
            return None
        pos = {}
        if Path(self.name).exists():
            try:
                with open(self.name, 'rb') as pfr:
                    pos = pickle.load(pfr)
                    logger.debug('history loaded..')
            except Exception as e:
                logger.debug(e)
                pos = {}
        else:
            pos = {}
        self.read_content(pos, self.source_loc)

    def read_content(self, pos1, source_loc1):
        while True:
            new_content = False

            # expand and validate source_loc1 with os type and file types and wildcards

            for file in self.get_files(source_loc1):
                try:
                    if (file in pos1 and pos1[file] == 'error') or ("\0" in open(file).read(512)):
                        continue
                    header = hashlib.md5(open(file).read(512).encode('utf-8')).hexdigest()
#                    logger.debug(file)
#                    print(file,datetime.datetime.now())
                    with open(file) as fh:
                        m = mmap.mmap(fh.fileno(), 0, prot=mmap.PROT_READ)
                        if not header in pos1:
                            pos1[header] = m.tell()
                        else:
                            m.seek(pos1[header])
                        while True:
                            line = m.readline()
                            if not line:
                                break
                            pos1[header] = m.tell()
                            new_content = True
                            self.ingest_event(line.decode('utf-8'), file)
                except Exception as e:
                    pos1[file] = 'error'
                    logger.debug(str(file)+' :  '+str(e))
                    continue
            if new_content:
                logger.debug('updating data...')
                self.write_inv(pos1)
            time.sleep(0.2)

    def get_files(self, source_loc2):

        # validate and expand by wildcard and OS type

        files = glob.glob(source_loc2+'/*', recursive=True)
        return [f for f in files if os.path.isfile(f)]

    def ingest_event(self, event1, file1):
        auth_token = ' Bearer '+self.dest_token
        event2 = {"@rawstring": event1, "#source": file1, "#host": hostname}
        return self.http.request('POST', self.dest_url, body=json.dumps(event2), headers={'Content-Type': 'text/plain', 'charset': 'utf-8', 'Authorization': 'Bearer' + self.dest_token})

    def write_inv(self, pos2):
        with open(self.name, 'wb') as pfw:
            pickle.dump(pos2, pfw)


class GCPAuditLog(threading.Thread):
    def __init__(self, proj_id, sub_id, cred_path, dest_url, dest_token, name="gcp-audit-log", daemon=True):
        threading.Thread.__init__(self)
        self.name = name
        self.proj_id = proj_id
        self.sub_id = sub_id
        self.cred_path = cred_path
        self.dest_url = dest_url
        self.dest_token = dest_token
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = self.cred_path
        self.subscriber = pubsub_v1.SubscriberClient()
        self.sub_path = self.subscriber.subscription_path(self.proj_id, self.sub_id)
        self.http = urllib3.PoolManager()

    def callback(self, message: pubsub_v1.subscriber.message.Message):
        self.ingest_event(message.data)
        message.ack()

    def run(self):
        timeout = 5.0
        logger.debug('Starting {}'.format(self.name))
        streaming_pull_future = self.subscriber.subscribe(self.sub_path, callback=self.callback)
        logger.debug("Listening for messages on {self.sub_path}")
        with self.subscriber:
            try:
                streaming_pull_future.result()
            except TimeoutError:
                streaming_pull_future.cancel()
                streaming_pull_future.result()

    def ingest_event(self, event1):
        auth_token = ' Bearer '+self.dest_token
        return self.http.request('POST', self.dest_url, body=event1, headers={'Content-Type': 'application/json', 'Authorization': 'Bearer' + self.dest_token})


if __name__ == "__main__":
    try:
        config = configparser.ConfigParser()
        config.read('logshipper.conf')
        for i in config.sections():
            logger.debug('**** Section: {} ****'.format(i))
            logger.debug(config.items(i))
            if config[i]['source_type'] == "aws-cloudtrail":
                thread1 = CloudTrail(config[i]['access_key'], config[i]['secret_key'], config[i]['sqs_queue_url'],
                                     config[i]['region'], config[i]['dest_url'], config[i]['dest_token'], name=i)
                thread1.start()
            if config[i]['source_type'] == "crwd-siem-connector":
                thread2 = SIEMConnector(config[i]['source_location'], config[i]['dest_url'], config[i]['dest_token'], name=i)
                thread2.start()
            if config[i]['source_type'] == "syslog":
                thread3 = Syslog(config[i]['source_location'], config[i]['source_category'], config[i]
                                 ['dest_type'], config[i]['dest_url'], config[i]['dest_token'], name=i)
                thread3.start()
            if config[i]['source_type'] == "gcp-audit-log":
                thread4 = GCPAuditLog(config[i]['project_id'], config[i]['subscription_id'], config[i]
                                      ['credential_path'], config[i]['dest_url'], config[i]['dest_token'], name=i)
                thread4.start()

    except configparser.NoOptionError as e:
        print("No option error", e)
        sys.exit(1)
    except Exception as e:
        print(e)
        sys.exit(1)

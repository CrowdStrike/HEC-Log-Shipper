"""Humio Log Shipping utility.

 ___ ___                __
|   Y   .--.--.--------|__.-----.
|.  1   |  |  |        |  |  _  |
|.  _   |_____|__|__|__|__|_____|
|:  |   |
|::.|:. |      Log Connector
`--- ---'

Creation date: 10.12.2022 - ckachigian@CrowdStrike, nkhetia31@CrowdStrike, kylesmartin@CrowdStrike
Modified: 01.20.2022 - nkhetia31@CrowdStrike, jshcodes@CrowdStrike, redhatrises@CrowdStrike
"""
import configparser
import json
import gzip
from io import BytesIO
import sys
import os
import logging
from logging.handlers import RotatingFileHandler
import threading
from pathlib import Path
import time
import glob
import hashlib
import socket
import signal
import mmap
import urllib3
import boto3
from google.cloud import pubsub_v1

# Configure logging.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s — %(name)s — %(levelname)s — %(message)s")
log_handle = RotatingFileHandler('logshipper.log', maxBytes=2048000, backupCount=5)
log_handle.setLevel(logging.DEBUG)
log_handle.setFormatter(formatter)
logger.addHandler(log_handle)
hostname = socket.getfqdn()

# add OS identification, hostname, ip address automatically


class CloudTrail(threading.Thread):
    """AWS CloudTrail class."""

    def __init__(self,
                 a_key,
                 s_key,
                 sqs_q,
                 rgn,
                 dest_url,
                 dest_token,
                 name="aws-cloudtrail",
                 ):
        """Initialize the CloudTrail object."""
        threading.Thread.__init__(self)
        self.name = name
        self.a_key = a_key
        self.s_key = s_key
        self.sqs_q = sqs_q
        self.rgn = rgn
        self.dest_url = dest_url
        self.dest_token = dest_token
        self.sqs_client = boto3.client('sqs',
                                       region_name=self.rgn,
                                       aws_access_key_id=self.a_key,
                                       aws_secret_access_key=self.s_key
                                       )
        self.s3_client = boto3.client("s3",
                                      region_name=self.rgn,
                                      aws_access_key_id=self.a_key,
                                      aws_secret_access_key=self.s_key
                                      )
        self.http = urllib3.PoolManager()
        self.killed = False

    def run(self):
        """Start the thread."""
        logger.debug('Starting %s', self.name)
        while not self.killed:
            sub_threads = []
            for _ in range(50):  # Might want to make thread count an adjustable variable
                try:
                    bucket1, key1, handle1 = self.get_location()
                    subthread = threading.Thread(target=self.read_events, args=[bucket1, key1, handle1])
                    sub_threads.append(subthread)
                    subthread.start()
                except Exception as erred:
                    logger.debug(erred)
                    break
            time.sleep(5)
            for sub_thread in sub_threads:
                sub_thread.join()
        logger.debug("Stopping %s", self.name)

    def read_events(self, bucket2, key2, handle2):
        """Event reader sub-processing thread handler."""
        reccount = 0
        for record in self.get_content(bucket2, key2):
            _ = self.ingest_event(json.dumps(record))
            reccount = reccount + 1
        logger.debug("file: %s events: %s", str(key2), str(reccount))
        self.delete_message(handle2)

    def get_location(self):
        """Retrieve the S3 location from the SQS message."""
        response = self.sqs_client.receive_message(QueueUrl=self.sqs_q, MessageAttributeNames=["All"],
                                                   WaitTimeSeconds=10, VisibilityTimeout=300, MaxNumberOfMessages=1)
        message = json.loads(response["Messages"][0]["Body"])
        name = message["Records"][0]["s3"]["bucket"]["name"]
        key = message["Records"][0]["s3"]["object"]["key"]
        receipt_handle = response["Messages"][0]["ReceiptHandle"]
        return name, key, receipt_handle

    def get_content(self, bucket1, key1):
        """Read in the gzip'd message."""
        response = self.s3_client.get_object(Bucket=bucket1, Key=key1)
        json_file = json.load(gzip.GzipFile(None, 'rb', None, BytesIO(response['Body'].read())))
        return json_file["Records"]

    def delete_message(self, handle1):
        """Delete the message from the SQS queue."""
        return self.sqs_client.delete_message(QueueUrl=self.sqs_q, ReceiptHandle=handle1)

    def ingest_event(self, record1):
        """Ingest the parsed event."""
        return self.http.request("POST",
                                 self.dest_url,
                                 body=record1,
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.dest_token}"}
                                 )

    def kill(self):
        """Set the kill flag."""
        self.killed = True


class SIEMConnector(threading.Thread):
    """SIEM connector class."""

    def __init__(self, source_loc, dest_url, dest_token, name="siem-connector"):
        """Initialize the SIEM connector object."""
        threading.Thread.__init__(self)
        self.name = name
        self.source_loc = source_loc
        self.dest_url = dest_url
        self.dest_token = dest_token
        self.http = urllib3.PoolManager()
        self.killed = False

    def run(self):
        """Run the connector."""
        count = 0
        logger.debug('Starting %s', self.name)
        if Path(self.source_loc).is_file():
            logger.debug('filename: %s', self.source_loc)
            newevent = ''
            with open(self.source_loc, encoding="utf-8") as source_file:
                for line in self.read_streaming_file(source_file):
                    newevent = newevent + line.rstrip()
                    if line.rstrip() == '}':
                        count = count + 1
                        read_event = json.loads(newevent)
                        logger.debug('Count = %s', str(count))
                        self.ingest_event(json.dumps(read_event)+'\n')
                        newevent = ''
        logger.debug('Stopping %s', self.name)

    def read_streaming_file(self, source_loc1):
        """Read in the contents of the streamed file."""
        interval = 0.2
        while not self.killed:
            _ = source_loc1.tell()
            line = source_loc1.readline()
            if not line:
                logger.debug('sleeping... %s', self.name)
                time.sleep(interval)
            else:
                yield line

    def ingest_event(self, event1):
        """Ingest the parsed event."""
        return self.http.request("POST",
                                 self.dest_url,
                                 body=event1,
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.dest_token}"}
                                 )

    def kill(self):
        """Set the kill flag."""
        self.killed = True


class Syslog(threading.Thread):
    """Class to represent a SysLog connection."""

    def __init__(self,
                 source_loc,
                 source_cat,
                 dest_type,
                 dest_url,
                 dest_token,
                 name="syslog"
                 ):
        """Initialize the Syslog object."""
        threading.Thread.__init__(self)
        self.name = name
        self.source_loc = source_loc
        self.source_cat = source_cat
        self.dest_type = dest_type
        self.dest_url = dest_url
        self.dest_token = dest_token
        self.http = urllib3.PoolManager()
        self.killed = False

    def run(self):
        """Start the connector."""
        logger.debug('Starting %s', self.name)
        if (Path(self.source_loc).is_file() and self.source_cat == 'folder') \
                or Path(self.source_loc).is_dir() and self.source_cat == 'file':
            logger.debug(self.source_loc+' is not '+self.source_cat)
        else:
            pos = {}
            if Path(self.name).exists():
                try:
                    with open(self.name, 'r') as pfr:
                        pos = json.load(pfr)
                        logger.debug('history loaded..')
                except Exception as erred:
                    logger.debug(erred)
                    pos = {}
            else:
                pos = {}

            self.read_content(pos, self.source_loc)

    def read_content(self, pos1, source_loc1):
        """Read the SysLog file contents."""
        while not self.killed:
            new_content = False

            # expand and validate source_loc1 with os type and file types and wildcards

            for file in self.get_files(source_loc1):
                try:
                    # pylint: disable=R1732
                    if (file in pos1 and pos1[file] == 'error') or ("\0" in open(file).read(512)):
                        continue
                    with open(file) as content_file:
                        # MD5 is used here to determine position only.
                        header = hashlib.md5(content_file.read(512).encode('utf-8')).hexdigest()  # nosec
                    with open(file) as file_handle:
                        mapped = mmap.mmap(file_handle.fileno(), 0, prot=mmap.PROT_READ)  # pylint: disable=I1101
                        if header not in pos1:
                            pos1[header] = mapped.tell()
                        else:
                            mapped.seek(pos1[header])
                        while True:
                            line = mapped.readline()
                            if not line:
                                break
                            pos1[header] = mapped.tell()
                            new_content = True
                            self.ingest_event(line.decode('utf-8'), file)
                except Exception as erred:
                    pos1[file] = 'error'
                    logger.debug("%s : %s", str(file), str(erred))
                    continue
            if new_content:
                logger.debug('updating data...')
                self.write_inv(pos1)
            time.sleep(0.1)

    @staticmethod
    def get_files(source_loc2):
        """Retrieve the files from the log content.

        Validate and expand by wildcard and OS type.
        """
        files = glob.glob(source_loc2+'/**', recursive=True)
        return [f for f in files if os.path.isfile(f)]

    def ingest_event(self, event1, file1):
        """Ingest the parsed event."""
        event2 = {"@rawstring": event1, "#source": file1, "#host": hostname}
        return self.http.request("POST",
                                 self.dest_url,
                                 body=json.dumps(event2),
                                 headers={
                                     "Content-Type": "text/plain",
                                     "charset": "utf-8",
                                     "Authorization": f"Bearer {self.dest_token}"
                                     }
                                 )

    def write_inv(self, pos2):
        """Store our position in the file."""
        with open(self.name, 'w') as pfw:
            json.dump(pos2, pfw)

    def kill(self):
        """Set the kill flag."""
        self.killed = True


class GCPAuditLog(threading.Thread):
    """Class to represent a GCP audit log connection."""

    def __init__(self,
                 proj_id,
                 sub_id,
                 cred_path,
                 dest_url,
                 dest_token,
                 name="gcp-audit-log"
                 ):
        """Initialize the GCP Audit object."""
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
        self.killed = False

    def callback(self, message: pubsub_v1.subscriber.message.Message):
        """Handle callbacks to ingest event."""
        while not self.killed:
            self.ingest_event(message.data)
            message.ack()

    def run(self):
        """Run the connector and set the trace."""
        sys.settrace(self.globaltrace)
        # timeout = 5.0
        logger.debug("Starting %s", self.name)
        streaming_pull_future = self.subscriber.subscribe(self.sub_path, callback=self.callback)
        logger.debug("Listening for messages on %s", self.sub_path)
        with self.subscriber:
            time.sleep(5)
            try:
                streaming_pull_future.result()
            except TimeoutError:
                streaming_pull_future.cancel()
                streaming_pull_future.result()
            except KeyboardInterrupt:
                streaming_pull_future.cancel()
                sys.exit(1)
            except Exception as erred:
                logger.debug(erred.args[0])
                sys.exit(1)

    def globaltrace(self, frame, event, arg):  # pylint: disable=W0613
        """Return the local trace for `call` events."""
        returned = None
        if event == 'call':
            returned = self.localtrace

        return returned

    def localtrace(self, frame, event, arg):  # pylint: disable=W0613
        """Raise SystemExit on the next line called."""
        if self.killed:
            if event == 'line':
                raise SystemExit("Thread quitting")
        return self.localtrace

    def ingest_event(self, event1):
        """Ingest the parsed event."""
        # auth_token = ' Bearer '+self.dest_token
        return self.http.request("POST",
                                 self.dest_url,
                                 body=event1,
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.dest_token}"}
                                 )

    def kill(self):
        """Set the kill flag."""
        self.killed = True


class GracefulShutdown:
    """Class to handle graceful shutdown."""

    shutdown = False

    def __init__(self):
        """Initialize the class and set the exit handlers."""
        signal.signal(signal.SIGINT, self.graceful_shutdown)
        signal.signal(signal.SIGTERM, self.graceful_shutdown)

    def graceful_shutdown(self, *args):  # pylint: disable=W0613
        """Set the shutdown flag."""
        self.shutdown = True


if __name__ == "__main__":
    threads = []
    try:
        config = configparser.ConfigParser()
        config.read("logshipper.conf")
        for i in config.sections():
            logger.debug("**** Section: %s ****", i)
            logger.debug(config.items(i))
            if config[i]["source_type"] == "aws-cloudtrail":
                thread1 = CloudTrail(config[i]["access_key"], config[i]["secret_key"], config[i]["sqs_queue_url"],
                                     config[i]["region"], config[i]["dest_url"], config[i]["dest_token"], name=i)
                thread1.daemon = True
                thread1.start()
                threads.append([thread1, "aws-cloudtrail"])
            if config[i]["source_type"] == "crwd-siem-connector":
                thread2 = SIEMConnector(config[i]["source_location"], config[i]["dest_url"], config[i]["dest_token"], name=i)
                thread2.daemon = True
                thread2.start()
                threads.append([thread2, "crwd-siem-connector"])
            if config[i]["source_type"] == "syslog":
                thread3 = Syslog(config[i]["source_location"], config[i]["source_category"], config[i]
                                 ["dest_type"], config[i]["dest_url"], config[i]["dest_token"], name=i)
                thread3.daemon = True
                thread3.start()
                threads.append([thread3, "syslog"])
            if config[i]["source_type"] == "gcp-audit-log":
                thread4 = GCPAuditLog(config[i]["project_id"], config[i]["subscription_id"], config[i]
                                      ["credential_path"], config[i]["dest_url"], config[i]["dest_token"], name=i)
                thread4.daemon = True
                thread4.start()
                threads.append([thread4, "gcp-audit-log"])

    except configparser.NoOptionError as err:
        raise SystemExit(f"No option error.\n{err}") from err

    except Exception as err:
        raise SystemExit(err) from err

    shipper = GracefulShutdown()
    while not shipper.shutdown:
        # Check thread status
        # for thread in threads:
        #     if not thread[0].isAlive():
        #         # restart thread
        time.sleep(2)
    for running_thread in threads:
        running_thread[0].kill()
        running_thread[0].join()
        if not running_thread[0].isAlive():
            print("Thread killed.")

    print("Process shutdown.")

from google.oauth2 import service_account
from googleapiclient import _auth
from time import time
from requests import request
from datetime import datetime
from json import loads, dumps

HUMIO_INGEST_TOKEN = "YOUR_INGEST_TOKEN_HERE"
HUMIO_BASE_URL = "YOUR_BASE_URL_HERE"
POLLING_INTERVAL = 60 * 5
# Change to the location you placed your JSON file.
SERVICE_ACCOUNT_FILE = "PATH_TO_SERVICE_CREDS_JSON"

def call_list_iocs(http_client, start_time):
  # Construct the URL
  BACKSTORY_API_V1_URL = 'https://backstory.googleapis.com/v1'
  LIST_IOCS_URL = '{}/ioc/listiocs?start_time={}&page_size=10000'.format(BACKSTORY_API_V1_URL, start_time)
  # Make a request
  response = http_client.request(LIST_IOCS_URL, 'GET')
  # Parse the response
  if response[0].status == 200:
    matches = loads(response[1].decode('utf-8'))['response']
    # List of iocs returned for further processing
    return matches
  else:
    # Something went wrong. See the response for details.
    err = response[1]
    print(err)

def post_to_humio(event):
  headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + HUMIO_INGEST_TOKEN
  }
  r = request(
    "POST",
    "http://" + HUMIO_BASE_URL + "/api/v1/ingest/hec",
    data=dumps({"event": event}),
    headers=headers
  )
  if r.status_code < 200 or r.status_code > 299:
    print('Error posting to Humio: %s' % r.text)
  else:
    print('Posted event to Humio: %s' % event)

def get_timestamp(epoch):
  stamp = str(datetime.fromtimestamp(epoch))
  return stamp.split(' ')[0]+'T'+stamp.split(' ')[1]+'Z'

if __name__ == "__main__":
  # Imports required for the sample - Google Auth and API Client Library Imports. 
  # Get these packages from https://pypi.org/project/google-api-python-client/ or 
  # run $ pip install google-api-python-client from your terminal
  # Constants
  SCOPES = ['https://www.googleapis.com/auth/chronicle-backstory']
  # Create a credential using Google Developer Service Account Credential and Chronicle API scope.
  credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)
  # Build an HTTP client which can make authorized OAuth requests.
  http_client = _auth.authorized_http(credentials)
  # Begin polling
  last_poll = 0
  while True:
    current_time = time()
    # Call list iocs if the polling interval has been reached
    if current_time - last_poll > POLLING_INTERVAL:
      iocs = call_list_iocs(http_client, get_timestamp(last_poll))
      post_to_humio(iocs)
      last_poll = current_time
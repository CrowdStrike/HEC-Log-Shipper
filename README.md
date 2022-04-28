# HEC Log Shipper 
A connector to send arbitrary log sources to remote/local Humio instance.

## Installation:
- Download all files in a new folder on a linux node 
- install.sh will install the tool with required configs 
- Verify if logshipper service is running : systemctl status logshipper 
- Stop the service, if its already running : systemctl stop logshipper 
- Update the logshipper.service file in case using logshipper.py instead of logshipper executable

## Add sourcetype stanzas for ingestion: 
- Update logshipper.conf 
- Stop and start the logshipper service : systemctl stop logshipper; systemctl start logshipper 
- Check logshipper.log for more info
- loshipper service will not start unless there is one valid stanza in config file
 Check Humio marketplace to download respective packages

## Available Sourcetypes and suggested parsers:
(Check Humio marketplace to download respective packages)

- CrowdStrike FDR 

- AWS CloudTrail

- CrowdStrike SIEM Connector

- Syslog
    - it supports both JSON and standard syslog format
    - it will add hostname and source file name to each event
    - use parseJson() to parse the json fields and then use suitable syslog parser as each event will be ingested as json event

- GCP Audit Logs




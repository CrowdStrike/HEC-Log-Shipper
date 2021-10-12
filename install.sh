#!/bin/bash

sudo yum -y update
sudo pip3 install --upgrade pip
sudo pip3 install boto3
sudo pip3 install --ignore-installed PyYAML
sudo pip3 install google-cloud-datastore
sudo pip3 install google-cloud-pubsub

echo '*** Starting installation ***'
sudo mkdir /opt/logshipper
echo '   created /opt/logshipper'
sudo cp logshipper.py /opt/logshipper/
sudo cp logshipper /opt/logshipper/
sudo cp logshipper.conf /opt/logshipper/
echo '-----------------------'
sudo ls -l /opt/logshipper
echo '-----------------------'
sudo cp logshipper.service /usr/lib/systemd/system/
sudo ln -s /usr/lib/systemd/system/logshipper.service /etc/systemd/system/multi-user.target.wants
sudo ls -l /etc/systemd/system/multi-user.target.wants/logshipper.service
sudo systemctl daemon-reload
sudo systemctl enable logshipper
sudo systemctl stop logshipper
echo '  '
echo '*** logshipper installation completed ***'


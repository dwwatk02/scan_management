#!/usr/bin/python3

from asoc_api import ASoC
import urllib3
import json

urllib3.disable_warnings()

## ------ please edit variables in this block -----
#API Key
keyId=""
keySecret=""
## path to scan file to upload
scan_file=""
app_id = ""
scan_name = "test_scan_upload"

## ------------------------------------------------

## ------ please do NOT edit anything below  -----
## authenticate
asoc = ASoC(keyId, keySecret)
code, result = asoc.login()
if code != 200:
	print(f'error logging into ASOC!! code is {code}')

file_id = asoc.uploadCollectionFile(scan_file)["FileId"]

asoc.createDastScan(app_id,file_id,starting_url,scan_name)
#!/usr/bin/python3

import requests
from contextlib import closing
import logging
import argparse

logger_handler = logging.StreamHandler()
logger_handler.setFormatter(logging.Formatter('[%(levelname)s]\t(%(asctime)s)\t%(message)s'))
logger = logging.getLogger(__name__)
logger.addHandler(logger_handler)

parser = argparse.ArgumentParser(
    prog="Cloudflare DDNS updater",
    description="A small command line tool to update your domain's IP",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-f", "--force", action="store_true", help="force update")
parser.add_argument("-v", "--debug", action="store_true", help="enable debug")
parser.add_argument("--zone-id", required=True, type=str, help="Cloudflare Zone ID")
parser.add_argument("--token", required=True, type=str, help="Cloudflare API token")
parser.add_argument("-d", "--domain", required=True, type=str, help="DDNS domain")
args = parser.parse_args()

if args.debug:
    logger.info('debug enabled')
if args.force:
    logger.info('IP will be forced update')

log_level = logging.DEBUG if args.debug else logging.INFO
logger.setLevel(log_level)

IP_CHECK_URL = 'https://api.ipify.org?format=json'
CLOUDFLARE_API_DOMAIN = f'https://api.cloudflare.com/client/v4/zones/{args.zone_id}/dns_records'
CLOUDLARE_HEADERS = {
    "Authorization": f"Bearer {args.token}"
}
DDNS_DOMAIN = args.domain

with closing(requests.get(IP_CHECK_URL)) as resp:
    json_resp = resp.json()

logger.debug(f'ipify response: {json_resp}')
ip = json_resp.get('ip')

if not ip:
    logger.info('no IP found')
    exit(1)

logger.info(f'current IP: {ip}')

with closing(requests.get(f"{CLOUDFLARE_API_DOMAIN}?name={DDNS_DOMAIN}", headers=CLOUDLARE_HEADERS)) as resp:
    resp_json = resp.json()

logger.debug(f'Cloudflare List DNS Records response: {resp_json}')
result = resp_json['result']
if not result:
    logger.error('no domain found')
    exit(1)

domain_ip = result[0]['content']
logger.info(f'domain IP: {domain_ip}')

if domain_ip == ip:
    logger.info('IP is up to date, update skipped')
    if not args.force:
        exit(1)
    

domain_id = result[0]['id']
logger.info(f'preparing to update domain {DDNS_DOMAIN}')


cf_req = {
    "content": ip
}

with closing(requests.patch(f"{CLOUDFLARE_API_DOMAIN}/{domain_id}", headers=CLOUDLARE_HEADERS, json=cf_req)) as resp:
    resp_json = resp.json()

logger.debug(f'Cloudflare Patch DNS Record response: {resp_json}')

if not resp_json['success']:
    logger.error('cannot update domain IP')
    logger.error(f'errors: {resp_json["errors"]}')
    logger.error(f'messages: {resp_json["messages"]}')
    exit(1)

logger.info(f"domain IP has been {'forced' if args.force else ''} updated to {ip}")

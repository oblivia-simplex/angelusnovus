#! /usr/bin/env python3

import sqlite3
import requests
import urllib
import json
import re

apikey  = open('virustotal_api_key','r').read().strip()
field_d = {'apikey' : apikey}
domain_scan_url   = 'https://www.virustotal.com/vtapi/v2/domain/scan'
domain_report_url = 'https://www.virustotal.com/vtapi/v2/domain/report'

DATA = {}

#def vt_domain_query(domain):
#  fields = field_d.copy()
#  fields['domain'] = domain
#  r = requests.post(domain_scan_url, fields)
#  try:
#    return json.loads(r.text)
#  except:
#    return None

def vt_domain_report(domain=None, scan_id=None):
  fields = field_d.copy()
  if domain is not None:
    fields['domain'] = domain
  if scan_id is not None:
    fields['scan_id'] = scan_id
  #  r = requests.post(domain_report_url, fields)
  r = urllib.request.urlopen('{:s}?{:s}'.format(domain_report_url,
          urllib.parse.urlencode(fields))).read()
  # print(r)
  try:
    return json.loads(r.decode('utf-8'))
  except json.JSONDecodeError:
    return None

def domain_score(domain):
  j = vt_domain_report(domain)
  if j is None:
    return -1
  try:
    urls = j['detected_urls']
    scores = [k['positives'] / k['total'] for k in urls]
    if len(scores) > 0:
      s = max(scores)
    else:
      s = 0
    DATA[domain] = (s, urls)
  except KeyError:
    s = -1
  return s

def get_urls_from_history(path='History'):
  conn = sqlite3.connect(path)
  c = conn.cursor()
  cmd = 'select url from urls;'
  c.execute(cmd)
  res = [r[0] for r in c.fetchall()]
  return res

dom_regex = re.compile('^https?://([^/]+\.)*(([a-zA-Z0-1-_]+)\.([a-zA-Z0-9]+))/.*')
dom_group = 2
def get_domains(path='History'):
  urls = get_urls_from_history(path)
  dom_matches = [dom_regex.match(u) for u in urls]
  doms = [m.group(dom_group) for m in dom_matches if m is not None]
  return sorted(list(set(doms)))


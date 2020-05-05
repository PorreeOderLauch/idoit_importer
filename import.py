#!/usr/bin/env python

import argparse
import json
import urllib2
import ssl
import itertools

req_count = itertools.count()

def make_request(url, request):
    if not request:
        raise Exception('request empty')
    req = urllib2.Request(url, json.dumps(request).encode('UTF-8'), {'Content-Type': 'application/json'})
    f = urllib2.urlopen(req, context=ssl._create_unverified_context())
    response = f.read()
    f.close()
    return json.loads(response)

def update_idoit_cis(url, apikey):
    request = {
            "method": "cmdb.objects.read",
            "params": {
                "apikey": apikey,
                "filter": {
                    "type": "C__OBJTYPE__CLIENT",
                },
            },
            "jsonrpc": "2.0",
            "id": req_count.next(),
        }

    result = make_request(url, request)['result']
    return dict(map(lambda x: (x['sysid'], x), result))




def main(url, apikey, input_data):
    idoit_cis = update_idoit_cis(url, apikey)
    request = []

    for client in input_data:
        if client['general']['sysid'] not in idoit_cis:
            request.append({
                "method": "cmdb.object.create",
                "params": {
                    "apikey": apikey,
                    "type": "C__OBJTYPE__CLIENT",
                    "title": client["general"]["Object_title"],
                    "sysid": client["general"]["sysid"],
                    },
                "jsonrpc": "2.0",
                "id": req_count.next(),
                })
    try:        
        make_request(url, request)
    except:
        print('no objects created')

    idoit_cis = update_idoit_cis(url, apikey)

#    print(json.dumps(idoit_cis, indent=2))
    request = []

    for client in input_data:
        idoit_id = idoit_cis[client['general']['sysid']]['id']
        print('updating category info for ' + client['general']['sysid'] + " with ID: " + str(idoit_id))
        request.append({
            "method": "cmdb.category.save",
            "params": {
                "apikey": apikey,
                "object": idoit_id,
                "category": "C__CATG__IP",
                "data": {
                    "primary_hostaddress": client['Host_address']['Hostname']
                    },
                },
            "jsonrpc": "2.0",
            "id": req_count.next(),
            })

    try:        
        print(json.dumps(make_request(url, request), indent=2))
    except:
        print('no objects created')



if __name__ == '__main__':
    url = None
    apikey = None
    input_data = None
    with open('./default.conf', 'rb') as f:
        content = json.loads(f.read().decode('UTF-8'))
        url = content['url']
        apikey = content['apikey']
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('datafile', help='filecontaining json data for import')
    args = argument_parser.parse_args()

    with open(args.datafile, 'rb') as f:
        input_data = json.loads(f.read().decode('UTF-8'))

    main(url, apikey, input_data)



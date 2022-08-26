from __main__ import app
from functools import reduce
import json
from flask import request, redirect, url_for
import protobuf.GdpMsg_pb2

@app.route('/')
def hello_world():
    return '<p>Welcome to GDP switch proxy<p>'

@app.route('/<GdpName>')
def get_index(GdpName):
    if len(GdpName) != 64:
        return "Invalid Get Request, you are providing an invalid GdpName"
    if (GdpName == app.config['GdpName']):
        return redirect(url_for('hello_world'))
    
    
    return "todo: forwarding get request"

# Parse http request headers into strings of json format.
# Return value is a string, can be json.load and reproduced by json.dump
def parse_http_headers(input):
    splitted = input.split('\r\n')
    splitted = filter(lambda x: x!='', splitted)
    def add_quotations(string_with_colon):
        idx_of_colon = string_with_colon.find(':')
        key = string_with_colon[0:idx_of_colon].strip()
        value = string_with_colon[idx_of_colon+1:].strip()
        return '"{0}":"{1}"'.format(key, value)
    splitted = map(add_quotations, splitted)
    
    splitted = reduce(lambda x, y: x + ', ' + y, splitted)
    return '{'+splitted+'}'

@app.route('/<GdpName>/submit', methods = ['POST'])
def submit_something(GdpName):
    # print(request.content_length)
    # content = str(request.headers) + str(request.data)
    # print(content)
    # print(json.loads(str(request.headers)))
    header_json = parse_http_headers(str(request.headers))
    print(header_json)

    return "submitted"


@app.route('/validate', methods = ['POST'])
def validate_resending():
    print(request)
    print(request.headers)


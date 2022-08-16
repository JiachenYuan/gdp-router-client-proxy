from __main__ import app
from flask import request
import protobuf.GdpMsg_pb2

@app.route('/')
def hello_word():
    return '<p>Welcome to GDP switch proxy<p>'

@app.route('/<GdpName>')
def get_index(GdpName):
    if len(GdpName) != 32:
        return "Invalid Get Request, you are providing an invalid GdpName"
    print(str(request.headers))
    return "Wait"

@app.route('/<GdpName>/submit', methods = ['POST'])
def submit_something(GdpName):
    print(request.headers)
    print(request.content_length)
    return "submitted"

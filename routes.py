from __main__ import app

@app.route('/')
def hello_word():
    return '<p>Welcome to GDP switch proxy<p>'
from flask import Flask
from google.cloud import datastore


app = Flask(__name__)

client = datastore.Client()


@app.route('/')
def index():
    return "HW 6 submission for CS 493. Please navigate to /businesses to use this API"


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5023, debug=True)
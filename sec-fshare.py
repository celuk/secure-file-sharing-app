from flask import Flask, request, send_from_directory
import os

import socket

import argparse

app = Flask(__name__)

parser = argparse.ArgumentParser(description='Create Configuration')
parser.add_argument('-p', '--path', type=str, help='Specify full file path', default='')
args = parser.parse_args()

UPLOAD_FOLDER = args.path

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        file.save(os.path.join(UPLOAD_FOLDER, file.filename))
        return 'File uploaded successfully'
    else:
        return '''
        <!doctype html>
        <title>Upload a File</title>
        <h1>Upload a File</h1>
        <form method=post enctype=multipart/form-data>
          <input type=file name=file>
          <input type=submit value=Upload>
        </form>
        '''

@app.route('/downloads/<path:filename>', methods=['GET', 'POST'])
def download(filename):
    return send_from_directory(directory=UPLOAD_FOLDER, filename=filename)

if __name__ == '__main__':
    app.run(host=socket.gethostbyname(socket.gethostname()), port=8080)


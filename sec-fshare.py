from flask import (
    Flask,
    request,
    redirect,
    url_for,
    send_from_directory,
    session,
    render_template,
)
from markupsafe import escape
import socket

import os
import sys
import argparse

from werkzeug.security import generate_password_hash, check_password_hash

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

parser = argparse.ArgumentParser(description="Specify paths to upload")
parser.add_argument(
    "-fp", "--filepath", type=str, help="Specify full file path", default="."
)
parser.add_argument(
    "-fo", "--folder", type=str, help="Specify full folder path", default="."
)
parser.add_argument(
    "-ips",
    "--iplist",
    type=str,
    help="Specify ip whitelist for authorized access",
    default="",
)
parser.add_argument(
    "-pw",
    "--loginpassword",
    type=str,
    help="Specify login password for authorized access",
    default="admin",
)
args = parser.parse_args()

## argumanlara kisitla ekleyebilirim, sadece o iplerde indirilebilsin diye, bu da ek özellik olur
## dosyanın folder olup olmadığını sen anla

UPLOAD_FOLDER = args.filepath

aes_key_256 = get_random_bytes(32)  
# b'\x84\xe19{Ww\xff\xeb\x9d\xda\xd3\x17$,\x19\xfdJKL\xc5\xd6\xf1\x97\x91c\xfd\x83\xd8\xb8m\xdf\xe7'


# https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib/28950776#28950776
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(("10.255.255.255", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()
    return IP


iplistsp = []
if "".join(args.iplist.split()) != "":
    iplistsp = [each_ip.strip() for each_ip in args.iplist.split(",")]
    iplistsp[:] = [x for x in iplistsp if x.strip()]

allowed_ips = [get_ip()]

# verilen ip listesini izin verilen (beyaz) listeye ekle
for each_ip in iplistsp:
    if each_ip not in allowed_ips:
        allowed_ips.append(each_ip)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # 192 bit


# CBC modunda AES ile dosya sifreleme
def encrypt_file(file_path, key):
    chunk_size = 64 * 1024
    output_file = file_path + ".enc"

    cipher = AES.new(key, AES.MODE_CBC)

    with open(file_path, "rb") as infile:
        with open(output_file, "wb") as outfile:
            outfile.write(cipher.encrypt(get_random_bytes(16)))
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b" " * (16 - len(chunk) % 16)
                outfile.write(cipher.encrypt(chunk))

    return output_file


# CBC modunda AES ile sifrelenen dosyayi cozme
def decrypt_file(encrypted_file, key):
    chunk_size = 64 * 1024
    output_file = encrypted_file[:-4]

    cipher = AES.new(key, AES.MODE_CBC)

    # Dosya okuma ve çözme işlemi
    with open(encrypted_file, "rb") as infile:
        with open(output_file, "wb") as outfile:
            iv = infile.read(16)
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                outfile.write(decrypted_chunk.rstrip(b" "))

    return output_file


@app.route("/login", methods=["GET", "POST"])
def login():
    if "all" not in allowed_ips:
        client_ip = request.remote_addr  # istemci ip adresi
        if client_ip not in allowed_ips:
            return (
                "Access Denied. Unauthorized IP Address!",
                403,
            )  # beyaz listede degilse yetkisiz erisim

    if request.method == "POST":
        password = escape(request.form["password"])
        hashedpw = generate_password_hash(password, method="sha256")
        print()
        print(hashedpw)
        print()
        if check_password_hash(hashedpw, args.loginpassword):  # parola kontrol
            session["logged_in"] = True
            return redirect(url_for("upload"))
        else:
            return """
            <!doctype html>
            <title>Login</title>
            <h1>Login</h1>
            <p>Invalid password</p>
            <form method="post" action="">
            <input type="password" name="password" placeholder="Enter password" required>
            <input type="submit" value="Login">
            </form>
            """

    return """
    <!doctype html>
    <title>Login</title>
    <h1>Login</h1>
    <form method="post" action="">
    <input type="password" name="password" placeholder="Enter password" required>
    <input type="submit" value="Login">
    </form>
    """


@app.route("/", methods=["GET", "POST"])
def upload():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if request.method == "POST":
        if "all" not in allowed_ips:
            client_ip = request.remote_addr  # istemci ip adresi
            if client_ip not in allowed_ips:
                return (
                    "Access Denied. Unauthorized IP Address!",
                    403,
                )  # beyaz listede degilse yetkisiz erisim

        file = request.files["files"]
        file.save(os.path.join(UPLOAD_FOLDER, file.filename))

        files = os.listdir(UPLOAD_FOLDER)
        files.remove(sys.argv[0])
        file_list = "<br>".join(
            [f'<a href="/downloads/{file}">{file}</a>' for file in files]
        )

        # <p style="color:green;">File uploaded successfully</p>
        return f"""
            <!doctype html>
            <title>Upload and Download Files</title>
            <h1>Upload a File</h1>
            <div id="drop_area" style="padding:100px; border: 1px solid black">
                Drag and drop files here to upload
            </div>
            <input type="file" name="file_input" id="file_input">
            <button id="upload_button">Upload</button>
            <button id="cancel_button" style="display: none;">X</button>
            <div id="upload_progress"></div>
            <div id="speed"></div>
            <script>
            // prevent the default behavior of web browser
            ['dragleave', 'drop', 'dragenter', 'dragover'].forEach(function (evt) {{
                document.addEventListener(evt, function (e) {{
                    e.preventDefault();
                }}, false);
            }});

            var drop_area = document.getElementById('drop_area');
            var file_input = document.getElementById('file_input');
            var upload_button = document.getElementById('upload_button');
            var cancel_button = document.getElementById('cancel_button');
            var xhr = new XMLHttpRequest();

            drop_area.addEventListener('drop', function (e) {{
                e.preventDefault();
                file_input.files = e.dataTransfer.files;
            }}, false);

            upload_button.addEventListener('click', function (e) {{
                e.preventDefault();
                var fileList = file_input.files; // the files to be uploaded

                if (fileList.length == 0) {{
                    return false;
                }}

                // we use XMLHttpRequest here instead of fetch, because with the former we can easily implement progress and speed.
                xhr.open('post', '/', true); // assume that the url /upload handles uploading.

                // show uploading progress
                var lastTime = Date.now();
                var lastLoad = 0;
                xhr.upload.onprogress = function (event) {{
                    if (event.lengthComputable) {{
                        // update progress
                        var percent = Math.floor(event.loaded / event.total * 100);
                        document.getElementById('upload_progress').textContent = percent + '%';

                        // update speed
                        var curTime = Date.now();
                        var curLoad = event.loaded;
                        var speed = ((curLoad - lastLoad) / (curTime - lastTime) / 1024).toFixed(2);
                        document.getElementById('speed').textContent = speed + 'MB/s'
                        lastTime = curTime;
                        lastLoad = curLoad;
                    }}
                }};

                xhr.upload.onloadend = function (event) {{
                    document.getElementById('upload_progress').textContent = 'File uploaded successfully';
                    document.getElementById('speed').textContent = '0 MB/s';
                    cancel_button.style.display = 'none';
                }};

                // send files to server
                xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                var fd = new FormData();
                for (let file of fileList) {{
                    fd.append('files', file);
                }}
                lastTime = Date.now();
                xhr.send(fd);
                cancel_button.style.display = 'inline';
            }}, false);

            cancel_button.addEventListener('click', function (e) {{
                xhr.abort();
                document.getElementById('upload_progress').textContent = '0%';
                document.getElementById('speed').textContent = '0 MB/s';
                cancel_button.style.display = 'none';
            }}, false);
            </script>
            <h1>Download a File</h1>
            {file_list}
            """
    else:
        if "all" not in allowed_ips:
            client_ip = request.remote_addr  # istemci ip adresi
            if client_ip not in allowed_ips:
                return (
                    "Access Denied. Unauthorized IP Address!",
                    403,
                )  # beyaz listede degilse yetkisiz erisim

        files = os.listdir(UPLOAD_FOLDER)
        files.remove(sys.argv[0])
        file_list = "<br>".join(
            [f'<a href="/downloads/{file}">{file}</a>' for file in files]
        )

        return f"""
            <!doctype html>
            <title>Upload and Download Files</title>
            <h1>Upload a File</h1>
            <div id="drop_area" style="padding:100px; border: 1px solid black">
                Drag and drop files here to upload
            </div>
            <input type="file" name="file_input" id="file_input">
            <button id="upload_button">Upload</button>
            <button id="cancel_button" style="display: none;">X</button>
            <div id="upload_progress"></div>
            <div id="speed"></div>
            <script>
            // prevent the default behavior of web browser
            ['dragleave', 'drop', 'dragenter', 'dragover'].forEach(function (evt) {{
                document.addEventListener(evt, function (e) {{
                    e.preventDefault();
                }}, false);
            }});

            var drop_area = document.getElementById('drop_area');
            var file_input = document.getElementById('file_input');
            var upload_button = document.getElementById('upload_button');
            var cancel_button = document.getElementById('cancel_button');
            var xhr = new XMLHttpRequest();

            drop_area.addEventListener('drop', function (e) {{
                e.preventDefault();
                file_input.files = e.dataTransfer.files;
            }}, false);

            upload_button.addEventListener('click', function (e) {{
                e.preventDefault();
                var fileList = file_input.files; // the files to be uploaded

                if (fileList.length == 0) {{
                    return false;
                }}

                // we use XMLHttpRequest here instead of fetch, because with the former we can easily implement progress and speed.
                xhr.open('post', '/', true);

                // show uploading progress
                var lastTime = Date.now();
                var lastLoad = 0;
                xhr.upload.onprogress = function (event) {{
                    if (event.lengthComputable) {{
                        // update progress
                        var percent = Math.floor(event.loaded / event.total * 100);
                        document.getElementById('upload_progress').textContent = percent + '%';

                        // update speed
                        var curTime = Date.now();
                        var curLoad = event.loaded;
                        var speed = ((curLoad - lastLoad) / (curTime - lastTime) / 1024).toFixed(2);
                        document.getElementById('speed').textContent = speed + 'MB/s'
                        lastTime = curTime;
                        lastLoad = curLoad;
                    }}
                }};

                xhr.upload.onloadend = function (event) {{
                    document.getElementById('upload_progress').textContent = 'File uploaded successfully';
                    document.getElementById('speed').textContent = '0 MB/s';
                    cancel_button.style.display = 'none';
                }};

                // send files to server
                xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                var fd = new FormData();
                for (let file of fileList) {{
                    fd.append('files', file);
                }}
                lastTime = Date.now();
                xhr.send(fd);
                cancel_button.style.display = 'inline';
            }}, false);

            cancel_button.addEventListener('click', function (e) {{
                xhr.abort();
                document.getElementById('upload_progress').textContent = '0%';
                document.getElementById('speed').textContent = '0 MB/s';
                cancel_button.style.display = 'none';
            }}, false);
            </script>
            <h1>Download a File</h1>
            {file_list}
            """

    # return f"""
    # <!doctype html>
    # <title>Upload a File</title>
    # <h1>Upload a File</h1>
    # <form method=post enctype=multipart/form-data>
    #  <input type=file name=file>
    #  <input type=submit value=Upload>
    # </form>
    # <h1>Download a File</h1>
    # {file_list}
    # """


@app.route("/downloads/<path:filename>", methods=["GET", "POST"])
def download(filename):
    if "all" not in allowed_ips:
        client_ip = request.remote_addr  # istemci ip adresi
        if client_ip not in allowed_ips:
            return (
                "Access Denied. Unauthorized IP Address!",
                403,
            )  # beyaz listede degilse yetkisiz erisim
    decrypted_file = decrypt_file(
        os.path.join(UPLOAD_FOLDER, filename),
    )
    return send_from_directory(
        directory=UPLOAD_FOLDER, path=decrypted_file, as_attachment=True
    )


if __name__ == "__main__":
    # context = ("192.168.1.22.pem", "192.168.1.22-key.pem")
    # app.run(host=get_ip(), port=8080, ssl_context=context)
    # app.run(host=get_ip(), port=8080)  # , ssl_context="adhoc")
    app.run(host=get_ip(), port=8080, ssl_context="adhoc")

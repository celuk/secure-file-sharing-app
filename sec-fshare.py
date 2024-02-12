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
import shutil
import signal
import sys
import argparse

from werkzeug.security import generate_password_hash, check_password_hash

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import io
from werkzeug.datastructures import FileStorage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

parser = argparse.ArgumentParser(description="Specify paths, ips and password")
parser.add_argument(
    "-fp", "--folderpath", type=str, help="Specify upload folder path", default="."
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

UPLOAD_FOLDER = args.folderpath


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

aes_key_256 = get_random_bytes(16)
# b'\x84\xe19{Ww\xff\xeb\x9d\xda\xd3\x17$,\x19\xfdJKL\xc5\xd6\xf1\x97\x91c\xfd\x83\xd8\xb8m\xdf\xe7'


# CBC modunda AES ile dosya sifreleme
def encrypt_file(file_path: str, key: bytes) -> FileStorage:
    cipher = Cipher(
        algorithms.AES(key), modes.CBC(os.urandom(16)), backend=default_backend()
    )
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()

    encrypted_data = io.BytesIO()
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(64 * 1024)
            if len(chunk) == 0:
                break
            encrypted_data.write(encryptor.update(padder.update(chunk)))
        encrypted_data.write(encryptor.update(padder.finalize()))
        encrypted_data.write(encryptor.finalize())
    encrypted_data.seek(0)

    return FileStorage(encrypted_data, filename=file_path + ".enc")


# CBC modunda AES ile sifrelenen dosyayi cozme
def decrypt_file(file_path: str, key: bytes) -> FileStorage:
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    unpadder = padding.PKCS7(128).unpadder()

    decrypted_data = io.BytesIO()
    decrypted_data.write(unpadder.update(decryptor.update(encrypted_data[16:])))
    decrypted_data.write(unpadder.update(decryptor.finalize()))
    decrypted_data.seek(0)

    return FileStorage(decrypted_data, filename=file_path[:-4])


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
            return redirect(
                url_for("upload")
            )  # giris yapinca upload sayfasina yonlendir
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
        enc_file = encrypt_file(os.path.join(UPLOAD_FOLDER, file.filename), aes_key_256)
        enc_file.save(os.path.join(UPLOAD_FOLDER, "encrypted", enc_file.filename))
        os.remove(os.path.join(UPLOAD_FOLDER, file.filename))

        files = os.listdir(os.path.join(UPLOAD_FOLDER, "encrypted"))
        if "encrypted" in files:
            files.remove("encrypted")
        if sys.argv[0] in files:
            files.remove(sys.argv[0])
        if sys.argv[0] + ".enc" in files:
            files.remove(sys.argv[0] + ".enc")

        files.sort()
        file_list = "<br>".join(
            [f'<a href="/downloads/{file[:-4]}">{file[:-4]}</a>' for file in files]
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

        if not os.path.exists(os.path.join(UPLOAD_FOLDER, "encrypted")):
            os.makedirs(os.path.join(UPLOAD_FOLDER, "encrypted"))

        for each_file in os.listdir(UPLOAD_FOLDER):
            if (
                each_file.strip() != "encrypted"
                and each_file.strip() != sys.argv[0]
                and each_file.strip() != sys.argv[0] + ".enc"
            ):
                each_out = encrypt_file(
                    os.path.join(UPLOAD_FOLDER, each_file), aes_key_256
                )
                each_out.save(
                    os.path.join(UPLOAD_FOLDER, "encrypted", each_file + ".enc")
                )

        files = os.listdir(os.path.join(UPLOAD_FOLDER, "encrypted"))
        if "encrypted" in files:
            files.remove("encrypted")
        if sys.argv[0] in files:
            files.remove(sys.argv[0])
        if sys.argv[0] + ".enc" in files:
            files.remove(sys.argv[0] + ".enc")

        files.sort()
        file_list = "<br>".join(
            [f'<a href="/downloads/{file[:-4]}">{file[:-4]}</a>' for file in files]
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
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if "all" not in allowed_ips:
        client_ip = request.remote_addr  # istemci ip adresi
        if client_ip not in allowed_ips:
            return (
                "Access Denied. Unauthorized IP Address!",
                403,
            )  # beyaz listede degilse yetkisiz erisim
    decrypted_file = decrypt_file(
        os.path.join(UPLOAD_FOLDER, "encrypted", filename + ".enc"), aes_key_256
    )
    decrypted_file.save(os.path.join(UPLOAD_FOLDER, "encrypted", filename))

    return send_from_directory(
        directory=UPLOAD_FOLDER,
        path=decrypted_file.filename,
        as_attachment=True,
    )


def signal_handler(sig, frame):
    if os.path.exists(os.path.join(UPLOAD_FOLDER, "encrypted")):
        shutil.rmtree(os.path.join(UPLOAD_FOLDER, "encrypted"))

    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    # context = ("192.168.1.22.pem", "192.168.1.22-key.pem")
    # app.run(host=get_ip(), port=8080, ssl_context=context)
    # app.run(host=get_ip(), port=8080)  # , ssl_context="adhoc")
    if os.path.exists(os.path.join(UPLOAD_FOLDER, "encrypted")):
        shutil.rmtree(os.path.join(UPLOAD_FOLDER, "encrypted"))
    app.run(host=get_ip(), port=8080, ssl_context="adhoc")

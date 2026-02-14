
import http.server
import socketserver
import urllib.parse
import urllib.request
import webbrowser
import json
import os
import sys
import hashlib
import base64
import secrets
import struct

# Configuration
CLIENT_ID = "1001648701353-45oc3g1hqfbnp1m2v1ud2en1egpac079.apps.googleusercontent.com"
# Only one port supported, simple logic
REDIRECT_URI = "http://127.0.0.1:33418/"
SCOPES = "https://www.googleapis.com/auth/cloud-platform openid email"
AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
PORT = 33418
CONFIG_FILE_PATH = r"c:\Users\user\.gemini\antigravity\mcp_config.json"

def generate_code_verifier():
    token = secrets.token_urlsafe(32)
    return token

def generate_code_challenge(verifier):
    m = hashlib.sha256()
    m.update(verifier.encode('utf-8'))
    digest = m.digest()
    challenge = base64.urlsafe_b64encode(digest).decode('utf-8').replace('=', '')
    return challenge

class OAuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)

        if 'code' in query_params:
            self.server.auth_code = query_params['code'][0]
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Authentication Successful!</h1><p>You can close this window now.</p></body></html>")
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing code parameter.")

    def log_message(self, format, *args):
        return

def run_auth_flow():
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier)

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPES,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline"
    }
    
    # Simple urlencode
    query_string = urllib.parse.urlencode(params)
    auth_url = f"{AUTH_ENDPOINT}?{query_string}"
    
    print(f"Please visit the following URL to authenticate:\n{auth_url}")
    
    try:
        webbrowser.open(auth_url)
    except:
        pass

    with socketserver.TCPServer(("", PORT), OAuthHandler) as httpd:
        print(f"Listening on port {PORT}...")
        httpd.handle_request()
        if hasattr(httpd, 'auth_code'):
            return httpd.auth_code, verifier
        return None, None

def exchange_code_for_token(code, verifier):
    data = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier
    }
    data_encoded = urllib.parse.urlencode(data).encode('utf-8')
    req = urllib.request.Request(TOKEN_ENDPOINT, data=data_encoded, method='POST')
    
    try:
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"Token exchange failed: {e}")
    return None

def update_config_file(token_data):
    if not os.path.exists(CONFIG_FILE_PATH):
        print(f"Config file not found at {CONFIG_FILE_PATH}")
        return

    try:
        with open(CONFIG_FILE_PATH, 'r') as f:
            config = json.load(f)

        new_token = token_data.get('access_token')
        if new_token:
            # Navigate to the correct path in JSON
            if 'mcpServers' in config and 'stitch' in config['mcpServers']:
                if 'headers' in config['mcpServers']['stitch']:
                    config['mcpServers']['stitch']['headers']['Authorization'] = f"Bearer {new_token}"
                    with open(CONFIG_FILE_PATH, 'w') as f:
                        json.dump(config, f, indent=4)
                    print("Successfully updated mcp_config.json")
                else:
                    print("Could not find 'headers' in config structure.")
            else:
                print("Could not find 'mcpServers.stitch' in config structure.")
        else:
            print("No access token in response.")

    except Exception as e:
        print(f"Failed to update config: {e}")

if __name__ == "__main__":
    code, verifier = run_auth_flow()
    if code:
        token_data = exchange_code_for_token(code, verifier)
        if token_data:
            update_config_file(token_data)
        else:
            print("Failed to get token.")
    else:
        print("Failed to get authorization code.")

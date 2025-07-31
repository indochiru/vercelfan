from http.server import BaseHTTPRequestHandler
import json
import os
import jwt
import datetime
import hashlib
import hmac
import base64

# --- Helper Function for Verification ---
def pbkdf2_verify(password, stored_hash):
    """Verifies a password against a PBKDF2 hash."""
    try:
        parts = stored_hash.split(':')
        if len(parts) != 3:
            return False
        
        salt = base64.b64decode(parts[0])
        iterations = int(parts[1])
        stored_key = base64.b64decode(parts[2])
        
        # Generate the key from the provided password
        password_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        
        # Compare the generated key with the stored key
        return hmac.compare_digest(password_key, stored_key)
    except Exception:
        return False

# --- Main Handler Class ---
# Vercel will use this class to handle requests to /api/auth
class handler(BaseHTTPRequestHandler):

    def do_POST(self):
        # Get environment variables
        ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', '')
        JWT_SECRET = os.environ.get('JWT_SECRET', '')

        try:
            # Read and parse the request body
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            body = json.loads(post_data)
            password = body.get('password')

            # Verify the password
            if pbkdf2_verify(password, ADMIN_PASSWORD_HASH):
                # --- Success: Generate and send token ---
                payload = {
                    'user': 'admin',
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                }
                token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'token': token}).encode('utf-8'))
            else:
                # --- Failure: Send invalid password response ---
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'Invalid Access Code'}).encode('utf-8'))

        except Exception as e:
            # --- Error: Send server error response ---
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'message': f'Server Error: {str(e)}'}).encode('utf-8'))
        return

    def do_OPTIONS(self):
        # This handles the preflight CORS requests from the browser
        self.send_response(204) # 204 No Content
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        return


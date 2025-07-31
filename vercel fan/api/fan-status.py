from http.server import BaseHTTPRequestHandler
import json
import os
import jwt
import requests

# --- Main Handler Class ---
class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        # Get environment variables
        JWT_SECRET = os.environ.get('JWT_SECRET', '')
        ESP8266_IP = os.environ.get('ESP8266_IP', '')
        ESP8266_AUTH_TOKEN = os.environ.get('ESP8266_AUTH_TOKEN', '')

        # 1. Validate JWT Token
        try:
            auth_header = self.headers.get('authorization', '')
            token = auth_header.split(' ')[1]
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except Exception:
            self.send_response(401)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Unauthorized: Invalid token'}).encode('utf-8'))
            return

        # 2. Get status from ESP8266
        try:
            url = f"http://{ESP8266_IP}/status"
            esp_headers = {'X-Auth-Token': ESP8266_AUTH_TOKEN}

            response = requests.get(url, headers=esp_headers, timeout=5)
            response.raise_for_status()

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(response.text.encode('utf-8'))
            
        except requests.exceptions.RequestException:
            self.send_response(503)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'disconnected', 'error': 'Could not reach fan controller.'}).encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'message': f'Server error: {str(e)}'}).encode('utf-8'))
        return

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        return

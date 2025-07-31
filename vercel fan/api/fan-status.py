import json
import os
import jwt
import requests

# Get secrets from environment variables
JWT_SECRET = os.environ.get('JWT_SECRET', '')
ESP8266_IP = os.environ.get('ESP8266_IP', '')
ESP8266_AUTH_TOKEN = os.environ.get('ESP8266_AUTH_TOKEN', '')

def handler(event, context):
    # Standard headers for all responses
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET, OPTIONS'
    }
    
    # Handle preflight OPTIONS request
    if event['httpMethod'] == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({})
        }
    
    if event['httpMethod'] != 'GET':
        return {
            'statusCode': 405,
            'headers': headers,
            'body': json.dumps({'message': 'Method Not Allowed'})
        }

    # 1. Validate JWT Token
    try:
        auth_header = event['headers'].get('authorization', '')
        token = auth_header.split(' ')[1]
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return {
            'statusCode': 401,
            'headers': headers,
            'body': json.dumps({'message': 'Unauthorized: Invalid token'})
        }

    # 2. Get status from ESP8266
    try:
        url = f"http://{ESP8266_IP}/status"
        esp_headers = {'X-Auth-Token': ESP8266_AUTH_TOKEN}

        response = requests.get(url, headers=esp_headers, timeout=5)
        response.raise_for_status() # Raise exception for bad status codes

        fan_data = response.json()
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({'status': 'connected', 'fanState': fan_data.get('fanState')})
        }
    except requests.exceptions.RequestException as e:
        return {
            'statusCode': 503,
            'headers': headers,
            'body': json.dumps({'status': 'disconnected', 'error': f'Could not reach fan controller: {str(e)}'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'message': f'Server error: {str(e)}'})
        }

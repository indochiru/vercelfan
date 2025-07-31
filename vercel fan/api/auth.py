import json
import os
import jwt
import datetime
import hashlib
import hmac
import secrets
import base64

# Get secrets from environment variables
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', '')
JWT_SECRET = os.environ.get('JWT_SECRET', '')

def pbkdf2_verify(password, stored_hash):
    """
    Verify password using PBKDF2 with SHA256
    stored_hash format: salt:iterations:hash (base64 encoded)
    """
    try:
        parts = stored_hash.split(':')
        if len(parts) != 3:
            return False
        
        salt = base64.b64decode(parts[0])
        iterations = int(parts[1])
        stored_key = base64.b64decode(parts[2])
        
        # Generate key from password
        password_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(password_key, stored_key)
    except:
        # If any error occurs (e.g., bad base64 padding), fail verification
        return False

def handler(event, context):
    # Standard headers for all responses
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'POST, OPTIONS'
    }
    
    # Handle preflight OPTIONS request
    if event['httpMethod'] == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({})
        }
    
    if event['httpMethod'] != 'POST':
        return {
            'statusCode': 405,
            'headers': headers,
            'body': json.dumps({'message': 'Method Not Allowed'})
        }

    try:
        body = json.loads(event.get('body', '{}'))
        password = body.get('password')

        # Verify password using PBKDF2
        if pbkdf2_verify(password, ADMIN_PASSWORD_HASH):
            # Generate JWT token that expires in 1 hour
            payload = {
                'user': 'admin',
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
            return {
                'statusCode': 200,
                'headers': headers,
                'body': json.dumps({'token': token})
            }
        else:
            # Return JSON error message for invalid password
            return {
                'statusCode': 401,
                'headers': headers,
                'body': json.dumps({'message': 'Invalid Access Code'})
            }

    except Exception as e:
        # Return JSON error message for any other server error
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'message': f'Server Error: {str(e)}'})
        }

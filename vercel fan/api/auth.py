import json
import os
import jwt
import datetime
import bcrypt

# Get secrets from environment variables
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', '')
JWT_SECRET = os.environ.get('JWT_SECRET', '')

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

        # Use bcrypt directly instead of passlib
        password_bytes = password.encode('utf-8')
        hash_bytes = ADMIN_PASSWORD_HASH.encode('utf-8')
        
        if bcrypt.checkpw(password_bytes, hash_bytes):
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

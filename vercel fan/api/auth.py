import json
import os
import bcrypt
import jwt
import datetime

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
        password = body.get('password', '').encode('utf-8')

        # Verify password against stored hash
        if bcrypt.checkpw(password, ADMIN_PASSWORD_HASH.encode('utf-8')):
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
            # Return JSON error message
            return {
                'statusCode': 401,
                'headers': headers,
                'body': json.dumps({'message': 'Invalid Access Code'})
            }

    except Exception as e:
        # Return JSON error message
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'message': f'Server Error: {str(e)}'})
        }

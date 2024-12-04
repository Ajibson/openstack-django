import json
from datetime import datetime, timedelta, timezone
import os
from cryptography.fernet import Fernet
import httpx
from django.conf import settings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64

import logging

logger = logging.getLogger(__name__)
TOKEN_FILE_PATH = 'openstack_token.json'

def get_fernet_key():
    # Django's SECRET_KEY is used here as the source of entropy.
    secret_key_bytes = settings.SECRET_KEY.encode()
    # Derive a key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Length required for Fernet keys
        salt=None,
        info=b'fernet key derivation'
    )
    key = hkdf.derive(secret_key_bytes)
    return base64.urlsafe_b64encode(key)  # Fernet requires the key to be base64 encoded


def encrypt_data(data):
    key = get_fernet_key()
    cipher = Fernet(key)
    encrypted_bytes =  cipher.encrypt(data.encode())
    encrypted_base64 = base64.urlsafe_b64encode(encrypted_bytes)
    return encrypted_base64.decode()

def decrypt_data(encrypted_data):
    key = get_fernet_key()
    cipher = Fernet(key)
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
    decrypted_bytes = cipher.decrypt(encrypted_bytes).decode()
    return decrypted_bytes

def save_token(token, expires_at):
    token_data = {
        'token': encrypt_data(token),
        'created': datetime.now().isoformat(),
        'expires': expires_at
    }
    with open(TOKEN_FILE_PATH, 'w') as f:
        json.dump(token_data, f, indent=4)

def load_token():
    if not os.path.exists(TOKEN_FILE_PATH):
        return None
    try:
        with open(TOKEN_FILE_PATH, 'r') as f:
            token_data = json.load(f)
    except json.decoder.JSONDecodeError:
        return False
    return token_data

def token_is_valid(expires_at, is_admin=None):
    if is_admin:
        expires_at = datetime.fromisoformat(expires_at)
    # Get the current time in UTC
    current_utc_time = datetime.now(timezone.utc)
    # Add a 5-minute buffer to the expiration time
    if current_utc_time >= expires_at - timedelta(minutes=5):
        return False
    return True



async def get_new_token_or_use_old_one(user=None, admin_pass=None):
    if admin_pass:
        username, password = settings.OPEN_STACK_ADMIN_USERNAME, settings.OPEN_STACK_ADMIN_PASSWORD
        token_data = load_token()
        if not token_data:
            token = None
        else:
            expires_at, token = token_data.get('expires'), token_data.get('token')
            if not expires_at or not token:
                token =  None
    elif user:
        token, expires_at = user.open_stack_token, user.token_expires_at
        username, password = user.username, user.password[20:61]
    if token:
        if token_is_valid(expires_at, admin_pass):
            return (None, decrypt_data(token), None, None)
    return (username, password)

async def get_openstack_token(user=None, admin_pass=None):
    get_new_token_check = await get_new_token_or_use_old_one(user, admin_pass)
    if len(get_new_token_check) == 4:
        return get_new_token_check[0], get_new_token_check[1], get_new_token_check[2], get_new_token_check[3]
    else:
        username, password = get_new_token_check[0], get_new_token_check[1]
    auth_url = f"{settings.OPEN_STACK_AUTH_URL}/v3/auth/tokens"
    auth_data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"id": "default"},
                        "password": password
                    }
                }
            }
        }
    }
    if admin_pass:
        auth_data['auth'].update({ "scope": {
                "project": {
                    "id": settings.OPEN_STACK_ADMIN_PROJECT_ID
                }
            }})
    headers = {'Content-Type': 'application/json'}
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.post(auth_url, json=auth_data, headers=headers)
        if resp.status_code != 201:
            from rest_framework import serializers
            raise serializers.ValidationError("Error logging in to open stack")
        token = resp.headers["X-Subject-Token"]
        token_body = resp.json()  # Parse the JSON response body
        expires_at = token_body['token']['expires_at']
        if admin_pass:
            save_token(token, expires_at)
        return encrypt_data(token), token, resp.json()['token']['expires_at'], resp.json()['token']['issued_at']

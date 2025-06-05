from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
from GetWishListItems_pb2 import CSGetWishListItemsRes
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2
from datetime import datetime

app = Flask(__name__)

# Encryption config
key = "Yg&tc%DEuh6%Zc^8"
iv = "6oyZDr22E3ychjM%"

# Convert timestamp to readable format
def convert_timestamp(release_time):
    return datetime.utcfromtimestamp(release_time).strftime('%Y-%m-%d %H:%M:%S')

# Choose correct endpoint based on region
def get_api_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetWishListItems",
        "BR": "https://client.us.freefiremobile.com/GetWishListItems",
        "US": "https://client.us.freefiremobile.com/GetWishListItems",
        "SAC": "https://client.us.freefiremobile.com/GetWishListItems",
        "NA": "https://client.us.freefiremobile.com/GetWishListItems",
        "default": "https://clientbp.ggblueshark.com/GetWishListItems"
    }
    return endpoints.get(region, endpoints["default"])

# Extract token from API response
def extract_token_from_response(data, region):
    if region == "IND":
        if data.get('status') in ['success', 'live']:
            return data.get('token')
    elif region in ["BR", "US", "SAC", "NA"]:
        if isinstance(data, dict) and 'token' in data:
            return data['token']
    else:
        if data.get('status') == 'success':
            return data.get('token')
    return None

# Get JWT token from external APIs
def get_jwt_token(region):
    endpoints = {
        "IND": "https://nr-codex-jwtapi.vercel.app/token?uid=3921004570&password=D4156E856495027083FF4B08F593422A8B6B1C4033D72C7B2155F6E7CCCC4A88",
        "BR": "https://tokenalljwt.onrender.com/api/oauth_guest?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
        "US": "https://tokenalljwt.onrender.com/api/oauth_guest?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
        "SAC": "https://tokenalljwt.onrender.com/api/oauth_guest?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
        "NA": "https://tokenalljwt.onrender.com/api/oauth_guest?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
        "default": "https://projects-fox-x-get-jwt.vercel.app/get?uid=3763606630&password=7FF33285F290DDB97D9A31010DCAA10C2021A03F27C4188A2F6ABA418426527C"
    }
    url = endpoints.get(region, endpoints["default"])
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return extract_token_from_response(data, region)
    except Exception as e:
        print(f"JWT token fetch error: {e}")
    return None

# AES Encryption
def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

# Send request to official Free Fire API
def apis(encrypted_hex, token, region):
    endpoint = get_api_endpoint(region)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB48',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    try:
        response = requests.post(endpoint, headers=headers, data=bytes.fromhex(encrypted_hex), timeout=10)
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        print(f"API call failed: {e}")
        return None

# Main API route
@app.route('/wish', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'default').upper()
        custom_key = request.args.get('key', key)
        custom_iv = request.args.get('iv', iv)

        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400

        token = get_jwt_token(region)
        if not token:
            return jsonify({"error": "Failed to get JWT token"}), 500

        # Create protobuf request
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()

        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        response_hex = apis(encrypted_hex, token, region)

        if not response_hex:
            return jsonify({"error": "Empty or failed API response"}), 500

        api_response_bytes = bytes.fromhex(response_hex)
        decoded_response = CSGetWishListItemsRes()
        decoded_response.ParseFromString(api_response_bytes)

        wishlist = [
            {
                "item_id": item.item_id,
                "release_time": convert_timestamp(item.release_time)
            }
            for item in decoded_response.items
        ]

        return jsonify({"uid": uid, "wishlist": wishlist})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 404

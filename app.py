from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
from GetWishListItems_pb2 import CSGetWishListItemsRes
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2
import threading
import time
from datetime import datetime

app = Flask(__name__)
jwt_token = None
jwt_lock = threading.Lock()

# Convert timestamp to readable format
def convert_timestamp(release_time):
    return datetime.utcfromtimestamp(release_time).strftime('%Y-%m-%d %H:%M:%S')

# Universal token extractor
def extract_token_from_response(data, region):
    print(f"[DEBUG] Extracting token for {region}: {data}")
    if not isinstance(data, dict):
        return None

    if region == "IND":
        return data.get('token') or data.get('jwt') or data.get('data')
    elif region in ["BR", "US", "SAC", "NA"]:
        return data.get('token')
    else:
        return data.get('token') or data.get('jwt')

# Get JWT token from external service
def get_jwt_token_sync(region):
    global jwt_token
    endpoints = {
        "IND": "https://ff-token-generator.vercel.app/token?uid=3562381559&password=AF18F2EB5A410D815F54B16EAEAC369FC027E96925005A629E90A823996B0240",
        "BR": "https://tokenalljwt.onrender.com/api/oauth_guest?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
        "US": "https://tokenalljwt.onrender.com/api/oauth_guest?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
        "SAC": "https://tokenalljwt.onrender.com/api/oauth_guest?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
        "NA": "https://tokenalljwt.onrender.com/api/oauth_guest?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
        "default": "https://projects-fox-x-get-jwt.vercel.app/get?uid=3763606630&password=7FF33285F290DDB97D9A31010DCAA10C2021A03F27C4188A2F6ABA418426527C"
    }

    url = endpoints.get(region, endpoints["default"])
    with jwt_lock:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                print(f"[DEBUG] Raw token response for {region}: {data}")
                token = extract_token_from_response(data, region)
                if token:
                    jwt_token = token
                    print(f"[INFO] JWT Token for {region} updated successfully.")
                    return jwt_token
                else:
                    print(f"[ERROR] Failed to extract token for region {region}")
            else:
                print(f"[ERROR] HTTP {response.status_code} getting token for {region}")
        except Exception as e:
            print(f"[EXCEPTION] Token request for {region} failed: {e}")
    return None

# Ensure a token is available
def ensure_jwt_token_sync(region):
    global jwt_token
    if not jwt_token:
        print(f"[INFO] JWT token for {region} is missing. Trying to fetch...")
        return get_jwt_token_sync(region)
    return jwt_token

# Background thread to refresh token
def jwt_token_updater(region):
    while True:
        get_jwt_token_sync(region)
        time.sleep(300)

# API endpoint selection based on region
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

# AES Encryptor
key = "Yg&tc%DEuh6%Zc^8"
iv = "6oyZDr22E3ychjM%"
def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

# API Logic
def apis(idd, region):
    global jwt_token
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"Failed to get JWT token for region {region}")
    endpoint = get_api_endpoint(region)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB49',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    try:
        data = bytes.fromhex(idd)
        response = requests.post(endpoint, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] API request failed: {e}")
        raise

# Flask route
@app.route('/wish', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'default').upper()
        custom_key = request.args.get('key', key)
        custom_iv = request.args.get('iv', iv)

        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400

        threading.Thread(target=jwt_token_updater, args=(region,), daemon=True).start()

        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        api_response_hex = apis(encrypted_hex, region)
        if not api_response_hex:
            return jsonify({"error": "Empty response from API"}), 400

        api_response_bytes = bytes.fromhex(api_response_hex)
        decoded_response = CSGetWishListItemsRes()
        decoded_response.ParseFromString(api_response_bytes)

        wishlist = [
            {"item_id": item.item_id, "release_time": convert_timestamp(item.release_time)}
            for item in decoded_response.items
        ]
        return jsonify({"uid": uid, "wishlist": wishlist})

    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"[EXCEPTION] {e}")
        return jsonify({"error": f"Failure: {str(e)}"}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 404

if __name__ == "__main__":
    ensure_jwt_token_sync("default")
    app.run(host="0.0.0.0", port=5560)  # change from 5552 to 5560
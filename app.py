import os
import re
import json
import base64
import hashlib
import binascii
import itertools
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, template_folder='templates')

# 進捗（何番目のパスワードまで試したか）を保存するJSONファイル
PROGRESS_FILE = "search_progress.json"

# 🛠️ 自動生成に使用する文字セット（試したい文字に応じて変更可能）
# ここでは「数字（0-9）」と「英小文字（a-z）」を対象にしています
CHAR_SET = "0123456789abcdefghijklmnopqrstuvwxyz"

def get_current_index():
    """現在の試行進捗（インデックス）をJSONから読み込む"""
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("current_index", 0)
        except Exception:
            pass
    return 0

def save_progress(index):
    """現在の試行進捗をJSONに保存する"""
    try:
        with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
            json.dump({"current_index": index}, f, ensure_ascii=False, indent=4)
    except Exception as e:
        print(f"[-] 進捗保存エラー: {e}")

def generate_password_by_index(index, chars=CHAR_SET):
    """
    インデックス番号から一意のパスワード文字列を自動生成する
    0 -> a, 1 -> b ... 桁数も自動で繰り上がります（総当たりアルゴリズム）
    """
    if index == 0:
        return chars[0]
    result = []
    base = len(chars)
    while index > 0:
        index, rem = divmod(index - 1, base)
        result.append(chars[rem])
    return "".join(reversed(result))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/decrypt_auto', methods=['POST'])
def decrypt_auto():
    html_content = request.form.get("html_content", "")
    
    # 現在どこまで試したかを取得
    current_index = get_current_index()
    
    # 今回の通信で試すパスワードを自動生成
    password = generate_password_by_index(current_index)

    try:
        # HTMLからソルト値と暗号データを抽出
        salt_match = re.search(r'"staticryptSaltUniqueVariableName":"([a-f0-9]+)"', html_content)
        crypto_match = re.search(r'id="staticrypt-encrypted"[^>]*>([^<]+)', html_content) or \
                       re.search(r'data-crypto="([^"]+)"', html_content) or \
                       re.search(r'var encrypted = "([^"]+)"', html_content)

        if not salt_match or not crypto_match:
            return jsonify({"status": "error", "message": "HTMLデータの抽出に失敗しました。"})
        
        salt = binascii.unhexlify(salt_match.group(1))
        encrypted_data_raw = crypto_match.group(1).strip()

        # 進捗を1つ進めて保存（被りなしで次回は次の文字が生成される）
        save_progress(current_index + 1)

        # パスワードから暗号鍵を導出（PBKDF2-HMAC-SHA256 60万回）
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000, 32)

        # AES復号テスト
        from Crypto.Cipher import AES
        try:
            encrypted_bytes = base64.b64decode(encrypted_data_raw)
            iv = encrypted_bytes[:16]
            ciphertext = encrypted_bytes[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_bytes = cipher.decrypt(ciphertext)
            
            padding_len = decrypted_bytes[-1]
            if padding_len < 16:
                decrypted_text = decrypted_bytes[:-padding_len].decode('utf-8', errors='strict')
            else:
                decrypted_text = decrypted_bytes.decode('utf-8', errors='strict')

            # 復号成否の判定
            if "<script" in decrypted_text or "<html" in decrypted_text or "const" in decrypted_text:
                return jsonify({"status": "success", "password": password})
            else:
                return jsonify({"status": "fail", "password": password})

        except Exception:
            return jsonify({"status": "fail", "password": password})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
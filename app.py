import os
import re
import json
import base64
import hashlib
import binascii
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, template_folder='templates')

# 試行済みパスワードを保存するJSONファイルのパス
JSON_FILE = "tested_passwords.json"

def load_tested_passwords():
    """JSONファイルから試行済みのパスワードリストを読み込んでsetで返す"""
    if os.path.exists(JSON_FILE):
        try:
            with open(JSON_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return set(data)
        except Exception:
            pass
    return set()

def save_tested_password(password):
    """新しく試したパスワードをJSONファイルに追記保存する"""
    tested = load_tested_passwords()
    tested.add(password)
    try:
        with open(JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(list(tested), f, ensure_ascii=False, indent=4)
    except Exception as e:
        print(f"[-] JSON保存エラー: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/decrypt', methods=['POST'])
def decrypt_attempt():
    html_content = request.form.get("html_content", "")
    password = request.form.get("password", "")

    # 1. 過去に試行済みかどうかのチェック（被り排除）
    tested_list = load_tested_passwords()
    if password in tested_list:
        return jsonify({"status": "skipped", "message": "試行済み（スキップ）"})

    try:
        # 2. HTMLからソルト値と暗号データを抽出
        salt_match = re.search(r'"staticryptSaltUniqueVariableName":"([a-f0-9]+)"', html_content)
        crypto_match = re.search(r'id="staticrypt-encrypted"[^>]*>([^<]+)', html_content) or \
                       re.search(r'data-crypto="([^"]+)"', html_content) or \
                       re.search(r'var encrypted = "([^"]+)"', html_content)

        if not salt_match:
            return jsonify({"status": "error", "message": "HTMLからソルト（Salt）を抽出できませんでした。"})
        if not crypto_match:
            return jsonify({"status": "error", "message": "HTMLから暗号データを抽出できませんでした。"})
        
        salt = binascii.unhexlify(salt_match.group(1))
        encrypted_data_raw = crypto_match.group(1).strip()

        # 3. 新規パスワードを試すので、先にJSONリストへ記録
        save_tested_password(password)

        # 4. パスワードから暗号鍵を導出（PBKDF2-HMAC-SHA256 を60万回）
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000, 32)

        # 5. Cryptoライブラリの遅延インポート（エラー回避用）とAES復号
        from Crypto.Cipher import AES
        try:
            encrypted_bytes = base64.b64decode(encrypted_data_raw)
            iv = encrypted_bytes[:16]
            ciphertext = encrypted_bytes[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_bytes = cipher.decrypt(ciphertext)
            
            # パディング解除
            padding_len = decrypted_bytes[-1]
            if padding_len < 16:
                decrypted_text = decrypted_bytes[:-padding_len].decode('utf-8', errors='strict')
            else:
                decrypted_text = decrypted_bytes.decode('utf-8', errors='strict')

            # 6. 復号成否の厳密判定（正しいHTMLやJSの構文が戻ってきたか）
            if "<script" in decrypted_text or "<html" in decrypted_text or "const" in decrypted_text:
                return jsonify({"status": "success"})
            else:
                return jsonify({"status": "fail"})

        except Exception:
            # 復号エラー（パスワード不一致によるデータ破損状態）
            return jsonify({"status": "fail"})

    except Exception as e:
        return jsonify({"status": "fail", "reason": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
import os
import re
import hashlib
import binascii
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/decrypt', methods=['POST'])
def decrypt_attempt():
    html_content = request.form.get("html_content", "")
    password = request.form.get("password", "")

    try:
        # HTMLからソルト値を抽出 (StatiCryptの設定値)
        salt_match = re.search(r'"staticryptSaltUniqueVariableName":"([a-f0-9]+)"', html_content)
        if not salt_match:
            return jsonify({"status": "error", "message": "Saltが見つかりません"})
        
        salt = binascii.unhexlify(salt_match.group(1))
        
        # PBKDF2による鍵導出（60万回ループを再現）
        # ※実際のStatiCrypt v3/v4の仕様に合わせて計算します
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000, 32)

        # 🛠️ ここに本来はAES-GCMやCBCの復号ロジックを入れ、
        # 復号された文字列が正しいHTML構造（"<!DOCTYPE"等）を含んでいるかチェックします。
        # 今回は「テスト実行」として成否のダミー判定を返します
        success_trigger = False 

        if success_trigger:
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "fail"})

    except Exception as e:
        return jsonify({"status": "fail", "reason": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
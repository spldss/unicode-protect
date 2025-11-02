from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import json
# 在加密接口添加速率限制
from flask_limiter import Limiter
limiter = Limiter(app=app, key_func=get_remote_address)


app = Flask(__name__)

# Unicode 方块字符映射（简化版）
BLOCK_CHARS = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█', '▉', '▊', '▋', '▌', '▍', '▎', '▏', '■']
BLOCK_MAP = {c: i for i, c in enumerate(BLOCK_CHARS)}

# 加密模式（仅保留核心 3 种 + 组合）
MODES = {
    'single_aes': '单AES',
    'single_vigenere': '单Vigenère',
    'single_unicode': '单Unicode',
    'all_three': '三者组合'
}

def aes_encrypt(data, key, iv):
    """AES-256-CBC 加密（简化版）"""
    cipher = AES.new(key.ljust(32, b'\0')[:32], AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(encrypted).decode()

def aes_decrypt(encrypted, key, iv):
    """AES-256-CBC 解密（简化版）"""
    encrypted_bytes = base64.b64decode(encrypted)
    cipher = AES.new(key.ljust(32, b'\0')[:32], AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_bytes), AES.block_size).decode()

def vigenere_encrypt(text, keyword):
    """Vigenère 加密（简化版，仅字母）"""
    res = []
    kw = keyword.upper()
    for c in text:
        if c.isalpha():
            shift = ord(kw[(len(res)) % len(kw)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            res.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            res.append(c)
    return ''.join(res)

def vigenere_decrypt(text, keyword):
    """Vigenère 解密（简化版，仅字母）"""
    res = []
    kw = keyword.upper()
    for c in text:
        if c.isalpha():
            shift = ord(kw[(len(res)) % len(kw)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            res.append(chr((ord(c) - base - shift) % 26 + base))
        else:
            res.append(c)
    return ''.join(res)

def unicode_encrypt(text):
    """Unicode 方块编码（简化版）"""
    return ''.join([BLOCK_CHARS[ord(c) % 16] for c in text])

def unicode_decrypt(block_str):
    """Unicode 方块解码（简化版）"""
    return ''.join([chr(BLOCK_MAP.get(c, 0) + 65) for c in block_str])

@app.route('/')
def index():
    return render_template('index.html', modes=MODES)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        plaintext = data['plaintext']
        mode = data['mode']
        aes_key = data.get('aes_key', 'default_key').encode()
        vigenere_key = data.get('vigenere_key', 'KEY')

        if mode == 'single_aes':
            iv = get_random_bytes(16)
            encrypted = aes_encrypt(plaintext, aes_key, iv)
            return jsonify({'encrypted': encrypted, 'iv': iv.hex()})
        
        elif mode == 'single_vigenere':
            encrypted = vigenere_encrypt(plaintext, vigenere_key)
            return jsonify({'encrypted': encrypted})
        
        elif mode == 'single_unicode':
            encrypted = unicode_encrypt(plaintext)
            return jsonify({'encrypted': encrypted})
        
        elif mode == 'all_three':
            iv = get_random_bytes(16)
            aes_enc = aes_encrypt(plaintext, aes_key, iv)
            vigenere_enc = vigenere_encrypt(aes_enc, vigenere_key)
            encrypted = unicode_encrypt(vigenere_enc)
            return jsonify({'encrypted': encrypted, 'iv': iv.hex()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        encrypted = data['encrypted']
        mode = data['mode']
        aes_key = data.get('aes_key', 'default_key').encode()
        vigenere_key = data.get('vigenere_key', 'KEY')
        iv_hex = data.get('iv', '')

        if mode == 'single_aes':
            iv = bytes.fromhex(iv_hex)
            decrypted = aes_decrypt(encrypted, aes_key, iv)
            return jsonify({'decrypted': decrypted})
        
        elif mode == 'single_vigenere':
            decrypted = vigenere_decrypt(encrypted, vigenere_key)
            return jsonify({'decrypted': decrypted})
        
        elif mode == 'single_unicode':
            decrypted = unicode_decrypt(encrypted)
            return jsonify({'decrypted': decrypted})
        
        elif mode == 'all_three':
            nums = [BLOCK_MAP.get(c, 0) for c in encrypted]
            vigenere_enc = ''.join([chr(n + 65) for n in nums])
            aes_enc = vigenere_decrypt(vigenere_enc, vigenere_key)
            iv = bytes.fromhex(iv_hex)
            decrypted = aes_decrypt(aes_enc, aes_key, iv)
            return jsonify({'decrypted': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)  # 关闭调试模式

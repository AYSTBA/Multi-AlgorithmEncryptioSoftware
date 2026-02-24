import os
import json
import hashlib
import struct
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# ================== 算法配置管理 ==================
DEFAULT_CONFIG = {
    "name": "DefaultChaosV1",
    "chaos": {
        "logistic_r": 3.99,
        "tent_mu": 1.99,
        "hash_function": "sha256"
    },
    "operations": {
        "allowed": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],  # 所有16种操作
        "probabilities": None,  # 改为 None，表示均匀分布
        "params": {
            "shift_range": [0,7],
            "mult_odd_only": True
        }
    },
    "mode": "CFB",                # 反馈模式
    "iv_size": 16
}

class AlgorithmConfig:
    """加载/保存算法配置"""
    def __init__(self, config_file=None):
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = DEFAULT_CONFIG.copy()
        self.validate()

    def validate(self):
        """检查配置有效性"""
        ops = self.config['operations']['allowed']
        for op in ops:
            if op < 0 or op > 15:
                raise ValueError(f"无效操作类型 {op}，必须为0-15")

    def save(self, config_file):
        with open(config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

# ================== 增强型混沌核心（可配置） ==================
class ConfigurableChaosCrypto:
    """可配置的混沌加密核心"""

    def __init__(self, config: AlgorithmConfig):
        self.config = config
        self.inv_table = {i: self._modinv(i, 256) for i in range(1, 256, 2)}

    def _modinv(self, a, m):
        g, x, _ = self._egcd(a, m)
        return x % m if g == 1 else None

    def _egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = self._egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    def _logistic_map(self, x, r=None):
        r = r or self.config.config['chaos']['logistic_r']
        return r * x * (1 - x)

    def _tent_map(self, x, mu=None):
        mu = mu or self.config.config['chaos']['tent_mu']
        if x < 0.5:
            return mu * x
        else:
            return mu * (1 - x)

    def _mix_chaos(self, seed, idx, length):
        h = hashlib.sha512(seed + idx.to_bytes(4, 'big')).digest()
        x1 = struct.unpack('Q', h[:8])[0] / 2**64
        x2 = struct.unpack('Q', h[8:16])[0] / 2**64
        r = self.config.config['chaos']['logistic_r'] + (h[16] / 256) * 0.01

        result = bytearray()
        for _ in range(length):
            x1 = self._logistic_map(x1, r)
            x2 = self._tent_map(x2)
            combined = (x1 + x2) % 1.0
            byte_val = int(combined * 256) & 0xFF
            result.append(byte_val)
        return bytes(result)

    def _get_op_type(self, rand_byte, prev):
        allowed = self.config.config['operations']['allowed']
        if len(allowed) == 1:
            return allowed[0]
        probs = self.config.config['operations'].get('probabilities')
        if probs and len(probs) == len(allowed):
            r = rand_byte / 256.0
            cum = 0
            for op, p in zip(allowed, probs):
                cum += p
                if r < cum:
                    return op
            return allowed[-1]
        else:
            idx = rand_byte % len(allowed)
            return allowed[idx]

    def _generate_sbox(self, seed, idx):
        rand = self._mix_chaos(seed, idx, 256)
        indices = list(range(256))
        for i in range(255, 0, -1):
            j = rand[i] % (i + 1)
            indices[i], indices[j] = indices[j], indices[i]
        sbox = bytes(indices)
        inv_sbox = bytearray(256)
        for i, v in enumerate(sbox):
            inv_sbox[v] = i
        return sbox, bytes(inv_sbox)

    def encrypt(self, data: bytes, seed: bytes) -> bytes:
        if not data:
            return b''
        iv = self._mix_chaos(seed, 0, self.config.config['iv_size'])
        cipher = bytearray()
        prev = iv

        for i, p in enumerate(data):
            key_stream = self._mix_chaos(seed + prev, i, 1)[0]
            op_type = self._get_op_type(key_stream, prev)
            param = key_stream & 0x0F

            if op_type == 0:
                tmp = (p + param) & 0xFF
            elif op_type == 1:
                tmp = (p - param) & 0xFF
            elif op_type == 2:
                tmp = p ^ param
            elif op_type == 3:
                k = param if param % 2 else param + 1
                tmp = (p * k) & 0xFF
            elif op_type == 4:
                shift = param % 8
                tmp = ((p << shift) | (p >> (8 - shift))) & 0xFF
            elif op_type == 5:
                shift = param % 8
                tmp = ((p >> shift) | (p << (8 - shift))) & 0xFF
            elif op_type == 6:
                tmp = p ^ 0xFF
            elif op_type == 7:
                tmp = ((p & 0x0F) << 4) | ((p & 0xF0) >> 4)
            elif op_type == 8:
                a = param if param % 2 else param + 1
                b = (key_stream >> 4) & 0x0F
                tmp = (a * p + b) & 0xFF
            elif op_type == 9:
                sbox, _ = self._generate_sbox(seed + prev, i)
                tmp = sbox[p]
            elif op_type == 10:
                tmp = p ^ prev[i % len(prev)]
            elif op_type == 11:
                if p == 0:
                    tmp = 0
                else:
                    k = param if param % 2 else param + 1
                    tmp = (p * k) & 0xFF
            elif op_type == 12:
                tmp = (p + prev[i % len(prev)]) & 0xFF
            elif op_type == 13:
                tmp = p ^ prev[i % len(prev)]
            elif op_type == 14:
                shift = prev[i % len(prev)] % 8
                tmp = ((p << shift) | (p >> (8 - shift))) & 0xFF
            elif op_type == 15:
                shift = prev[i % len(prev)] % 8
                tmp = ((p >> shift) | (p << (8 - shift))) & 0xFF
            else:
                tmp = p

            c = tmp ^ key_stream
            cipher.append(c)
            prev = cipher[-16:] if len(cipher) >= 16 else cipher

        return iv + bytes(cipher)

    def decrypt(self, ciphertext: bytes, seed: bytes) -> bytes:
        if not ciphertext:
            return b''
        iv = ciphertext[:self.config.config['iv_size']]
        cipher_data = ciphertext[self.config.config['iv_size']:]
        plain = bytearray()
        prev = iv

        for i, c in enumerate(cipher_data):
            key_stream = self._mix_chaos(seed + prev, i, 1)[0]
            op_type = self._get_op_type(key_stream, prev)
            param = key_stream & 0x0F

            tmp = c ^ key_stream

            if op_type == 0:
                p = (tmp - param) & 0xFF
            elif op_type == 1:
                p = (tmp + param) & 0xFF
            elif op_type == 2:
                p = tmp ^ param
            elif op_type == 3:
                k = param if param % 2 else param + 1
                inv = self.inv_table[k]
                p = (tmp * inv) & 0xFF
            elif op_type == 4:
                shift = param % 8
                p = ((tmp >> shift) | (tmp << (8 - shift))) & 0xFF
            elif op_type == 5:
                shift = param % 8
                p = ((tmp << shift) | (tmp >> (8 - shift))) & 0xFF
            elif op_type == 6:
                p = tmp ^ 0xFF
            elif op_type == 7:
                p = ((tmp & 0x0F) << 4) | ((tmp & 0xF0) >> 4)
            elif op_type == 8:
                a = param if param % 2 else param + 1
                inv_a = self.inv_table[a]
                b = (key_stream >> 4) & 0x0F
                p = (inv_a * (tmp - b)) & 0xFF
            elif op_type == 9:
                _, inv_sbox = self._generate_sbox(seed + prev, i)
                p = inv_sbox[tmp]
            elif op_type == 10:
                p = tmp ^ prev[i % len(prev)]
            elif op_type == 11:
                if tmp == 0:
                    p = 0
                else:
                    k = param if param % 2 else param + 1
                    inv = self.inv_table[k]
                    p = (tmp * inv) & 0xFF
            elif op_type == 12:
                p = (tmp - prev[i % len(prev)]) & 0xFF
            elif op_type == 13:
                p = tmp ^ prev[i % len(prev)]
            elif op_type == 14:
                shift = prev[i % len(prev)] % 8
                p = ((tmp >> shift) | (tmp << (8 - shift))) & 0xFF
            elif op_type == 15:
                shift = prev[i % len(prev)] % 8
                p = ((tmp << shift) | (tmp >> (8 - shift))) & 0xFF
            else:
                p = tmp

            plain.append(p)
            prev = cipher_data[max(0, i+1-16):i+1] if i+1 >= 16 else cipher_data[:i+1]

        return bytes(plain)


# ================== ECIES 封装 ==================
def encrypt_seed_with_ecies(seed, public_key_hex):
    pub_key_bytes = bytes.fromhex(public_key_hex)
    recipient_key = ECC.import_key(pub_key_bytes, curve_name='P-256')
    ephemeral_key = ECC.generate(curve='P-256')
    temp_pub = ephemeral_key.public_key().export_key(format='raw')
    shared_secret = ephemeral_key.d * recipient_key.pointQ
    shared_secret_bytes = shared_secret.x.to_bytes(32, 'big')
    aes_key = HKDF(shared_secret_bytes, 32, salt=b'', context=b'ChaosCrypto-ECIES', hashmod=SHA256)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=get_random_bytes(12))
    ciphertext, tag = cipher.encrypt_and_digest(seed)
    return temp_pub + cipher.nonce + tag + ciphertext

def decrypt_seed_with_ecies(encrypted_package, private_key_hex):
    d = int.from_bytes(bytes.fromhex(private_key_hex), 'big')
    own_key = ECC.construct(curve='P-256', d=d)
    temp_pub = encrypted_package[:65]
    nonce = encrypted_package[65:77]
    tag = encrypted_package[77:93]
    ciphertext = encrypted_package[93:125]
    temp_key = ECC.import_key(temp_pub, curve_name='P-256')
    shared_secret = own_key.d * temp_key.pointQ
    shared_secret_bytes = shared_secret.x.to_bytes(32, 'big')
    aes_key = HKDF(shared_secret_bytes, 32, salt=b'', context=b'ChaosCrypto-ECIES', hashmod=SHA256)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    seed = cipher.decrypt_and_verify(ciphertext, tag)
    return seed

def generate_ecc_keypair():
    key = ECC.generate(curve='P-256')
    private_hex = key.d.to_bytes(32, 'big').hex()
    public_hex = key.public_key().export_key(format='raw').hex()
    return private_hex, public_hex


# ================== 主程序 ==================
def main():
    config_file = "chaos_config.json"
    config = AlgorithmConfig(config_file)
    crypto = ConfigurableChaosCrypto(config)

    print("=" * 70)
    print(f"        混合乱序加密算法系统 (当前算法: {config.config['name']})")
    print("=" * 70)

    while True:
        print("\n请选择操作：")
        print("1. 生成ECC密钥对")
        print("2. 使用公钥加密文本")
        print("3. 使用私钥解密文本")
        print("4. 使用公钥加密文件")
        print("5. 使用私钥解密文件")
        print("6. 查看/修改算法配置")
        print("7. 退出")
        choice = input("输入数字 (1-7): ").strip()

        if choice == '1':
            private_hex, public_hex = generate_ecc_keypair()
            print("\n【私钥（64字符）】")
            print("-" * 50)
            print(private_hex)
            print("-" * 50)
            print("\n【公钥（130字符）】")
            print("-" * 50)
            print(public_hex)
            print("-" * 50)
            input("\n按回车键继续...")

        elif choice == '2':
            print("\n请输入对方公钥（130字符十六进制）：")
            pub_hex = input().strip().replace(' ', '').replace('\n', '')
            if len(pub_hex) != 130:
                print("公钥长度应为130！")
                input("按回车键继续...")
                continue
            plaintext = input("请输入要加密的文本: ")
            try:
                seed = os.urandom(32)
                enc_seed = encrypt_seed_with_ecies(seed, pub_hex)
                data = plaintext.encode('utf-8')
                cipher_data = crypto.encrypt(data, seed)
                final_cipher = enc_seed + cipher_data
                print("\n【密文（十六进制）】")
                print("-" * 50)
                print(final_cipher.hex())
                print("-" * 50)
            except Exception as e:
                print(f"加密失败: {e}")
            input("按回车键继续...")

        elif choice == '3':
            print("\n请输入您的私钥（64字符十六进制）：")
            priv_hex = input().strip().replace(' ', '').replace('\n', '')
            if len(priv_hex) != 64:
                print("私钥长度应为64！")
                input("按回车键继续...")
                continue
            cipher_hex = input("请输入密文（十六进制）: ").strip().replace(' ', '').replace('\n', '')
            try:
                cipher_bytes = bytes.fromhex(cipher_hex)
                enc_seed = cipher_bytes[:125]
                cipher_data = cipher_bytes[125:]
                seed = decrypt_seed_with_ecies(enc_seed, priv_hex)
                plain_data = crypto.decrypt(cipher_data, seed)
                print("\n【解密结果】")
                print("-" * 50)
                print(plain_data.decode('utf-8'))
                print("-" * 50)
            except Exception as e:
                print(f"解密失败: {e}")
            input("按回车键继续...")

        elif choice == '4':
            print("\n请输入对方公钥（130字符十六进制）：")
            pub_hex = input().strip().replace(' ', '').replace('\n', '')
            if len(pub_hex) != 130:
                print("公钥长度应为130！")
                input("按回车键继续...")
                continue
            file_path = input("请输入要加密的文件路径: ").strip()
            if not os.path.exists(file_path):
                print("文件不存在！")
                input("按回车键继续...")
                continue
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                seed = os.urandom(32)
                enc_seed = encrypt_seed_with_ecies(seed, pub_hex)
                cipher_data = crypto.encrypt(file_data, seed)
                final_cipher = enc_seed + cipher_data
                out_path = file_path + ".enc"
                with open(out_path, 'wb') as f:
                    f.write(final_cipher)
                print(f"加密完成，密文已保存至: {out_path}")
            except Exception as e:
                print(f"加密失败: {e}")
            input("按回车键继续...")

        elif choice == '5':
            print("\n请输入您的私钥（64字符十六进制）：")
            priv_hex = input().strip().replace(' ', '').replace('\n', '')
            if len(priv_hex) != 64:
                print("私钥长度应为64！")
                input("按回车键继续...")
                continue
            file_path = input("请输入要解密的文件路径（.enc）: ").strip()
            if not os.path.exists(file_path):
                print("文件不存在！")
                input("按回车键继续...")
                continue
            try:
                with open(file_path, 'rb') as f:
                    cipher_bytes = f.read()
                enc_seed = cipher_bytes[:125]
                cipher_data = cipher_bytes[125:]
                seed = decrypt_seed_with_ecies(enc_seed, priv_hex)
                plain_data = crypto.decrypt(cipher_data, seed)
                out_path = file_path[:-4] if file_path.endswith('.enc') else file_path + ".dec"
                with open(out_path, 'wb') as f:
                    f.write(plain_data)
                print(f"解密完成，文件已保存至: {out_path}")
            except Exception as e:
                print(f"解密失败: {e}")
            input("按回车键继续...")

        elif choice == '6':
            print("\n当前算法配置:")
            print(json.dumps(config.config, indent=4))
            print("\n1. 保存配置到文件")
            print("2. 从文件重新加载配置")
            print("3. 返回主菜单")
            sub = input("选择: ").strip()
            if sub == '1':
                save_file = input("保存文件名 (默认 chaos_config.json): ").strip() or "chaos_config.json"
                config.save(save_file)
                print(f"配置已保存至 {save_file}")
            elif sub == '2':
                load_file = input("加载文件名 (默认 chaos_config.json): ").strip() or "chaos_config.json"
                try:
                    config = AlgorithmConfig(load_file)
                    crypto = ConfigurableChaosCrypto(config)
                    print("配置加载成功！")
                except Exception as e:
                    print(f"加载失败: {e}")
            input("按回车键继续...")

        elif choice == '7':
            print("感谢使用，再见！")
            break

        else:
            print("无效选择，请重新输入。")


if __name__ == "__main__":
    main()
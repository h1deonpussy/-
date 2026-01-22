# hybrid_engine.py
# ---------------------------------------------------------
# 【核心模块】混合加密引擎 (Hybrid Encryption Engine)
# 实现了 "数字信封" 技术：
# 1. 使用随机生成的 AES 密钥 (Session Key) 高速加密数据
# 2. 使用接收方的 RSA 公钥加密 AES 密钥，确保只有对方能解开
# ---------------------------------------------------------

import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class HybridCipher:
    def __init__(self):
        # AES 块大小，通常为 16 字节
        self.block_size = AES.block_size

    def encrypt_data(self, data_bytes, target_public_key_pem):
        """
        混合加密流程 (发送方调用):
        :param data_bytes: 要加密的原始数据 (bytes 格式)
        :param target_public_key_pem: 接收方的 RSA 公钥 (PEM 格式)
        :return: 包含加密密钥、IV 和密文的字典
        """
        try:
            # 1. 生成随机的 AES 会话密钥 (32字节 = 256位，强度极高)
            session_key = get_random_bytes(32)
            
            # 2. 使用 AES-CBC 模式加密数据 (速度快，适合大文件/长文本)
            cipher_aes = AES.new(session_key, AES.MODE_CBC)
            iv = cipher_aes.iv # 获取初始化向量
            # 对数据进行填充并加密
            encrypted_data = cipher_aes.encrypt(pad(data_bytes, self.block_size))
            
            # 3. 使用 RSA 公钥加密 session_key (数字信封核心步骤)
            # 这样只有拥有对应私钥的人才能拿到 session_key
            recipient_key = RSA.import_key(target_public_key_pem)
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            encrypted_session_key = cipher_rsa.encrypt(session_key)
            
            # 4. 打包返回 (全部转为 base64 字符串，方便 JSON 传输)
            return {
                'enc_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'ciphertext': base64.b64encode(encrypted_data).decode('utf-8')
            }
        except Exception as e:
            print(f"❌ [混合加密错误] {e}")
            return None

    def decrypt_data(self, package, private_key_pem):
        """
        混合解密流程 (接收方调用):
        :param package: 包含 enc_session_key, iv, ciphertext 的字典
        :param private_key_pem: 自己的 RSA 私钥
        :return: 解密后的原始数据 (bytes)
        """
        try:
            # 0. 解码 Base64 数据
            enc_session_key = base64.b64decode(package['enc_session_key'])
            iv = base64.b64decode(package['iv'])
            ciphertext = base64.b64decode(package['ciphertext'])
            
            # 1. 使用 RSA 私钥解密出 AES 会话密钥
            priv_key = RSA.import_key(private_key_pem)
            cipher_rsa = PKCS1_OAEP.new(priv_key)
            session_key = cipher_rsa.decrypt(enc_session_key)
            
            # 2. 使用解出来的 AES 密钥解密数据
            cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
            original_data = unpad(cipher_aes.decrypt(ciphertext), self.block_size)
            
            return original_data
        except Exception as e:
            print(f"❌ [混合解密失败] {e}")
            return None

# 单独测试代码 (运行时直接 python hybrid_engine.py 看看能不能跑通)
if __name__ == '__main__':
    print("正在进行混合加密引擎自检...")
    
    # 1. 模拟生成一对 RSA 密钥
    key = RSA.generate(2048)
    pub_pem = key.publickey().export_key()
    priv_pem = key.export_key()
    
    # 2. 准备数据
    msg = "这是一个用于毕业设计的绝密消息！".encode('utf-8')
    
    # 3. 加密
    engine = HybridCipher()
    encrypted_pkg = engine.encrypt_data(msg, pub_pem)
    print(f"加密成功! 生成的数据包 keys: {encrypted_pkg.keys()}")
    print(f"加密后的AES密钥(部分): {encrypted_pkg['enc_session_key'][:20]}...")
    
    # 4. 解密
    decrypted_msg = engine.decrypt_data(encrypted_pkg, priv_pem)
    print(f"解密结果: {decrypted_msg.decode('utf-8')}")
    
    assert msg == decrypted_msg
    print("✅ 自检通过：加密解密逻辑正常")

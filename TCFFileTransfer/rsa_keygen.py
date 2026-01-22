from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

# 生成RSA私钥（2048位，服务器专用）
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# 保存私钥到项目根目录
with open("rsa_private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# 生成并保存公钥（客户端用）
public_key = private_key.public_key()
with open("rsa_public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("✅ RSA密钥对生成完成！")
print("📁 生成的文件：")
print("   - rsa_private_key.pem（服务器私钥，已存项目根目录）")
print("   - rsa_public_key.pem（客户端公钥，已存项目根目录）")

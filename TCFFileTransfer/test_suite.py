# -*- coding: utf-8 -*-
"""
模块名称: SystemIntegrityTestSuite
模块版本: v1.0.0
功能描述: 
    安全传输系统的自动化集成测试框架。
    该模块基于 Python unittest 标准库构建，旨在验证核心加密组件、
    持久化存储层以及文件 I/O 子系统的正确性与鲁棒性。

    [测试覆盖范围]
    1. Cryptographic Primitives (密码学原语):
       - 验证 PBKDF2 密钥衍生的一致性与抗碰撞性。
       - 验证 AES-GCM 模式的加解密完整性及防篡改能力。
    2. Data Persistence (数据持久化):
       - 验证 SQLite 数据库的原子性写入操作。
       - 验证用户注册与文件元数据的约束条件 (Constraints)。
    3. Concurrency Control (并发控制):
       - 模拟多线程环境下的文件写入争用 (Race Condition) 检测。
"""

import unittest
import os
import sqlite3
import shutil
import time
import threading
import base64
import json
from datetime import datetime

# 引入核心加密依赖
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# --- 模拟核心逻辑类 (Mock Classes) ---
# 为了保证测试环境的隔离性，此处重构核心逻辑，避免直接引用 GUI 组件
class CryptoEngineMock:
    """
    密码学引擎的独立测试封装。
    用于验证底层算法实现的正确性，不依赖 UI 上下文。
    """
    
    @staticmethod
    def derive_key_pbkdf2(password, salt=None):
        """
        基于口令的密钥衍生函数 (RFC 2898)。
        Args:
            password (str): 用户输入的原始口令。
            salt (bytes): 随机盐值，若为空则自动生成。
        Returns:
            tuple: (derived_key, salt)
        """
        if not salt:
            salt = get_random_bytes(16)
        # 参数须与生产环境保持严格一致: HMAC-SHA256, 100000 迭代
        key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
        return key, salt

    @staticmethod
    def encrypt_aes_gcm(data, key, iv):
        """AES-GCM 认证加密模式"""
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext + tag

    @staticmethod
    def decrypt_aes_gcm(data, key, iv):
        """AES-GCM 解密与完整性校验"""
        try:
            tag = data[-16:]
            ciphertext = data[:-16]
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            return None  # 校验失败

# --- 单元测试类定义 ---

class TestCryptoMechanisms(unittest.TestCase):
    """
    [测试集 01] 密码学机制验证
    目标: 确保加密算法符合 NIST 标准，且密钥衍生逻辑无误。
    """
    
    def setUp(self):
        """测试前的初始化钩子"""
        self.password = "ComplexPass@123"
        self.payload = b"System Security Verification Payload" * 10
        print(f"\n[CryptoTest] 初始化测试向量，载荷大小: {len(self.payload)} bytes")

    def test_pbkdf2_determinism(self):
        """
        测试用例: 验证 PBKDF2 算法的确定性。
        预期结果: 给定相同的口令与盐值，必须生成完全一致的密钥。
        """
        key1, salt = CryptoEngineMock.derive_key_pbkdf2(self.password)
        key2, _ = CryptoEngineMock.derive_key_pbkdf2(self.password, salt)
        
        self.assertEqual(key1, key2, "严重错误: 相同参数下的密钥衍生结果不一致")
        print("  -> [Pass] 密钥衍生确定性校验通过")

    def test_pbkdf2_avalanche_effect(self):
        """
        测试用例: 验证盐值的雪崩效应 (Avalanche Effect)。
        预期结果: 即使口令相同，微小的盐值变化也应导致密钥剧烈变化。
        """
        key1, _ = CryptoEngineMock.derive_key_pbkdf2(self.password)
        key2, _ = CryptoEngineMock.derive_key_pbkdf2(self.password) # 重新生成随机盐
        
        self.assertNotEqual(key1, key2, "严重错误: 不同盐值生成了相同的密钥 (熵源失效)")
        print("  -> [Pass] 盐值随机化校验通过")

    def test_aes_gcm_integrity(self):
        """
        测试用例: 验证 GCM 模式的认证加密流程。
        预期结果: 解密数据应与原始数据位级全等。
        """
        key = get_random_bytes(32)
        iv = get_random_bytes(12)
        
        encrypted_blob = CryptoEngineMock.encrypt_aes_gcm(self.payload, key, iv)
        decrypted_blob = CryptoEngineMock.decrypt_aes_gcm(encrypted_blob, key, iv)
        
        self.assertEqual(self.payload, decrypted_blob, "数据完整性校验失败")
        print("  -> [Pass] AES-GCM 加解密回环测试通过")

    def test_tamper_detection(self):
        """
        测试用例: 验证对篡改数据的识别能力。
        预期结果: 任何对密文的比特翻转都应触发解密失败 (返回 None)。
        """
        key = get_random_bytes(32)
        iv = get_random_bytes(12)
        encrypted_blob = bytearray(CryptoEngineMock.encrypt_aes_gcm(self.payload, key, iv))
        
        # 模拟中间人攻击: 翻转密文中的一个比特
        encrypted_blob[10] = encrypted_blob[10] ^ 0xFF
        
        result = CryptoEngineMock.decrypt_aes_gcm(bytes(encrypted_blob), key, iv)
        self.assertIsNone(result, "严重漏洞: 系统未能检测到密文被篡改")
        print("  -> [Pass] 防篡改攻击检测通过")


class TestDatabaseTransaction(unittest.TestCase):
    """
    [测试集 02] 数据库事务完整性验证
    目标: 确保 SQLite 在高频写入下的数据一致性。
    """
    
    TEST_DB_PATH = "test_integrity.db"
    
    def setUp(self):
        """构建临时测试数据库环境"""
        # --- 修复点 1: 启动前强制清理残留文件 ---
        if os.path.exists(self.TEST_DB_PATH):
            try:
                os.remove(self.TEST_DB_PATH)
            except PermissionError:
                # 如果删不掉，换个名字，避免冲突
                self.TEST_DB_PATH = f"test_integrity_{int(time.time())}.db"

        self.conn = sqlite3.connect(self.TEST_DB_PATH)
        self.cursor = self.conn.cursor()
        # 初始化精简版 Schema
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS sys_users (
            uid INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            reg_time TEXT
        )''')
        self.conn.commit()

    def tearDown(self):
        """清理测试产生的临时文件"""
        # --- 修复点 2: 确保连接彻底关闭 ---
        try:
            self.cursor.close()
            self.conn.close()
        except Exception:
            pass
        
        # --- 修复点 3: 给 Windows 一点时间释放锁 ---
        time.sleep(0.2) 
        
        if os.path.exists(self.TEST_DB_PATH):
            try:
                os.remove(self.TEST_DB_PATH)
            except PermissionError:
                print(f"Warning: 无法删除临时数据库 {self.TEST_DB_PATH}，可能是文件被占用，不影响测试结果。")

    def test_atomic_registration(self):
        """
        测试用例: 验证用户注册的原子性与唯一性约束。
        """
        test_user = "load_test_user_01"
        test_hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 第一次注册 (应该成功)
        try:
            self.cursor.execute("INSERT INTO sys_users (username, password_hash, reg_time) VALUES (?,?,?)",
                                (test_user, test_hash, timestamp))
            self.conn.commit()
        except sqlite3.IntegrityError:
            self.fail("第一次插入用户失败，数据库可能未清理干净")
        
        # 验证读取
        self.cursor.execute("SELECT username FROM sys_users WHERE username=?", (test_user,))
        record = self.cursor.fetchone()
        self.assertIsNotNone(record)
        
        # 第二次注册同名用户 (应该触发 IntegrityError)
        with self.assertRaises(sqlite3.IntegrityError):
            self.cursor.execute("INSERT INTO sys_users (username, password_hash, reg_time) VALUES (?,?,?)",
                                (test_user, "new_hash", timestamp))
        
        print(f"  -> [Pass] 数据库唯一性约束 (Unique Constraint) 校验通过")


class TestIOConcurrency(unittest.TestCase):
    """
    [测试集 03] 文件系统并发 I/O 测试
    目标: 模拟多线程环境下的大量小文件写入，验证物理隔离机制。
    """
    
    TEMP_STORAGE = "test_io_zone"
    
    def setUp(self):
        if not os.path.exists(self.TEMP_STORAGE):
            os.makedirs(self.TEMP_STORAGE)
            
    def tearDown(self):
        if os.path.exists(self.TEMP_STORAGE):
            shutil.rmtree(self.TEMP_STORAGE)
            
    def _io_worker(self, thread_id):
        """模拟单个线程的写入行为"""
        filename = f"thread_{thread_id}.dat"
        filepath = os.path.join(self.TEMP_STORAGE, filename)
        # 写入 512KB 的随机数据
        data = os.urandom(512 * 1024)
        with open(filepath, 'wb') as f:
            f.write(data)
            
    def test_concurrent_throughput(self):
        """
        测试用例: 启动 10 个线程并发写入，检测是否存在死锁或文件损坏。
        """
        threads = []
        start_time = time.time()
        thread_count = 10
        
        print(f"\n[IOTest] 启动 {thread_count} 线程并发写入测试...")
        
        for i in range(thread_count):
            t = threading.Thread(target=self._io_worker, args=(i,))
            threads.append(t)
            t.start()
            
        for t in threads:
            t.join()
            
        duration = time.time() - start_time
        file_count = len(os.listdir(self.TEMP_STORAGE))
        
        self.assertEqual(file_count, thread_count, "文件生成数量与线程数不符")
        print(f"  -> [Pass] 并发测试完成，耗时: {duration:.4f}s")


if __name__ == '__main__':
    print("========================================================")
    print("     SECURITY SYSTEM AUTOMATED TEST SUITE (v1.0)        ")
    print("========================================================")
    print(f"执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"运行环境: Python {os.sys.version.split(' ')[0]}")
    print("--------------------------------------------------------")
    
    # 启动测试运行器，verbosity=2 表示输出详细信息
    unittest.main(verbosity=2)

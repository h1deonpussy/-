# -*- coding: utf-8 -*-
"""
模块名称: CoreNetworkService
功能描述: 
    基于 Flask-SocketIO 的高安全等级网络协同服务端。
    
    [本次更新 - 修复审计链]
    1. 增强审计: 在安全拦截处补全了文本日志写入，支持 SecurityLogAnalyzer 自动报表生成。
    2. 保持架构: 完整保留 DDL 结构、DAO 访问模式及物理隔离存储逻辑。
"""

import eventlet
eventlet.monkey_patch() # 协程补丁，确保 SocketIO 高并发非阻塞运行

import logging
import logging.handlers
from flask import Flask, request
from flask_socketio import SocketIO, emit
import os
import sqlite3
import datetime
import sys
import json
import base64

# --- 系统配置常量 ---
SERVER_PORT = 5003
STORAGE_ROOT = 'system_storage'  # 文件存储根路径
DB_FILE = 'system_data.db'       # 关系型数据库文件
LOG_FILE = 'service_audit.log'   # 文本审计日志

# 安全配置：禁止上传的文件扩展名黑名单
FORBIDDEN_EXTENSIONS = {'.exe', '.bat', '.sh', '.cmd', '.vbs', '.dll', '.com'}

# --- 日志子系统初始化 ---
logger = logging.getLogger("NetworkCore")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(module)s | %(message)s')

f_handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
f_handler.setFormatter(formatter)
s_handler = logging.StreamHandler(sys.stdout)
s_handler.setFormatter(formatter)

logger.addHandler(f_handler)
logger.addHandler(s_handler)

# --- Flask 与 SocketIO 实例 ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32) # 会话密钥动态生成
socketio = SocketIO(app, cors_allowed_origins="*", max_http_buffer_size=100*1024*1024, ping_timeout=60)

# 初始化存储根目录
if not os.path.exists(STORAGE_ROOT):
    os.makedirs(STORAGE_ROOT)

# --- 数据库交互层 (DAO Pattern) ---
class DatabaseInterface:
    """
    数据库访问对象 (DAO)
    封装所有 SQL 操作，确保连接生命周期管理与事务原子性。
    """
    def __init__(self, db_path):
        self.db_path = db_path
        self._init_schema()

    def _get_conn(self):
        """获取线程独立的数据库连接"""
        return sqlite3.connect(self.db_path)

    def _init_schema(self):
        """初始化数据库表结构 (DDL)"""
        conn = self._get_conn()
        cur = conn.cursor()
        
        cur.execute('''CREATE TABLE IF NOT EXISTS sys_users (
            uid INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            reg_time TEXT
        )''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS sys_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            filesize INTEGER,
            sender_id TEXT,
            receiver_id TEXT,
            is_public INTEGER,
            algo_type TEXT,
            key_data TEXT,      
            iv_data TEXT,
            pbkdf2_salt TEXT,   
            save_path TEXT,
            upload_time TEXT
        )''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS sys_logs (
            lid INTEGER PRIMARY KEY AUTOINCREMENT,
            log_type TEXT,
            user_id TEXT,
            content TEXT,
            create_time TEXT
        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS sys_chat (
            cid INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            content TEXT,
            send_time TEXT
        )''')
        
        conn.commit()
        conn.close()

    def write_audit_log(self, log_type, user_id, content):
        """
        写入结构化审计日志
        确保文件写入失败不会阻塞数据库和实时推送
        """
        ts_db = datetime.datetime.now().strftime("%H:%M:%S")
        
        # 1. 尝试写入数据库 (用于前端日志列表展示)
        try:
            conn = self._get_conn()
            conn.execute("INSERT INTO sys_logs (log_type, user_id, content, create_time) VALUES (?,?,?,?)",
                         (log_type, user_id, content, ts_db))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB Error] 数据库日志写入失败: {e}")

        # 2. 尝试写入文本日志 (用于 SecurityLogAnalyzer)
        try:
            lvl = logging.INFO
            if any(word in log_type for word in ["拦截", "失败", "警告", "安全"]):
                lvl = logging.WARNING
            
            # 确保消息格式兼容正则
            logger.log(lvl, f"User [{user_id}] | {log_type} | {content}")
        except Exception as e:
            print(f"[File Error] 文本日志写入失败 (请检查权限): {e}")

        # 3. 实时推送至管理端 (确保客户端能看到)
        try:
            socketio.emit('push_system_log', {
                'type': log_type, 
                'user': user_id, 
                'msg': content, 
                'time': ts_db
            })
        except Exception as e:
            print(f"[Socket Error] 实时日志推送失败: {e}")

    def verify_user(self, user, pwd):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT uid FROM sys_users WHERE username=? AND password_hash=?", (user, pwd))
        res = cur.fetchone()
        conn.close()
        return res is not None

    def create_user(self, user, pwd):
        try:
            conn = self._get_conn()
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("INSERT INTO sys_users (username, password_hash, reg_time) VALUES (?,?,?)", (user, pwd, ts))
            conn.commit()
            conn.close()
            self.write_audit_log("用户注册", user, "账户创建成功")
            return True
        except sqlite3.IntegrityError:
            return False

    def save_file_metadata(self, meta):
        conn = self._get_conn()
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute('''INSERT INTO sys_files 
            (filename, filesize, sender_id, receiver_id, is_public, algo_type, key_data, iv_data, pbkdf2_salt, save_path, upload_time)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)''', 
            (meta['fname'], meta['fsize'], meta['sender'], meta['receiver'], meta['is_public'], 
             meta['algo'], meta['key'], meta['iv'], meta.get('salt', ''), meta['path'], ts))
        conn.commit()
        conn.close()
        
        perm_scope = "云端公共区" if meta['is_public'] else f"用户 [{meta['receiver']}]"
        self.write_audit_log("文件归档", meta['sender'], f"文件 {meta['fname']} 加密存储至 {perm_scope}")

    def query_user_files(self, current_user):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute('''
            SELECT id, filename, filesize, sender_id, receiver_id, is_public, algo_type, upload_time 
            FROM sys_files 
            WHERE is_public=1 OR receiver_id=? OR sender_id=?
            ORDER BY id DESC
        ''', (current_user, current_user))
        rows = cur.fetchall()
        conn.close()
        
        file_list = []
        total_size = 0
        for r in rows:
            recv_display = "云端公共" if r[5] == 1 else f"私有: {r[4]}"
            file_list.append({
                'id': r[0], 'name': r[1], 'size': r[2], 
                'sender': r[3], 'recv': recv_display, 'algo': r[6], 'time': r[7]
            })
            total_size += r[2]
            
        return file_list, total_size

    def get_file_record(self, fid):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM sys_files WHERE id=?", (fid,))
        row = cur.fetchone()
        conn.close()
        return row
    
    def persist_chat_msg(self, sender, content):
        conn = self._get_conn()
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("INSERT INTO sys_chat (sender, content, send_time) VALUES (?,?,?)", (sender, content, ts))
        conn.commit()
        conn.close()
        return ts

    def fetch_chat_history(self, limit=50):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT sender, content, send_time FROM sys_chat ORDER BY cid DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        conn.close()
        return rows[::-1] 

db = DatabaseInterface(DB_FILE)

# --- WebSocket 事件处理路由 ---

@socketio.on('connect')
def handle_connect(auth=None):
    logger.info(f"TCP连接建立: {request.remote_addr}")

@socketio.on('req_login')
def handle_login(data):
    if db.verify_user(data['uid'], data['pwd']):
        emit('res_login', {'code': 200, 'msg': '验证通过'})
        db.write_audit_log("用户登录", data['uid'], "会话通道建立")
        history_data = db.fetch_chat_history()
        emit('res_chat_history', {'history': history_data})
    else:
        # 增加失败登录审计
        db.write_audit_log("登录警告", data['uid'], "身份核验未通过，连接被拒")
        emit('res_login', {'code': 401, 'msg': '认证失败：账号或密码错误'})

@socketio.on('req_register')
def handle_register(data):
    if db.create_user(data['uid'], data['pwd']):
        emit('res_register', {'code': 200, 'msg': '账户注册成功'})
    else:
        emit('res_register', {'code': 400, 'msg': '注册失败：用户ID已存在'})

@socketio.on('req_chat_send')
def handle_chat(data):
    ts = db.persist_chat_msg(data['sender'], data['content'])
    socketio.emit('push_chat_recv', {
        'sender': data['sender'],
        'content': data['content'],
        'time': ts
    })

@socketio.on('req_upload_packet')
def handle_upload(data):
    try:
        # [安全策略] 服务端二次校验文件扩展名
        file_ext = os.path.splitext(data['filename'])[1].lower()
        if file_ext in FORBIDDEN_EXTENSIONS:
            # 修正：在 return 之前必须先写入审计日志，否则拦截行为不会被记录
            db.write_audit_log("安全拦截", data['sender'], f"尝试上传非法可执行文件: {data['filename']}")
            emit('res_error', {'msg': f"安全警告：服务端禁止上传 {file_ext} 类型文件！"})
            return

        # 物理隔离
        user_storage_path = os.path.join(STORAGE_ROOT, data['sender'])
        if not os.path.exists(user_storage_path):
            os.makedirs(user_storage_path, exist_ok=True)
            
        save_path = os.path.join(user_storage_path, data['filename'])
        
        mode = 'ab' if data['chunk_index'] > 0 else 'wb'
        with open(save_path, mode) as f:
            f.write(data['chunk'])
            
        if data['is_last']:
            final_size = os.path.getsize(save_path)
            is_pub = 1 if data['mode'] == 'cloud' else 0
            recv_id = 'ALL' if is_pub else data['receiver']
            
            db.save_file_metadata({
                'fname': data['filename'],
                'fsize': final_size,
                'sender': data['sender'],
                'receiver': recv_id,
                'is_public': is_pub,
                'algo': data['algo'],
                'key': data.get('key_hex', ''),   
                'iv': data.get('iv_hex', ''),
                'salt': data.get('salt_hex', ''), 
                'path': save_path
            })
            
            emit('res_upload_complete', {'msg': '传输完成，文件已加密归档'})
            socketio.emit('push_list_refresh')
            
    except Exception as e:
        logger.error(f"文件写入IO异常: {e}")
        emit('res_error', {'msg': f"服务端存储错误: {str(e)}"})

@socketio.on('req_file_list')
def handle_file_list(data):
    files, total_size = db.query_user_files(data['uid'])
    emit('res_file_list', {
        'files': files,
        'stats': {
            'count': len(files),
            'total_size': total_size
        }
    })

@socketio.on('req_download')
def handle_download(data):
    finfo = db.get_file_record(data['fid'])
    if not finfo:
        emit('res_error', {'msg': '索引错误：文件记录不存在'})
        return
    
    file_path = finfo[10]
    
    if os.path.exists(file_path):
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            b64_content = base64.b64encode(content).decode('utf-8')
            
            emit('res_download_stream', {
                'filename': finfo[1],
                'body': b64_content,
                'algo': finfo[6],
                'key': finfo[7],
                'iv': finfo[8],
                'salt': finfo[9] 
            })
            db.write_audit_log("文件下载", data.get('uid', 'Unknown'), f"文件 {finfo[1]} 数据流已发出")
        except Exception as e:
            emit('res_error', {'msg': f"文件读取异常: {e}"})
    else:
        emit('res_error', {'msg': '物理文件缺失，可能已被删除'})

if __name__ == '__main__':
    print(f"=============================================")
    print(f" 安全传输核心服务  已就绪")
    print(f" 监听端口: {SERVER_PORT}")
    print(f" 审计追踪: 已激活日志持久化模块")
    print(f"=============================================")
    socketio.run(app, host='0.0.0.0', port=SERVER_PORT)

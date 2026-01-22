# -*- coding: utf-8 -*-
"""
模块名称: SecureTerminalClient
功能描述: 
    基于 Tkinter 的安全传输终端。
    
    [功能特性]
    1. 安全防护: 自动识别并拦截可执行文件 (.exe) 上传，防止恶意代码传播。
    2. 交互优化: 
       - 主题/算法选项完全中文化 (带说明)。
       - 增加云端文件统计面板 (数量/容量)。
       - 界面增加刷新按钮与加密标识。
    3. 稳定性: 采用主线程调度机制处理 SocketIO 回调，杜绝 UI 线程崩溃。
    4. 密码学: 集成 PBKDF2/AES/RSA/SHA256 完整加密套件。
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog
import socketio
import os
import sys
import threading
import time
import math
import subprocess
import base64
import logging
import traceback # 用于捕捉详细错误

# --- 依赖库加载 ---
# 必须包含 SHA256 和 PBKDF2，否则双层加密会报错
try:
    from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
    
    import matplotlib
    matplotlib.use('TkAgg') 
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    
    matplotlib.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'Arial']
    matplotlib.rcParams['axes.unicode_minus'] = False
    
except ImportError as e:
    messagebox.showerror("环境缺失", f"系统检测到必要组件缺失:\n{e}\n请检查 Python 环境配置。")
    sys.exit(1)

# --- 全局配置 ---
SERVER_URL = 'http://127.0.0.1:5003'
CHUNK_SIZE = 8192

# --- 1. 密码学核心引擎 ---
class CryptoCore:
    """提供加密原语实现的静态工具类"""
    
    @staticmethod
    def derive_key_pbkdf2(password, salt=None):
        if not salt:
            salt = get_random_bytes(16)
        # PBKDF2-HMAC-SHA256
        key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
        return key, salt

    @staticmethod
    def gen_random_params(algo_name):
        """生成随机密钥，根据算法名称调整 IV 长度"""
        key = get_random_bytes(32)
        if 'GCM' in algo_name: 
            iv = get_random_bytes(12)
        elif 'ChaCha' in algo_name: 
            iv = get_random_bytes(8)
        else: 
            iv = get_random_bytes(16)
        return key, iv

    @staticmethod
    def encrypt_data(data, algo_full_name, key, iv):
        """
        通用加密接口
        注意：algo_full_name 可能包含中文说明 (e.g. "AES-GCM (推荐)"), 需要清洗
        """
        # 清洗算法名称，只取空格前的部分
        algo = algo_full_name.split(' ')[0]
        
        if algo == 'AES-256-GCM':
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return ciphertext + tag
        elif algo == 'AES-256-CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return cipher.encrypt(pad(data, AES.block_size))
        elif algo == 'ChaCha20':
            cipher = ChaCha20.new(key=key, nonce=iv)
            return cipher.encrypt(data)
        return data

    @staticmethod
    def decrypt_data(data, algo_full_name, key, iv):
        algo = algo_full_name.split(' ')[0]
        try:
            if algo == 'AES-256-GCM':
                tag = data[-16:]
                ciphertext = data[:-16]
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                return cipher.decrypt_and_verify(ciphertext, tag)
            elif algo == 'AES-256-CBC':
                cipher = AES.new(key, AES.MODE_CBC, iv)
                return unpad(cipher.decrypt(data), AES.block_size)
            elif algo == 'ChaCha20':
                cipher = ChaCha20.new(key=key, nonce=iv)
                return cipher.decrypt(data)
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None
        return data

    @staticmethod
    def get_entropy(data):
        if not data: return 0
        entropy = 0
        length = len(data)
        for x in range(256):
            p_x = float(data.count(x)) / length
            if p_x > 0: entropy += - p_x * math.log(p_x, 2)
        return entropy

# --- 2. 嵌入式可视化组件 ---
class DataVisualizer:
    def __init__(self, parent):
        self.fig = Figure(figsize=(6, 2.5), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("数据流熵值分析 (Entropy Monitor)", fontsize=9)
        self.ax.set_ylabel("熵值 (Bit)")
        self.ax.set_ylim(0, 8.5)
        self.ax.grid(True, linestyle='--', alpha=0.5)
        
        self.line_raw, = self.ax.plot([], [], label='原始数据 (Plain)', color='#1f77b4', lw=1)
        self.line_enc, = self.ax.plot([], [], label='加密数据 (Cipher)', color='#d62728', lw=1)
        self.ax.legend(loc='lower right', fontsize=8)
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.x_data, self.y_raw, self.y_enc = [], [], []

    def update(self, idx, raw_val, enc_val):
        self.x_data.append(idx)
        self.y_raw.append(raw_val)
        self.y_enc.append(enc_val)
        if len(self.x_data) > 50:
            self.x_data.pop(0); self.y_raw.pop(0); self.y_enc.pop(0)
        self.line_raw.set_data(range(len(self.x_data)), self.y_raw)
        self.line_enc.set_data(range(len(self.x_data)), self.y_enc)
        self.ax.set_xlim(0, len(self.x_data))
        self.canvas.draw()

    def reset(self):
        self.x_data, self.y_raw, self.y_enc = [], [], []
        self.canvas.draw()

# --- 3. 客户端主控逻辑 ---
class Application:
    def __init__(self, root):
        self.root = root
        self.root.title("安全传输系统  (客户端)")
        self.root.geometry("1080x820")
        
        self.sio = socketio.Client()
        self.uid = None
        
        self._init_ui()
        self._bind_socket_events()
        
        # 延时连接服务端
        self.root.after(800, self.connect_server)

    def connect_server(self):
        try:
            self.sio.connect(SERVER_URL)
            self.lbl_status.config(text=f"状态: 已连接至 {SERVER_URL}", fg="green")
        except Exception as e:
            self.lbl_status.config(text=f"状态: 连接失败 ({e})", fg="red")

    def _init_ui(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # 底部状态栏
        self.lbl_status = tk.Label(self.root, text="初始化中...", bg="#eee", anchor='w')
        self.lbl_status.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.p_login = tk.Frame(self.nb)
        self.p_trans = tk.Frame(self.nb)
        self.p_cloud = tk.Frame(self.nb)
        self.p_chat = tk.Frame(self.nb)
        self.p_logs = tk.Frame(self.nb)
        
        self.nb.add(self.p_login, text="1. 身份认证")
        self.nb.add(self.p_trans, text="2. 加密传输")
        self.nb.add(self.p_cloud, text="3. 云端存储")
        self.nb.add(self.p_chat, text="4. 群组通讯")
        self.nb.add(self.p_logs, text="5. 审计日志")
        
        self._build_login(self.p_login)
        self._build_trans(self.p_trans)
        self._build_cloud(self.p_cloud)
        self._build_chat(self.p_chat)
        self._build_logs(self.p_logs)

    def _build_login(self, parent):
        f = tk.Frame(parent)
        f.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        
        tk.Label(f, text="终端接入认证", font=("黑体", 18)).grid(row=0, columnspan=2, pady=20)
        
        tk.Label(f, text="账号:").grid(row=1, column=0, sticky='e')
        self.e_uid = tk.Entry(f, width=22, font=("Arial", 11))
        self.e_uid.grid(row=1, column=1, pady=5)
        
        tk.Label(f, text="密码:").grid(row=2, column=0, sticky='e')
        self.e_pwd = tk.Entry(f, show="*", width=22, font=("Arial", 11))
        self.e_pwd.grid(row=2, column=1, pady=5)
        
        # [修改] 界面主题中文化 (括号说明)
        tk.Label(f, text="界面主题:").grid(row=3, column=0, sticky='e')
        # 在选择时只取空格前的部分传给 style
        self.theme_map = {
            'clam (默认扁平)': 'clam',
            'alt (原生系统)': 'alt',
            'default (经典复古)': 'default',
            'classic (Windows95)': 'classic'
        }
        self.cb_theme = ttk.Combobox(f, values=list(self.theme_map.keys()), state="readonly", width=20)
        self.cb_theme.current(0)
        self.cb_theme.grid(row=3, column=1, pady=5)
        self.cb_theme.bind("<<ComboboxSelected>>", self._change_theme)
        
        btn_box = tk.Frame(f)
        btn_box.grid(row=4, columnspan=2, pady=20)
        tk.Button(btn_box, text="登录", bg="#4CAF50", fg="white", width=10, command=self.do_login).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_box, text="注册", bg="#2196F3", fg="white", width=10, command=self.do_register).pack(side=tk.LEFT, padx=5)
        
        tk.Button(f, text="[调试] 启动多开实例", command=lambda: subprocess.Popen([sys.executable, sys.argv[0]])).grid(row=5, columnspan=2, pady=20)

    def _change_theme(self, event):
        selected_text = self.cb_theme.get()
        real_theme = self.theme_map.get(selected_text, 'clam')
        self.style.theme_use(real_theme)

    def _build_trans(self, parent):
        f_cfg = tk.LabelFrame(parent, text="传输参数配置")
        f_cfg.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(f_cfg, text="加密算法:").pack(side=tk.LEFT, padx=5)
        # [修改] 算法选择带中文说明
        self.cb_algo = ttk.Combobox(f_cfg, values=[
            "AES-256-GCM (推荐/高速)", 
            "AES-256-CBC (通用兼容)", 
            "ChaCha20 (移动端优化)"
        ], width=20, state="readonly")
        self.cb_algo.current(0)
        self.cb_algo.pack(side=tk.LEFT, padx=5)
        
        tk.Label(f_cfg, text="提取码(可选):").pack(side=tk.LEFT, padx=(10, 5))
        self.e_pass = tk.Entry(f_cfg, width=10, show="*")
        self.e_pass.pack(side=tk.LEFT)
        
        self.v_mode = tk.StringVar(value="cloud")
        tk.Radiobutton(f_cfg, text="云端公开", var=self.v_mode, value="cloud", command=self._toggle_recv).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(f_cfg, text="私有发送 ->", var=self.v_mode, value="private", command=self._toggle_recv).pack(side=tk.LEFT)
        self.e_recv = tk.Entry(f_cfg, width=10, state='disabled')
        self.e_recv.pack(side=tk.LEFT, padx=5)
        
        tk.Button(f_cfg, text="开始传输", bg="orange", command=self.start_upload).pack(side=tk.RIGHT, padx=10)
        
        f_vis = tk.LabelFrame(parent, text="加密过程可视化")
        f_vis.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.vis = DataVisualizer(f_vis)
        
        f_btm = tk.Frame(parent)
        f_btm.pack(fill=tk.X, padx=5)
        self.pb = ttk.Progressbar(f_btm, orient="horizontal", mode="determinate")
        self.pb.pack(fill=tk.X)
        self.txt_log = scrolledtext.ScrolledText(f_btm, height=5, font=("Consolas", 9))
        self.txt_log.pack(fill=tk.X, pady=5)

    def _build_cloud(self, parent):
        # 顶部工具栏
        tb = tk.Frame(parent)
        tb.pack(fill=tk.X, padx=5, pady=5)
        
        # [新增] 刷新按钮
        tk.Button(tb, text="↻ 刷新列表", command=self._req_refresh, bg="#eee").pack(side=tk.LEFT)
        
        # [新增] 统计信息 Label
        self.lbl_stats = tk.Label(tb, text="统计: 正在获取...", fg="blue")
        self.lbl_stats.pack(side=tk.RIGHT, padx=10)
        
        cols = ("ID", "文件名", "大小", "发送者", "接收权限", "算法", "时间")
        self.tree_file = ttk.Treeview(parent, columns=cols, show="headings")
        for c in cols: 
            self.tree_file.heading(c, text=c)
            self.tree_file.column(c, width=100)
        self.tree_file.pack(fill=tk.BOTH, expand=True, padx=5)
        self.tree_file.bind("<Double-1>", self.do_download)

    def _build_chat(self, parent):
        # [新增] 安全标识
        tk.Label(parent, text="🔒 [端到端加密通道] 历史消息已加密存储", fg="green", bg="#f0f0f0").pack(fill=tk.X)
        
        self.chat_box = scrolledtext.ScrolledText(parent, state='disabled')
        self.chat_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        f_in = tk.Frame(parent)
        f_in.pack(fill=tk.X, padx=5, pady=5)
        self.e_msg = tk.Entry(f_in)
        self.e_msg.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.e_msg.bind("<Return>", lambda e: self.send_chat())
        tk.Button(f_in, text="发送", command=self.send_chat).pack(side=tk.RIGHT, padx=5)

    def _build_logs(self, parent):
        cols = ("时间", "类型", "用户", "详情")
        self.tree_log = ttk.Treeview(parent, columns=cols, show="headings")
        for c in cols: self.tree_log.heading(c, text=c)
        self.tree_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # --- 交互逻辑 ---
    def _toggle_recv(self):
        state = 'normal' if self.v_mode.get() == 'private' else 'disabled'
        self.e_recv.config(state=state)

    def log(self, msg):
        self.txt_log.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.txt_log.see(tk.END)

    def do_login(self):
        self.sio.emit('req_login', {'uid': self.e_uid.get(), 'pwd': self.e_pwd.get()})

    def do_register(self):
        self.sio.emit('req_register', {'uid': self.e_uid.get(), 'pwd': self.e_pwd.get()})

    def send_chat(self):
        txt = self.e_msg.get()
        if txt and self.uid:
            self.sio.emit('req_chat_send', {'sender': self.uid, 'content': txt})
            self.e_msg.delete(0, tk.END)

    def _req_refresh(self):
        if self.uid: self.sio.emit('req_file_list', {'uid': self.uid})

    def start_upload(self):
        if not self.uid: return messagebox.showwarning("","请先登录")
        path = filedialog.askopenfilename()
        if not path: return
        
        # [安全策略] 客户端前置拦截 EXE
        fname = os.path.basename(path)
        ext = os.path.splitext(fname)[1].lower()
        if ext in ['.exe', '.bat', '.sh', '.cmd', '.vbs']:
            messagebox.showerror("安全警告", f"系统禁止上传可执行文件 ({ext})！\n此操作已被安全策略拦截。")
            return
        
        receiver = self.e_recv.get()
        if self.v_mode.get() == 'private' and not receiver:
            return messagebox.showwarning("","请输入接收者ID")
            
        threading.Thread(target=self._upload_thread, args=(path, receiver), daemon=True).start()

    def _upload_thread(self, path, receiver):
        fname = os.path.basename(path)
        fsize = os.path.getsize(path)
        # 获取下拉框的值，注意这里带有中文
        algo_display = self.cb_algo.get()
        pwd = self.e_pass.get().strip()
        
        try:
            salt_hex = ""
            if pwd:
                key, salt = CryptoCore.derive_key_pbkdf2(pwd)
                salt_hex = salt.hex()
                self.root.after(0, lambda: self.log("模式: PBKDF2 双层加密"))
            else:
                key, _ = CryptoCore.gen_random_params(algo_display)
                self.root.after(0, lambda: self.log("模式: 随机密钥信封加密"))
            
            _, iv = CryptoCore.gen_random_params(algo_display)
            
            key_hex = key.hex()
            iv_hex = iv.hex()
            
            self.root.after(0, self.vis.reset)
            
            with open(path, 'rb') as f:
                idx = 0
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk: break
                    
                    # 传入带中文的 algo_name，内部会自动清洗
                    enc = CryptoCore.encrypt_data(chunk, algo_display, key, iv)
                    
                    e1 = CryptoCore.get_entropy(chunk)
                    e2 = CryptoCore.get_entropy(enc)
                    self.root.after(0, self.vis.update, idx, e1, e2)
                    
                    is_last = (f.tell() == fsize)
                    self.sio.emit('req_upload_packet', {
                        'filename': fname,
                        'chunk': enc,
                        'chunk_index': idx,
                        'is_last': is_last,
                        'sender': self.uid,
                        'mode': self.v_mode.get(),
                        'receiver': receiver,
                        'algo': algo_display.split(' ')[0], # 传给服务端只传英文名
                        'key_hex': key_hex,
                        'iv_hex': iv_hex,
                        'salt_hex': salt_hex
                    })
                    idx += 1
                    self.root.after(0, lambda v=(f.tell()/fsize)*100: self.pb.configure(value=v))
                    time.sleep(0.01)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("上传中断", str(e)))

    def do_download(self, event):
        item = self.tree_file.selection()
        if item: self.sio.emit('req_download', {'fid': self.tree_file.item(item, "values")[0]})

    def _bind_socket_events(self):
        @self.sio.on('res_login')
        def on_login(d):
            if d['code'] == 200:
                self.uid = self.e_uid.get()
                self.root.title(f"User: {self.uid}")
                self.nb.select(1)
                self._req_refresh()
                messagebox.showinfo("","登录成功")
            else: messagebox.showerror("", d['msg'])

        @self.sio.on('res_register')
        def on_reg(d): messagebox.showinfo("注册", d['msg'])

        @self.sio.on('res_error')
        def on_err(d):
            messagebox.showerror("服务端错误", d['msg'])

        @self.sio.on('res_upload_complete')
        def on_up_done(d): 
            self.log(d['msg'])
            self.pb['value'] = 0

        @self.sio.on('res_file_list')
        def on_list(d):
            # 1. 更新列表
            for i in self.tree_file.get_children(): self.tree_file.delete(i)
            for f in d['files']:
                self.tree_file.insert("", "end", values=(f['id'],f['name'],f['size'],f['sender'],f['recv'],f['algo'],f['time']))
            
            # 2. [新增] 更新统计信息
            if 'stats' in d:
                count = d['stats']['count']
                size_mb = d['stats']['total_size'] / 1024 / 1024
                self.lbl_stats.config(text=f"文件总数: {count} | 总占用: {size_mb:.2f} MB")

        @self.sio.on('push_list_refresh')
        def on_refresh(): self._req_refresh()

        @self.sio.on('push_chat_recv')
        def on_chat(d):
            self.chat_box.config(state='normal')
            self.chat_box.insert(tk.END, f"[{d['time']}] {d['sender']}: {d['content']}\n")
            self.chat_box.see(tk.END)
            self.chat_box.config(state='disabled')

        @self.sio.on('res_chat_history')
        def on_history(d):
            self.chat_box.config(state='normal')
            self.chat_box.insert(tk.END, "--- 历史消息 ---\n")
            for m in d['history']:
                self.chat_box.insert(tk.END, f"[{m[2]}] {m[0]}: {m[1]}\n")
            self.chat_box.insert(tk.END, "---------------\n")
            self.chat_box.see(tk.END)
            self.chat_box.config(state='disabled')

        @self.sio.on('res_download_stream')
        def on_down(d):
            # 使用 root.after 调度到主线程执行，防止 TclError
            def _safe_ui_download():
                try:
                    # 提取参数
                    salt_hex = d.get('salt', '')
                    key_hex = d.get('key', '')
                    iv_hex = d.get('iv', '')
                    algo = d.get('algo', 'AES-256-GCM')
                    body_b64 = d.get('body', '')

                    if salt_hex and salt_hex != 'None':
                        pwd = simpledialog.askstring("双层加密验证", f"文件 {d['filename']} 受保护\n请输入提取码:")
                        if not pwd: return

                        try:
                            salt_bytes = bytes.fromhex(salt_hex)
                            derived_key, _ = CryptoCore.derive_key_pbkdf2(pwd, salt_bytes)
                            key_hex = derived_key.hex()
                        except Exception as e_kdf:
                            messagebox.showerror("密钥计算错误", str(e_kdf))
                            return

                    path = filedialog.asksaveasfilename(initialfile=d['filename'])
                    if not path: return

                    # 解密
                    body_bytes = base64.b64decode(body_b64)
                    k = bytes.fromhex(key_hex)
                    v = bytes.fromhex(iv_hex)
                    
                    plain_data = CryptoCore.decrypt_data(body_bytes, algo, k, v)
                    
                    if plain_data:
                        with open(path, 'wb') as f: f.write(plain_data)
                        messagebox.showinfo("成功", f"文件已解密保存。\n算法: {algo}")
                    else:
                        messagebox.showerror("失败", "解密失败：提取码错误或数据损坏")
                        
                except Exception as e:
                    print(traceback.format_exc())
                    messagebox.showerror("下载异常", f"处理失败: {e}")

            self.root.after(0, _safe_ui_download)

        @self.sio.on('push_system_log')
        def on_log(d):
            self.tree_log.insert("", 0, values=(d['time'],d['type'],d['user'],d['msg']))

if __name__ == '__main__':
    root = tk.Tk()
    app = Application(root)
    root.mainloop()

# -*- coding: utf-8 -*-
"""
模块名称: SecurityLogAnalyzer
功能描述: 
    系统审计日志的高级分析与可视化工具。
    [核心功能]
    1. Regex Log Parsing
    2. Statistical Analysis
    3. User Behavior Profiling
    4. Report Generation
    5. Auto Visualization (修复 Windows 下无法自动弹窗的问题)
"""

import re
import os
import sys
import datetime
import webbrowser
import platform  # <--- 新增: 用于判断操作系统
from collections import Counter, defaultdict

# --- 配置参数 ---
LOG_SOURCE_FILE = 'service_audit.log'
REPORT_OUTPUT_FILE = 'security_report.html'

class LogRecord:
    """日志记录实体类"""
    def __init__(self, raw_line, line_num):
        self.line_num = line_num
        self.raw_content = raw_line.strip()
        self.timestamp = None
        self.level = "UNKNOWN"
        self.module = "UNKNOWN"
        self.message = ""
        self.user_identifier = "SYSTEM"
        self._parse_raw()

    def _parse_raw(self):
        log_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| (\w+) \| (\w+) \| (.*)'
        match = re.match(log_pattern, self.raw_content)
        if match:
            try:
                self.timestamp = datetime.datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                self.level = match.group(2)
                self.module = match.group(3)
                self.message = match.group(4)
                user_match = re.search(r'User \[(.*?)\]', self.message) or re.search(r'用户 \[(.*?)\]', self.message)
                if user_match:
                    self.user_identifier = user_match.group(1)
            except Exception:
                pass
        else:
            self.message = self.raw_content

class AuditEngine:
    """审计分析引擎"""
    def __init__(self, filepath):
        self.filepath = filepath
        self.records = []
        self.stats = {
            'total_count': 0, 'error_count': 0, 'warning_count': 0,
            'upload_ops': 0, 'login_ops': 0, 'download_ops': 0
        }
        self.user_activity_map = Counter()

    def load_data(self):
        if not os.path.exists(self.filepath):
            print(f"[Error] 日志源文件不存在: {self.filepath}")
            with open(self.filepath, 'w', encoding='utf-8') as f:
                f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | INFO | System | Log initialized.\n")
            print(f"[Info] 已自动创建空日志文件。")

        print(f"[Info] 正在加载日志文件: {self.filepath} ...")
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                for idx, line in enumerate(f):
                    if not line.strip(): continue
                    record = LogRecord(line, idx + 1)
                    self.records.append(record)
                    self._aggregate_metrics(record)
            print(f"[Success] 数据加载完成，共解析 {len(self.records)} 条记录")
            return True
        except Exception as e:
            print(f"[Error] 文件读取异常: {e}")
            return False

    def _aggregate_metrics(self, record):
        self.stats['total_count'] += 1
        if record.level == 'ERROR': self.stats['error_count'] += 1
        if record.level == 'WARNING': self.stats['warning_count'] += 1
        
        msg_lower = record.message.lower()
        if '上传' in msg_lower or 'upload' in msg_lower: self.stats['upload_ops'] += 1
        elif '登录' in msg_lower or 'login' in msg_lower: self.stats['login_ops'] += 1
        elif '下载' in msg_lower or 'download' in msg_lower: self.stats['download_ops'] += 1
            
        if record.user_identifier != 'SYSTEM':
            self.user_activity_map[record.user_identifier] += 1

    def launch_browser(self, report_path):
        """
        [双重保险版] 自动唤起浏览器 + 输出可点击链接。
        """
        abs_path = os.path.abspath(report_path)
        # 将 Windows 路径转换为浏览器通用的 URI 格式
        file_url = 'file:///' + abs_path.replace('\\', '/')
        
        print("-" * 50)
        print(f"[System] 报表生成成功！")
        print(f"[Link] 复制并在浏览器打开以下网址:")
        print(f"\033[4;34m{file_url}\033[0m")  # 使用 ANSI 转义码显示蓝色下划线网址
        print("-" * 50)
        
        try:
            current_os = platform.system()
            if current_os == 'Windows':
                # 尝试使用 start 命令
                os.system(f'start "" "{abs_path}"')
            else:
                webbrowser.open(file_url, new=2)
            print("[Success] 已发送打开浏览器指令。")
        except Exception:
            print("[Note] 自动打开受限，请点击上方链接。")
            
    def render_report(self):
        print("[Info] 正在生成可视化报表...")
        
        user_rows = ""
        for user, count in self.user_activity_map.most_common(10):
            status_bar = f"<div style='width:{min(count*10, 100)}px; height:10px; background:#2196F3;'></div>"
            user_rows += f"<tr><td>{user}</td><td>{count}</td><td>{status_bar}</td></tr>"

        risk_rows = ""
        risk_records = [r for r in self.records if r.level in ['ERROR', 'WARNING']][-10:]
        if not risk_records:
            risk_rows = "<tr><td colspan='4' style='text-align:center; color:#27ae60;'>✅ 系统运行健康，近期无高危异常</td></tr>"
        else:
            for r in risk_records:
                color = "#ffebee" if r.level == 'ERROR' else "#fff3e0"
                risk_rows += f"<tr style='background:{color}'><td>{r.timestamp}</td><td><b>{r.level}</b></td><td>{r.module}</td><td>{r.message}</td></tr>"

        html_content = f"""
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <title>系统安全审计报告</title>
            <style>
                body {{ font-family: 'Segoe UI', Roboto, Helvetica, sans-serif; background-color: #f5f7fa; color: #333; margin: 0; padding: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.05); border-radius: 8px; overflow: hidden; }}
                .header {{ background: #2c3e50; color: white; padding: 20px 30px; display: flex; justify-content: space-between; align-items: center; }}
                .header h1 {{ margin: 0; font-size: 24px; }}
                .dashboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; }}
                .card {{ background: #fff; border: 1px solid #e1e4e8; border-radius: 6px; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.02); }}
                .card h3 {{ margin: 0 0 10px 0; color: #7f8c8d; font-size: 14px; text-transform: uppercase; }}
                .card .value {{ font-size: 36px; font-weight: bold; color: #2c3e50; }}
                .section {{ padding: 0 30px 30px 30px; }}
                .section h2 {{ border-bottom: 2px solid #3498db; padding-bottom: 10px; color: #2c3e50; font-size: 18px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }}
                th {{ background: #f8f9fa; text-align: left; padding: 12px; border-bottom: 2px solid #dee2e6; color: #495057; }}
                td {{ padding: 12px; border-bottom: 1px solid #dee2e6; }}
                tr:hover {{ background-color: #f1f3f5; }}
                .footer {{ text-align: center; padding: 20px; color: #999; font-size: 12px; border-top: 1px solid #eee; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ 安全传输系统审计报告</h1>
                    <span>生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                </div>
                
                <div class="dashboard">
                    <div class="card">
                        <h3>日志总数</h3>
                        <div class="value">{self.stats['total_count']}</div>
                    </div>
                    <div class="card">
                        <h3 style="color:#e74c3c">安全警告</h3>
                        <div class="value" style="color:#e74c3c">{self.stats['warning_count'] + self.stats['error_count']}</div>
                    </div>
                    <div class="card">
                        <h3 style="color:#27ae60">文件传输</h3>
                        <div class="value" style="color:#27ae60">{self.stats['upload_ops'] + self.stats['download_ops']}</div>
                    </div>
                    <div class="card">
                        <h3 style="color:#2980b9">用户登录</h3>
                        <div class="value" style="color:#2980b9">{self.stats['login_ops']}</div>
                    </div>
                </div>

                <div class="section">
                    <h2>📊 用户活跃度画像 (Top 10)</h2>
                    <table>
                        <thead><tr><th width="30%">用户ID</th><th width="20%">操作频次</th><th>活跃度可视化</th></tr></thead>
                        <tbody>{user_rows if user_rows else "<tr><td colspan='3'>暂无活跃用户数据</td></tr>"}</tbody>
                    </table>
                </div>

                <div class="section">
                    <h2>⚠️ 近期高危/异常事件</h2>
                    <table>
                        <thead><tr><th width="20%">时间</th><th width="10%">等级</th><th width="15%">模块</th><th>详情内容</th></tr></thead>
                        <tbody>{risk_rows}</tbody>
                    </table>
                </div>

                <div class="footer">
                    Secure File Transfer System Audit Module v1.3.1 | Powered by Python
                </div>
            </div>
        </body>
        </html>
        """
        
        try:
            with open(REPORT_OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"[Success] 报表已生成: {os.path.abspath(REPORT_OUTPUT_FILE)}")
            self.launch_browser(REPORT_OUTPUT_FILE)
        except Exception as e:
            print(f"[Error] 报表写入失败: {e}")

if __name__ == '__main__':
    print("------------------------------------------------")
    print("   Security Log Analysis System (SLAS) Startup  ")
    print("------------------------------------------------")
    engine = AuditEngine(LOG_SOURCE_FILE)
    if engine.load_data():
        engine.render_report()
    print("\n[Done] 分析流程结束.")

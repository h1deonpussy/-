import sqlite3

# 连接数据库
conn = sqlite3.connect('encryption_system.db')
cursor = conn.cursor()

# 查询所有用户的 Token
cursor.execute("SELECT id, username, token FROM user")
users = cursor.fetchall()

print("===== 所有用户 Token =====")
for user in users:
    print(f"用户ID：{user[0]} | 用户名：{user[1]} | Token：{user[2]}")

# 关闭连接
conn.close()

# 按任意键退出
input("\n按回车键退出...")

"""故意包含漏洞的演示靶场（仅供 AuditAgentX 本地授权测试，切勿部署）。

该应用只用于静态扫描和隔离实验演示，不连接真实第三方系统。
如需动态验证 SQL 注入链路，优先使用 safe_sqli_target，它不会执行真实 SQL。
"""
import os
import sqlite3
import pickle

from flask import Flask, request

app = Flask(__name__)

# 硬编码密钥（Hardcoded Secret）
API_KEY = "sk-1234567890secretkey"
DB_PASSWORD = "admin123456"


@app.route("/user")
def get_user():
    uid = request.args.get("id", "1")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("create table if not exists users (id integer, email text)")
    cur.execute("delete from users")
    cur.execute("insert into users values (1, 'admin@example.local')")
    # SQL 注入：字符串拼接
    cur.execute("select * from users where id=" + uid)
    rows = cur.fetchall()
    conn.close()
    return str(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # 命令注入：拼接进 os.system
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/load")
def load_data():
    blob = request.args.get("data")
    # 不安全的反序列化
    obj = pickle.loads(blob.encode())
    return str(obj)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

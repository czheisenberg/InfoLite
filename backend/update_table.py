# -*- coding: utf-8 -*-
# @Author: Info Lite
# @Desc: 更新MySQL表结构，添加headers字段
import pymysql
import os
from dotenv import load_dotenv

print("开始更新MySQL表结构...")

# 加载配置
load_dotenv()
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_PORT = os.getenv("MYSQL_PORT")
MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PWD = os.getenv("MYSQL_PWD")
MYSQL_DB = os.getenv("MYSQL_DB")

print(f"MySQL配置：{MYSQL_HOST}:{MYSQL_PORT}, DB: {MYSQL_DB}")

# 连接MySQL
try:
    conn = pymysql.connect(
        host=MYSQL_HOST,
        port=int(MYSQL_PORT),
        user=MYSQL_USER,
        password=MYSQL_PWD,
        database=MYSQL_DB,
        charset="utf8mb4"
    )
    print("MySQL连接成功")
    
    cursor = conn.cursor()
    
    # 检查headers字段是否存在
    print("检查headers字段是否存在...")
    cursor.execute("SHOW COLUMNS FROM asset LIKE 'headers'")
    result = cursor.fetchone()
    
    if not result:
        # 添加headers字段
        print("headers字段不存在，开始添加...")
        alter_sql = "ALTER TABLE asset ADD COLUMN headers TEXT COMMENT 'HTTP响应头（JSON格式）'"
        cursor.execute(alter_sql)
        conn.commit()
        print("MySQL表结构更新成功：添加了headers字段")
    else:
        print("headers字段已存在，跳过更新")
        print(f"字段信息：{result}")
finally:
    if 'cursor' in locals():
        cursor.close()
    if 'conn' in locals():
        conn.close()
    print("MySQL连接已关闭")

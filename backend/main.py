# -*- coding: utf-8 -*-
# @Author: Info Lite
# @Desc: 测绘平台后端主程序 - FastAPI入口、配置初始化
import os
import time
from dotenv import load_dotenv
from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer

# 导入自定义模块
from scan_nmap import (
    init_scan_config
)
from db_operate import (
    init_mysql_conn, init_es_conn, create_mysql_asset_table,
    create_es_asset_index, create_mysql_user_table
)

# 导入依赖模块
import api.deps

# 导入API路由
from api.routes import api_router

# ===================== 初始化配置 =====================
# 加载.env配置文件
load_dotenv(override=True)  # override=True：覆盖系统环境变量
# 读取MySQL配置
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_PORT = os.getenv("MYSQL_PORT")
MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PWD = os.getenv("MYSQL_PWD")
MYSQL_DB = os.getenv("MYSQL_DB")
# 读取ES配置
ES_HOST = os.getenv("ES_HOST")
ES_PORT = os.getenv("ES_PORT")
# 读取扫描配置
ALLOWED_IP_PREFIX = os.getenv("ALLOWED_IP_PREFIX")
MAX_CONCURRENT = os.getenv("MAX_CONCURRENT")
SCAN_TIMEOUT = os.getenv("SCAN_TIMEOUT")
COMMON_PORTS = os.getenv("COMMON_PORTS")
NMAP_PATH = os.getenv("NMAP_PATH", "nmap")
SCAN_EXPIRE_TIME = int(os.getenv("SCAN_EXPIRE_TIME"))
# 读取API配置
API_HOST = os.getenv("API_HOST")
API_PORT = int(os.getenv("API_PORT"))

# JWT配置
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")  # 生产环境应从环境变量读取
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2密码流
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# 初始化FastAPI应用
app = FastAPI(
    title="Info Lite 测绘平台API",
    description="轻量版网络空间测绘平台 - 端口探测+指纹识别+资产存储",
    version="1.0.0",
    docs_url="/docs",  # Swagger接口文档地址
    redoc_url="/redoc" # 备用文档地址
)

# 全局初始化数据库连接和扫描配置（启动时执行一次）
# 扫描配置
SCAN_CONFIG = init_scan_config(ALLOWED_IP_PREFIX, MAX_CONCURRENT, SCAN_TIMEOUT, COMMON_PORTS, NMAP_PATH)
# MySQL连接
MYSQL_CONN, MYSQL_CURSOR = init_mysql_conn(MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PWD, MYSQL_DB)
# ES连接
ES_CONN = init_es_conn(ES_HOST, ES_PORT)
# 初始化MySQL表和ES索引
create_mysql_asset_table(MYSQL_CONN, MYSQL_CURSOR)
create_mysql_user_table(MYSQL_CONN, MYSQL_CURSOR)
create_es_asset_index(ES_CONN)

# 将全局变量赋值给deps模块
api.deps.mysql_conn = MYSQL_CONN
api.deps.mysql_cursor = MYSQL_CURSOR
api.deps.es_conn = ES_CONN
api.deps.scan_config = SCAN_CONFIG
api.deps.scan_expire_time = SCAN_EXPIRE_TIME
api.deps.secret_key = SECRET_KEY
api.deps.algorithm = ALGORITHM

print("="*50)
print("Info Lite 后端服务初始化完成！")
print(f"API文档地址: http://{API_HOST}:{API_PORT}/docs")
print(f"扫描白名单: {ALLOWED_IP_PREFIX}")
print("="*50)

# 依赖注入函数
async def get_db():
    """
    获取数据库连接
    """
    return {
        "mysql_conn": MYSQL_CONN,
        "mysql_cursor": MYSQL_CURSOR,
        "es_conn": ES_CONN,
        "scan_config": SCAN_CONFIG,
        "scan_expire_time": SCAN_EXPIRE_TIME,
        "secret_key": SECRET_KEY,
        "algorithm": ALGORITHM
    }

# 注册API路由
app.include_router(api_router, dependencies=[Depends(get_db)])

# ===================== 程序入口 =====================
if __name__ == "__main__":
    import uvicorn
    # 启动FastAPI服务，仅本地访问
    uvicorn.run(
        app="main:app",
        host=API_HOST,
        port=API_PORT,
        reload=True,  # 开发模式：代码修改自动重启服务
        log_level="info"
    )

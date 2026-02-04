# -*- coding: utf-8 -*-
# @Author: Info Lite
# @Desc: 测绘平台后端主程序 - FastAPI入口、API接口、核心业务逻辑
import os
import time
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Query, HTTPException, Depends, Body
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext

# 导入自定义模块
from scan_core import (
    init_scan_config, check_ip_allowed, ip_full_scan
)
from db_operate import (
    init_mysql_conn, init_es_conn, create_mysql_asset_table,
    create_es_asset_index, insert_asset_to_mysql, insert_asset_to_es,
    query_asset_from_db, close_db_conn, create_mysql_user_table,
    insert_user, query_user, update_user_login_time
)

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
SCAN_EXPIRE_TIME = int(os.getenv("SCAN_EXPIRE_TIME"))
# 读取API配置
API_HOST = os.getenv("API_HOST")
API_PORT = int(os.getenv("API_PORT"))

# JWT配置
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")  # 生产环境应从环境变量读取
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 密码加密上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
SCAN_CONFIG = init_scan_config(ALLOWED_IP_PREFIX, MAX_CONCURRENT, SCAN_TIMEOUT, COMMON_PORTS)
# MySQL连接
MYSQL_CONN, MYSQL_CURSOR = init_mysql_conn(MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PWD, MYSQL_DB)
# ES连接
ES_CONN = init_es_conn(ES_HOST, ES_PORT)
# 初始化MySQL表和ES索引
create_mysql_asset_table(MYSQL_CONN, MYSQL_CURSOR)
create_mysql_user_table(MYSQL_CONN, MYSQL_CURSOR)
create_es_asset_index(ES_CONN)

print("="*50)
print("Info Lite 后端服务初始化完成！")
print(f"API文档地址: http://{API_HOST}:{API_PORT}/docs")
print(f"扫描白名单: {ALLOWED_IP_PREFIX}")
print("="*50)

# ===================== JWT工具函数 =====================
def verify_password(plain_password, hashed_password):
    """
    验证密码
    :param plain_password: 明文密码
    :param hashed_password: 哈希密码
    :return: 是否匹配
    """
    try:
        # 截断密码到72字节，PassLib库的限制
        plain_password = plain_password[:72]
        # 先尝试bcrypt验证
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        print(f"bcrypt验证失败: {str(e)}")
        # 尝试SHA256验证（备用方案）
        try:
            import hashlib
            return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password
        except Exception as e2:
            print(f"SHA256验证失败: {str(e2)}")
            return False

def get_password_hash(password):
    """
    获取密码哈希值
    :param password: 明文密码
    :return: 哈希密码
    """
    try:
        # 截断密码到72字节，PassLib库的限制
        password = password[:72]
        return pwd_context.hash(password)
    except Exception as e:
        print(f"密码哈希失败: {str(e)}")
        # 使用备用哈希方法
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()

def create_access_token(data: dict, expires_delta=None):
    """
    创建访问令牌
    :param data: 要编码的数据
    :param expires_delta: 过期时间
    :return: JWT token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = time.time() + expires_delta
    else:
        expire = time.time() + ACCESS_TOKEN_EXPIRE_MINUTES * 60
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token):
    """
    解码访问令牌
    :param token: JWT token
    :return: 解码后的数据
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    获取当前用户
    :param token: JWT token
    :return: 用户信息
    """
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = query_user(MYSQL_CONN, MYSQL_CURSOR, username)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

# ===================== 认证API接口 =====================
@app.post("/api/auth/register", summary="用户注册接口", tags=["认证操作"])
async def register(
    username: str = Body(..., description="用户名"),
    password: str = Body(..., description="密码")
):
    """
    用户注册接口
    """
    # 注册逻辑
    try:
        # 检查用户名是否已存在
        existing_user = query_user(MYSQL_CONN, MYSQL_CURSOR, username)
        if existing_user:
            return JSONResponse(
                status_code=400,
                content={"code": 400, "msg": "用户名已存在", "data": []}
            )
        
        # 密码加密
        hashed_password = get_password_hash(password)
        
        # 插入用户
        success = insert_user(MYSQL_CONN, MYSQL_CURSOR, username, hashed_password)
        if not success:
            return JSONResponse(
                status_code=500,
                content={"code": 500, "msg": "注册失败", "data": []}
            )
        
        return JSONResponse(
            status_code=200,
            content={"code": 200, "msg": "注册成功", "data": []}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"服务器内部错误：{str(e)}", "data": []}
        )

@app.post("/api/auth/login", summary="用户登录接口", tags=["认证操作"])
async def login(
    username: str = Body(..., description="用户名"),
    password: str = Body(..., description="密码")
):
    """
    用户登录接口
    """
    try:
        # 查询用户
        user = query_user(MYSQL_CONN, MYSQL_CURSOR, username)
        if not user:
            return JSONResponse(
                status_code=401,
                content={"code": 401, "msg": "用户名或密码错误", "data": []}
            )
        
        # 验证密码
        if not verify_password(password, user["password"]):
            return JSONResponse(
                status_code=401,
                content={"code": 401, "msg": "用户名或密码错误", "data": []}
            )
        
        # 更新最后登录时间
        update_user_login_time(MYSQL_CONN, MYSQL_CURSOR, user["id"])
        
        # 创建访问令牌
        access_token = create_access_token(data={"sub": user["username"]})
        
        return JSONResponse(
            status_code=200,
            content={
                "code": 200,
                "msg": "登录成功",
                "data": {
                    "access_token": access_token,
                    "token_type": "bearer",
                    "username": user["username"]
                }
            }
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"服务器内部错误：{str(e)}", "data": []}
        )

@app.get("/api/asset/query", summary="资产查询/扫描接口", tags=["资产操作"])
async def query_asset(
    ip: str = Query(..., description="目标IP地址，如127.0.0.1"),
    refresh: bool = Query(False, description="是否强制刷新扫描，默认False"),
    current_user: dict = Depends(get_current_user)
):
    """
    资产查询/扫描核心接口：
    1. 非刷新+IP有有效数据 → 直接返回数据库数据
    2. 非刷新+无数据/数据过期 → 触发扫描+入库+返回
    3. 刷新 → 强制触发扫描+覆盖数据库+返回
    """
    try:
        # 第一步：IP格式简单校验（基础校验，避免无效请求）
        ip_parts = ip.split(".")
        if len(ip_parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
            raise HTTPException(status_code=400, detail=f"IP地址格式错误：{ip}")
        
        # 第二步：IP白名单校验（核心安全限制，禁止扫描非白名单IP）
        if not check_ip_allowed(ip, SCAN_CONFIG["allowed_ip"]):
            raise HTTPException(status_code=403, detail=f"IP {ip} 不在扫描白名单内，禁止扫描！")
        
        # 第三步：非刷新模式，先查询数据库是否有有效数据
        if not refresh:
            db_result = query_asset_from_db(ip, MYSQL_CONN, MYSQL_CURSOR, ES_CONN, SCAN_EXPIRE_TIME)
            if db_result["is_valid"] and db_result["data"]:
                return JSONResponse(
                    status_code=200,
                    content={
                        "code": 200,
                        "msg": "查询成功（从数据库获取）",
                        "data": db_result["data"],
                        "scan_type": "db_query"
                    }
                )
        
        # 第四步：触发扫描（无数据/数据过期/强制刷新）
        asset_list = ip_full_scan(ip, SCAN_CONFIG)
        if not asset_list:
            return JSONResponse(
                status_code=200,
                content={
                    "code": 200,
                    "msg": f"IP {ip} 无开放端口或扫描失败",
                    "data": [],
                    "scan_type": "scan"
                }
            )
        
        # 第五步：扫描结果入库（MySQL+ES）
        insert_asset_to_mysql(MYSQL_CONN, MYSQL_CURSOR, asset_list)
        insert_asset_to_es(ES_CONN, asset_list)
        
        # 第六步：返回扫描结果
        return JSONResponse(
            status_code=200,
            content={
                "code": 200,
                "msg": "扫描成功（新结果已入库）",
                "data": asset_list,
                "scan_type": "scan"
            }
        )
    
    except HTTPException as e:
        # 自定义异常（IP格式/白名单）
        return JSONResponse(
            status_code=e.status_code,
            content={"code": e.status_code, "msg": e.detail, "data": []}
        )
    except Exception as e:
        # 未知异常
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"服务器内部错误：{str(e)}", "data": []}
        )

@app.get("/api/health", summary="服务健康检查接口", tags=["系统操作"])
async def health_check(current_user: dict = Depends(get_current_user)):
    """服务健康检查 - 验证后端和数据库是否正常运行"""
    try:
        # 检查MySQL连接
        MYSQL_CURSOR.execute("SELECT 1")
        # 检查ES连接
        ES_CONN.ping()
        return JSONResponse(
            status_code=200,
            content={"code": 200, "msg": "服务健康", "data": {"time": time.strftime("%Y-%m-%d %H:%M:%S")}}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"服务异常：{str(e)}", "data": {}}
        )

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
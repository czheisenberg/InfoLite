# -*- coding: utf-8 -*-
# @Author: Info Lite
# @Desc: 认证相关API路由
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer

from api.utils.jwt_utils import verify_password, get_password_hash, create_access_token, decode_access_token
from api.deps import get_db
from db_operate import query_user, insert_user, update_user_login_time

router = APIRouter(prefix="/api/auth", tags=["认证操作"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


async def get_current_user(token: str = Depends(oauth2_scheme), db: dict = Depends(get_db)):
    """
    获取当前用户
    :param token: JWT token
    :param db: 数据库连接和配置
    :return: 用户信息
    """
    payload = decode_access_token(token, db["secret_key"], db["algorithm"])
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
    user = query_user(db["mysql_conn"], db["mysql_cursor"], username)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@router.post("/register", summary="用户注册接口")
async def register(
    username: str = Body(..., description="用户名"),
    password: str = Body(..., description="密码"),
    db: dict = Depends(get_db)
):
    """
    用户注册接口
    """
    try:
        # 检查用户名是否已存在
        existing_user = query_user(db["mysql_conn"], db["mysql_cursor"], username)
        if existing_user:
            return JSONResponse(
                status_code=400,
                content={"code": 400, "msg": "用户名已存在", "data": []}
            )
        
        # 密码加密
        hashed_password = get_password_hash(password)
        
        # 插入用户
        success = insert_user(db["mysql_conn"], db["mysql_cursor"], username, hashed_password)
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


@router.post("/login", summary="用户登录接口")
async def login(
    username: str = Body(..., description="用户名"),
    password: str = Body(..., description="密码"),
    db: dict = Depends(get_db)
):
    """
    用户登录接口
    """
    try:
        # 查询用户
        user = query_user(db["mysql_conn"], db["mysql_cursor"], username)
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
        update_user_login_time(db["mysql_conn"], db["mysql_cursor"], user["id"])
        
        # 创建访问令牌
        access_token = create_access_token(data={"sub": user["username"]}, secret_key=db["secret_key"], algorithm=db["algorithm"])
        
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

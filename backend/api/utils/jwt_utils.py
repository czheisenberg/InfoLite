# -*- coding: utf-8 -*-
# @Author: Info Lite
# @Desc: JWT认证工具函数
import time
import jwt
import hashlib
from passlib.context import CryptContext

# 密码加密上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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
        return hashlib.sha256(password.encode()).hexdigest()


def create_access_token(data: dict, expires_delta=None, secret_key="your-secret-key", algorithm="HS256"):
    """
    创建访问令牌
    :param data: 要编码的数据
    :param expires_delta: 过期时间
    :param secret_key: 密钥
    :param algorithm: 算法
    :return: JWT token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = time.time() + expires_delta
    else:
        expire = time.time() + 30 * 60  # 默认30分钟
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt


def decode_access_token(token, secret_key="your-secret-key", algorithm="HS256"):
    """
    解码访问令牌
    :param token: JWT token
    :param secret_key: 密钥
    :param algorithm: 算法
    :return: 解码后的数据
    """
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        return payload
    except jwt.PyJWTError:
        return None

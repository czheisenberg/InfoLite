# -*- coding: utf-8 -*-
# @Author: Info Lite
# @Desc: 依赖注入模块
from fastapi import Depends

# 全局变量，将在main.py中初始化
mysql_conn = None
mysql_cursor = None
es_conn = None
scan_config = None
scan_expire_time = 3600
secret_key = "your-secret-key"
algorithm = "HS256"

# 依赖注入函数
async def get_db():
    """
    获取数据库连接
    """
    return {
        "mysql_conn": mysql_conn,
        "mysql_cursor": mysql_cursor,
        "es_conn": es_conn,
        "scan_config": scan_config,
        "scan_expire_time": scan_expire_time,
        "secret_key": secret_key,
        "algorithm": algorithm
    }

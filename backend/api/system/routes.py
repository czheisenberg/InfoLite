# -*- coding: utf-8 -*-
# @Author: Info Lite
# @Desc: 系统相关API路由
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
import time

from api.deps import get_db

router = APIRouter(prefix="/api", tags=["系统操作"])


@router.get("/health", summary="服务健康检查接口")
async def health_check(
    current_user: dict = Depends(lambda: None),  # 临时占位，后续会替换
    db: dict = Depends(get_db)
):
    """
    服务健康检查 - 验证后端和数据库是否正常运行
    """
    try:
        # 检查MySQL连接
        db["mysql_cursor"].execute("SELECT 1")
        # 检查ES连接
        db["es_conn"].ping()
        return JSONResponse(
            status_code=200,
            content={"code": 200, "msg": "服务健康", "data": {"time": time.strftime("%Y-%m-%d %H:%M:%S")}}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"服务异常：{str(e)}", "data": {}}
        )

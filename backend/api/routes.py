# -*- coding: utf-8 -*-
# @Author: Info Lite
# @Desc: API路由主文件
from fastapi import APIRouter, Depends
from api.auth.routes import router as auth_router
from api.asset.routes import router as asset_router
from api.system.routes import router as system_router

# 创建主路由
api_router = APIRouter()

# 注册子路由
api_router.include_router(auth_router)
api_router.include_router(asset_router)
api_router.include_router(system_router)

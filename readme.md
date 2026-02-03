## InfoLite

backend/
├── .env                # 敏感配置文件（数据库/Redis/ES地址、密码）
├── requirements.txt    # 项目依赖（已修正无内置库、无编译问题）
├── main.py             # 后端主程序（API接口、核心逻辑）
├── scan_core.py        # 扫描核心模块（端口探测、指纹识别）
└── db_operate.py       # 数据库操作模块（MySQL/ES 增删改查）
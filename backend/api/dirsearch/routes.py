"""
dirsearch 扫描 API 路由
"""

import os
import sys
import time
import json
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

# 添加 dirsearch 到 path
DIRSEARCH_PATH = os.path.join(os.path.dirname(__file__), '..', 'dirsearch')
if DIRSEARCH_PATH not in sys.path:
    sys.path.insert(0, DIRSEARCH_PATH)

from dirsearch import DirsearchFuzzer, FuzzerConfig, Wordlist

router = APIRouter(prefix="/api/dirsearch", tags=["dirsearch"])


class DirsearchResult(BaseModel):
    """单个结果模型"""
    url: str
    path: str
    status: int
    length: int
    content_type: str = ""
    redirect: str = ""
    elapsed: float = 0
    headers: Dict[str, str] = {}


class DirsearchScanResponse(BaseModel):
    """扫描响应模型"""
    success: bool
    message: str
    total: int = 0
    results: List[DirsearchResult] = []
    scan_time: float = 0


@router.get("/scan", response_model=DirsearchScanResponse)
async def dirsearch_scan(
    url: str = Query(..., description="目标 URL（需要以 / 结尾）"),
    extensions: Optional[str] = Query("php,html,js,json,jsp,asp,aspx,py,rb,java,cs,cgi,xml,yaml,yml,txt,md", description="文件扩展名，逗号分隔"),
    timeout: int = Query(10, description="请求超时时间（秒）"),
    user_agent: Optional[str] = Query(None, description="自定义 User-Agent"),
    cookies: Optional[str] = Query(None, description="HTTP Cookies"),
    headers: Optional[str] = Query(None, description="自定义请求头，JSON 格式"),
    follow_redirects: bool = Query(False, description="是否跟随重定向"),
    exclude_status_codes: Optional[str] = Query(None, description="排除的状态码，逗号分隔"),
    include_status_codes: Optional[str] = Query(None, description="包含的状态码，逗号分隔"),
    ignore_404: bool = Query(True, description="忽略 404 状态码"),
    ignore_403: bool = Query(False, description="忽略 403 状态码"),
    ignore_5xx: bool = Query(False, description="忽略 5xx 状态码"),
    wordlist_type: str = Query("default", description="词表类型: default / common / api / admin / auth / backups / db / logs"),
):
    """
    执行 dirsearch Web 目录扫描

    支持自定义扩展名、超时时间、状态码过滤等参数
    """
    start_time = time.time()

    # 验证 URL
    if not url.startswith(('http://', 'https://')):
        return DirsearchScanResponse(
            success=False,
            message="URL 必须以 http:// 或 https:// 开头"
        )

    # 确保 URL 格式正确
    if not url.endswith('/'):
        url += '/'

    # 解析 headers
    headers_dict = {}
    if headers:
        try:
            headers_dict = json.loads(headers)
        except:
            pass

    # 设置 Cookies
    if cookies:
        headers_dict['Cookie'] = cookies

    # 解析排除的状态码
    exclude_codes = set()
    if ignore_404:
        exclude_codes.add(404)
    if ignore_403:
        exclude_codes.add(403)
    if ignore_5xx:
        for code in range(500, 600):
            exclude_codes.add(code)
    if exclude_status_codes:
        try:
            for code in exclude_status_codes.split(','):
                code = code.strip()
                if code:
                    exclude_codes.add(int(code))
        except:
            pass

    # 解析包含的状态码
    include_codes = set()
    if include_status_codes:
        try:
            for code in include_status_codes.split(','):
                code = code.strip()
                if code:
                    include_codes.add(int(code))
        except:
            pass

    # 选择词表
    wordlist_file = None
    if wordlist_type == "default":
        wordlist_file = os.path.join(DIRSEARCH_PATH, 'db', 'dicc.txt')
    elif wordlist_type == "common":
        wordlist_file = os.path.join(DIRSEARCH_PATH, 'db', 'categories', 'common.txt')
    elif wordlist_type == "api":
        wordlist_file = os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'api.txt')
    elif wordlist_type == "admin":
        wordlist_file = os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'admin.txt')
    elif wordlist_type == "auth":
        wordlist_file = os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'auth.txt')
    elif wordlist_type == "backups":
        wordlist_file = os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'backups.txt')
    elif wordlist_type == "db":
        wordlist_file = os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'db.txt')
    elif wordlist_type == "logs":
        wordlist_file = os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'logs.txt')

    # 加载词表
    wordlist = None
    if wordlist_file and os.path.exists(wordlist_file):
        wordlist = Wordlist.from_file(wordlist_file)
    else:
        # 默认使用一个小词表
        wordlist = Wordlist([
            "admin", "login", "api", "index", "index.html", "index.php",
            "robots.txt", "sitemap.xml", ".git", "backup", "test",
            "config", "db", "phpinfo", "info.php", "wp-admin",
            "wp-login.php", "console", "manager", "administrator"
        ])

    # 解析扩展名
    ext_list = ()
    if extensions:
        ext_list = tuple(e.strip() for e in extensions.split(',') if e.strip())

    # 构建 FuzzerConfig
    config = FuzzerConfig(
        url=url,
        wordlist=wordlist,
        extensions=ext_list,
        headers=headers_dict,
        timeout=float(timeout),
        follow_redirects=follow_redirects,
        exclude_status_codes=exclude_codes,
        include_status_codes=include_codes,
        user_agent=user_agent if user_agent else None,
    )

    results = []

    try:
        fuzzer = DirsearchFuzzer(config)
        fuzzer_results = fuzzer.run()

        for result in fuzzer_results:
            result_dict = DirsearchResult(
                url=result.url,
                path=result.path,
                status=result.status,
                length=result.length,
                content_type=result.content_type,
                redirect=result.redirect,
                elapsed=result.elapsed,
                headers=dict(result.headers)
            )
            results.append(result_dict)

        scan_time = time.time() - start_time

        return DirsearchScanResponse(
            success=True,
            message=f"扫描完成，发现 {len(results)} 个路径",
            total=len(results),
            results=results,
            scan_time=scan_time
        )

    except Exception as e:
        scan_time = time.time() - start_time
        return DirsearchScanResponse(
            success=False,
            message=f"扫描出错: {str(e)}",
            total=0,
            results=[],
            scan_time=scan_time
        )


@router.get("/wordlists")
async def get_wordlists():
    """
    获取可用的词表列表
    """
    wordlists = [
        {
            'name': 'default',
            'description': '内置词表 (dicc.txt)',
            'path': os.path.join(DIRSEARCH_PATH, 'db', 'dicc.txt'),
            'exists': os.path.exists(os.path.join(DIRSEARCH_PATH, 'db', 'dicc.txt'))
        },
        {
            'name': 'common',
            'description': '通用词表 (common.txt)',
            'path': os.path.join(DIRSEARCH_PATH, 'db', 'categories', 'common.txt'),
            'exists': os.path.exists(os.path.join(DIRSEARCH_PATH, 'db', 'categories', 'common.txt'))
        },
        {
            'name': 'api',
            'description': 'API 词表 (api.txt)',
            'path': os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'api.txt'),
            'exists': os.path.exists(os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'api.txt'))
        },
        {
            'name': 'admin',
            'description': '管理员词表 (admin.txt)',
            'path': os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'admin.txt'),
            'exists': os.path.exists(os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'admin.txt'))
        },
        {
            'name': 'auth',
            'description': '认证词表 (auth.txt)',
            'path': os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'auth.txt'),
            'exists': os.path.exists(os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'auth.txt'))
        },
        {
            'name': 'backups',
            'description': '备份词表 (backups.txt)',
            'path': os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'backups.txt'),
            'exists': os.path.exists(os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'backups.txt'))
        },
        {
            'name': 'db',
            'description': '数据库词表 (db.txt)',
            'path': os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'db.txt'),
            'exists': os.path.exists(os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'db.txt'))
        },
        {
            'name': 'logs',
            'description': '日志词表 (logs.txt)',
            'path': os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'logs.txt'),
            'exists': os.path.exists(os.path.join(DIRSEARCH_PATH, 'db', 'templates', 'logs.txt'))
        },
    ]

    return JSONResponse({
        'success': True,
        'wordlists': wordlists
    })


@router.get("/extensions")
async def get_extensions():
    """
    获取常用扩展名列表
    """
    common_extensions = [
        {'name': 'PHP', 'value': 'php', 'checked': True},
        {'name': 'HTML', 'value': 'html', 'checked': True},
        {'name': 'JS', 'value': 'js', 'checked': True},
        {'name': 'JSON', 'value': 'json', 'checked': True},
        {'name': 'JSP', 'value': 'jsp', 'checked': False},
        {'name': 'ASP', 'value': 'asp', 'checked': False},
        {'name': 'ASPX', 'value': 'aspx', 'checked': False},
        {'name': 'Python', 'value': 'py', 'checked': False},
        {'name': 'Ruby', 'value': 'rb', 'checked': False},
        {'name': 'Java', 'value': 'java', 'checked': False},
        {'name': 'C#', 'value': 'cs', 'checked': False},
        {'name': 'CGI', 'value': 'cgi', 'checked': False},
        {'name': 'XML', 'value': 'xml', 'checked': False},
        {'name': 'YAML', 'value': 'yaml,yml', 'checked': False},
        {'name': 'TXT', 'value': 'txt', 'checked': False},
        {'name': 'MD', 'value': 'md', 'checked': False},
        {'name': 'Conf', 'value': 'conf', 'checked': False},
        {'name': 'DB', 'value': 'db,sql', 'checked': False},
        {'name': '备份', 'value': 'bak,backup,old', 'checked': False},
    ]

    return JSONResponse({
        'success': True,
        'extensions': common_extensions
    })

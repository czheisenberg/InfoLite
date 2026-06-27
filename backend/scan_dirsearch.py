"""
dirsearch 扫描模块
集成 maurosoria/dirsearch 进行 Web 目录扫描
"""

import sys
import os
import time
import threading
from typing import List, Dict, Any, Optional, Callable

from dirsearch import DirsearchFuzzer, FuzzerConfig, Wordlist
import dirsearch

DIRSEARCH_DB_PATH = os.path.join(os.path.dirname(dirsearch.__file__), 'db')


class DirsearchScanner:
    """dirsearch 扫描器封装类"""

    def __init__(self):
        self.results = []
        self.is_running = False
        self._thread = None
        self._stop_event = threading.Event()

    def scan(
        self,
        url: str,
        extensions: Optional[List[str]] = None,
        wordlist: Optional[List[str]] = None,
        wordlist_file: Optional[str] = None,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        cookies: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = False,
        exclude_status_codes: Optional[List[int]] = None,
        include_status_codes: Optional[List[int]] = None,
        ignore_404: bool = True,
        ignore_403: bool = False,
        ignore_5xx: bool = False,
        match_callback: Optional[Callable] = None,
        progress_callback: Optional[Callable] = None
    ) -> List[Dict[str, Any]]:
        """
        执行 dirsearch 扫描

        Args:
            url: 目标 URL（需要以 / 结尾，如 https://example.com/）
            extensions: 文件扩展名列表，如 ['php', 'html', 'js']
            wordlist: 自定义词表列表
            wordlist_file: 词表文件路径
            timeout: 请求超时时间（秒）
            user_agent: 自定义 User-Agent
            cookies: HTTP Cookies
            headers: 自定义请求头
            follow_redirects: 是否跟随重定向
            exclude_status_codes: 排除的状态码列表
            include_status_codes: 包含的状态码列表
            ignore_404: 是否忽略 404 状态码
            ignore_403: 是否忽略 403 状态码
            ignore_5xx: 是否忽略 5xx 状态码
            match_callback: 匹配结果回调函数 (result: Dict) -> None
            progress_callback: 进度回调函数 (current: int, total: int, result: Dict) -> None

        Returns:
            扫描结果列表
        """
        self.results = []
        self.is_running = True
        self._stop_event.clear()

        # 确保 URL 格式正确
        if not url.endswith('/'):
            url += '/'

        # 处理扩展名
        ext_tuple = ()
        if extensions:
            if isinstance(extensions, str):
                ext_list = [e.strip() for e in extensions.split(',') if e.strip()]
            else:
                ext_list = [str(e).strip() for e in extensions if str(e).strip()]
            ext_tuple = tuple(ext_list)

        # 加载词表
        if wordlist:
            wl = Wordlist(wordlist)
        elif wordlist_file and os.path.exists(wordlist_file):
            wl = Wordlist.from_file(wordlist_file)
        else:
            default_file = os.path.join(DIRSEARCH_DB_PATH, 'dicc.txt')
            if os.path.exists(default_file):
                wl = Wordlist.from_file(default_file)
            else:
                wl = Wordlist([
                    "admin", "login", "api", "index", "index.html", "index.php",
                    "robots.txt", "sitemap.xml", ".git", "backup", "test",
                    "config", "db", "phpinfo", "info.php", "wp-admin",
                    "wp-login.php", "console", "manager", "administrator"
                ])

        # 构建请求头
        headers_dict = dict(headers) if headers else {}
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
            exclude_codes.update(int(code) for code in exclude_status_codes)

        # 解析包含的状态码
        include_codes = set()
        if include_status_codes:
            include_codes.update(int(code) for code in include_status_codes)

        # 构建 FuzzerConfig
        config = FuzzerConfig(
            url=url,
            wordlist=wl,
            extensions=ext_tuple,
            headers=headers_dict,
            timeout=float(timeout),
            follow_redirects=follow_redirects,
            exclude_status_codes=exclude_codes,
            include_status_codes=include_codes,
            user_agent=user_agent if user_agent else None,
        )

        try:
            fuzzer = DirsearchFuzzer(config)
            fuzzer_results = fuzzer.run()

            for result in fuzzer_results:
                if self._stop_event.is_set():
                    break

                result_dict = {
                    'url': result.url,
                    'path': result.path,
                    'status': result.status,
                    'length': result.length,
                    'content_type': result.content_type,
                    'redirect': result.redirect,
                    'elapsed': result.elapsed,
                    'headers': dict(result.headers),
                }

                self.results.append(result_dict)

                # 调用回调函数
                if match_callback:
                    match_callback(result_dict)
                if progress_callback:
                    progress_callback(len(self.results), 0, result_dict)

            return self.results

        except Exception as e:
            raise Exception(f"dirsearch 扫描出错: {str(e)}")
        finally:
            self.is_running = False

    def scan_async(
        self,
        url: str,
        extensions: Optional[List[str]] = None,
        wordlist: Optional[List[str]] = None,
        wordlist_file: Optional[str] = None,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        cookies: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = False,
        exclude_status_codes: Optional[List[int]] = None,
        include_status_codes: Optional[List[int]] = None,
        ignore_404: bool = True,
        ignore_403: bool = False,
        ignore_5xx: bool = False,
        progress_callback: Optional[Callable] = None
    ):
        """异步启动扫描"""
        self._thread = threading.Thread(
            target=self.scan,
            kwargs={
                'url': url,
                'extensions': extensions,
                'wordlist': wordlist,
                'wordlist_file': wordlist_file,
                'timeout': timeout,
                'user_agent': user_agent,
                'cookies': cookies,
                'headers': headers,
                'follow_redirects': follow_redirects,
                'exclude_status_codes': exclude_status_codes,
                'include_status_codes': include_status_codes,
                'ignore_404': ignore_404,
                'ignore_403': ignore_403,
                'ignore_5xx': ignore_5xx,
                'progress_callback': progress_callback
            }
        )
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        """停止扫描"""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def get_results(self) -> List[Dict[str, Any]]:
        """获取当前扫描结果"""
        return self.results

    def is_scanning(self) -> bool:
        """检查是否正在扫描"""
        return self.is_running


# 全局扫描器实例
_scanner = DirsearchScanner()


def dirsearch_scan(
    url: str,
    extensions: Optional[List[str]] = None,
    wordlist: Optional[List[str]] = None,
    wordlist_file: Optional[str] = None,
    timeout: int = 10,
    user_agent: Optional[str] = None,
    cookies: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    follow_redirects: bool = False,
    exclude_status_codes: Optional[List[int]] = None,
    include_status_codes: Optional[List[int]] = None,
    ignore_404: bool = True,
    ignore_403: bool = False,
    ignore_5xx: bool = False
) -> List[Dict[str, Any]]:
    """
    dirsearch 扫描的便捷函数

    Args:
        url: 目标 URL
        extensions: 文件扩展名列表
        wordlist: 自定义词表
        wordlist_file: 词表文件路径
        timeout: 请求超时时间
        user_agent: User-Agent 字符串
        cookies: HTTP Cookies
        headers: 自定义请求头
        follow_redirects: 是否跟随重定向
        exclude_status_codes: 排除的状态码
        include_status_codes: 包含的状态码
        ignore_404: 忽略 404
        ignore_403: 忽略 403
        ignore_5xx: 忽略 5xx

    Returns:
        扫描结果列表
    """
    global _scanner
    _scanner = DirsearchScanner()

    return _scanner.scan(
        url=url,
        extensions=extensions,
        wordlist=wordlist,
        wordlist_file=wordlist_file,
        timeout=timeout,
        user_agent=user_agent,
        cookies=cookies,
        headers=headers,
        follow_redirects=follow_redirects,
        exclude_status_codes=exclude_status_codes,
        include_status_codes=include_status_codes,
        ignore_404=ignore_404,
        ignore_403=ignore_403,
        ignore_5xx=ignore_5xx
    )

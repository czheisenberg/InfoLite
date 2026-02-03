# -*- coding: utf-8 -*-
# @Author: Info Lite
# @Desc: 扫描核心模块 - 端口探测、指纹识别、IP白名单校验
import re
import socket
import time
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用HTTPS证书警告（本地测试无需验证证书）
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# 全局变量 - 指纹规则库（基于Wappalyzer，适配常见Web组件）
FINGERPRINT_DB = [
    {"name": "Nginx", "regex": [r"Server: nginx/(\d+\.\d+\.\d+)", r"Server: nginx"], "favicon": []},
    {"name": "Apache", "regex": [r"Server: Apache/(\d+\.\d+\.\d+)", r"Server: Apache"], "favicon": []},
    {"name": "Tomcat", "regex": [r"Apache-Coyote", r"JSESSIONID", r"Tomcat"], "favicon": ["443b7e4d4a853022c66014e059820433"]},
    {"name": "WordPress", "regex": [r"WordPress", r"/wp-content/", r"/wp-includes/"], "favicon": []},
    {"name": "MySQL", "regex": [r"MySQL Server", r"mysql_native_password"], "favicon": []},
    {"name": "Redis", "regex": [r"Redis server", r"REDIS"], "favicon": []}
]

def init_scan_config(allowed_ip_prefix, max_concurrent, scan_timeout, common_ports):
    """
    初始化扫描配置
    :param allowed_ip_prefix: IP白名单前缀（字符串，逗号分隔）
    :param max_concurrent: 最大并发数
    :param scan_timeout: 探测超时时间（秒）
    :param common_ports: 常用端口（字符串，逗号分隔）
    :return: 格式化后的配置字典
    """
    return {
        "allowed_ip": allowed_ip_prefix.split(","),
        "max_workers": int(max_concurrent),
        "timeout": int(scan_timeout),
        "ports": [int(p) for p in common_ports.split(",") if p.strip()]
    }

def check_ip_allowed(ip, allowed_ip_list):
    """
    IP白名单校验 - 核心安全限制，仅允许扫描白名单内IP
    :param ip: 待扫描IP
    :param allowed_ip_list: 白名单IP前缀列表
    :return: True(允许) / False(禁止)
    """
    for prefix in allowed_ip_list:
        if ip.startswith(prefix.strip()):
            return True
    return False

def tcp_port_scan(ip, port, timeout):
    """
    单端口TCP存活探测
    :param ip: 目标IP
    :param port: 目标端口
    :param timeout: 超时时间（秒）
    :return: 字典 - 端口状态、Banner
    """
    result = {"ip": ip, "port": port, "status": "closed", "banner": ""}
    try:
        # 创建TCP连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn_result = sock.connect_ex((ip, port))
        if conn_result == 0:
            result["status"] = "open"
            # 尝试读取服务Banner（部分服务会主动返回）
            sock.settimeout(timeout)
            try:
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                result["banner"] = banner
            except:
                result["banner"] = "Unknown"
        sock.close()
    except Exception as e:
        result["error"] = str(e)
    return result

def get_favicon_md5(ip, port, timeout):
    """
    获取目标站点favicon.ico的MD5哈希（指纹识别核心特征）
    :param ip: 目标IP
    :param port: 目标端口
    :param timeout: 超时时间（秒）
    :return: 字符串 - MD5哈希值（空则获取失败）
    """
    try:
        # 确定协议（443端口默认HTTPS，其他为HTTP）
        scheme = "https" if port == 443 else "http"
        favicon_url = f"{scheme}://{ip}:{port}/favicon.ico"
        # 发送请求获取图标
        resp = requests.get(
            url=favicon_url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )
        if resp.status_code == 200 and resp.content:
            # 计算MD5哈希
            md5_obj = hashlib.md5()
            md5_obj.update(resp.content)
            return md5_obj.hexdigest()
        return ""
    except:
        return ""

def http_https_scan(ip, port, timeout):
    """
    HTTP/HTTPS应用层探测 - 采集响应头、状态码、favicon哈希
    :param ip: 目标IP
    :param port: 目标端口
    :param timeout: 超时时间（秒）
    :return: 字典 - 应用层信息（None则探测失败）
    """
    try:
        scheme = "https" if port == 443 else "http"
        target_url = f"{scheme}://{ip}:{port}"
        resp = requests.get(
            url=target_url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )
        # 格式化响应头为字符串
        http_header = "\n".join([f"{k}: {v[0]}" for k, v in resp.headers.items()])
        # 获取favicon哈希
        favicon_md5 = get_favicon_md5(ip, port, timeout)
        return {
            "ip": ip,
            "port": port,
            "protocol": scheme,
            "status_code": resp.status_code,
            "http_header": http_header,
            "favicon_md5": favicon_md5
        }
    except:
        return None

def match_fingerprint(scan_info):
    """
    指纹匹配 - 正则匹配（Banner/响应头）+ favicon MD5匹配
    :param scan_info: 扫描信息字典（含banner、http_header、favicon_md5）
    :return: 列表 - 匹配到的组件名（如["Nginx", "Tomcat"]）
    """
    match_list = []
    if not scan_info:
        return match_list
    # 拼接匹配内容（Banner + HTTP响应头）
    match_content = f"{scan_info.get('banner', '')} {scan_info.get('http_header', '')}".lower()
    favicon_md5 = scan_info.get('favicon_md5', '')
    
    for rule in FINGERPRINT_DB:
        matched = False
        # 1. 正则匹配（忽略大小写）
        for reg in rule["regex"]:
            if re.search(reg, match_content, re.IGNORECASE):
                matched = True
                break
        # 2. Favicon MD5匹配（正则未匹配时触发）
        if not matched and favicon_md5 and favicon_md5 in rule["favicon"]:
            matched = True
        # 匹配成功则加入结果
        if matched:
            match_list.append(rule["name"])
    # 去重并返回
    return list(set(match_list))

def ip_full_scan(ip, scan_config):
    """
    IP全量扫描 - 多线程TCP端口探测 + 开放端口应用层探测 + 指纹识别
    :param ip: 目标IP
    :param scan_config: 扫描配置字典（init_scan_config返回）
    :return: 列表 - 结构化资产数据（含IP、端口、指纹、扫描时间等）
    """
    start_time = time.time()
    open_ports = []
    asset_list = []
    max_workers = scan_config["max_workers"]
    timeout = scan_config["timeout"]
    ports = scan_config["ports"]
    
    # 第一步：多线程TCP端口探测，筛选开放端口
    print(f"[扫描开始] IP: {ip}，探测端口数: {len(ports)}，并发数: {max_workers}")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有端口探测任务
        futures = [executor.submit(tcp_port_scan, ip, port, timeout) for port in ports]
        # 遍历任务结果
        for future in as_completed(futures):
            res = future.result()
            if res["status"] == "open":
                open_ports.append(res)
    
    if not open_ports:
        print(f"[扫描结果] IP: {ip} 无开放端口")
        return asset_list
    print(f"[端口探测完成] IP: {ip}，开放端口数: {len(open_ports)}")
    
    # 第二步：对开放端口做应用层探测+指纹识别
    for port_info in open_ports:
        ip = port_info["ip"]
        port = port_info["port"]
        banner = port_info["banner"]
        # 初始化资产数据
        asset = {
            "ip": ip,
            "port": port,
            "protocol": "tcp",
            "status": "open",
            "banner": banner,
            "http_info": None,
            "fingerprint": [],
            "scan_time": int(time.time()),
            "scan_time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }
        # 对Web常用端口做HTTP/HTTPS探测（80/443/8080/8090/9090）
        if port in [80, 443, 8080, 8090, 9090]:
            http_info = http_https_scan(ip, port, timeout)
            if http_info:
                asset["protocol"] = http_info["protocol"]
                asset["http_info"] = http_info
                # 合并端口信息和HTTP信息做指纹识别
                match_info = {**port_info, **http_info}
                asset["fingerprint"] = match_fingerprint(match_info)
        else:
            # 非Web端口直接用Banner做指纹识别
            asset["fingerprint"] = match_fingerprint(port_info)
        asset_list.append(asset)
    
    scan_cost = round(time.time() - start_time, 2)
    print(f"[扫描完成] IP: {ip}，资产数: {len(asset_list)}，耗时: {scan_cost}s")
    return asset_list
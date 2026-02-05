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
    # Web服务
    {"name": "Nginx", "regex": [r"Server: nginx/(\d+\.\d+\.\d+)", r"Server: nginx"], "favicon": [], "ports": [80, 443, 8000, 8080, 8090, 9090]},
    {"name": "Apache", "regex": [r"Server: Apache/(\d+\.\d+\.\d+)", r"Server: Apache"], "favicon": [], "ports": [80, 443, 8000, 8080, 8090, 9090]},
    {"name": "Tomcat", "regex": [r"Apache-Coyote", r"JSESSIONID", r"Tomcat"], "favicon": ["443b7e4d4a853022c66014e059820433"], "ports": [8000, 8080, 8443]},
    {"name": "WordPress", "regex": [r"WordPress", r"/wp-content/", r"/wp-includes/"], "favicon": [], "ports": [80, 443, 8000, 8080, 8090, 9090]},
    
    # 数据库服务
    {"name": "MySQL", "regex": [r"MySQL Server", r"mysql_native_password", r"MariaDB server"], "favicon": [], "ports": [3306]},
    {"name": "PostgreSQL", "regex": [r"PostgreSQL", r"postgres"], "favicon": [], "ports": [5432]},
    {"name": "MongoDB", "regex": [r"MongoDB", r"mongodb"], "favicon": [], "ports": [27017]},
    {"name": "Redis", "regex": [r"Redis server", r"REDIS"], "favicon": [], "ports": [6379]},
    
    # 远程访问服务
    {"name": "SSH", "regex": [r"SSH-\d+\.\d+", r"OpenSSH"], "favicon": [], "ports": [22]},
    {"name": "RDP", "regex": [r"RDP", r"Remote Desktop"], "favicon": [], "ports": [3389]},
    {"name": "Telnet", "regex": [r"Telnet", r"Escape character is"], "favicon": [], "ports": [23]},
    
    # 其他常见服务
    {"name": "FTP", "regex": [r"220.*FTP", r"FileZilla Server", r"ProFTPD", r"vsftpd"], "favicon": [], "ports": [21]},
    {"name": "SMTP", "regex": [r"220.*ESMTP", r"Postfix", r"Sendmail"], "favicon": [], "ports": [25, 465, 587]},
    {"name": "POP3", "regex": [r"\\+OK.*POP3", r"POP3 server"], "favicon": [], "ports": [110, 995]},
    {"name": "IMAP", "regex": [r"\\* OK.*IMAP", r"IMAP4rev1"], "favicon": [], "ports": [143, 993]},
    {"name": "DNS", "regex": [r"DNS", r"domain service"], "favicon": [], "ports": [53]},
    {"name": "DHCP", "regex": [r"DHCP", r"Dynamic Host Configuration Protocol"], "favicon": [], "ports": [67, 68]},
    {"name": "SNMP", "regex": [r"SNMP", r"Simple Network Management Protocol"], "favicon": [], "ports": [161, 162]},
    {"name": "LDAP", "regex": [r"LDAP", r"Lightweight Directory Access Protocol"], "favicon": [], "ports": [389, 636]},
    {"name": "SMB", "regex": [r"SMB", r"Server Message Block", r"Microsoft Windows Network"], "favicon": [], "ports": [445]},
    {"name": "NFS", "regex": [r"NFS", r"Network File System"], "favicon": [], "ports": [2049]}
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
        print(f"[HTTP探测] 开始探测: {target_url}")
        resp = requests.get(
            url=target_url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )
        print(f"[HTTP探测] 成功: {target_url}, 状态码: {resp.status_code}")
        # 获取响应头字典
        headers_dict = dict(resp.headers)
        # 格式化响应头为字符串（保留原有格式，方便查看）
        http_header_str = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
        # 获取favicon哈希
        favicon_md5 = get_favicon_md5(ip, port, timeout)
        return {
            "ip": ip,
            "port": port,
            "protocol": scheme,
            "status_code": resp.status_code,
            "http_header": http_header_str,
            "headers": headers_dict,
            "favicon_md5": favicon_md5
        }
    except Exception as e:
        print(f"[HTTP探测] 失败: {ip}:{port}, 错误: {str(e)}")
        return None

def match_fingerprint(scan_info):
    """
    指纹匹配 - 正则匹配（Banner/响应头）+ favicon MD5匹配 + 端口号匹配
    :param scan_info: 扫描信息字典（含banner、http_header、favicon_md5、port）
    :return: 列表 - 匹配到的组件名（如["Nginx", "Tomcat"]）
    """
    match_list = []
    if not scan_info:
        return match_list
    # 拼接匹配内容（Banner + HTTP响应头）
    match_content = f"{scan_info.get('banner', '')} {scan_info.get('http_header', '')}".lower()
    favicon_md5 = scan_info.get('favicon_md5', '')
    port = scan_info.get('port', 0)
    
    print(f"[指纹识别] 端口: {port}, Banner: {scan_info.get('banner', '')}")
    
    for rule in FINGERPRINT_DB:
        matched = False
        # 1. 正则匹配（忽略大小写）
        for reg in rule["regex"]:
            try:
                if re.search(reg, match_content, re.IGNORECASE):
                    matched = True
                    print(f"[指纹识别] 正则匹配成功: {rule['name']}")
                    break
            except Exception as e:
                print(f"[指纹识别] 正则错误: {reg}, 错误: {str(e)}")
        # 2. Favicon MD5匹配（正则未匹配时触发）
        if not matched and favicon_md5 and favicon_md5 in rule["favicon"]:
            matched = True
            print(f"[指纹识别] Favicon匹配成功: {rule['name']}")
        # 3. 端口号匹配（正则和Favicon都未匹配时触发）
        if not matched and port and "ports" in rule and port in rule["ports"]:
            matched = True
            print(f"[指纹识别] 端口匹配成功: {rule['name']} (端口: {port})")
        # 匹配成功则加入结果
        if matched:
            match_list.append(rule["name"])
    
    print(f"[指纹识别] 最终匹配结果: {match_list}")
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
    
    # 确定要扫描的端口列表
    port_option = scan_config.get("port_option", "common")
    port_range = scan_config.get("port_range", "1-65535")
    
    if port_option == "common":
        # 常用端口：1-1024
        ports = list(range(1, 1025))
    elif port_option == "custom":
        # 自定义端口范围
        try:
            start_port, end_port = map(int, port_range.split("-"))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                # 范围无效，使用默认端口
                ports = scan_config["ports"]
                print(f"[警告] 端口范围无效: {port_range}，使用默认端口列表")
            else:
                ports = list(range(start_port, end_port + 1))
        except:
            # 解析失败，使用默认端口
            ports = scan_config["ports"]
            print(f"[警告] 端口范围格式错误: {port_range}，使用默认端口列表")
    else:
        # 默认使用配置中的端口列表
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
        # 对可能的Web服务端口做HTTP/HTTPS探测
        # 1. 常见Web端口
        web_ports = [80, 443, 8000, 8080, 8081, 8090, 9000, 9090, 3000, 4000, 5000, 5050, 5173]
        # 2. 检查是否在常见Web端口列表中，且不是自身API端口
        if port in web_ports and not (ip == "127.0.0.1" and port == 8000):
            http_info = http_https_scan(ip, port, timeout)
            if http_info:
                asset["protocol"] = http_info["protocol"]
                asset["http_info"] = http_info
                # 合并端口信息和HTTP信息做指纹识别
                match_info = {**port_info, **http_info}
                asset["fingerprint"] = match_fingerprint(match_info)
        # 3. 对于自身API端口，手动设置HTTP信息
        elif ip == "127.0.0.1" and port == 8000:
            asset["protocol"] = "http"
            headers_dict = {
                "Server": "Uvicorn",
                "Content-Type": "application/json"
            }
            http_header_str = "\n".join([f"{k}: {v}" for k, v in headers_dict.items()])
            asset["http_info"] = {
                "ip": ip,
                "port": port,
                "protocol": "http",
                "status_code": 200,
                "http_header": http_header_str,
                "headers": headers_dict,
                "favicon_md5": ""
            }
            asset["fingerprint"] = ["Uvicorn", "FastAPI"]
        else:
            # 非Web端口直接用Banner做指纹识别
            asset["fingerprint"] = match_fingerprint(port_info)
        asset_list.append(asset)
    
    scan_cost = round(time.time() - start_time, 2)
    print(f"[扫描完成] IP: {ip}，资产数: {len(asset_list)}，耗时: {scan_cost}s")
    return asset_list
# -*- coding: utf-8 -*-
# @Author: Info Lite
# @Desc: 扫描核心模块 - 基于 python-nmap 的端口探测、服务识别、版本检测
import re
import time
import hashlib
import requests
import nmap
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

FINGERPRINT_DB = [
    {"name": "Nginx", "regex": [r"nginx/(\d+\.\d+\.\d+)", r"nginx"], "favicon": [], "ports": [80, 443, 8000, 8080, 8090, 9090]},
    {"name": "Apache", "regex": [r"Apache/(\d+\.\d+\.\d+)", r"Apache"], "favicon": [], "ports": [80, 443, 8000, 8080, 8090, 9090]},
    {"name": "Tomcat", "regex": [r"Apache-Coyote", r"JSESSIONID", r"Tomcat"], "favicon": ["443b7e4d4a853022c66014e059820433"], "ports": [8000, 8080, 8443]},
    {"name": "WordPress", "regex": [r"WordPress", r"/wp-content/", r"/wp-includes/"], "favicon": [], "ports": [80, 443, 8000, 8080, 8090, 9090]},
    {"name": "MySQL", "regex": [r"MySQL", r"mysql"], "favicon": [], "ports": [3306]},
    {"name": "PostgreSQL", "regex": [r"PostgreSQL", r"postgres"], "favicon": [], "ports": [5432]},
    {"name": "MongoDB", "regex": [r"MongoDB", r"mongodb"], "favicon": [], "ports": [27017]},
    {"name": "Redis", "regex": [r"Redis", r"redis"], "favicon": [], "ports": [6379]},
    {"name": "SSH", "regex": [r"SSH-\d+\.\d+", r"OpenSSH"], "favicon": [], "ports": [22]},
    {"name": "RDP", "regex": [r"RDP", r"Remote Desktop", r"ms-wbt-server"], "favicon": [], "ports": [3389]},
    {"name": "Telnet", "regex": [r"Telnet", r"telnet"], "favicon": [], "ports": [23]},
    {"name": "FTP", "regex": [r"FTP", r"FileZilla", r"ProFTPD", r"vsftpd"], "favicon": [], "ports": [21]},
    {"name": "SMTP", "regex": [r"ESMTP", r"Postfix", r"Sendmail", r"smtp"], "favicon": [], "ports": [25, 465, 587]},
    {"name": "POP3", "regex": [r"POP3", r"pop3"], "favicon": [], "ports": [110, 995]},
    {"name": "IMAP", "regex": [r"IMAP", r"imap"], "favicon": [], "ports": [143, 993]},
    {"name": "DNS", "regex": [r"DNS", r"domain"], "favicon": [], "ports": [53]},
    {"name": "SNMP", "regex": [r"SNMP", r"snmp"], "favicon": [], "ports": [161, 162]},
    {"name": "LDAP", "regex": [r"LDAP", r"ldap"], "favicon": [], "ports": [389, 636]},
    {"name": "SMB", "regex": [r"SMB", r"microsoft-ds", r"netbios"], "favicon": [], "ports": [445]},
    {"name": "NFS", "regex": [r"NFS", r"nfs"], "favicon": [], "ports": [2049]}
]


def init_scan_config(enable_whitelist, allowed_ip_prefix, max_concurrent, scan_timeout, common_ports, nmap_path="nmap"):
    return {
        "enable_whitelist": enable_whitelist,
        "allowed_ip": allowed_ip_prefix.split(",") if allowed_ip_prefix else [],
        "max_workers": int(max_concurrent),
        "timeout": int(scan_timeout),
        "ports": [int(p) for p in common_ports.split(",") if p.strip()],
        "nmap_path": nmap_path
    }


def check_ip_allowed(ip, scan_config):
    """
    检查IP是否在白名单中
    :param ip: 要检查的IP地址
    :param scan_config: 扫描配置，包含 enable_whitelist 和 allowed_ip
    :return: True=允许扫描，False=禁止扫描
    """
    # 如果白名单限制被禁用，直接允许
    if not scan_config.get("enable_whitelist", True):
        return True
    
    # 白名单限制启用，检查IP是否在白名单中
    allowed_ip_list = scan_config.get("allowed_ip", [])
    for prefix in allowed_ip_list:
        if ip.startswith(prefix.strip()):
            return True
    return False


def get_favicon_md5(ip, port, timeout):
    try:
        scheme = "https" if port == 443 else "http"
        favicon_url = f"{scheme}://{ip}:{port}/favicon.ico"
        resp = requests.get(
            url=favicon_url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )
        if resp.status_code == 200 and resp.content:
            md5_obj = hashlib.md5()
            md5_obj.update(resp.content)
            return md5_obj.hexdigest()
        return ""
    except:
        return ""


def http_https_scan(ip, port, timeout):
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
        headers_dict = dict(resp.headers)
        http_header_str = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
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
    match_list = []
    if not scan_info:
        return match_list
    match_content = f"{scan_info.get('banner', '')} {scan_info.get('http_header', '')} {scan_info.get('product', '')} {scan_info.get('version', '')}".lower()
    favicon_md5 = scan_info.get('favicon_md5', '')
    port = scan_info.get('port', 0)

    print(f"[指纹识别] 端口: {port}, Banner: {scan_info.get('banner', '')}, 产品: {scan_info.get('product', '')}")

    for rule in FINGERPRINT_DB:
        matched = False
        for reg in rule["regex"]:
            try:
                if re.search(reg, match_content, re.IGNORECASE):
                    matched = True
                    print(f"[指纹识别] 正则匹配成功: {rule['name']}")
                    break
            except Exception as e:
                print(f"[指纹识别] 正则错误: {reg}, 错误: {str(e)}")
        if not matched and favicon_md5 and favicon_md5 in rule["favicon"]:
            matched = True
            print(f"[指纹识别] Favicon匹配成功: {rule['name']}")
        if not matched and port and "ports" in rule and port in rule["ports"]:
            matched = True
            print(f"[指纹识别] 端口匹配成功: {rule['name']} (端口: {port})")
        if matched:
            match_list.append(rule["name"])

    print(f"[指纹识别] 最终匹配结果: {match_list}")
    return list(set(match_list))


def _parse_nmap_result(nm, ip, scan_config):
    asset_list = []
    timeout = scan_config["timeout"]

    if ip not in nm.all_hosts():
        return asset_list

    host = nm[ip]
    tcp_ports = host.get('tcp', {})

    for port, port_info in tcp_ports.items():
        state = port_info.get('state', 'closed')
        if state != 'open':
            continue

        product = port_info.get('product', '')
        version = port_info.get('version', '')
        name = port_info.get('name', '')
        extrainfo = port_info.get('extrainfo', '')

        banner_parts = []
        if product:
            banner_parts.append(product)
        if version:
            banner_parts.append(version)
        if extrainfo:
            banner_parts.append(f"({extrainfo})")
        banner = " ".join(banner_parts) if banner_parts else (name or "Unknown")

        asset = {
            "ip": ip,
            "port": port,
            "protocol": "tcp",
            "status": "open",
            "banner": banner,
            "product": product,
            "version": version,
            "service_name": name,
            "http_info": None,
            "fingerprint": [],
            "scan_time": int(time.time()),
            "scan_time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }

        web_ports = [80, 443, 8000, 8080, 8081, 8090, 9000, 9090, 3000, 4000, 5000, 5050, 5173]
        is_web = name in ['http', 'https', 'http-proxy', 'ssl/http'] or port in web_ports

        if is_web and not (ip == "127.0.0.1" and port == 8000):
            http_info = http_https_scan(ip, port, timeout)
            if http_info:
                asset["protocol"] = http_info["protocol"]
                asset["http_info"] = http_info
                match_info = {**asset, **http_info}
                asset["fingerprint"] = match_fingerprint(match_info)
        elif ip == "127.0.0.1" and port == 8000:
            asset["protocol"] = "http"
            headers_dict = {"Server": "Uvicorn", "Content-Type": "application/json"}
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
            asset["fingerprint"] = match_fingerprint(asset)

        asset_list.append(asset)

    return asset_list


def _split_port_range(port_range_str, chunk_size=1000):
    """
    将端口范围拆分为多个分块
    :param port_range_str: 端口范围字符串，如 "1-65535" 或 "80,443,8080"
    :param chunk_size: 每个分块的大小
    :return: 分块列表，每个元素是端口范围字符串
    """
    chunks = []
    
    if "," in port_range_str:
        port_list = []
        for part in port_range_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-"))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(part))
        port_list = sorted(set(port_list))
        for i in range(0, len(port_list), chunk_size):
            chunk_ports = port_list[i:i + chunk_size]
            chunks.append(",".join(map(str, chunk_ports)))
    elif "-" in port_range_str:
        start, end = map(int, port_range_str.split("-"))
        if end - start + 1 <= chunk_size:
            chunks.append(port_range_str)
        else:
            first_chunk_end = min(start + 1023, end)
            if start <= first_chunk_end:
                chunks.append(f"{start}-{first_chunk_end}")
            current = first_chunk_end + 1
            while current <= end:
                chunk_end = min(current + chunk_size - 1, end)
                chunks.append(f"{current}-{chunk_end}")
                current = chunk_end + 1
    else:
        chunks.append(port_range_str)
    
    return chunks


def _quick_port_discovery(nm, ip, ports_str, scan_config):
    """
    快速端口发现（仅检测端口是否开放，不做版本探测）
    :param nm: nmap PortScanner 对象
    :param ip: 目标IP
    :param ports_str: 端口范围字符串
    :param scan_config: 扫描配置
    :return: 开放端口列表
    """
    open_ports = []
    try:
        quick_args = f"-sT -T4 --host-timeout {scan_config['timeout'] * 30}s --max-retries 2"
        print(f"[Nmap快速发现] 端口: {ports_str}, 参数: {quick_args}")
        nm.scan(hosts=ip, ports=ports_str, arguments=quick_args)
        
        if ip in nm.all_hosts():
            host = nm[ip]
            tcp_ports = host.get('tcp', {})
            for port, port_info in tcp_ports.items():
                if port_info.get('state') == 'open':
                    open_ports.append(port)
        print(f"[Nmap快速发现] 开放端口: {open_ports}")
    except Exception as e:
        print(f"[Nmap快速发现] 异常: {str(e)}")
    
    return open_ports


def ip_full_scan(ip, scan_config):
    start_time = time.time()
    all_assets = []
    all_open_ports = set()

    port_option = scan_config.get("port_option", "common")
    port_range = scan_config.get("port_range", "1-65535")

    if port_option == "common":
        ports_str = ",".join([str(p) for p in scan_config.get("ports", [80, 443, 22, 3389, 8080])])
    elif port_option == "custom":
        ports_str = port_range
    elif port_option == "all":
        ports_str = "1-65535"
    else:
        ports_str = ",".join([str(p) for p in scan_config.get("ports", [80, 443, 22, 3389, 8080])])

    is_full_scan = (port_option == "all") or (port_option == "custom" and "-" in port_range and int(port_range.split("-")[1]) - int(port_range.split("-")[0]) + 1 > 2000)

    print(f"[扫描开始] IP: {ip}，端口: {ports_str}，工具: Nmap，全量扫描: {is_full_scan}")

    try:
        nm = nmap.PortScanner(nmap_search_path=(scan_config.get("nmap_path", "nmap"),))

        if is_full_scan:
            chunks = _split_port_range(ports_str, chunk_size=5000)
            print(f"[分块扫描] 共 {len(chunks)} 个分块: {chunks}")

            for idx, chunk in enumerate(chunks, 1):
                chunk_start = time.time()
                print(f"[分块扫描] 第 {idx}/{len(chunks)} 块: {chunk}")

                chunk_open_ports = _quick_port_discovery(nm, ip, chunk, scan_config)
                all_open_ports.update(chunk_open_ports)

                chunk_cost = round(time.time() - chunk_start, 2)
                print(f"[分块扫描] 第 {idx} 块完成，发现 {len(chunk_open_ports)} 个开放端口，耗时 {chunk_cost}s")

            print(f"[分块扫描] 全部完成，累计开放端口: {sorted(all_open_ports)}")

            if all_open_ports:
                version_ports_str = ",".join(map(str, sorted(all_open_ports)))
                version_args = f"-sV -T4 --host-timeout {scan_config['timeout'] * 120}s"
                print(f"[版本探测] 对 {len(all_open_ports)} 个开放端口进行版本识别，参数: {version_args}")
                nm.scan(hosts=ip, ports=version_ports_str, arguments=version_args)
                all_assets = _parse_nmap_result(nm, ip, scan_config)
        else:
            scan_args = f"-sV -T4 --host-timeout {scan_config['timeout'] * 60}s"
            print(f"[Nmap] 执行扫描，参数: {scan_args}")
            nm.scan(hosts=ip, ports=ports_str, arguments=scan_args)
            all_assets = _parse_nmap_result(nm, ip, scan_config)

    except nmap.PortScannerError as e:
        print(f"[Nmap错误] PortScannerError: {str(e)}")
        print("[Nmap] 提示: 请确保已安装 Nmap 并正确配置路径")
    except Exception as e:
        print(f"[扫描异常] {str(e)}")

    scan_cost = round(time.time() - start_time, 2)
    print(f"[扫描完成] IP: {ip}，资产数: {len(all_assets)}，耗时: {scan_cost}s")
    return all_assets


def custom_nmap_scan(ip, scan_config, custom_args="", ports=""):
    """
    自定义 Nmap 扫描 - 用户手动指定参数
    :param ip: 目标IP
    :param scan_config: 扫描配置
    :param custom_args: 自定义 nmap 参数
    :param ports: 端口范围（可选，为空则使用默认）
    :return: 资产列表
    """
    start_time = time.time()
    all_assets = []

    print(f"[自定义扫描] IP: {ip}，参数: {custom_args}，端口: {ports}")

    try:
        nm = nmap.PortScanner(nmap_search_path=(scan_config.get("nmap_path", "nmap"),))

        if ports:
            nm.scan(hosts=ip, ports=ports, arguments=custom_args)
        else:
            nm.scan(hosts=ip, arguments=custom_args)

        all_assets = _parse_nmap_result(nm, ip, scan_config)

    except nmap.PortScannerError as e:
        print(f"[Nmap错误] PortScannerError: {str(e)}")
        raise Exception(f"Nmap扫描失败: {str(e)}")
    except Exception as e:
        print(f"[扫描异常] {str(e)}")
        raise Exception(f"扫描异常: {str(e)}")

    scan_cost = round(time.time() - start_time, 2)
    print(f"[自定义扫描完成] IP: {ip}，资产数: {len(all_assets)}，耗时: {scan_cost}s")
    return all_assets

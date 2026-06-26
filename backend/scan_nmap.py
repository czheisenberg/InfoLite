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


def init_scan_config(allowed_ip_prefix, max_concurrent, scan_timeout, common_ports, nmap_path="nmap"):
    return {
        "allowed_ip": allowed_ip_prefix.split(","),
        "max_workers": int(max_concurrent),
        "timeout": int(scan_timeout),
        "ports": [int(p) for p in common_ports.split(",") if p.strip()],
        "nmap_path": nmap_path
    }


def check_ip_allowed(ip, allowed_ip_list):
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


def ip_full_scan(ip, scan_config):
    start_time = time.time()
    asset_list = []

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

    print(f"[扫描开始] IP: {ip}，端口: {ports_str}，工具: Nmap")

    try:
        nm = nmap.PortScanner(nmap_search_path=(scan_config.get("nmap_path", "nmap"),))

        scan_args = f"-sV -T4 --host-timeout {scan_config['timeout'] * 60}s"
        print(f"[Nmap] 执行扫描，参数: {scan_args}")

        nm.scan(hosts=ip, ports=ports_str, arguments=scan_args)

        asset_list = _parse_nmap_result(nm, ip, scan_config)

    except nmap.PortScannerError as e:
        print(f"[Nmap错误] PortScannerError: {str(e)}")
        print("[Nmap] 提示: 请确保已安装 Nmap 并正确配置路径")
    except Exception as e:
        print(f"[扫描异常] {str(e)}")

    scan_cost = round(time.time() - start_time, 2)
    print(f"[扫描完成] IP: {ip}，资产数: {len(asset_list)}，耗时: {scan_cost}s")
    return asset_list

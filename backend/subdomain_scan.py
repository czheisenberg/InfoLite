# -*- coding: utf-8 -*-
# @Desc: 子域名扫描模块 - crt.sh查询 + 字典爆破
import time
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "pop3",
    "imap", "admin", "api", "test", "dev", "staging", "prod", "blog",
    "shop", "store", "app", "mobile", "m", "cdn", "static", "img",
    "images", "css", "js", "assets", "media", "video", "audio",
    "portal", "dashboard", "panel", "console", "manage", "manager",
    "backend", "frontend", "api2", "api3", "gw", "gateway",
    "auth", "login", "sso", "oauth", "register", "signup",
    "db", "database", "mysql", "redis", "mongo", "es", "elastic",
    "cache", "memcached", "queue", "mq", "kafka", "rabbitmq",
    "monitor", "monitoring", "metrics", "grafana", "prometheus",
    "logs", "log", "elk", "kibana",
    "backup", "bak", "storage", "s3", "bucket", "oss",
    "wiki", "docs", "documentation", "help", "support",
    "status", "health", "ping",
    "git", "gitlab", "github", "jenkins", "ci", "cd",
    "svn", "trac", "redmine", "jira",
    "vpn", "proxy", "bastion", "jump",
    "mail2", "web", "www2", "www3",
    "old", "new", "test2", "dev2",
    "demo", "sandbox", "lab",
    "intranet", "internal", "office",
    "pay", "payment", "billing",
    "search", "find", "go",
    "chat", "message", "im",
    "file", "files", "download",
    "video", "live", "stream",
    "forum", "bbs", "community",
    "news", "press", "release",
    "about", "contact", "info",
    "job", "jobs", "career",
    "hr", "staff", "employee",
    "crm", "erp", "oa",
    "finance", "financial", "account",
    "report", "analytics", "stats",
    "map", "maps", "geo",
    "cdn1", "cdn2", "cdn3",
    "img1", "img2", "img3",
    "static1", "static2",
    "api-qa", "api-dev", "api-prod",
    "qa", "uat", "sit", "pet",
    "pre", "preprod", "stage",
    "beta", "alpha", "rc",
    "vip", "waf", "fw",
    "dns", "ns1", "ns2", "ns3",
    "whois", "nic",
    "cert", "ssl", "acme",
    "webhook", "hooks", "events",
    "data", "datalake", "warehouse",
    "bi", "reporting",
    "shop", "mall", "trade",
    "game", "gamer", "gaming",
    "edu", "school", "campus",
    "gov", "org", "com",
    "net", "cn", "com.cn",
    "test", "testing", "tester",
    "debug", "trace", "logstash","cats"
]


def scan_crtsh(domain):
    """
    从 crt.sh 查询子域名
    :param domain: 目标域名
    :return: 子域名列表
    """
    subdomains = set()
    if not requests:
        print("[crt.sh] 未安装 requests 库，跳过")
        return list(subdomains)

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    print(f"[crt.sh] 查询: {url}")

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        resp = requests.get(url, headers=headers, timeout=30)
        
        if resp.status_code == 200:
            try:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if line and line.endswith(domain) and "*" not in line:
                            subdomains.add(line)
            except Exception as e:
                print(f"[crt.sh] JSON解析失败: {str(e)}")
                pattern = r'[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.' + re.escape(domain)
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                for m in matches:
                    m = m.lower().strip()
                    if m.endswith(domain) and "*" not in m:
                        subdomains.add(m)
        else:
            print(f"[crt.sh] HTTP状态码: {resp.status_code}")
    except Exception as e:
        print(f"[crt.sh] 查询异常: {str(e)}")

    result = sorted(subdomains)
    print(f"[crt.sh] 发现 {len(result)} 个子域名")
    return result


def scan_chaziyu(domain):
    """
    从 chaziyu.com 查询子域名
    :param domain: 目标域名
    :return: 子域名列表
    """
    subdomains = set()
    if not requests:
        print("[chaziyu] 未安装 requests 库，跳过")
        return list(subdomains)

    url = f"https://chaziyu.com/{domain}"
    print(f"[chaziyu] 查询: {url}")

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Referer": "https://chaziyu.com/"
        }
        resp = requests.get(url, headers=headers, timeout=30)
        
        if resp.status_code == 200:
            if "禁止查询该域名" in resp.text:
                print(f"[chaziyu] 该域名被禁止查询")
                return list(subdomains)

            pattern = r'href="[^"]*\.(' + re.escape(domain) + r')"[^>]*>([^<]+)\.' + re.escape(domain) + r'<\/a>'
            matches = re.findall(pattern, resp.text, re.IGNORECASE)
            for match in matches:
                full_domain = match[1].lower() + "." + domain.lower()
                if "*" not in full_domain and full_domain.endswith(domain.lower()):
                    subdomains.add(full_domain)

            alt_pattern = r'([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.' + re.escape(domain) + r')'
            alt_matches = re.findall(alt_pattern, resp.text, re.IGNORECASE)
            for m in alt_matches:
                m = m.lower().strip()
                if m.endswith(domain.lower()) and "*" not in m and m != domain.lower():
                    subdomains.add(m)
        else:
            print(f"[chaziyu] HTTP状态码: {resp.status_code}")
    except Exception as e:
        print(f"[chaziyu] 查询异常: {str(e)}")

    result = sorted(subdomains)
    print(f"[chaziyu] 发现 {len(result)} 个子域名")
    return result


def resolve_subdomain(subdomain):
    """
    解析子域名是否存在（DNS解析）
    :param subdomain: 子域名
    :return: (子域名, IP列表) 或 None
    """
    try:
        ips = socket.gethostbyname_ex(subdomain)[2]
        if ips:
            return (subdomain, ips)
    except socket.gaierror:
        pass
    except Exception:
        pass
    return None


def scan_dict(domain, subdomain_list=None, max_workers=50):
    """
    字典爆破子域名
    :param domain: 目标域名
    :param subdomain_list: 子域名字典列表，None则使用内置字典
    :param max_workers: 最大并发数
    :return: 存活子域名列表 [(subdomain, [ips]), ...]
    """
    if subdomain_list is None:
        subdomain_list = COMMON_SUBDOMAINS

    results = []
    total = len(subdomain_list)
    print(f"[字典爆破] 目标: {domain}, 字典数量: {total}, 并发: {max_workers}")

    start_time = time.time()
    count = 0
    found = 0
    lock = threading.Lock()

    def progress_callback():
        nonlocal count, found
        with lock:
            count += 1

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {}
        for sub in subdomain_list:
            full_domain = f"{sub}.{domain}"
            future = executor.submit(resolve_subdomain, full_domain)
            future_map[future] = full_domain

        for future in as_completed(future_map):
            progress_callback()
            result = future.result()
            if result:
                results.append(result)
                found += 1
                print(f"[字典爆破] 发现: {result[0]} -> {', '.join(result[1])}")

    cost = round(time.time() - start_time, 2)
    print(f"[字典爆破] 完成，共发现 {found} 个存活子域名，耗时 {cost}s")
    return results


def merge_results(sources, dict_results=None):
    """
    合并多种扫描结果
    :param sources: 字典，key为来源名，value为子域名列表
    :param dict_results: 字典爆破结果 [(subdomain, [ips]), ...]
    :return: 合并后的结果列表
    """
    domain_map = {}

    for source_name, domain_list in sources.items():
        for sub in domain_list:
            key = sub.lower()
            if key not in domain_map:
                domain_map[key] = {
                    "domain": key,
                    "ips": [],
                    "source": source_name,
                    "status": "unknown"
                }
            else:
                if source_name not in domain_map[key]["source"]:
                    domain_map[key]["source"] += "," + source_name

    if dict_results:
        for sub, ips in dict_results:
            key = sub.lower()
            if key in domain_map:
                domain_map[key]["ips"] = ips
                if "dict" not in domain_map[key]["source"]:
                    domain_map[key]["source"] += ",dict"
                domain_map[key]["status"] = "alive"
            else:
                domain_map[key] = {
                    "domain": key,
                    "ips": ips,
                    "source": "dict",
                    "status": "alive"
                }

    for key in domain_map:
        if not domain_map[key]["ips"]:
            try:
                ips = socket.gethostbyname_ex(key)[2]
                domain_map[key]["ips"] = ips
                domain_map[key]["status"] = "alive"
            except Exception:
                domain_map[key]["status"] = "unknown"

    result_list = sorted(domain_map.values(), key=lambda x: x["domain"])
    return result_list


def subdomain_scan(domain, scan_type="all", max_workers=50, custom_dict=None):
    """
    子域名扫描主函数
    :param domain: 目标域名
    :param scan_type: 扫描类型：crtsh、chaziyu、dict、all，支持逗号分隔多选项
    :param max_workers: 字典爆破最大并发数
    :param custom_dict: 自定义子域名字典列表
    :return: 扫描结果列表
    """
    start_time = time.time()
    print(f"[子域名扫描] 开始，目标: {domain}, 类型: {scan_type}")

    domain = domain.strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]

    sources = {}
    dict_results = []

    use_crtsh = False
    use_chaziyu = False
    use_dict = False

    if scan_type == "all":
        use_crtsh = True
        use_chaziyu = True
        use_dict = True
    else:
        types = [t.strip() for t in scan_type.split(",")]
        use_crtsh = "crtsh" in types
        use_chaziyu = "chaziyu" in types
        use_dict = "dict" in types

    if use_crtsh:
        crtsh_results = scan_crtsh(domain)
        if crtsh_results:
            sources["crtsh"] = crtsh_results

    if use_chaziyu:
        chaziyu_results = scan_chaziyu(domain)
        if chaziyu_results:
            sources["chaziyu"] = chaziyu_results

    if use_dict:
        dict_results = scan_dict(domain, custom_dict, max_workers)

    if sources and dict_results:
        final_results = merge_results(sources, dict_results)
    elif sources:
        final_results = merge_results(sources, None)
    elif dict_results:
        final_results = []
        for sub, ips in dict_results:
            final_results.append({
                "domain": sub,
                "ips": ips,
                "source": "dict",
                "status": "alive"
            })
    else:
        final_results = []

    cost = round(time.time() - start_time, 2)
    alive_count = sum(1 for r in final_results if r["status"] == "alive")
    print(f"[子域名扫描] 完成，共发现 {len(final_results)} 个子域名，其中存活 {alive_count} 个，耗时 {cost}s")

    return {
        "target": domain,
        "scan_type": scan_type,
        "total": len(final_results),
        "alive_count": alive_count,
        "cost_time": cost,
        "results": final_results
    }

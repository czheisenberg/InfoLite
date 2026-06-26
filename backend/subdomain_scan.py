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
    # ===== 通用基础 =====
    "www", "www1", "www2", "www3", "www4", "www5", "www6", "www7", "www8", "www9",
    "web", "web1", "web2", "web3", "web4", "web5",
    "m", "mobile", "wap", "h5", "app", "apps",
    "main", "home", "index", "default", "root",
    "test", "test1", "test2", "test3", "testing", "tester", "t",
    "dev", "dev1", "dev2", "dev3", "develop", "development",
    "prod", "pro", "production", "online", "release",
    "staging", "stage", "stg", "pre", "preprod", "preview",
    "qa", "uat", "sit", "pet", "sandbox", "demo", "lab",
    "alpha", "beta", "rc", "stable", "nightly","cats",

    # ===== 管理后台 =====
    "admin", "adm", "admin1", "admin2", "admin3",
    "administrator", "manage", "manager", "management",
    "backend", "back", "boss", "control", "console",
    "panel", "dashboard", "portal", "platform",
    "super", "root", "sys", "system", "sysadmin",
    "cp", "cpanel", "ispconfig", "plesk", "directadmin",
    "drupal", "wordpress", "wp", "wp-admin", "wp-login",
    "joomla", "magento", "shopify", "opencart",

    # ===== 接口/网关 =====
    "api", "api1", "api2", "api3", "api4", "api5",
    "api-dev", "api-test", "api-prod", "api-staging", "api-uat",
    "gw", "gateway", "gate", "edge", "edge-api",
    "openapi", "open", "public", "private", "internal",
    "rest", "restapi", "graphql", "gql", "grpc",
    "rpc", "jsonrpc", "xmlrpc", "soap", "ws",
    "websocket", "socket", "push", "pull",

    # ===== 认证/用户 =====
    "auth", "login", "signin", "signup", "register",
    "sso", "oauth", "oauth2", "openid", "cas",
    "passport", "account", "user", "users", "member",
    "uc", "ucenter", "id", "identity", "profile",
    "permission", "role", "rbac", "acl",

    # ===== 数据库/存储 =====
    "db", "database", "db1", "db2", "db3",
    "mysql", "mysql1", "mysql2", "mysql-master", "mysql-slave",
    "mariadb", "percona", "postgresql", "pgsql", "pg",
    "mongo", "mongodb", "mongo1", "mongo2", "mongo3",
    "redis", "redis1", "redis2", "redis-sentinel",
    "memcached", "mc", "cache", "cache1", "cache2",
    "es", "elastic", "elasticsearch", "kibana", "logstash",
    "influxdb", "clickhouse", "cassandra", "hbase",
    "oracle", "mssql", "sqlserver", "sqlite",
    "neo4j", "graphdb", "tdengine", "tidb",
    "oss", "s3", "storage", "store", "bucket",
    "minio", "ceph", "nfs", "ftp", "sftp",
    "nas", "san", "backup", "bak", "archive",

    # ===== 消息队列 =====
    "mq", "queue", "mq1", "mq2",
    "kafka", "kafka1", "kafka2", "kafka3",
    "rabbitmq", "rabbit", "rmq", "activemq", "artemis",
    "rocketmq", "rocket", "pulsar", "nsq", "zeromq",

    # ===== 监控/日志 =====
    "monitor", "monitoring", "mon", "zabbix",
    "nagios", "prometheus", "prom", "grafana",
    "alertmanager", "alert", "metrics", "stats",
    "monitor", "health", "healthcheck", "ping",
    "status", "uptime", "watchdog", "sentry",
    "log", "logs", "logserver", "elk", "efk",
    "loki", "tempo", "jaeger", "zipkin",
    "apm", "skywalking", "pinpoint", "cat",

    # ===== CI/CD/版本控制 =====
    "git", "gitlab", "github", "gitea", "gogs",
    "jenkins", "ci", "cd", "cicd", "pipeline",
    "svn", "trac", "redmine", "jira", "confluence",
    "harbor", "registry", "docker", "dockerhub",
    "nexus", "maven", "npm", "pypi", "gem",
    "artifactory", "chartmuseum", "helm",

    # ===== 中间件/服务 =====
    "nginx", "apache", "tomcat", "jboss", "weblogic",
    "websphere", "iis", "caddy", "traefik", "haproxy",
    "lvs", "keepalived", "haproxy", "varnish", "squid",
    "waf", "firewall", "fw", "ids", "ips",
    "vpn", "openvpn", "wireguard", "pptp", "l2tp",
    "proxy", "proxy1", "proxy2", "forward", "reverse",
    "bastion", "jump", "jumper", "ops", "operation",
    "ansible", "salt", "puppet", "chef", "k8s",
    "kubernetes", "k8s-master", "k8s-node", "rancher",
    "consul", "etcd", "eureka", "nacos", "apollo",
    "zookeeper", "zk", "dubbo", "springcloud",
    "servicecomb", "istio", "linkerd",

    # ===== 文件/媒体 =====
    "file", "files", "download", "upload", "share",
    "static", "static1", "static2", "static3",
    "img", "img1", "img2", "img3", "img4", "img5",
    "image", "images", "pic", "pics", "photo", "photos",
    "media", "video", "audio", "music", "movie",
    "vod", "live", "stream", "streaming", "hls",
    "rtmp", "webrtc", "rtc",
    "css", "js", "assets", "resource", "resources",
    "font", "fonts", "icon", "icons",
    "cdn", "cdn1", "cdn2", "cdn3", "cdn4", "cdn5",
    "oss", "cos", "bos", "obs", "kodo",

    # ===== 邮件服务 =====
    "mail", "mail1", "mail2", "mail3",
    "smtp", "smtp1", "smtp2", "pop", "pop3",
    "imap", "webmail", "exchange", "outlook",
    "postfix", "dovecot", "spam", "antispam",
    "mx", "mx1", "mx2", "mx3", "mailgate",

    # ===== DNS/域名 =====
    "dns", "dns1", "dns2", "dns3",
    "ns", "ns1", "ns2", "ns3", "ns4", "ns5",
    "whois", "nic", "domain", "ddns",
    "dyn", "dynamic",

    # ===== 安全/证书 =====
    "ssl", "cert", "ca", "acme", "letsencrypt",
    "vault", "secrets", "security", "sec",
    "waf", "ids", "ips", "honeypot",

    # ===== 办公/协同 =====
    "oa", "office", "work", "workflow",
    "crm", "erp", "hr", "hrm", "payroll",
    "finance", "financial", "account", "accounting", "caiwu",
    "sales", "marketing", "customer", "clients",
    "project", "projects", "pm", "task", "tasks",
    "meeting", "conference", "room", "calendar",
    "doc", "docs", "document", "documentation",
    "wiki", "knowledge", "kb", "faq", "help", "support",
    "chat", "im", "message", "messages",
    "talk", "teambition", "dingtalk", "wework",
    "feishu", "lark", "slack", "discord",
    "mail", "email", "webmail",

    # ===== 电商/交易 =====
    "shop", "store", "mall", "trade", "trading",
    "cart", "order", "orders", "pay", "payment",
    "pay1", "pay2", "billing", "cashier", "checkout",
    "product", "products", "goods", "item", "items",
    "search", "find", "s", "so", "so1", "so2",
    "user", "users", "member", "members", "vip",
    "coupon", "promotion", "promo", "activity",
    "seckill", "flashsale", "group", "groupon",
    "comment", "review", "rate", "rating",
    "refund", "return", "aftersale",

    # ===== 内容/社区 =====
    "blog", "news", "press", "release", "article",
    "bbs", "forum", "forums", "community",
    "post", "posts", "thread", "threads",
    "topic", "topics", "board", "boards",
    "ask", "question", "qa", "qna", "answer",
    "wiki", "doc", "docs", "tutorial",
    "book", "books", "read", "reader",
    "video", "videos", "movie", "movies", "film",
    "music", "song", "songs", "radio",
    "game", "games", "gamer", "gaming", "play",
    "live", "zhibo", "anchor", "host",

    # ===== 招聘/企业 =====
    "job", "jobs", "career", "careers", "zhaopin",
    "hr", "join", "joinus", "about", "aboutus",
    "company", "corp", "team", "news", "contact",
    "info", "service", "services", "business",
    "partner", "partners", "channel", "agent",
    "edu", "education", "school", "campus",
    "gov", "government", "org", "organization",

    # ===== 地图/位置 =====
    "map", "maps", "geo", "geography",
    "location", "position", "gps", "lbs",
    "navi", "navigation", "route", "path",

    # ===== 数据/分析 =====
    "data", "datas", "bigdata", "hadoop",
    "hive", "spark", "flink", "storm",
    "datalake", "warehouse", "dw", "datawarehouse",
    "bi", "report", "reports", "reporting",
    "analytics", "analysis", "stats", "statistics",
    "ai", "ml", "model", "models", "algorithm",
    "recommend", "rec", "suggest", "prediction",
    "crawler", "spider", "crawl", "scrape",

    # ===== 测试/调试 =====
    "debug", "test", "testing", "tester",
    "unittest", "e2e", "integration", "perf",
    "stress", "load", "benchmark", "quality",
    "qa", "qat", "qat1", "qat2",
    "trace", "debugger", "profile", "profiler",

    # ===== 其他常见 =====
    "old", "new", "next", "v1", "v2", "v3",
    "v4", "v5", "v6", "v7", "v8", "v9", "v10",
    "zh", "zh-cn", "en", "en-us", "jp", "kr",
    "china", "global", "international", "intl",
    "north", "south", "east", "west",
    "beijing", "shanghai", "guangzhou", "shenzhen",
    "hangzhou", "chengdu", "wuhan", "xian",
    "aws", "aliyun", "alicloud", "tencentcloud",
    "huaweicloud", "azure", "gcp",
    "beian", "icp", "legal", "privacy", "terms",
    "sitemap", "rss", "feed", "atom",
    "robots", "favicon", "crossdomain",
    "well-known", "apple-touch-icon",

    # ===== 数字后缀 =====
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
    "a", "b", "c", "d", "e", "f", "g",
    "node1", "node2", "node3", "node4", "node5",
    "srv1", "srv2", "srv3", "srv4", "srv5",
    "svr1", "svr2", "svr3", "svr4", "svr5",
    "host1", "host2", "host3", "host4", "host5",
    "server1", "server2", "server3",
    "master", "master1", "master2", "slave", "slave1", "slave2",
    "primary", "secondary", "replica", "standby",

    # ===== 行业特定 =====
    "erp", "mes", "wms", "scm", "plm",
    "pos", "pda", "rfid",
    "his", "lis", "pacs", "ris",
    "cms", "wcm", "dms", "ecm",
    "eip", "km", "pmo",
    "iot", "device", "sensor", "gateway-mqtt",
    "chain", "blockchain", "bcs",
    "ar", "vr", "mr", "meta", "metaverse",
    "nft", "defi", "dao",

    # ===== 中文拼音常见 =====
    "xinwen", "news", "zixun", "info",
    "chanpin", "product", "fuwu", "service",
    "guanyu", "about", "lianxi", "contact",
    "zhaopin", "job", "jiameng", "join",
    "shangcheng", "shop", "gouwu", "mall",
    "tupian", "img", "shipin", "video",
    "shenghuo", "life", "youxi", "game",
    "shequ", "community", "luntan", "forum",
    "wangye", "web", "yidong", "mobile",
    "kehuduan", "app", "guanli", "admin",
    "xitong", "system", "shujuku", "db",
    "jiekou", "api", "wangguan", "gateway",
    "jiance", "monitor", "rizhi", "log",
    "cunchu", "storage", "beifen", "backup",
    "anquan", "security", "yanzheng", "auth",
    "yonghu", "user", "denglu", "login",
    "zhuce", "register", "zhifu", "pay",
    "dingdan", "order", "shangpin", "goods",
    "sousuo", "search", "fenxi", "analysis",
    "baogao", "report", "shuju", "data",
    "ceshi", "test", "kaifa", "dev",
    "shengchan", "prod", "yufa", "staging",
    "yunxing", "ops", "weihu", "maintenance",
]

_seen = set()
COMMON_SUBDOMAINS = [x for x in COMMON_SUBDOMAINS if not (x in _seen or _seen.add(x))]
del _seen


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
        unique_dict = {}
        for sub, ips in dict_results:
            key = sub.lower()
            if key in unique_dict:
                existing_ips = set(unique_dict[key]["ips"])
                new_ips = set(ips)
                unique_dict[key]["ips"] = list(existing_ips | new_ips)
            else:
                unique_dict[key] = {
                    "domain": key,
                    "ips": ips,
                    "source": "dict",
                    "status": "alive"
                }
        final_results = sorted(unique_dict.values(), key=lambda x: x["domain"])
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

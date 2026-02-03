# -*- coding: utf-8 -*-
# @Author: Info Lite
# @Desc: 数据库操作模块 - MySQL+Elasticsearch 增删改查、表/索引初始化
import pymysql
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

def init_mysql_conn(mysql_host, mysql_port, mysql_user, mysql_pwd, mysql_db):
    """
    初始化MySQL连接
    :param mysql_host: 主机地址
    :param mysql_port: 端口
    :param mysql_user: 用户名
    :param mysql_pwd: 密码
    :param mysql_db: 数据库名
    :return: MySQL连接对象/游标对象
    """
    try:
        conn = pymysql.connect(
            host=mysql_host,
            port=int(mysql_port),
            user=mysql_user,
            password=mysql_pwd,
            database=mysql_db,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor  # 游标返回字典格式
        )
        cursor = conn.cursor()
        return conn, cursor
    except Exception as e:
        raise Exception(f"MySQL连接失败: {str(e)}")

def init_es_conn(es_host, es_port):
    """
    初始化Elasticsearch连接（8.x版本，开发环境关闭认证）
    :param es_host: 主机地址
    :param es_port: 端口
    :return: ES连接对象
    """
    try:
        es = Elasticsearch(
            hosts=[f"http://{es_host}:{es_port}"],
            verify_certs=False,  # 关闭证书验证
            ssl_show_warn=False  # 关闭SSL警告
        )
        if es.ping():
            return es
        else:
            raise Exception("ES连接失败：ping不通")
    except Exception as e:
        raise Exception(f"ES连接失败: {str(e)}")

def create_mysql_asset_table(conn, cursor):
    """
    创建MySQL资产表 - 若表不存在则创建，存在则不操作
    :param conn: MySQL连接对象
    :param cursor: MySQL游标对象
    :return: None
    """
    create_sql = """
    CREATE TABLE IF NOT EXISTS asset (
        id INT AUTO_INCREMENT PRIMARY KEY COMMENT '主键ID',
        ip VARCHAR(16) NOT NULL COMMENT '目标IP',
        port INT NOT NULL COMMENT '开放端口',
        protocol VARCHAR(10) DEFAULT 'tcp' COMMENT '协议（tcp/http/https）',
        status VARCHAR(10) DEFAULT 'open' COMMENT '端口状态',
        banner TEXT COMMENT '服务Banner',
        fingerprint VARCHAR(255) COMMENT '组件指纹（逗号分隔）',
        scan_time INT NOT NULL COMMENT '扫描时间戳',
        scan_time_str VARCHAR(20) NOT NULL COMMENT '扫描时间字符串',
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '入库时间',
        UNIQUE KEY uk_ip_port (ip, port)  # 唯一键：IP+端口，避免重复数据
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='网络资产表';
    """
    try:
        cursor.execute(create_sql)
        conn.commit()
        print("MySQL资产表初始化成功（存在则跳过）")
    except Exception as e:
        conn.rollback()
        raise Exception(f"创建MySQL表失败: {str(e)}")

def create_es_asset_index(es, index_name="cyberscan_asset"):
    """
    创建ES资产索引 - 若索引不存在则创建，存在则不操作
    :param es: ES连接对象
    :param index_name: 索引名
    :return: None
    """
    # ES索引映射（keyword用于精准查询，text用于模糊查询，提升检索效率）
    index_mapping = {
        "mappings": {
            "properties": {
                "ip": {"type": "keyword"},          # IP精准查询
                "port": {"type": "integer"},        # 端口
                "protocol": {"type": "keyword"},    # 协议精准查询
                "status": {"type": "keyword"},      # 状态
                "banner": {"type": "text"},         # Banner模糊查询
                "fingerprint": {"type": "keyword"}, # 指纹精准查询
                "scan_time": {"type": "integer"},   # 扫描时间戳
                "scan_time_str": {"type": "keyword"}# 扫描时间字符串
            }
        },
        "settings": {
            "number_of_shards": 1,    # 单节点开发环境，1个分片足够
            "number_of_replicas": 0   # 无副本，节省资源
        }
    }
    try:
        if not es.indices.exists(index=index_name):
            es.indices.create(index=index_name, body=index_mapping)
            print(f"ES索引 {index_name} 初始化成功")
        else:
            print(f"ES索引 {index_name} 已存在，跳过初始化")
    except Exception as e:
        raise Exception(f"创建ES索引失败: {str(e)}")

def insert_asset_to_mysql(conn, cursor, asset_list):
    """
    批量插入资产数据到MySQL - 先删旧数据（IP+端口），再插新数据，避免重复
    :param conn: MySQL连接对象
    :param cursor: MySQL游标对象
    :param asset_list: 资产数据列表（ip_full_scan返回）
    :return: 插入成功的条数
    """
    if not asset_list:
        return 0
    # 第一步：批量删除该IP的旧数据
    ip_list = list(set([asset["ip"] for asset in asset_list]))
    delete_sql = f"DELETE FROM asset WHERE ip IN ({','.join(['%s']*len(ip_list))})"
    cursor.execute(delete_sql, ip_list)
    
    # 第二步：批量插入新数据
    insert_sql = """
    INSERT INTO asset (ip, port, protocol, status, banner, fingerprint, scan_time, scan_time_str)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    # 格式化数据（指纹列表转逗号分隔字符串）
    data_list = [
        (
            asset["ip"],
            asset["port"],
            asset["protocol"],
            asset["status"],
            asset["banner"][:255],  # 限制Banner长度，避免超出字段限制
            ",".join(asset["fingerprint"]),
            asset["scan_time"],
            asset["scan_time_str"]
        ) for asset in asset_list
    ]
    try:
        cursor.executemany(insert_sql, data_list)
        conn.commit()
        insert_count = cursor.rowcount
        print(f"MySQL插入成功: {insert_count} 条数据")
        return insert_count
    except Exception as e:
        conn.rollback()
        raise Exception(f"MySQL插入数据失败: {str(e)}")

def insert_asset_to_es(es, asset_list, index_name="cyberscan_asset"):
    """
    批量插入资产数据到ES - 覆盖旧数据（基于IP+端口）
    :param es: ES连接对象
    :param asset_list: 资产数据列表
    :param index_name: ES索引名
    :return: 插入成功的条数
    """
    if not asset_list:
        return 0
    # 构造ES批量插入数据（_id为ip-port，避免重复）
    bulk_data = []
    for asset in asset_list:
        doc = {
            "ip": asset["ip"],
            "port": asset["port"],
            "protocol": asset["protocol"],
            "status": asset["status"],
            "banner": asset["banner"],
            "fingerprint": asset["fingerprint"],
            "scan_time": asset["scan_time"],
            "scan_time_str": asset["scan_time_str"]
        }
        bulk_data.append({
            "_index": index_name,
            "_id": f"{asset['ip']}-{asset['port']}",  # 唯一ID：IP-端口
            "_source": doc
        })
    # 批量写入
    try:
        success, failed = bulk(es, bulk_data)
        print(f"ES插入成功: {success} 条，失败: {failed} 条")
        return success
    except Exception as e:
        raise Exception(f"ES插入数据失败: {str(e)}")

def query_asset_from_db(ip, mysql_conn, mysql_cursor, es, scan_expire_time, index_name="cyberscan_asset"):
    """
    从数据库查询资产数据 - 优先查ES（检索效率高），并校验扫描有效期
    :param ip: 目标IP
    :param mysql_conn: MySQL连接
    :param mysql_cursor: MySQL游标
    :param es: ES连接
    :param scan_expire_time: 扫描有效期（秒）
    :param index_name: ES索引名
    :return: 字典 - {is_valid: 是否有效, data: 资产数据列表}
    """
    try:
        # 1. ES精准查询该IP的所有资产
        es_query = {
            "query": {
                "term": {
                    "ip": ip
                }
            }
        }
        es_result = es.search(index=index_name, body=es_query, size=100)
        asset_list = [hit["_source"] for hit in es_result["hits"]["hits"]]
        if not asset_list:
            return {"is_valid": False, "data": []}
        
        # 2. 校验扫描有效期（取最新的扫描时间戳）
        latest_scan_time = max([asset["scan_time"] for asset in asset_list])
        current_time = int(time.time())
        if (current_time - latest_scan_time) > scan_expire_time:
            return {"is_valid": False, "data": []}
        
        # 3. 数据有效，返回结果
        return {"is_valid": True, "data": asset_list}
    except Exception as e:
        print(f"数据库查询失败: {str(e)}")
        return {"is_valid": False, "data": []}

def close_db_conn(mysql_conn, mysql_cursor, es):
    """
    关闭数据库连接 - 避免连接泄漏
    :param mysql_conn: MySQL连接
    :param mysql_cursor: MySQL游标
    :param es: ES连接
    :return: None
    """
    try:
        if mysql_cursor:
            mysql_cursor.close()
        if mysql_conn:
            mysql_conn.close()
        print("MySQL连接已关闭")
    except:
        pass
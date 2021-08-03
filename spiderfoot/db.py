import re
import sqlite3
import threading
import time
import hashlib


class SpiderFootDb:
    """SpiderFoot database

    Attributes:
        conn: SQLite connect() connection
        dbh: SQLite cursor() database handle
        dbhLock (_thread.RLock): thread lock on database handle
    """

    dbh = None    # SQLite游标, 数据库句柄
    conn = None   # 数据库句柄，保存数据库连接

    # Prevent multithread access to sqlite database
    dbhLock = threading.RLock()    # RLock(可重入锁),可递归acquire，当释放锁时调用release()需要相同次数

    # Queries for creating the SpiderFoot database
    # 创建数据库字段
    createSchemaQueries = [
        "PRAGMA journal_mode=WAL",
        "CREATE TABLE tbl_event_types ( \
            event       VARCHAR NOT NULL PRIMARY KEY, \
            event_descr VARCHAR NOT NULL, \
            event_raw   INT NOT NULL DEFAULT 0, \
            event_type  VARCHAR NOT NULL \
        )",
        "CREATE TABLE tbl_config ( \
            scope   VARCHAR NOT NULL, \
            opt     VARCHAR NOT NULL, \
            val     VARCHAR NOT NULL, \
            PRIMARY KEY (scope, opt) \
        )",
        "CREATE TABLE tbl_scan_instance ( \
            guid        VARCHAR NOT NULL PRIMARY KEY, \
            name        VARCHAR NOT NULL, \
            seed_target VARCHAR NOT NULL, \
            created     INT DEFAULT 0, \
            started     INT DEFAULT 0, \
            ended       INT DEFAULT 0, \
            status      VARCHAR NOT NULL \
        )",
        "CREATE TABLE tbl_scan_log ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            generated           INT NOT NULL, \
            component           VARCHAR, \
            type                VARCHAR NOT NULL, \
            message             VARCHAR \
        )",
        "CREATE TABLE tbl_scan_config ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            component           VARCHAR NOT NULL, \
            opt                 VARCHAR NOT NULL, \
            val                 VARCHAR NOT NULL \
        )",
        "CREATE TABLE tbl_scan_results ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            hash                VARCHAR NOT NULL, \
            type                VARCHAR NOT NULL REFERENCES tbl_event_types(event), \
            generated           INT NOT NULL, \
            confidence          INT NOT NULL DEFAULT 100, \
            visibility          INT NOT NULL DEFAULT 100, \
            risk                INT NOT NULL DEFAULT 0, \
            module              VARCHAR NOT NULL, \
            data                VARCHAR, \
            false_positive      INT NOT NULL DEFAULT 0, \
            source_event_hash  VARCHAR DEFAULT 'ROOT' \
        )",
        "CREATE INDEX idx_scan_results_id ON tbl_scan_results (scan_instance_id)",
        "CREATE INDEX idx_scan_results_type ON tbl_scan_results (scan_instance_id, type)",
        "CREATE INDEX idx_scan_results_hash ON tbl_scan_results (scan_instance_id, hash)",
        "CREATE INDEX idx_scan_results_srchash ON tbl_scan_results (scan_instance_id, source_event_hash)",
        "CREATE INDEX idx_scan_logs ON tbl_scan_log (scan_instance_id)"

    ]

    # 创建要搜集的信息实体，包括IP、域名等等信息
    eventDetails = [
        ['ROOT', '内部SpiderFoot Root事件', 1, 'INTERNAL'],
        ['IP_ADDRESS', 'IP', 0, 'ENTITY'],           # 格式=> IP       例: 1.1.1.1
        ['AFFILIATE_IPADDRESS', '关联IP', 0, 'ENTITY'],  # 跟目标相关联的IP
        ['IPV6_ADDRESS', 'IPv6', 0, 'ENTITY'],      # 格式
        ["NETBLOCK_OWNER", "所属子网", 0, 'ENTITY'],    # 用户在输入目标时填写
        ['NETBLOCK_MEMBER', '子网', 0, 'ENTITY'],      # 目标存在的网段  例如: 1.1.1.0/24
        ['NETBLOCK_WHOIS', '子网Whois', 0, 'DATA'],    # 子网Whois信息
        ['OPERATING_SYSTEM', '操作系统', 0, 'DATA'],  # 某个IP对应的操作系统  IP:OS
        ['TCP_PORT_OPEN', 'TCP端口', 0, 'SUBENTITY'],    # 格式=> IP:Port  例: 1.1.1.1:80
        ['TCP_PORT_OPEN_BANNER', 'TCP端口Banner', 0, 'DATA'],  # 对应IP+Port显示在Source Data Element栏 TCP端口Banner信息
        ['TCP_PORT_SERVICE', 'TCP端口服务', 0, 'DATA'],   # 服务
        ['TCP_PORT_PRODUCT', 'TCP端口运行程序', 0, 'DATA'],  # 产品
        ['DEVICE_TYPE', '设备类型', 0, 'DATA'],  # 设备
        ['TCP_PORT_RAW_DATA', 'TCP端口内容', 0, 'DATA'],   # 访问该端口内容
        ['DOMAIN_NAME', '域名', 0, 'ENTITY'],    # 域名/子域名
        ['DOMAIN_NAME_PARENT', '父域名', 0, 'ENTITY'],     # 父域名，有且只有一个，为输入Target的父域名 
        ['DOMAIN_WHOIS', '域名Whois', 1, 'DATA'],     # 对域名Whois信息进行收集，只针对父域名
        ['AFFILIATE_DOMAIN_NAME', '关联域名', 0, 'ENTITY'],   # 跟目标域名相关，与Target不属于同一个一级域名，例如 baidu.com 与 baidu.com.cn, 前者为Target域名，后者为关联域名，关联域名可能会产生较多错误信息
        ['AFFILIATE_DOMAIN_WHOIS', '关联域名Whois', 1, 'DATA'],    # 关联域名的Whois信息
        ['INTERNET_NAME', '主机名', 0, 'ENTITY'],   # 主机名
        ['AFFILIATE_INTERNET_NAME', '关联主机名', 0, 'ENTITY'],    # 关联主机名
        ['DNS_MX', 'DNS MX记录', 0, 'DATA'],      # domain+address 例: gf.com.cn:mx5.gf.com.cn
        ['DNS_NS', 'DNS NS记录', 0, 'DATA'],      # domain+address 例: 195.190.126.178:d.root-servers.net.
        ['DNS_A', 'DNS A记录', 0, 'DATA'],        # domain+address 例: ask.ns.gf.com.cn:183.232.63.22
        ['DNS_SPF', 'DNS SPF记录', 0, 'DATA'],
        ['DNS_AAAA', 'DNS AAAA记录', 0, 'DATA'],        # 例: info.ns.gf.com.cn:2402:4e00:1010:210d:0:9292:13f8:4b0c
        ['DNS_CNAME', 'DNS CNAME记录', 0, 'DATA'],        # 例: oauth.gf.com.cn:oauth.ns.gf.com.cn
        ['DNS_CERTIFICATE', 'DNS证书颁发机构授权', 0, 'DATA'],   # 例:  *.gf.com.cn:183.62.246.172
        ['DNS_TXT', 'DNS TXT记录', 0, 'DATA'],
        ['RDNS', 'DNS反向解析记录', '0', 'DATA'],   # 例: 118.212.233.0:0.233.212.118.adsl-pool.jx.chinaunicom.com.
        ['RAW_DNS_RECORDS', 'DNS原始记录', 1, 'DATA'],    # 例: get.gf.com.cn. 600 IN CNAME get.ns.gf.com.cn.
        ['WEBSERVER_URL', 'Web Server URL', 0, 'ENTITY'],    # Web服务器的URL
        ['WEBSERVER_BANNER', 'Web Server Banner', 0, 'DATA'],   # Web服务器Banner信息(Header响应包), 对比时使用hash256
        ['WEBSERVER_IP', 'Web Server IP', 0, 'DATA'],    # Web服务器IP
        ['WEBSERVER_TITLE', 'Web Server 标题', 0, 'DATA'],  # Web服务器标题
        ['WEBSERVER_COOKIE', 'Web Server Cookie值', 0, 'DATA'],
        ['WEBSERVER_APPLICATION', 'Web Server 中间件', 0, 'DATA'],   # Web服务器中间件
        ['WEBSERVER_PATH', 'Web Server 路径', 0, 'DATA'],     # 使用搜索引擎，爬取搜索结果
        ['WEBSERVER_FRAMEWORK', 'Web Server 框架', 0, 'DATA'],     # Web服务器所使用的前后端框架
        ['SSL_CERTIFICATE_RAW', 'SSL证书原始数据', 1, 'DATA'],   # SSL证书的原始数据
        ['SSL_CERTIFICATE_ISSUED', 'SSL证书使用机构', 0, 'ENTITY'],   # SSL证书颁发给以下机构
        ['SSL_CERTIFICATE_ISSUER', 'SSL证书颁发机构', 0, 'ENTITY'],   # SSL证书由以下机构颁发
        ['BGP_AS_MEMBER', 'ASN', 0, 'ENTITY'],     # asn号，重复率非常高
        ['ORG', '组织', 0, 'ENTITY'],  # 所属组织, 重复率非常高
        ['RAW_RIR_DATA', 'API原始数据', 1, 'DATA'],    # 使用hash256存储
        ['EMAILADDR', '邮件地址', 0, 'ENTITY'],    # 邮件地址
        ['EMAILADDR_GENERIC', '通用电子邮件地址', 0, 'ENTITY'],
        ['AFFILIATE_EMAILADDR', '关联邮件地址', 0, 'ENTITY'],    # 相关联邮件地址
        ['PHONE_NUMBER', '电话号码', 0, 'ENTITY'],     # 电话号码
        ['PHYSICAL_ADDRESS', '物理地址', 0, 'ENTITY'],
        ['VULNERABILITY', '漏洞', 0, 'DATA'],        # 漏洞编号
        ['COMPANY_NAME', '公司名', 0, 'ENTITY'],
        ['AFFILIATE_COMPANY_NAME', '关联公司名', 0, 'ENTITY'],
        ['PUBLIC_CODE_REPO', '公开代码库', 0, 'ENTITY'],
        ['USERNAME', '用户名', 0, 'ENTITY'],
        ['LINKED_URL', '链接URL', 0, 'SUBENTITY'],
        ['APPSTORE_ENTRY', 'App商店', 0, 'ENTITY'],
        ['PROVIDER_TELCO', '电信供应商', 0, 'ENTITY'],
    ]

    # 初始化数据库各种信息，创建
    def __init__(self, opts, init=False):
        """Initialize database and create handle to the SQLite database file.
        Creates the database file if it does not exist.
        Creates database schema if it does not exist.

        Args:
            opts (dict): 必须在'__database'键中指定数据库文件路径
            init (bool): 初始化数据库

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """

        if not isinstance(opts, dict):   # opts参数必须为字典
            raise TypeError(f"opts is {type(opts)}; expected dict()")
        if not opts:
            raise ValueError("opts is empty")
        if not opts.get('__database'):
            raise ValueError("opts['__database'] is empty")

        database_path = opts['__database']

        # connect() will create the database file if it doesn't exist, but
        # at least we can use this opportunity to ensure we have permissions to
        # read and write to such a file.
        try:
            dbh = sqlite3.connect(database_path)
        except Exception as e:
            raise IOError(f"Error connecting to internal database {database_path}: {e}")

        if dbh is None:
            raise IOError(f"Could not connect to internal database, and could not create {database_path}")

        # Python拥有两种字符串类型。标准字符串是单字节字符序列，允许包含二进制数据和嵌入的null字符。 Unicode 字符串是双字节字符序列，一个字符使用两个字节来保存
        # 这句话是在将TEXT返回bytestring对象，默认为Unicode对象
        dbh.text_factory = str

        self.conn = dbh
        self.dbh = dbh.cursor()

        # SQLite doesn't support regex queries, so we create
        # a custom function to do so..
        # 正则匹配数据库查询信息
        def __dbregex__(qry, data):
            try:
                rx = re.compile(qry, re.IGNORECASE | re.DOTALL)
                ret = rx.match(data)
            except Exception:
                return False
            return ret is not None

        # Now we actually check to ensure the database file has the schema set
        # up correctly.
        # 设置数据库，确保数据库正确启动
        with self.dbhLock:
            try:
                self.dbh.execute('SELECT COUNT(*) FROM tbl_scan_config')
                self.conn.create_function("REGEXP", 2, __dbregex__)
            except sqlite3.Error:
                # .. If not set up, we set it up.
                try:
                    self.create()
                    init = True
                except Exception as e:
                    raise IOError(f"Tried to set up the SpiderFoot database schema, but failed: {e.args[0]}")

            if init:
                # 批量插入扫描信息实体到表，添加字段
                for row in self.eventDetails:
                    event = row[0]
                    event_descr = row[1]
                    event_raw = row[2]
                    event_type = row[3]
                    qry = "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES (?, ?, ?, ?)"

                    try:
                        self.dbh.execute(qry, (
                            event, event_descr, event_raw, event_type
                        ))
                        self.conn.commit()
                    except Exception:
                        continue
                self.conn.commit()

    #
    # Back-end database operations
    #

    # 数据库创建
    def create(self):
        """Create the database schema.

        Raises:
            IOError: database I/O failed
        """

        with self.dbhLock:
            try:
                for qry in self.createSchemaQueries:
                    self.dbh.execute(qry)
                self.conn.commit()
                for row in self.eventDetails:
                    event = row[0]
                    event_descr = row[1]
                    event_raw = row[2]
                    event_type = row[3]
                    qry = "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES (?, ?, ?, ?)"

                    self.dbh.execute(qry, (
                        event, event_descr, event_raw, event_type
                    ))
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when setting up database: {e.args[0]}")

    # 关闭数据库句柄
    def close(self):
        """Close the database handle."""

        with self.dbhLock:
            self.dbh.close()

    # 搜索数据库中信息搜集结果，传递参数criteria为一个字典，可用于查询的包括scan_id, type, value, regex
    def search(self, criteria, filterFp=False):
        """Search database.

        Args:
            criteria (dict): search criteria such as:
                - scan_id (search within a scan, if omitted search all)
                - type (search a specific type, if omitted search all)
                - value (search values for a specific string, if omitted search all)
                - regex (search values for a regular expression)
                ** at least two criteria must be set **
            filterFp (bool): filter out false positives

        Returns:
            list: search results

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """
        if not isinstance(criteria, dict):
            raise TypeError(f"criteria is {type(criteria)}; expected dict()")

        valid_criteria = ['scan_id', 'type', 'value', 'regex']

        for key in list(criteria.keys()):
            if key not in valid_criteria:
                criteria.pop(key, None)
                continue

            if not isinstance(criteria.get(key), str):
                raise TypeError(f"criteria[{key}] is {type(criteria.get(key))}; expected str()")

            if not criteria[key]:
                criteria.pop(key, None)
                continue

        if len(criteria) == 0:
            raise ValueError(f"No valid search criteria provided; expected: {', '.join(valid_criteria)}")

        if len(criteria) == 1:
            raise ValueError("Only one search criteria provided; expected at least two")

        qvars = list()
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, c.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
            WHERE s.scan_instance_id = c.scan_instance_id AND \
            t.event = c.type AND c.source_event_hash = s.hash "

        if filterFp:
            qry += " AND c.false_positive <> 1 "

        if criteria.get('scan_id') is not None:
            qry += "AND c.scan_instance_id = ? "
            qvars.append(criteria['scan_id'])

        if criteria.get('type') is not None:
            qry += " AND c.type = ? "
            qvars.append(criteria['type'])

        if criteria.get('value') is not None:
            qry += " AND (c.data LIKE ? OR s.data LIKE ?) "
            qvars.append(criteria['value'])
            qvars.append(criteria['value'])

        if criteria.get('regex') is not None:
            qry += " AND (c.data REGEXP ? OR s.data REGEXP ?) "
            qvars.append(criteria['regex'])
            qvars.append(criteria['regex'])

        qry += " ORDER BY c.data"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when fetching search results: {e.args[0]}")

    # 获取实体信息
    def eventTypes(self):
        """Get event types.

        Returns:
            list: event types

        Raises:
            IOError: database I/O failed
        """

        qry = "SELECT event_descr, event, event_raw, event_type FROM tbl_event_types"
        with self.dbhLock:
            try:
                self.dbh.execute(qry)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when retrieving event types: {e.args[0]}")

    # 写入日志
    def scanLogEvent(self, instanceId, classification, message, component=None):
        """Log an event to the database.

        Args:
            instanceId (str): scan instance ID
            classification (str): TBD
            message (str): TBD
            component (str): TBD

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed

        Todo:
            Do something smarter to handle database locks
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(classification, str):
            raise TypeError(f"classification is {type(classification)}; expected str()")

        if not isinstance(message, str):
            raise TypeError(f"message is {type(message)}; expected str()")

        if not component:
            component = "SpiderFoot"

        qry = "INSERT INTO tbl_scan_log \
            (scan_instance_id, generated, component, type, message) \
            VALUES (?, ?, ?, ?, ?)"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (
                    instanceId, time.time() * 1000, component, classification, message
                ))
                self.conn.commit()
            except sqlite3.Error as e:
                if "locked" in e.args[0] or "thread" in e.args[0]:
                    # print("[warning] Couldn't log due to SQLite limitations. You can probably ignore this.")
                    # log.critical(f"Unable to log event in DB due to lock: {e.args[0]}")
                    pass
                else:
                    raise IOError(f"Unable to log scan event in DB: {e.args[0]}")

    # 写入具体的扫描任务实例
    def scanInstanceCreate(self, instanceId, scanName, scanTarget):
        """Store a scan instance in the database.

        Args:
            instanceId (str): scan instance ID
            scanName(str): scan name
            scanTarget (str): scan target

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(scanName, str):
            raise TypeError(f"scanName is {type(scanName)}; expected str()")

        if not isinstance(scanTarget, str):
            raise TypeError(f"scanTarget is {type(scanTarget)}; expected str()")

        qry = "INSERT INTO tbl_scan_instance \
            (guid, name, seed_target, created, status) \
            VALUES (?, ?, ?, ?, ?)"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (
                    instanceId, scanName, scanTarget, time.time() * 1000, 'CREATED'
                ))
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError(f"Unable to create scan instance in DB: {e.args[0]}")

    # 更新任务的启动时间，结束时间以及设置状态
    def scanInstanceSet(self, instanceId, started=None, ended=None, status=None):
        """Update the start time, end time or status (or all 3) of a scan instance.

        Args:
            instanceId (str): scan instance ID
            started (str): scan start time
            ended (str): scan end time
            status (str): scan status

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        qvars = list()
        qry = "UPDATE tbl_scan_instance SET "

        if started is not None:
            qry += " started = ?,"
            qvars.append(started)

        if ended is not None:
            qry += " ended = ?,"
            qvars.append(ended)

        if status is not None:
            qry += " status = ?,"
            qvars.append(status)

        # guid = guid is a little hack to avoid messing with , placement above
        qry += " guid = guid WHERE guid = ?"
        qvars.append(instanceId)

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                self.conn.commit()
            except sqlite3.Error:
                raise IOError("Unable to set information for the scan instance.")

    # 根据实例ID获取任务信息
    def scanInstanceGet(self, instanceId):
        """Return info about a scan instance (name, target, created, started, ended, status)

        Args:
            instanceId (str): scan instance ID

        Returns:
            list: scan instance info

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        qry = "SELECT name, seed_target, ROUND(created/1000) AS created, \
            ROUND(started/1000) AS started, ROUND(ended/1000) AS ended, status \
            FROM tbl_scan_instance WHERE guid = ?"
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when retrieving scan instance: {e.args[0]}")

    # 获得每个事件类型的结果摘要,by in ['type', 'module', 'entity']
    def scanResultSummary(self, instanceId, by="type"):
        """Obtain a summary of the results, filtered by event type, module or entity.

        Args:
            instanceId (str): scan instance ID
            by (str): filter by type

        Returns:
            list: scan instance info

        Raises:
            TypeError: arg type was invalid
            ValueError: arg valie was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(by, str):
            raise TypeError(f"by is {type(by)}; expected str()")

        if by not in ["type", "module", "entity"]:
            raise ValueError(f"Invalid filter by value: {by}")

        if by == "type":
            qry = "SELECT r.type, e.event_descr, MAX(ROUND(generated)) AS last_in, \
                count(*) AS total, count(DISTINCT r.data) as utotal FROM \
                tbl_scan_results r, tbl_event_types e WHERE e.event = r.type \
                AND r.scan_instance_id = ? GROUP BY r.type ORDER BY e.event_descr"

        if by == "module":
            qry = "SELECT r.module, '', MAX(ROUND(generated)) AS last_in, \
                count(*) AS total, count(DISTINCT r.data) as utotal FROM \
                tbl_scan_results r, tbl_event_types e WHERE e.event = r.type \
                AND r.scan_instance_id = ? GROUP BY r.module ORDER BY r.module DESC"

        if by == "entity":
            qry = "SELECT r.data, e.event_descr, MAX(ROUND(generated)) AS last_in, \
                count(*) AS total, count(DISTINCT r.data) as utotal FROM \
                tbl_scan_results r, tbl_event_types e WHERE e.event = r.type \
                AND r.scan_instance_id = ? \
                AND e.event_type in ('ENTITY') \
                GROUP BY r.data, e.event_descr ORDER BY total DESC limit 50"

        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when fetching result summary: {e.args[0]}")

    # 根据实例获取任务扫描结果
    def scanResultEvent(self, instanceId, eventType='ALL', filterFp=False):
        """Obtain the data for a scan and event type.

        Args:
            instanceId (str): scan instance ID
            eventType (str): filter by event type
            filterFp (bool): filter false positives

        Returns:
            list: scan results

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(eventType, str):
            raise TypeError(f"eventType is {type(eventType)}; expected str()")

        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
            WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
            s.scan_instance_id = c.scan_instance_id AND \
            t.event = c.type"

        qvars = [instanceId]

        if eventType != "ALL":
            qry += " AND c.type = ?"
            qvars.append(eventType)

        if filterFp:
            qry += " AND c.false_positive <> 1"

        qry += " ORDER BY c.data"
        #  去重操作
        qry = "SELECT * FROM (" + qry + ") GROUP BY data"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when fetching result events: {e.args[0]}")

    # 根据ID获取任务扫描结果统计
    def scanResultEventUnique(self, instanceId, eventType='ALL', filterFp=False):
        """Obtain a unique list of elements.

        Args:
            instanceId (str): scan instance ID
            eventType (str): filter by event type
            filterFp (bool): filter false positives

        Returns:
            list: unique scan results

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(eventType, str):
            raise TypeError(f"eventType is {type(eventType)}; expected str()")

        qry = "SELECT DISTINCT data, type, COUNT(*) FROM tbl_scan_results \
            WHERE scan_instance_id = ?"
        qvars = [instanceId]

        if eventType != "ALL":
            qry += " AND type = ?"
            qvars.append(eventType)

        if filterFp:
            qry += " AND false_positive <> 1"

        qry += " GROUP BY type, data ORDER BY COUNT(*)"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when fetching unique result events: {e.args[0]}")

    # 获取日志
    def scanLogs(self, instanceId, limit=None, fromRowId=None, reverse=False):
        """Get scan logs.

        Args:
            instanceId (str): scan instance ID
            limit (int): limit number of results
            fromRowId (int): retrieve logs starting from row ID
            reverse (bool): search result order

        Returns:
            list: scan logs

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        qry = "SELECT generated AS generated, component, \
            type, message, rowid FROM tbl_scan_log WHERE scan_instance_id = ?"
        if fromRowId:
            qry += " and rowid > ?"

        qry += " ORDER BY generated "
        if reverse:
            qry += "ASC"
        else:
            qry += "DESC"
        qvars = [instanceId]

        if fromRowId:
            qvars.append(fromRowId)

        if limit is not None:
            qry += " LIMIT ?"
            qvars.append(limit)

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when fetching scan logs: {e.args[0]}")

    # 获取错误信息
    def scanErrors(self, instanceId, limit=None):
        """Get scan errors.

        Args:
            instanceId (str): scan instance ID
            limit (int): limit number of results

        Returns:
            list: scan errors

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        qry = "SELECT generated AS generated, component, \
            message FROM tbl_scan_log WHERE scan_instance_id = ? \
            AND type = 'ERROR' ORDER BY generated DESC"
        qvars = [instanceId]

        if limit is not None:
            qry += " LIMIT ?"
            qvars.append(limit)

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when fetching scan errors: {e.args[0]}")

    # Delete a scan instance
    def scanInstanceDelete(self, instanceId):
        """Delete a scan instance.

        Args:
            instanceId (str): scan instance ID

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        qry1 = "DELETE FROM tbl_scan_instance WHERE guid = ?"
        qry2 = "DELETE FROM tbl_scan_config WHERE scan_instance_id = ?"
        qry3 = "DELETE FROM tbl_scan_results WHERE scan_instance_id = ?"
        qry4 = "DELETE FROM tbl_scan_log WHERE scan_instance_id = ?"
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry1, qvars)
                self.dbh.execute(qry2, qvars)
                self.dbh.execute(qry3, qvars)
                self.dbh.execute(qry4, qvars)
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when deleting scan: {e.args[0]}")

    # 设置false_positive位
    def scanResultsUpdateFP(self, instanceId, resultHashes, fpFlag):
        """Set the false positive flag for a result.

        Args:
            instanceId (str): scan instance ID
            resultHashes (list): list of event hashes
            fpFlag (int): false positive

        Returns:
            bool: success

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(resultHashes, list):
            raise TypeError(f"resultHashes is {type(resultHashes)}; expected list()")

        with self.dbhLock:
            for resultHash in resultHashes:
                qry = "UPDATE tbl_scan_results SET false_positive = ? WHERE \
                    scan_instance_id = ? AND hash = ?"
                qvars = [fpFlag, instanceId, resultHash]
                try:
                    self.dbh.execute(qry, qvars)
                except sqlite3.Error as e:
                    raise IOError(f"SQL error encountered when updating F/P: {e.args[0]}")

            try:
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when updating F/P: {e.args[0]}")

        return True

    # 保存默认配置
    def configSet(self, optMap=dict()):
        """Store the default configuration in the database.

        Args:
            optMap (dict): config options

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """

        if not isinstance(optMap, dict):
            raise TypeError(f"optMap is {type(optMap)}; expected dict()")
        if not optMap:
            raise ValueError("optMap is empty")

        qry = "REPLACE INTO tbl_config (scope, opt, val) VALUES (?, ?, ?)"

        with self.dbhLock:
            for opt in list(optMap.keys()):
                # Module option
                if ":" in opt:
                    parts = opt.split(':')
                    qvals = [parts[0], parts[1], optMap[opt]]
                else:
                    # Global option
                    qvals = ["GLOBAL", opt, optMap[opt]]

                try:
                    self.dbh.execute(qry, qvals)
                except sqlite3.Error as e:
                    raise IOError(f"SQL error encountered when storing config, aborting: {e.args[0]}")

            try:
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when storing config, aborting: {e.args[0]}")

    # 获取默认配置
    def configGet(self):
        """Retreive the config from the database

        Returns:
            dict: config

        Raises:
            IOError: database I/O failed
        """

        qry = "SELECT scope, opt, val FROM tbl_config"

        retval = dict()

        with self.dbhLock:
            try:
                self.dbh.execute(qry)
                for [scope, opt, val] in self.dbh.fetchall():
                    if scope == "GLOBAL":
                        retval[opt] = val
                    else:
                        retval[f"{scope}:{opt}"] = val

                return retval
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when fetching configuration: {e.args[0]}")

    # 清除默认配置
    def configClear(self):
        """Reset the config to default.
        Clears the config from the database and lets the hard-coded settings in the code take effect.

        Raises:
            IOError: database I/O failed
        """

        qry = "DELETE from tbl_config"
        with self.dbhLock:
            try:
                self.dbh.execute(qry)
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError(f"Unable to clear configuration from the database: {e.args[0]}")

    # 保存一个具体扫描任务的配置
    def scanConfigSet(self, id, optMap=dict()):
        """Store a configuration value for a scan.

        Args:
            id (int): scan instance ID
            optMap (dict): config options

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """

        if not isinstance(optMap, dict):
            raise TypeError(f"optMap is {type(optMap)}; expected dict()")
        if not optMap:
            raise ValueError("optMap is empty")

        qry = "REPLACE INTO tbl_scan_config \
                (scan_instance_id, component, opt, val) VALUES (?, ?, ?, ?)"

        with self.dbhLock:
            for opt in list(optMap.keys()):
                # Module option
                if ":" in opt:
                    parts = opt.split(':')
                    qvals = [id, parts[0], parts[1], optMap[opt]]
                else:
                    # Global option
                    qvals = [id, "GLOBAL", opt, optMap[opt]]

                try:
                    self.dbh.execute(qry, qvals)
                except sqlite3.Error as e:
                    raise IOError(f"SQL error encountered when storing config, aborting: {e.args[0]}")

            try:
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when storing config, aborting: {e.args[0]}")

    # 获取一个具体扫描任务的配置
    def scanConfigGet(self, instanceId):
        """Retrieve configuration data for a scan component.

        Args:
            instanceId (int): scan instance ID

        Returns:
            dict: configuration data

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        qry = "SELECT component, opt, val FROM tbl_scan_config \
                WHERE scan_instance_id = ? ORDER BY component, opt"
        qvars = [instanceId]

        retval = dict()

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                for [component, opt, val] in self.dbh.fetchall():
                    if component == "GLOBAL":
                        retval[opt] = val
                    else:
                        retval[f"{component}:{opt}"] = val
                return retval
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when fetching configuration: {e.args[0]}")

    # 存储一个事件到表中
    def scanEventStore(self, instanceId, sfEvent, truncateSize=0):
        """Store an event in the database.

        Args:
            instanceId (str): scan instance ID
            sfEvent (SpiderFootEvent): event to be stored in the database
            truncateSize (int): truncate size for event data

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """
        from spiderfoot import SpiderFootEvent

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        if not instanceId:
            raise ValueError("instanceId is empty")

        if not isinstance(sfEvent, SpiderFootEvent):
            raise TypeError(f"sfEvent is {type(sfEvent)}; expected SpiderFootEvent()")

        if not isinstance(sfEvent.generated, float):
            raise TypeError(f"sfEvent.generated is {type(sfEvent.generated)}; expected float()")

        if not sfEvent.generated:
            raise ValueError("sfEvent.generated is empty")

        if not isinstance(sfEvent.eventType, str):
            raise TypeError(f"sfEvent.eventType is {type(sfEvent.eventType,)}; expected str()")

        if not sfEvent.eventType:
            raise ValueError("sfEvent.eventType is empty")

        if not isinstance(sfEvent.data, str):
            raise TypeError(f"sfEvent.data is {type(sfEvent.data)}; expected str()")

        if not sfEvent.data:
            raise ValueError("sfEvent.data is empty")

        if not isinstance(sfEvent.module, str):
            raise TypeError(f"sfEvent.module is {type(sfEvent.module)}; expected str()")

        if not sfEvent.module:
            if sfEvent.eventType != "ROOT":
                raise ValueError("sfEvent.module is empty")

        if not isinstance(sfEvent.confidence, int):
            raise TypeError(f"sfEvent.confidence is {type(sfEvent.confidence)}; expected int()")

        if not 0 <= sfEvent.confidence <= 100:
            raise ValueError(f"sfEvent.confidence value is {type(sfEvent.confidence)}; expected 0 - 100")

        if not isinstance(sfEvent.visibility, int):
            raise TypeError(f"sfEvent.visibility is {type(sfEvent.visibility)}; expected int()")

        if not 0 <= sfEvent.visibility <= 100:
            raise ValueError(f"sfEvent.visibility value is {type(sfEvent.visibility)}; expected 0 - 100")

        if not isinstance(sfEvent.risk, int):
            raise TypeError(f"sfEvent.risk is {type(sfEvent.risk)}; expected int()")

        if not 0 <= sfEvent.risk <= 100:
            raise ValueError(f"sfEvent.risk value is {type(sfEvent.risk)}; expected 0 - 100")

        if not isinstance(sfEvent.sourceEvent, SpiderFootEvent):
            if sfEvent.eventType != "ROOT":
                raise TypeError(f"sfEvent.sourceEvent is {type(sfEvent.sourceEvent)}; expected str()")

        if not isinstance(sfEvent.sourceEventHash, str):
            raise TypeError(f"sfEvent.sourceEventHash is {type(sfEvent.sourceEventHash)}; expected str()")

        if not sfEvent.sourceEventHash:
            raise ValueError("sfEvent.sourceEventHash is empty")

        storeData = sfEvent.data

        # truncate if required
        if isinstance(truncateSize, int):
            if truncateSize > 0:
                storeData = storeData[0:truncateSize]

        # retrieve scan results
        qry = "INSERT INTO tbl_scan_results \
            (scan_instance_id, hash, type, generated, confidence, \
            visibility, risk, module, data, source_event_hash) \
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

        qvals = [instanceId, sfEvent.hash, sfEvent.eventType, sfEvent.generated,
                 sfEvent.confidence, sfEvent.visibility, sfEvent.risk,
                 sfEvent.module, storeData, sfEvent.sourceEventHash]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvals)
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when storing event data ({self.dbh}): {e.args[0]}")

    # 列出扫描实例
    def scanInstanceList(self):
        """List all previously run scans.

        Returns:
            list: previously run scans

        Raises:
            IOError: database I/O failed
        """

        # SQLite doesn't support OUTER JOINs, so we need a work-around that
        # does a UNION of scans with results and scans without results to
        # get a complete listing.
        qry = "SELECT i.guid, i.name, i.seed_target, ROUND(i.created/1000), \
            ROUND(i.started)/1000 as started, ROUND(i.ended)/1000, i.status, COUNT(r.type) \
            FROM tbl_scan_instance i, tbl_scan_results r WHERE i.guid = r.scan_instance_id \
            AND r.type <> 'ROOT' GROUP BY i.guid \
            UNION ALL \
            SELECT i.guid, i.name, i.seed_target, ROUND(i.created/1000), \
            ROUND(i.started)/1000 as started, ROUND(i.ended)/1000, i.status, '0' \
            FROM tbl_scan_instance i  WHERE i.guid NOT IN ( \
            SELECT distinct scan_instance_id FROM tbl_scan_results WHERE type <> 'ROOT') \
            ORDER BY started DESC"

        with self.dbhLock:
            try:
                self.dbh.execute(qry)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when fetching scan list: {e.args[0]}")

    # 扫描的数据时间
    def scanResultHistory(self, instanceId):
        """History of data from the scan.

        Args:
            instanceId (str): scan instance ID

        Returns:
            list: scan data history

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        qry = "SELECT STRFTIME('%H:%M %w', generated, 'unixepoch') AS hourmin, \
                type, COUNT(*) FROM tbl_scan_results \
                WHERE scan_instance_id = ? GROUP BY hourmin, type"
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when fetching scan history: {e.args[0]}")

    # 获取一组ID的源ID、类型和数据
    def scanElementSourcesDirect(self, instanceId, elementIdList):
        """Get the source IDs, types and data for a set of IDs.

        Args:
            instanceId (str): scan instance ID
            elementIdList (list): TBD

        Returns:
            list: TBD

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(elementIdList, list):
            raise TypeError(f"elementIdList is {type(elementIdList)}; expected list()")

        hashIds = []
        for hashId in elementIdList:
            if not hashId:
                continue
            if not hashId.isalnum():
                continue
            hashIds.append(hashId)

        # the output of this needs to be aligned with scanResultEvent,
        # as other functions call both expecting the same output.
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
            WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
            s.scan_instance_id = c.scan_instance_id AND \
            t.event = c.type AND c.hash in ('%s')" % "','".join(hashIds)
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when getting source element IDs: {e.args[0]}")

    # 获取一组ID的子ID、类型和数据
    def scanElementChildrenDirect(self, instanceId, elementIdList):
        """Get the child IDs, types and data for a set of IDs.

        Args:
            instanceId (str): scan instance ID
            elementIdList (list): TBD

        Returns:
            list: TBD

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(elementIdList, list):
            raise TypeError(f"elementIdList is {type(elementIdList)}; expected list()")

        hashIds = []
        for hashId in elementIdList:
            if not hashId:
                continue
            if not hashId.isalnum():
                continue
            hashIds.append(hashId)

        # the output of this needs to be aligned with scanResultEvent,
        # as other functions call both expecting the same output.
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
            WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
            s.scan_instance_id = c.scan_instance_id AND \
            t.event = c.type AND s.hash in ('%s')" % "','".join(hashIds)
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when getting child element IDs: {e.args[0]}")

    # 获取作为所提供的ID集的父代的全部上游ID集
    def scanElementSourcesAll(self, instanceId, childData):
        """Get the full set of upstream IDs which are parents to the supplied set of IDs.

        Data has to be in the format of output from scanElementSourcesDirect
        and produce output in the same format.

        Args:
            instanceId (str): scan instance ID
            childData (list): TBD

        Returns:
            list: TBD

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(childData, list):
            raise TypeError(f"childData is {type(childData)}; expected list()")

        if not childData:
            raise ValueError("childData is empty")

        # Get the first round of source IDs for the leafs
        keepGoing = True
        nextIds = list()
        datamap = dict()
        pc = dict()

        for row in childData:
            # these must be unique values!
            parentId = row[9]
            childId = row[8]
            datamap[childId] = row

            if parentId in pc:
                if childId not in pc[parentId]:
                    pc[parentId].append(childId)
            else:
                pc[parentId] = [childId]

            # parents of the leaf set
            if parentId not in nextIds:
                nextIds.append(parentId)

        while keepGoing:
            parentSet = self.scanElementSourcesDirect(instanceId, nextIds)
            nextIds = list()
            keepGoing = False

            for row in parentSet:
                parentId = row[9]
                childId = row[8]
                datamap[childId] = row

                if parentId in pc:
                    if childId not in pc[parentId]:
                        pc[parentId].append(childId)
                else:
                    pc[parentId] = [childId]
                if parentId not in nextIds:
                    nextIds.append(parentId)

                # Prevent us from looping at root
                if parentId != "ROOT":
                    keepGoing = True

        datamap[parentId] = row
        return [datamap, pc]

    # 获取作为所提供的ID集的子集的全部下游ID
    def scanElementChildrenAll(self, instanceId, parentIds):
        """Get the full set of downstream IDs which are children of the supplied set of IDs.

        Args:
            instanceId (str): scan instance ID
            parentIds (list): TBD

        Returns:
            list: TBD

        Raises:
            TypeError: arg type was invalid

        Note: This function is not the same as the scanElementParent* functions.
              This function returns only ids.
        """

        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(parentIds, list):
            raise TypeError(f"parentIds is {type(parentIds)}; expected list()")

        datamap = list()
        keepGoing = True
        nextIds = list()

        nextSet = self.scanElementChildrenDirect(instanceId, parentIds)
        for row in nextSet:
            datamap.append(row[8])

        for row in nextSet:
            if row[8] not in nextIds:
                nextIds.append(row[8])

        while keepGoing:
            nextSet = self.scanElementChildrenDirect(instanceId, nextIds)
            if nextSet is None or len(nextSet) == 0:
                keepGoing = False
                break

            for row in nextSet:
                datamap.append(row[8])
                nextIds = list()
                nextIds.append(row[8])

        return datamap

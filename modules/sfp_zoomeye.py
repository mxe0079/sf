# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_zoomeye
# Purpose:      获取各种主机端口信息
# Author:      Noah AO
# Created:     26/07/2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import time
import random
import json
import requests
from netaddr import IPNetwork
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_zoomeye(SpiderFootPlugin):

    meta = {
        'name': "ZoomEye",
        'summary': "ZoomEye 作为国际领先的网络空间测绘搜索引擎",
        'flags': [""],
        'useCases': ["Passive", "Footprint"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.zoomeye.org/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://www.zoomeye.org/profile",
                'https://www.zoomeye.org/doc#endpoints',
            ],
            # 数据源的图标的URL
            'favIcon': "https://www.zoomeye.org/favicon.ico",
            # 数据源的全尺寸logo的URL.
            'logo': "https://www.zoomeye.org/static/media/logo.a6751955.mp4",
            # 关于数据源的一两段话
            'description': "国内互联网安全厂商知道创宇开放了他们的海量数据库，对之前沉淀的数据进行了整合、整理，打造了一个名符其实的网络空间搜索引擎ZoomEye，该搜索引擎的后端数据计划包括网站组件指纹和主机设备指纹两部分(日志中如果出现大量请求错误时，需要手动访问ZoomEye网站输入验证码)"
        }
    }

    opts = {
        'checkweb': True,
        'maxdelay': 5
    }

    optdescs = {
        'checkweb': "检查web server",
        'maxdelay': "最大延时"
    }

    results = None

    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "INTERNET_NAME",
            "DOMAIN_NAME",
            "DOMAIN_NAME_PARENT",
            "NETBLOCK_OWNER",
            "NETBLOCK_MEMBER"
        ]

    # 本模块产生哪些事件
    def producedEvents(self):
        return [
            "IP_ADDRESS",
            "DOMAIN_NAME",
            "TCP_PORT_OPEN",     # IP + TCP Port
            "TCP_PORT_OPEN_BANNER",   # IP + TCP Port + banner
            "OPERATING_SYSTEM",  # IP + OS
            'GEOINFO',     # Physical Location
            'BGP_AS_MEMBER',   # asn号
            'TCP_PORT_SERVICE',   # 对应端口的服务
            'TCP_PORT_PRODUCT',   # 对应端口运行的产品
            'TCP_PORT_RAW_DATA',   # 对应端口内容
            'SSL_CERTIFICATE_RAW'
            'WEBSERVER_URL',
            'WEBSERVER_BANNER',
            'WEBSERVER_IP',
            'WEBSERVER_TITLE',
            'WEBSERVER_APPLICATION',
            'RDNS',
            'DNS_TXT',
            'DNS_NS',
            'DNS_MX',
            'VULNERABILITY'
        ]

    # 当查询第三方时，最好有一个专门的函数来做，避免把它放在handleEvent()中。
    def queryDetial(self, token, s, query_type):
        headers = {
            'User-Agent': self.opts['_useragent']
        }
        url = list()
        url.append(f"https://www.zoomeye.org/{query_type}/details/{token}?from=detail")
        if query_type == 'host':
            query_type = '1'
        if query_type == 'web':
            query_type = '2'
        url.append(f"https://www.zoomeye.org/host/dns/?ip={token}&query_type={query_type}")
        url.append(f"https://www.zoomeye.org/host/vuls/?ip={token}&query_type={query_type}")

        response = list()
        try:
            for i in range(3):
                response.append(s.get(url[i], timeout=self.opts['_fetchtimeout'], headers=headers))
        except Exception as e:
            self.sf.error(f'ZoomEye request detail message error: {e}')
            return None

        result = list()
        try:
            for i in range(3):
                result.append(json.loads(response[i].text))
        except Exception as e:
            self.sf.error(f"Error processing JSON response from Zoomeye: {e}")
            return None

        return result

    def query(self, qry, s, qry_type):
        headers = {
            'User-Agent': self.opts['_useragent']
        }
        if qry_type == 'domain':
            data = f"site%3A%22{qry}%22"
        elif qry_type == 'ip':
            data = f"ip%253A%2522{qry}%2522"
        elif qry_type == 'cidr':
            ip = str(IPNetwork(qry).ip)
            cidr_value = str(IPNetwork(qry).prefixlen)
            data = f"cidr%3A{ip}%2F{cidr_value}"
        else:
            self.sf.error(f"Zoomeye Request type error")
            return None
        try:
            s.get(r"https://www.zoomeye.org/search_check", timeout=self.opts['_fetchtimeout'], headers=headers)
            r0 = s.get(fr"https://www.zoomeye.org/search_total?q={data}", timeout=self.opts['_fetchtimeout'], headers=headers)
            r0 = json.loads(r0.text)
            if r0.get('status') != 200:
                self.sf.error(f"Zoomeye request data {qry} failed")
                return None
            r1 = s.get(fr"https://www.zoomeye.org/search?q={data}", timeout=self.opts['_fetchtimeout'], headers=headers)
            r1 = json.loads(r1.text)
            if r1.get('status') != 200:
                self.sf.error(f"Zoomeye request data {qry} failed")
                return None
            return r1
        except Exception as e:
            self.sf.error(f"Error processing JSON response from Zoomeye: {e}")
            return None

    # 处理发送到该模块的事件
    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data
        s = requests.Session()

        # 一旦我们处于这种状态，立即返回.
        if self.errorState:
            return

        # 检查模块是否已经分析了该事件数据
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        # 将事件数据添加到结果字典中，以防止重复查询。如果eventData可能是大的东西，把键设置为值的哈希而不是值，以避免内存的滥用。
        self.results[eventData] = True

        # 延时操作
        time.sleep(random.randint(1, self.opts['maxdelay']))

        res = None
        res1, res2, res3, res4 = list(), list(), list(), list()
        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            res = self.query(eventData, s, 'ip')

        if eventName in ['DOMAIN_NAME_PARENT', 'DOMAIN_NAME', 'INTERNET_NAME']:
            res = self.query(eventData, s, 'domain')

        if eventName in ['NETBLOCK_OWNER', 'NETBLOCK_MEMBER']:
            res = self.query(eventData, s, 'cidr')

        if res and isinstance(res, dict):
            res1 = res.get('matches')
            if res1 and isinstance(res1, list):
                if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
                    t = self.queryDetial(res1[0].get('token'), s, res1[0].get('type'))  # 返回为dict对象
                    if t and isinstance(t, list):
                        res2, res3, res4 = t[0], t[1], t[2]
                if eventName in ['DOMAIN_NAME_PARENT', 'DOMAIN_NAME', 'INTERNET_NAME', 'NETBLOCK_OWNER', 'NETBLOCK_MEMBER']:
                    for i in res1:
                        t = self.queryDetial(i.get('token'), s, i.get('type'))
                        if t and isinstance(t, list):
                            res2.append(t[0])
                            res3.append(t[1])
                            res4.append(t[2])

        if res2:
            data = list()
            if isinstance(res2, dict):
                data.append(res2)
            if isinstance(res2, list):
                data = res2
            for r2 in data:
                if int(r2.get('status')) == 200 and r2.get('ports'):
                    for i in r2.get('ports'):
                        tmp1 = r2.get('ip') + ':' + str(i.get('port'))
                        if tmp1:
                            pevt = SpiderFootEvent("TCP_PORT_OPEN", tmp1, self.__name__, event)
                            self.notifyListeners(pevt)

                            if i.get('service'):
                                tmp2 = i.get('service')
                                tmp2 = tmp1 + ' => ' + tmp2
                                evt = SpiderFootEvent("TCP_PORT_SERVICE", tmp2, self.__name__, pevt)
                                self.notifyListeners(evt)

                            if i.get('product'):
                                tmp2 = i.get('product')
                                tmp2 = tmp1 + ' => ' + tmp2 + ' ' + str(i.get('version') or '')
                                evt = SpiderFootEvent("TCP_PORT_PRODUCT", tmp2, self.__name__, pevt)
                                self.notifyListeners(evt)

                            if i.get('os'):
                                tmp2 = i.get('os')
                                tmp2 = r2.get('ip') + ' => ' + tmp2
                                if tmp2:
                                    evt = SpiderFootEvent("OPERATING_SYSTEM", tmp2, self.__name__, event)
                                    self.notifyListeners(evt)

                            if i.get('banner'):
                                tmp2 = i.get('banner')
                                tmp2 = tmp1 + ' =>\r\n' + tmp2
                                evt = SpiderFootEvent("TCP_PORT_OPEN_BANNER", tmp2, self.__name__, pevt)
                                self.notifyListeners(evt)

                if int(r2.get('status')) == 200 and r2.get('site'):
                    site = r2.get('site')
                    url = 'http://' + site
                    evt = SpiderFootEvent("WEBSERVER_URL", url, self.__name__, event)
                    self.notifyListeners(evt)

                    if r2.get('server'):
                        for i in r2.get('server'):
                            data = str(i.get('name').get('en') or '') + ' ' + str(i.get('version') or '')
                            data = site + " => " + data
                            evt = SpiderFootEvent("WEBSERVER_APPLICATION", data, self.__name__, event)
                            self.notifyListeners(evt)

                    if r2.get('headers'):
                        data = r2.get('headers')
                        data = site + " =>\r\n" + data
                        evt = SpiderFootEvent("WEBSERVER_BANNER", data, self.__name__, event)
                        self.notifyListeners(evt)

                    if r2.get('ip') and isinstance(r2.get('ip'), list):
                        for ip in r2.get('ip'):
                            evt = SpiderFootEvent("IP_ADDRESS", ip, self.__name__, event)
                            self.notifyListeners(evt)
                        data = ','.join(r2.get('ip'))
                        data = site + " => " + data
                        evt = SpiderFootEvent("WEBSERVER_IP", data, self.__name__, event)
                        self.notifyListeners(evt)

                    if r2.get('title'):
                        data = r2.get('title')
                        if isinstance(data, list):
                            data = ','.join(data)
                        data = site + " => " + data
                        evt = SpiderFootEvent("WEBSERVER_TITLE", data, self.__name__, event)
                        self.notifyListeners(evt)

                    if r2.get('os'):
                        data = r2.get('os')
                        data = site + " => " + str(data)
                        evt = SpiderFootEvent("OPERATING_SYSTEM", data, self.__name__, event)
                        self.notifyListeners(evt)

        if res3:
            data = list()
            if isinstance(res3, dict):
                data.append(res3)
            if isinstance(res3, list):
                data = res3
            for r3 in data:
                if int(r3.get('status')) == 200 and r3.get('datas'):
                    for i in r3.get('datas'):
                        if i.get('Type') == "rDNS":
                            tmp1 = i.get('Domain/IP') + ' : ' + i.get('Address')
                            if tmp1:
                                evt = SpiderFootEvent("RDNS", tmp1, self.__name__, event)
                                self.notifyListeners(evt)
                                evt = SpiderFootEvent("DOMAIN_NAME", i.get('Address'), self.__name__, event)
                                self.notifyListeners(evt)

                        if i.get('Type') == "NS":
                            tmp1 = i.get('Domain/IP') + ' : ' + i.get('Address')
                            if tmp1 not in self.results:
                                evt = SpiderFootEvent("DNS_NS", tmp1, self.__name__, event)
                                self.results[evt.data] = True
                                self.notifyListeners(evt)

                        if i.get('Type') == "A":
                            tmp1 = i.get('Domain/IP') + ' : ' + i.get('Address')
                            if tmp1 not in self.results:
                                evt = SpiderFootEvent("DNS_A", tmp1, self.__name__, event)
                                self.results[evt.data] = True
                                self.notifyListeners(evt)

                        if i.get('Type').startswith("MX"):
                            tmp1 = i.get('Domain/IP') + ' : ' + i.get('Address')
                            if tmp1 not in self.results:
                                evt = SpiderFootEvent("DNS_MX", tmp1, self.__name__, event)
                                self.results[evt.data] = True
                                self.notifyListeners(evt)
                                evt = SpiderFootEvent("DOMAIN_NAME", i.get('Address'), self.__name__, event)
                                self.notifyListeners(evt)

                        if i.get('Type').startswith("TXT"):
                            tmp1 = i.get('Domain/IP') + ' : ' + i.get('Address')
                            if tmp1 not in self.results:
                                evt = SpiderFootEvent("DNS_TXT", tmp1, self.__name__, event)
                                self.results[evt.data] = True
                                self.notifyListeners(evt)

                        if i.get('Type') == "domainnames":
                            tmp1 = i.get('Address')
                            if tmp1 not in self.results:
                                evt = SpiderFootEvent("DOMAIN_NAME", tmp1, self.__name__, event)
                                self.results[evt.data] = True
                                self.notifyListeners(evt)

        if res4:
            data = list()
            if isinstance(res4, dict):
                data.append(res4)
            if isinstance(res4, list):
                data = res4
            for r4 in data:
                if int(r4.get('status')) == 200 and r4.get('vuls'):
                    for i in r4.get('vuls'):
                        tmp1 = r4.get('ip')+'('+','.join(i.get('name')) + ')\r\n' + i.get('title')
                        if tmp1:
                            evt = SpiderFootEvent("VULNERABILITY", tmp1, self.__name__, event)
                            self.notifyListeners(evt)

        if res1 and isinstance(res1, list):
            for r1 in res1:
                if r1.get('type') == 'host':
                    if r1.get('geoinfo') and str(r1.get('geoinfo')) not in self.results:
                        data = r1.get('geoinfo').get('country').get('names').get('cn') + ', ' + r1.get('geoinfo').get('subdivisions').get('names').get('cn') + ', ' + r1.get('geoinfo').get('city').get('names').get('cn')
                        evt = SpiderFootEvent("GEOINFO", data, self.__name__, event)
                        self.notifyListeners(evt)
                        if r1.get('geoinfo').get('asn') and r1.get('geoinfo').get('asn') not in self.results:
                            evt = SpiderFootEvent("BGP_AS_MEMBER", str(r1.get('geoinfo').get('asn')), self.__name__, event)
                            self.results[evt.data] = True
                            self.notifyListeners(evt)

                    if r1.get('portinfo') and r1.get('ip'):
                        tmp1 = r1.get('ip') + ':' + str(r1.get('portinfo').get('port'))
                        if tmp1:
                            pevt = SpiderFootEvent("TCP_PORT_OPEN", tmp1, self.__name__, event)
                            self.notifyListeners(pevt)

                            data = list()
                            if r1.get('portinfo').get('extrainfo'):
                                data.append(r1.get('portinfo').get('extrainfo'))
                            if r1.get('portinfo').get('title'):
                                data += r1.get('portinfo').get('title')
                            data = '\r\n'.join(data)
                            data = tmp1+' =>\r\n' + data
                            evt = SpiderFootEvent("TCP_PORT_OPEN_BANNER", data, self.__name__, pevt)
                            self.notifyListeners(evt)

                            if r1.get('portinfo').get('service'):
                                tmp2 = r1.get('portinfo').get('service')
                                tmp2 = tmp1 + ' => ' + tmp2
                                evt = SpiderFootEvent("TCP_PORT_SERVICE", tmp2, self.__name__, pevt)
                                self.notifyListeners(evt)

                            if r1.get('portinfo').get('product'):
                                tmp2 = r1.get('portinfo').get('product')
                                tmp2 = tmp1 + ' => ' + tmp2
                                evt = SpiderFootEvent("TCP_PORT_PRODUCT", tmp2, self.__name__, pevt)
                                self.notifyListeners(evt)

                            if r1.get('raw_data'):
                                tmp2 = r1.get('raw_data')
                                tmp2 = tmp1 + ' =>\r\n' + tmp2
                                evt = SpiderFootEvent("TCP_PORT_RAW_DATA", tmp2, self.__name__, pevt)
                                self.notifyListeners(evt)

                            if r1.get('portinfo').get('os'):
                                tmp2 = r1.get('portinfo').get('os')
                                tmp2 = r1.get('ip') + ' => ' + tmp2
                                if tmp2 not in self.results:
                                    evt = SpiderFootEvent("OPERATING_SYSTEM", tmp2, self.__name__, event)
                                    self.results[evt.data] = True
                                    self.notifyListeners(evt)

                            if r1.get('os'):
                                tmp2 = r1.get('os')
                                tmp2 = r1.get('ip') + ' => ' + tmp2
                                if tmp2 not in self.results:
                                    evt = SpiderFootEvent("OPERATING_SYSTEM", tmp2, self.__name__, event)
                                    self.results[evt.data] = True
                                    self.notifyListeners(evt)

                    if r1.get('ssl'):
                        evt = SpiderFootEvent("SSL_CERTIFICATE_RAW", r1.get('ssl'), self.__name__, event)
                        self.notifyListeners(evt)

                if r1.get('type') == 'web':
                    if r1.get('geoinfo') and str(r1.get('geoinfo')) not in self.results:
                        data = r1.get('geoinfo').get('country').get('names').get('cn') + ', ' + r1.get('geoinfo').get('subdivisions').get('names').get('cn') + ', ' + r1.get('geoinfo').get('city').get('names').get('cn')
                        evt = SpiderFootEvent("GEOINFO", data, self.__name__, event)
                        self.notifyListeners(evt)
                        if r1.get('geoinfo').get('asn') and r1.get('geoinfo').get('asn') not in self.results:
                            evt = SpiderFootEvent("BGP_AS_MEMBER", str(r1.get('geoinfo').get('asn')), self.__name__, event)
                            self.results[evt.data] = True
                            self.notifyListeners(evt)

                    if r1.get('site'):
                        site = r1.get('site')
                        url = 'http://' + site
                        evt = SpiderFootEvent("WEBSERVER_URL", url, self.__name__, event)
                        self.notifyListeners(evt)

                        if r1.get('server'):
                            for i in r1.get('server'):
                                data = str(i.get('name').get('en') or '') + ' ' + str(i.get('version') or '')
                                data = site + " => " + data
                                evt = SpiderFootEvent("WEBSERVER_APPLICATION", data, self.__name__, event)
                                self.notifyListeners(evt)

                        if r1.get('headers'):
                            data = r1.get('headers')
                            data = site + " =>\r\n" + data
                            evt = SpiderFootEvent("WEBSERVER_BANNER", data, self.__name__, event)
                            self.notifyListeners(evt)

                        if r1.get('ip') and isinstance(r1.get('ip'), list):
                            for ip in r1.get('ip'):
                                evt = SpiderFootEvent("IP_ADDRESS", ip, self.__name__, event)
                                self.notifyListeners(evt)
                            data = ','.join(r1.get('ip'))
                            data = site + " => " + data
                            evt = SpiderFootEvent("WEBSERVER_IP", data, self.__name__, event)
                            self.notifyListeners(evt)

                        if r1.get('title'):
                            data = r1.get('title')
                            data = site + " => " + data
                            evt = SpiderFootEvent("WEBSERVER_TITLE", data, self.__name__, event)
                            self.notifyListeners(evt)

                        if r1.get('os'):
                            data = r1.get('os')
                            data = site + " => " + data
                            evt = SpiderFootEvent("OPERATING_SYSTEM", data, self.__name__, event)
                            self.notifyListeners(evt)

# End of sfp_zoomeye class

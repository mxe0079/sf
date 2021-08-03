# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_fofa
# Purpose:      从FOFA搜集信息
# Author:      Noah AO
# Created:     28/07/2021
# Licence:     GPL
# -------------------------------------------------------------------------------


import base64
from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from lxml import etree
import random
import time


class sfp_fofa(SpiderFootPlugin):

    meta = {
        'name': "FOFA",
        'summary': "从FOFA获取关于已识别的IP地址的信息",
        'flags': [""],
        'useCases': ["Passive", "Footprint"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://fofa.so",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://fofa.so/static_pages/api_help"
            ],
            'favIcon': "https://fofa.so/favicon.ico",
            'logo': "https://fofa.so/_nuxt/img/logo.d9ee5c4.png",
            'description': "FOFA 是白帽汇推出的一款网络空间搜索引擎,它通过进行网络空间测绘,能够帮助研究人员或者企业迅速进行网络资产匹配"
        }
    }

    opts = {
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxdelay': 10
    }

    optdescs = {
        'netblocklookup': "在被认为是你的目标拥有的网络块上查找所有的IP，以寻找同一目标子域/域名上可能的主机",
        'maxnetblock': "网络块大小（CIDR值，24=/24，16=/16，等等）",
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
            # "DOMAIN_NAME",
            "DOMAIN_NAME_PARENT",
            # "IP_ADDRESS",
        ]

    # 本模块产生哪些事件
    def producedEvents(self):
        return [
            "WEBSERVER_URL",
            "WEBSERVER_BANNER",
            "WEBSERVER_IP",
            "WEBSERVER_TITLE",
            "WEBSERVER_APPLICATION",
            "ORG",
            "BGP_AS_MEMBER",
            "SSL_CERTIFICATE_RAW"
        ]

    def processURL(self, qry):
        qry = qry.strip()
        if qry.startswith('https'):
            qry = qry[8:]

        if qry.startswith('http'):
            qry = qry[7:]

        if qry.endswith('/'):
            qry = qry[:-1]

        return qry

    # 当查询第三方时，最好有一个专门的函数来做，避免把它放在handleEvent()中。
    def query(self, qry):
        qbase64 = str(base64.b64encode(qry.encode()), encoding='utf-8')
        res = self.sf.fetchUrl(
            f"https://fofa.so/result?qbase64={qbase64}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
            verify=False
            )

        if res['content'] is None:
            self.sf.info(f"No FOFA info found for {qry}")
            return None

        return res['content']

    # 处理发送到该模块的事件
    def handleEvent(self, event):

        eventName = event.eventType
        eventData = event.data

        # 一旦我们处于这种状态，立即返回.
        if self.errorState:
            return

        # 检查模块是否已经分析了该事件数据
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        # 将事件数据添加到结果字典中，以防止重复查询。如果eventData可能是大的东西，把键设置为值的哈希而不是值，以避免内存的滥用。
        self.results[eventData] = True

        qry = 'host="' + eventData + '"'
        time.sleep(random.randint(1, self.opts['maxdelay']))
        html = self.query(qry)

        if html and isinstance(html, str):
            selector = etree.HTML(html)
            item = selector.xpath('//*[@id="__layout"]/div/div[2]/div/div[2]/div[2]/div[1]/div[1]/p[1]/span[1]/text()')
            item = int(item[0]) if item else 0
            item = 10 if item > 10 else item
            for i in range(1, item+1):
                url = selector.xpath(f'//*[@id="__layout"]/div/div[2]/div/div[2]/div[2]/div[2]/div[{str(i)}]/div[1]/div[1]/span[2]/a/@href')
                if url and isinstance(url, list):
                    url = str(url[0])
                    site = self.processURL(url)
                    pevt = SpiderFootEvent("WEBSERVER_URL", url, self.__name__, event)
                    self.notifyListeners(pevt)

                    ip = selector.xpath(f'//*[@id="__layout"]/div/div[2]/div/div[2]/div[2]/div[2]/div[{str(i)}]/div[2]/div[1]/p[2]/a/text()')
                    if ip and isinstance(ip, list):
                        ip = str(ip[0])
                        data = site + " => " + ip
                        evt = SpiderFootEvent("WEBSERVER_IP", data, self.__name__, pevt)
                        self.notifyListeners(evt)

                    asn = selector.xpath(f'//*[@id="__layout"]/div/div[2]/div/div[2]/div[2]/div[2]/div[{str(i)}]/div[2]/div[1]/p[4]/a/text()')
                    if asn and isinstance(asn, list):
                        asn = str(asn[0])
                        if asn not in self.results:
                            evt = SpiderFootEvent("BGP_AS_MEMBER", asn, self.__name__, event)
                            self.results[evt.data] = True
                            self.notifyListeners(evt)

                    org = selector.xpath(f'//*[@id="__layout"]/div/div[2]/div/div[2]/div[2]/div[2]/div[{str(i)}]/div[2]/div[1]/p[5]/a/text()')
                    if org and isinstance(org, list):
                        org = str(org[0])
                        if org not in self.results:
                            evt = SpiderFootEvent("ORG", org, self.__name__, event)
                            self.results[evt.data] = True
                            self.notifyListeners(evt)

                    title = selector.xpath(f'//*[@id="__layout"]/div/div[2]/div/div[2]/div[2]/div[2]/div[{str(i)}]/div[2]/div[1]/p[1]/text()')
                    if title and isinstance(title, list):
                        title = str(title[0])
                        title = site + " => " + title
                        evt = SpiderFootEvent("WEBSERVER_TITLE", title, self.__name__, pevt)
                        self.notifyListeners(evt)

                    app = selector.xpath(f'//*[@id="__layout"]/div/div[2]/div/div[2]/div[2]/div[2]/div[{str(i)}]/div[2]/div[1]/p[7]/a/text()')
                    if app and isinstance(app, list):
                        app = str(app[0])
                        app = site + " => " + app
                        evt = SpiderFootEvent("WEBSERVER_APPLICATION", app, self.__name__, pevt)
                        self.notifyListeners(evt)

                    banner = selector.xpath(f'//*[@id="__layout"]/div/div[2]/div/div[2]/div[2]/div[2]/div[{str(i)}]/div[2]/div[2]/div[1]/div/div[1]/div/span/text()')
                    if banner and isinstance(banner, list):
                        banner = str(banner[0])
                        banner = site + " =>\r\n" + banner
                        evt = SpiderFootEvent("WEBSERVER_BANNER", banner, self.__name__, pevt)
                        self.notifyListeners(evt)

                    ssl = selector.xpath(f'/html/body/div[1]/div/div/div[2]/div/div[2]/div[2]/div[2]/div[{str(i)}]/div[2]/div[2]/div[2]/div/div[2]/div/div[2]/text()')
                    if ssl and isinstance(ssl, list):
                        ssl = str(ssl[0])
                        evt = SpiderFootEvent("SSL_CERTIFICATE_RAW", ssl, self.__name__, event)
                        self.notifyListeners(evt)

# End of sfp_fofa class

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ip138
# Purpose:      
#
# Author:      Noah AO
#
# Created:     2021-07-21
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from lxml import etree
from netaddr import IPNetwork
import time
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ip138(SpiderFootPlugin):
    meta = {
        'name': "Ip138",
        'summary': "从Ip138获取子域名和域名解析信息",
        'flags': [],
        'useCases': ["Passive", "Footprint"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://site.ip138.com/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://site.ip138.com/"
            ],
            'favIcon': "https://site.ip138.com/favicon.ico",
            'logo': "",
            'description': "IP138"
        }
    }

    opts = {
        'checkcohosts': True,
        'checkaffiliates': True,
    }

    # 选项描述，删除任何不适用于本模块的选项
    optdescs = {
        'checkcohosts': "检查共同托管的网站",
        'checkaffiliates': "检查附属机构",
    }

    # 跟踪结果可以帮助避免报告/处理重复的情况
    results = None

    # 追踪模块的错误状态对于检测第三方的失败和你不希望再处理任何事件是很有用的
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # 这个模块对什么事件的输入感兴趣。关于所有事件的列表，请查看spiderfoot/db.py。
    def watchedEvents(self):
        return [
            "DOMAIN_NAME_PARENT",
            "DOMAIN_NAME"
        ]

    # 本模块产生哪些事件
    def producedEvents(self):
        return [
            "DOMAIN_NAME",
            "AFFILIATE_IPADDRESS"
        ]

    # 当查询第三方时，最好有一个专门的函数来做，避免把它放在handleEvent()中。
    def queryDomain(self, qry):

        res = self.sf.fetchUrl(
            f"https://site.ip138.com/{qry}/domain.htm",
            timeout=self.opts['_fetchtimeout'],
            useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
        )

        if res['content'] is None:
            self.sf.info(f"No ip138 info found for {qry}")
            return None

        # 始终用try/except来处理预期为特定格式的外部数据，因为我们不能相信数据的格式符合预期。
        try:
            selector = etree.HTML(res['content'])
            data = selector.xpath('/html/body/div[1]/div[2]/div[2]/div[2]/div[2]/div[3]/div/div/p/a/text()')
            return data[:-1]
        except Exception as e:
            self.sf.error(f"Error processing get response from Chinaz: {e}")

        return None

    def queryHost(self, qry):
        url = f"https://site.ip138.com/domain/read.do?domain={qry}&time=" + str(int(time.time() * 1000))
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
        )

        if res['content'] is None:
            self.sf.info(f"No ip138 info found for {qry}")
            return None

        # 始终用try/except来处理预期为特定格式的外部数据，因为我们不能相信数据的格式符合预期。
        try:
            data = json.loads(res['content'])
            ips = list()
            for i in data.get('data'):
                ips.append(i.get('ip'))
            return ips
        except Exception as e:
            self.sf.error(f"Error processing get response from Chinaz: {e}")

        return None

    # 处理发送到该模块的事件
    def handleEvent(self, event):
        # SpiderFootEvent中最常用的三个字段是:
        # event.eventType - 事件类型, e.g. INTERNET_NAME, IP_ADDRESS, etc.
        # event.module - 产生该事件的模块名称, e.g. sfp_dnsresolve
        # event.data - 实际数据, e.g. 127.0.0.1. This can sometimes be megabytes in size (e.g. a PDF)
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

        if eventName == 'DOMAIN_NAME_PARENT':
            domains = self.queryDomain(eventData)
            if domains:
                for domain in domains:
                    evt = SpiderFootEvent("DOMAIN_NAME", domain, self.__name__, event)
                    self.notifyListeners(evt)

        if eventName == 'DOMAIN_NAME':
            ips = self.queryHost(eventData)
            if ips:
                for ip in ips:
                    if ip not in self.results:
                        evt = SpiderFootEvent("AFFILIATE_IPADDRESS", ip, self.__name__, event)
                        self.results[evt.data] = True
                        self.notifyListeners(evt)

# End of sfp_ip138 class

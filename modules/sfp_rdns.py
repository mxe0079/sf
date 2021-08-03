# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_rdns
# Purpose:      
# Author:      Noah AO
# Created:     02/08/2021
# Licence:     GPL
# -------------------------------------------------------------------------------

from lxml import etree
from netaddr import IPNetwork
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_rdns(SpiderFootPlugin):
    meta = {
        'name': "rDNS",
        'summary': "从rDNS获取域名信息",
        'flags': [],
        'useCases': ["Passive", "Footprint"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://rdnsdb.com/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://rdnsdb.com/"
            ],
            'favIcon': "https://rdnsdb.com/favicon.ico",
            'description': "通过IP反向解析到域名"
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
            "IP_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCK_MEMBER"
        ]

    # 本模块产生哪些事件
    def producedEvents(self):
        return [
            "RDNS",
            "IP_ADDRESS",
            "DOMAIN_NAME"
        ]

    def check(self, qry):
        if self.sf.validIP(qry):
            tmp = qry.split('.')
            qry = tmp[0]+'.'+tmp[1]+'.'+tmp[2]+'.0/24'
            if qry not in self.results:
                self.results[qry] = True
                return True
            else:
                return False
        else:
            return False

    # 当查询第三方时，最好有一个专门的函数来做，避免把它放在handleEvent()中。
    def query(self, qry):
        if self.check(qry):
            try:
                res = self.sf.fetchUrl(
                    f"https://rdnsdb.com/{qry}",
                    timeout=self.opts['_fetchtimeout'],
                    useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
                )
                html = etree.HTML(res['content'])
                ips = html.xpath('/html/body/div/div[2]/div/div[1]/div[1]/div/div[2]/div/table/tbody/tr/td[2]/a/text()')
                domains = html.xpath('/html/body/div/div[2]/div/div[1]/div[1]/div/div[2]/div/table/tbody/tr/td[3]/span/text()')
                return ips, domains
            except Exception as e:
                self.sf.error(f"Error processing get response from rdns: {e}")
        return None

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

        result = list()
        if eventName == 'IP_ADDRESS':
            tmp = eventData.split('.')
            data = tmp[0]+'.'+tmp[1]+'.'+tmp[2]+'.0/24'
            if data not in self.results:
                self.results[data] = True
                result = self.query(data)
            else:
                self.sf.debug(f"Skipping {data}, already checked.")
                return

        if eventName in ["NETBLOCK_OWNER", "NETBLOCK_MEMBER"]:
            data = eventData
            result = self.query(data)

        if result and isinstance(result, list):
            ips, domains = result[0], result[1]
            if ips and domains:
                length = len(ips) if len(ips) < len(domains) else len(domains)
                for i in range(length):
                    tmp = ips[i] + ' : ' + domains[i]
                    pevt = SpiderFootEvent("RDNS", tmp, self.__name__, event)
                    self.notifyListeners(pevt)
                    evt = SpiderFootEvent("IP_ADDRESS", ips[i], self.__name__, pevt)
                    self.notifyListeners(evt)
                    evt = SpiderFootEvent("DOMAIN_NAME", domains[i], self.__name__, pevt)
                    self.notifyListeners(evt)

# End of sfp_rdns class

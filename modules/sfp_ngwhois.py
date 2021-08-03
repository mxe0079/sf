# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ngwhois
# Purpose:      whois信息收集
# Author:      Noah AO
# Created:     28/07/2021
# Licence:     GPL
# -------------------------------------------------------------------------------

from lxml import etree
from netaddr import IPNetwork
import requests
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ngwhois(SpiderFootPlugin):

    meta = {
        'name': "NGwhois",
        'summary': "域名Whois信息查询",
        'flags': [],
        'useCases': ["Passive", "Footprint"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "http://140.143.241.232:8080/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "http://140.143.241.232:8080/doc",
                "https://whois.zhuonao.net/"
            ],
            # 数据源的图标的URL
            'favIcon': "http://140.143.241.232:8080/favicon.ico",

            # 数据源的全尺寸logo的URL.
            'logo': "http://140.143.241.232:8080/img/ng-primary.png",

            # 关于数据源的一两段话
            'description': "域名查询，查出谁拥有这个网站"
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
            "NETBLOCK_MEMBER",
            "NETBLOCK_OWNER",
        ]

    # 本模块产生哪些事件
    def producedEvents(self):
        return [
            "DOMAIN_WHOIS",
            "NETBLOCK_WHOIS"
        ]

    # 当查询第三方时，最好有一个专门的函数来做，避免把它放在handleEvent()中。
    def query1(self, qry):

        data = {'domain': qry}
        res = self.sf.fetchUrl(
            "http://140.143.241.232:8080/whois",
            timeout=self.opts['_fetchtimeout'],
            useragent="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0",
            postData=data
        )

        if res['content'] is None:
            self.sf.info(f"No whois info found for {qry}")
            return None

        try:
            selector = etree.HTML(res['content'])
            r = selector.xpath('//*[@id="main"]/section[2]/div/div/div[2]/text()')[0]
            if "Domain not found" in r:
                return None
            return r
        except Exception as e:
            self.sf.error(f"Error processing xpath response from NGWhois: {e}")

        return None

    def query2(self, qry):

        data = {'domain': qry}
        res = requests.post(
            "https://whois.zhuonao.net/lookup.php",
            data=data,
            verify=False
        )

        if res.text is None:
            self.sf.info(f"No whois info found for {qry}")
            return None

        if 'Invalid Input!' in res.text:
            self.sf.info(f"No whois info found for {qry}")
            return None

        return res.text


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

        if eventName == 'DOMAIN_NAME_PARENT':
            data = self.query1(eventData)
            if data:
                evt = SpiderFootEvent("DOMAIN_WHOIS", data, self.__name__, event)
                self.notifyListeners(evt)

        if eventName == 'DOMAIN_NAME_PARENT':
            data = self.query2(eventData)
            if data:
                evt = SpiderFootEvent("DOMAIN_WHOIS", data, self.__name__, event)
                self.notifyListeners(evt)

        if eventName in ['NETBLOCK_MEMBER', 'NETBLOCK_OWNER']:
            data = self.query2(str(IPNetwork(eventData).ip))
            if data:
                evt = SpiderFootEvent("NETBLOCK_WHOIS", data, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_namegee class

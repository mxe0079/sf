# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_rapid_dns
# Purpose:     获取获取子域名和IP信息
# Author:      Noah AO
# Created:     26/07/2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import time
import random
from lxml import etree
from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_rapid_dns(SpiderFootPlugin):
    meta = {
        'name': "Rapid Dns",
        'summary': "从RapidDns获取获取子域名和IP信息",
        'flags': [""],
        'useCases': ["Passive", "Footprint"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "https://rapiddns.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://rapiddns.io/subdomain",
                "https://rapiddns.io/sameip"
            ],
            'favIcon': "https://rapiddns.io/",
            'logo': "https://rapiddns.io/static/img/avatar.jpg",
            'description': "获取子域名和IP"
        }
    }

    opts = {
        'checkaffiliates': True,
        'netblocklookup': True,
        'maxnetblock': 16,
        'maxdelay': 3
    }

    # 选项描述，删除任何不适用于本模块的选项
    optdescs = {
        'checkaffiliates': "检查附属机构",
        'netblocklookup': "目标拥有的子网络块上查找所有的IP，以寻找同一目标子域/域名上可能的主机",
        'maxnetblock': "查询所有IP的最大子网络块大小（CIDR值，24=/24，16=/16，等等）",
        'maxdelay': "最大延时"
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
            "AFFILIATE_DOMAIN_NAME_PARENT",
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCK_MEMBER",
        ]

    # 本模块产生哪些事件
    def producedEvents(self):
        return [
            "DNS_A",
            "DNS_AAAA",
            "DNS_MX",
            "DNS_CERTIFICATE",
            "DOMAIN",
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDRESS",
            "AFFILIATE_DOMAIN_NAME"
        ]

    def judgeDomain(self, data):
        if data and isinstance(data, str):
            if 'cdn' in data:
                return False
            tmp = data.split('.')
            if len(tmp[0]) > 11 and tmp[0][0].isdigit():
                return False
            else:
                return True
        return False

    # 当查询第三方时，最好有一个专门的函数来做，避免把它放在handleEvent()中。
    def queryDomain(self, qry):

        res = self.sf.fetchUrl(
            f"https://rapiddns.io/subdomain/{qry}?full=1",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.sf.info(f"No RapidDns info found for {qry}")
            return None

        # 始终用try/except来处理预期为特定格式的外部数据，因为我们不能相信数据的格式符合预期。
        try:
            selector = etree.HTML(res['content'])
            domains = selector.xpath('//*[@id="table"]/tbody/tr/td[1]/a/text()')
            addresses = selector.xpath('//*[@id="table"]/tbody/tr/td[2]/a/text()')
            types = selector.xpath('//*[@id="table"]/tbody/tr/td[3]/text()')
            return [domains, addresses, types]
        except Exception as e:
            self.sf.error(f"Error processing response from RapidDns: {e}")
            return None

    def queryCIDR(self, qry):

        domains, addresses, types = list(), list(), list()
        try:
            res = self.sf.fetchUrl(
                f"https://rapiddns.io/sameip/{qry}",
                timeout=self.opts['_fetchtimeout'],
                useragent=self.opts['_useragent']
            )
            selector = etree.HTML(res['content'])
            page = selector.xpath('/html/body/section[2]/div/div/div[1]/div[1]/div[3]/span/text()')
        except Exception as e:
            self.sf.error(f"Error processing response from RapidDns: {e}")
            return None
        page = int(page[0] or 0) // 100 + 1
        for i in range(page):
            res = self.sf.fetchUrl(
                f"https://rapiddns.io/sameip/{qry}?page={i}",
                timeout=self.opts['_fetchtimeout'],
                useragent=self.opts['_useragent']
            )

            if res['content'] is None:
                self.sf.info(f"No RapidDns info found for {qry}")
                break

            # 始终用try/except来处理预期为特定格式的外部数据，因为我们不能相信数据的格式符合预期。
            try:
                selector = etree.HTML(res['content'])
                domain = selector.xpath('//*[@id="table"]/tbody/tr/td[1]/a/text()')
                address = selector.xpath('//*[@id="table"]/tbody/tr/td[2]/a/text()')
                itype = selector.xpath('//*[@id="table"]/tbody/tr/td[3]/text()')
                if not domain or not address or not itype:
                    break
                domains += domain
                addresses += address
                types += itype
            except Exception as e:
                self.sf.error(f"Error processing response from RapidDns: {e}")
                break

        return [domains, addresses, types]

    # 创建添加事件的函数
    def addEvent(self, domains, addresses, types, length, event, flag):
        for i in range(length):
            if not self.judgeDomain(domains[i]):
                continue
            data = domains[i] + " : " + addresses[i]
            if data in self.results:
                self.sf.debug(f"Skipping {domains[i]}, already checked.")
                continue
            if flag:
                if types[i] == 'A':
                    evt = SpiderFootEvent("DNS_A", data, self.__name__, event)
                    self.notifyListeners(evt)
                if types[i] == 'AAAA':
                    evt = SpiderFootEvent("DNS_AAAA", data, self.__name__, event)
                    self.notifyListeners(evt)
                if types[i] == 'DNS_MX':
                    evt = SpiderFootEvent("DNS_MX", data, self.__name__, event)
                    self.notifyListeners(evt)
                    evt = SpiderFootEvent("AFFILIATE_DOMAIN_NAME", addresses[i], self.__name__, event)
                    self.notifyListeners(evt)
                if types[i] == 'DNS_CERTIFICATE':
                    evt = SpiderFootEvent("DNS_CERTIFICATE", data, self.__name__, event)
                    self.notifyListeners(evt)
                    if '*' not in domains[i]:
                        evt = SpiderFootEvent("AFFILIATE_DOMAIN_NAME", domains[i], self.__name__, event)
                        self.notifyListeners(evt)
                if types[i] in ['A', 'CERTIFICATE']:
                    if addresses[i] not in ['127.0.0.1']:
                        evt = SpiderFootEvent("IP_ADDRESS", addresses[i], self.__name__, event)
                        self.notifyListeners(evt)
                if types[i] in ['A', 'AAAA', 'CNAME']:
                    evt = SpiderFootEvent("AFFILIATE_DOMAIN_NAME", domains[i], self.__name__, event)
                    self.notifyListeners(evt)
            else:
                if data in self.results:
                    self.sf.debug(f"Skipping {domains[i]}, already checked.")
                    continue
                if types[i] == 'A':
                    evt = SpiderFootEvent("DNS_A", data, self.__name__, event)
                    self.notifyListeners(evt)
                if types[i] == 'AAAA':
                    evt = SpiderFootEvent("DNS_AAAA", data, self.__name__, event)
                    self.notifyListeners(evt)
                    evt = SpiderFootEvent("IPV6_ADDRESS", addresses[i], self.__name__, event)
                    self.notifyListeners(evt)
                if types[i] == 'DNS_MX':
                    evt = SpiderFootEvent("DNS_MX", data, self.__name__, event)
                    self.notifyListeners(evt)
                    evt = SpiderFootEvent("DOMAIN_NAME", addresses[i], self.__name__, event)
                    self.notifyListeners(evt)
                if types[i] == 'DNS_CERTIFICATE':
                    evt = SpiderFootEvent("DNS_CERTIFICATE", data, self.__name__, event)
                    self.notifyListeners(evt)
                    if '*' not in domains[i]:
                        evt = SpiderFootEvent("DOMAIN_NAME", domains[i], self.__name__, event)
                        self.notifyListeners(evt)
                if types[i] in ['A', 'CERTIFICATE']:
                    if addresses[i] not in ['127.0.0.1']:
                        evt = SpiderFootEvent("AFFILIATE_IP_ADDRESS", addresses[i], self.__name__, event)
                        self.notifyListeners(evt)
                if types[i] in ['A', 'AAAA']:
                    evt = SpiderFootEvent("DOMAIN_NAME", domains[i], self.__name__, event)
                    self.notifyListeners(evt)

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

        time.sleep(random.randint(1, self.opts['maxdelay']))

        if eventName in ["IP_ADDRESS", "AFFILIATE_IPADDR"]:
            tmp = eventData.split('.')
            tmp = tmp[:-1]
            eventData = '.'.join(tmp)
            eventData += '.0/24'
            event.data = eventData

            if eventData in self.results:
                self.sf.debug(f"Skipping {eventData}, already checked.")
                return

            self.results[eventData] = True

        if eventName in ["DOMAIN_NAME_PARENT", "AFFILIATE_DOMAIN_NAME_PARENT"]:
            result = self.queryDomain(eventData)
            if isinstance(result, list):
                domains, addresses, types = result[0], result[1], result[2]
                length = len(domains) if len(domains) <= len(addresses) else len(addresses)
                length = length if length <= len(types) else len(types)
                if length == 0:
                    return
                self.addEvent(domains, addresses, types, length, event, False)

        if eventName in ["IP_ADDRESS", "AFFILIATE_IPADDRESS", "NETBLOCK_OWNER", "NETBLOCK_MEMBER"]:

            if not self.opts['netblocklookup']:
                return

            max_netblock = self.opts['maxnetblock']
            net_size = IPNetwork(eventData).prefixlen
            if net_size < max_netblock:
                self.sf.debug(f"Network size {net_size} bigger than permitted: {max_netblock}")
                return

            # 最后直接处理CIDR
            result = self.queryCIDR(eventData)
            if isinstance(result, list):
                domains, addresses, types = result[0], result[1], result[2]

                length = len(domains) if len(domains) <= len(addresses) else len(addresses)
                length = length if length <= len(types) else len(types)
                if length == 0:
                    self.sf.info(f"No RapidDns info found for {eventData}")
                    return

                self.addEvent(domains, addresses, types, length, event, True)

# End of sfp_rapid_dns class

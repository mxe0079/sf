# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_phpinfo
# Purpose:      获取子域名和IP信息
# Author:      Noah AO
# Created:     26/07/2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_phpinfo(SpiderFootPlugin):

    meta = {
        'name': "Phpinfo",
        'summary': "从phpinfo.me网站进行子域名的扫描",
        'flags': ["slow"],
        'useCases': ["Passive", "Footprint"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://phpinfo.me/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://phpinfo.me/domain/"
            ],
            'favIcon': "",
            'logo': "",
            'description': "在线子域名爆破"
        }
    }

    opts = {
        'checkaffiliates': True,
        'level': 0
    }

    optdescs = {
        'checkaffiliates': "检查相关联信息",
        'level': '设置子域名字典的等级(0, 1, 2), 等级越高字典越大，扫描时间越长'
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
            "DOMAIN_NAME_PARENT",
        ]

    # 本模块产生哪些事件
    def producedEvents(self):
        return [
            "DOMAIN_NAME",
            "AFFILIATE_IPADDRESS",
        ]

    def judgeIP(self, data):
        if data and isinstance(data, str):
            if '127.0.0.1' in data:
                return False
            else:
                return True
        return False

    # 当查询第三方时，最好有一个专门的函数来做，避免把它放在handleEvent()中。
    def query(self, qry, dist):
        try:
            res = self.sf.fetchUrl(
                f"https://phpinfo.me/domain/?domain={qry}&q={dist}",
                timeout=self.opts['_fetchtimeout'],
                useragent=self.opts['_useragent'],
                verify=False
            )
        except Exception as e:
            self.sf.error(f"phpinfo get 请求错误: {e}")
            return None

        if res['content'] is None:
            self.sf.info(f"No info found for {qry}")
            return None

        try:
            r = json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from phpinfo: {e}")
            return None

        if int(r.get('status')) == 200:
            return r
        else:
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

        if eventName == 'DOMAIN_NAME_PARENT':
            dists = list()
            self.opts['level'] = 2 if self.opts['level'] > 2 else self.opts['level']
            self.opts['level'] = 0 if self.opts['level'] < 0 else self.opts['level']
            try:
                with open(f"spiderfoot/dicts/subdomains_{str(self.opts['level'])}.txt", 'r') as f:
                    dists = f.readlines()
            except Exception as e:
                self.sf.error(f"Error opening file from phpinfo: {e}")
            for dist in dists:
                res = self.query(eventData, dist)
                if not res:
                    continue

                if res.get('domain') and res.get('domain') not in self.results:
                    evt = SpiderFootEvent("DOMAIN_NAME", res.get('domain'), self.__name__, event)
                    self.results[evt.data] = True
                    self.notifyListeners(evt)
                    if self.judgeIP(res.get('ip')):
                        evt = SpiderFootEvent("AFFILIATE_IPADDRESS", res.get('ip'), self.__name__, event)
                        self.results[evt.data] = True
                        self.notifyListeners(evt)

# End of sfp_phpinfo class

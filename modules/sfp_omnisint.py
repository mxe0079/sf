# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_omnisint
# Purpose:      获取子域名
# Author:      Noah AO
# Created:     02/08/2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_omnisint(SpiderFootPlugin):
    meta = {
        'name': "Omnisint",
        'summary': "从omnisint.io获取子域名信息",
        'flags': [""],
        'useCases': ["Passive", "Footprint"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://sonar.omnisint.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://sonar.omnisint.io/"
            ],
            'favIcon': "",
            'logo': "",
            'description': "z子域名信息库"
        }
    }

    opts = {}

    optdescs = {}

    results = None

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
        ]

    # 本模块产生哪些事件
    def producedEvents(self):
        return [
            "DOMAIN_NAME"
        ]

    # 当查询第三方时，最好有一个专门的函数来做，避免把它放在handleEvent()中。
    def query(self, qry):

        res = self.sf.fetchUrl(
            f"https://sonar.omnisint.io/subdomains/{qry}",
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.sf.info(f"No Omnisint info found for {qry}")
            return None

        # 始终用try/except来处理预期为特定格式的外部数据，因为我们不能相信数据的格式符合预期。
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from Ominisint: {e}")

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
            data = self.query(eventData)
            if data and isinstance(data, list):
                data = list(set(data))
                for i in data:
                    evt = SpiderFootEvent('DOMAIN_NAME', i, self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_omnisint class

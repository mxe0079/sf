# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_skymem
# Purpose:      获取邮箱信息
# Author:      Noah AO
# Created:     26/07/2021
# Licence:     GPL
# -------------------------------------------------------------------------------

from lxml import etree
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_skymem(SpiderFootPlugin):
    meta = {
        'name': "Skymem",
        'summary': "从skymem获取邮箱信息",
        'flags': [""],
        'useCases': ["Passive", "Footprint"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.skymem.info/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://www.skymem.info/"
            ],
            'favIcon': "",
            'logo': "",
            'description': "邮箱搜索"
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

    def watchedEvents(self):
        return [
            "DOMAIN_NAME_PARENT",
        ]

    # 本模块产生哪些事件
    def producedEvents(self):
        return [
            "EMAILADDR"
        ]

    # 当查询第三方时，最好有一个专门的函数来做，避免把它放在handleEvent()中。
    def query(self, qry):

        res = self.sf.fetchUrl(
            f"https://www.skymem.info/srch?q={qry}&ss=srch",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.sf.info(f"No skymem info found for {qry}")
            return None

        # 始终用try/except来处理预期为特定格式的外部数据，因为我们不能相信数据的格式符合预期。
        try:
            selector = etree.HTML(res['content'])
            results = selector.xpath('/html/body/main/div/div/div/div[2]/div[1]/div/table/tbody/tr/td[2]/a/text()')
            return results
        except Exception as e:
            self.sf.error(f"Error processing get response from skymem: {e}")

        return None

    # 处理发送到该模块的事件
    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'DOMAIN_NAME_PARENT':
            data = self.query(eventData)
            for i in data:
                evt = SpiderFootEvent("EMAILADDR", i, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_skymem class

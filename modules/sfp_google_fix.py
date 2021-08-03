# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_google_fix
# Purpose:      从Google-Fix获取文件路径
# Author:      Noah AO
# Created:     26/07/2021
# Licence:     GPL
# -------------------------------------------------------------------------------


import re
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_google_fix(SpiderFootPlugin):
    # 模块描述符字典包含了所有关于模块的元数据，这些数据对用户来说是必要的，以了解...
    meta = {
        'name': "Google-Fix",
        'summary': "从Google-Fix获取文件路径",
        'flags': [""],
        'useCases': ["Passive", "Footprint"],
        'categories': ["Search Engines"],
        'dataSource': {
            # 数据源的主要网站URL
            'website': "https://www.google-fix.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.google-fix.com/search?q=a&&start=0"
            ],
            'favIcon': "https://www.google-fix.com/favicon.ico",

            # 数据源的全尺寸logo的URL.
            'logo': "https://www.google-fix.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png",

            # 关于数据源的一两段话
            'description': "Google搜索引擎"
        }
    }

    opts = {
        'checkaffiliates': True,
    }

    # 选项描述，删除任何不适用于本模块的选项
    optdescs = {
        'checkaffiliates': "检查相关联信息",
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
            "WEBSERVER_URL",
        ]

    # 本模块产生哪些事件
    def producedEvents(self):
        return [
            "WEBSERVER_PATH"
        ]

    def processQry(self, qry):
        qry = qry.strip()

        if qry.endswith('/'):
            qry = qry[:-1]

        qry = qry.split(':')
        return qry[0]

    # 当查询第三方时，最好有一个专门的函数来做，避免把它放在handleEvent()中。
    def query(self, qry):

        self.processQry(qry)
        res = []
        for i in range(17):
            url = f"https://www.google-fix.com/search?q=inurl:{qry}&&start={i}"
            r = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
            if r['content'] is None:
                self.sf.error("Received no content from Google Fix")
                return res

            if "建议" in r['content']:
                self.sf.info(f"The information of {qry} of google-fix is done")
                break

            pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            res += re.findall(pattern, r['content'])

        return res

    # 处理发送到该模块的事件
    def handleEvent(self, event):

        eventName = event.eventType
        eventData = event.data

        # 一旦我们处于这种状态，立即返回.
        if self.errorState:
            return

        # 检查模块是否已经分析了该事件数据
        if self.sf.hashstring(eventData) in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        # 将事件数据添加到结果字典中，以防止重复查询。如果eventData可能是大的东西，把键设置为值的哈希而不是值，以避免内存的滥用。
        self.results[self.sf.hashstring(eventData)] = True

        if eventName =='WEBSERVER_URL':
            res = self.query(eventData)
            data = '\r\n'.join(res)
            if data:
                evt = SpiderFootEvent('WEBSERVER_PATH', data, self.__name__, event)
                self.notifyListeners(evt)


# End of sfp_google_fix class

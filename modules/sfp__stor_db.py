# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_stor_db
# Purpose:      存储事件到数据库
# Author:      Noah AO
# Created:     23/07/2021
# Licence:     GPL
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootPlugin


class sfp__stor_db(SpiderFootPlugin):

    meta = {
        'name': "Storage",
        'summary': "将扫描结果存入后端SpiderFoot数据库(此模块必须存在)"
    }

    _priority = 0

    # 默认设置
    opts = {
        'maxstorage': 1024,  #
        '_store': True
    }

    # 描述
    optdescs = {
        'maxstorage': "检索到的任何信息所要存储的最大字节数（0=无限）"
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # 此模块监听的事件
    def watchedEvents(self):
        return ["*"]

    # 处理事件函数
    def handleEvent(self, sfEvent):
        if not self.opts['_store']:
            return

        if self.opts['maxstorage'] != 0:
            if len(sfEvent.data) > self.opts['maxstorage']:
                self.sf.debug("Storing an event: " + sfEvent.eventType)
                self.__sfdb__.scanEventStore(self.getScanId(), sfEvent, self.opts['maxstorage'])
                return

        self.sf.debug("Storing an event: " + sfEvent.eventType)
        self.__sfdb__.scanEventStore(self.getScanId(), sfEvent)

# End of sfp__stor_db class

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_stor_db
# Purpose:      输出事件到标准输出流
# Author:      Noah AO
# Created:     23/07/2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootPlugin


class sfp__stor_stdout(SpiderFootPlugin):

    meta = {
        'name': "Command-line output",
        'summary': "将输出转储到标准输出, 当SpiderFoot扫描通过命令行运行时使用"
    }

    _priority = 0
    firstEvent = True

    # 默认配置
    opts = {
        "_format": "tab",  # tab, csv, json
        "_requested": [],
        "_showonlyrequested": False,
        "_stripnewline": False,
        "_showsource": False,
        "_csvdelim": ",",
        "_maxlength": 0,
        "_eventtypes": dict()
    }

    # 配置描述
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # 监听事件类型
    def watchedEvents(self):
        return ["*"]

    def output(self, event):
        d = self.opts['_csvdelim']
        if type(event.data) in [list, dict]:
            data = str(event.data)
        else:
            data = event.data

        if type(data) != str:
            data = str(event.data)

        if type(event.sourceEvent.data) in [list, dict]:
            srcdata = str(event.sourceEvent.data)
        else:
            srcdata = event.sourceEvent.data

        if type(srcdata) != str:
            srcdata = str(event.sourceEvent.data)

        if self.opts['_stripnewline']:
            data = data.replace("\n", " ").replace("\r", "")
            srcdata = srcdata.replace("\n", " ").replace("\r", "")

        if "<SFURL>" in data:
            data = data.replace("<SFURL>", "").replace("</SFURL>", "")
        if "<SFURL>" in srcdata:
            srcdata = srcdata.replace("<SFURL>", "").replace("</SFURL>", "")

        if self.opts['_maxlength'] > 0:
            data = data[0:self.opts['_maxlength']]
            srcdata = srcdata[0:self.opts['_maxlength']]

        if self.opts['_format'] == "tab":
            if self.opts['_showsource']:
                print(('{0:30}\t{1:45}\t{2}\t{3}'.format(event.module, self.opts['_eventtypes'][event.eventType], srcdata, data)))
            else:
                print(('{0:30}\t{1:45}\t{2}'.format(event.module, self.opts['_eventtypes'][event.eventType], data)))

        if self.opts['_format'] == "csv":
            print((event.module + d + self.opts['_eventtypes'][event.eventType] + d + srcdata + d + data))

        if self.opts['_format'] == "json":
            d = event.asDict()
            d['type'] = self.opts['_eventtypes'][event.eventType]
            if self.firstEvent:
                self.firstEvent = False
            else:
                print(",")
            print(json.dumps(d), end='')

    # 处理事件函数
    def handleEvent(self, sfEvent):
        if sfEvent.eventType == "ROOT":
            return

        if self.opts['_showonlyrequested']:
            if sfEvent.eventType in self.opts['_requested']:
                self.output(sfEvent)
        else:
            self.output(sfEvent)

# End of sfp__stor_stdout class

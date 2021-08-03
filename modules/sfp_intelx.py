# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_intelx
# Purpose:      Query IntelligenceX (intelx.io) for identified IP addresses,
#               domains, e-mail addresses and phone numbers.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     28/04/2019
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import datetime
import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_intelx(SpiderFootPlugin):

    meta = {
        'name': "IntelligenceX",
        'summary': "从IntelligenceX获得关于已确定的IP地址，域名，电子邮件地址的信息",
        'flags': ["apikey"],
        'useCases': ["Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://intelx.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://ginseg.com/wp-content/uploads/sites/2/2019/07/Manual-Intelligence-X-API.pdf",
                "https://blog.intelx.io/2019/01/25/new-developer-tab/",
                "https://github.com/IntelligenceX/SDK"
            ],
            'apiKeyInstructions': [
                "访问 https://intelx.io/",
                "注册账号",
                "访问 https://intelx.io/account?tab=developer",
            ],
            'favIcon': "https://intelx.io/favicon/favicon-32x32.png",
            'logo': "https://intelx.io/assets/img/IntelligenceX.svg",
            'description': "Intelligence X是一家独立的欧洲技术公司，由Peter Kleissner于2018年创立",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "base_url": "public.intelx.io",
        "checkcohosts": False,
        "checkaffiliates": False,
        'netblocklookup': False,
        'maxnetblock': 24,
        'subnetlookup': False,
        'maxsubnet': 24,
        'maxage': 90
    }

    # Option descriptions
    optdescs = {
        "api_key": "IntelligenceX API key",
        "base_url": "API URL，如你的IntelligenceX账户设置中提供的",
        "checkcohosts": "检查共同托管的网站",
        "checkaffiliates": "检查关联网站",
        'netblocklookup': "查找被认为是你的目标拥有的网块上的所有IP，以寻找同一目标子域/域名上的可能主机",
        'maxnetblock': "如果查询拥有的网块，要查询所有IP的最大网络块大小（CIDR值，24=/24，16=/16，等等）",
        'subnetlookup': "查询你的目标所处的子网的所有IP",
        'maxsubnet': "如果查询子网，要查询其中所有IP的最大子网大小（CIDR值，24=/24，16=/16，等等）",
        'maxage': "被视为有效的结果的最大天数"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "DOMAIN_NAME_PARENT", "INTERNET_NAME", "PHONE_NUMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["WEBSERVER_PATH", "INTERNET_NAME", "DOMAIN_NAME",
                "EMAILADDR", "EMAILADDR_GENERIC", "LINKED_URL"]

    def query(self, qry, qtype, t):
        retdata = list()

        headers = {
            "User-Agent":  self.opts['_useragent'],
            "x-key": self.opts['api_key'],
        }

        payload = {
            "term": qry,
            "maxresults": 10000,
            "timeout": 20,
            "target": t,
            "media": 0,
            "terminate": []
        }

        url = 'https://' + self.opts['base_url'] + '/' + qtype + '/search'
        res = self.sf.fetchUrl(url, postData=json.dumps(payload),
                               headers=headers, timeout=self.opts['_fetchtimeout'])

        if res['content'] == "":
            self.sf.info("No IntelligenceX info found for " + qry)
            return None

        if res['code'] == "402":
            self.sf.info("IntelligenceX credits expired.")
            self.errorState = True
            return None

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from IntelligenceX: {e}")
            self.errorState = True
            return None

        if ret.get('status', -1) == 0:
            # Craft API URL with the id to return results
            resulturl = f"{url}/result?k={self.opts['api_key']}&id={ret['id']}"
            if self.checkForStop():
                return None

            res = self.sf.fetchUrl(resulturl, headers=headers)
            if not res['content']:
                self.sf.info("No IntelligenceX info found for results from " + qry)
                return None

            if res['code'] == "402":
                self.sf.info("IntelligenceX credits expired.")
                self.errorState = True
                return None

            try:
                ret = json.loads(res['content'])
                return ret
            except Exception as e:
                self.sf.error("Error processing JSON response from IntelligenceX: " + str(e))
                return None

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if self.opts['api_key'] == "" or self.opts['base_url'] == "":
            self.sf.error("You enabled sfp_intelx but did not set an API key and/or base URL!")
            self.errorState = True
            return None

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None

        self.results[eventData] = True

        data1 = self.query(eventData, "phonebook", 2)
        if data1 is None:
            return None

        data2 = self.query(eventData, "phonebook", 3)
        if data2 is None:
            return None

        data = list()
        data += data1.get("selectors", dict())
        data += data2.get("selectors", dict())

        self.sf.info(f"Found IntelligenceX host and email data for {eventData}")
        for rec in data:
            try:
                val = rec['selectorvalueh']
                evt = None
                if rec['selectortype'] == 1:  # Email
                    evt = "EMAILADDR"
                    if val.split("@")[0] in self.opts['_genericusers'].split(","):
                        evt = "EMAILADDR_GENERIC"
                if rec['selectortype'] == 2:  # Domain
                    evt = "INTERNET_NAME"
                    if val == eventData:
                        continue
                if rec['selectortype'] == 3:  # URL
                    evt = "LINKED_URL"

                if not val or not evt:
                    self.sf.debug("Unexpected record, skipping.")
                    continue
            except Exception as e:
                self.sf.error(f"Error processing content from IntelX: {e}")
                continue

            # Notify other modules of what you've found
            e = SpiderFootEvent(evt, val, self.__name__, event)
            self.notifyListeners(e)

            if evt == "INTERNET_NAME" and self.sf.isDomain(val, self.opts['_internettlds']):
                e = SpiderFootEvent("DOMAIN_NAME", val, self.__name__, event)
                self.notifyListeners(e)

# End of sfp_intelx class

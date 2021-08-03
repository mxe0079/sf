# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_robtex
# Purpose:      Searches Robtex.com for hosts sharing the same IP.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_robtex(SpiderFootPlugin):

    meta = {
        'name': "Robtex",
        'summary': "在Robtex.com上搜索共享同一IP的主机",
        'flags': [""],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "https://www.robtex.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.robtex.com/api/"
            ],
            'favIcon': "https://www.robtex.com/favicon.ico",
            'logo': "https://www.robtex.com/favicon.ico",
            'description': "Robtex用于IP号码、域名等的各种研究",
        }
    }

    # Default options
    opts = {
        'verify': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'cohostsamedomain': False,
        'maxcohost': 100,
        'subnetlookup': False,
        'maxsubnet': 24
    }

    # Option descriptions
    optdescs = {
        'verify': "通过检查共同主机是否仍然解析到共享IP，来验证共同主机是否有效",
        'netblocklookup': "在被认为是你的目标拥有的网块上查找所有的IP，以寻找同一目标子域/域名上可能的共同主机",
        'maxnetblock': "如果查询拥有的网块，要查询所有IP的最大网块大小（CIDR值，24=/24，16=/16，等等）",
        'cohostsamedomain': "将同一目标域上的共同托管网站视为共同托管",
        'maxcohost': "在多个共同托管的网站后，停止报告，因为这很可能表明是网络托管",
        'subnetlookup': "查询你的目标所处的子网的所有IP",
        'maxsubnet': "如果查询子网，要查询其中所有IP的最大子网大小（CIDR值，24=/24，16=/16，等等）"
    }

    results = None
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER", "NETBLOCK_MEMBER"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["AFFILIATE_INTERNET_NAME", "IP_ADDRESS"]

    # Don't notify me about events from myself
    def watchOpts(self):
        return ['noself']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.cohostcount > self.opts['maxcohost']:
            return

        if srcModuleName == "sfp_robtex" and eventName == "IP_ADDRESS":
            self.sf.debug("Ignoring " + eventName + ", from self.")
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                    self.sf.debug("Network size bigger than permitted: "
                                  + str(IPNetwork(eventData).prefixlen) + " > "
                                  + str(self.opts['maxnetblock']))
                    return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                    self.sf.debug("Network size bigger than permitted: "
                                  + str(IPNetwork(eventData).prefixlen) + " > "
                                  + str(self.opts['maxsubnet']))
                    return

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)
            self.results[eventData] = True

        for ip in qrylist:
            if self.checkForStop():
                return

            retry = 0
            while retry < 2:
                res = self.sf.fetchUrl("https://freeapi.robtex.com/ipquery/" + ip, timeout=self.opts['_fetchtimeout'])
                if res['code'] == "200":
                    break
                if res['code'] == "404":
                    return
                if res['code'] == "429":
                    # Back off a little further
                    time.sleep(2)
                retry += 1

            if res['content'] is None:
                self.sf.error("Unable to query robtex API.")
                retry += 1
                continue

            try:
                data = json.loads(res['content'])
            except Exception as e:
                self.sf.error(f"Error parsing JSON from Robtex API: {e}")
                return

            pas = data.get('pas')
            if not pas:
                return

            if len(data.get('pas')) > 0:
                for r in data.get('pas'):
                    if 'o' not in r:
                        continue
                    if not self.opts['cohostsamedomain']:
                        if self.getTarget().matches(r['o'], includeParents=True):
                            self.sf.debug("Skipping " + r['o'] + " because it is on the same domain.")
                            continue

                    if self.opts['verify'] and not self.sf.validateIP(r['o'], ip):
                        self.sf.debug("Host " + r['o'] + " no longer resolves to " + ip)
                        continue
                    if eventName == "NETBLOCK_OWNER":
                        ipe = SpiderFootEvent("IP_ADDRESS", ip, self.__name__, event)
                        self.notifyListeners(ipe)
                        evt = SpiderFootEvent("AFFILIATE_INTERNET_NAME", r['o'], self.__name__, ipe)
                        self.notifyListeners(evt)
                    else:
                        evt = SpiderFootEvent("AFFILIATE_INTERNET_NAME", r['o'], self.__name__, event)
                        self.notifyListeners(evt)
                    self.cohostcount += 1

# End of sfp_robtex class

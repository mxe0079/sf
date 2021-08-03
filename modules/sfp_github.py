# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_github
# Purpose:      Identifies public code repositories in Github associated with
#               your target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     21/07/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_github(SpiderFootPlugin):

    meta = {
        'name': "Github",
        'summary': "确定Github上的相关公共代码库",
        'flags': [""],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://github.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://developer.github.com/"
            ],
            'favIcon': "https://github.githubassets.com/favicons/favicon.png",
            'logo': "https://github.githubassets.com/favicons/favicon.png",
            'description': "GitHub将世界上最大的开发者社区聚集在一起，发现、分享和构建更好的软件",
        }
    }

    # Default options
    opts = {
        'namesonly': True
    }

    # Option descriptions
    optdescs = {
        'namesonly': "只通过名称而不是描述来匹配存储库。有助于减少误报"
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "USERNAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["RAW_RIR_DATA", "GEOINFO", "PUBLIC_CODE_REPO"]

    # Build up repo info for use as an event
    def buildRepoInfo(self, item):
        repo_info = None

        # Get repos matching the name
        if item.get('name') is None:
            self.sf.debug("Incomplete Github information found (name).")
            return None

        if item.get('html_url') is None:
            self.sf.debug("Incomplete Github information found (url).")
            return None

        if item.get('description') is None:
            self.sf.debug("Incomplete Github information found (description).")
            return None

        repo_info = "Name: " + item['name'] + "\n" + "URL: " + item['html_url'] + \
                    "\n" + "Description: " + item['description']

        return repo_info

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if eventData in self.results:
            self.sf.debug(f"Already did a search for {eventData}, skipping.")
            return None

        self.results[eventData] = True

        if eventName == "DOMAIN_NAME":
            username = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
            if not username:
                return None

        if eventName == "USERNAME":
            username = eventData

        self.sf.debug(f"Looking at {username}")
        failed = False

        # Get all the repositories based on direct matches with the
        # name identified
        url = f"https://api.github.com/search/repositories?q={username}"
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.sf.error(f"Unable to fetch {url}")
            failed = True

        if not failed:
            try:
                ret = json.loads(res['content'])
            except Exception as e:
                self.sf.debug(f"Error processing JSON response from GitHub: {e}")
                ret = None

            if ret is None:
                self.sf.error(f"Unable to process empty response from Github for: {username}")
                failed = True

        if not failed:
            if ret.get('total_count', "0") == "0" or len(ret['items']) == 0:
                self.sf.debug(f"No Github information for {username}")
                failed = True

        if not failed:
            for item in ret['items']:
                repo_info = self.buildRepoInfo(item)
                if repo_info is not None:
                    if self.opts['namesonly'] and username != item['name']:
                        continue

                    evt = SpiderFootEvent("PUBLIC_CODE_REPO", repo_info, self.__name__, event)
                    self.notifyListeners(evt)

        # Now look for users matching the name found
        failed = False
        url = f"https://api.github.com/search/users?q={username}"
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.sf.error(f"Unable to fetch {url}")
            failed = True

        if not failed:
            try:
                ret = json.loads(res['content'])
                if ret is None:
                    self.sf.error(f"Unable to process empty response from Github for: {username}")
                    failed = True
            except Exception:
                self.sf.error(f"Unable to process invalid response from Github for: {username}")
                failed = True

        if not failed:
            if ret.get('total_count', "0") == "0" or len(ret['items']) == 0:
                self.sf.debug("No Github information for " + username)
                failed = True

        if not failed:
            # For each user matching the username, get their repos
            for item in ret['items']:
                if item.get('repos_url') is None:
                    self.sf.debug("Incomplete Github information found (repos_url).")
                    continue

                url = item['repos_url']
                res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.sf.error(f"Unable to fetch {url}")
                    continue

                try:
                    repret = json.loads(res['content'])
                except Exception as e:
                    self.sf.error(f"Invalid JSON returned from Github: {e}")
                    continue

                if repret is None:
                    self.sf.error(f"Unable to process empty response from Github for: {username}")
                    continue

                for item in repret:
                    if type(item) != dict:
                        self.sf.debug("Encountered an unexpected or empty response from Github.")
                        continue

                    repo_info = self.buildRepoInfo(item)
                    if repo_info is not None:
                        if self.opts['namesonly'] and item['name'] != username:
                            continue
                        if eventName == "USERNAME" and "/" + username + "/" not in item.get('html_url', ''):
                            continue

                        evt = SpiderFootEvent("PUBLIC_CODE_REPO", repo_info,
                                              self.__name__, event)
                        self.notifyListeners(evt)


# End of sfp_github class

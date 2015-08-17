# -*- coding: utf-8 -*-

"""Python sina weibo sdk.

Rely on `requests` to do the dirty work, so it's much simpler and cleaner
than the official SDK.

For more info, refer to:
http://lxyu.github.io/weibo/
"""

from __future__ import absolute_import

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

import json
import time

import requests

def _get_requests_parmas(kwdict):
    _requests = kwdict.pop("_requests", None)
    if not isinstance(_requests, dict):
        _requests = {}
    return _requests


class Client(object):
    def __init__(self, api_key, api_secret, redirect_uri, token=None,
                 username=None, password=None):
        # const define
        self.site = 'https://api.weibo.com/'
        self.authorization_url = self.site + 'oauth2/authorize'
        self.token_url = self.site + 'oauth2/access_token'
        self.api_url = self.site + '2/'

        # init basic info
        self.client_id = api_key
        self.client_secret = api_secret
        self.redirect_uri = redirect_uri

        self.session = requests.session()
        if username and password:
            self.session.auth = username, password

        # activate client directly if given token
        if token:
            self.set_token(token)

    @property
    def authorize_url(self):
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri
        }
        return "{0}?{1}".format(self.authorization_url, urlencode(params))

    @property
    def alive(self):
        if self.expires_at:
            return self.expires_at > time.time()
        else:
            return False

    def _send_request(func, url,*args,**kwargs):
        try:
            res = func(url,*args,**kwargs)
        except Exception as e:
            pass

        error = None
        res = self._parse_resp(res)
        if resp.get("error_coe"):
            res = None
            error = resp

        return res,error


    def set_code(self, authorization_code,**kwargs):
        """Activate client by authorization_code.
        """
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': self.redirect_uri
        }
        _requests = _get_requests_parmas(kwargs)
        res = requests.post(self.token_url, data=params,**_requests)

        token = self._parse_resp(res)
        if token.get("error"):
            return None

        token = json.loads(res.text)
        token[u'expires_at'] = int(time.time()) + int(token.pop(u'expires_in'))
        self.set_token(token)
        return token

    def set_token(self, token):
        """Directly activate client by access_token.
        """
        self.token = token

        self.uid = token['uid']
        self.access_token = token['access_token']
        self.expires_at = token['expires_at']

        self.session.params = {'access_token': self.access_token}

    def _assert_error(self, d):
        """Assert if json response is error.
        """
        if 'error_code' in d and 'error' in d:
            raise RuntimeError("{0} {1}".format(
                d.get("error_code", ""), d.get("error", "")))

    def _parse_resp(self, resp):
        try:
            resp = json.load(resp.text)
            return resp
        except ValueError:
            error = {
                "error_code": "9876543210",
                "error": "No JSON object could be decoded"
            }
            return error

    def get(self, uri, **kwargs):
        """Request resource by get method.
        """
        url = "{0}{1}.json".format(self.api_url, uri)

        # for username/password client auth
        if self.session.auth:
            kwargs['source'] = self.client_id
        _requests = _get_requests_parmas(kwargs)
        res = json.loads(self.session.get(url, params=kwargs,**_requests).text)
        return res

    def post(self, uri, **kwargs):
        """Request resource by post method.
        """
        url = "{0}{1}.json".format(self.api_url, uri)

        # for username/password client auth
        if self.session.auth:
            kwargs['source'] = self.client_id

        files = None
        if kwargs.get("pic"):
            files = {"pic": kwargs.pop("pic")}

        _requests = _get_requests_parmas(kwargs)

        res = json.loads(self.session.post(url,
                                           data=kwargs,
                                           files=files, **_requests).text)
        try:
            self._assert_error(res)
        except RuntimeError:
            return None
        return res

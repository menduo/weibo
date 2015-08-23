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

from weibos.rescodes import resp_codes


def _get_requests_parmas(kwdict):
    _requests = kwdict.pop("_reqs", None)
    if not isinstance(_requests, dict):
        _requests = {}
    return _requests


def _send_request(func, url, **kwargs):
    error = None
    resp = None

    _requests = _get_requests_parmas(kwargs)
    kwargs.update(_requests)
    try:
        resp = func(url, **kwargs)
    except Exception as e:
        error = {
            "error_code": 9876543210,
            "error": str(e),
            "error_cn": "HTTP 请求/读取失败"
        }

    if error:
        return None, error

    resp = _parse_resp(resp)
    if isinstance(resp, dict) and resp.get("error_code"):
        error_code = str(resp.get("error_code"))
        error = resp
        resp = None
        error['error_cn'] = resp_codes.get(error_code, "新浪微博接口未知错误")

    return resp, error


def _parse_resp(resp):
    try:
        resp = json.loads(resp.text)
        return resp
    except Exception as e:
        error = {
            "error_code": 9876543211,
            "error": str(e)
        }
        return error


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

    def set_code(self, authorization_code, **kwargs):
        """Activate client by authorization_code.
        """
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': self.redirect_uri
        }

        rebuilds = {}
        rebuilds["_reqs"] = _get_requests_parmas(kwargs)
        rebuilds["data"] = params

        token, error = _send_request(func=requests.post, url=self.token_url, **rebuilds)

        if error and error.get("error"):
            return None, error

        token[u'expires_at'] = int(time.time()) + int(token.get(u'expires_in'))
        self.set_token(token)

        return token, None

    def set_token(self, token):
        """Directly activate client by access_token.
        """
        self.token = token

        self.uid = token['uid']
        self.access_token = token['access_token']
        self.expires_at = token['expires_at']

        self.session.params = {'access_token': self.access_token}
        return token

    def get(self, uri, **kwargs):
        """Request resource by get method.
        """
        url = "{0}{1}.json".format(self.api_url, uri)

        # for username/password client auth
        if self.session.auth:
            kwargs['source'] = self.client_id

        rebuilds = {}
        rebuilds["_reqs"] = _get_requests_parmas(kwargs)
        rebuilds["params"] = kwargs

        res, error = _send_request(func=self.session.get, url=url, **rebuilds)

        return res, error

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

        rebuilds = {}
        rebuilds["_reqs"] = _get_requests_parmas(kwargs)

        rebuilds["data"] = kwargs
        rebuilds["files"] = files

        res, error = _send_request(func=self.session.post, url=url, **rebuilds)
        return res, error

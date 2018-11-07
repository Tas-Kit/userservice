"""Summary
"""
import requests
from .generic import APISERVICE


class PLATFORM(APISERVICE):
    SCHEME = 'http'
    HOST = 'platform'
    PORT = 8000
    API_VERSION = 'v1'

    def get_platform_root_key(self, uid):
        resp = requests.get(self.get_full_url('/internal/'), cookies={
            'uid': str(uid)
        })
        return resp.json()

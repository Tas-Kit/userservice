"""Summary
"""
import requests
from .generic import APISERVICE


class USERSERVICE(APISERVICE):

    """User Example
    {
        'uid': '90f5a8e3-1a43-4b4e-84c4-00167b79e477',
        'username': 'root',
        'first_name': '',
        'last_name': '',
        'birthday': None,
        'gender': 'unknow',
        'phone': None,
        'address': None
    }
    """

    SCHEME = 'http'
    HOST = 'userservice'
    PORT = 8000
    API_VERSION = 'v1'

    def get_user_list(self, uid_list):
        if uid_list:
            query = '&'.join(['uid={0}'.format(uid) for uid in uid_list])
            url = '/users/?{0}'.format(query)
            url = self.get_full_url(url)
            response = requests.get(url)
            return response.json()['results']
        return []

    def get_user(self, uid=None, username=None):
        query = []
        if uid:
            query.append('uid={0}'.format(uid))
        if username:
            query.append('username={0}'.format(username))
        if query:
            url = '/users/?{0}'.format('&'.join(query))
            url = self.get_full_url(url)
            response = requests.get(url)
            return response.json()['results'][0]
        return []

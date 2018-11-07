"""Summary
"""
import requests
import json
from .generic import APISERVICE


class NOTIFICATIONS(APISERVICE):
    SCHEME = 'http'
    HOST = 'notifications'
    PORT = 8000
    API_VERSION = 'v1'

    @staticmethod
    def generate_params(**kwargs):
        return json.dumps(kwargs)

    def invite(self, uid_list, inviter_id, task_id):
        """Send invitation notification

        Args:
            uid_list (list): List of uid ['<uuid>', '<uuid>']
            inviter_id (uuid): Description
            task_id (TYPE): Description

        Returns:
            TYPE: Description
        """
        if uid_list:
            uid_list = ','.join([str(uid) for uid in uid_list])
            params = NOTIFICATIONS.generate_params(
                inviter_id=str(inviter_id),
                task_id=str(task_id))
            data = {
                'uid_list': uid_list,
                'notitype': 'InvitationNotification',
                'params': params
            }
            url = self.get_full_url('/internal/')
            response = requests.post(url, data=data)
            return response.json()
        return {}

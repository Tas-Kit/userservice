import os
import requests


class GENERICSERVICE(object):

    def get_attrs(self):
        return [attr for attr in dir(self)
                if attr.isupper()]

    def set_attr(self, attr):
        param = '{0}_{1}'.format(self.__class__.__name__, attr)
        value = os.getenv(param, None)
        if value:
            origin_value = getattr(self, attr, None)
            if origin_value:
                value = type(origin_value)(value)
            setattr(self, attr, value)

    def __init__(self):
        attrs = self.get_attrs()
        for attr in attrs:
            self.set_attr(attr)


class APISERVICE(GENERICSERVICE):

    def get_base_url(self):
        return '{scheme}://{host}:{port}/api/{version}/{service}'.format(
            scheme=self.SCHEME,
            host=self.HOST,
            port=str(self.PORT),
            version=self.API_VERSION,
            service=self.__class__.__name__.lower())

    def get_full_url(self, sub_url):
        return self.get_base_url() + sub_url

    def send_request(self, sub_url, method=requests.get):
        url = self.get_base_url() + sub_url
        return method(url)

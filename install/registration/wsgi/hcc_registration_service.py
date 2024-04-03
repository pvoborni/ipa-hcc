__all__ = ("application",)

# import WSGI app before api
from ipalib import api

from ipahcc.server.registration import Application

application = Application(api=api)

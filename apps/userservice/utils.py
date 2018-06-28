import time
import hashlib
from django.conf import settings


def get_code(email, t=None):
    if t is None:
        t = int(time.time() / settings.VERI_CODE_EXP)
    t = str(t)
    k = settings.SECRET_KEY
    s = email + ';' + t + ';' + k
    h = hashlib.sha256(s.encode('utf-8')).hexdigest()
    return h[:6]


def verify_code(email, code):
    t = int(time.time() / settings.VERI_CODE_EXP)
    prev = get_code(email, t - 1)
    curr = get_code(email, t)
    return code == prev or code == curr

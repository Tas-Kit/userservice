import time
import hashlib
from utils.s3 import upload
from django.conf import settings
from io import BytesIO
from PIL import Image
from rest_framework.exceptions import ParseError


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


def process_image(image):
    if image is None:
        raise ParseError("Empty content")
    try:
        img = Image.open(image)
        img.verify()
    except Exception as e:
        raise ParseError("Unable to upload image: {0}".format(e))

    try:
        img = Image.open(image)
        rgb_im = img.convert('RGB')
        out_image = BytesIO()
        rgb_im.save(out_image, format="jpeg")
        out_image.seek(0)
    except Exception as e:
        raise ParseError("Unable to process image: {0}".format(e), code=411)
    return out_image


def upload_user_profile(user, image):
    image = process_image(image)
    upload('user/{0}/profile.jpg'.format(user.id), image)

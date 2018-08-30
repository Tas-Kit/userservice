import time
import hashlib
from django.conf import settings
from io import BytesIO
from PIL import Image
from rest_framework.exceptions import ParseError


def upload(key, data):
    s3 = settings.S3
    bucket_name = settings.BUCKET_NAME
    bucket_root = settings.BUCKET_ROOT
    s3.Bucket(bucket_name).put_object(
        Key='{0}/{1}'.format(bucket_root, key),
        Body=data,
        ACL='public-read'
    )


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


def verify_image(image):
    try:
        img = Image.open(image)
        img.verify()
    except Exception as e:
        raise ParseError("Unable to verify image image: {0}".format(e), code=411)


def process_image(image):
    verify_image(image)
    try:
        img = Image.open(image)
        rgb_im = img.convert('RGB')
        out_image = BytesIO()
        rgb_im.save(out_image, format="jpeg")
        out_image.seek(0)
    except Exception as e:
        raise ParseError("Unable to process image: {0}".format(e), code=412)
    return out_image


def upload_user_profile(user, image):
    image = process_image(image)
    upload('user/{0}/profile.jpg'.format(user.id), image)

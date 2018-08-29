from django.conf import settings


def upload(key, data):
    s3 = settings.S3
    bucket_name = settings.BUCKET_NAME
    bucket_root = settings.BUCKET_ROOT
    s3.Bucket(bucket_name).put_object(
        Key='{0}/{1}'.format(bucket_root, key),
        Body=data,
        ACL='public-read'
    )

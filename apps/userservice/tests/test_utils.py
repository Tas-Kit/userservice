from django.test import TestCase
from django.conf import settings
from io import BytesIO
from mock import patch, MagicMock
from rest_framework.exceptions import ParseError
from apps.userservice.utils import (
    verify_image,
    process_image,
    upload_user_profile,
    upload,
    get_code,
    verify_code,
)


class TestUtils(TestCase):

    def test_verify_code(self):
        email = 'myemail'
        code = get_code(email)
        self.assertTrue(verify_code(email, code))

    @patch('django.conf.settings.S3.Bucket', return_value=MagicMock())
    def test_upload(self, mock_bucket):
        put_object = MagicMock()
        mock_bucket.return_value.put_object = put_object
        upload('mykey', 'mydata')
        mock_bucket.called_once_with(settings.BUCKET_NAME)
        put_object.called_once_with(Key='{0}/mykey'.format(settings.BUCKET_ROOT),
                                    Body='mydata',
                                    ACL='public-read')

    @patch('apps.userservice.utils.process_image')
    @patch('apps.userservice.utils.upload')
    def test_upload_user_profile(self, mock_upload, mock_process_image):
        user = MagicMock()
        user.id = 'testid'
        image = MagicMock()
        out_image = MagicMock()
        mock_process_image.return_value = out_image
        upload_user_profile(user, image)
        mock_process_image.called_once_with(image)
        mock_upload.called_once_with('user/testid/profile.jpg', out_image)

    @patch('PIL.Image.open', return_value=MagicMock())
    def test_verify_image(self, mock_open):
        with self.assertRaises(ParseError):
            mock_open.return_value.verify = MagicMock(side_effect=Exception('Any Exception'))
            verify_image(MagicMock)

    @patch('apps.userservice.utils.verify_image')
    def test_process_image(self, mock_verify_image):
        with open('apps/userservice/tests/a.jpg', 'rb') as image:
            image = process_image(image)
            self.assertTrue(type(image), BytesIO)

    @patch('apps.userservice.utils.verify_image')
    def test_process_fail(self, mock_verify_image):
        with open('apps/userservice/tests/a.jpg', 'r') as image:
            with self.assertRaises(ParseError):
                image = process_image(image)

    def test_verify_code_fail(self):
        self.assertFalse(verify_code('myemail', 'badcod'))

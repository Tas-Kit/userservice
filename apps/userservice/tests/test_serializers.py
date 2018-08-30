from django.test import TestCase
from mock import patch, MagicMock
from validators.uuid import uuid
from rest_framework import serializers

from apps.userservice.serializers import (
    validate_password,
    ProfileUploadSerializer,
    ImageUploadSerializer
)


class TestGlobal(TestCase):

    def test_validate_password(self):
        self.assertEqual('abcd1234', validate_password('abcd1234'))

    def test_validate_password_all_char(self):
        with self.assertRaises(serializers.ValidationError):
            validate_password('abcdEFgh')

    def test_validate_password_all_num(self):
        with self.assertRaises(serializers.ValidationError):
            validate_password('43521234')


class TestProfileUploadSerializer(TestCase):

    @patch('apps.userservice.serializers.upload')
    def test_create(self, mock_upload):
        serializer = ProfileUploadSerializer()
        request = MagicMock()
        user = MagicMock()
        image = MagicMock()
        user.id = 'testid'
        request.user = user
        serializer.context['request'] = request
        validate_data = {
            'image': image
        }
        result = serializer.create(validate_data)
        self.assertEqual(result, 'SUCCESS')
        self.assertTrue(mock_upload.called_once_with('user/testid/profile.jpg', image))


class TestImageUploadSerializer(TestCase):

    def test_validate_path(self):
        serializer = ImageUploadSerializer()
        path = '///task///description///jpg///'
        path = serializer.validate_path(path)
        self.assertEqual('task/description/jpg', path)

    def test_validate_incorrect_path(self):
        serializer = ImageUploadSerializer()
        path = '///task///description///icon///'
        with self.assertRaises(serializers.ValidationError):
            path = serializer.validate_path(path)

    @patch('apps.userservice.serializers.upload')
    def test_create(self, mock_upload):
        validate_data = {
            'path': 'valid_path',
            'image': MagicMock()
        }
        serializer = ImageUploadSerializer()
        result = serializer.create(validate_data)
        iid = result['iid']
        self.assertTrue(uuid(iid))
        self.assertTrue(mock_upload.called_once_with('valid_path/{0}'.format(iid), validate_data['image']))

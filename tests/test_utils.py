from django.test.utils import override_settings
from django.test import TestCase
from django.test import RequestFactory
from django.conf import settings

import onelogin

import urllib.request
from django_saml2_pro_auth.utils import get_provider_config, init_saml_auth, prepare_django_request, apply_attribute_map

from .data.configs import MOCK_SAML2_CONFIG
from django_saml2_pro_auth.utils import SAMLError, SAMLSettingsError

from . import init_test_settings

test_settings = init_test_settings()
try:
    settings.configure(**test_settings)
except RuntimeError:
    # already configured in other test
    pass

class TestUtils(TestCase):

    @override_settings(SAML_PROVIDERS=MOCK_SAML2_CONFIG)
    def test_init_saml_auth(self):
        r = RequestFactory()
        request = r.get('/sso/saml/?provider=MyProvider', **dict(HTTP_HOST='example.com'))
        req = prepare_django_request(request)
        auth_obj = init_saml_auth(req)
        self.assertTrue(type(auth_obj) is onelogin.saml2.auth.OneLogin_Saml2_Auth)

    @override_settings(SAML_PROVIDERS=[{'MyProvider': {'name': 'MyProvider'}}])
    def test_get_provider_config_with_missing_query_str(self):
        r = RequestFactory()
        request = r.get('/sso/saml/', **dict(HTTP_HOST='example.com'))
        req = prepare_django_request(request)
        config = get_provider_config(req)
        self.assertEqual(config['name'], 'MyProvider')

    @override_settings(SAML_PROVIDERS=MOCK_SAML2_CONFIG)
    def test_get_provider_config_with_missing_provider(self):
        r = RequestFactory()
        request = r.get('/sso/saml/?provider=MissingProvider', **dict(HTTP_HOST='example.com'))
        req = prepare_django_request(request)
        self.assertRaises(SAMLSettingsError, get_provider_config, req)

    @override_settings(SAML_PROVIDERS=MOCK_SAML2_CONFIG)
    def test_get_provider_config(self):
        r = RequestFactory()
        request = r.get('/sso/saml/?provider=MyProvider', **dict(HTTP_HOST='example.com'))
        req = prepare_django_request(request)
        config = get_provider_config(req)
        mock_cfg = MOCK_SAML2_CONFIG[0]['MyProvider']
        for top_attr in mock_cfg.keys():
            if type(top_attr) is dict:
                for key, value in top_attr.iteritems():
                    self.assertEqual(mock_cfg[key], config[key])
            else:
                self.assertEqual(mock_cfg[top_attr], config[top_attr])

    def test_prepare_http_request_with_GET_no_proxy(self):
        r = RequestFactory()
        request = r.get('/sso/saml/?provider=MyProvider', **dict(HTTP_HOST='example.com'))
        req = prepare_django_request(request)

        self.assertEqual(req['get_data']['provider'], 'MyProvider')
        self.assertEqual(req['https'], 'off')
        self.assertEqual(req['script_name'], '/sso/saml/')
        self.assertEqual(req['http_host'], 'example.com')

    def test_prepare_https_request_with_GET_no_proxy(self):
        r = RequestFactory()
        request = r.get('/sso/saml/?provider=MyProvider', secure=True, **dict(HTTP_HOST='example.com'))
        req = prepare_django_request(request)
        self.assertEqual(req['get_data']['provider'], 'MyProvider')
        self.assertEqual(req['https'], 'on')
        self.assertEqual(req['script_name'], '/sso/saml/')
        self.assertEqual(req['http_host'], 'example.com')

    def test_prepare_http_request_with_GET_plus_proxy(self):
        r = RequestFactory()
        request = r.get('/sso/saml/?provider=MyProvider', **dict(HTTP_X_FORWARDED_FOR='10.10.10.10', HTTP_X_FORWARDED_PROTO='http', HTTP_HOST='example.com'))
        req = prepare_django_request(request)
        self.assertEqual(req['get_data']['provider'], 'MyProvider')
        self.assertEqual(req['https'], 'off')
        self.assertEqual(req['script_name'], '/sso/saml/')
        self.assertEqual(req['http_host'], 'example.com')

    def test_prepare_https_request_with_GET_plus_proxy(self):
        r = RequestFactory()
        request = r.get('/sso/saml/?provider=MyProvider', **dict(HTTP_X_FORWARDED_FOR='10.10.10.10', HTTP_X_FORWARDED_PROTO='https', HTTP_HOST='example.com'))
        req = prepare_django_request(request)
        self.assertEqual(req['get_data']['provider'], 'MyProvider')
        self.assertEqual(req['https'], 'on')
        self.assertEqual(req['script_name'], '/sso/saml/')
        self.assertEqual(req['http_host'], 'example.com')

    def test_prepare_http_request_with_POST_no_proxy(self):
        r = RequestFactory()
        request = r.post('/sso/saml/?provider=MyProvider', **dict(HTTP_HOST='example.com'))
        req = prepare_django_request(request)

        self.assertEqual(req['get_data']['provider'], 'MyProvider')
        self.assertEqual(req['https'], 'off')
        self.assertEqual(req['script_name'], '/sso/saml/')
        self.assertEqual(req['http_host'], 'example.com')

    def test_prepare_https_request_with_POST_no_proxy(self):
        r = RequestFactory()
        request = r.post('/sso/saml/?provider=MyProvider', secure=True, **dict(HTTP_HOST='example.com'))
        req = prepare_django_request(request)
        self.assertEqual(req['get_data']['provider'], 'MyProvider')
        self.assertEqual(req['https'], 'on')
        self.assertEqual(req['script_name'], '/sso/saml/')
        self.assertEqual(req['http_host'], 'example.com')

    def test_prepare_http_request_with_POST_plus_proxy(self):
        r = RequestFactory()
        request = r.post('/sso/saml/?provider=MyProvider', **dict(HTTP_X_FORWARDED_FOR='10.10.10.10', HTTP_X_FORWARDED_PROTO='http', HTTP_HOST='example.com'))
        req = prepare_django_request(request)
        self.assertEqual(req['get_data']['provider'], 'MyProvider')
        self.assertEqual(req['https'], 'off')
        self.assertEqual(req['script_name'], '/sso/saml/')
        self.assertEqual(req['http_host'], 'example.com')

    def test_prepare_https_request_with_POST_plus_proxy(self):
        r = RequestFactory()
        request = r.post('/sso/saml/?provider=MyProvider', **dict(HTTP_X_FORWARDED_FOR='10.10.10.10', HTTP_X_FORWARDED_PROTO='https', HTTP_HOST='example.com'))
        req = prepare_django_request(request)
        self.assertEqual(req['get_data']['provider'], 'MyProvider')
        self.assertEqual(req['https'], 'on')
        self.assertEqual(req['script_name'], '/sso/saml/')
        self.assertEqual(req['http_host'], 'example.com')

    def test_apply_attribute_map(self):
        attr_map = urllib.request.urlopen('https://confluence.it.ubc.ca/download/attachments/126882414/attribute-map.xml?version=1&modificationDate=1530660054000&api=v2').read()
        data = {
            'urn:oid:2.5.4.42': ['givenName'],
            'urn:oid:2.16.840.1.113719.1.1.4.1.25': ['groupMembership'],
            'urn:oid:2.5.4.4': ['sn'],
            'urn:oid:0.9.2342.19200300.100.1.1': ['uid']
        }
        fixed = apply_attribute_map(attr_map, data)
        for k, v in fixed.items():
            self.assertEqual(k, v[0])

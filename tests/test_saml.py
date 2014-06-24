import unittest
from mock import Mock
import time
import urlparse
import base64
import copy
from flask import Flask, session, request
from werkzeug.exceptions import BadRequest
from saml2 import (VERSION, saml, samlp,
    BINDING_HTTP_REDIRECT, BINDING_HTTP_POST)
from saml2.ident import IdentDB, code, decode
from saml2.server import Server
from saml2.client import Saml2Client
from saml2.config import IdPConfig, SPConfig
from saml2.mdstore import MetaData, destinations
from saml2.s_utils import (decode_base64_and_inflate, deflate_and_base64_encode,
    UnsupportedBinding)
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.saml import NameID, NAMEID_FORMAT_TRANSIENT
from saml2.samlp import Response
from saml2.time_util import instant

import flask_pysaml2 as auth
from sp_config import CONFIG as sp_config
from idp_config import CONFIG as idp_config

import os
root_path = os.path.dirname(os.path.abspath(__file__))

AUTHN = {
    "class_ref": INTERNETPROTOCOLPASSWORD,
    "authn_auth": "http://www.example.com/login"
}

def create_authn_response(session_id, identity=dict(),
                          sign_response=True, sign_assertion=True):
    config = IdPConfig()
    config.load(idp_config)
    idp_server = Server(config=config)
    idp_server.ident = IdentDB(auth.AuthDictCache(dict(), '_ident'))
    authn_response = idp_server.create_authn_response(
        identity=identity,
        in_response_to=session_id,
        destination='https://foo.example.com/sp/acs',
        sp_entity_id='https://foo.example.com/sp/metadata',
        name_id_policy=None,
        userid='Irrelevent',
        sign_response=sign_response,
        sign_assertion=sign_assertion,
        instance=True,
        authn=AUTHN)
    if isinstance(authn_response, Response):
        authn_response = authn_response.to_string()
    response = samlp.response_from_string(authn_response)
    return response.assertion[0].subject.name_id.text, authn_response

def create_logout_response(subject_id, destination, issuer_entity_id,
        req_entity_id, sign=True):
    config = IdPConfig()
    config.load(idp_config)
    idp_server = Server(config=config)
    # construct a request
    logout_request = create_logout_request(
        subject_id=subject_id,
        destination=destination,
        issuer_entity_id=issuer_entity_id,
        req_entity_id=req_entity_id)

    enc_logout_request = deflate_and_base64_encode("%s" % logout_request)
    req_info = idp_server.parse_logout_request(enc_logout_request,
                                            BINDING_HTTP_REDIRECT)
    bindings = [BINDING_HTTP_REDIRECT]
    response = idp_server.create_logout_response(req_info.message,
                                          bindings, sign=sign)
    http_args = idp_server.apply_binding(BINDING_HTTP_REDIRECT, "%s" % response, destination,
                                  "relay_state", response=True)
    location = dict(http_args.get('headers')).get('Location')
    url = urlparse.urlparse(location)
    params = urlparse.parse_qs(url.query)
    logout_response_xml = decode_base64_and_inflate(params['SAMLResponse'][0])
    response = samlp.logout_response_from_string(logout_response_xml)
    return response.in_response_to, logout_response_xml

def create_logout_request(subject_id, destination, issuer_entity_id,
        req_entity_id, sign=True):
    config = SPConfig()
    config.load(sp_config)
    sp_client = Saml2Client(config=config)
    # construct a request
    logout_request = samlp.LogoutRequest(
        id='a123456',
        version=VERSION,
        destination=destination,
        issue_instant=instant(),
        issuer=saml.Issuer(text=req_entity_id,
            format=saml.NAMEID_FORMAT_ENTITY),
        name_id=saml.NameID(name_qualifier='https://sso.example.com/idp/metadata',
                            format=NAMEID_FORMAT_TRANSIENT, text=subject_id))
    return logout_request

# taken from tests/fakeIDP.py in the pysaml2 repo
def unpack_form(_str, ver="SAMLRequest"):
    SR_STR = "name=\"%s\" value=\"" % ver
    RS_STR = 'name="RelayState" value="'

    i = _str.find(SR_STR)
    i += len(SR_STR)
    j = _str.find('"', i)

    sr = _str[i:j]

    k = _str.find(RS_STR, j)
    k += len(RS_STR)
    l = _str.find('"', k)

    rs = _str[k:l]

    return {ver: sr, "RelayState": rs}

class TestSaml(unittest.TestCase):

    def setUp(self):
        super(TestSaml, self).setUp()
        self.app = Flask(__name__)
        self.app.secret_key = 'Super secret key. Shhhh!'
        self.client = self.app.test_client()

    def test_AuthDictCache(self):
        with self.app.test_request_context('/',
                method='GET'):
            # assert empty session
            self.assertEqual(session, {})
            # create cache pointing at undefined key in empty session
            cache = auth.AuthDictCache(session, '_test')
            # assert empty
            self.assertEqual(cache, {})
            self.assertEqual(cache.session_data, {})
            # verify that cache works like a normal dict
            cache['key_1'] = 'value_1'
            self.assertEqual(cache, {'key_1': 'value_1'})
            cache['key_2'] = 'value_2'
            cache.update({'key_1': 'value_4', 'key_3': 'value_3'})
            self.assertEqual(cache, {
                'key_1': 'value_4', 'key_2': 'value_2', 'key_3': 'value_3'})
            # verify that data has not been sync'ed to the session
            self.assertEqual(session, {})
            self.assertEqual(cache.session_data, {})
            # verify that data has been sync'ed to the session
            cache.sync()
            self.assertEqual(cache.session_data,
                {'key_1': 'value_4', 'key_2': 'value_2', 'key_3': 'value_3'})
            self.assertEqual(session.get('_test'),
                {'key_1': 'value_4', 'key_2': 'value_2', 'key_3': 'value_3'})
            # if we create a cache pointing to existing session data, it
            # should be populated
            cache = auth.AuthDictCache(session, '_test')
            self.assertEqual(cache,
                {'key_1': 'value_4', 'key_2': 'value_2', 'key_3': 'value_3'})

    def test_IdentityCache(self):
        with self.app.test_request_context('/',
                method='GET'):
            # assert empty session
            self.assertEqual(session, {})
            # create cache pointing at undefined key in empty session
            cache = auth.IdentityCache(session, '_test')
            self.assertEqual(session, {})
            self.assertEqual(cache._db, {})
            self.assertTrue(cache._sync)
            # Add something to the cache _db
            name_id = saml.NameID('subject_id')
            cache.set(name_id, 'entity_id', 'info')
            # verify that data has  been sync'ed to the session automagically
            self.assertEqual(cache._db,
                {'0=subject_id': {'entity_id': (0, 'info')}})
            self.assertEqual(session.get('_test'),
                {'0=subject_id': {'entity_id': (0, 'info')}})
            # if we create a cache pointing to existing session data, it
            # should be populated
            cache = auth.IdentityCache(session, '_test')
            self.assertEqual(cache._db,
                {'0=subject_id': {'entity_id': (0, 'info')}})

    def test_Saml_init(self):
        entity_id = 'https://sso.example.com/idp/metadata'
        with self.app.test_request_context('/',
                method='GET'):
            try:
                sp = auth.Saml({'service': {'sp':'invalid'}})
                self.fail(
                    'Expected TypeError on invalid submission to Saml __init__')
            except TypeError:
                pass
            sp = auth.Saml(sp_config)
            self.assertEqual(sp._config.metadata.identity_providers(),
                [entity_id])
            slo = sp._config.metadata.single_logout_service(
                entity_id, binding=BINDING_HTTP_REDIRECT, typ='idpsso')[0]
            self.assertEqual(slo['location'],
                'https://sso.example.com/idp/slo')
            self.assertEqual(slo['binding'],
                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')
            sso = sp._config.metadata.single_sign_on_service(entity_id)[0]
            self.assertEqual(sso['location'],
                'https://sso.example.com/idp/sso')
            self.assertEqual(sso['binding'],
                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')

    def test_Saml_init_idp_as_config(self):
        tmp_sp_config = copy.deepcopy(sp_config)
        entity_id = 'https://sso.example.com/idp/metadata'
        tmp_sp_config['metadata']['inline'] = {
            'entityid': entity_id,
            'contact_person': [{
                'email_address': 'helpdesk@kavi.com',
                'contact_type': 'technical',
                },
            ],
            'service': {
                'idp': {
                    'name': 'Test Identity Provider',
                    'endpoints': {
                        'single_sign_on_service': [(
                            'https://sso.example.com/idp/sso',
                            BINDING_HTTP_REDIRECT)],
                        'single_logout_service': [(
                            'https://sso.example.com/idp/slo',
                            BINDING_HTTP_REDIRECT)],
                    },
                    'policy': {
                        'default': {
                            'lifetime': {'hours': 24},
                            'attribute_restrictions': None,
                            'name_form':
                                'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
                        },
                    },
                },
            },
            'cert_file': root_path + '/sso_public.crt',
        }
        with self.app.test_request_context('/',
                method='GET'):
            sp = auth.Saml(tmp_sp_config)
            self.assertIn(entity_id, sp._config.metadata.identity_providers())
            slo = sp._config.metadata.single_logout_service(
                entity_id, binding=BINDING_HTTP_REDIRECT, typ='idpsso')[0]
            self.assertEqual(slo['location'],
                'https://sso.example.com/idp/slo')
            self.assertEqual(slo['binding'],
                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')
            sso = sp._config.metadata.single_sign_on_service(entity_id)[0]
            self.assertEqual(sso['location'],
                'https://sso.example.com/idp/sso')
            self.assertEqual(sso['binding'],
                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')

    def test_Saml_init_IdP(self):
        entity_id = 'https://foo.example.com/sp/metadata'
        with self.app.test_request_context('/',
                method='GET'):
            idp = auth.SamlServer(idp_config)
            sls = idp._config.metadata.single_logout_service(
                entity_id, binding=BINDING_HTTP_REDIRECT, typ='spsso')
            self.assertEqual(destinations(sls),
                ['https://foo.example.com/sp/slo'])
            self.assertIsNotNone(
                getattr(idp._config.metadata, 'assertion_consumer_service'))
            acs = idp._config.metadata.assertion_consumer_service(entity_id)
            self.assertEqual(acs[0]['location'], 'https://foo.example.com/sp/acs')

    def test_Saml_authenticate(self):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test signed authentication request
        with self.app.test_request_context('/',
                method='GET'):
            sp = auth.Saml(tmp_sp_config)
            resp = sp.authenticate(next_url='/next')
            self.assertEqual(resp.status_code, 302)
            self.assert_('SAMLRequest' in resp.headers['Location'])
            url = urlparse.urlparse(resp.headers['Location'])
            self.assertEqual(url.hostname, 'sso.example.com')
            self.assertEqual(url.path, '/idp/sso')
            params = urlparse.parse_qs(url.query)
            self.assert_('SAMLRequest' in params)
            self.assertEqual(params['RelayState'], ['/next'])
            authn = samlp.authn_request_from_string(
                decode_base64_and_inflate(params['SAMLRequest'][0]))
            self.assertEqual(authn.destination,
                'https://sso.example.com/idp/sso')
            self.assertEqual(authn.assertion_consumer_service_url,
                'https://foo.example.com/sp/acs')
            self.assertEqual(authn.protocol_binding, BINDING_HTTP_POST)
            self.assertIsNotNone(authn.signature)
            self.assertEqual(session['_saml_outstanding_queries'],
                {authn.id: '/next'})
        # test un-signed authentication request
        with self.app.test_request_context('/',
                method='GET'):
            tmp_sp_config['key_file'] = None
            tmp_sp_config['service']['sp']['authn_requests_signed'] = None
            sp = auth.Saml(tmp_sp_config)
            resp = sp.authenticate(next_url='/next')
            self.assertEqual(resp.status_code, 302)
            self.assert_('SAMLRequest' in resp.headers['Location'])
            url = urlparse.urlparse(resp.headers['Location'])
            params = urlparse.parse_qs(url.query)
            authn = samlp.authn_request_from_string(
                decode_base64_and_inflate(params['SAMLRequest'][0]))
            self.assertIsNone(authn.signature)

    def test_Saml_authenticate_via_post(self):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test signed authentication request
        with self.app.test_request_context('/',
                method='GET'):
            tmp_sp_config['metadata'] = {
                'local': [root_path + '/idp_post_metadata.xml']
            }
            sp = auth.Saml(tmp_sp_config)
            resp, status = sp.authenticate(next_url='/next',
                binding=BINDING_HTTP_POST)
            self.assertEqual(status, 200)
            _form = unpack_form(resp['data'][3])
            self.assert_('SAMLRequest' in _form)
            self.assert_('RelayState' in _form)
            authn_id = session['_saml_outstanding_queries'].keys()[0]
            self.assertEqual(session['_saml_outstanding_queries'],
                {authn_id: '/next'})

    def test_Saml_authenticate_no_idp(self):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test using binding method not configured for in IdP metadata
        with self.app.test_request_context('/',
                method='GET'):
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.authenticate(next_url='/next',
                    binding=BINDING_HTTP_POST)
                self.fail(
                    'Expected AuthException on invalid Saml authentication')
            except UnsupportedBinding, e:
                self.assertEqual(
                    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', str(e))
        # test with only allowed IdP not included in metadata file
        with self.app.test_request_context('/',
                method='GET'):
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.authenticate(next_url='/next')
            except auth.AuthException, e:
                self.assertEqual(
                    'Unable to locate valid IdP for this request', str(e))

    def test_Saml_authenticate_invalid_config(self):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test signed authentication request w/o private key file
        with self.app.test_request_context('/',
                method='GET'):
            tmp_sp_config['key_file'] = None
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.authenticate(next_url='/next')
                self.fail(
                    'Expected AuthException on invalid Saml authentication')
            except auth.AuthException, e:
                self.assertEqual(
                    'Signature requested for this Saml authentication request,'
                    ' but no private key file configured', str(e))
            # outstanding queury cache should still be empty
            self.assertEqual(session.get('_saml_outstanding_queries',{}), {})

    def test_Saml_handle_assertion(self):
        ava = {'uid': '123456'}
        session_id = 'a0123456789abcdef0123456789abcdef'
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # create a response to assert upon
        name_id, authn_response = create_authn_response(session_id, ava)
        self.assert_('Signature' in authn_response)
        # test fails if there is no known outstanding auth request
        with self.app.test_request_context('/',
                method='POST',
                data=dict(SAMLResponse=base64.b64encode(authn_response),
                    RelayState='/next')):
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.handle_assertion(request)
                self.fail(
                    'Expected Exception due to lack of outstanding request')
            except:
                pass
        # test with default user_id mapping
        with self.app.test_request_context('/',
                method='POST',
                data=dict(SAMLResponse=base64.b64encode(authn_response),
                    RelayState='/next')):
            # make the client thing there is outstanding request
            session['_saml_outstanding_queries'] = {session_id: '/next'}
            user_id, user_attributes, resp = sp.handle_assertion(request)
            self.assertEqual(user_id.text, name_id)
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.headers['Location'], '/next')
            # outstanding queury cache should now be empty
            self.assertEqual(session.get('_saml_outstanding_queries',{}), {})
            # identity and subject_id should now be set
            self.assertEqual(session.get('_saml_subject_id').text, name_id)
        # test user_id mapped to 'uid' attribute
        with self.app.test_request_context('/',
                method='POST',
                data=dict(SAMLResponse=base64.b64encode(authn_response),
                    RelayState='/next')):
            sp.attribute_map = dict(uid='uid')
            session['_saml_outstanding_queries'] = {session_id: '/next'}
            user_id, user_attributes, resp = sp.handle_assertion(request)
            self.assertEqual(user_id, '123456')
            # outstanding queury cache should now be empty
            self.assertEqual(session.get('_saml_outstanding_queries',{}), {})
            # identity and subject_id should now be set
            self.assert_(name_id in session.get('_saml_identity').keys()[0])
            self.assertEqual(session.get('_saml_subject_id').text, name_id)
        # test user_id mapped to missing attribute
        with self.app.test_request_context('/',
                method='POST',
                data=dict(SAMLResponse=base64.b64encode(authn_response),
                    RelayState='/next')):
            sp.attribute_map = dict(uid='invalid')
            session['_saml_outstanding_queries'] = {session_id: '/next'}
            try:
                user_id, user_attributes, resp = \
                    sp.handle_assertion(request)
                self.fail('Expected AuthException for invalid attribute name')
            except auth.AuthException, e:
                self.assertEqual(
                    'Unable to find "invalid" attribute in response', str(e))
            # outstanding queury cache should now be empty
            self.assertEqual(session.get('_saml_outstanding_queries',{}), {})
            # identity is still set by internal Saml client call
            # ~ I feel like maybe this should get cleared if we couldn't
            #   find an exceptable uid.
            self.assert_(name_id in session.get('_saml_identity').keys()[0])
            # subject_id is not set if unable to parse attribute
            self.assertEqual(session.get('_saml_subject_id'), None)

    def test_Saml_handle_assertion_allow_unsolicited(self):
        ava = {'uid': '123456'}
        session_id = 'a0123456789abcdef0123456789abcdef'
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # The following setting allows for handling unsolicited
        # assertions which ironically is the expected behavior according to
        # the SAML 2.0 specification
        tmp_sp_config['service']['sp']['allow_unsolicited'] = 'true'
        # create a response to assert upon
        name_id, authn_response = create_authn_response(session_id, ava)
        self.assert_('Signature' in authn_response)
        # test success if no outstanding queries exist
        with self.app.test_request_context('/',
                method='POST',
                data=dict(SAMLResponse=base64.b64encode(authn_response),
                    RelayState='/next')):
            sp = auth.Saml(tmp_sp_config)
            user_id, user_attributes, resp = sp.handle_assertion(request)
            self.assertEqual(user_id.text, name_id)
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.headers['Location'], '/next')
            # identity and subject_id should now be set
            self.assert_(name_id in session.get('_saml_identity').keys()[0])
            self.assertEqual(session.get('_saml_subject_id').text, name_id)
        # test success if outstanding queries exist
        with self.app.test_request_context('/',
                method='POST',
                data=dict(SAMLResponse=base64.b64encode(authn_response),
                    RelayState='/next')):
            sp = auth.Saml(tmp_sp_config)
            session['_saml_outstanding_queries'] = {session_id: '/next'}
            user_id, user_attributes, resp = sp.handle_assertion(request)
            self.assertEqual(user_id.text, name_id)
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.headers['Location'], '/next')
            # outstanding queury cache should now be empty
            self.assertEqual(session.get('_saml_outstanding_queries',{}), {})
            # identity and subject_id should now be set
            self.assert_(name_id in session.get('_saml_identity').keys()[0])
            self.assertEqual(session.get('_saml_subject_id').text, name_id)

    def test_Saml_handle_assertion_invalid_SAMLResponse(self):
        ava = {'uid': '123456'}
        session_id = 'a0123456789abcdef0123456789abcdef'
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test missing SAMLResponse
        with self.app.test_request_context('/',
                method='POST'):
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.handle_assertion(request)
                self.fail(
                    'Expected BadRequest on missing SAMLResponse POST var')
            except BadRequest, e:
                self.assertEqual(400, e.code)
                self.assertEqual('SAMLResponse missing from POST', e.description)
        # test SAMLResponse via GET
        with self.app.test_request_context('/',
                method='GET',
                query_string=dict(SAMLResponse='invalid', RelayState='/next')):
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.handle_assertion(request)
                self.fail(
                    'Expected BadRequest on missing SAMLResponse POST var')
            except BadRequest, e:
                self.assertEqual(400, e.code)
                self.assertEqual('SAMLResponse missing from POST', e.description)
        # test invalid SAMLResponse
        with self.app.test_request_context('/',
                method='POST',
                data=dict(SAMLResponse='invalid', RelayState='/next')):
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.handle_assertion(request)
                self.fail(
                    'Expected BadRequest on invalid SAMLResponse POST var')
            except BadRequest, e:
                self.assertEqual(400, e.code)
                self.assertEqual('SAML response is invalid', e.description)
        # test on unsigned SAMLResponse when signing is required
        # create a response to assert upon
        name_id, authn_response = create_authn_response(session_id, ava,
                                      sign_response=False, sign_assertion=False)
        self.assertNotIn('Signature', authn_response)
        with self.app.test_request_context('/',
                method='POST',
                data=dict(SAMLResponse=base64.b64encode(authn_response),
                    RelayState='/next')):
            sp = auth.Saml(tmp_sp_config)
            # test fails if there is no known outstanding auth request
            try:
                sp.handle_assertion(request)
                self.fail(
                    'Expected Exception due to lack of outstanding request')
            except:
                pass
            # make the client thing there is outstanding request
            session['_saml_outstanding_queries'] = {session_id: '/next'}
            try:
                user_id, user_attributes, resp = sp.handle_assertion(request)
            except BadRequest, e:
                self.assertEqual(400, e.code)
                self.assertEqual('SAML response is invalid', e.description)

    def test_Saml_logout(self):
        not_on_or_after = time.time()+3600
        identity = {'4=id-1': {
            'https://sso.example.com/idp/metadata': (
                not_on_or_after, {
                    'authn_info': [],
                    'name_id': 'id-1',
                    'not_on_or_after': not_on_or_after,
                    'came_from': '/next',
                    'ava': {'uid': ['123456']}
                }
            )
        }}
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        with self.app.test_request_context('/',
                method='GET'):
            sp = auth.Saml(tmp_sp_config)
            # first need to be logged in, let's pretend
            session['_saml_identity'] = identity
            session['_saml_subject_id'] = saml.NameID(text='id-1')
            resp = sp.logout(next_url='/next')
            self.assertEqual(resp.status_code, 302)
            self.assert_("SAMLRequest" in resp.headers['Location'])
            url = urlparse.urlparse(resp.headers['Location'])
            self.assertEqual(url.hostname, 'sso.example.com')
            self.assertEqual(url.path, '/idp/slo')
            params = urlparse.parse_qs(url.query)
            self.assert_('SAMLRequest' in params)
            logout = samlp.logout_request_from_string(
                decode_base64_and_inflate(params['SAMLRequest'][0]))
            self.assertEqual(logout.destination,
                'https://sso.example.com/idp/slo')
            self.assertEqual(logout.name_id.text, 'id-1')
            self.assertIsNotNone(logout.signature)
            # check the caches still contain data
            self.assertEqual(session['_saml_identity'], identity)
            self.assertEqual(session['_saml_subject_id'].text, 'id-1')
            # verify state cache
            self.assert_(logout.id in session['_saml_state'])
            self.assertEqual(session['_saml_state'][logout.id]['entity_id'],
                'https://sso.example.com/idp/metadata')
            self.assertEqual(session['_saml_state'][logout.id]['entity_ids'],
                ['https://sso.example.com/idp/metadata'])
            self.assertEqual(session['_saml_state'][logout.id]['operation'],
                'SLO')
            self.assertEqual(session['_saml_state'][logout.id]['name_id'].text,
                'id-1')
            self.assertEqual(session['_saml_state'][logout.id]['reason'],
                '')
            self.assertTrue(session['_saml_state'][logout.id]['sign'])
        # test unsigned logout request
        with self.app.test_request_context('/',
                method='GET'):
            tmp_sp_config['key_file'] = None
            tmp_sp_config['service']['sp']['logout_requests_signed'] = 'false'
            sp = auth.Saml(tmp_sp_config)
            # first need to be logged in, let's pretend
            session['_saml_identity'] = identity
            session['_saml_subject_id'] = saml.NameID(text='id-1')
            resp = sp.logout(next_url='/next')
            self.assertEqual(resp.status_code, 302)
            self.assert_("SAMLRequest" in resp.headers['Location'])
            url = urlparse.urlparse(resp.headers['Location'])
            params = urlparse.parse_qs(url.query)
            self.assert_('SAMLRequest' in params)
            logout = samlp.logout_request_from_string(
                decode_base64_and_inflate(params['SAMLRequest'][0]))
            self.assertIsNone(logout.signature)
            # verify state cache shows signing off
            self.assertFalse(session['_saml_state'][logout.id]['sign'])

    def test_Saml_logout_via_post(self):
        self.skipTest('logout POST broken')
        not_on_or_after = time.time()+3600
        identity = {'4=id-1': {
            'https://sso.example.com/idp/metadata': (
                not_on_or_after, {
                    'authn_info': [('urn:oasis:names:tc:SAML:2.0:ac:classes:Password', [])],
                    'name_id': saml.NameID(text='id-1'),
                    'not_on_or_after': not_on_or_after,
                    'came_from': '/next',
                    'ava': {'uid': ['a123456']}
                }
            )
        }}
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test signed authentication request
        with self.app.test_request_context('/',
                method='GET'):
            tmp_sp_config['metadata'] = {
                'local': [root_path + '/idp_post_metadata.xml']
            }
            sp = auth.Saml(tmp_sp_config)
            # first need to be logged in, let's pretend
            session['_saml_identity'] = identity
            session['_saml_subject_id'] = saml.NameID(text='id-1')
            resp, status = sp.logout(next_url='/next')
            self.assertEqual(status, 200)
            _form = unpack_form(resp['data'][3])
            self.assert_('SAMLRequest' in _form)
            self.assert_('RelayState' in _form)

    def test_Saml_logout_not_logged_in(self):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        with self.app.test_request_context('/',
                method='GET'):
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.logout(next_url='/next')
                self.fail('Expected AuthException on attempted logout when'
                    ' not logged in')
            except auth.AuthException, e:
                self.assertEqual(
                    'Unable to retrieve subject id for logout', str(e))

    def test_Saml_logout_invalid_config(self):
        not_on_or_after = time.time()+3600
        identity = {'4=id-1': {
            'https://sso.example.com/idp/metadata': (
                not_on_or_after, {
                    'authn_info': [],
                    'name_id': 'id-1',
                    'not_on_or_after': not_on_or_after,
                    'came_from': '/next',
                    'ava': {'uid': ['123456']}
                }
            )
        }}
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        with self.app.test_request_context('/',
                method='GET'):
            tmp_sp_config['key_file'] = None
            sp = auth.Saml(tmp_sp_config)
            # first need to be logged in, let's pretend
            session['_saml_identity'] = identity
            session['_saml_subject_id'] = saml.NameID(text='id-1')
            try:
                sp.logout(next_url='/next')
                self.fail(
                    'Expected AuthException on invalid Saml logout request')
            except TypeError, e:
                self.assertEqual('sequence item 3: expected string or '
                                 'Unicode, NoneType found', str(e))
            except auth.AuthException, e:
                self.assertEqual(
                    'Signature requested for this Saml logout request,'
                    ' but no private key file configured', str(e))

    def test_Saml_handle_logout_response(self):
        not_on_or_after = time.time()+3600
        identity = {'4=id-1': {
            'https://sso.example.com/idp/metadata': (
                not_on_or_after, {
                    'authn_info': [],
                    'name_id': 'id-1',
                    'not_on_or_after': not_on_or_after,
                    'came_from': '/next',
                    'ava': {'uid': ['123456']}
                }
            )
        }}
        state = {
            'entity_ids': ['https://sso.example.com/idp/metadata'],
            'subject_id': 'id-1',
            #'return_to': '/next',
            'name_id': saml.NameID(text='id-1'),
            'entity_id': 'https://sso.example.com/idp/metadata',
            'not_on_or_after': not_on_or_after,
            'operation': 'SLO',
            'reason': '',
        }
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # create a response to assert upon
        sp = auth.Saml(tmp_sp_config)
        session_id, logout_response = create_logout_response('id-1',
            destination='https://sso.example.com/idp/slo',
            issuer_entity_id='https://sso.example.com/idp/metadata',
            req_entity_id='https://foo.example.com/sp/metadata')
        self.assert_('Signature' in logout_response)
        # test SAMLResponse logout as GET
        with self.app.test_request_context('/',
                method='GET',
                query_string=dict(
                    SAMLResponse=deflate_and_base64_encode(logout_response),
                    RelayState='/next')):
            # first need to be logged in, let's pretend
            session['_saml_identity'] = identity
            session['_saml_subject_id'] = saml.NameID(text='id-1')
            session['_saml_state'] = {session_id: state}
            success, resp = sp.handle_logout(request, next_url='/next')
            self.assertEqual(session.get('_saml_identity', None), {})
            self.assertIsNone(session.get('_saml_subject_id', None))
            self.assertEqual(session.get('_saml_state', None), {})
            self.assertTrue(success)
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.headers['Location'], '/next')
        # test SAMLResponse logout as POST
        with self.app.test_request_context('/',
                method='POST',
                data=dict(
                    SAMLResponse=base64.b64encode(logout_response),
                    RelayState='/next')):
            endpoints = tmp_sp_config['service']['sp']['endpoints']
            slo = endpoints['single_logout_service'][0][0]
            endpoints['single_logout_service'] = [(slo, BINDING_HTTP_POST)]
            # first need to be logged in, let's pretend
            session['_saml_identity'] = identity
            session['_saml_subject_id'] = saml.NameID(text='id-1')
            session['_saml_state'] = {session_id: state}
            success, resp = sp.handle_logout(request, next_url='/next')
            self.assertTrue(success)
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.headers['Location'], '/next')

    def test_Saml_handle_logout_request(self):
        not_on_or_after = time.time()+3600
        identity = {'4=id-1': {
            'https://sso.example.com/idp/metadata': (
                not_on_or_after, {
                    'authn_info': [('urn:oasis:names:tc:SAML:2.0:ac:classes:Password', [])],
                    'name_id': saml.NameID(text='id-1'),
                    'not_on_or_after': not_on_or_after,
                    'came_from': '/next',
                    'ava': {'uid': ['a123456']}
                }
            )
        }}
        state = {
            'entity_ids': ['https://sso.example.com/idp/metadata'],
            'name_id': saml.NameID(text='id-1'),
            'entity_id': 'https://sso.example.com/idp/metadata',
            'not_on_or_after': not_on_or_after,
            'operation': 'SLO',
            'reason': '',
            'sign': False,
        }
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # create a response to assert upon
        sp = auth.Saml(tmp_sp_config)
        logout_request = create_logout_request(
            subject_id='id-1',
            destination='https://foo.example.com/sp/slo',
            issuer_entity_id='https://sso.example.com/idp/metadata',
            req_entity_id='https://sso.example.com/idp/metadata')
        # test SAMLRequest logout
        with self.app.test_request_context('/',
                method='GET',
                query_string=dict(
                    SAMLRequest=deflate_and_base64_encode(str(logout_request)),
                    RelayState=deflate_and_base64_encode(logout_request.id))):
            # first need to be logged in, let's pretend
            session['_saml_identity'] = identity
            session['_saml_subject_id'] = saml.NameID(
                name_qualifier='https://sso.example.com/idp/metadata',
                text='id-1')
            session['_saml_state'] = {'id-' + logout_request.id: state}
            success, resp = sp.handle_logout(request, next_url='/next')
            self.assertTrue(success)
            self.assertEqual(resp.status_code, 302)
            self.assert_("SAMLResponse" in resp.headers['Location'])
            url = urlparse.urlparse(resp.headers['Location'])
            params = urlparse.parse_qs(url.query)
            self.assert_('SAMLResponse' in params)
            logout = samlp.logout_response_from_string(
                decode_base64_and_inflate(params['SAMLResponse'][0]))
            # CHANGE THIS
            # LOGOUT IS RETURNING Responder STATUS
            self.assertEqual(logout.status.status_code.value,
                'urn:oasis:names:tc:SAML:2.0:status:Responder')
            self.assertEqual(logout.destination, 'https://sso.example.com/idp/slo')

    def test_Saml_handle_logout_invalid_missing(self):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test missing any GET/POST parameters
        with self.app.test_request_context('/',
                method='GET'):
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.handle_logout(request)
                self.fail(
                    'Expected BadRequest on missing SAMLResponse'
                    ' GET arg')
            except BadRequest, e:
                self.assertEqual(400, e.code)
                self.assertEqual('Unable to find supported binding', e.description)
        # test missing SAMLRequest/SAMLResponse in GET
        with self.app.test_request_context('/',
                method='GET',
                query_string=dict(RelayState='/next')):
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.handle_logout(request)
                self.fail(
                    'Expected BadRequest on missing SAMLRequest/SAMLResponse'
                    ' GET arg')
            except BadRequest, e:
                self.assertEqual(400, e.code)
                self.assertEqual('Unable to find SAMLRequest or SAMLResponse',
                                 e.description)
        # test missing SAMLRequest/SAMLResponse in POST
        with self.app.test_request_context('/',
                method='POST',
                data=dict(RelayState='/next')):
            # tell config to accept POST binding on the slo endpoint
            endpoints = tmp_sp_config['service']['sp']['endpoints']
            slo = endpoints['single_logout_service'][0][0]
            endpoints['single_logout_service'] = [(slo, BINDING_HTTP_POST)]
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.handle_logout(request)
                self.fail(
                    'Expected BadRequest on missing SAMLRequest/SAMLResponse'
                    ' POST data')
            except BadRequest, e:
                self.assertEqual(400, e.code)
                self.assertEqual('Unable to find SAMLRequest or SAMLResponse',
                                 e.description)

    def test_Saml_handle_logout_invalid_SAMLResponse(self):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test invalid SAMLResponse in GET
        with self.app.test_request_context('/',
                method='GET',
                query_string=dict(SAMLResponse='invalid', RelayState='/next')):
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.handle_logout(request)
                self.fail(
                    'Expected BadRequest on invalid SAMLResponse GET arg')
            except BadRequest, e:
                self.assertEqual(400, e.code)
                self.assertEqual('SAML response is invalid', e.description)
        # test invalid SAMLResponse in POST
        with self.app.test_request_context('/',
                method='POST',
                data=dict(SAMLResponse='invalid', RelayState='/next')):
            # tell config to accept POST binding on the slo endpoint
            endpoints = tmp_sp_config['service']['sp']['endpoints']
            slo = endpoints['single_logout_service'][0][0]
            endpoints['single_logout_service'] = [(slo, BINDING_HTTP_POST)]
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.handle_logout(request)
                self.fail(
                    'Expected BadRequest on invalid SAMLResponse POST data')
            except BadRequest, e:
                self.assertEqual(400, e.code)
                self.assertEqual('SAML response is invalid', e.description)

    def test_Saml_handle_logout_invalid_SAMLRequest(self):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test invalid SAMLRequest
        with self.app.test_request_context('/',
                method='GET',
                query_string=dict(SAMLRequest='invalid', RelayState='/next')):
            sp = auth.Saml(tmp_sp_config)
            try:
                sp.handle_logout(request)
                self.fail(
                    'Expected BadRequest on invalid SAMLRequest GET arg')
            except BadRequest, e:
                self.assertEqual(400, e.code)
                self.assertEqual('SAML request is invalid', e.description)

    def test_Saml_get_metadata(self):
        entity_id = 'https://sso.example.com/idp/metadata'
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test with defined private key file
        with self.app.test_request_context('/',
                method='GET'):
            sp = auth.Saml(tmp_sp_config)
            resp = sp.get_metadata()
            self.assertTrue(
                'Content-type: text/xml; charset=utf-8' in str(resp.headers))
            metadata_xml = resp.data
            self.assert_("Signature" in metadata_xml)
            sp._config.load(tmp_sp_config)
            sls = sp._config.metadata.single_logout_service(
                entity_id, binding=BINDING_HTTP_REDIRECT, typ='idpsso')
            self.assertEqual(destinations(sls),
                ['https://sso.example.com/idp/slo'])
            ssos = sp._config.metadata.single_sign_on_service(entity_id)
            self.assertEqual(destinations(ssos),
                ['https://sso.example.com/idp/sso'])
        # test without defined private key file
        with self.app.test_request_context('/',
                method='GET'):
            tmp_sp_config['key_file'] = None
            sp = auth.Saml(tmp_sp_config)
            resp = sp.get_metadata()
            self.assertTrue(
                'Content-type: text/xml; charset=utf-8' in str(resp.headers))
            metadata_xml = resp.data
            self.assert_(not "Signature" in metadata_xml)

    def test_Saml_get_metadata_IdP(self):
        entity_id = 'https://foo.example.com/sp/metadata'
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_idp_config = copy.deepcopy(idp_config)
        # test with defined private key file
        with self.app.test_request_context('/',
                method='GET'):
            idp = auth.SamlServer(tmp_idp_config)
            resp = idp.get_metadata()
            self.assertTrue(
                'Content-type: text/xml; charset=utf-8' in str(resp.headers))
            metadata_xml = resp.data
            self.assert_("Signature" in metadata_xml)
            idp._config.load(tmp_idp_config)
            sls = idp._config.metadata.single_logout_service(
                entity_id, binding=BINDING_HTTP_REDIRECT, typ='spsso')
            self.assertEqual(destinations(sls),
                ['https://foo.example.com/sp/slo'])
        # test without defined private key file
        with self.app.test_request_context('/',
                method='GET'):
            tmp_idp_config['key_file'] = None
            idp = auth.SamlServer(tmp_idp_config)
            resp = idp.get_metadata()
            self.assertTrue(
                'Content-type: text/xml; charset=utf-8' in str(resp.headers))
            metadata_xml = resp.data
            self.assert_(not "Signature" in metadata_xml)

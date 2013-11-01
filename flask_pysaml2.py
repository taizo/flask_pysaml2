# -*- coding: utf-8 -*-
"""
Flask-PySAML2
-------------

This library implements an integration for the Flask web framework to the
PySAML2 library developed by Roland Hedberg.

The Service Provider integration is fairly complete. Identity Provider
integration is still under development.

Copyright (c) 2012, Kavi Corporation
License (Modified BSD License), see LICENSE for more details.
"""

import os
import logging

from flask import (session, make_response, redirect)
from werkzeug.exceptions import BadRequest

from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.server import Server
from saml2.metadata import (entity_descriptor, sign_entity_descriptor)
from saml2.config import SPConfig, IdPConfig
from saml2.cache import Cache
from saml2.sigver import security_context

LOGGER = logging.getLogger(__name__)

class AuthException(Exception):
    """Exception for Authentication errors (SAML2)"""
    pass

class Saml(object):

    """
    SAML Wrapper around pysaml2.

    Implements SAML2 Service Provider functionality for Flask.
    """

    def __init__(self, config, attribute_map=None):
        """Initialize SAML Service Provider.

        Args:
            config (dict): Service Provider config info in dict form
            attribute_map (dict): Mapping of attribute keys to user data
        """
        self._config = SPConfig()
        self._config.load(config)
        if config['metadata'].get('config'):
            # Hacked in a way to get the IdP metadata from a python dict
            # rather than having to resort to loading XML from file or http.
            idp_config = IdPConfig()
            idp_config.load(config['metadata']['config'][0])
            idp_entityid = config['metadata']['config'][0]['entityid']
            idp_metadata_str = str(entity_descriptor(idp_config, 24))
            LOGGER.debug('IdP XML Metadata for %s: %s' % (
                idp_entityid, idp_metadata_str))
            self._config.metadata.import_metadata(
                idp_metadata_str, idp_entityid)
        self.attribute_map = {}
        if attribute_map is not None:
            self.attribute_map = attribute_map

    def authenticate(self, next_url='/', binding=BINDING_HTTP_REDIRECT):
        """Start SAML Authentication login process.

        Args:
            next_url (string): HTTP URL to return user to when authentication
                is complete.
            binding (binding): Saml2 binding method to use for request,
                default BINDING_HTTP_REDIRECT (don't change til HTTP_POST
                support is complete in pysaml2.

        Returns:
            Flask Response object to return to user containing either
                HTTP_REDIRECT or HTTP_POST SAML message.

        Raises:
            AuthException: when unable to locate valid IdP.
            BadRequest: when invalid result returned from SAML client.
        """
        # find configured for IdP for requested binding method
        idp_entityid = ''
        idps = self._config.idps().keys()
        for idp in idps:
            if self._config.single_sign_on_services(idp, binding) != []:
                idp_entityid = idp
                break
        if idp_entityid == '':
            raise AuthException('Unable to locate valid IdP for this request')
        # fail if signing requested but no private key configured
        if self._config.authn_requests_signed == 'true':
            if not self._config.key_file \
                or not os.path.exists(self._config.key_file):
                raise AuthException(
                    'Signature requested for this Saml authentication request,'
                    ' but no private key file configured')

        LOGGER.debug('Connecting to Identity Provider %s' % idp_entityid)
        # retrieve cache
        outstanding_queries_cache = \
            AuthDictCache(session, '_saml_outstanding_queries')

        LOGGER.debug('Outstanding queries cache %s' % (
            outstanding_queries_cache))

        # make pysaml2 call to authenticate
        client = Saml2Client(self._config, logger=LOGGER)
        (session_id, result) = client.authenticate(
            entityid=idp_entityid,
            relay_state=next_url,
            binding=binding)

        # The psaml2 source for this method indicates that BINDING_HTTP_POST
        # should not be used right now to authenticate. Regardless, we'll
        # check for it and act accordingly.

        if binding == BINDING_HTTP_REDIRECT:
            LOGGER.debug('Redirect to Identity Provider %s ( %s )' % (
                idp_entityid, result))
            response = make_response('', 302, dict([result]))
        elif binding == BINDING_HTTP_POST:
            LOGGER.warn('POST binding used to authenticate is not currently'
                ' supported by pysaml2 release version. Fix in place in repo.')
            LOGGER.debug('Post to Identity Provider %s ( %s )' % (
                idp_entityid, result))
            response = make_response('\n'.join(result), 200)
        else:
            raise BadRequest('Invalid result returned from SAML client')

        LOGGER.debug(
            'Saving session_id ( %s ) in outstanding queries' % session_id)
        # cache the outstanding query
        outstanding_queries_cache.update({session_id: next_url})
        outstanding_queries_cache.sync()

        LOGGER.debug('Outstanding queries cache %s' % (
            session['_saml_outstanding_queries']))

        return response

    def handle_assertion(self, request):
        """Handle SAML Authentication login assertion (POST).

        Args:
            request (Request): Flask request object for this HTTP transaction.

        Returns:
            User Id (string), User attributes (dict), Redirect Flask response
                object to return user to now that authentication is complete.

        Raises:
            BadRequest: when error with SAML response from Identity Provider.
            AuthException: when unable to locate uid attribute in response.
        """
        if not request.form.get('SAMLResponse'):
            raise BadRequest('SAMLResponse missing from POST')
        # retrieve cache
        outstanding_queries_cache = \
            AuthDictCache(session, '_saml_outstanding_queries')
        identity_cache = IdentityCache(session, '_saml_identity')

        LOGGER.debug('Outstanding queries cache %s' % (
            outstanding_queries_cache))
        LOGGER.debug('Identity cache %s' % identity_cache)

        # use pysaml2 to process the SAML authentication response
        client = Saml2Client(self._config, identity_cache=identity_cache,
            logger=LOGGER)
        saml_response = client.response(
            dict(SAMLResponse=request.form['SAMLResponse']),
            outstanding_queries_cache)
        if saml_response is None:
            raise BadRequest('SAML response is invalid')
        # make sure outstanding query cache is cleared for this session_id
        session_id = saml_response.session_id()
        if session_id in outstanding_queries_cache.keys():
            del outstanding_queries_cache[session_id]
        outstanding_queries_cache.sync()
        # retrieve session_info
        saml_session_info = saml_response.session_info()
        LOGGER.debug('SAML Session Info ( %s )' % saml_session_info)
        # retrieve user data via API
        try:
            if self.attribute_map.get('uid', 'name_id') == 'name_id':
                user_id = saml_session_info.get('name_id')
            else:
                user_id = saml_session_info['ava'] \
                    .get(self.attribute_map.get('uid'))[0]
        except:
            raise AuthException('Unable to find "%s" attribute in response' % (
                self.attribute_map.get('uid', 'name_id')))
        # Future: map attributes to user info
        user_attributes = dict()
        # set subject Id in cache to retrieved name_id
        session['_saml_subject_id'] = saml_session_info.get('name_id')

        LOGGER.debug('Outstanding queries cache %s' % (
            session['_saml_outstanding_queries']))
        LOGGER.debug('Identity cache %s' % session['_saml_identity'])
        LOGGER.debug('Subject Id %s' % session['_saml_subject_id'])

        relay_state = request.form.get('RelayState', '/')
        LOGGER.debug('Returning redirect to %s' % relay_state)
        return user_id, user_attributes, redirect(relay_state)

    def logout(self, next_url='/', expire=None):
        """Start SAML Authentication logout process.

        Args:
            next_url (string): HTTP URL to return user to when logout is
                complete.
            expire (struct_time): The latest the log out should happen.

        Returns:
            Flask Response object to return to user containing either
                HTTP_REDIRECT or HTTP_POST SAML message.

        Raises:
            AuthException: when unable to resolve Identity Provider single logout end-point.
        """
        # retrieve cache
        state_cache = AuthDictCache(session, '_saml_state')
        identity_cache = IdentityCache(session, '_saml_identity')
        subject_id = session.get('_saml_subject_id')
        # don't logout if not logged in
        if subject_id is None:
            raise AuthException('Unable to retrieve subject id for logout')
        # fail if signing requested but no private key configured
        if self._config.logout_requests_signed == 'true':
            if not self._config.key_file \
                or not os.path.exists(self._config.key_file):
                raise AuthException(
                    'Signature requested for this Saml logout request,'
                    ' but no private key file configured')

        LOGGER.debug('State cache %s' % state_cache)
        LOGGER.debug('Identity cache %s' % identity_cache)
        LOGGER.debug('Subject Id %s' % subject_id)

        # use pysaml2 to initiate the SAML logout request
        client = Saml2Client(self._config, state_cache=state_cache,
            identity_cache=identity_cache, logger=LOGGER)
        saml_response = client.global_logout(subject_id,
            return_to=next_url, expire=expire)

        # sync the state to cache
        state_cache.sync()

        LOGGER.debug('State cache %s' % session['_saml_state'])
        LOGGER.debug('Identity cache %s' % session['_saml_identity'])

        if saml_response[1] == "": # used SOAP BINDING successfully
            return redirect(next_url)

        LOGGER.debug('Returning Response from SAML for continuation of the'
            ' logout process')
        return make_response('\n'.join(saml_response[3]),
            saml_response[1], saml_response[2]) # body, status, headers

    def _handle_logout_request(self, client, request, subject_id, binding):
        """Handle SAML Authentication logout request (GET).

        Args:
            client (Saml2Client): instance of SAML client class.
            request (Request): Flask request object for this HTTP transaction.
            subject_id (string): Id of the subject we are processing the
                logout for.
            binding (string): the SAML binding method being used for this
                request.

        Returns:
            Flask Response object to return to user containing
                HTTP_REDIRECT SAML message.

        Raises:
            BadRequest: when SAML request data is missing.
            AuthException: when SAML request indicates logout failed.
        """
        LOGGER.debug('Received a logout request from Identity Provider')

        # pysaml2 logout_request currently only returns for
        # BINDING_HTTP_REDIRECT. We will have it fail for anything
        # other than the header 'Location'

        try:
            headers, _success = client.logout_request(
                request.values, subject_id, binding=binding)
        except TypeError:
            raise BadRequest('SAML request is invalid')
        try:
            assert headers is not None
            assert headers[0][0] == 'Location'
            return redirect(headers[0][1])
        except:
            raise AuthException('An error occurred during logout')

    def _handle_logout_response(self, client, request, binding, next_url):
        """Handle SAML Authentication logout response (GET or POST).

        Args:
            client (Saml2Client): instance of SAML client class.
            request (Request): Flask request object for this HTTP transaction.
            binding (string): the SAML binding method being used for this
                request.
            next_url (string): URL to get redirected to if all is successful.

        Returns:
            Flask Response object to return to user containing
                HTTP_REDIRECT SAML message.

        Raises:
            BadRequest: when SAML response data is missing.
            AuthException: when SAML response indicates logout failed.
        """
        LOGGER.debug('Received a logout response from Identity Provider')
        try:
            saml_response = client.logout_response(
                request.values['SAMLResponse'], binding=binding)
        except TypeError:
            raise BadRequest('SAML response is invalid')
        LOGGER.debug(saml_response)
        if saml_response:
            if saml_response[1] == '': # used SOAP BINDING successfully
                response = redirect(next_url)
            else:
                # body, status, headers
                response = make_response('\n'.join(saml_response[3]),
                    saml_response[1], saml_response[2])
                # pysaml2 returns an empty 200 in some cases,
                # we'll redirect instead
                if response.status_code == 200 and not response.data:
                    response = redirect(next_url)
        else:
            raise AuthException('An error occurred during logout')
        return response

    def handle_logout(self, request, next_url='/'):
        """Handle SAML Authentication logout request/response.

        Args:
            request (Request): Flask request object for this HTTP transaction.
            next_url (string): URL to get redirected to if all is successful.

        Returns:
            (boolean) Success, Flask Response object to return to user
                containing HTTP_REDIRECT SAML message.

        Raises:
            BadRequest: when SAML request/response data is missing.
        """
        # retrieve cache
        state_cache = AuthDictCache(session, '_saml_state')
        identity_cache = IdentityCache(session, '_saml_identity')
        subject_id = session.get('_saml_subject_id')

        LOGGER.debug('State cache %s' % state_cache)
        LOGGER.debug('Identity cache %s' % identity_cache)
        LOGGER.debug('Subject Id %s' % subject_id)

        # use pysaml2 to complete the SAML logout request
        client = Saml2Client(self._config, state_cache=state_cache,
            identity_cache=identity_cache, logger=LOGGER)
        # let's try to figure out what binding is being used and what type of
        # logout call we are handling
        if request.args:
            binding = BINDING_HTTP_REDIRECT
        elif request.form:
            binding = BINDING_HTTP_POST
        else:
            # The SOAP binding is only valid on logout requests which currently
            # pysaml2 doesn't support.
            raise BadRequest('Unable to find supported binding')

        if 'SAMLRequest' in request.values:
            response = self._handle_logout_request(
                client, request, subject_id, binding)
        elif 'SAMLResponse' in request.values:
            response = self._handle_logout_response(
                client, request, binding, next_url)
        else:
            raise BadRequest('Unable to find SAMLRequest or SAMLResponse')

        # cache the state and remove subject if logout was successful
        success = identity_cache.get_identity(subject_id) == ({}, [])
        if success:
            session.pop('_saml_subject_id')
        state_cache.sync()

        LOGGER.debug('State cache %s' % session['_saml_state'])
        LOGGER.debug('Identity cache %s' % session['_saml_identity'])

        LOGGER.debug(
            'Returning redirect to complete/continue the logout process')
        return success, response

    def get_metadata(self):
        """Returns SAML Service Provider Metadata"""
        edesc = entity_descriptor(self._config, 24)
        if self._config.key_file:
            edesc = sign_entity_descriptor(edesc, 24, None, security_context(self._config))
        response = make_response(str(edesc))
        response.headers['Content-type'] = 'text/xml; charset=utf-8'
        return response

class SamlServer(object):
    """
    SAML Wrapper around pysaml2.

    Implements SAML2 Identity Provider functionality for Flask.
    """
    def __init__(self, config, attribute_map=None):
        """Initialize SAML Identity Provider.

        Args:
            config (dict): Identity Provider config info in dict form
            attribute_map (dict): Mapping of attribute keys to user data
        """
        self._config = IdPConfig()
        self._config.load(config)
        self._server = Server(config=self._config)
        self.attribute_map = {}
        if attribute_map is not None:
            self.attribute_map = attribute_map

    def handle_authn_request(self, request, login_form_cb):
        """Handles authentication request.

        TODO: create default login_form_cb, with unstyled login form?

        Args:
            request (Request): Flask request object for this HTTP transaction.
            login_form_cb (function): Function that displays login form with 
                username and password fields. Takes a single parameter which
                is the service_provider_id so the form may be styled accordingly.
        """
        if 'SAMLRequest' in request.values:
            details = self._server.parse_authn_request(request.details,
                BINDING_HTTP_REDIRECT)
            # TODO: check session for already authenticated user
            # and send authn_response immediately.
            # TODO: otherwise render login form login_form_cb(service_provider_id)
        else:
            pass # TODO: bad request?

    def get_service_provider_id(self, request):
        # TODO: pull service_provider_id from session
        pass

    def authn_response(self, userid):
        service_provider_id = get_service_provider_id()
        # TODO: send authn_response
        pass

    def get_metadata(self):
        """Returns SAML Identity Provider Metadata"""
        edesc = entity_descriptor(self._config, 24)
        if self._config.key_file:
            edesc = sign_entity_descriptor(edesc, 24, None, security_context(self._config))
        response = make_response(str(edesc))
        response.headers['Content-type'] = 'text/xml; charset=utf-8'
        return response

class AuthDictCache(dict):

    """Adapter to make working with session cache easier"""

    def __init__(self, session_instance, key):
        self.session = session_instance
        self.key = key
        super(AuthDictCache, self).__init__(self.session_data)

    @property
    def session_data(self):
        """Return session data associated with this cache"""
        return self.session.get(self.key, {})

    def sync(self):
        """Sync's the cache object with the underlying session store"""
        objs = {}
        objs.update(self)
        self.session[self.key] = objs

class IdentityCache(Cache):

    """Adapter for the Identity Cache pysaml2 Cache object"""

    def __init__(self, session_instance, key):
        super(IdentityCache, self).__init__()
        self._db = AuthDictCache(session_instance, key)
        self._sync = True

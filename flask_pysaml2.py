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

from flask import session, make_response, redirect
from werkzeug.exceptions import BadRequest

from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.extension.idpdisc import BINDING_DISCO #pylint: disable=unused-import
from saml2.client import Saml2Client
from saml2.metadata import (entity_descriptor, sign_entity_descriptor,
        do_key_descriptor)
from saml2.config import SPConfig, IdPConfig
from saml2.cache import Cache
from saml2.sigver import security_context
from saml2.s_utils import UnravelError, sid


LOGGER = logging.getLogger(__name__)


class AuthException(Exception):
    """Exception for Authentication errors (SAML2)"""
    pass


def _handle_logout_request(client, request, subject_id, binding):
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
        response = client.handle_logout_request(
                       request.values["SAMLRequest"],
                       subject_id, binding=binding,
                       relay_state=request.values["RelayState"])
    except (UnravelError, TypeError):
        raise BadRequest('SAML request is invalid')

    try:
        assert response['headers'] is not None
        assert isinstance(response['headers'], list)
        for header in response['headers']:
            if isinstance(header, tuple):
                tag, data = header
                if tag == 'Location':
                    return redirect(data)
    except:
        raise AuthException('An error occurred during logout')

def _handle_logout_response(client, request, binding, next_url):
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
        response = client.parse_logout_request_response(
                       request.values["SAMLResponse"], binding)
        saml_response = client.handle_logout_response(response)
    except (UnravelError, TypeError):
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

def _parse_key_descriptors(certs):
    """Creates the PySAML2 key descriptor for inclusion in a metadata object.

    Args:
        certs (list): Config information about the certificates and how they
            are used.

    Returns:
        (list): key descriptors for all configured certs.
    """
    key_descriptors = []
    for _cert in certs:
        _cdata = _cert.get('cert_data') or \
            "".join(open(_cert.get('cert_file')).readlines()[1:-1])
        if _cert.get('use', 'both') == 'both':
            key_descriptors.extend(
                    do_key_descriptor(_cdata, _cert.get('use', 'both')))
        else:
            key_descriptors.append(
                    do_key_descriptor(_cdata, _cert.get('use', 'both')))
    return key_descriptors

def _parse_metadata_dict_to_inline(metadata):
    """Convert any metadata included as dict to PySAML2's `inline` type.

    Currently PySAML supports remote, local files, and string IdP metadata to
    be included in the SP config dict as XML. It is also possible to pull your
    IdP metadata from local JSON files (the format of the JSON is nearly
    unparsable for any normal human).

    This function adds the ability to include the IdP metadata directly in the
    SP config as a dict of IdP attributes by hacking around this PySAML2
    limitation and converting the dict into XML via PySAML2's IdPConfig class.

    Note: In the process of trying to find an alternative which will allow us
        to NOT be hacking around PySAML so rudely in order to load IdP metadata
        from a Python dict. https://github.com/rohe/pysaml2/issues/172

    Args:
        metadata (dict): The IdP metadata this SP is configured for.

    Returns:
        (dict) config where any metadata `inline_dict` data has been
            converted to `inline` XML.
    """
    if metadata.get('inline_dict', None):
        metadata['inline'] = metadata.get('inline', [])
        for _idp in metadata.get('inline_dict'):
            idp_config = IdPConfig()
            idp_config.load(_idp)
            entity_desc = entity_descriptor(idp_config)
            # Hack for supporting multiple certificates.
            if _idp.get('certs'):
                # `certs` config directive overrided `cert_file`.
                entity_desc.idpsso_descriptor.key_descriptor = \
                        _parse_key_descriptors(_idp['certs'])
            idp_metadata_str = str(entity_desc)
            LOGGER.debug('IdP XML Metadata for %s: %s',
                _idp['entityid'], idp_metadata_str)
            metadata['inline'].append(idp_metadata_str)
        del metadata['inline_dict']
    return metadata


class Saml(object):

    """
    SAML Wrapper around pysaml2.

    Implements SAML2 Service Provider functionality for Flask.
    """

    def __init__(self, config):
        """Initialize SAML Service Provider.

        Args:
            config (dict): Service Provider config info in dict form
        """
        if config.get('metadata') is not None:
            config['metadata'] = _parse_metadata_dict_to_inline(
                    config['metadata'])
        self._config = SPConfig().load(config)
        self._config.setattr('', 'allow_unknown_attributes', True)
        # Set discovery end point, if configured for.
        if config['service']['sp'].get('ds'):
            self.discovery_service_end_point = \
                config['service']['sp'].get('ds')[0]

    def authenticate(self, next_url='/', binding=BINDING_HTTP_REDIRECT,
            selected_idp=None):
        """Start SAML Authentication login process.

        Args:
            next_url (string): HTTP URL to return user to when authentication
                is complete.
            binding (binding): Saml2 binding method to use for request.
                Defaults to BINDING_HTTP_REDIRECT (don't change til HTTP_POST
                support is complete in pysaml2).
            selected_idp (string): A specfic IdP that should be used to
                authenticate. Defaults to `None`.

        Returns:
            Flask Response object to return to user containing either
                HTTP_REDIRECT or HTTP_POST SAML message.

        Raises:
            AuthException: when unable to locate valid IdP.
            BadRequest: when invalid result returned from SAML client.
        """
        # Fail if signing requested but no private key configured.
        if self._config.getattr('authn_requests_signed') == 'true':
            if not self._config.key_file \
                or not os.path.exists(self._config.key_file):
                raise AuthException(
                    'Signature requested for this Saml authentication request,'
                    ' but no private key file configured')

        # Find configured for IdPs for requested binding method.
        bindable_idps = []
        all_idps = self._config.metadata.identity_providers()
        # Filter IdPs to allowed IdPs, if we have some.
        if self._config.getattr('idp') is not None:
            all_idps = list(set(all_idps) & set(self._config.getattr('idp')))
        # Filter IdPs to selected IdP, if we have one.
        if selected_idp is not None:
            all_idps = list(set(all_idps) & set([selected_idp]))
        # From all IdPs allowed/selected, get the ones we can bind to.
        for idp in all_idps:
            if self._config.metadata.single_sign_on_service(idp, binding) != []:
                bindable_idps.append(idp)
        if not len(bindable_idps):
            raise AuthException('Unable to locate valid IdP for this request')

        # Retrieve cache.
        outstanding_queries_cache = \
            AuthDictCache(session, '_saml_outstanding_queries')
        LOGGER.debug('Outstanding queries cache %s', outstanding_queries_cache)

        if len(bindable_idps) > 1:
            # Redirect to discovery service
            (session_id, response) = self._handle_discovery_request()
        else:
            idp_entityid = bindable_idps[0]
            LOGGER.debug('Connecting to Identity Provider %s', idp_entityid)

            # Make pysaml2 call to authenticate.
            client = Saml2Client(self._config)
            (session_id, result) = client.prepare_for_authenticate(
                entityid=idp_entityid,
                relay_state=next_url,
                sign=self._config.getattr('authn_requests_signed'),
                binding=binding)

            # The psaml2 source for this method indicates that
            # BINDING_HTTP_POST should not be used right now to authenticate.
            # Regardless, we'll check for it and act accordingly.

            if binding == BINDING_HTTP_REDIRECT:
                LOGGER.debug('Redirect to Identity Provider %s ( %s )',
                    idp_entityid, result)
                response = make_response('', 302, dict(result['headers']))
            elif binding == BINDING_HTTP_POST:
                LOGGER.debug('Post to Identity Provider %s ( %s )',
                    idp_entityid, result)
                response = result, 200
            else:
                raise BadRequest('Invalid result returned from SAML client')

        LOGGER.debug(
            'Saving session_id ( %s ) in outstanding queries', session_id)
        # cache the outstanding query
        outstanding_queries_cache.update({session_id: next_url})
        outstanding_queries_cache.sync()

        LOGGER.debug('Outstanding queries cache %s',
            session['_saml_outstanding_queries'])

        return response

    def _handle_discovery_request(self):
        """Handle SAML Discovery Service request. This method is called
        internally by the `authenticate` method when multiple acceptable IdPs
        are detected.

        Returns:
            Tuple containing session Id and Flask Response object to return to
                user containing either HTTP_REDIRECT to configured Discovery
                Service end point.

        Raises:
            AuthException: when unable to find discovery response end point.
        """
        session_id = sid()
        try:
            return_url = self._config.getattr(
                    'endpoints', 'sp')['discovery_response'][0][0]
        except KeyError:
            raise AuthException('Multiple IdPs configured with no' + \
                                ' configured Discovery response end point.')
        return_url += "?session_id=%s" % session_id
        #pylint: disable=star-args
        disco_url = Saml2Client.create_discovery_service_request(
                self.discovery_service_end_point,
                self._config.entityid, **{'return': return_url})
        LOGGER.debug('Redirect to Discovery Service %s', disco_url)
        return (session_id, make_response('', 302, {'Location': disco_url}))

    def handle_discovery_response(self, request):
        """Handle SAML Discovery Service response. This method is basically
        a wrapper around `authenticate` with a little extra logic for getting
        the `entityID` out of the request and the next_url and binding that was
        previously submitted to `authenticate` from the user's session.

        Args:
            request (Request): Flask request object for this HTTP transaction.

        Returns:
            Flask Response object to return to user containing either
                HTTP_REDIRECT or HTTP_POST SAML message.

        Raises:
            AuthException: when unable to locate valid IdP.
            BadRequest: when invalid result returned from SAML client.
        """
        session_id = request.args.get('session_id')
        next_url = '/'

        # Retrieve cache. Get `next_url` from cache.
        outstanding_queries_cache = \
            AuthDictCache(session, '_saml_outstanding_queries')
        if session_id in outstanding_queries_cache.keys():
            next_url = outstanding_queries_cache[session_id]
            del outstanding_queries_cache[session_id]
        outstanding_queries_cache.sync()
        # Get the selected IdP from the Discovery Service response.
        selected_idp = Saml2Client.parse_discovery_service_response(
                query=request.query_string)
        return self.authenticate(next_url=next_url, selected_idp=selected_idp)

    def handle_assertion(self, request):
        """Handle SAML Authentication login assertion (POST).

        Args:
            request (Request): Flask request object for this HTTP transaction.

        Returns:
            (tuple) SAML assertion response information (dict) containing the
                IdP entity id, the subject's name id, and any additional
                attributes which may have been returned in the assertion, and
                Redirect Flask response object to return user to now that
                authentication is complete.

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

        LOGGER.debug('Outstanding queries cache %s', outstanding_queries_cache)
        LOGGER.debug('Identity cache %s', identity_cache)

        # use pysaml2 to process the SAML authentication response
        client = Saml2Client(self._config, identity_cache=identity_cache)
        saml_response = client.parse_authn_request_response(
            request.form['SAMLResponse'],
            BINDING_HTTP_POST,
            outstanding=outstanding_queries_cache)
        if saml_response is None:
            raise BadRequest('SAML response is invalid')
        # make sure outstanding query cache is cleared for this session_id
        session_id = saml_response.session_id()
        if session_id in outstanding_queries_cache.keys():
            del outstanding_queries_cache[session_id]
        outstanding_queries_cache.sync()

        saml_subject_id = saml_response.name_id
        # Assemble SAML assertion info for returning to the method caller.
        saml_assertion_info = saml_response.get_identity()
        # Note: SAML assertion attributes can have multiple values so the
        # values returned for these attributes are lists even if there is only
        # one entry. For consistency the `name_id` returned with the SAML
        # assertion information has been included as a single item list.
        saml_assertion_info['name_id'] = [saml_response.get_subject().text]
        # The IdP entity id is obviously not an attribute, so no list required.
        saml_assertion_info['idp_entity_id'] = saml_response.issuer()
        LOGGER.debug('SAML Session Info ( %s )', saml_assertion_info)

        # set subject Id in cache to retrieved name_id
        session['_saml_subject_id'] = saml_subject_id

        LOGGER.debug('Outstanding queries cache %s',
            session['_saml_outstanding_queries'])
        LOGGER.debug('Identity cache %s', session['_saml_identity'])
        LOGGER.debug('Subject Id %s', session['_saml_subject_id'])

        relay_state = request.form.get('RelayState', '/')
        LOGGER.debug('Returning redirect to %s', relay_state)
        return (saml_assertion_info, redirect(relay_state))

    def logout(self, next_url='/'):
        """Start SAML Authentication logout process.

        Args:
            next_url (string): HTTP URL to return user to when logout is
                complete.

        Returns:
            Flask Response object to return to user containing either
                HTTP_REDIRECT or HTTP_POST SAML message.

        Raises:
            AuthException: Can not resolve IdP single logout end-point.
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

        LOGGER.debug('State cache %s', state_cache)
        LOGGER.debug('Identity cache %s', identity_cache)
        LOGGER.debug('Subject Id %s', subject_id)

        # use pysaml2 to initiate the SAML logout request
        client = Saml2Client(self._config, state_cache=state_cache,
            identity_cache=identity_cache)
        saml_response = client.global_logout(subject_id)

        # sync the state to cache
        state_cache.sync()

        LOGGER.debug('State cache %s', session['_saml_state'])
        LOGGER.debug('Identity cache %s', session['_saml_identity'])

        if saml_response.get('1', None) == "": # used SOAP BINDING successfully
            return redirect(next_url)

        LOGGER.debug('Returning Response from SAML for continuation of the'
            ' logout process')
        for _, item in saml_response.items():
            if isinstance(item, tuple):
                http_type, htargs = item
                break

        if http_type == BINDING_HTTP_POST:
            return htargs, 200
        else:
            return make_response('', 302, htargs['headers'])

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

        LOGGER.debug('State cache %s', state_cache)
        LOGGER.debug('Identity cache %s', identity_cache)
        LOGGER.debug('Subject Id %s', subject_id)

        # use pysaml2 to complete the SAML logout request
        client = Saml2Client(self._config, state_cache=state_cache,
            identity_cache=identity_cache)
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
            response = _handle_logout_request(client, request, subject_id,
                                              binding)
        elif 'SAMLResponse' in request.values:
            response = _handle_logout_response(client, request, binding,
                                               next_url)
        else:
            raise BadRequest('Unable to find SAMLRequest or SAMLResponse')

        # cache the state and remove subject if logout was successful
        success = identity_cache.get_identity(subject_id) == ({}, [])
        if success:
            session.pop('_saml_subject_id', None)
        state_cache.sync()

        LOGGER.debug('State cache %s', session['_saml_state'])
        LOGGER.debug('Identity cache %s', session['_saml_identity'])

        LOGGER.debug(
            'Returning redirect to complete/continue the logout process')
        return success, response

    def get_metadata(self):
        """Returns SAML Service Provider Metadata"""
        edesc = entity_descriptor(self._config)
        if self._config.key_file:
            _, edesc = sign_entity_descriptor(edesc, None,
                                           security_context(self._config))
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

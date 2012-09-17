import os
from saml2 import BINDING_HTTP_REDIRECT

root_path = os.path.dirname(os.path.abspath(__file__))

CONFIG = {
    'entityid': 'https://foo.example.com/sp/metadata',
    'contact_person': [{
        'given_name': 'John',
        'sur_name': 'Smith',
        'email_address': 'john.smith@foo.example.com',
        'type': 'technical',
    }],
    'service': {
        'sp': {
            'name': 'Test Service Provider',
            'endpoints': {
                'assertion_consumer_service': ['https://foo.example.com/sp/acs'],
                'single_logout_service': [('https://foo.example.com/sp/slo',
                    BINDING_HTTP_REDIRECT)],
            },
            'idp': {
                'https://sso.example.com/idp/metadata' : None,
            },
            'logout_requests_signed': 'true',
            'authn_requests_signed': 'true',
            'want_assertions_signed': 'true',
            # The following setting allows for handling unsolicited
            # assertions which ironically is the expected behavior according to
            # the SAML 2.0 specification
            #'allow_unsolicited': 'true',
        },
    },
    'debug': False,
    'xmlsec_binary': '/usr/bin/xmlsec1',
    'key_file': root_path + '/sso_private.key',
    'cert_file': root_path + '/sso_public.crt',
    'ca_certs': None,
    'metadata': {
        'local': [root_path + '/idp_metadata.xml'],
    },
}

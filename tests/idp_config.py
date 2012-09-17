import os
from saml2 import BINDING_HTTP_REDIRECT

root_path = os.path.dirname(os.path.abspath(__file__))

CONFIG = {
    'entityid': 'https://sso.example.com/idp/metadata',
    'contact_person': [{
        'given_name': 'John',
        'sur_name': 'Smith',
        'email_address': 'john.smith@sso.example.com',
        'type': 'technical',
    }],
    'service': {
        'idp': {
            'name': 'Test Service Provider',
            'endpoints': {
                'single_sign_on_service': [('https://sso.example.com/idp/sso',
                    BINDING_HTTP_REDIRECT)],
                'single_logout_service': [('https://sso.example.com/idp/slo',
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
    'debug': True,
    'xmlsec_binary': '/usr/bin/xmlsec1',
    'key_file': root_path + '/sso_private.key',
    'cert_file': root_path + '/sso_public.crt',
    'ca_certs': None,
    'metadata': {
        'local': [root_path + '/sp_metadata.xml'],
    },
}
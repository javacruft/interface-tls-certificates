import json

from charms.reactive import set_flag, clear_flag
from charms.reactive import Endpoint
from charms.reactive import when_any, when_not, when


class TlsProvides(Endpoint):
    '''The class that provides a TLS interface other units.'''

    def __init__(self):
        super(TlsProvides, self).__init__()
        self.multi_certs = {}

    @when_any('endpoint.{endpoint_name}.changed.common_name',
              'endpoint.{endpoint_name}.changed.sans',
              'endpoint.{endpoint_name}.changed.certificate_name',
              'endpoint.{endpoint_name}.changed.cert_requests')
    def new_request(self):
        # New cert request detected, set flags and clear changed flags
        set_flag(self.expand_name('endpoint.{endpoint_name}.new-request'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.'
                                    'changed.common_name'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.'
                                    'changed.sans'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.'
                                    'changed.certificate_name'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.'
                                    'changed.cert_requests'))

    @when('endpoint.{endpoint_name}.joined')
    def joined(self):
        '''When a unit joins, set the available state.'''
        set_flag(self.expand_name('{endpoint_name}.connected'))

    @when_not('endpoint.{endpoint_name}.joined')
    def broken_or_departed(self):
        '''Remove the available state from the unit as we are leaving.'''
        clear_flag(self.expand_name('{endpoint_name}.connected'))

    def set_ca(self, certificate_authority):
        '''Set the CA on all relations.'''
        # Iterate over all conversations of this type.
        for relation in self.relations:
            # All the clients get the same CA, so send it to them.
            relation.to_publish['ca'] = certificate_authority

    def set_chain(self, chain):
        '''Set the chain on all the conversations in the relation data.'''
        # Iterate over all conversations of this type.
        for relation in self.relations:
            # All the clients get the same chain, so send it to them.
            relation.to_publish['chain'] = chain

    def set_client_cert(self, unit, cert, key):
        '''Set the client cert and key for the provided units relation.'''
        unit.relation.to_publish['client.cert'] = cert
        unit.relation.to_publish['client.key'] = key

    def set_server_cert(self, unit, cert, key):
        '''Set the server cert and key for the provided units relation.'''
        name = unit.unit_name.replace('/', '_')
        unit.relation.to_publish['{}.server.cert'.format(name)] = cert
        unit.relation.to_publish['{}.server.key'.format(name)] = key

    def set_server_multicerts(self, unit):
        '''Provide the processed requests for the provided unit scope.'''
        # The scope is the unit name, replace the slash with underscore.
        name = unit.unit_name.replace('/', '_')
        unit.relation.to_publish['{}.processed_requests'.format(name)] = \
            json.dumps(self.multi_certs[unit.unit_name], sort_keys=True)

    def add_server_cert(self, unit, cn, cert, key):
        '''
            'client_0': {
                'admin': {
                    'cert': cert
                    'key': key}}
        '''
        if unit.unit_name not in self.multi_certs:
            self.multi_certs[unit.unit_name] = {}

        self.multi_certs[unit.unit_name][cn] = {
            'cert': cert,
            'key': key
        }

    def get_server_requests(self):
        '''One provider can have many requests to generate server certificates.
        Return a map of all server request objects indexed by the scope
        which is essentially unit name.'''
        request_map = {}
        for relation in self.relations:
            for unit in relation.units:
                common_name = unit.received['common_name']
                sans = unit.received['sans']
                certificate_name = unit.received['certificate_name']
                cert_requests = unit.received['cert_requests']
                if (not all([common_name, certificate_name]) or
                        not cert_requests):
                    continue
                request = {
                    'unit': unit,
                    'common_name': common_name,
                    'certificate_name': certificate_name,
                }
                if sans:
                    request['sans'] = json.loads(sans)
                if cert_requests:
                    request['cert_requests'] = json.loads(cert_requests)
            # Create a map indexed by unit name.
            request_map[unit.unit_name] = request
        return request_map

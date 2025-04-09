from pathlib import Path

class ConfigServerModule:
    def __init__(self, resource_directory, server_cert_chain, server_key, intermadiate_server_cert_chain, intermadiate_server_key, ca_cert=None, server_file=None):
        self.resource_directory = resource_directory
        self.server_cert_chain = server_cert_chain
        self.server_key = server_key
        self.intermadiate_server_cert_chain = intermadiate_server_cert_chain
        self.intermadiate_server_key = intermadiate_server_key
        # Adicionar ca_cert com valor padrão
        self.ca_cert = ca_cert if ca_cert else resource_directory / 'rootca.cert.pem'
        self.server_file = server_file
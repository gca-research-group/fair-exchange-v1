import argparse
from pathlib import Path
from fairExchange.Utils.Configurations import Configuration
from fairExchange.Utils.ConfigServer import ConfigServerModule
from fairExchange.Utils.ConfigClient import ConfigClientModule


class ConfigsAlice:

    def __init__(self):
        server_name = "localhost"
        local_port = 8290
        client_name = "Alice"
        buffer_size = 4096
        separator = "<SEPARATOR>"
        recv_file_name_prefix = ""
        headersize = 10
        path_file = Path(__file__).resolve().parent / "files"
        server_file = "alicedoc_encrypted.txt"
        cliente_file = "aliceFile.txt"

        # Garantir que o diretório de arquivos exista
        path_file.mkdir(parents=True, exist_ok=True)

        # Configurações para o servidor (módulo - attestable)
        resource_directory = Path(__file__).resolve().parent.parent.parent / 'certskeys' / 'alice'
        server_cert_chain = resource_directory / 'server.cert.pem'
        server_key = resource_directory / 'server.key.pem'
        intermadiate_server_key = resource_directory / 'server.key.pem'
        intermadiate_server_cert_chain = resource_directory / 'server.intermediate.chain.pem'

        # Certificado CA para verificação de clientes
        ca_cert = resource_directory / 'rootca.cert.pem'

        # Criar configuração do servidor com o certificado CA explícito
        configServerModule = ConfigServerModule(
            resource_directory,
            server_cert_chain,
            server_key,
            intermadiate_server_cert_chain,
            intermadiate_server_key,
            ca_cert,
            server_file
        )

        # Configurações para comunicar com o servidor (módulo - attestable)
        resource_directory_client = Path(__file__).resolve().parent.parent.parent / 'certskeys' / 'alice'
        client_cert_chain = resource_directory_client / 'client.chain.pem'
        client_key = resource_directory_client / 'client.key.pem'
        intermadiate_client_cert_chain = resource_directory_client / 'client.intermediate.chain.pem'
        intermadiate_client_key = resource_directory_client / 'client.key.pem'
        ca_cert_client = resource_directory_client / 'rootca.cert.pem'

        # Verificar se os arquivos de certificado e chave existem
        for cert_file in [server_cert_chain, server_key, intermadiate_server_cert_chain,
                          intermadiate_server_key, ca_cert, client_cert_chain, client_key,
                          intermadiate_client_cert_chain, intermadiate_client_key, ca_cert_client]:
            if not cert_file.exists():
                print(f"Aviso: Arquivo de certificado/chave não encontrado: {cert_file}")

        # Criar configuração do cliente
        configClientModule = ConfigClientModule(
            resource_directory_client,
            client_cert_chain,
            client_key,
            intermadiate_client_cert_chain,
            intermadiate_client_key,
            ca_cert_client,
            None,
            cliente_file
        )

        # Criar configuração geral
        self.configuration = Configuration(
            server_name,
            local_port,
            client_name,
            path_file,
            separator,
            buffer_size,
            headersize,
            recv_file_name_prefix,
            configServerModule,
            configClientModule
        )
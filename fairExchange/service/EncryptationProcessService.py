import threading
import time
import logging
import os
from pathlib import Path

from fairExchange.client.Client import ClientSSL
from fairExchange.server.ServerSSL import ServerSSL

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('EncryptationProcessService')


class EncryptationProcessService():
    def __init__(self):
        self.server = None
        self.client = None
        self.server_thread = None

    def startProcess(self, conf):
        """
        Inicia o processo de encriptação para um cliente.

        Args:
            conf: Configuração do cliente

        Returns:
            Tupla (sucesso, arquivo_recebido)
        """
        if conf is None:
            logger.error("Configuração não fornecida")
            return False, None

        try:
            logger.info(f"-----------------------------------------------------------------------------------------")
            logger.info(
                f"------Iniciando processo de encriptação do documento de {conf.configuration.client_name}-----")

            # Iniciar servidor em uma thread separada
            self.server_thread = threading.Thread(target=self.start_server, name="encryption_server", args=(conf,))
            self.server_thread.daemon = True
            self.server_thread.start()

            # Aguardar um momento para o servidor iniciar
            time.sleep(1)

            # Iniciar cliente e enviar arquivo para encriptação
            client, received_file = self.start_client(conf)
            self.client = client

            logger.info(
                f"------Finalizado processo de encriptação do documento de {conf.configuration.client_name}-----")

            return True, received_file

        except Exception as e:
            logger.error(f"Ocorreu um erro durante o processo de encriptação: {e}")
            self.cleanup()
            return False, None

    def start_server(self, conf):
        """
        Inicia o servidor attestable para encriptação.

        Args:
            conf: Configuração do cliente

        Returns:
            Instância do servidor
        """
        try:
            logger.info(f" --> 1 - {conf.configuration.client_name} iniciando seu Attestable")

            # Garantir que os diretórios necessários existam
            client_dir = Path(f"{conf.configuration.client_name}")
            os.makedirs(client_dir / "temp", exist_ok=True)
            os.makedirs(client_dir / "files", exist_ok=True)

            # Criar e iniciar o servidor
            server = ServerSSL(
                conf,
                conf.configuration.config_server.server_cert_chain,
                conf.configuration.config_server.server_key,
                "uploadFile",
                conf.configuration.server_name,
                conf.configuration.local_port,
                None,
                True
            )

            self.server = server
            logger.info(f" --> Attestable de {conf.configuration.client_name} iniciado com sucesso")

            return server

        except Exception as e:
            logger.error(f"Erro ao iniciar o servidor attestable: {e}")
            raise

    def start_client(self, conf):
        """
        Inicia o cliente e envia o arquivo para encriptação.

        Args:
            conf: Configuração do cliente

        Returns:
            Tupla (cliente, arquivo_recebido)
        """
        try:
            logger.info(f" --> 2 - Iniciando cliente para {conf.configuration.client_name}")

            # Criar e iniciar o cliente
            client = ClientSSL(
                conf,
                conf.configuration.config_client.client_cert_chain,
                conf.configuration.config_client.client_key,
                conf.configuration.server_name,
                conf.configuration.local_port,
                True
            )

            # Conectar ao servidor attestable
            server_name = "GCA"  # Nome do servidor para verificação SSL
            if not client.sock_connect(server_name):
                raise Exception(f"Não foi possível conectar ao attestable de {conf.configuration.client_name}")

            # Obter caminho do arquivo a ser encriptado
            path_f = conf.configuration.path_file
            cliente_f = conf.configuration.config_client.cliente_file

            # Verificar se o arquivo existe
            file_path = path_f / cliente_f
            if not os.path.exists(file_path):
                raise Exception(f"Arquivo não encontrado: {file_path}")

            # Enviar arquivo para encriptação e receber arquivo encriptado
            logger.info(f" --> 3 - Enviando arquivo {cliente_f} para encriptação")
            received_file = client.send_and_receive_encrypted_file(file_path)

            if not received_file:
                raise Exception("Falha ao receber arquivo encriptado")

            logger.info(f" --> 4 - Arquivo encriptado recebido: {received_file}")

            return client, path_f / received_file

        except Exception as e:
            logger.error(f"Erro ao iniciar cliente ou enviar arquivo: {e}")
            raise

    def cleanup(self):
        """
        Limpa recursos utilizados pelo processo de encriptação.
        """
        logger.info("Limpando recursos...")

        # Fechar cliente
        if self.client:
            try:
                self.client.close_socket()
            except:
                pass

        # Parar servidor
        if self.server:
            try:
                self.server.stop_server()
            except:
                pass

        logger.info("Recursos limpos")

    def __del__(self):
        """
        Destrutor da classe, garante que os recursos sejam limpos.
        """
        self.cleanup()

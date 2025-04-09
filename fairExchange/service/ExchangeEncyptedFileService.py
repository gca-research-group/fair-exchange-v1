import threading
import logging
import os
import time
import random
import string
from pathlib import Path

from fairExchange.client.Client import ClientSSL
from fairExchange.server.ServerSSL import ServerSSL
from fairExchange.service.FileVerificationService import FileVerificationService

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ExchangeEncryptedFile')


class ExchangeEncryptedFile():
    def __init__(self):
        self.verification_services = {}

    def startProcess(self, conf1, conf2, encrypted_file_Alice, encrypted_file_Bob):
        """
        Inicia o processo de troca de arquivos encriptados entre Alice e Bob.

        Args:
            conf1: Configuração de Alice
            conf2: Configuração de Bob
            encrypted_file_Alice: Arquivo encriptado de Alice
            encrypted_file_Bob: Arquivo encriptado de Bob

        Returns:
            True se a troca for bem-sucedida, False caso contrário
        """
        try:
            logger.info("-----------------------------------------------------------------------------------------")
            logger.info("------Iniciando processo de troca de documentos encriptados-----")

            # Criar serviços de verificação para Alice e Bob
            self.verification_services[conf1.configuration.client_name] = FileVerificationService(conf1)
            self.verification_services[conf2.configuration.client_name] = FileVerificationService(conf2)

            # Gerar compromissos para os arquivos encriptados
            alice_commitment = self.verification_services[conf1.configuration.client_name].generate_file_commitment(
                encrypted_file_Alice)
            bob_commitment = self.verification_services[conf2.configuration.client_name].generate_file_commitment(
                encrypted_file_Bob)

            if not alice_commitment or not bob_commitment:
                logger.error("Falha ao gerar compromissos para os arquivos encriptados")
                return False

            # Trocar compromissos entre Alice e Bob
            logger.info("Trocando compromissos entre Alice e Bob")
            # Em um cenário real, esta troca seria feita através da rede
            # Aqui, simulamos a troca diretamente

            # Iniciar servidor para receber arquivo encriptado
            server_thread = threading.Thread(
                target=self.upServerToReceivDocEncrypted,
                name="exchange_server",
                args=(conf1, encrypted_file_Bob, bob_commitment)
            )
            server_thread.start()

            # Aguardar um momento para o servidor iniciar
            time.sleep(1)

            # Enviar arquivo encriptado para o outro cliente
            client_name = "GCA"  # Nome do servidor para verificação SSL
            success = self.upClienteToSendDocumentEncripted(conf2, client_name, encrypted_file_Alice, alice_commitment)

            if not success:
                logger.error("Falha na troca de arquivos encriptados")
                return False

            logger.info("-----------------------------------------------------------------------------------------")
            logger.info("------Processo de troca de documentos encriptados concluído com sucesso-----")
            return True

        except Exception as e:
            logger.error(f"Erro durante o processo de troca de arquivos encriptados: {e}")
            return False

    def upServerToReceivDocEncrypted(self, conf, file_to_exchange, file_commitment):
        """
        Inicia o servidor para receber o arquivo encriptado.

        Args:
            conf: Configuração do cliente
            file_to_exchange: Arquivo encriptado a ser trocado
            file_commitment: Compromisso do arquivo a ser recebido
        """
        try:
            server_cert_chain = conf.configuration.config_server.intermadiate_server_cert_chain
            server_key = conf.configuration.config_server.intermadiate_server_key
            host = conf.configuration.server_name
            local_port = 8290

            logger.info(f"------Iniciando módulo de {conf.configuration.client_name} para troca de documentos-----")

            # Criar diretório para armazenar o arquivo recebido
            exchange_dir = Path(f"{conf.configuration.client_name}/exchange")
            os.makedirs(exchange_dir, exist_ok=True)

            # Salvar compromisso em arquivo para uso posterior
            commitment_path = exchange_dir / f"received_commitment.json"
            with open(commitment_path, 'w') as f:
                import json
                json.dump(file_commitment, f, indent=2)

            # Iniciar servidor
            server = ServerSSL(
                conf,
                server_cert_chain,
                server_key,
                "exchangeEncryptedFiles",
                host,
                local_port,
                file_to_exchange,
                True
            )

            # Aguardar um momento para garantir que o servidor esteja pronto
            time.sleep(1)

        except Exception as e:
            logger.error(f"Erro ao iniciar servidor para receber arquivo encriptado: {e}")

    def upClienteToSendDocumentEncripted(self, conf, client_name, file_to_exchange, file_commitment):
        """
        Inicia o cliente para enviar o arquivo encriptado.

        Args:
            conf: Configuração do cliente
            client_name: Nome do cliente
            file_to_exchange: Arquivo encriptado a ser enviado
            file_commitment: Compromisso do arquivo a ser enviado

        Returns:
            True se o envio for bem-sucedido, False caso contrário
        """
        try:
            client_cert_chain = conf.configuration.config_client.intermadiate_client_cert_chain
            client_key = conf.configuration.config_client.intermadiate_client_key
            host = conf.configuration.server_name
            port = 8290

            logger.info(f"------Iniciando módulo de {conf.configuration.client_name} para troca de documentos-----")

            # Criar cliente SSL
            ssl_client_file = ClientSSL(conf, client_cert_chain, client_key, host, port, True)

            # Conectar ao servidor
            if not ssl_client_file.sock_connect(client_name):
                logger.error(f"Falha ao conectar ao servidor {client_name}")
                return False

            # Gerar desafio para prova de conhecimento zero
            challenge = self._generate_random_challenge()

            # Gerar prova de conhecimento zero
            verification_service = self.verification_services[conf.configuration.client_name]
            zkp = verification_service.generate_zero_knowledge_proof(file_to_exchange, challenge)

            if not zkp:
                logger.error("Falha ao gerar prova de conhecimento zero")
                return False

            # Adicionar prova ao compromisso
            file_commitment["zkp"] = zkp

            # Trocar arquivo encriptado
            success = ssl_client_file.exchange_encrypted_file(file_to_exchange)

            # Fechar conexão
            ssl_client_file.close_socket()

            return success

        except Exception as e:
            logger.error(f"Erro ao enviar arquivo encriptado: {e}")
            return False

    def _generate_random_challenge(self, length=16):
        """
        Gera um desafio aleatório para prova de conhecimento zero.

        Args:
            length: Comprimento do desafio

        Returns:
            Desafio aleatório
        """
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    def verify_received_file(self, conf, received_file_path):
        """
        Verifica se o arquivo recebido corresponde ao compromisso.

        Args:
            conf: Configuração do cliente
            received_file_path: Caminho para o arquivo recebido

        Returns:
            True se o arquivo for válido, False caso contrário
        """
        try:
            # Obter serviço de verificação
            verification_service = self.verification_services.get(conf.configuration.client_name)
            if not verification_service:
                logger.error(f"Serviço de verificação não encontrado para {conf.configuration.client_name}")
                return False

            # Carregar compromisso do arquivo recebido
            exchange_dir = Path(f"{conf.configuration.client_name}/exchange")
            commitment_path = exchange_dir / "received_commitment.json"

            if not os.path.exists(commitment_path):
                logger.error(f"Compromisso não encontrado: {commitment_path}")
                return False

            # Verificar arquivo
            return verification_service.verify_file_commitment(received_file_path, commitment_path)

        except Exception as e:
            logger.error(f"Erro ao verificar arquivo recebido: {e}")
            return False
import socket
import ssl
import os
import time
import logging
from tqdm import tqdm

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ClientSSL')


class ClientSSL():
    def __init__(self, config_client, client_cert_chain, client_key, host, port, use_ssl=True):
        self.config_client = config_client
        config = config_client.configuration
        self.client_name = config.client_name
        self.client_cert_chain = client_cert_chain
        self.client_key = client_key
        self.server = host
        self.port = port
        self.headersize = config.headersize
        self.buffer_size = config.buffer_size
        self.separator = config.separator
        self.soc = None
        self.conn = None
        self.use_ssl = use_ssl
        self.context = None
        self.connected = False
        self.max_retries = 3

    def sock_connect(self, serverName, retries=0):
        """
        Estabelece conexão com o servidor com suporte a reconexão automática
        """
        if self.connected and self.conn:
            logger.info(f"Já conectado ao servidor {serverName}")
            return True

        try:
            self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if self.use_ssl:
                # Criar contexto SSL apenas uma vez
                if not self.context:
                    self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

                    # Verificar se o certificado CA existe
                    ca_cert_path = self.config_client.configuration.config_client.ca_cert
                    if os.path.exists(ca_cert_path):
                        self.context.load_verify_locations(ca_cert_path)
                    else:
                        logger.warning(
                            f"Certificado CA não encontrado: {ca_cert_path}. Verificação de servidor desativada.")
                        self.context.check_hostname = False
                        self.context.verify_mode = ssl.CERT_NONE

                    # Carregar certificado e chave do cliente
                    self.context.load_cert_chain(
                        certfile=self.client_cert_chain,
                        keyfile=self.client_key,
                        password="camb"
                    )

                # Envolver o socket com SSL
                self.conn = self.context.wrap_socket(self.soc, server_hostname=serverName)
            else:
                self.conn = self.soc

            # Estabelecer conexão
            self.conn.connect((self.server, self.port))
            self.connected = True

            return True

        except (socket.error, ssl.SSLError) as e:
            logger.error(f"Erro ao conectar: {e}")
            self.close_socket()

            # Tentar reconectar automaticamente
            if retries < self.max_retries:
                logger.info(f"Tentando reconectar ({retries + 1}/{self.max_retries})...")
                time.sleep(2)  # Esperar antes de reconectar
                return self.sock_connect(serverName, retries + 1)
            else:
                logger.error(f"Falha ao conectar após {self.max_retries} tentativas")
                return False

    def send_and_receive_encrypted_file(self, file_path):
        """
        Envia um arquivo para o attestable encriptar e recebe o arquivo encriptado
        """
        if not self.connected and not self.sock_connect("GCA"):
            logger.error("Não foi possível conectar ao attestable")
            return None

        progress_send = None
        progress_recv = None

        try:
            # Verificar se o arquivo existe
            if not os.path.exists(file_path):
                logger.error(f"Arquivo não encontrado: {file_path}")
                return None

            file_size = os.path.getsize(file_path)
            base_name = os.path.basename(file_path)

            # Enviar comando para encriptar arquivo
            command = f"ENCRYPT_FILE:{base_name}:{file_size}"
            self.conn.send(command.encode())

            # Aguardar confirmação do servidor
            response = self.conn.recv(1024).decode()
            if not response.startswith("READY"):
                logger.error(f"Servidor não está pronto: {response}")
                return None

            # Enviar o arquivo
            progress_send = tqdm(total=file_size, desc=f"{self.client_name} envia arquivo para ATT", unit="B",
                                 unit_scale=True)

            # Enviar o arquivo em blocos
            with open(file_path, 'rb') as f:
                bytes_sent = 0
                while bytes_sent < file_size:
                    data = f.read(self.buffer_size)
                    if not data:
                        break
                    self.conn.sendall(data)
                    bytes_sent += len(data)
                    progress_send.update(len(data))

            progress_send.close()

            # Receber resposta do servidor
            response = self.conn.recv(1024).decode()

            if response.startswith("ERROR:"):
                logger.error(f"Erro na encriptação: {response[6:]}")
                return None

            if response.startswith("ENCRYPTED_FILE:"):
                # Formato: ENCRYPTED_FILE:nome_arquivo:tamanho
                parts = response.split(":", 2)
                if len(parts) < 3:
                    logger.error("Formato de resposta inválido")
                    return None

                _, encrypted_name, encrypted_size = parts
                encrypted_size = int(encrypted_size)

                # Criar nome do arquivo encriptado
                encrypted_file_path = f'{self.client_name}/files/{encrypted_name}'.lower()

                # Garantir que o diretório existe
                os.makedirs(os.path.dirname(encrypted_file_path), exist_ok=True)

                # Receber o arquivo encriptado
                progress_recv = tqdm(total=encrypted_size, desc=f"Recebendo arquivo encriptado", unit="B",
                                     unit_scale=True)

                # Receber e salvar o arquivo encriptado
                with open(encrypted_file_path, "wb") as f:
                    bytes_received = 0
                    while bytes_received < encrypted_size:
                        bytes_to_read = min(self.buffer_size, encrypted_size - bytes_received)
                        data = self.conn.recv(bytes_to_read)
                        if not data:
                            break
                        f.write(data)
                        bytes_received += len(data)
                        progress_recv.update(len(data))

                return encrypted_name
            else:
                logger.error(f"Resposta inesperada do servidor: {response}")
                return None

        except Exception as e:
            logger.error(f"Erro ao encriptar arquivo: {e}")
            return None
        finally:
            if progress_send:
                progress_send.close()
            if progress_recv:
                progress_recv.close()

    def exchange_encrypted_file(self, filename):
        """
        Troca arquivos encriptados com outro cliente
        """
        if not self.connected:
            logger.error("Não conectado ao servidor")
            return False

        try:
            if not os.path.exists(filename):
                logger.error(f"Arquivo não encontrado: {filename}")
                return False

            filesize = os.path.getsize(filename)

            # Enviar comando para iniciar troca
            command = f"EXCHANGE_FILE:{os.path.basename(filename)}:{filesize}"
            self.conn.send(command.encode())

            # Aguardar confirmação
            response = self.conn.recv(self.buffer_size).decode()
            if not response.startswith("READY"):
                logger.error(f"Servidor não está pronto para troca: {response}")
                return False

            # Enviar arquivo
            logger.info(f"Enviando arquivo {filename} ({filesize} bytes) para troca")

            # Enviar o arquivo em blocos
            with open(filename, 'rb') as f:
                bytes_sent = 0
                while bytes_sent < filesize:
                    data = f.read(self.buffer_size)
                    if not data:
                        break
                    self.conn.sendall(data)
                    bytes_sent += len(data)

            # Receber resposta do servidor
            response = self.conn.recv(self.buffer_size).decode()

            if response.startswith("ERROR:"):
                logger.error(f"Erro na troca: {response[6:]}")
                return False

            if response.startswith("INCOMING_FILE:"):
                # Formato: INCOMING_FILE:nome_arquivo:tamanho
                parts = response.split(":", 2)
                if len(parts) < 3:
                    logger.error("Formato de resposta inválido")
                    return False

                _, incoming_filename, incoming_filesize = parts
                incoming_filesize = int(incoming_filesize)

                # Definir caminho para salvar o arquivo recebido
                save_path = self.config_client.configuration.path_file / incoming_filename

                # Garantir que o diretório existe
                os.makedirs(os.path.dirname(save_path), exist_ok=True)

                # Receber e salvar o arquivo
                logger.info(f"Recebendo arquivo {incoming_filename} ({incoming_filesize} bytes)")

                with open(save_path, "wb") as f:
                    bytes_received = 0
                    while bytes_received < incoming_filesize:
                        bytes_to_read = min(self.buffer_size, incoming_filesize - bytes_received)
                        data = self.conn.recv(bytes_to_read)
                        if not data:
                            break
                        f.write(data)
                        bytes_received += len(data)

                logger.info(f"Troca concluída com sucesso. Arquivo recebido: {save_path}")
                return True
            else:
                logger.error(f"Resposta inesperada durante a troca: {response}")
                return False

        except Exception as e:
            logger.error(f"Erro durante a troca de arquivos: {e}")
            return False

    def close_socket(self):
        """
        Fecha a conexão com o servidor de forma segura
        """
        try:
            if self.conn:
                # Enviar comando de desconexão
                try:
                    self.conn.send(b"DISCONNECT")
                except:
                    pass  # Ignorar erros ao enviar comando de desconexão

                # Fechar conexão
                self.conn.close()

            if self.soc:
                self.soc.close()

            self.conn = None
            self.soc = None
            self.connected = False

        except Exception as e:
            logger.error(f"Erro ao fechar conexão: {e}")
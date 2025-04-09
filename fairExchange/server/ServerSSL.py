import socket
import ssl
import threading
import logging
import os
from pathlib import Path

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ServerSSL')


class ServerSSL:
    def __init__(self, config, server_cert_chain, server_key, server_type, host, port, file_to_exchange=None,
                 use_ssl=True):
        self.config = config
        self.server_cert_chain = server_cert_chain
        self.server_key = server_key
        self.server_type = server_type
        self.host = host
        self.port = port
        self.file_to_exchange = file_to_exchange
        self.use_ssl = use_ssl
        self.server_socket = None
        self.running = False
        self.clients = []
        self.context = None

        # Atualizar a configuração com o arquivo para troca
        if file_to_exchange:
            self.config.configuration.file_to_exchange = file_to_exchange

        # Iniciar o servidor em uma thread separada
        self.server_thread = threading.Thread(target=self.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()

    def start_server(self):
        """
        Inicia o servidor SSL e aguarda conexões de clientes.
        """
        try:
            # Criar socket do servidor
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Configurar SSL se necessário
            if self.use_ssl:
                self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                self.context.load_cert_chain(certfile=self.server_cert_chain, keyfile=self.server_key, password="camb")

                # Verificar se o certificado CA está disponível antes de carregá-lo
                # Não vamos mais usar ca_cert do ConfigServerModule, pois não existe
                # Em vez disso, usamos o certificado CA do diretório de recursos
                resource_directory = Path(self.server_cert_chain).parent
                ca_cert = resource_directory / 'rootca.cert.pem'

                if os.path.exists(ca_cert):
                    self.context.load_verify_locations(cafile=ca_cert)
                    self.context.verify_mode = ssl.CERT_REQUIRED
                else:
                    logger.warning(f"Certificado CA não encontrado: {ca_cert}. Verificação de cliente desativada.")
                    self.context.verify_mode = ssl.CERT_NONE

            # Vincular socket ao endereço e porta
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            while self.running:
                try:
                    # Aceitar conexão
                    client_socket, client_address = self.server_socket.accept()

                    if self.use_ssl:
                        # Envolver socket com SSL
                        try:
                            ssl_client_socket = self.context.wrap_socket(client_socket, server_side=True)
                            client_socket = ssl_client_socket
                        except ssl.SSLError as e:
                            logger.error(f"Erro SSL ao aceitar conexão: {e}")
                            client_socket.close()
                            continue

                    # Iniciar thread para manipular cliente
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                    # Adicionar cliente à lista
                    self.clients.append((client_socket, client_thread))

                except ssl.SSLError as e:
                    logger.error(f"Erro SSL ao aceitar conexão: {e}")
                except Exception as e:
                    if not self.running:
                        break

        except Exception as e:
            logger.error(f"Erro ao iniciar servidor: {e}")
        finally:
            self.stop_server()

    def handle_client(self, client_socket, client_address):
        """
        Manipula a conexão com um cliente.

        Args:
            client_socket: Socket do cliente
            client_address: Endereço do cliente (IP, porta)
        """
        client_name = f"{client_address[0]}:{client_address[1]}"
        try:
            # Determinar o tipo de servidor e manipular adequadamente
            if self.server_type == "uploadFile":
                # Servidor para upload e encriptação de arquivos
                self.handle_upload_file(client_socket, client_address)
            elif self.server_type == "exchangeEncryptedFiles":
                # Servidor para troca de arquivos encriptados
                self.handle_exchange_files(client_socket, client_address)
            else:
                logger.warning(f"Tipo de servidor desconhecido: {self.server_type}")
                client_socket.send(b"ERROR:Unknown server type")

        except Exception as e:
            logger.error(f"Erro ao manipular cliente {client_name}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

            # Remover cliente da lista
            self.clients = [(s, t) for s, t in self.clients if s != client_socket]

    def handle_upload_file(self, client_socket, client_address):
        """
        Manipula o upload e encriptação de arquivos.

        Args:
            client_socket: Socket do cliente
            client_address: Endereço do cliente (IP, porta)
        """
        client_name = f"{client_address[0]}:{client_address[1]}"
        try:
            # Receber comando do cliente
            command = client_socket.recv(self.config.configuration.buffer_size).decode().strip()

            if command.startswith("ENCRYPT_FILE:"):
                # Formato: ENCRYPT_FILE:nome_arquivo:tamanho
                parts = command.split(":", 2)
                if len(parts) < 3:
                    client_socket.send(b"ERROR:Invalid command format")
                    return

                _, file_name, file_size = parts
                file_size = int(file_size)

                # Informar ao cliente que estamos prontos para receber
                client_socket.send(b"READY")

                # Definir caminho para o arquivo temporário
                client_dir = Path(f"{self.config.configuration.client_name}")
                temp_dir = client_dir / "temp"
                output_dir = client_dir / "files"

                os.makedirs(temp_dir, exist_ok=True)
                os.makedirs(output_dir, exist_ok=True)

                temp_file_path = temp_dir / file_name

                # Receber o arquivo

                # Receber e salvar o arquivo
                bytes_received = 0
                with open(temp_file_path, "wb") as f:
                    while bytes_received < file_size:
                        bytes_to_read = min(self.config.configuration.buffer_size, file_size - bytes_received)
                        data = client_socket.recv(bytes_to_read)
                        if not data:
                            break
                        f.write(data)
                        bytes_received += len(data)

                # Verificar se recebemos o arquivo completo
                if bytes_received < file_size:
                    logger.error(f"Arquivo incompleto recebido: {bytes_received}/{file_size} bytes")
                    client_socket.send(b"ERROR:Incomplete file received")
                    return

                # Simular encriptação (apenas para demonstração)
                # Em um cenário real, você implementaria a encriptação adequada aqui
                encrypted_file_name = f"{self.config.configuration.client_name.lower()}doc_encrypted{Path(file_name).suffix}"
                encrypted_file_path = output_dir / encrypted_file_name

                # Simular encriptação (apenas copia o arquivo)
                with open(temp_file_path, 'rb') as src, open(encrypted_file_path, 'wb') as dst:
                    dst.write(src.read())

                # Obter tamanho do arquivo encriptado
                encrypted_size = os.path.getsize(encrypted_file_path)

                # Informar ao cliente sobre o arquivo encriptado
                response = f"ENCRYPTED_FILE:{encrypted_file_name}:{encrypted_size}"
                client_socket.send(response.encode())

                # Enviar o arquivo encriptado
                with open(encrypted_file_path, 'rb') as f:
                    bytes_sent = 0
                    while bytes_sent < encrypted_size:
                        data = f.read(self.config.configuration.buffer_size)
                        if not data:
                            break
                        client_socket.sendall(data)
                        bytes_sent += len(data)

                # Limpar arquivo temporário
                os.remove(temp_file_path)
                logger.info(f"Encriptação concluída para {client_name}")
            else:
                logger.warning(f"Comando desconhecido de {client_name}: {command}")
                client_socket.send(b"ERROR:Unknown command")

        except Exception as e:
            logger.error(f"Erro ao processar upload de arquivo de {client_name}: {e}")
            try:
                client_socket.send(f"ERROR:{str(e)}".encode())
            except:
                pass

    def handle_exchange_files(self, client_socket, client_address):
        """
        Manipula a troca de arquivos encriptados entre clientes.

        Args:
            client_socket: Socket do cliente
            client_address: Endereço do cliente (IP, porta)
        """
        client_name = f"{client_address[0]}:{client_address[1]}"
        try:
            # Receber comando do cliente
            command = client_socket.recv(self.config.configuration.buffer_size).decode().strip()

            if command.startswith("EXCHANGE_FILE:"):
                # Formato: EXCHANGE_FILE:nome_arquivo:tamanho
                parts = command.split(":", 2)
                if len(parts) < 3:
                    client_socket.send(b"ERROR:Invalid command format")
                    return

                _, file_name, file_size = parts
                file_size = int(file_size)

                # Informar ao cliente que estamos prontos para receber
                client_socket.send(b"READY")

                # Definir caminho para o arquivo recebido
                client_dir = Path(f"{self.config.configuration.client_name}/exchange")
                os.makedirs(client_dir, exist_ok=True)
                received_file_path = client_dir / f"received_{file_name}"

                  # Receber e salvar o arquivo
                bytes_received = 0
                with open(received_file_path, "wb") as f:
                    while bytes_received < file_size:
                        bytes_to_read = min(self.config.configuration.buffer_size, file_size - bytes_received)
                        data = client_socket.recv(bytes_to_read)
                        if not data:
                            break
                        f.write(data)
                        bytes_received += len(data)

                # Verificar se temos um arquivo para troca
                if not self.file_to_exchange or not os.path.exists(self.file_to_exchange):
                    client_socket.send(b"ERROR:No file available for exchange")
                    return

                # Obter tamanho do arquivo para troca
                exchange_file_size = os.path.getsize(self.file_to_exchange)
                exchange_file_name = os.path.basename(self.file_to_exchange)

                # Informar ao cliente sobre o arquivo para troca
                response = f"INCOMING_FILE:{exchange_file_name}:{exchange_file_size}"
                client_socket.send(response.encode())

                # Enviar o arquivo para troca
                logger.info(f"Enviando arquivo {exchange_file_name} ({exchange_file_size} bytes) para {client_name}")

                # Enviar o arquivo para troca
                with open(self.file_to_exchange, 'rb') as f:
                    bytes_sent = 0
                    while bytes_sent < exchange_file_size:
                        data = f.read(self.config.configuration.buffer_size)
                        if not data:
                            break
                        client_socket.sendall(data)
                        bytes_sent += len(data)

                logger.info(f"Troca concluída para {client_name}")
            else:
                logger.warning(f"Comando desconhecido de {client_name}: {command}")
                client_socket.send(b"ERROR:Unknown command")

        except Exception as e:
            logger.error(f"Erro na troca de arquivos com {client_name}: {e}")
            try:
                client_socket.send(f"ERROR:{str(e)}".encode())
            except:
                pass

    def stop_server(self):
        """
        Para o servidor e fecha todas as conexões.
        """
        self.running = False

        # Fechar todas as conexões de clientes
        for client_socket, _ in self.clients:
            try:
                client_socket.close()
            except:
                pass

        # Fechar socket do servidor
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

        self.clients = []

    def __del__(self):
        """
        Destrutor da classe, garante que o servidor seja parado.
        """
        self.stop_server()
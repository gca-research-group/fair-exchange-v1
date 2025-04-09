import os
import logging
import socket
import ssl
from pathlib import Path
from typing import Tuple, Optional, Dict, Any

from fairExchange.server.Utils.files2sockets import recv_store_file, read_send_file, send_content

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AttestableProtocolHandler')

class AttestableProtocolHandler:
    """
    Manipulador de protocolo para o servidor attestable.
    Implementa o protocolo de comunicação entre o cliente e o attestable.
    """
    
    def __init__(self, config, encryption_service=None):
        """
        Inicializa o manipulador de protocolo.
        
        Args:
            config: Configuração do servidor
            encryption_service: Serviço de encriptação (opcional)
        """
        self.config = config
        self.encryption_service = encryption_service
        self.buffer_size = config.configuration.buffer_size
        self.temp_dir = Path(f"{config.configuration.client_name}/temp")
        self.output_dir = Path(f"{config.configuration.client_name}/files")
        
        # Garantir que os diretórios existam
        os.makedirs(self.temp_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        
    def handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]) -> None:
        """
        Manipula a conexão com um cliente.
        
        Args:
            client_socket: Socket do cliente
            client_address: Endereço do cliente (IP, porta)
        """
        client_name = f"{client_address[0]}:{client_address[1]}"
        logger.info(f"Conexão estabelecida com {client_name}")
        
        try:
            # Receber comando do cliente
            command = client_socket.recv(self.buffer_size).decode().strip()

            if command.startswith("ENCRYPT_FILE:"):
                self._handle_encrypt_file(client_socket, command, client_name)
            elif command.startswith("REQUEST_FILE:"):
                self._handle_request_file(client_socket, command, client_name)
            elif command.startswith("EXCHANGE_FILE:"):
                self._handle_exchange_file(client_socket, command, client_name)
            elif command == "DISCONNECT":
                logger.info(f"Cliente {client_name} solicitou desconexão")
            else:
                logger.warning(f"Comando desconhecido de {client_name}: {command}")
                client_socket.send(b"ERROR:Unknown command")
        
        except Exception as e:
            logger.error(f"Erro ao manipular cliente {client_name}: {e}")
            try:
                client_socket.send(f"ERROR:{str(e)}".encode())
            except:
                pass
        finally:
            logger.info(f"Fechando conexão com {client_name}")
            client_socket.close()
    
    def _handle_encrypt_file(self, client_socket: socket.socket, command: str, client_name: str) -> None:
        """
        Manipula o comando ENCRYPT_FILE.
        
        Args:
            client_socket: Socket do cliente
            command: Comando recebido
            client_name: Nome do cliente para logging
        """
        try:
            # Formato: ENCRYPT_FILE:nome_arquivo:tamanho
            _, file_name, file_size = command.split(":", 2)
            file_size = int(file_size)
            
            # Informar ao cliente que estamos prontos para receber
            client_socket.send(b"READY")
            
            # Definir caminho para o arquivo temporário
            temp_file_path = self.temp_dir / file_name
            
            # Receber o arquivo
            recv_store_file(temp_file_path, file_size, self.buffer_size, client_socket)
            
            # Encriptar o arquivo
            logger.info(f"Encriptando arquivo {file_name}")
            encrypted_file_path = self._encrypt_file(temp_file_path)
            
            if not encrypted_file_path:
                client_socket.send(b"ERROR:Failed to encrypt file")
                return
                
            # Obter tamanho do arquivo encriptado
            encrypted_size = os.path.getsize(encrypted_file_path)
            encrypted_name = os.path.basename(encrypted_file_path)
            
            # Informar ao cliente sobre o arquivo encriptado
            response = f"ENCRYPTED_FILE:{encrypted_name}:{encrypted_size}"
            client_socket.send(response.encode())
            
            # Enviar o arquivo encriptado
            read_send_file(encrypted_file_path, encrypted_size, self.buffer_size, client_socket)
            
            # Limpar arquivo temporário
            os.remove(temp_file_path)
            logger.info(f"Encriptação concluída para {client_name}")
            
        except Exception as e:
            logger.error(f"Erro ao encriptar arquivo para {client_name}: {e}")
            client_socket.send(f"ERROR:{str(e)}".encode())
    
    def _handle_request_file(self, client_socket: socket.socket, command: str, client_name: str) -> None:
        """
        Manipula o comando REQUEST_FILE.
        
        Args:
            client_socket: Socket do cliente
            command: Comando recebido
            client_name: Nome do cliente para logging
        """
        try:
            # Formato: REQUEST_FILE:nome_arquivo
            _, file_name = command.split(":", 1)
            
            # Verificar se o arquivo existe
            file_path = self.output_dir / file_name
            if not os.path.exists(file_path):
                client_socket.send(f"ERROR:File not found: {file_name}".encode())
                return
                
            # Obter tamanho do arquivo
            file_size = os.path.getsize(file_path)
            
            # Informar ao cliente sobre o arquivo
            response = f"FILE_INFO:{file_name}:{file_size}"
            client_socket.send(response.encode())
            
            # Enviar o arquivo
            logger.info(f"Enviando arquivo {file_name} ({file_size} bytes) para {client_name}")
            read_send_file(file_path, file_size, self.buffer_size, client_socket)
            
        except Exception as e:
            logger.error(f"Erro ao enviar arquivo para {client_name}: {e}")
            client_socket.send(f"ERROR:{str(e)}".encode())
    
    def _handle_exchange_file(self, client_socket: socket.socket, command: str, client_name: str) -> None:
        """
        Manipula o comando EXCHANGE_FILE.
        
        Args:
            client_socket: Socket do cliente
            command: Comando recebido
            client_name: Nome do cliente para logging
        """
        try:
            # Formato: EXCHANGE_FILE:nome_arquivo:tamanho
            _, file_name, file_size = command.split(":", 2)
            file_size = int(file_size)
            
            # Informar ao cliente que estamos prontos para receber
            client_socket.send(b"READY")
            
            # Definir caminho para o arquivo recebido
            received_file_path = self.output_dir / f"received_{file_name}"
            
            # Receber o arquivo
            recv_store_file(received_file_path, file_size, self.buffer_size, client_socket)
            
            # Simular a obtenção do arquivo do outro cliente
            # Em um cenário real, isso seria obtido de outro cliente ou de um armazenamento
            exchange_file_path = self.config.configuration.file_to_exchange
            if not exchange_file_path or not os.path.exists(exchange_file_path):
                client_socket.send(b"ERROR:No file available for exchange")
                return
                
            # Obter tamanho do arquivo para troca
            exchange_file_size = os.path.getsize(exchange_file_path)
            exchange_file_name = os.path.basename(exchange_file_path)
            
            # Informar ao cliente sobre o arquivo para troca
            response = f"INCOMING_FILE:{exchange_file_name}:{exchange_file_size}"
            client_socket.send(response.encode())
            
            # Enviar o arquivo para troca
            logger.info(f"Enviando arquivo {exchange_file_name} ({exchange_file_size} bytes) para {client_name}")
            read_send_file(exchange_file_path, exchange_file_size, self.buffer_size, client_socket)
            
            logger.info(f"Troca concluída para {client_name}")
            
        except Exception as e:
            logger.error(f"Erro na troca de arquivos com {client_name}: {e}")
            client_socket.send(f"ERROR:{str(e)}".encode())
    
    def _encrypt_file(self, file_path: Path) -> Optional[Path]:
        """
        Encripta um arquivo.
        
        Args:
            file_path: Caminho para o arquivo a ser encriptado
            
        Returns:
            Caminho para o arquivo encriptado ou None se falhar
        """
        try:
            # Se tiver um serviço de encriptação, use-o
            if self.encryption_service:
                return self.encryption_service.encrypt_file(file_path)
                
            # Caso contrário, simular encriptação (apenas para demonstração)
            # Em um cenário real, você implementaria a encriptação adequada aqui
            encrypted_file_name = f"{file_path.stem}_encrypted{file_path.suffix}"
            encrypted_file_path = self.output_dir / encrypted_file_name
            
            # Simular encriptação (apenas copia o arquivo)
            with open(file_path, 'rb') as src, open(encrypted_file_path, 'wb') as dst:
                dst.write(src.read())
                
            logger.info(f"Arquivo encriptado: {encrypted_file_path}")
            return encrypted_file_path
            
        except Exception as e:
            logger.error(f"Erro ao encriptar arquivo {file_path}: {e}")
            return None
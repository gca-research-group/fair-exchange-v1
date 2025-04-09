import hashlib
import os
import json
import logging
import hmac
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('FileVerificationService')

class FileVerificationService:
    """
    Serviço para verificação de arquivos encriptados, garantindo trocas justas.
    """
    
    def __init__(self, config):
        """
        Inicializa o serviço de verificação.
        
        Args:
            config: Configuração do cliente
        """
        self.config = config
        self.client_name = config.configuration.client_name
        self.verification_dir = Path(f"{self.client_name}/verification")
        
        # Garantir que o diretório de verificação exista
        os.makedirs(self.verification_dir, exist_ok=True)
        
    def generate_file_commitment(self, file_path):
        """
        Gera um compromisso para um arquivo, incluindo hash e metadados.
        
        Args:
            file_path: Caminho para o arquivo
            
        Returns:
            Dicionário contendo o compromisso do arquivo
        """
        try:
            if not os.path.exists(file_path):
                logger.error(f"Arquivo não encontrado: {file_path}")
                return None
                
            # Calcular hash SHA-256 do arquivo
            file_hash = self._calculate_file_hash(file_path)
            
            # Obter metadados do arquivo
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            # Criar compromisso
            commitment = {
                "file_name": file_name,
                "file_size": file_size,
                "file_hash": file_hash,
                "owner": self.client_name,
                "timestamp": self._get_timestamp()
            }
            
            # Assinar o compromisso
            signature = self._sign_commitment(commitment)
            commitment["signature"] = signature
            
            # Salvar compromisso em arquivo
            commitment_path = self.verification_dir / f"{file_name}.commitment.json"
            with open(commitment_path, 'w') as f:
                json.dump(commitment, f, indent=2)
                
            logger.info(f"Compromisso gerado para {file_name}: {file_hash}")
            return commitment
            
        except Exception as e:
            logger.error(f"Erro ao gerar compromisso para {file_path}: {e}")
            return None
            
    def verify_file_commitment(self, file_path, commitment):
        """
        Verifica se um arquivo corresponde ao compromisso fornecido.
        
        Args:
            file_path: Caminho para o arquivo a ser verificado
            commitment: Compromisso a ser verificado (dicionário ou caminho para arquivo JSON)
            
        Returns:
            True se o arquivo corresponder ao compromisso, False caso contrário
        """
        try:
            # Carregar compromisso se for um caminho de arquivo
            if isinstance(commitment, (str, Path)):
                with open(commitment, 'r') as f:
                    commitment = json.load(f)
                    
            # Verificar se o arquivo existe
            if not os.path.exists(file_path):
                logger.error(f"Arquivo não encontrado: {file_path}")
                return False
                
            # Verificar tamanho do arquivo
            file_size = os.path.getsize(file_path)
            if file_size != commitment.get("file_size"):
                logger.error(f"Tamanho do arquivo não corresponde: {file_size} != {commitment.get('file_size')}")
                return False
                
            # Calcular hash do arquivo
            file_hash = self._calculate_file_hash(file_path)
            
            # Verificar hash
            if file_hash != commitment.get("file_hash"):
                logger.error(f"Hash do arquivo não corresponde: {file_hash} != {commitment.get('file_hash')}")
                return False
                
            # Verificar assinatura
            if not self._verify_signature(commitment):
                logger.error("Assinatura do compromisso inválida")
                return False
                
            logger.info(f"Arquivo {file_path} verificado com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao verificar compromisso para {file_path}: {e}")
            return False
            
    def exchange_commitments(self, my_commitment, other_commitment):
        """
        Troca compromissos entre as partes.
        
        Args:
            my_commitment: Compromisso do arquivo local
            other_commitment: Compromisso do arquivo remoto
            
        Returns:
            True se a troca for bem-sucedida, False caso contrário
        """
        try:
            # Em um cenário real, esta função enviaria o compromisso para a outra parte
            # e receberia o compromisso da outra parte
            
            # Verificar se os compromissos são válidos
            if not my_commitment or not other_commitment:
                logger.error("Compromissos inválidos")
                return False
                
            # Verificar assinatura do compromisso remoto
            if not self._verify_signature(other_commitment):
                logger.error("Assinatura do compromisso remoto inválida")
                return False
                
            logger.info("Troca de compromissos bem-sucedida")
            return True
            
        except Exception as e:
            logger.error(f"Erro na troca de compromissos: {e}")
            return False
            
    def _calculate_file_hash(self, file_path):
        """
        Calcula o hash SHA-256 de um arquivo.
        
        Args:
            file_path: Caminho para o arquivo
            
        Returns:
            Hash do arquivo em formato hexadecimal
        """
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            # Ler o arquivo em blocos para evitar carregar arquivos grandes na memória
            for block in iter(lambda: f.read(4096), b''):
                sha256.update(block)
                
        return sha256.hexdigest()
        
    def _get_timestamp(self):
        """
        Obtém o timestamp atual.
        
        Returns:
            Timestamp atual em formato ISO
        """
        from datetime import datetime
        return datetime.now().isoformat()
        
    def _sign_commitment(self, commitment):
        """
        Assina um compromisso usando a chave privada do cliente.
        
        Args:
            commitment: Compromisso a ser assinado
            
        Returns:
            Assinatura em formato base64
        """
        try:
            # Criar uma cópia do compromisso sem a assinatura
            commitment_copy = commitment.copy()
            if "signature" in commitment_copy:
                del commitment_copy["signature"]
                
            # Converter para string JSON
            commitment_str = json.dumps(commitment_copy, sort_keys=True)
            
            # Em um cenário real, você usaria a chave privada para assinar
            # Aqui, usamos HMAC como uma simplificação
            key = self.client_name.encode()  # Em produção, use uma chave privada real
            signature = hmac.new(key, commitment_str.encode(), hashlib.sha256).digest()
            
            return base64.b64encode(signature).decode()
            
        except Exception as e:
            logger.error(f"Erro ao assinar compromisso: {e}")
            return None
            
    def _verify_signature(self, commitment):
        """
        Verifica a assinatura de um compromisso.
        
        Args:
            commitment: Compromisso a ser verificado
            
        Returns:
            True se a assinatura for válida, False caso contrário
        """
        try:
            # Obter assinatura
            signature = commitment.get("signature")
            if not signature:
                logger.error("Compromisso não possui assinatura")
                return False
                
            # Criar uma cópia do compromisso sem a assinatura
            commitment_copy = commitment.copy()
            del commitment_copy["signature"]
            
            # Converter para string JSON
            commitment_str = json.dumps(commitment_copy, sort_keys=True)
            
            # Em um cenário real, você usaria a chave pública para verificar
            # Aqui, usamos HMAC como uma simplificação
            key = commitment.get("owner", "").encode()  # Em produção, use a chave pública real
            expected_signature = hmac.new(key, commitment_str.encode(), hashlib.sha256).digest()
            
            return base64.b64encode(expected_signature).decode() == signature
            
        except Exception as e:
            logger.error(f"Erro ao verificar assinatura: {e}")
            return False
            
    def generate_zero_knowledge_proof(self, file_path, challenge):
        """
        Gera uma prova de conhecimento zero para um arquivo.
        
        Args:
            file_path: Caminho para o arquivo
            challenge: Desafio fornecido pela outra parte
            
        Returns:
            Prova de conhecimento zero
        """
        # Esta é uma implementação simplificada
        # Em um cenário real, você usaria um protocolo ZKP adequado
        try:
            if not os.path.exists(file_path):
                logger.error(f"Arquivo não encontrado: {file_path}")
                return None
                
            # Calcular hash do arquivo
            file_hash = self._calculate_file_hash(file_path)
            
            # Combinar hash com desafio
            combined = f"{file_hash}:{challenge}"
            proof = hashlib.sha256(combined.encode()).hexdigest()
            
            return {
                "proof": proof,
                "challenge": challenge
            }
            
        except Exception as e:
            logger.error(f"Erro ao gerar prova ZKP: {e}")
            return None
            
    def verify_zero_knowledge_proof(self, proof, challenge, commitment):
        """
        Verifica uma prova de conhecimento zero.
        
        Args:
            proof: Prova a ser verificada
            challenge: Desafio fornecido
            commitment: Compromisso do arquivo
            
        Returns:
            True se a prova for válida, False caso contrário
        """
        try:
            # Obter hash do arquivo do compromisso
            file_hash = commitment.get("file_hash")
            if not file_hash:
                logger.error("Compromisso não possui hash do arquivo")
                return False
                
            # Combinar hash com desafio
            combined = f"{file_hash}:{challenge}"
            expected_proof = hashlib.sha256(combined.encode()).hexdigest()
            
            return expected_proof == proof.get("proof") and challenge == proof.get("challenge")
            
        except Exception as e:
            logger.error(f"Erro ao verificar prova ZKP: {e}")
            return False
import sys
import os
from base64 import urlsafe_b64encode as b64e
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.padding import PKCS7

import config

def derive_key(password: str) -> bytes:
    """Deriva uma chave AES forte a partir da senha alfanumerica."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        # Use config.KEY_LENGTH, config.SALT, e config.ITERATIONS
        length=config.KEY_LENGTH,
        salt=config.SALT,
        iterations=config.ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file_content(input_filepath: str, key_string: str) -> bytes:
    """Lê o arquivo, criptografa e retorna os dados (IV + Cifrado) em Base64."""
    
    key = derive_key(key_string)
    
    # 1. Abrir e ler o arquivo em modo binário
    with open(input_filepath, 'rb') as f:
        plaintext = f.read()

    # 2. Gerar um Vetor de Inicialização (IV) aleatório
    iv = os.urandom(16) 
    
    # 3. Configurar e executar a criptografia
    cipher = Cipher(
        algorithms.AES(key), 
        modes.CBC(iv), 
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
     # 4. ADICIONAR: Aplicar Padding PKCS7 aos dados de texto puro
    # Usamos PKCS7().padder()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # 5. Criptografar os dados preenchidos
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Retorna o IV + texto cifrado, codificado em Base64
    return b64e(iv + ciphertext)

def main():
    if len(sys.argv) != 3:
        print("Uso: python encrypt.py <nome_do_arquivo_em_src_com_extensao> <chave_alfanumerica>", file=sys.stderr)
        sys.exit(1)

    input_filename = sys.argv[1] # Ex: dados.json
    encryption_key = sys.argv[2]
    
    # Caminhos
    current_dir = os.getcwd()
    input_dir = os.path.join(current_dir, 'src')
    output_dir = os.path.join(current_dir, 'dbdata')

    input_filepath = os.path.join(input_dir, input_filename)
    
    # Verificar a existência da pasta SRC e do arquivo
    if not os.path.exists(input_filepath):
        print(f"ERRO: Arquivo de entrada não encontrado em 'src/': {input_filepath}", file=sys.stderr)
        sys.exit(1)

    # Obter o nome base do arquivo (sem extensão)
    filename_base = os.path.splitext(os.path.basename(input_filename))[0]
    output_filepath = os.path.join(output_dir, filename_base)
    
    # Criar a pasta de saída 'dbdata' se não existir
    os.makedirs(output_dir, exist_ok=True)

    try:
        encrypted_data = encrypt_file_content(input_filepath, encryption_key)
        
        # Salvar o conteúdo criptografado no caminho de destino (sem extensão)
        with open(output_filepath, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"Sucesso: Arquivo criptografado salvo em: {os.path.basename(output_dir)}/{filename_base}")
        
    except Exception as e:
        print(f"ERRO durante a criptografia: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
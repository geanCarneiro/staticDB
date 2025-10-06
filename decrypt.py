import sys
import os
import json
from base64 import urlsafe_b64decode as b64d
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7

import config

def derive_key(password: str) -> bytes:
    """Deriva a chave AES forte a partir da senha alfanumerica."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        # Use config.KEY_LENGTH, config.SALT, e config.ITERATIONS
        length=config.KEY_LENGTH,
        salt=config.SALT,
        iterations=config.ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())
    
def decrypt_file_content(input_filepath: str, key_string: str) -> str:
    """Lê o arquivo criptografado, descriptografa e retorna o texto puro (plaintext)."""
    
    key = derive_key(key_string)
    
    # Ler o conteudo criptografado (Base64)
    with open(input_filepath, 'rb') as f:
        full_data_b64 = f.read()

    # Decodificar Base64
    full_data = b64d(full_data_b64)
    
    # Separar IV (primeiros 16 bytes) e ciphertext
    iv = full_data[:16]
    ciphertext = full_data[16:]

    # Configurar e executar a descriptografia
    cipher = Cipher(
        algorithms.AES(key), 
        modes.CBC(iv), 
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
     # 5. Descriptografar
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 6. Remover o preenchimento (unpad)
    unpadder = PKCS7(algorithms.AES.block_size).unpadder() # << USANDO PKCS7 AGORA
    plaintext = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    return plaintext.decode('utf-8')

def main():
    if len(sys.argv) != 3:
        print("Uso: python decrypt.py <nome_do_arquivo_em_dbdata_sem_extensao> <chave_alfanumerica>", file=sys.stderr)
        sys.exit(1)

    filename_base = sys.argv[1] # Ex: dados
    encryption_key = sys.argv[2]
    
    # Caminhos
    current_dir = os.getcwd()
    input_dir = os.path.join(current_dir, 'dbdata')
    output_dir = os.path.join(current_dir, 'src')

    input_filepath = os.path.join(input_dir, filename_base)
    
    # Verificar a existência da pasta DBDAA e do arquivo
    if not os.path.exists(input_filepath):
        print(f"ERRO: Arquivo criptografado não encontrado em 'dbdata/': {input_filepath}", file=sys.stderr)
        sys.exit(1)

    # Definir o caminho de saída (src/<nome_do_arquivo>.json)
    output_filepath = os.path.join(output_dir, f'{filename_base}.json')
    
    # Criar a pasta de saída 'src' se não existir
    os.makedirs(output_dir, exist_ok=True)

    print(f"Tentando descriptografar {filename_base}...")
    
    try:
        plaintext_content = decrypt_file_content(input_filepath, encryption_key)
        
        # Tentar salvar como JSON formatado
        try:
            data = json.loads(plaintext_content)
            with open(output_filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            print(f"Sucesso: Conteúdo descriptografado (JSON) salvo em: {os.path.basename(output_dir)}/{filename_base}.json")

        except json.JSONDecodeError:
            # Se não for um JSON, salva como texto simples com a extensão .json
            print("AVISO: Conteúdo não é JSON válido. Salvando como texto simples em .json.")
            with open(output_filepath, 'w', encoding='utf-8') as f:
                f.write(plaintext_content)
            print(f"Sucesso: Conteúdo descriptografado (Texto) salvo em: {os.path.basename(output_dir)}/{filename_base}.json")
            
    except Exception as e:
        print(f"ERRO durante a descriptografia. A chave está incorreta? Erro: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
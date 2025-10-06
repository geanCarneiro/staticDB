# config.py

# SALT (DEVE ser mantido em segredo, mas é fixo para derivacao da chave)
# ----------------------------------------------------------------------
# IMPORTANTE: A alteracao deste valor invalida todos os arquivos criptografados anteriormente.
SALT = b'' 

# PBKDF2 PARAMETERS (Parametros de Derivacao de Chave)
# ---------------------------------------------------
ITERATIONS = 480000 
KEY_LENGTH = 32 # 32 bytes = AES-256 (AES-256)

# AES PARAMETERS
# --------------
BLOCK_SIZE = 128 # Tamanho do bloco em bits (128 bits = 16 bytes)
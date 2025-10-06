@echo off
setlocal
:: Uso: encrypt.cmd <nome_do_arquivo_em_src_com_extensao> <chave_alfanumerica>
python encrypt.py %1 %2
if errorlevel 1 (
    echo.
    echo FALHA na criptografia.
) else (
    echo.
    echo Criptografia CONCLUIDA.
)
endlocal
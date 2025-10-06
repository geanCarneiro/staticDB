@echo off
setlocal
:: Uso: decrypt.cmd <nome_do_arquivo_em_dbdata_sem_extensao> <chave_alfanumerica>
python decrypt.py %1 %2
if errorlevel 1 (
    echo.
    echo FALHA na descriptografia. Verifique a chave e o nome do arquivo.
) else (
    echo.
    echo Descriptografia CONCLUIDA.
)
endlocal
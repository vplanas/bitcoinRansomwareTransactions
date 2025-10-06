"""
Bitcoin y ransomware: detección de wallets activas mediante consulta batch

Proyecto de Fin de Grado - Universidad Internacional de La Rioja (UNIR)
Grado en Ingeniería Informática

Autor: Víctor Planas Ortega (vplanas en GitHub)
Octubre 2025

Este script procesa una lista de direcciones Bitcoin utilizando consultas por lotes
(batch) a la API de blockchain.info. El objetivo es identificar cuáles tienen
transacciones (están activas) y exportar esas filas completas junto con el número
de transacciones a un CSV de salida. Se respeta el límite de llamadas de la API
con esperas intermedias.
"""
import pandas as pd
import requests
import time

# Función que, dado un conjunto de wallets, devuelve un diccionario con el número de transacciones de cada una
def transactions_counter(wallets):
    base_url = 'https://blockchain.info/multiaddr'
    wallets_str = '|'.join(wallets)
    url = f'{base_url}?active={wallets_str}'
    # Creamos un diccionario con el número de transacciones por wallet (inicializado a -1) -> -1 indica error
    dict_tx_count = {wallet: -1 for wallet in wallets}
    try:
        response = requests.get(url)
        if response.status_code != 200:
            # Si hay un error, devolvemos el diccionario con -1 para todas las wallets
            print(f'Error en la consulta batch: {response.status_code}')
            return dict_tx_count
        # Si la respuesta es correcta, continuamos y procesamos los datos
        data = response.json()
        for wallet_info in data.get('addresses', []):
            # Obtenemos la wallet y el número de transacciones (0 si no tiene)
            wallet = wallet_info.get('address')
            n_tx = wallet_info.get('n_tx', 0)
            # Actualizamos el diccionario solo si la wallet existe
            if wallet in dict_tx_count:
                dict_tx_count[wallet] = n_tx
    except Exception as e:
        print(f'Error en la consulta batch: {e}')
    return dict_tx_count

batch_size = 100
tiempo_espera = 10  # segundos

def process_wallets_File(df, archivo_salida):
    total_activas = 0
    lote_wallets = []
    filas_activas = []
    columna_wallet = df.columns.tolist().index('identifiers') # Columna donde están las wallets en el csv de entrada

    # Diccionario para guardar la fila correspondiente a cada wallet para pasarla a filas_activas si tiene transacciones
    wallet_a_fila = {}

    # Para cada una de las wallets en el DataFrame las agrupamos en lotes de 100 y las consultamos
    for i, fila in enumerate(df.itertuples(index=False, name=None)):
        wallet = fila[columna_wallet]
        # Añadimos la wallet actual al lote
        lote_wallets.append(wallet)
        # Guardamos la fila completa para esta wallet
        wallet_a_fila[wallet] = fila
        print(f'Procesando wallet {i+1}/{len(df)}: {wallet}')

        # Si hemos alcanzado el tamaño de lote o es la última fila, consultamos la API
        if len(lote_wallets) == batch_size or (i+1) == len(df):
            dict_tx_count = transactions_counter(lote_wallets)
            # Para cada wallet del lote
            for wallet in lote_wallets:
                # Recuperamos el número de transacciones de la wallet; si no existe, -1
                n_tx = dict_tx_count.get(wallet, -1)
                if n_tx > 0:
                    # Si la wallet tiene transacciones, guardamos TODA la fila original (todas las columnas) + n_tx
                    fila_original = wallet_a_fila[wallet]
                    fila_con_n_tx = fila_original + (n_tx,)
                    filas_activas.append(fila_con_n_tx)
                    total_activas += 1
                    print(f'Wallet activa encontrada: {wallet} con {n_tx} transacciones')

            # Si hay wallets activas en este lote, exportamos al CSV
            if filas_activas:
                # Creamos un DataFrame temporal para exportar las filas activas y añadimos la columna n_tx
                columnas_con_n_tx = list(df.columns) + ['n_tx']
                parte_activa_df = pd.DataFrame(filas_activas, columns=columnas_con_n_tx)
                # Escribimos el header solo la primera vez
                parte_activa_df.to_csv(archivo_salida, mode='a', header=total_activas == len(filas_activas), index=False)
                # Reiniciamos la lista de filas activas para el próximo lote
                filas_activas = []

            print(f'Procesadas {i+1} wallets -> Activas encontradas hasta ahora: {total_activas}')
            lote_wallets.clear()
            # Si no hemos acabado, esperamos para respetar los límites de la API
            if (i+1) < len(df):
                print(f'Esperando {tiempo_espera} segundos para la siguiente consulta batch...')
                time.sleep(tiempo_espera)

    print(f'Proceso finalizado. Total de wallets activas encontradas: {total_activas}')

# Carga tu CSV
df = pd.read_csv('targets.simple.csv')

# Ejecuta el proceso
process_wallets_File(df, 'direcciones_activas.csv')

"""
Bitcoin y ransomware: análisis y monitorización de pagos

Proyecto de Fin de Grado - Universidad Internacional de La Rioja (UNIR)
Grado en Ingeniería Informática

Autor: Víctor Planas Ortega (vplanas en GitHub)
Octubre 2025

Este script rastrea y analiza flujos de fondos en la blockchain de Bitcoin
partiendo de una dirección dada, para monitorizar posibles pagos relacionados
con incidentes de ransomware. Implementa manejo de límites de API, análisis
recursivo de transacciones y exportación de resultados a CSV.
"""

import requests
import json
import time
import argparse
from collections import defaultdict
import csv
from datetime import datetime
import random


def get_address_info(address, retry_count=0, max_retries=3):
    """
    Realiza consulta HTTP GET a la API de blockchain.info para obtener información
    completa de una dirección Bitcoin específica.
    
    Implementa mecanismo de reintentos para gestionar limitaciones de la API cuando da error (HTTP 429 - Too Many Requests).
    
    Args:
        address (str): Dirección Bitcoin a consultar
        retry_count (int): Contador interno de reintentos realizados
        max_retries (int): Número máximo de reintentos antes de abandonar
        
    Returns:
        dict: Estructura JSON con datos de la dirección o None en caso de error
    """
    # Endpoint de blockchain.info con límite de 50 transacciones por economía de llamadas
    url = f"https://blockchain.info/rawaddr/{address}?limit=50"
    
    try:
        print(f"Consultando dirección: {address}")
        response = requests.get(url)
        wait_time = 10  # Intervalo de espera en segundos para cumplir rate limiting
        
        # Manejo específico del error HTTP 429 (Too Many Requests)
        # Si da error, espera y reintenta hasta un máximo definido, 3 por defecto
        if response.status_code == 429:
            if retry_count < max_retries:
                print(f"Error 429 detectado. Esperando {wait_time} segundos antes del reintento {retry_count + 1}")
                time.sleep(wait_time)
                return get_address_info(address, retry_count + 1, max_retries)
            else:
                print(f"Error 429 persistente para dirección {address}. Omitiendo consulta.")
                return None

        # Validación de respuesta HTTP exitosa
        response.raise_for_status()
        
        # Pausa obligatoria entre llamadas para respetar términos de uso de la API
        print(f"Respuesta recibida. Esperando {wait_time} segundos.")
        time.sleep(wait_time)
        
        # Deserialización de respuesta JSON
        return response.json()
        
    except requests.exceptions.RequestException as e:
        # Captura de excepciones
        print(f"Excepción durante consulta de {address}: {e}")
        return None


def analyze_transactions(address_data, target_address):
    """
    Procesa el conjunto de transacciones asociadas a una dirección Bitcoin
    para extraer las salidas (outputs) relevantes hacia otras direcciones.
    
    Solo analiza transacciones donde target_address aparece en los
    inputs, es decir, donde la dirección está GASTANDO fondos (salientes reales).
    
    Aplica filtros para excluir:
    - Salidas hacia la misma dirección (change outputs)
    - Salidas con valor cero o nulo
    - Outputs sin dirección asignada
    
    La API devuelve los montos en Satoshis, la conversión de satoshis a BTC se realiza dividiendo por 10^8 según
    
    Args:
        address_data (dict): Respuesta JSON de la API conteniendo transacciones
        target_address (str): Dirección Bitcoin objeto del análisis
        
    Returns:
        tuple: (set de direcciones destino, lista de detalles de transacciones)
    """
    # Validación de entrada de datos
    if not address_data or 'txs' not in address_data:
        return set(), []

    outgoing_addresses = set()
    transaction_details = []

    # Iteración sobre todas las transacciones asociadas a la dirección
    for tx in address_data.get('txs', []):
        tx_hash = tx.get('hash')
        # Conversión de timestamp UNIX a formato legible para análisis temporal
        tx_time = datetime.fromtimestamp(tx.get('time', 0)).strftime('%Y-%m-%d %H:%M:%S')

        # VERIFICACIÓN CRÍTICA: comprobar que target_address está GASTANDO en esta tx
        # Iteramos sobre los inputs para verificar si la dirección objetivo es el origen
        is_spending = False
        for input_item in tx.get('inputs', []):
            prev_out = input_item.get('prev_out', {})
            input_address = prev_out.get('addr')
            if input_address == target_address:
                is_spending = True
                break
        
        # Solo procesar outputs si la dirección está gastando fondos (transacciones salientes)
        if not is_spending:
            continue

        # Análisis de cada output de la transacción
        for output in tx.get('out', []):
            dest_address = output.get('addr')
            value_satoshis = output.get('value', 0)
            # Conversión de satoshis a unidades BTC estándar
            value_btc = value_satoshis / 100000000.0

            # Aplicación de filtros para identificar salidas reales
            if dest_address and dest_address != target_address and value_btc > 0:
                outgoing_addresses.add(dest_address)

                # Construcción del registro de transacción para análisis posterior
                transaction_details.append({
                    'tx_hash': tx_hash,
                    'timestamp': tx_time,
                    'from_address': target_address,
                    'to_address': dest_address,
                    'value_btc': value_btc,
                    'value_satoshis': value_satoshis,
                    # Comisión si está disponible, convertida a BTC
                    'tx_fee': tx.get('fee', 0) / 100000000.0 if tx.get('fee') else 0.0
                })

    return outgoing_addresses, transaction_details



def recursive_trace(start_address, max_depth=2, visited=None, all_transactions=None, current_depth=0):
    """
    Implementa algoritmo de búsqueda en profundidad (DFS) para rastrear
    flujos de fondos Bitcoin desde una dirección inicial.
    
    Utiliza conjunto 'visited' para prevenir ciclos infinitos en el grafo
    de transacciones. Limita la profundidad de búsqueda para controlar
    complejidad computacional y uso de API.
    
    Prioriza direcciones destino por volumen total de fondos recibidos
    para optimizar la relevancia del análisis en casos de ransomware.
    
    Args:
        start_address (str): Dirección Bitcoin inicial del rastreo
        max_depth (int): Profundidad máxima de recursión permitida
        visited (set): Conjunto de direcciones ya procesadas
        all_transactions (list): Acumulador de transacciones encontradas
        current_depth (int): Nivel actual de recursión
        
    Returns:
        list: Lista completa de transacciones rastreadas
    """
    # Inicialización de estructuras de datos en primera llamada
    if visited is None:
        visited = set()
    if all_transactions is None:
        all_transactions = []

    # Condiciones de terminación: ciclo detectado o profundidad máxima alcanzada
    if start_address in visited or current_depth >= max_depth:
        return all_transactions

    # Marcado de dirección como visitada y actualización de profundidad
    visited.add(start_address)
    current_depth += 1

    # Logging del progreso del análisis
    print(f"ANÁLISIS NIVEL {current_depth}: procesando dirección {start_address}")

    # Consulta de datos de la dirección actual
    address_data = get_address_info(start_address)

    # Validación de disponibilidad de datos
    if not address_data:
        print(f"No se pudieron obtener datos para dirección {start_address}")
        return all_transactions

    # Extracción y presentación de métricas básicas de la dirección
    balance = address_data.get('final_balance', 0) / 100000000.0
    total_received = address_data.get('total_received', 0) / 100000000.0
    total_sent = address_data.get('total_sent', 0) / 100000000.0
    n_tx = address_data.get('n_tx', 0)

    print(f"Balance actual: {balance:.8f} BTC")
    print(f"Total recibido: {total_received:.8f} BTC")
    print(f"Total enviado: {total_sent:.8f} BTC")
    print(f"Número de transacciones: {n_tx}")

    # Análisis de transacciones de salida para identificar destinos
    outgoing_addresses, transactions = analyze_transactions(address_data, start_address)

    # Procesamiento de resultados del análisis
    if transactions:
        print(f"Encontradas {len(transactions)} transacciones de salida hacia {len(outgoing_addresses)} direcciones diferentes")
        
        # Presentación de muestra representativa de transacciones
        for i, tx in enumerate(transactions[:3], 1):
            # Formato de dirección truncada para legibilidad
            truncated_addr = f"{tx['to_address'][:15]}...{tx['to_address'][-15:]}"
            print(f"  {i}. {tx['timestamp']} -> {truncated_addr}: {tx['value_btc']:.8f} BTC")
        
        if len(transactions) > 3:
            print(f"  ... y {len(transactions) - 3} transacciones adicionales")
    else:
        print("No se detectaron transacciones de salida relevantes")

    # Acumulación de transacciones en estructura global
    all_transactions.extend(transactions)

    # Continuación recursiva con direcciones de mayor relevancia
    if current_depth < max_depth and outgoing_addresses:
        # Algoritmo de priorización por volumen total de fondos recibidos
        address_values = []
        for addr in outgoing_addresses:
            total_value = sum(tx['value_btc'] for tx in transactions if tx['to_address'] == addr)
            address_values.append((addr, total_value))
        
        # Ordenación descendente y selección de top 3 direcciones
        significant_addresses = sorted(address_values, key=lambda x: x[1], reverse=True)[:3]

        # Recursión sobre direcciones priorizadas
        for dest_address, total_value in significant_addresses:
            print(f"Continuando rastreo hacia: {dest_address} (Volumen: {total_value:.8f} BTC)")
            # Copia de 'visited' para evitar interferencias entre ramas recursivas
            recursive_trace(dest_address, max_depth, visited.copy(), all_transactions, current_depth)

    return all_transactions


def save_results(transactions, output_file="bitcoin_trace_results.csv"):
    """
    Serializa los resultados del análisis en formato CSV para análisis posterior.
        
    Args:
        transactions (list): Lista de diccionarios con datos de transacciones
        output_file (str): Nombre del archivo CSV de salida
    """
    # Validación de datos antes de procesamiento
    if not transactions:
        print("No hay transacciones disponibles para exportar")
        return

    # Definición de campos CSV según estructura de datos de transacciones
    fieldnames = ['tx_hash', 'timestamp', 'from_address', 'to_address', 'value_btc', 'value_satoshis', 'tx_fee']
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Serialización iterativa de transacciones
            for tx in transactions:
                writer.writerow(tx)

        print(f"Resultados exportados correctamente a: {output_file}")
        print(f"Total de registros procesados: {len(transactions)}")
        
    except IOError as e:
        print(f"Error durante exportación CSV: {e}")


def analyze_wallet(wallet_address, depth=2, output_file="bitcoin_trace_results.csv"):
    """
    Función coordinadora principal que orquesta el proceso completo de análisis.
        
    Args:
        wallet_address (str): Dirección Bitcoin objetivo del análisis
        depth (int): Profundidad máxima de rastreo recursivo
        output_file (str): Archivo de salida para resultados CSV
        data_file (str): Archivo opcional con datos precargados
        
    Returns:
        list: Lista completa de transacciones analizadas
    """
    # Presentación de parámetros de configuración del análisis
    print("ANALIZADOR DE FLUJO DE FONDOS BITCOIN - SISTEMA DE RASTREO")
    print("=" * 60)
    print(f"Dirección objetivo: {wallet_address}")
    print(f"Profundidad máxima: {depth} niveles")
    print(f"Archivo de salida: {output_file}")


    print("=" * 60)

    # Ejecución del algoritmo principal de rastreo
    all_transactions = recursive_trace(wallet_address, max_depth=depth)

    # Exportación de resultados a formato CSV
    save_results(all_transactions, output_file)

    # Generación de métricas agregadas y resumen estadístico
    if all_transactions:
        unique_addresses = set()
        total_value = 0.0
        total_fees = 0.0

        # Cálculo de métricas agregadas sobre conjunto completo de transacciones
        for tx in all_transactions:
            unique_addresses.add(tx['from_address'])
            unique_addresses.add(tx['to_address'])
            total_value += tx['value_btc']
            total_fees += tx.get('tx_fee', 0.0)

        # Presentación de resumen estadístico final
        print("\nRESUMEN ESTADÍSTICO DEL ANÁLISIS:")
        print("=" * 40)
        print(f"Direcciones únicas identificadas: {len(unique_addresses)}")
        print(f"Valor total rastreado: {total_value:.8f} BTC")
        print(f"Comisiones totales: {total_fees:.8f} BTC")
        print(f"Transacciones procesadas: {len(all_transactions)}")
        print(f"Conexiones en grafo de transacciones: {len(all_transactions)}")
    else:
        print("ADVERTENCIA: No se encontraron transacciones para el análisis especificado")

    return all_transactions


def main():
    """
    Función de entrada principal que gestiona argumentos de línea de comandos.
    
    """
    parser = argparse.ArgumentParser(
        description='Sistema de análisis de flujos de fondos Bitcoin con manejo de limitaciones API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplo de uso:
  python bitcoin_tracer.py -w 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa -d 3 -o resultados.csv
        """
    )
    
    parser.add_argument('-w', '--wallet', required=True, 
                        help='Dirección Bitcoin a analizar (formato base58check)')
    parser.add_argument('-d', '--depth', type=int, default=2,
                        help='Profundidad máxima de rastreo recursivo (por defecto: 2)')
    parser.add_argument('-o', '--output', default='bitcoin_trace_results.csv',
                        help='Archivo CSV de salida para resultados')

    # Parsing y validación de argumentos
    args = parser.parse_args()

    # Ejecución del análisis con parámetros especificados
    analyze_wallet(args.wallet, args.depth, args.output)


if __name__ == "__main__":
    main()

"""
Bitcoin y ransomware: análisis y monitorización de pagos

Proyecto de Fin de Grado - Universidad Internacional de La Rioja (UNIR)
Grado en Ingeniería Informática

Autor: Víctor Planas Ortega (vplanas en GitHub)
Octubre 2025

Análisis de flujos de fondos en ransomware usando bitcoinlib.
Rastrea 2 niveles de transacciones para identificar carteras acumuladoras
y destinos finales.
"""

import requests
import time
from collections import defaultdict
import csv
import argparse
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import Patch



def get_outgoing_transactions(address):
    """
    Obtiene transacciones donde la dirección ENVÍA fondos.
    Versión simplificada: suma exactamente lo que aparece en sus inputs.
    """
    import requests
    
    url = f"https://blockchain.info/rawaddr/{address}?limit=100"
    
    try:
        print(f"\n[Consultando transacciones de {address[:16]}...]")
        response = requests.get(url)
        response.raise_for_status()
        time.sleep(10)
        
        data = response.json()
        outgoing = defaultdict(float)
        tx_count = 0
        
        for tx in data.get('txs', []):
            tx_hash = tx.get('hash', '')[:16]
            
            # Calcular cuánto GASTA esta dirección (suma de sus inputs)
            total_spending = 0
            for inp in tx.get('inputs', []):
                prev_out = inp.get('prev_out', {})
                if prev_out.get('addr') == address:
                    total_spending += prev_out.get('value', 0) / 100000000.0
            
            if total_spending == 0:
                continue
            
            # Obtener la dirección principal destino (la que recibe MÁS)
            outputs_to_others = []
            for out in tx.get('out', []):
                dest_addr = out.get('addr')
                value_btc = out.get('value', 0) / 100000000.0
                
                if dest_addr and dest_addr != address and value_btc > 0:
                    outputs_to_others.append({
                        'address': dest_addr,
                        'value': value_btc
                    })
            
            # SIMPLIFICACIÓN: Asignar todo el gasto a la dirección que recibe MÁS
            # (ignorando pequeños outputs que suelen ser fees o dust)
            if outputs_to_others:
                # Ordenar por valor y tomar la principal
                main_output = max(outputs_to_others, key=lambda x: x['value'])
                
                # Si el output principal es significativo (>90% del gasto), asignar todo ahí
                if main_output['value'] > total_spending * 0.9:
                    outgoing[main_output['address']] += total_spending
                    print(f"    TX {tx_hash}...: gasta {total_spending:.8f} BTC → {main_output['address'][:16]}...")
                else:
                    # Si hay múltiples outputs significativos, distribuir proporcionalmente
                    total_to_others = sum(o['value'] for o in outputs_to_others)
                    for out in outputs_to_others:
                        proportion = out['value'] / total_to_others
                        amount = total_spending * proportion
                        outgoing[out['address']] += amount
                        print(f"    TX {tx_hash}...: gasta {amount:.8f} BTC → {out['address'][:16]}... ({proportion*100:.1f}%)")
            
            tx_count += 1
        
        total_sent = sum(outgoing.values())
        print(f"  ✓ Transacciones procesadas: {tx_count}")
        print(f"  ✓ Total GASTADO: {total_sent:.8f} BTC")
        
        return dict(outgoing)
        
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return {}




def get_incoming_transactions(address):
    """
    Obtiene transacciones donde la dirección RECIBE fondos.
    """
    import requests
    
    url = f"https://blockchain.info/rawaddr/{address}?limit=100"
    
    try:
        print(f"\n[Consultando fuentes hacia {address[:16]}...]")
        response = requests.get(url)
        response.raise_for_status()
        time.sleep(10)
        
        data = response.json()
        incoming = defaultdict(float)
        
        for tx in data.get('txs', []):
            # Paso 1: Verificar cuánto RECIBE esta dirección en esta tx
            amount_received = 0
            for out in tx.get('out', []):
                if out.get('addr') == address:
                    amount_received += out.get('value', 0) / 100000000.0
            
            # Si no recibe nada, saltar
            if amount_received == 0:
                continue
            
            # Paso 2: Identificar orígenes (inputs)
            sources = []
            for inp in tx.get('inputs', []):
                prev_out = inp.get('prev_out', {})
                source_addr = prev_out.get('addr')
                if source_addr and source_addr != address:
                    sources.append(source_addr)
            
            # Paso 3: Distribuir monto entre fuentes únicas
            if sources:
                unique_sources = list(set(sources))
                amount_per_source = amount_received / len(unique_sources)
                
                for source in unique_sources:
                    incoming[source] += amount_per_source
        
        total_received = sum(incoming.values())
        print(f"  ✓ Fuentes identificadas: {len(incoming)}")
        print(f"  ✓ Total RECIBIDO: {total_received:.8f} BTC")
        
        return dict(incoming)
        
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return {}



def analyze_ransomware_flow(initial_address):
    """
    Analiza el flujo de fondos desde una dirección de ransomware.
    
    Estructura del análisis:
    - NIVEL 0: Dirección inicial (ransomware) → identifica cartera acumuladora
    - NIVEL 1: Analiza todas las fuentes que envían a la acumuladora
    - NIVEL 2: Analiza destinos desde la acumuladora
    
    Args:
        initial_address (str): Dirección Bitcoin inicial
        
    Returns:
        dict: Datos estructurados del flujo
    """
    print("=" * 80)
    print("ANÁLISIS DE FLUJO DE FONDOS DE RANSOMWARE")
    print("=" * 80)
    print(f"Dirección inicial: {initial_address}")
    print("=" * 80)
    
    
    # Estructura de datos del grafo
    flow_data = {
        'initial': initial_address,
        'initial_to_accumulator': 0,
        'accumulator': None,
        'other_sources': {},
        'destinations': {},
        'all_transactions': []
    }
    
    # NIVEL 0: Analizar salidas de la dirección inicial
    print("\n" + "=" * 80)
    print("[NIVEL 0] Analizando dirección inicial de ransomware")
    print("=" * 80)
    
    outgoing_from_initial = get_outgoing_transactions(initial_address)
    
    if not outgoing_from_initial:
        print("\n✗ No se encontraron transacciones salientes desde la dirección inicial")
        return None
    
    # Identificar la cartera acumuladora (la que más recibe)
    accumulator = max(outgoing_from_initial, key=outgoing_from_initial.get)
    amount_to_accumulator = outgoing_from_initial[accumulator]
    
    flow_data['accumulator'] = accumulator
    flow_data['initial_to_accumulator'] = amount_to_accumulator
    
    print(f"\n{'':->80}")
    print(f"[CARTERA ACUMULADORA IDENTIFICADA]")
    print(f"{'':->80}")
    print(f"Dirección: {accumulator}")
    print(f"Monto recibido desde inicial: {amount_to_accumulator:.8f} BTC")
    
    # NIVEL 1: Analizar TODAS las fuentes que envían a la acumuladora
    print("\n" + "=" * 80)
    print("[NIVEL 1] Analizando fuentes hacia la cartera acumuladora")
    print("=" * 80)
    
    incoming_to_accumulator = get_incoming_transactions(accumulator)
    
    # Separar la dirección inicial de otras fuentes
    other_sources = {addr: amount for addr, amount in incoming_to_accumulator.items() 
                     if addr != initial_address}
    
    flow_data['other_sources'] = other_sources
    
    total_from_others = sum(other_sources.values())
    total_to_accumulator = amount_to_accumulator + total_from_others
    
    print(f"\n{'':->80}")
    print(f"[RESUMEN DE FUENTES]")
    print(f"{'':->80}")
    print(f"  • Inicial (ransomware):     {amount_to_accumulator:.8f} BTC ({amount_to_accumulator/total_to_accumulator*100:.2f}%)")
    print(f"  • Otras {len(other_sources):2d} fuentes:        {total_from_others:.8f} BTC ({total_from_others/total_to_accumulator*100:.2f}%)")
    print(f"  {'':─>60}")
    print(f"  • TOTAL RECIBIDO:          {total_to_accumulator:.8f} BTC")
    
    if other_sources:
        print(f"\n[TOP 10 OTRAS FUENTES]")
        for i, (source_addr, amount) in enumerate(sorted(other_sources.items(), 
                                                         key=lambda x: x[1], reverse=True)[:10], 1):
            percentage = (amount / total_to_accumulator) * 100
            print(f"  {i:2d}. {source_addr[:10]}...{source_addr[-10:]}: {amount:.8f} BTC ({percentage:.2f}%)")
    
    # NIVEL 2: Analizar destinos desde la acumuladora
    print("\n" + "=" * 80)
    print("[NIVEL 2] Analizando destinos desde la cartera acumuladora")
    print("=" * 80)
    
    outgoing_from_accumulator = get_outgoing_transactions(accumulator)
    flow_data['destinations'] = outgoing_from_accumulator
    
    total_to_destinations = sum(outgoing_from_accumulator.values())
    
    print(f"\n{'':->80}")
    print(f"[DESTINOS FINALES]")
    print(f"{'':->80}")
    print(f"Total enviado a destinos: {total_to_destinations:.8f} BTC")
    print(f"Número de destinos: {len(outgoing_from_accumulator)}")
    
    if outgoing_from_accumulator:
        print(f"\n[TOP 10 DESTINOS]")
        for i, (dest_addr, amount) in enumerate(sorted(outgoing_from_accumulator.items(),
                                                       key=lambda x: x[1], reverse=True)[:10], 1):
            percentage = (amount / total_to_destinations) * 100 if total_to_destinations > 0 else 0
            print(f"  {i:2d}. {dest_addr[:10]}...{dest_addr[-10:]}: {amount:.8f} BTC ({percentage:.2f}%)")
    
    # Resumen final
    print("\n" + "=" * 80)
    print("[RESUMEN ESTADÍSTICO]")
    print("=" * 80)
    print(f"  • Direcciones únicas identificadas:  {1 + len(other_sources) + len(outgoing_from_accumulator) + 1}")
    print(f"  • Fuentes hacia acumuladora:         {len(other_sources) + 1}")
    print(f"  • Destinos desde acumuladora:        {len(outgoing_from_accumulator)}")
    print(f"  • Total acumulado:                   {total_to_accumulator:.8f} BTC")
    print(f"  • Total redistribuido:               {total_to_destinations:.8f} BTC")
    print(f"  • Diferencia (fees/retenido):        {total_to_accumulator - total_to_destinations:.8f} BTC")
    print("=" * 80)
    
    return flow_data


def export_to_csv(flow_data, output_file="ransomware_analysis.csv"):
    """
    Exporta los resultados a CSV con detalle de todas las transacciones.
    """
    if not flow_data:
        return
    
    rows = []
    
    # Transacción inicial -> acumuladora
    rows.append({
        'from_address': flow_data['initial'],
        'to_address': flow_data['accumulator'],
        'amount_btc': flow_data['initial_to_accumulator'],
        'flow_type': 'INITIAL_TO_ACCUMULATOR'
    })
    
    # Otras fuentes -> acumuladora
    for source_addr, amount in flow_data['other_sources'].items():
        rows.append({
            'from_address': source_addr,
            'to_address': flow_data['accumulator'],
            'amount_btc': amount,
            'flow_type': 'SOURCE_TO_ACCUMULATOR'
        })
    
    # Acumuladora -> destinos
    for dest_addr, amount in flow_data['destinations'].items():
        rows.append({
            'from_address': flow_data['accumulator'],
            'to_address': dest_addr,
            'amount_btc': amount,
            'flow_type': 'ACCUMULATOR_TO_DESTINATION'
        })
    
    # Escribir CSV
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['from_address', 'to_address', 'amount_btc', 'flow_type'])
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"\n✓ Datos exportados a: {output_file}")
    print(f"  Total de registros: {len(rows)}")


def create_graph(flow_data, output_file="ransomware_graph.png"):
    """
    Crea visualización del grafo de flujo usando NetworkX.
    """
    if not flow_data:
        return
    
    print(f"\n[GENERANDO GRÁFICO]")
    
    G = nx.DiGraph()
    
    initial = flow_data['initial']
    accumulator = flow_data['accumulator']
    initial_amount = flow_data['initial_to_accumulator']
    
    # Calcular totales
    total_from_others = sum(flow_data['other_sources'].values())
    total_to_accumulator = initial_amount + total_from_others
    total_to_destinations = sum(flow_data['destinations'].values())
    
    # Añadir nodos principales
    G.add_node(initial, node_type='initial',
              label=f'INICIAL\n(Ransomware)\n{initial[:8]}...\n\nEnvía:\n{initial_amount:.4f} BTC')
    
    G.add_node(accumulator, node_type='accumulator',
              label=f'ACUMULADORA\n{accumulator[:8]}...\n\nRecibe: {total_to_accumulator:.4f} BTC\nEnvía: {total_to_destinations:.4f} BTC')
    
    # CORRECCIÓN PROBLEMA 2: Arista inicial -> acumuladora con monto correcto
    G.add_edge(initial, accumulator, weight=initial_amount,
              label=f'{initial_amount:.4f} BTC')
    
    # CORRECCIÓN PROBLEMA 3: Mostrar mínimo 10 carteras individuales con aristas individuales
    other_sources_sorted = sorted(flow_data['other_sources'].items(), 
                                  key=lambda x: x[1], reverse=True)
    
    # Mostrar top 10 fuentes con aristas individuales
    for i, (source_addr, amount) in enumerate(other_sources_sorted[:10], 1):
        G.add_node(source_addr, node_type='source',
                  label=f'Fuente {i}\n{source_addr[:6]}...{source_addr[-6:]}\n{amount:.4f} BTC')
        G.add_edge(source_addr, accumulator, weight=amount,
                  label=f'{amount:.4f} BTC')
    
    # Si hay más de 10 fuentes, agrupar el resto
    if len(other_sources_sorted) > 10:
        remaining_amount = sum(amount for _, amount in other_sources_sorted[10:])
        num_remaining = len(other_sources_sorted) - 10
        G.add_node('other_sources_summary', node_type='sources_summary',
                  label=f'OTRAS FUENTES\n({num_remaining} carteras)\n{remaining_amount:.4f} BTC')
        G.add_edge('other_sources_summary', accumulator, weight=remaining_amount,
                  label=f'{remaining_amount:.4f} BTC')
    
    # Destinos (mostrar top 5 + resumen del resto)
    top_destinations = sorted(flow_data['destinations'].items(), key=lambda x: x[1], reverse=True)
    
    for i, (dest_addr, amount) in enumerate(top_destinations[:5], 1):
        G.add_node(dest_addr, node_type='destination',
                  label=f'Destino {i}\n{dest_addr[:6]}...{dest_addr[-6:]}\n{amount:.4f} BTC')
        G.add_edge(accumulator, dest_addr, weight=amount,
                  label=f'{amount:.4f} BTC')
    
    # Resumen de otros destinos
    if len(top_destinations) > 5:
        remaining_amount = sum(amount for _, amount in top_destinations[5:])
        num_remaining = len(top_destinations) - 5
        G.add_node('other_destinations', node_type='destinations_summary',
                  label=f'OTROS DESTINOS\n({num_remaining} carteras)\n{remaining_amount:.4f} BTC')
        G.add_edge(accumulator, 'other_destinations', weight=remaining_amount,
                  label=f'{remaining_amount:.4f} BTC')
    
    # Layout: columnas (inicial/fuentes | acumuladora | destinos)
    pos = {}
    
    # Columna izquierda: inicial arriba, fuentes abajo distribuidas
    pos[initial] = (0, 5)  # Posición más arriba para evitar solapamiento con leyenda
    
    # Distribuir las fuentes individuales verticalmente
    sources = [n for n in G.nodes() if G.nodes[n].get('node_type') == 'source']
    num_sources = len(sources)
    for i, source in enumerate(sources):
        y_pos = 3 - (i * 0.8)  # Distribuir hacia abajo desde y=3
        pos[source] = (0, y_pos)
    
    # Si hay resumen de otras fuentes, ponerlo al final
    if 'other_sources_summary' in G.nodes():
        pos['other_sources_summary'] = (0, 3 - (num_sources * 0.8) - 0.5)
    
    # Columna centro: acumuladora
    pos[accumulator] = (4, 0)
    
    # Columna derecha: destinos distribuidos verticalmente
    destinations = [n for n in G.nodes() if G.nodes[n].get('node_type') in ['destination', 'destinations_summary']]
    num_dests = len(destinations)
    for i, dest in enumerate(destinations):
        y_pos = (i - (num_dests - 1) / 2) * 1.2
        pos[dest] = (8, y_pos)
    
    # Crear figura más grande para acomodar más nodos
    plt.figure(figsize=(22, 16))
    
    # Colores por tipo
    colors = {
        'initial': '#FF4444',
        'accumulator': '#FF8C00',
        'source': '#FFD700',
        'sources_summary': '#FFA500',
        'destination': '#90EE90',
        'destinations_summary': '#98FB98'
    }
    
    sizes = {
        'initial': 5000,
        'accumulator': 6000,
        'source': 2500,
        'sources_summary': 3500,
        'destination': 3000,
        'destinations_summary': 3000
    }
    
    # Dibujar nodos
    for node_type, color in colors.items():
        nodelist = [n for n in G.nodes() if G.nodes[n].get('node_type') == node_type]
        if nodelist:
            nx.draw_networkx_nodes(G, pos, nodelist=nodelist,
                                  node_color=color, node_size=sizes[node_type],
                                  alpha=0.95, edgecolors='black', linewidths=2.5)
    
    # Dibujar aristas
    # Inicial -> Acumuladora (roja, sólida, gruesa)
    nx.draw_networkx_edges(G, pos, [(initial, accumulator)],
                          edge_color='#FF4444', width=5, arrowsize=35,
                          arrowstyle='->', alpha=0.9, connectionstyle='arc3,rad=0.1')
    
    # Fuentes individuales -> Acumuladora (amarilla, discontinua)
    source_edges = [(u, v) for u, v in G.edges() if G.nodes[u].get('node_type') == 'source']
    if source_edges:
        nx.draw_networkx_edges(G, pos, source_edges,
                              edge_color='#FFD700', width=2.5, arrowsize=25,
                              style='dashed', alpha=0.75, connectionstyle='arc3,rad=0.15')
    
    # Resumen de fuentes -> Acumuladora (naranja, punteada)
    if 'other_sources_summary' in G.nodes():
        nx.draw_networkx_edges(G, pos, [('other_sources_summary', accumulator)],
                              edge_color='#FFA500', width=3, arrowsize=30,
                              style='dotted', alpha=0.8, connectionstyle='arc3,rad=0.15')
    
    # Acumuladora -> Destinos (verde, sólida)
    dest_edges = [(u, v) for u, v in G.edges() 
                  if G.nodes[v].get('node_type') in ['destination', 'destinations_summary']]
    nx.draw_networkx_edges(G, pos, dest_edges,
                          edge_color='#32CD32', width=3.5, arrowsize=28,
                          alpha=0.9, connectionstyle='arc3,rad=0.1')
    
    # Etiquetas de nodos
    labels = nx.get_node_attributes(G, 'label')
    nx.draw_networkx_labels(G, pos, labels, font_size=9, font_weight='bold',
                           bbox=dict(boxstyle='round,pad=0.5', facecolor='white',
                                   edgecolor='black', linewidth=2, alpha=0.95))
    
    # Etiquetas de aristas (montos)
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=8,
                                font_weight='bold',
                                bbox=dict(boxstyle='round,pad=0.3', facecolor='white',
                                        edgecolor='gray', linewidth=1.5, alpha=0.95))
    
    # Título
    plt.title(f"Análisis de Flujo de Fondos de Ransomware\n" +
             f"Total acumulado: {total_to_accumulator:.6f} BTC | " +
             f"Total distribuido: {total_to_destinations:.6f} BTC",
             fontsize=18, fontweight='bold', pad=25)
    
    # CORRECCIÓN PROBLEMA 1: Leyenda en posición que no solape (abajo a la derecha)
    legend = [
        Patch(facecolor='#FF4444', edgecolor='black', label='Cartera Ransomware (inicial)'),
        Patch(facecolor='#FF8C00', edgecolor='black', label='Cartera Acumuladora'),
        Patch(facecolor='#FFD700', edgecolor='black', label='Fuentes individuales'),
        Patch(facecolor='#FFA500', edgecolor='black', label='Otras fuentes agrupadas'),
        Patch(facecolor='#90EE90', edgecolor='black', label='Carteras destino finales')
    ]
    plt.legend(handles=legend, loc='lower right', fontsize=11, framealpha=0.95,
              edgecolor='black', fancybox=True)
    
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
    
    print(f"✓ Gráfico guardado: {output_file}")
    print(f"  - Nodos totales: {G.number_of_nodes()}")
    print(f"  - Fuentes individuales mostradas: {len(sources)}")
    print(f"  - Destinos mostrados: {len([n for n in G.nodes() if G.nodes[n].get('node_type') == 'destination'])}")
    plt.close()



def main():
    parser = argparse.ArgumentParser(
        description='Análisis de flujo de fondos de ransomware usando bitcoinlib',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplo de uso:
  python bitcoin_ransomware_bitcoinlib.py -w 15mGM5Hkjic47WnRQ52F9vBfwnr5K1XSbk
        """
    )
    
    parser.add_argument('-w', '--wallet', required=True,
                       help='Dirección Bitcoin inicial asociada a ransomware')
    parser.add_argument('-o', '--output', default='ransomware_analysis.csv',
                       help='Archivo CSV de salida (default: ransomware_analysis.csv)')
    parser.add_argument('-g', '--graph', default='ransomware_graph.png',
                       help='Archivo PNG del gráfico (default: ransomware_graph.png)')
    
    args = parser.parse_args()
    
    # Ejecutar análisis
    flow_data = analyze_ransomware_flow(args.wallet)
    
    if flow_data:
        # Exportar resultados
        export_to_csv(flow_data, args.output)
        create_graph(flow_data, args.graph)
        
        print("\n" + "=" * 80)
        print("✓ ANÁLISIS COMPLETADO")
        print("=" * 80)
    else:
        print("\n✗ No se pudo completar el análisis")


if __name__ == "__main__":
    main()

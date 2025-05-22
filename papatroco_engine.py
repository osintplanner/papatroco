import requests
import time
import datetime
from collections import Counter
import logging

# Configuração do Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuração da API Key da CoinMarketCap
COINMARKETCAP_API_KEY = "7f8fa209-acbe-4fd1-bcbb-ae8c886fea58"
WALLETEXPLORER_API_BASE = "https://www.walletexplorer.com/api/1"

# === CONSULTAS VIA MEMPOOL.SPACE ===
def get_transaction_mempool(txid):
    url = f"https://mempool.space/api/tx/{txid}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro ao obter transação {txid}: {e}")
        return None
    except ValueError as e:
        logging.error(f"Erro ao decodificar JSON para transação {txid}: {e}")
        return None
    except Exception as e:
        logging.exception(f"Erro inesperado ao obter transação {txid}: {e}")
        return None

def get_outspend_mempool(txid, vout_idx):
    url = f"https://mempool.space/api/tx/{txid}/outspend/{vout_idx}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro ao obter outspend de {txid}:{vout_idx}: {e}")
        return None
    except ValueError as e:
        logging.error(f"Erro ao decodificar JSON para outspend de {txid}:{vout_idx}: {e}")
        return None
    except Exception as e:
        logging.exception(f"Erro inesperado ao obter outspend de {txid}:{vout_idx}: {e}")
        return None

def get_address_txs_mempool(address):
    """Consulta transações com fallback para WalletExplorer"""
    # Tenta primeiro mempool.space
    url = f"https://mempool.space/api/address/{address}/txs"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        if r.status_code == 200:
            return r.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro ao consultar transações de {address} no Mempool.space: {e}")
    except ValueError as e:
        logging.error(f"Erro ao decodificar JSON para transações de {address} no Mempool.space: {e}")
    except Exception as e:
        logging.exception(f"Erro inesperado ao consultar transações de {address} no Mempool.space: {e}")

    # Fallback para WalletExplorer (se mempool falhar)
    return get_address_txs_walletexplorer(address)

def get_block_timestamp(block_height):
    url_hash = f"https://mempool.space/api/block-height/{block_height}"
    try:
        r_hash = requests.get(url_hash, timeout=10)
        r_hash.raise_for_status()
        block_hash = r_hash.text.strip()
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro ao obter hash do bloco {block_height}: {e}")
        return None
    except ValueError as e:
        logging.error(f"Erro ao decodificar JSON para hash do bloco {block_height}: {e}")
        return None
    except Exception as e:
        logging.exception(f"Erro inesperado ao obter hash do bloco {block_height}: {e}")
        return None

    url_block = f"https://mempool.space/api/block/{block_hash}"
    try:
        r_block = requests.get(url_block, timeout=10)
        r_block.raise_for_status()
        return r_block.json().get('timestamp')
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro ao obter timestamp do bloco {block_hash}: {e}")
        return None
    except ValueError as e:
        logging.error(f"Erro ao decodificar JSON para timestamp do bloco {block_hash}: {e}")
        return None
    except Exception as e:
        logging.exception(f"Erro inesperado ao obter timestamp do bloco {block_hash}: {e}")
        return None

def get_address_txs_walletexplorer(address):
    """Consulta transações de um endereço no WalletExplorer (se for uma carteira conhecida)"""
    url = f"{WALLETEXPLORER_API_BASE}/address/{address}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json().get('transactions', [])
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro ao consultar WalletExplorer: {e}")
        return []
    except ValueError as e:
        logging.error(f"Erro ao decodificar JSON para WalletExplorer: {e}")
        return []
    except Exception as e:
        logging.exception(f"Erro inesperado ao consultar WalletExplorer: {e}")
        return []

def is_wallet_address(address):
    """Verifica se o endereço está associado a uma carteira conhecida (ex: exchanges)"""
    url = f"{WALLETEXPLORER_API_BASE}/address/{address}"
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        return r.status_code == 200 and 'label' in r.json()
    except requests.exceptions.RequestException:
        return False
    except ValueError:
        return False
    except Exception:
        return False

def get_wallet_label(address):
    """Obtém o rótulo da carteira (ex: 'Binance', 'Coinbase')"""
    url = f"{WALLETEXPLORER_API_BASE}/address/{address}"
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        return r.json().get('label', 'Desconhecido')
    except requests.exceptions.RequestException:
        return 'Desconhecido'
    except ValueError:
        return 'Desconhecido'
    except Exception:
        return 'Desconhecido'

# === COTAÇÃO COM PRIORIDADE PARA COINMARKETCAP ===
def get_btc_price_on_date(date_str):
    """Obtém cotação histórica com prioridade para CoinMarketCap"""
    day, month, year = date_str.split('-')
    date_iso = f"{year}-{month}-{day}"

    # 1. Tenta primeiro com CoinMarketCap
    try:
        url = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/historical"
        params = {
            'symbol': 'BTC',
            'convert': 'USD',
            'time_start': date_iso,
            'time_end': date_iso
        }
        headers = {'X-CMC_PRO_API_KEY': COINMARKETCAP_API_KEY}

        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        if 'data' in data and 'BTC' in data['data']:
            quotes = data['data']['BTC']['quotes']
            if quotes and len(quotes) > 0:
                price = quotes[0]['quote']['USD']['price']
                print(f"✅ Cotação obtida via CoinMarketCap: {price:.2f} USD")
                return price
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro ao consultar CoinMarketCap: {e}")
    except KeyError as e:
        logging.error(f"Erro ao processar resposta do CoinMarketCap: {e}")

    # 2. Fallback para outras APIs
    apis = [
        {
            'nome': 'CoinGecko',
            'url': f"https://api.coingecko.com/api/v3/coins/bitcoin/history?date={date_str}",
            'parser': lambda r: r.json().get('market_data', {}).get('current_price', {}).get('usd')
        },
        {
            'nome': 'Coinpaprika',
            'url': f"https://api.coinpaprika.com/v1/coins/btc-bitcoin/ohlcv/historical?start={date_str}&end={date_str}",
            'parser': lambda r: r.json()[0]['close'] if r.json() and isinstance(r.json(), list) else None
        },
        {
            'nome': 'CryptoCompare',
            'url': f"https://min-api.cryptocompare.com/data/pricehistorical?fsym=BTC&tsyms=USD&ts={int(time.mktime(datetime.datetime.strptime(date_str, '%d-%m-%Y').timetuple()))}",
            'parser': lambda r: r.json().get('BTC', {}).get('USD')
        },
        {
            'nome': 'WalletExplorer',
            'url': f"https://www.walletexplorer.com/api/1/coinprice?coin=btc&date={date_str}",
            'parser': lambda r: float(r.json().get('price')) if r.json().get('price') else None
        }
    ]

    for api in apis:
        try:
            r = requests.get(api['url'], timeout=10)
            r.raise_for_status()
            price = api['parser'](r)
            if price:
                print(f"✅ Cotação obtida via {api['nome']}: {price:.2f} USD")
                return float(price)
        except requests.exceptions.RequestException as e:
            logging.error(f"Erro ao consultar {api['nome']}: {e}")
        except KeyError as e:
            logging.error(f"Erro ao processar resposta da {api['nome']}: {e}")
        except Exception as e:
            logging.exception(f"Erro inesperado ao consultar {api['nome']}: {e}")

    print("❌ Não foi possível obter cotação para a data.")
    return None

# === FUNÇÕES AUXILIARES ===
def prefixo_tecnologia(endereco):
    if endereco.startswith("1"):
        return "P2PKH"
    elif endereco.startswith("3"):
        return "P2SH"
    elif endereco.startswith("bc1p"):
        return "P2TR"
    elif endereco.startswith("bc1q"):
        return "Bech32"
    else:
        return "Desconhecido"

def is_valor_redondo(valor_btc):
    str_valor = f"{valor_btc:.8f}".rstrip("0").rstrip(".") if "." in f"{valor_btc:.8f}" else f"{valor_btc:.8f}"

    if str_valor.endswith("0000") or str_valor.endswith("5000"):
        return True

    partes = str_valor.split(".")
    if len(partes) == 2:
        parte_decimal = partes[1]
        if len(parte_decimal.rstrip("0")) <= 2:
            return True
        if parte_decimal.count("0") >= 4 and len(parte_decimal.rstrip("0")) <= 3:
            return True

    if str_valor.endswith(".0") or str_valor.endswith(".5"):
        return True

    if any(str_valor.endswith(x) for x in ["99", "9999"]):
        return True

    return False

def is_valor_redondo_usd(valor_btc, btc_usd):
    if not btc_usd:
        return False
    valor_usd = valor_btc * btc_usd
    return abs(valor_usd - round(valor_usd)) <= 0.05

def buscar_primeira_transacao(address):
    txs = get_address_txs_mempool(address)
    return len(txs) == 1

def is_multisig_script(texto):
    return texto and "OP_CHECKMULTISIG" in texto

def buscar_multisig_real(input_data):
    prev_txid = input_data.get('txid')
    vout_idx = input_data.get('vout')
    if prev_txid is None or vout_idx is None:
        return False

    prevout = input_data.get('prevout', {})
    address = prevout.get('scriptpubkey_address')
    if not address:
        return False

    outspend = get_outspend_mempool(prev_txid, vout_idx)
    if outspend and outspend.get('spent'):
        gasto_txid = outspend.get('txid')
        if gasto_txid:
            gasto_tx = get_transaction_mempool(gasto_txid)
            if gasto_tx:
                for vin in gasto_tx.get('vin', []):
                    if vin.get('prevout', {}).get('txid') == prev_txid and vin.get('prevout', {}).get('vout') == vout_idx:
                        witness = vin.get('witness', [])
                        if witness:
                            for w in witness:
                                if is_multisig_script(w):
                                    return True
                        asm = vin.get('scriptsig_asm', '')
                        if is_multisig_script(asm):
                            return True
    return False

def analyze_address_reuse(address, current_txid):
    """Analisa o reuso de um endereço, penalizando endereços de troco."""

    txs = get_address_txs_mempool(address)
    if not txs:
        return 0  # Endereço não encontrado (neutro)

    score = 0
    if len(txs) > 1:
        score -= 0.5  # Penalidade leve para reuso
    if any(tx['txid'] == current_txid for tx in txs):
        score = 0 # Ignora a transação atual
    return score

def calculate_time_between_spending(txid, output_addresses):
    """Calcula o tempo médio entre o recebimento e o gasto de um output."""

    tx = get_transaction_mempool(txid)
    if not tx:
        return {}

    output_spent_times = {}
    for i, o in enumerate(tx['vout']):
        addr = o.get('scriptpubkey_address')
        if not addr or addr not in output_addresses:
            continue

        outspend = get_outspend_mempool(txid, i)
        if outspend and outspend.get('spent'):
            spending_txid = outspend.get('txid')
            spending_tx = get_transaction_mempool(spending_txid)
            if spending_tx and tx.get('status', {}).get('block_time') and spending_tx.get('status', {}).get('block_time'):
                time_diff = spending_tx['status']['block_time'] - tx['status']['block_time']
                output_spent_times[addr] = time_diff
    return output_spent_times

# === ANÁLISE DE TROCO PRINCIPAL ===
def analisar_troco(txid):
    btc_usd = None
    print("\n🔎 Iniciando análise da transação...")

    tx = get_transaction_mempool(txid)
    if not tx:
        return "Transação não encontrada.", None, []

    inputs = tx['vin']
    outputs = tx['vout']

    # Cálculo dos totais
    total_input = sum(i.get('prevout', {}).get('value', 0) for i in inputs) / 100_000_000
    total_output = sum(o.get('value', 0) for o in outputs) / 100_000_000
    taxa = total_input - total_output

    print(f"💸 Totais: Inputs={total_input:.8f} BTC | Outputs={total_output:.8f} BTC | Taxa≈{taxa:.8f} BTC")

    # Obter cotação histórica
    block_height = tx.get('status', {}).get('block_height')
    if block_height:
        timestamp = get_block_timestamp(block_height)
        if timestamp:
            dt = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            date_str = dt.strftime("%d-%m-%Y")
            print(f"📅 Data da transação: {date_str}")
            btc_usd = get_btc_price_on_date(date_str)
            if btc_usd:
                print(f"✅ Cotação BTC/USD encontrada: {btc_usd:.2f} USD")
            else:
                print("⚠️ Cotação não encontrada para esta data")

    # Coletar informações dos inputs
    input_addresses = set()
    input_tecnologias = set()
    input_multisig = False
    input_values = []

    for i in inputs:
        prevout = i.get('prevout', {})
        addr = prevout.get('scriptpubkey_address')
        val = prevout.get('value', 0) / 100_000_000
        if addr:
            input_addresses.add(addr)
            input_tecnologias.add(prefixo_tecnologia(addr))
        input_values.append(val)

        if buscar_multisig_real(i):
            input_multisig = True

    # Preparar dados dos outputs
    outputs_data = []
    for o in outputs:
        addr = o.get('scriptpubkey_address')
        val = o.get('value') / 100_000_000
        tipo = prefixo_tecnologia(addr) if addr else "Desconhecido"
        script_type = o.get('scriptpubkey_type')
        outputs_data.append({
            'endereco': addr,
            'valor': val,
            'tecnologia': tipo,
            'script_type': script_type,
            'diferenca_input': None,
            'valor_usd': val * btc_usd if btc_usd else None,
            'address_reuse_score': 0,
            'time_until_spent': None
        })

    # --- HEURÍSTICAS APRIMORADAS ---

    # Heurística 0: Se um output é de uma carteira conhecida, provavelmente NÃO é troco
    for out in outputs_data[:]:  # Usamos [:] para criar uma cópia durante a iteração
        if out['endereco'] and is_wallet_address(out['endereco']):
            logging.info(f"Endereço {out['endereco']} pertence a uma carteira conhecida (não é troco)")
            outputs_data.remove(out)

    # Heurística 1: Endereço repetido (input = output)
    for out in outputs_data:
        if out['endereco'] in input_addresses:
            logging.info(f"Endereço {out['endereco']} é igual a um dos inputs.")
            return f"🎯 Troco identificado: {out['endereco']} (mesmo endereço nos inputs)", btc_usd, outputs_data

    # Heurística 2: Valores redondos em BTC e USD
    for out in outputs_data:
        if is_valor_redondo(out['valor']):
            logging.info(f"Valor BTC redondo detectado: {out['valor']:.8f} BTC")
            return f"🎯 Troco identificado: {out['endereco']} (valor redondo: {out['valor']:.8f} BTC)", btc_usd, outputs_data
        if btc_usd and is_valor_redondo_usd(out['valor'], btc_usd):
            logging.info(f"Valor USD redondo detectado: {out['valor_usd']:.2f} USD")
            return f"🎯 Troco identificado: {out['endereco']} (valor redondo: {out['valor_usd']:.2f} USD)", btc_usd, outputs_data

    # Heurística 3: Diferença em relação aos inputs
    for out in outputs_data:
        out['diferenca_input'] = min(abs(val - out['valor']) for val in input_values)

    outputs_data.sort(key=lambda x: x['diferenca_input'])
    if len(outputs_data) > 1 and outputs_data[0]['diferenca_input'] < outputs_data[1]['diferenca_input'] * 0.1:
        logging.info(f"Menor diferença: {outputs_data[0]['endereco']} (dif={outputs_data[0]['diferenca_input']:.8f} BTC)")
        return f"🎯 Troco identificado: {outputs_data[0]['endereco']} (valor mais próximo da diferença)", btc_usd, outputs_data

    # Heurística 4: Mesma tecnologia que inputs
    if len(input_tecnologias) == 1:
        tech = list(input_tecnologias)[0]
        mesmo_tech = [o for o in outputs_data if o['tecnologia'] == tech]
        if len(mesmo_tech) == 1:
            logging.info(f"Único output com tecnologia {tech}")
            return f"🎯 Troco identificado: {mesmo_tech[0]['endereco']} (único com tecnologia {tech})", btc_usd, outputs_data

    # Heurística 5: Primeira transação do endereço
    for out in outputs_data:
        if buscar_primeira_transacao(out['endereco']):
            logging.info(f"Primeira transação do endereço: {out['endereco']}")
            return f"🎯 Provável troco: {out['endereco']} (primeira transação recebida)", btc_usd, outputs_data

    # Heurística 6: Análise de reuso de endereços
    for out in outputs_data:
        out['address_reuse_score'] = analyze_address_reuse(out['endereco'], txid)

    outputs_data.sort(key=lambda x: x['address_reuse_score'])
    if outputs_data[0]['address_reuse_score'] < -0.2:  # Limiar para penalizar reuso
        logging.info(f"Endereço de troco provável (reuso): {outputs_data[0]['endereco']} (score={outputs_data[0]['address_reuse_score']})")
        return f"🎯 Provável troco: {outputs_data[0]['endereco']} (baixo reuso)", btc_usd, outputs_data

    # Heurística 7: Análise de tempo até o próximo gasto (time_until_spent)
    output_addresses = [out['endereco'] for out in outputs_data if out['endereco']]
    time_spent_data = calculate_time_between_spending(txid, output_addresses)

    for out in outputs_data:
        if out['endereco'] and out['endereco'] in time_spent_data:
            out['time_until_spent'] = time_spent_data[out['endereco']]

    # Se houver dados de tempo, ordenar por tempo e escolher o menor
    if any(out['time_until_spent'] is not None for out in outputs_data):
        outputs_data_with_time = [out for out in outputs_data if out['time_until_spent'] is not None]
        outputs_data_with_time.sort(key=lambda x: x['time_until_spent'])
        shortest_spent = outputs_data_with_time[0]
        logging.info(f"Troco provável (gasto rápido): {shortest_spent['endereco']} (tempo={shortest_spent['time_until_spent']})")
        return f"🎯 Troco provável: {shortest_spent['endereco']} (gasto rápido)", btc_usd, outputs_data

    # Se nenhuma heurística decisiva, recomendar análise manual
    logging.warning("Nenhuma regra conseguiu identificar o troco.")
    return f"🔗 Análise manual recomendada: https://blockchair.com/bitcoin/transaction/{txid}", btc_usd, outputs_data

# === GERAR CONTEXTO PARA IA ===
def gerar_contexto_para_ia(txid):
    print("\n🧠 Gerando contexto detalhado para a Inteligência Artificial...")

    tx = get_transaction_mempool(txid)
    if not tx:
        return "Transação não encontrada."

    inputs = tx['vin']
    outputs = tx['vout']

    input_addresses = set()
    for i in inputs:
        prevout = i.get('prevout', {})
        addr = prevout.get('scriptpubkey_address', 'desconhecido')
        if addr:
            input_addresses.add(addr)

    contexto = []
    contexto.append(f"🔍 TXID analisado: {txid}\n")

    contexto.append("📥 Inputs (endereços de envio):")
    for i in inputs:
        prevout = i.get('prevout', {})
        addr = prevout.get('scriptpubkey_address', 'desconhecido')
        val = prevout.get('value', 0) / 100_000_000
        tipo = prefixo_tecnologia(addr)
        contexto.append(f"- {addr} | {tipo} | {val:.8f} BTC")

    contexto.append("\n📤 Outputs (endereços de recebimento):")
    for o in outputs:
        addr = o.get('scriptpubkey_address', 'desconhecido')
        val = o.get('value', 0) / 100_000_000
        tipo = prefixo_tecnologia(addr)
        script_type = o.get('scriptpubkey_type', 'desconhecido')
        extra = " (também nos inputs)" if addr in input_addresses else ""
        contexto.append(f"- {addr} | {tipo} ({script_type}) | {val:.8f} BTC{extra}")

    # Identifica carteiras conhecidas
    for o in outputs:
        addr = o.get('scriptpubkey_address')
        if addr and is_wallet_address(addr):
            contexto.append(f"   → Carteira conhecida: {addr} (serviço: {get_wallet_label(addr)})")

    # Verificação de multisig
    multisig_detectado = any(buscar_multisig_real(i) for i in inputs)
    contexto.append(f"\n⚡ Multisig detectado entre os inputs: {'SIM' if multisig_detectado else 'NÃO'}")

    # Incluir cotação BTC/USD
    block_height = tx.get('status', {}).get('block_height')
    if block_height:
        timestamp = get_block_timestamp(block_height)
        if timestamp:
            dt = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            date_str = dt.strftime("%d-%m-%Y")
            btc_usd = get_btc_price_on_date(date_str)
            contexto.append(f"\n💵 Cotação do BTC em {date_str}: {btc_usd if btc_usd else 'não disponível'} USD")
    
    return "\n".join(contexto)

# === EXECUÇÃO ===
if __name__ == "__main__":
    txid = input("Digite o TXID da transação: ").strip()
    resultado, btc_usd, outputs_data = analisar_troco(txid)

    print("\n🔚 Resultado:", resultado)

    if btc_usd:
        print(f"\n💵 Valor de 1 BTC na data da transação: {btc_usd:.2f} USD")
        print("🔎 Calculando valores USD dos outputs:")
        for out in outputs_data:
            valor_usd = out['valor'] * btc_usd
            print(f"• {out['endereco']}: {out['valor']:.8f} BTC ≈ {valor_usd:.2f} USD")
    else:
        print("\n⛔ Não foi possível obter a cotação BTC/USD da data da transação.")

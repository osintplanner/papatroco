import requests
import time
import datetime

# Configuração da API Key da CoinMarketCap
COINMARKETCAP_API_KEY = "7f8fa209-acbe-4fd1-bcbb-ae8c886fea58"
WALLETEXPLORER_API_BASE = "https://www.walletexplorer.com/api/1"

# === CONSULTAS VIA MEMPOOL.SPACE ===
def get_transaction_mempool(txid):
    url = f"https://mempool.space/api/tx/{txid}"
    r = requests.get(url, timeout=10)
    return r.json() if r.status_code == 200 else None

def get_outspend_mempool(txid, vout_idx):
    url = f"https://mempool.space/api/tx/{txid}/outspend/{vout_idx}"
    r = requests.get(url, timeout=10)
    return r.json() if r.status_code == 200 else None

def get_address_txs_mempool(address):
    """Consulta transações com fallback para WalletExplorer"""
    # Tenta primeiro mempool.space
    url = f"https://mempool.space/api/address/{address}/txs"
    r = requests.get(url, timeout=10)
    if r.status_code == 200:
        return r.json()
    
    # Fallback para WalletExplorer (se mempool falhar)
    return get_address_txs_walletexplorer(address)

def get_block_timestamp(block_height):
    url_hash = f"https://mempool.space/api/block-height/{block_height}"
    r_hash = requests.get(url_hash, timeout=10)
    if r_hash.status_code != 200:
        return None
    block_hash = r_hash.text.strip()
    url_block = f"https://mempool.space/api/block/{block_hash}"
    r_block = requests.get(url_block, timeout=10)
    if r_block.status_code != 200:
        return None
    return r_block.json().get('timestamp')

def get_address_txs_walletexplorer(address):
    """Consulta transações de um endereço no WalletExplorer (se for uma carteira conhecida)"""
    url = f"{WALLETEXPLORER_API_BASE}/address/{address}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.json().get('transactions', [])
    except Exception as e:
        print(f"⚠️ Erro ao consultar WalletExplorer: {str(e)}")
    return []

def is_wallet_address(address):
    """Verifica se o endereço está associado a uma carteira conhecida (ex: exchanges)"""
    url = f"{WALLETEXPLORER_API_BASE}/address/{address}"
    try:
        r = requests.get(url, timeout=5)
        return r.status_code == 200 and 'label' in r.json()
    except:
        return False

def get_wallet_label(address):
    """Obtém o rótulo da carteira (ex: 'Binance', 'Coinbase')"""
    url = f"{WALLETEXPLORER_API_BASE}/address/{address}"
    try:
        r = requests.get(url, timeout=5)
        return r.json().get('label', 'Desconhecido')
    except:
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
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'BTC' in data['data']:
                quotes = data['data']['BTC']['quotes']
                if quotes and len(quotes) > 0:
                    price = quotes[0]['quote']['USD']['price']
                    print(f"✅ Cotação obtida via CoinMarketCap: {price:.2f} USD")
                    return price
    except Exception as e:
        print(f"⚠️ Erro ao consultar CoinMarketCap: {str(e)}")

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
            if r.status_code == 200:
                price = api['parser'](r)
                if price:
                    print(f"✅ Cotação obtida via {api['nome']}: {price:.2f} USD")
                    return float(price)
        except Exception as e:
            print(f"⚠️ Erro ao consultar {api['nome']}: {str(e)}")

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
            'valor_usd': val * btc_usd if btc_usd else None
        })

    # Nova verificação: Se um output é de uma carteira conhecida, provavelmente NÃO é troco
    for out in outputs_data[:]:  # Usamos [:] para criar uma cópia durante a iteração
        if out['endereco'] and is_wallet_address(out['endereco']):
            print(f"⚠️ Endereço {out['endereco']} pertence a uma carteira conhecida (não é troco)")
            outputs_data.remove(out)

    # Verificação 1: Endereço repetido (input = output)
    for out in outputs_data:
        if out['endereco'] in input_addresses:
            print(f"✅ Endereço {out['endereco']} é igual a um dos inputs.")
            return f"🎯 Troco identificado: {out['endereco']} (mesmo endereço nos inputs)", btc_usd, outputs_data

    # Verificação 2: Valores redondos em BTC
    for out in outputs_data:
        if is_valor_redondo(out['valor']):
            print(f"✅ Valor BTC redondo detectado: {out['valor']:.8f} BTC")
            return f"🎯 Troco identificado: {out['endereco']} (valor redondo: {out['valor']:.8f} BTC)", btc_usd, outputs_data

    # Verificação 3: Diferença em relação aos inputs
    for out in outputs_data:
        out['diferenca_input'] = min(abs(val - out['valor']) for val in input_values)
    
    outputs_data.sort(key=lambda x: x['diferenca_input'])
    if len(outputs_data) > 1 and outputs_data[0]['diferenca_input'] < outputs_data[1]['diferenca_input'] * 0.1:
        print(f"✅ Menor diferença: {outputs_data[0]['endereco']} (dif={outputs_data[0]['diferenca_input']:.8f} BTC)")
        return f"🎯 Troco identificado: {outputs_data[0]['endereco']} (valor mais próximo da diferença)", btc_usd, outputs_data

    # Verificação 4: Mesma tecnologia que inputs
    if len(input_tecnologias) == 1:
        tech = list(input_tecnologias)[0]
        mesmo_tech = [o for o in outputs_data if o['tecnologia'] == tech]
        if len(mesmo_tech) == 1:
            print(f"✅ Único output com tecnologia {tech}")
            return f"🎯 Troco identificado: {mesmo_tech[0]['endereco']} (único com tecnologia {tech})", btc_usd, outputs_data

    # Verificação 5: Primeira transação do endereço
    for out in outputs_data:
        if buscar_primeira_transacao(out['endereco']):
            print(f"✅ Primeira transação do endereço: {out['endereco']}")
            return f"🎯 Provável troco: {out['endereco']} (primeira transação recebida)", btc_usd, outputs_data

    print("⚠️ Nenhuma regra conseguiu identificar o troco.")
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
        addr = prevout.get('scriptpubkey_address')
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
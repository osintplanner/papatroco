from flask import Flask, request, jsonify, render_template
import papatroco_engine
import datetime
import webbrowser
import threading
import time
from openai import OpenAI  # SDK >= 1.0.0
import os
from functools import lru_cache

app = Flask(__name__, template_folder='templates')

# Variável global para controlar se o browser já foi aberto
browser_opened = False

@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/analisar', methods=['POST'])
def analisar():
    data = request.get_json()
    txid = data.get('txid')

    if not txid:
        return jsonify({'resultado': '❌ TXID não informado.'}), 400

    if not isinstance(txid, str) or len(txid) != 64 or not all(c in '0123456789abcdefABCDEF' for c in txid):
        return jsonify({'resultado': '❌ Formato de TXID inválido. Deve ter 64 caracteres hexadecimais.'}), 400

    try:
        resultado, btc_usd, outputs_data = papatroco_engine.analisar_troco(txid)

        tx = papatroco_engine.get_transaction_mempool(txid)
        if not tx:
            return jsonify({'resultado': '❌ Transação não encontrada. Verifique o TXID.'}), 404

        inputs = []
        for i in tx['vin']:
            prevout = i.get('prevout', {})
            endereco = prevout.get('scriptpubkey_address', 'desconhecido')
            valor = prevout.get('value', 0) / 100_000_000
            valor_usd = (valor * btc_usd) if btc_usd else 0
            inputs.append({
                'endereco': endereco, 
                'valor_btc': round(valor, 8), 
                'valor_usd': round(valor_usd, 2)
            })

        outputs = []
        for o in tx['vout']:
            endereco = o.get('scriptpubkey_address', 'desconhecido')
            valor = o.get('value', 0) / 100_000_000
            valor_usd = (valor * btc_usd) if btc_usd else 0
            outputs.append({
                'endereco': endereco, 
                'valor_btc': round(valor, 8), 
                'valor_usd': round(valor_usd, 2)
            })

        timestamp = None
        if tx.get('status', {}).get('block_time'):
            timestamp = datetime.datetime.fromtimestamp(tx['status']['block_time'], datetime.timezone.utc)
        datahora = timestamp.strftime("%d/%m/%Y %H:%M:%S") if timestamp else "Não confirmada"

        return jsonify({
            'resultado': resultado,
            'dados': {
                'datahora': datahora,
                'inputs': inputs,
                'outputs': outputs,
                'btc_usd': round(btc_usd, 2) if btc_usd else None
            }
        })

    except Exception as e:
        app.logger.error(f"Erro ao analisar transação {txid}: {str(e)}")
        return jsonify({'resultado': '❌ Erro interno no servidor ao analisar a transação.'}), 500

@app.route('/consultar-ia', methods=['POST'])
def consultar_ia():
    data = request.get_json()
    txid = data.get('txid')
    apikey = data.get('apikey')

    if not txid or not apikey:
        return jsonify({'resposta': '❌ TXID ou API Key não informados.'}), 400

    try:
        contexto = papatroco_engine.gerar_contexto_para_ia(txid)
        if not contexto:
            return jsonify({'resposta': '❌ Não foi possível gerar contexto para análise.'}), 400

        client = OpenAI(api_key=apikey)

        prompt = (
            "Você é um analista de blockchain. Analise esta transação Bitcoin e identifique "
            "qual output é provavelmente o troco, explicando com base em:\n"
            "1. Heurística de endereço único\n"
            "2. Valor do output\n"
            "3. Ordem dos outputs\n"
            "4. Outros padrões relevantes\n\n"
            f"Dados da transação:\n{contexto}\n\n"
            "Forneça uma análise concisa em português (3-5 parágrafos). "
            "Destaque o endereço de troco mais provável se identificado."
        )

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system", 
                    "content": "Você é um analista especializado em blockchain Bitcoin com foco em análise forense."
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=500
        )

        resposta = response.choices[0].message.content.strip()
        return jsonify({'resposta': resposta})

    except Exception as e:
        app.logger.error(f"Erro ao consultar IA para transação {txid}: {str(e)}")
        return jsonify({'resposta': '❌ Erro ao consultar a IA. Verifique sua API Key e tente novamente.'}), 500

def abrir_navegador():
    global browser_opened
    if not browser_opened:
        time.sleep(1.5)
        webbrowser.open_new("http://127.0.0.1:5000")
        browser_opened = True

if __name__ == "__main__":
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    if not os.path.exists(os.path.join(template_dir, 'index.html')):
        print(f"❌ Erro: index.html não encontrado em {template_dir}")
    else:
        threading.Thread(target=abrir_navegador).start()
        app.run(debug=True, use_reloader=False)

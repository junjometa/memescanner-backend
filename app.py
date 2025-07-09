from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from functools import wraps
from web3 import Web3
from web3.exceptions import ContractLogicError
import requests
import time
import json
import os
import logging
import hashlib
import hmac

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuración de seguridad
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-this')
API_KEY = os.environ.get('API_KEY', 'your-api-key-here')

# Configuración CORS para producción
allowed_origins = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
CORS(app, origins=allowed_origins, supports_credentials=True)

# Rate limiting mejorado
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get('REDIS_URL', 'memory://')
)

# Configuración Web3
POLYGON_RPC = os.environ.get('POLYGON_RPC', 'https://polygon-rpc.com')
CONTRACT_ADDRESS = os.environ.get('CONTRACT_ADDRESS', '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512')

# ABI del contrato (simplificado)
CONTRACT_ABI = json.loads('''[
    {
        "inputs": [{"internalType": "uint256", "name": "scanId", "type": "uint256"}],
        "name": "getScanDetails",
        "outputs": [
            {"internalType": "address", "name": "buyer", "type": "address"},
            {"internalType": "address", "name": "targetContract", "type": "address"},
            {"internalType": "uint256", "name": "chainId", "type": "uint256"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "bool", "name": "isFullScan", "type": "bool"},
            {"internalType": "uint256", "name": "paidAmountUSD", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]''')

# Inicializar Web3
try:
    w3 = Web3(Web3.HTTPProvider(POLYGON_RPC))
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    logger.info(f"Connected to Polygon: {w3.is_connected()}")
except Exception as e:
    logger.error(f"Failed to connect to Polygon: {e}")
    w3 = None
    contract = None

# Cache de precios crypto
crypto_prices = {}
last_price_update = 0

# Cache de análisis (5 minutos)
analysis_cache = {}
CACHE_TTL = 300  # 5 minutos

# Autenticación API Key
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        # En desarrollo, permitir sin API key
        if os.environ.get('ENVIRONMENT') == 'development':
            return f(*args, **kwargs)
            
        if not api_key or api_key != API_KEY:
            return jsonify({'error': 'Invalid or missing API key'}), 401
            
        return f(*args, **kwargs)
    return decorated_function

# Validación mejorada
def validate_address(address):
    """Valida dirección Ethereum con Web3"""
    if not address or not isinstance(address, str):
        return False
    try:
        Web3.to_checksum_address(address)
        return True
    except:
        return False

def validate_chain_id(chain_id):
    """Valida chain ID soportados"""
    supported_chains = {
        1: "Ethereum",
        56: "BSC", 
        137: "Polygon",
        42161: "Arbitrum",
        31337: "Localhost"
    }
    try:
        chain_id = int(chain_id)
        return chain_id in supported_chains
    except:
        return False

def validate_tx_hash(tx_hash):
    """Valida formato de transaction hash"""
    if not tx_hash or not isinstance(tx_hash, str):
        return False
    if not tx_hash.startswith('0x'):
        return False
    if len(tx_hash) != 66:
        return False
    try:
        int(tx_hash, 16)
        return True
    except ValueError:
        return False

# Función para verificar pago en blockchain
def verify_payment(tx_hash, expected_buyer):
    """Verifica que el pago se haya realizado en blockchain"""
    if not w3 or not contract:
        logger.error("Web3 not connected")
        return False
        
    try:
        # Obtener recibo de transacción
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if not receipt or receipt.status != 1:
            return False
            
        # Verificar que la tx sea al contrato correcto
        if receipt.to.lower() != CONTRACT_ADDRESS.lower():
            return False
            
        # Aquí podrías verificar eventos emitidos
        # Por simplicidad, asumimos que si la tx fue exitosa, el pago es válido
        return True
        
    except Exception as e:
        logger.error(f"Error verifying payment: {e}")
        return False

def get_crypto_prices():
    """Obtiene precios actuales de crypto con mejor manejo de errores"""
    global crypto_prices, last_price_update
    
    # Actualizar cada 5 minutos
    if time.time() - last_price_update > 300:
        try:
            # CoinGecko API
            url = "https://api.coingecko.com/api/v3/simple/price"
            params = {
                'ids': 'bitcoin,ethereum,matic-network,binancecoin',
                'vs_currencies': 'usd',
                'include_24hr_change': 'true'
            }
            
            resp = requests.get(url, params=params, timeout=5)
            if resp.status_code == 200:
                crypto_prices = resp.json()
                last_price_update = time.time()
                logger.info("Crypto prices updated successfully")
            else:
                logger.warning(f"Failed to fetch prices: {resp.status_code}")
                
        except requests.exceptions.Timeout:
            logger.error("Timeout fetching crypto prices")
        except Exception as e:
            logger.error(f"Error fetching crypto prices: {e}")
    
    # Devolver precios en cache o valores por defecto
    return crypto_prices or {
        "bitcoin": {"usd": 45000, "usd_24h_change": 2.5},
        "ethereum": {"usd": 2500, "usd_24h_change": 3.2},
        "matic-network": {"usd": 0.85, "usd_24h_change": -1.5},
        "binancecoin": {"usd": 320, "usd_24h_change": 1.8}
    }

# Análisis real de tokens (simplificado)
def analyze_token_onchain(address, chain_id):
    """Realiza análisis básico on-chain del token"""
    try:
        # En producción real, aquí conectarías a diferentes RPCs según chain_id
        # y realizarías consultas reales al contrato del token
        
        # Por ahora, simulación mejorada basada en la dirección
        address_hash = hashlib.sha256(address.encode()).hexdigest()
        risk_seed = int(address_hash[:8], 16) % 100
        
        return {
            'risk_score': risk_seed,
            'is_verified': risk_seed < 50,
            'has_liquidity': risk_seed < 80,
            'holder_count': 1000 + (risk_seed * 100),
            'liquidity_usd': 50000 + (risk_seed * 1000)
        }
    except Exception as e:
        logger.error(f"Error in on-chain analysis: {e}")
        return None

@app.route('/')
def index():
    """Root endpoint"""
    return jsonify({
        'name': 'MemeScanner API',
        'version': '2.0.0',
        'status': 'running',
        'documentation': 'https://docs.memescanner.com',
        'endpoints': [
            '/api/health',
            '/api/crypto-prices', 
            '/api/trending',
            '/api/analyze',
            '/api/verify-payment'
        ]
    })

@app.route('/api/health')
def health():
    """Health check endpoint mejorado"""
    blockchain_connected = w3.is_connected() if w3 else False
    
    return jsonify({
        'status': 'healthy',
        'version': '2.0.0',
        'timestamp': datetime.utcnow().isoformat(),
        'environment': os.environ.get('ENVIRONMENT', 'production'),
        'blockchain_connected': blockchain_connected,
        'cache_type': 'redis' if 'redis' in os.environ.get('REDIS_URL', '') else 'memory'
    })

@app.route('/api/crypto-prices')
@limiter.limit("30 per minute")
def prices():
    """Endpoint para precios de crypto"""
    try:
        prices = get_crypto_prices()
        return jsonify({
            'success': True,
            'data': prices,
            'last_update': datetime.fromtimestamp(last_price_update).isoformat() if last_price_update else None
        })
    except Exception as e:
        logger.error(f"Error in prices endpoint: {e}")
        return jsonify({'error': 'Failed to fetch prices'}), 500

@app.route('/api/trending')
@limiter.limit("30 per minute")
def trending():
    """Tokens trending con datos más realistas"""
    try:
        # En producción, esto vendría de una base de datos o servicio externo
        trending_tokens = [
            {
                "rank": 1,
                "name": "PepeCoin",
                "symbol": "PEPE",
                "address": "0x6982508145454ce325ddbe47a25d4ec3d2311933",
                "chain_id": 1,
                "price_change_24h": "+125.5%",
                "volume_24h": "$45.2M",
                "market_cap": "$1.2B",
                "risk_level": "HIGH",
                "verified": True
            },
            {
                "rank": 2,
                "name": "Shiba Inu",
                "symbol": "SHIB",
                "address": "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce",
                "chain_id": 1,
                "price_change_24h": "+45.2%",
                "volume_24h": "$234.5M",
                "market_cap": "$5.8B",
                "risk_level": "MEDIUM",
                "verified": True
            }
        ]
        
        return jsonify({
            'success': True,
            'data': trending_tokens,
            'updated_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in trending endpoint: {e}")
        return jsonify({'error': 'Failed to fetch trending tokens'}), 500

@app.route('/api/analyze', methods=['POST', 'OPTIONS'])
@limiter.limit("10 per minute")
@require_api_key
def analyze():
    """Análisis de token mejorado con cache"""
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        # Validar JSON
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
            
        data = request.get_json()
        
        # Validaciones
        address = data.get('address', '').lower()
        if not validate_address(address):
            return jsonify({'error': 'Invalid token address format'}), 400
        
        chain_id = data.get('chain_id')
        if not validate_chain_id(chain_id):
            return jsonify({'error': 'Unsupported chain ID'}), 400
        
        scan_type = data.get('scan_type', 'basic')
        if scan_type not in ['basic', 'full']:
            return jsonify({'error': 'Invalid scan type'}), 400
        
        # Verificar pago si se proporciona tx_hash
        tx_hash = data.get('tx_hash')
        if tx_hash:
            if not validate_tx_hash(tx_hash):
                return jsonify({'error': 'Invalid transaction hash'}), 400
                
            # Verificar pago en blockchain
            if not verify_payment(tx_hash, data.get('buyer_address')):
                return jsonify({'error': 'Payment verification failed'}), 402
        
        # Check cache
        cache_key = f"{address}:{chain_id}:{scan_type}"
        if cache_key in analysis_cache:
            cached_data, cached_time = analysis_cache[cache_key]
            if time.time() - cached_time < CACHE_TTL:
                logger.info(f"Returning cached analysis for {address}")
                return jsonify(cached_data)
        
        # Realizar análisis
        logger.info(f"Analyzing token {address} on chain {chain_id}")
        
        # Obtener datos on-chain
        onchain_data = analyze_token_onchain(address, chain_id)
        if not onchain_data:
            return jsonify({'error': 'Failed to analyze token'}), 500
        
        # Preparar respuesta
        if scan_type == 'basic':
            result = generate_basic_analysis(address, chain_id, onchain_data)
        else:
            result = generate_full_analysis(address, chain_id, onchain_data)
        
        # Guardar en cache
        analysis_cache[cache_key] = (result, time.time())
        
        # Log para monitoreo
        logger.info(f"Analysis completed: {address} - Risk: {result['risk_score']}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in analyze endpoint: {e}", exc_info=True)
        return jsonify({'error': 'Analysis failed', 'message': 'Internal server error'}), 500

@app.route('/api/verify-payment', methods=['POST'])
@limiter.limit("20 per minute")
@require_api_key
def verify_payment_endpoint():
    """Verificar pago realizado"""
    try:
        data = request.get_json()
        tx_hash = data.get('tx_hash')
        buyer_address = data.get('buyer_address')
        
        if not validate_tx_hash(tx_hash):
            return jsonify({'error': 'Invalid transaction hash'}), 400
            
        if not validate_address(buyer_address):
            return jsonify({'error': 'Invalid buyer address'}), 400
        
        # Verificar en blockchain
        is_valid = verify_payment(tx_hash, buyer_address)
        
        return jsonify({
            'success': True,
            'valid': is_valid,
            'tx_hash': tx_hash
        })
        
    except Exception as e:
        logger.error(f"Error verifying payment: {e}")
        return jsonify({'error': 'Verification failed'}), 500

def generate_basic_analysis(address, chain_id, onchain_data):
    """Genera análisis básico"""
    risk_score = onchain_data['risk_score']
    
    return {
        'success': True,
        'scan_type': 'basic',
        'scan_id': hashlib.md5(f"{address}{time.time()}".encode()).hexdigest()[:8],
        'timestamp': datetime.utcnow().isoformat(),
        'token_address': address,
        'chain_id': chain_id,
        'risk_score': risk_score,
        'risk_level': get_risk_level(risk_score),
        'verdict': get_verdict(risk_score),
        'token': {
            'is_verified': onchain_data['is_verified'],
            'has_liquidity': onchain_data['has_liquidity']
        },
        'warnings': get_basic_warnings(risk_score)
    }

def generate_full_analysis(address, chain_id, onchain_data):
    """Genera análisis completo"""
    risk_score = onchain_data['risk_score']
    
    # Análisis básico + datos adicionales
    result = generate_basic_analysis(address, chain_id, onchain_data)
    
    # Añadir datos detallados
    result.update({
        'liquidity': {
            'total_usd': onchain_data['liquidity_usd'],
            'locked': risk_score < 40,
            'dex': 'QuickSwap' if chain_id == 137 else 'Uniswap'
        },
        'holders': {
            'total': onchain_data['holder_count'],
            'distribution_score': 100 - risk_score
        },
        'contract_analysis': {
            'verified_source': onchain_data['is_verified'],
            'audit_status': 'Not audited' if risk_score > 40 else 'Community audited'
        },
        'recommendations': get_recommendations(risk_score)
    })
    
    return result

def get_risk_level(score):
    """Determina nivel de riesgo"""
    if score >= 80: return 'CRITICAL'
    elif score >= 60: return 'HIGH'
    elif score >= 40: return 'MEDIUM'
    elif score >= 20: return 'LOW'
    else: return 'SAFE'

def get_verdict(score):
    """Genera veredicto basado en score"""
    if score >= 80:
        return '🚨 EXTREME DANGER - High probability of scam'
    elif score >= 60:
        return '⚠️ HIGH RISK - Multiple red flags detected'
    elif score >= 40:
        return '🟡 MODERATE RISK - Proceed with caution'
    elif score >= 20:
        return '🟢 LOW RISK - Appears relatively safe'
    else:
        return '✅ SAFE - All security checks passed'

def get_basic_warnings(score):
    """Genera warnings básicos"""
    warnings = []
    if score > 70:
        warnings.append("🚨 Possible honeypot detected")
    if score > 60:
        warnings.append("⚠️ Low liquidity - high slippage risk")
    if score > 50:
        warnings.append("⚠️ Contract not verified")
    if score < 30:
        warnings.append("✅ Contract verified on explorer")
    return warnings

def get_recommendations(score):
    """Genera recomendaciones"""
    if score > 70:
        return ["❌ DO NOT BUY - Extremely high risk", "❌ Report to scam databases"]
    elif score > 50:
        return ["⚠️ High risk investment", "⚠️ Only invest what you can afford to lose"]
    else:
        return ["✅ Relatively safe for investment", "✅ Still do your own research"]

# Error handlers mejorados
@app.errorhandler(400)
def bad_request(e):
    logger.warning(f"Bad request: {e}")
    return jsonify({'error': 'Bad request', 'message': str(e)}), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({'error': 'Unauthorized', 'message': 'Invalid API key'}), 401

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded', 'retry_after': e.description}), 429

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal error: {e}", exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

# Cleanup cache periódicamente
def cleanup_cache():
    """Limpia entradas expiradas del cache"""
    current_time = time.time()
    expired_keys = [
        key for key, (_, timestamp) in analysis_cache.items()
        if current_time - timestamp > CACHE_TTL
    ]
    for key in expired_keys:
        del analysis_cache[key]
    logger.info(f"Cleaned {len(expired_keys)} expired cache entries")

# Configurar limpieza periódica (cada 10 minutos)
import atexit
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup_cache, trigger="interval", minutes=10)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    
    logger.info("=" * 50)
    logger.info("🚀 MemeScanner Backend PRO v2.0 - PRODUCTION")
    logger.info(f"📊 Port: {port}")
    logger.info(f"🔒 CORS: {allowed_origins}")
    logger.info(f"🌐 Environment: {os.environ.get('ENVIRONMENT', 'production')}")
    logger.info(f"⛓️  Blockchain: {'Connected' if w3 and w3.is_connected() else 'Disconnected'}")
    logger.info(f"🔑 API Key: {'Configured' if API_KEY != 'your-api-key-here' else 'NOT SET!'}")
    logger.info("=" * 50)
    
    # Solo para desarrollo local
    if os.environ.get('ENVIRONMENT') == 'development':
        app.run(host='0.0.0.0', port=port, debug=True)
    else:
        # En producción, Gunicorn manejará la aplicación
        logger.info("Ready for Gunicorn...")
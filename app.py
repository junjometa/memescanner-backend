"""
MemeScanner API - Backend Principal
Sistema completo listo para producción en Render
"""
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from web3 import Web3
from datetime import datetime
import time
import logging
from scanner_core import TokenScanner
from payment_handler import PaymentHandler
from report_generator import ReportGenerator

# Configuración de Flask
app = Flask(__name__)
CORS(app, origins=["*"])  # Configurar según tu dominio

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "100 per hour"],
    storage_uri="memory://"
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ===================== CONFIGURACIÓN =====================

# Obtener variables de entorno o usar valores por defecto
CONTRACT_ADDRESS = os.environ.get('CONTRACT_ADDRESS', '0x0000000000000000000000000000000000000000')
POLYGON_RPC = os.environ.get('POLYGON_RPC', 'https://polygon-rpc.com/')

# RPC Endpoints públicos (funcionan sin API key)
RPC_ENDPOINTS = {
    'ethereum': os.environ.get('ETH_RPC', 'https://eth.llamarpc.com'),
    'bsc': os.environ.get('BSC_RPC', 'https://bsc-dataseed1.binance.org'),
    'polygon': POLYGON_RPC,
    'arbitrum': os.environ.get('ARB_RPC', 'https://arb1.arbitrum.io/rpc'),
    'optimism': os.environ.get('OP_RPC', 'https://mainnet.optimism.io'),
    'base': os.environ.get('BASE_RPC', 'https://mainnet.base.org')
}

# Precios de escaneo
SCAN_PRICES = {
    'normal': 1.00,
    'pro': 2.50
}

# ===================== INICIALIZACIÓN =====================
# ... resto del código continúa igual

# ===================== INICIALIZACIÓN =====================

# Inicializar componentes
try:
    scanner = TokenScanner(RPC_ENDPOINTS)
    payment_handler = PaymentHandler(CONTRACT_ADDRESS, POLYGON_RPC)
    report_generator = ReportGenerator()
    logger.info("All components initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize components: {e}")
    scanner = None
    payment_handler = None
    report_generator = None

# ===================== RUTAS API =====================

@app.route('/', methods=['GET'])
def home():
    """Endpoint raíz"""
    return jsonify({
        'service': 'MemeScanner API',
        'version': '1.0.0',
        'status': 'operational',
        'endpoints': {
            '/api/health': 'Service health check',
            '/api/analyze': 'Token analysis (requires payment)',
            '/api/verify-payment': 'Payment verification',
            '/api/supported-chains': 'List of supported blockchains',
            '/api/scan-info': 'Scan types and features'
        }
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check para Render"""
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'components': {
            'scanner': scanner is not None,
            'payment_handler': payment_handler is not None,
            'report_generator': report_generator is not None
        },
        'contract': CONTRACT_ADDRESS,
        'chains_available': list(RPC_ENDPOINTS.keys())
    }
    
    # Verificar que todos los componentes estén funcionando
    all_healthy = all(health_status['components'].values())
    
    return jsonify(health_status), 200 if all_healthy else 503

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("50 per hour")
def analyze_token():
    """Endpoint principal de análisis"""
    try:
        # Validar request
        if not request.json:
            return jsonify({
                'success': False,
                'error': 'Request body required'
            }), 400
        
        data = request.json
        token_address = data.get('token_address', '').strip()
        chain = data.get('chain', 'ethereum').lower()
        payment_id = data.get('payment_id')
        
        # Validaciones
        if not token_address:
            return jsonify({
                'success': False,
                'error': 'token_address is required'
            }), 400
        
        if not payment_id:
            return jsonify({
                'success': False,
                'error': 'payment_id is required. Please complete payment first.'
            }), 402
        
        if chain not in RPC_ENDPOINTS:
            return jsonify({
                'success': False,
                'error': f'Chain {chain} not supported',
                'supported_chains': list(RPC_ENDPOINTS.keys())
            }), 400
        
        # Verificar pago
        logger.info(f"Verifying payment {payment_id}")
        payment_info = payment_handler.verify_payment(payment_id)
        
        if not payment_info['valid']:
            return jsonify({
                'success': False,
                'error': payment_info.get('error', 'Invalid payment'),
                'payment_status': payment_info
            }), 402
        
        # Verificar que el pago sea reciente (1 hora)
        if payment_info.get('age_minutes', 999) > 60:
            return jsonify({
                'success': False,
                'error': 'Payment expired. Payments are valid for 1 hour.',
                'payment_age_minutes': payment_info.get('age_minutes')
            }), 402
        
        # Determinar tipo de escaneo
        is_pro = payment_info.get('is_pro', False)
        scan_type = 'PRO' if is_pro else 'BASIC'
        
        logger.info(f"Starting {scan_type} scan for {token_address} on {chain}")
        
        # Realizar escaneo
        scan_result = scanner.scan_token(token_address, chain, is_pro)
        
        if not scan_result['success']:
            return jsonify({
                'success': False,
                'error': scan_result.get('error', 'Scan failed'),
                'details': scan_result
            }), 400
        
        # Generar reporte
        report = report_generator.generate_report(
            scan_result['data'],
            is_pro,
            payment_info
        )
        
        # Preparar respuesta
        response = {
            'success': True,
            'scan_id': f"{chain}_{token_address}_{int(time.time())}",
            'payment_id': payment_id,
            'scan_type': scan_type,
            'data': report
        }
        
        logger.info(f"Scan completed successfully for {token_address}")
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'message': str(e) if app.debug else 'An error occurred'
        }), 500

@app.route('/api/verify-payment', methods=['POST'])
@limiter.limit("30 per minute")
def verify_payment():
    """Verificar un pago"""
    try:
        data = request.json or {}
        payment_id = data.get('payment_id')
        
        if not payment_id:
            return jsonify({
                'success': False,
                'error': 'payment_id is required'
            }), 400
        
        # Verificar pago
        payment_info = payment_handler.verify_payment(payment_id)
        
        return jsonify({
            'success': payment_info['valid'],
            'payment': payment_info
        })
        
    except Exception as e:
        logger.error(f"Payment verification error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Verification failed'
        }), 500

@app.route('/api/supported-chains', methods=['GET'])
def get_supported_chains():
    """Obtener chains soportadas"""
    chains = [
        {
            'id': 'ethereum',
            'name': 'Ethereum',
            'chainId': 1,
            'currency': 'ETH',
            'explorer': 'https://etherscan.io'
        },
        {
            'id': 'bsc',
            'name': 'BNB Smart Chain',
            'chainId': 56,
            'currency': 'BNB',
            'explorer': 'https://bscscan.com'
        },
        {
            'id': 'polygon',
            'name': 'Polygon',
            'chainId': 137,
            'currency': 'MATIC',
            'explorer': 'https://polygonscan.com'
        },
        {
            'id': 'arbitrum',
            'name': 'Arbitrum One',
            'chainId': 42161,
            'currency': 'ETH',
            'explorer': 'https://arbiscan.io'
        },
        {
            'id': 'optimism',
            'name': 'Optimism',
            'chainId': 10,
            'currency': 'ETH',
            'explorer': 'https://optimistic.etherscan.io'
        },
        {
            'id': 'base',
            'name': 'Base',
            'chainId': 8453,
            'currency': 'ETH',
            'explorer': 'https://basescan.org'
        }
    ]
    
    return jsonify({
        'success': True,
        'chains': chains,
        'payment_chain': {
            'name': 'Polygon',
            'chainId': 137,
            'contract': CONTRACT_ADDRESS
        }
    })

@app.route('/api/scan-info', methods=['GET'])
def get_scan_info():
    """Información sobre tipos de escaneo"""
    return jsonify({
        'success': True,
        'payment_contract': CONTRACT_ADDRESS,
        'payment_chain': 'Polygon',
        'scan_types': {
            'basic': {
                'price_usd': SCAN_PRICES['normal'],
                'name': 'Basic Scan',
                'description': 'Essential security analysis',
                'features': [
                    '✓ Contract verification',
                    '✓ Bytecode analysis', 
                    '✓ Function detection',
                    '✓ Basic honeypot check',
                    '✓ Ownership analysis',
                    '✓ Risk score calculation',
                    '✓ Key warnings'
                ],
                'delivery': 'Instant'
            },
            'pro': {
                'price_usd': SCAN_PRICES['pro'],
                'name': 'Pro Scan',
                'description': 'Complete deep analysis',
                'features': [
                    '✓ Everything in Basic',
                    '✓ Advanced pattern detection',
                    '✓ Code complexity analysis',
                    '✓ Known scam comparison',
                    '✓ Gas optimization check',
                    '✓ Obfuscation detection',
                    '✓ Vulnerability scanning',
                    '✓ Detailed recommendations',
                    '✓ Professional report'
                ],
                'delivery': 'Instant'
            }
        },
        'accepted_tokens': {
            'USDC': '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174',
            'USDT': '0xc2132D05D31c914a87C6611C10748AEb04B58e8F',
            'DAI': '0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063'
        }
    })

# Manejo de errores
@app.errorhandler(404)
def not_found(e):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'message': 'Check API documentation'
    }), 404

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded',
        'message': str(e.description)
    }), 429

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {str(e)}", exc_info=True)
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'Please try again later'
    }), 500

# Inicialización
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting MemeScanner API on port {port}")
    logger.info(f"Contract address: {CONTRACT_ADDRESS}")
    logger.info(f"Debug mode: {debug}")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )
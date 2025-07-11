"""
Payment Handler - Verificación de pagos en blockchain
"""
from web3 import Web3
from datetime import datetime
import logging
import time

logger = logging.getLogger(__name__)

class PaymentHandler:
    """Maneja la verificación de pagos del contrato inteligente"""
    
    # ABI del contrato (solo funciones necesarias)
    CONTRACT_ABI = [
        {
            "inputs": [{"name": "paymentId", "type": "uint256"}],
            "name": "getPaymentInfo",
            "outputs": [
                {"name": "payer", "type": "address"},
                {"name": "isPro", "type": "bool"},
                {"name": "token", "type": "address"},
                {"name": "amount", "type": "uint256"},
                {"name": "timestamp", "type": "uint256"}
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "totalPayments",
            "outputs": [{"name": "", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]
    
    # Mapeo de direcciones de tokens a símbolos
    TOKEN_SYMBOLS = {
        '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174': 'USDC',
        '0xc2132D05D31c914a87C6611C10748AEb04B58e8F': 'USDT',
        '0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063': 'DAI'
    }
    
    def __init__(self, contract_address: str, rpc_url: str):
        """
        Inicializar el manejador de pagos
        
        Args:
            contract_address: Dirección del contrato MemeScanner
            rpc_url: URL del RPC de Polygon
        """
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        # Verificar conexión
        if not self.w3.is_connected():
            logger.error("Failed to connect to Polygon RPC")
            raise ConnectionError("Cannot connect to blockchain")
        
        logger.info(f"Connected to Polygon. Contract: {self.contract_address}")
        
        # Inicializar contrato
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.CONTRACT_ABI
        )
    
    def verify_payment(self, payment_id: int) -> dict:
        """
        Verificar un pago en el blockchain
        
        Args:
            payment_id: ID del pago a verificar
            
        Returns:
            dict: Información del pago y estado de validación
        """
        try:
            # Convertir payment_id a int si es string
            if isinstance(payment_id, str):
                payment_id = int(payment_id)
            
            # Verificar que el payment_id sea válido
            if payment_id <= 0:
                return {
                    'valid': False,
                    'error': 'Invalid payment ID',
                    'payment_id': payment_id
                }
            
            # Obtener total de pagos para validar el ID
            try:
                total_payments = self.contract.functions.totalPayments().call()
                
                if payment_id > total_payments:
                    return {
                        'valid': False,
                        'error': 'Payment ID does not exist',
                        'payment_id': payment_id,
                        'total_payments': total_payments
                    }
            except Exception as e:
                logger.warning(f"Could not verify total payments: {e}")
            
            # Obtener información del pago
            payment_info = self.contract.functions.getPaymentInfo(payment_id).call()
            
            # Desestructurar la respuesta
            payer_address = payment_info[0]
            is_pro = payment_info[1]
            token_address = payment_info[2]
            amount = payment_info[3]
            timestamp = payment_info[4]
            
            # Verificar que el pago existe (timestamp > 0)
            if timestamp == 0:
                return {
                    'valid': False,
                    'error': 'Payment not found',
                    'payment_id': payment_id
                }
            
            # Calcular edad del pago
            current_time = int(time.time())
            age_seconds = current_time - timestamp
            age_minutes = age_seconds // 60
            
            # Obtener símbolo del token
            token_symbol = self.TOKEN_SYMBOLS.get(
                token_address.lower(),
                'Unknown'
            )
            
            # Formatear cantidad (asumiendo 6 decimales para stablecoins)
            decimals = 6 if token_symbol in ['USDC', 'USDT'] else 18
            formatted_amount = amount / (10 ** decimals)
            
            # Preparar respuesta
            return {
                'valid': True,
                'payment_id': payment_id,
                'payer': payer_address,
                'is_pro': is_pro,
                'scan_type': 'PRO' if is_pro else 'BASIC',
                'token_address': token_address,
                'token_symbol': token_symbol,
                'amount': amount,
                'formatted_amount': formatted_amount,
                'timestamp': timestamp,
                'payment_date': datetime.fromtimestamp(timestamp).isoformat(),
                'age_seconds': age_seconds,
                'age_minutes': age_minutes,
                'expired': age_minutes > 60,  # Pagos válidos por 1 hora
                'status': 'valid' if age_minutes <= 60 else 'expired'
            }
            
        except ValueError as e:
            logger.error(f"Invalid payment ID format: {e}")
            return {
                'valid': False,
                'error': 'Invalid payment ID format',
                'details': str(e)
            }
            
        except Exception as e:
            logger.error(f"Error verifying payment {payment_id}: {e}")
            return {
                'valid': False,
                'error': 'Payment verification failed',
                'details': str(e),
                'payment_id': payment_id
            }
    
    def get_payment_status_message(self, payment_info: dict) -> str:
        """
        Generar mensaje de estado del pago
        
        Args:
            payment_info: Información del pago
            
        Returns:
            str: Mensaje descriptivo del estado
        """
        if not payment_info.get('valid'):
            return payment_info.get('error', 'Invalid payment')
        
        if payment_info.get('expired'):
            return f"Payment expired {payment_info['age_minutes']} minutes ago"
        
        scan_type = payment_info.get('scan_type', 'UNKNOWN')
        token = payment_info.get('token_symbol', 'Unknown')
        amount = payment_info.get('formatted_amount', 0)
        
        return f"{scan_type} scan paid with {amount} {token}"
    
    def is_payment_valid_for_scan(self, payment_info: dict) -> bool:
        """
        Verificar si un pago es válido para realizar un escaneo
        
        Args:
            payment_info: Información del pago
            
        Returns:
            bool: True si el pago es válido para escanear
        """
        return (
            payment_info.get('valid', False) and
            not payment_info.get('expired', True) and
            payment_info.get('age_minutes', 999) <= 60
        )
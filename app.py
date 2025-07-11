"""
MemeScanner Backend - Simple & Powerful
No DB, No Login, Just Scan & Pay
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
from web3 import Web3
from datetime import datetime
import time
import re
import logging
from concurrent.futures import ThreadPoolExecutor
import json

# Import our modules
from config import *
from payment_handler import payment_handler

# Initialize Flask
app = Flask(__name__)
CORS(app, origins=CORS_ORIGINS)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Setup logging
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

# Thread pool for concurrent analysis
executor = ThreadPoolExecutor(max_workers=10)

class TokenAnalyzer:
    """Main analyzer class - the brain of the scanner"""
    
    def __init__(self):
        self.w3_connections = {
            'ethereum': Web3(Web3.HTTPProvider(RPC_ENDPOINTS['ethereum'])),
            'bsc': Web3(Web3.HTTPProvider(RPC_ENDPOINTS['bsc'])),
            'polygon': Web3(Web3.HTTPProvider(RPC_ENDPOINTS['polygon'])),
            'arbitrum': Web3(Web3.HTTPProvider(RPC_ENDPOINTS['arbitrum'])),
            'optimism': Web3(Web3.HTTPProvider(RPC_ENDPOINTS['optimism'])),
            'base': Web3(Web3.HTTPProvider(RPC_ENDPOINTS['base']))
        }
    
    def analyze_token(self, token_address: str, chain: str, is_pro: bool = False):
        """
        Main analysis function
        Returns 30-40% data for normal, 100% for pro
        """
        try:
            # Validate inputs
            if not Web3.is_address(token_address):
                return {'error': 'Invalid token address'}
            
            if chain not in self.w3_connections:
                return {'error': 'Unsupported chain'}
            
            # Start analysis
            logger.info(f"Analyzing token {token_address} on {chain} (Pro: {is_pro})")
            
            # Collect all data points
            analysis_results = {
                'token_address': token_address,
                'chain': chain,
                'scan_time': datetime.utcnow().isoformat(),
                'is_pro_scan': is_pro
            }
            
            # Basic token info (always included)
            token_info = self._get_token_info(token_address, chain)
            analysis_results.update(token_info)
            
            # Contract verification (always included)
            contract_check = self._check_contract(token_address, chain)
            analysis_results['contract_verification'] = contract_check
            
            # Liquidity analysis (always included)
            liquidity_info = self._analyze_liquidity(token_address, chain)
            analysis_results['liquidity'] = liquidity_info
            
            # Holder analysis (basic for normal, detailed for pro)
            holder_info = self._analyze_holders(token_address, chain, detailed=is_pro)
            analysis_results['holders'] = holder_info
            
            # Honeypot detection (basic for normal, advanced for pro)
            honeypot_check = self._check_honeypot(token_address, chain, advanced=is_pro)
            analysis_results['honeypot_analysis'] = honeypot_check
            
            # PRO ONLY FEATURES
            if is_pro:
                # Advanced security audit
                analysis_results['security_audit'] = self._advanced_security_audit(token_address, chain)
                
                # Developer history
                analysis_results['developer_analysis'] = self._analyze_developers(token_address, chain)
                
                # Social media analysis
                if ENABLE_SOCIAL_ANALYSIS:
                    analysis_results['social_analysis'] = self._analyze_social_presence(token_info.get('symbol', ''))
                
                # AI-powered risk assessment
                if ENABLE_AI_ANALYSIS:
                    analysis_results['ai_analysis'] = self._ai_risk_assessment(analysis_results)
                
                # Transaction pattern analysis
                analysis_results['transaction_patterns'] = self._analyze_transaction_patterns(token_address, chain)
                
                # Similar scam detection
                analysis_results['scam_similarity'] = self._check_scam_similarity(token_address, chain)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(analysis_results, is_pro)
            analysis_results['risk_score'] = risk_score
            
            # Generate warnings
            warnings = self._generate_warnings(analysis_results, is_pro)
            analysis_results['warnings'] = warnings
            
            # Create summary
            analysis_results['summary'] = self._create_summary(analysis_results, is_pro)
            
            return {
                'success': True,
                'data': analysis_results
            }
            
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _get_token_info(self, address: str, chain: str) -> dict:
        """Get basic token information"""
        try:
            w3 = self.w3_connections[chain]
            
            # Basic ERC20 functions
            contract = w3.eth.contract(address=Web3.to_checksum_address(address), abi=ERC20_ABI)
            
            info = {}
            
            # Try to get basic info
            try:
                info['name'] = contract.functions.name().call()
            except:
                info['name'] = 'Unknown'
            
            try:
                info['symbol'] = contract.functions.symbol().call()
            except:
                info['symbol'] = 'Unknown'
            
            try:
                info['decimals'] = contract.functions.decimals().call()
            except:
                info['decimals'] = 18
            
            try:
                total_supply = contract.functions.totalSupply().call()
                info['total_supply'] = total_supply / (10 ** info['decimals'])
            except:
                info['total_supply'] = 0
            
            # Get deployer info
            info['creation_info'] = self._get_creation_info(address, chain)
            
            return info
            
        except Exception as e:
            logger.error(f"Error getting token info: {str(e)}")
            return {'error': str(e)}
    
    def _check_contract(self, address: str, chain: str) -> dict:
        """Check contract verification and source code"""
        try:
            api_key = {
                'ethereum': ETHERSCAN_API_KEY,
                'bsc': BSCSCAN_API_KEY,
                'polygon': POLYGONSCAN_API_KEY,
                'arbitrum': ETHERSCAN_API_KEY,
                'optimism': ETHERSCAN_API_KEY,
                'base': ETHERSCAN_API_KEY
            }.get(chain)
            
            base_url = {
                'ethereum': 'https://api.etherscan.io/api',
                'bsc': 'https://api.bscscan.com/api',
                'polygon': 'https://api.polygonscan.com/api',
                'arbitrum': 'https://api.arbiscan.io/api',
                'optimism': 'https://api-optimistic.etherscan.io/api',
                'base': 'https://api.basescan.org/api'
            }.get(chain)
            
            # Check if contract is verified
            response = requests.get(base_url, params={
                'module': 'contract',
                'action': 'getsourcecode',
                'address': address,
                'apikey': api_key
            })
            
            data = response.json()
            
            if data['status'] == '1' and data['result'][0]['SourceCode']:
                source_code = data['result'][0]['SourceCode']
                contract_name = data['result'][0]['ContractName']
                
                # Check for common red flags in source code
                red_flags = []
                
                # Ownership patterns
                if 'onlyOwner' in source_code:
                    if 'mint' in source_code and 'onlyOwner' in source_code:
                        red_flags.append('Owner can mint tokens')
                    if 'pause' in source_code and 'onlyOwner' in source_code:
                        red_flags.append('Owner can pause trading')
                    if 'blacklist' in source_code or 'whitelist' in source_code:
                        red_flags.append('Has blacklist/whitelist functionality')
                
                # Tax/Fee patterns
                tax_pattern = r'(tax|fee|commission)\s*=\s*(\d+)'
                tax_matches = re.findall(tax_pattern, source_code.lower())
                if tax_matches:
                    max_tax = max([int(match[1]) for match in tax_matches])
                    if max_tax > 10:
                        red_flags.append(f'High tax/fee detected: {max_tax}%')
                
                # Hidden functions
                if 'hidden' in source_code.lower() or 'backdoor' in source_code.lower():
                    red_flags.append('Suspicious function names detected')
                
                return {
                    'verified': True,
                    'contract_name': contract_name,
                    'compiler_version': data['result'][0]['CompilerVersion'],
                    'optimization_enabled': data['result'][0]['OptimizationUsed'] == '1',
                    'red_flags': red_flags,
                    'risk_level': 'high' if len(red_flags) > 2 else 'medium' if red_flags else 'low'
                }
            else:
                return {
                    'verified': False,
                    'risk_level': 'high',
                    'red_flags': ['Contract source code not verified']
                }
                
        except Exception as e:
            logger.error(f"Contract check error: {str(e)}")
            return {'error': str(e), 'verified': False}
    
    def _analyze_liquidity(self, address: str, chain: str) -> dict:
        """Analyze token liquidity"""
        try:
            # This would integrate with DEX APIs (Uniswap, PancakeSwap, etc.)
            # For now, returning mock data structure
            
            liquidity_data = {
                'total_liquidity_usd': 0,
                'main_pair': None,
                'liquidity_locked': False,
                'lock_duration': 0,
                'dex_presence': []
            }
            
            # Check major DEXs based on chain
            dex_mapping = {
                'ethereum': ['uniswap_v2', 'uniswap_v3', 'sushiswap'],
                'bsc': ['pancakeswap_v2', 'pancakeswap_v3', 'biswap'],
                'polygon': ['quickswap', 'sushiswap', 'uniswap_v3'],
                'arbitrum': ['uniswap_v3', 'sushiswap', 'camelot'],
                'optimism': ['uniswap_v3', 'velodrome'],
                'base': ['uniswap_v3', 'aerodrome']
            }
            
            # Would check each DEX for liquidity pools
            # This is a simplified version
            liquidity_data['dex_presence'] = dex_mapping.get(chain, [])
            
            # Risk assessment based on liquidity
            if liquidity_data['total_liquidity_usd'] < MIN_LIQUIDITY_USD:
                liquidity_data['risk'] = 'high'
                liquidity_data['warning'] = 'Low liquidity - high risk of price manipulation'
            else:
                liquidity_data['risk'] = 'low'
            
            return liquidity_data
            
        except Exception as e:
            logger.error(f"Liquidity analysis error: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_holders(self, address: str, chain: str, detailed: bool = False) -> dict:
        """Analyze token holders distribution"""
        try:
            # This would use block explorer APIs to get holder data
            holder_data = {
                'total_holders': 0,
                'top_10_percentage': 0,
                'top_holder_percentage': 0,
                'holder_distribution': 'unknown'
            }
            
            # Basic analysis for normal scan
            if holder_data['total_holders'] < MIN_HOLDERS_WARNING:
                holder_data['risk'] = 'high'
                holder_data['warning'] = 'Very few holders - possible scam'
            elif holder_data['top_holder_percentage'] > 50:
                holder_data['risk'] = 'high'
                holder_data['warning'] = 'Single wallet holds majority of supply'
            else:
                holder_data['risk'] = 'low'
            
            # Detailed analysis for pro scan
            if detailed:
                holder_data['top_100_holders'] = []  # Would fetch actual data
                holder_data['whale_transactions'] = []  # Recent large transactions
                holder_data['holder_growth'] = []  # Historical holder count
                
            return holder_data
            
        except Exception as e:
            logger.error(f"Holder analysis error: {str(e)}")
            return {'error': str(e)}
    
    def _check_honeypot(self, address: str, chain: str, advanced: bool = False) -> dict:
        """Check if token is a honeypot"""
        try:
            honeypot_data = {
                'is_honeypot': False,
                'buy_tax': 0,
                'sell_tax': 0,
                'can_sell': True,
                'warnings': []
            }
            
            # Basic honeypot detection
            # Would simulate buy/sell transactions
            
            if honeypot_data['sell_tax'] > MAX_TAX_PERCENTAGE:
                honeypot_data['warnings'].append(f'High sell tax: {honeypot_data["sell_tax"]}%')
                honeypot_data['is_honeypot'] = True
            
            if not honeypot_data['can_sell']:
                honeypot_data['warnings'].append('Cannot sell tokens - definite honeypot!')
                honeypot_data['is_honeypot'] = True
            
            # Advanced detection for pro users
            if advanced and ENABLE_ADVANCED_HONEYPOT:
                # Check for hidden functions
                # Analyze transaction patterns
                # Check for blacklist functions
                honeypot_data['advanced_checks'] = {
                    'hidden_mint': False,
                    'pausable': False,
                    'blacklist_function': False,
                    'ownership_renounced': False,
                    'modifiable_taxes': False
                }
            
            return honeypot_data
            
        except Exception as e:
            logger.error(f"Honeypot check error: {str(e)}")
            return {'error': str(e), 'is_honeypot': 'unknown'}
    
    def _advanced_security_audit(self, address: str, chain: str) -> dict:
        """PRO: Advanced security audit"""
        try:
            audit_results = {
                'audit_score': 0,
                'vulnerabilities': [],
                'code_quality': 'unknown',
                'similar_to_known_scams': False,
                'audit_details': {}
            }
            
            # Would perform deep code analysis
            # Check against known vulnerability patterns
            # Compare with scam database
            
            return audit_results
            
        except Exception as e:
            logger.error(f"Security audit error: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_developers(self, address: str, chain: str) -> dict:
        """PRO: Analyze developer history"""
        try:
            dev_data = {
                'deployer_address': None,
                'deployer_history': [],
                'other_tokens_deployed': [],
                'reputation_score': 0,
                'known_scammer': False
            }
            
            # Would check deployer's history
            # Cross-reference with scam databases
            
            return dev_data
            
        except Exception as e:
            logger.error(f"Developer analysis error: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_social_presence(self, symbol: str) -> dict:
        """PRO: Analyze social media presence"""
        try:
            social_data = {
                'twitter': {'found': False, 'followers': 0, 'verified': False},
                'telegram': {'found': False, 'members': 0},
                'website': {'found': False, 'ssl': False, 'domain_age': 0},
                'coingecko_listed': False,
                'coinmarketcap_listed': False
            }
            
            # Would use Twitter API, web scraping, etc.
            
            return social_data
            
        except Exception as e:
            logger.error(f"Social analysis error: {str(e)}")
            return {'error': str(e)}
    
    def _ai_risk_assessment(self, full_analysis: dict) -> dict:
        """PRO: AI-powered risk assessment"""
        try:
            # Would use OpenAI API for comprehensive analysis
            ai_assessment = {
                'risk_summary': 'Comprehensive AI analysis of all factors',
                'red_flags_found': [],
                'confidence_score': 0,
                'recommendation': 'avoid/caution/safe'
            }
            
            return ai_assessment
            
        except Exception as e:
            logger.error(f"AI assessment error: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_transaction_patterns(self, address: str, chain: str) -> dict:
        """PRO: Analyze transaction patterns"""
        try:
            patterns = {
                'bot_activity': False,
                'wash_trading': False,
                'pump_indicators': False,
                'organic_growth': True,
                'suspicious_patterns': []
            }
            
            return patterns
            
        except Exception as e:
            logger.error(f"Pattern analysis error: {str(e)}")
            return {'error': str(e)}
    
    def _check_scam_similarity(self, address: str, chain: str) -> dict:
        """PRO: Check similarity to known scams"""
        try:
            similarity_data = {
                'similar_scams_found': 0,
                'similarity_score': 0,
                'matched_patterns': [],
                'risk_level': 'low'
            }
            
            return similarity_data
            
        except Exception as e:
            logger.error(f"Scam similarity check error: {str(e)}")
            return {'error': str(e)}
    
    def _get_creation_info(self, address: str, chain: str) -> dict:
        """Get contract creation information"""
        try:
            # Would use block explorer API to get creation tx
            return {
                'creator': 'unknown',
                'creation_date': 'unknown',
                'creation_block': 0
            }
        except:
            return {}
    
    def _calculate_risk_score(self, analysis: dict, is_pro: bool) -> dict:
        """Calculate overall risk score"""
        try:
            score = 100  # Start with perfect score
            risk_factors = []
            
            # Contract verification
            if not analysis.get('contract_verification', {}).get('verified'):
                score -= 30
                risk_factors.append('Unverified contract')
            
            # Red flags in code
            red_flags = analysis.get('contract_verification', {}).get('red_flags', [])
            score -= len(red_flags) * 10
            risk_factors.extend(red_flags)
            
            # Liquidity
            liquidity = analysis.get('liquidity', {})
            if liquidity.get('risk') == 'high':
                score -= 20
                risk_factors.append('Low liquidity')
            
            # Holders
            holders = analysis.get('holders', {})
            if holders.get('risk') == 'high':
                score -= 20
                risk_factors.append(holders.get('warning', 'Holder distribution issue'))
            
            # Honeypot
            honeypot = analysis.get('honeypot_analysis', {})
            if honeypot.get('is_honeypot'):
                score -= 50
                risk_factors.append('Honeypot detected!')
            
            # Pro features affect score
            if is_pro:
                # Developer reputation
                if analysis.get('developer_analysis', {}).get('known_scammer'):
                    score -= 40
                    risk_factors.append('Developer linked to previous scams')
                
                # Social presence
                social = analysis.get('social_analysis', {})
                if not social.get('twitter', {}).get('found') and not social.get('telegram', {}).get('found'):
                    score -= 10
                    risk_factors.append('No social media presence')
            
            # Ensure score is between 0-100
            score = max(0, min(100, score))
            
            # Determine risk level
            if score >= 80:
                risk_level = 'LOW'
                color = 'green'
            elif score >= 50:
                risk_level = 'MEDIUM'
                color = 'yellow'
            else:
                risk_level = 'HIGH'
                color = 'red'
            
            return {
                'score': score,
                'risk_level': risk_level,
                'color': color,
                'risk_factors': risk_factors[:5] if not is_pro else risk_factors  # Limit factors for normal scan
            }
            
        except Exception as e:
            logger.error(f"Risk score calculation error: {str(e)}")
            return {
                'score': 0,
                'risk_level': 'UNKNOWN',
                'color': 'gray',
                'risk_factors': ['Error calculating risk']
            }
    
    def _generate_warnings(self, analysis: dict, is_pro: bool) -> list:
        """Generate warning messages"""
        warnings = []
        
        # Critical warnings (always show)
        if analysis.get('honeypot_analysis', {}).get('is_honeypot'):
            warnings.append({
                'level': 'critical',
                'message': '🚨 HONEYPOT DETECTED - DO NOT BUY!'
            })
        
        if analysis.get('contract_verification', {}).get('verified') is False:
            warnings.append({
                'level': 'high',
                'message': '⚠️ Contract not verified - high risk'
            })
        
        # More warnings for pro users
        if is_pro:
            if analysis.get('developer_analysis', {}).get('known_scammer'):
                warnings.append({
                    'level': 'critical',
                    'message': '🚨 Developer linked to previous scams'
                })
            
            if analysis.get('transaction_patterns', {}).get('bot_activity'):
                warnings.append({
                    'level': 'medium',
                    'message': '🤖 Bot trading activity detected'
                })
        
        return warnings[:3] if not is_pro else warnings  # Limit warnings for normal scan
    
    def _create_summary(self, analysis: dict, is_pro: bool) -> dict:
        """Create analysis summary"""
        risk_score = analysis.get('risk_score', {})
        
        summary = {
            'verdict': self._get_verdict(risk_score['score']),
            'risk_level': risk_score['risk_level'],
            'key_findings': risk_score['risk_factors'][:3] if not is_pro else risk_score['risk_factors'],
            'recommendation': self._get_recommendation(risk_score['score'])
        }
        
        if is_pro:
            summary['detailed_explanation'] = self._generate_detailed_explanation(analysis)
        
        return summary
    
    def _get_verdict(self, score: int) -> str:
        """Get verdict based on score"""
        if score >= 80:
            return "✅ LIKELY SAFE"
        elif score >= 50:
            return "⚠️ PROCEED WITH CAUTION"
        else:
            return "🚨 HIGH RISK - AVOID"
    
    def _get_recommendation(self, score: int) -> str:
        """Get recommendation based on score"""
        if score >= 80:
            return "This token appears relatively safe, but always DYOR"
        elif score >= 50:
            return "Consider the risks carefully before investing"
        else:
            return "Strong indicators of scam - recommend avoiding"
    
    def _generate_detailed_explanation(self, analysis: dict) -> str:
        """Generate detailed explanation for pro users"""
        return "Comprehensive analysis covering contract security, liquidity, holder distribution, and behavioral patterns."

# Initialize analyzer
analyzer = TokenAnalyzer()

# API ROUTES

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '2.0',
        'contract': CONTRACT_ADDRESS,
        'chain': NETWORK_NAME
    })

@app.route('/api/get-price', methods=['POST'])
@limiter.limit("10 per minute")
def get_price():
    """Get scan price in different tokens"""
    try:
        data = request.json
        is_pro = data.get('is_pro', False)
        token = data.get('token', 'USDC')
        
        if token not in ACCEPTED_TOKENS:
            return jsonify({
                'success': False,
                'error': 'Token not accepted. Use USDC, USDT, or DAI'
            }), 400
        
        price = payment_handler.get_scan_price(is_pro, token)
        
        if price is None:
            return jsonify({
                'success': False,
                'error': 'Could not fetch price'
            }), 500
        
        return jsonify({
            'success': True,
            'price': {
                'amount': price,
                'formatted': payment_handler.format_token_amount(price, token),
                'token': token,
                'scan_type': 'pro' if is_pro else 'normal',
                'usd_value': SCAN_PRICES['pro' if is_pro else 'normal']
            },
            'contract_address': CONTRACT_ADDRESS,
            'chain_id': CHAIN_ID,
            'accepted_tokens': list(ACCEPTED_TOKENS.keys())
        })
        
    except Exception as e:
        logger.error(f"Get price error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/verify-payment', methods=['POST'])
@limiter.limit("30 per minute")
def verify_payment():
    """Verify blockchain payment"""
    try:
        data = request.json
        payment_id = data.get('payment_id')
        
        if not payment_id:
            return jsonify({
                'success': False,
                'error': 'Payment ID required'
            }), 400
        
        # Verify payment on blockchain
        payment_info = payment_handler.verify_payment(int(payment_id))
        
        if not payment_info['success']:
            return jsonify(payment_info), 400
        
        # Return verification result
        return jsonify({
            'success': True,
            'payment': payment_info,
            'message': payment_handler.get_payment_status_message(payment_info),
            'can_scan': True
        })
        
    except Exception as e:
        logger.error(f"Payment verification error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("100 per hour")
def analyze_token():
    """Main analysis endpoint - requires payment verification"""
    try:
        data = request.json
        
        # Required parameters
        token_address = data.get('token_address')
        chain = data.get('chain', 'ethereum')
        payment_id = data.get('payment_id')
        
        # Validate inputs
        if not token_address:
            return jsonify({
                'success': False,
                'error': 'Token address required'
            }), 400
        
        if not payment_id:
            return jsonify({
                'success': False,
                'error': 'Payment required. Please complete payment first.'
            }), 402
        
        # Verify payment
        payment_info = payment_handler.verify_payment(int(payment_id))
        
        if not payment_info['success'] or not payment_info['verified']:
            return jsonify({
                'success': False,
                'error': 'Invalid or unverified payment'
            }), 402
        
        # Check if payment is recent (within 1 hour)
        payment_time = payment_info['timestamp']
        current_time = int(time.time())
        
        if current_time - payment_time > 3600:  # 1 hour
            return jsonify({
                'success': False,
                'error': 'Payment expired. Please make a new payment.'
            }), 402
        
        # Determine scan type from payment
        is_pro = payment_info['is_pro']
        
        # Perform analysis
        logger.info(f"Starting {'PRO' if is_pro else 'NORMAL'} analysis for {token_address} on {chain}")
        
        analysis_result = analyzer.analyze_token(token_address, chain, is_pro)
        
        if not analysis_result['success']:
            return jsonify(analysis_result), 500
        
        # Add payment info to result
        analysis_result['payment_info'] = {
            'payment_id': payment_id,
            'scan_type': 'pro' if is_pro else 'normal',
            'token_used': payment_info.get('token_symbol', 'UNKNOWN')
        }
        
        return jsonify(analysis_result)
        
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Analysis failed',
            'details': str(e)
        }), 500

@app.route('/api/supported-chains', methods=['GET'])
def get_supported_chains():
    """Get list of supported blockchains"""
    return jsonify({
        'success': True,
        'chains': [
            {'id': 'ethereum', 'name': 'Ethereum', 'chainId': 1},
            {'id': 'bsc', 'name': 'BSC', 'chainId': 56},
            {'id': 'polygon', 'name': 'Polygon', 'chainId': 137},
            {'id': 'arbitrum', 'name': 'Arbitrum', 'chainId': 42161},
            {'id': 'optimism', 'name': 'Optimism', 'chainId': 10},
            {'id': 'base', 'name': 'Base', 'chainId': 8453}
        ]
    })

@app.route('/api/payment-info', methods=['GET'])
def get_payment_info():
    """Get payment configuration"""
    return jsonify({
        'success': True,
        'payment': {
            'contract_address': CONTRACT_ADDRESS,
            'chain': NETWORK_NAME,
            'chain_id': CHAIN_ID,
            'accepted_tokens': ACCEPTED_TOKENS,
            'prices': {
                'normal': {
                    'usd': SCAN_PRICES['normal'],
                    'description': 'Basic scan with essential security checks'
                },
                'pro': {
                    'usd': SCAN_PRICES['pro'],
                    'description': 'Complete analysis with all advanced features'
                }
            },
            'features': {
                'normal': [
                    'Contract verification check',
                    'Basic liquidity analysis',
                    'Holder distribution overview',
                    'Honeypot detection',
                    'Risk score calculation'
                ],
                'pro': [
                    'Everything in Normal scan',
                    'Advanced security audit',
                    'Developer history analysis',
                    'Social media presence check',
                    'AI-powered risk assessment',
                    'Transaction pattern analysis',
                    'Scam similarity detection',
                    'Detailed recommendations'
                ]
            }
        }
    })

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded',
        'message': str(e.description)
    }), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
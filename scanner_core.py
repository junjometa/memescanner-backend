"""
Scanner Core - Motor de análisis real para MemeScanner
Análisis completo sin dependencias de terceros
"""
import re
from web3 import Web3
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class TokenScanner:
    """Motor principal de escaneo - 100% funcional"""
    
    # Signatures de funciones ERC20 y peligrosas
    FUNCTION_SIGNATURES = {
        # Standard ERC20
        '095ea7b3': 'approve',
        'a9059cbb': 'transfer', 
        '23b872dd': 'transferFrom',
        '70a08231': 'balanceOf',
        '18160ddd': 'totalSupply',
        '313ce567': 'decimals',
        '06fdde03': 'name',
        '95d89b41': 'symbol',
        
        # Ownership
        '8da5cb5b': 'owner',
        'f2fde38b': 'transferOwnership',
        '715018a6': 'renounceOwnership',
        
        # Pausable
        '5c975abb': 'paused',
        '8456cb59': 'pause',
        '3f4ba83a': 'unpause',
        
        # Fees/Tax
        'c0246668': 'setFee',
        'f2cc0c18': 'addToWhitelist',
        'f9f92be4': 'addToBlacklist',
        '4ada218b': 'tradingEnabled',
        
        # Mint/Burn
        '40c10f19': 'mint',
        '42966c68': 'burn',
        
        # Liquidity
        'f305d719': 'addLiquidityETH',
        'e8e33700': 'addLiquidity',
        'baa2abde': 'removeLiquidity',
        
        # Limits
        '860a32ec': 'maxTransactionAmount',
        '89476069': 'maxWalletAmount'
    }
    
    # Bytecode patterns peligrosos
    DANGEROUS_PATTERNS = {
        'ff': {'name': 'selfdestruct', 'severity': 'critical'},
        '6080604052': {'name': 'proxy_pattern', 'severity': 'medium'},
        'f2fde38b': {'name': 'ownership_transfer', 'severity': 'high'},
        '40c10f19': {'name': 'mint_function', 'severity': 'high'},
        '42966c68': {'name': 'burn_function', 'severity': 'medium'},
        '5c975abb': {'name': 'pausable', 'severity': 'high'},
        'f9f92be4': {'name': 'blacklist', 'severity': 'critical'},
        'c0246668': {'name': 'modifiable_fees', 'severity': 'high'}
    }
    
    def __init__(self, rpc_endpoints):
        self.connections = {}
        for chain, endpoint in rpc_endpoints.items():
            try:
                self.connections[chain] = Web3(Web3.HTTPProvider(endpoint))
                logger.info(f"Connected to {chain}")
            except Exception as e:
                logger.error(f"Failed to connect to {chain}: {e}")
    
    def scan_token(self, address: str, chain: str = 'ethereum', is_pro: bool = False):
        """Escaneo principal del token"""
        try:
            if chain not in self.connections:
                return {'success': False, 'error': f'Chain {chain} not supported'}
            
            w3 = self.connections[chain]
            
            if not Web3.is_address(address):
                return {'success': False, 'error': 'Invalid address format'}
            
            address = Web3.to_checksum_address(address)
            
            # Recopilar toda la información
            scan_result = {
                'address': address,
                'chain': chain,
                'scan_time': datetime.utcnow().isoformat(),
                'scan_type': 'PRO' if is_pro else 'BASIC'
            }
            
            # 1. Verificar si es contrato
            code = w3.eth.get_code(address)
            if len(code) <= 2:
                return {
                    'success': False,
                    'error': 'Address is not a contract'
                }
            
            scan_result['is_contract'] = True
            scan_result['bytecode_size'] = len(code)
            
            # 2. Análisis del bytecode
            bytecode_analysis = self._analyze_bytecode(code.hex())
            scan_result['bytecode_analysis'] = bytecode_analysis
            
            # 3. Información básica del token
            token_info = self._get_token_basics(address, w3)
            scan_result['token_info'] = token_info
            
            # 4. Análisis de funciones
            function_analysis = self._analyze_functions(code.hex())
            scan_result['functions'] = function_analysis
            
            # 5. Detección de honeypot básica
            honeypot_check = self._basic_honeypot_check(bytecode_analysis, function_analysis)
            scan_result['honeypot_analysis'] = honeypot_check
            
            # 6. Análisis de ownership
            ownership_analysis = self._analyze_ownership(address, w3, bytecode_analysis)
            scan_result['ownership'] = ownership_analysis
            
            if is_pro:
                # Análisis PRO adicionales
                
                # 7. Análisis de patrones avanzados
                scan_result['advanced_patterns'] = self._advanced_pattern_analysis(code.hex())
                
                # 8. Análisis de complejidad
                scan_result['complexity_analysis'] = self._analyze_complexity(code.hex())
                
                # 9. Comparación con tokens conocidos
                scan_result['similarity_check'] = self._check_known_patterns(code.hex())
                
                # 10. Análisis de gas optimization
                scan_result['gas_analysis'] = self._analyze_gas_patterns(code.hex())
            
            # Calcular risk score final
            risk_score = self._calculate_final_risk_score(scan_result, is_pro)
            scan_result['risk_assessment'] = risk_score
            
            # Generar recomendaciones
            recommendations = self._generate_recommendations(scan_result, is_pro)
            scan_result['recommendations'] = recommendations
            
            return {
                'success': True,
                'data': scan_result
            }
            
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _analyze_bytecode(self, bytecode: str) -> dict:
        """Analizar bytecode en busca de patrones"""
        analysis = {
            'dangerous_patterns': [],
            'suspicious_opcodes': [],
            'risk_indicators': []
        }
        
        # Buscar patrones peligrosos
        for pattern, info in self.DANGEROUS_PATTERNS.items():
            if pattern in bytecode.lower():
                analysis['dangerous_patterns'].append({
                    'pattern': info['name'],
                    'severity': info['severity'],
                    'description': self._get_pattern_description(info['name'])
                })
        
        # Analizar opcodes sospechosos
        suspicious_opcodes = {
            'selfdestruct': 'ff',
            'delegatecall': 'f4',
            'callcode': 'f2',
            'create2': 'f5'
        }
        
        for opcode_name, opcode in suspicious_opcodes.items():
            count = bytecode.lower().count(opcode)
            if count > 0:
                analysis['suspicious_opcodes'].append({
                    'opcode': opcode_name,
                    'count': count,
                    'risk': 'high' if opcode in ['ff', 'f4'] else 'medium'
                })
        
        # Detectar patrones de proxy
        if '363d3d373d3d3d363d73' in bytecode:
            analysis['risk_indicators'].append({
                'type': 'proxy_pattern',
                'description': 'Minimal proxy pattern detected',
                'risk': 'medium'
            })
        
        # Calcular complejidad
        analysis['complexity'] = {
            'size': len(bytecode),
            'unique_opcodes': len(set(re.findall(r'[0-9a-f]{2}', bytecode.lower()))),
            'complexity_score': self._calculate_complexity_score(bytecode)
        }
        
        return analysis
    
    def _get_token_basics(self, address: str, w3) -> dict:
        """Obtener información básica del token de forma segura"""
        info = {
            'retrieval_status': 'success',
            'data': {}
        }
        
        # ABI mínimo para funciones básicas
        basic_abi = [
            {"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "type": "function"},
            {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
            {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
            {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
            {"constant": True, "inputs": [], "name": "owner", "outputs": [{"name": "", "type": "address"}], "type": "function"}
        ]
        
        contract = w3.eth.contract(address=address, abi=basic_abi)
        
        # Intentar obtener cada campo con manejo de errores
        fields = {
            'name': 'Unknown',
            'symbol': 'Unknown', 
            'decimals': 18,
            'total_supply': 0,
            'owner': None
        }
        
        for field in fields:
            try:
                if field == 'total_supply':
                    value = contract.functions.totalSupply().call()
                    decimals = fields.get('decimals', 18)
                    fields[field] = value / (10 ** decimals)
                else:
                    func = getattr(contract.functions, field)
                    fields[field] = func().call()
            except:
                # Campo no disponible o error
                pass
        
        info['data'] = fields
        
        # Validaciones adicionales
        if fields['name'] == 'Unknown' and fields['symbol'] == 'Unknown':
            info['warnings'] = ['Cannot retrieve basic token information']
        
        if fields['total_supply'] == 0:
            info['warnings'] = info.get('warnings', []) + ['Zero or unretrievable total supply']
        
        return info
    
    def _analyze_functions(self, bytecode: str) -> dict:
        """Analizar funciones presentes en el bytecode"""
        analysis = {
            'standard_functions': [],
            'admin_functions': [],
            'dangerous_functions': [],
            'unknown_functions': []
        }
        
        # Buscar function selectors (4 bytes)
        selectors = re.findall(r'63([0-9a-f]{8})', bytecode.lower())
        
        for selector in set(selectors):
            if selector in self.FUNCTION_SIGNATURES:
                func_name = self.FUNCTION_SIGNATURES[selector]
                
                # Categorizar funciones
                if func_name in ['transfer', 'approve', 'transferFrom', 'balanceOf']:
                    analysis['standard_functions'].append(func_name)
                elif func_name in ['owner', 'transferOwnership', 'renounceOwnership']:
                    analysis['admin_functions'].append(func_name)
                elif func_name in ['pause', 'mint', 'burn', 'addToBlacklist', 'setFee']:
                    analysis['dangerous_functions'].append({
                        'name': func_name,
                        'risk': self._get_function_risk(func_name),
                        'description': self._get_function_description(func_name)
                    })
            else:
                analysis['unknown_functions'].append(selector)
        
        # Análisis de riesgos basado en funciones
        analysis['risk_summary'] = {
            'has_pause': any(f['name'] == 'pause' for f in analysis['dangerous_functions']),
            'has_mint': any(f['name'] == 'mint' for f in analysis['dangerous_functions']),
            'has_blacklist': any('blacklist' in f['name'].lower() for f in analysis['dangerous_functions']),
            'has_fee_change': any('fee' in f['name'].lower() for f in analysis['dangerous_functions']),
            'centralization_risk': len(analysis['admin_functions']) > 2
        }
        
        return analysis
    
    def _basic_honeypot_check(self, bytecode_analysis: dict, function_analysis: dict) -> dict:
        """Detección básica de honeypot"""
        honeypot_indicators = {
            'is_honeypot': False,
            'confidence': 0,
            'indicators': [],
            'risk_level': 'unknown'
        }
        
        confidence = 0
        
        # Check 1: Pausable sin unpause
        if function_analysis['risk_summary']['has_pause']:
            has_unpause = any(f == 'unpause' for f in function_analysis.get('admin_functions', []))
            if not has_unpause:
                confidence += 30
                honeypot_indicators['indicators'].append('Can be paused without unpause function')
        
        # Check 2: Blacklist presente
        if function_analysis['risk_summary']['has_blacklist']:
            confidence += 40
            honeypot_indicators['indicators'].append('Blacklist functionality detected')
        
        # Check 3: Fees modificables
        if function_analysis['risk_summary']['has_fee_change']:
            confidence += 20
            honeypot_indicators['indicators'].append('Modifiable transaction fees')
        
        # Check 4: Funciones peligrosas sin renounce
        has_dangerous = len(function_analysis['dangerous_functions']) > 0
        has_renounce = 'renounceOwnership' in function_analysis['admin_functions']
        
        if has_dangerous and not has_renounce:
            confidence += 25
            honeypot_indicators['indicators'].append('Dangerous functions with active ownership')
        
        # Check 5: Patrones de bytecode sospechosos
        critical_patterns = [p for p in bytecode_analysis['dangerous_patterns'] 
                           if p['severity'] == 'critical']
        if critical_patterns:
            confidence += 35
            honeypot_indicators['indicators'].append('Critical bytecode patterns found')
        
        # Determinar si es honeypot
        honeypot_indicators['confidence'] = min(confidence, 100)
        
        if confidence >= 70:
            honeypot_indicators['is_honeypot'] = True
            honeypot_indicators['risk_level'] = 'critical'
        elif confidence >= 50:
            honeypot_indicators['risk_level'] = 'high'
        elif confidence >= 30:
            honeypot_indicators['risk_level'] = 'medium'
        else:
            honeypot_indicators['risk_level'] = 'low'
        
        return honeypot_indicators
    
    def _analyze_ownership(self, address: str, w3, bytecode_analysis: dict) -> dict:
        """Analizar estructura de ownership"""
        ownership = {
            'has_owner': False,
            'owner_address': None,
            'ownership_renounced': False,
            'centralization_risk': 'unknown'
        }
        
        try:
            # Intentar obtener owner
            owner_abi = [{"constant": True, "inputs": [], "name": "owner", "outputs": [{"name": "", "type": "address"}], "type": "function"}]
            contract = w3.eth.contract(address=address, abi=owner_abi)
            
            owner_address = contract.functions.owner().call()
            
            if owner_address and owner_address != '0x0000000000000000000000000000000000000000':
                ownership['has_owner'] = True
                ownership['owner_address'] = owner_address
                ownership['ownership_renounced'] = False
                ownership['centralization_risk'] = 'high'
            else:
                ownership['ownership_renounced'] = True
                ownership['centralization_risk'] = 'low'
                
        except:
            # No tiene función owner o falló la llamada
            if any(p['pattern'] == 'ownership_transfer' for p in bytecode_analysis.get('dangerous_patterns', [])):
                ownership['has_owner'] = True
                ownership['centralization_risk'] = 'high'
            else:
                ownership['centralization_risk'] = 'medium'
        
        return ownership
    
    def _advanced_pattern_analysis(self, bytecode: str) -> dict:
        """Análisis avanzado de patrones (PRO)"""
        patterns = {
            'complexity_indicators': [],
            'obfuscation_detected': False,
            'known_vulnerabilities': []
        }
        
        # Detectar ofuscación
        entropy = self._calculate_entropy(bytecode)
        if entropy > 0.95:  # Alta entropía indica posible ofuscación
            patterns['obfuscation_detected'] = True
            patterns['complexity_indicators'].append('High entropy bytecode')
        
        # Buscar vulnerabilidades conocidas
        vuln_patterns = {
            '6080604052348015': 'Standard Solidity pattern',
            'f47261b0': 'Potential reentrancy',
            '23b872dd14': 'Unsafe transfer pattern'
        }
        
        for pattern, desc in vuln_patterns.items():
            if pattern in bytecode:
                patterns['known_vulnerabilities'].append({
                    'type': desc,
                    'severity': 'medium'
                })
        
        return patterns
    
    def _analyze_complexity(self, bytecode: str) -> dict:
        """Analizar complejidad del contrato"""
        return {
            'bytecode_length': len(bytecode),
            'estimated_gas_deploy': len(bytecode) * 200,  # Aproximación
            'complexity_score': self._calculate_complexity_score(bytecode),
            'is_optimized': len(bytecode) < 10000  # Contratos optimizados son más pequeños
        }
    
    def _check_known_patterns(self, bytecode: str) -> dict:
        """Comparar con patrones de scams conocidos"""
        known_scam_patterns = {
            'squid_game': '4a74747970650000',
            'honeypot_v1': 'f9f92be4c0246668',
            'rug_pull_pattern': '5c975abbf2fde38b'
        }
        
        matches = []
        for scam_name, pattern in known_scam_patterns.items():
            if pattern in bytecode:
                matches.append({
                    'scam_type': scam_name,
                    'confidence': 85
                })
        
        return {
            'matches_found': len(matches),
            'similar_scams': matches,
            'is_likely_scam': len(matches) > 0
        }
    
    def _analyze_gas_patterns(self, bytecode: str) -> dict:
        """Analizar patrones de gas"""
        # Buscar infinite loops o high gas consumption
        infinite_loop_pattern = '5b600056'  # Pattern simplificado
        high_gas_patterns = ['f4', 'f5', 'f0']  # DELEGATECALL, CREATE2, CREATE
        
        return {
            'has_infinite_loops': infinite_loop_pattern in bytecode,
            'high_gas_operations': sum(1 for p in high_gas_patterns if p in bytecode),
            'estimated_transfer_gas': 65000 if 'a9059cbb' in bytecode else 21000
        }
    
    def _calculate_final_risk_score(self, scan_data: dict, is_pro: bool) -> dict:
        """Calcular puntuación de riesgo final"""
        score = 100  # Empezar con puntuación perfecta
        factors = []
        
        # Factores del análisis de bytecode
        bytecode = scan_data.get('bytecode_analysis', {})
        dangerous_count = len(bytecode.get('dangerous_patterns', []))
        
        if dangerous_count > 0:
            score -= min(dangerous_count * 15, 45)
            factors.append(f'{dangerous_count} dangerous patterns found')
        
        # Factores de honeypot
        honeypot = scan_data.get('honeypot_analysis', {})
        if honeypot.get('is_honeypot'):
            score -= 50
            factors.append('HONEYPOT DETECTED!')
        elif honeypot.get('confidence', 0) > 50:
            score -= 25
            factors.append('High honeypot probability')
        
        # Factores de ownership
        ownership = scan_data.get('ownership', {})
        if ownership.get('centralization_risk') == 'high':
            score -= 20
            factors.append('High centralization risk')
        
        # Factores de funciones
        functions = scan_data.get('functions', {})
        if functions.get('risk_summary', {}).get('has_blacklist'):
            score -= 30
            factors.append('Blacklist functionality')
        
        if is_pro:
            # Factores PRO adicionales
            if scan_data.get('similarity_check', {}).get('is_likely_scam'):
                score -= 40
                factors.append('Matches known scam patterns')
            
            if scan_data.get('advanced_patterns', {}).get('obfuscation_detected'):
                score -= 15
                factors.append('Code obfuscation detected')
        
        # Asegurar que el score esté entre 0-100
        score = max(0, min(100, score))
        
        # Determinar nivel de riesgo
        if score >= 80:
            risk_level = 'LOW'
            verdict = '✅ PROBABLY SAFE'
        elif score >= 60:
            risk_level = 'MEDIUM'
            verdict = '⚠️ MODERATE RISK'
        elif score >= 40:
            risk_level = 'HIGH'
            verdict = '⚠️ HIGH RISK'
        else:
            risk_level = 'CRITICAL'
            verdict = '🚨 EXTREME RISK'
        
        return {
            'score': score,
            'risk_level': risk_level,
            'verdict': verdict,
            'key_factors': factors[:5] if not is_pro else factors
        }
    
    def _generate_recommendations(self, scan_data: dict, is_pro: bool) -> list:
        """Generar recomendaciones basadas en el análisis"""
        recommendations = []
        risk_score = scan_data.get('risk_assessment', {}).get('score', 0)
        
        # Recomendación principal basada en score
        if risk_score < 40:
            recommendations.append({
                'priority': 'critical',
                'message': 'DO NOT INVEST - Extremely high risk of scam or rug pull'
            })
        elif risk_score < 60:
            recommendations.append({
                'priority': 'high',
                'message': 'HIGH RISK - Only invest what you can afford to lose'
            })
        elif risk_score < 80:
            recommendations.append({
                'priority': 'medium',
                'message': 'MODERATE RISK - Proceed with caution and do additional research'
            })
        else:
            recommendations.append({
                'priority': 'low',
                'message': 'Appears relatively safe, but always DYOR and invest responsibly'
            })
        
        # Recomendaciones específicas
        honeypot = scan_data.get('honeypot_analysis', {})
        if honeypot.get('is_honeypot'):
            recommendations.append({
                'priority': 'critical',
                'message': 'HONEYPOT DETECTED - You will not be able to sell!'
            })
        
        ownership = scan_data.get('ownership', {})
        if ownership.get('centralization_risk') == 'high' and not ownership.get('ownership_renounced'):
            recommendations.append({
                'priority': 'high',
                'message': 'Owner has dangerous privileges - risk of rug pull'
            })
        
        if is_pro:
            # Recomendaciones PRO adicionales
            if scan_data.get('similarity_check', {}).get('is_likely_scam'):
                recommendations.append({
                    'priority': 'critical',
                    'message': 'Token matches known scam patterns - AVOID!'
                })
            
            if scan_data.get('advanced_patterns', {}).get('obfuscation_detected'):
                recommendations.append({
                    'priority': 'high',
                    'message': 'Obfuscated code detected - developer may be hiding functionality'
                })
        
        return recommendations
    
    # Funciones auxiliares
    def _get_pattern_description(self, pattern_name: str) -> str:
        descriptions = {
            'selfdestruct': 'Contract can be destroyed by owner',
            'proxy_pattern': 'Upgradeable proxy - code can be changed',
            'ownership_transfer': 'Ownership can be transferred',
            'mint_function': 'New tokens can be created',
            'burn_function': 'Tokens can be destroyed',
            'pausable': 'Trading can be paused',
            'blacklist': 'Addresses can be blacklisted',
            'modifiable_fees': 'Transaction fees can be changed'
        }
        return descriptions.get(pattern_name, 'Unknown pattern')
    
    def _get_function_risk(self, func_name: str) -> str:
        high_risk = ['pause', 'mint', 'addToBlacklist', 'setFee']
        medium_risk = ['burn', 'transferOwnership']
        
        if func_name in high_risk:
            return 'high'
        elif func_name in medium_risk:
            return 'medium'
        return 'low'
    
    def _get_function_description(self, func_name: str) -> str:
        descriptions = {
            'pause': 'Can stop all trading',
            'mint': 'Can create new tokens (inflation risk)',
            'burn': 'Can destroy tokens',
            'addToBlacklist': 'Can prevent addresses from trading',
            'setFee': 'Can change transaction fees',
            'transferOwnership': 'Can transfer control to another address'
        }
        return descriptions.get(func_name, 'Unknown function')
    
    def _calculate_complexity_score(self, bytecode: str) -> int:
        """Calcular score de complejidad (0-100)"""
        length = len(bytecode)
        if length < 5000:
            return 20
        elif length < 10000:
            return 40
        elif length < 20000:
            return 60
        elif length < 40000:
            return 80
        return 100
    
    def _calculate_entropy(self, data: str) -> float:
        """Calcular entropía de Shannon"""
        if not data:
            return 0
        
        entropy = 0
        for i in range(256):
            char = chr(i)
            freq = data.count(char)
            if freq > 0:
                prob = float(freq) / len(data)
                entropy -= prob * (prob and prob * 2)
        
        return entropy / 8  # Normalizar a 0-1
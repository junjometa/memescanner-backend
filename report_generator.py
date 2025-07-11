"""
Report Generator - Genera reportes formateados del análisis
"""
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Genera reportes de análisis en formato estructurado"""
    
    def generate_report(self, scan_data: dict, is_pro: bool, payment_info: dict) -> dict:
        """
        Generar reporte completo del análisis
        
        Args:
            scan_data: Datos del escaneo
            is_pro: Si es escaneo PRO
            payment_info: Información del pago
            
        Returns:
            dict: Reporte formateado
        """
        try:
            # Estructura base del reporte
            report = {
                'metadata': self._generate_metadata(scan_data, is_pro, payment_info),
                'summary': self._generate_summary(scan_data),
                'token_info': self._format_token_info(scan_data),
                'security_analysis': self._format_security_analysis(scan_data),
                'risk_assessment': scan_data.get('risk_assessment', {}),
                'warnings': self._generate_warnings(scan_data),
                'recommendations': scan_data.get('recommendations', [])
            }
            
            # Secciones adicionales para PRO
            if is_pro:
                report['advanced_analysis'] = self._format_advanced_analysis(scan_data)
                report['detailed_findings'] = self._format_detailed_findings(scan_data)
                report['technical_details'] = self._format_technical_details(scan_data)
            else:
                # Para básico, agregar mensaje de upgrade
                report['upgrade_notice'] = {
                    'message': 'Upgrade to PRO for advanced pattern detection, code audit, and detailed recommendations',
                    'features_missing': [
                        'Advanced pattern analysis',
                        'Code complexity metrics',
                        'Known scam comparison',
                        'Obfuscation detection',
                        'Gas optimization analysis'
                    ]
                }
            
            # Agregar visualización de score
            report['risk_visualization'] = self._generate_risk_visualization(
                scan_data.get('risk_assessment', {})
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return {
                'error': 'Failed to generate report',
                'summary': {
                    'verdict': '❓ ANALYSIS ERROR',
                    'message': 'Could not complete analysis'
                }
            }
    
    def _generate_metadata(self, scan_data: dict, is_pro: bool, payment_info: dict) -> dict:
        """Generar metadata del reporte"""
        return {
            'report_id': f"scan_{int(datetime.utcnow().timestamp())}",
            'generated_at': datetime.utcnow().isoformat(),
            'scan_type': 'PRO' if is_pro else 'BASIC',
            'token_address': scan_data.get('address', 'Unknown'),
            'chain': scan_data.get('chain', 'Unknown'),
            'payment_id': payment_info.get('payment_id'),
            'scanner_version': '1.0.0'
        }
    
    def _generate_summary(self, scan_data: dict) -> dict:
        """Generar resumen ejecutivo"""
        risk = scan_data.get('risk_assessment', {})
        honeypot = scan_data.get('honeypot_analysis', {})
        
        # Determinar mensaje principal
        if honeypot.get('is_honeypot'):
            main_message = "🚨 HONEYPOT DETECTED - DO NOT BUY!"
        elif risk.get('score', 0) < 40:
            main_message = "🚨 EXTREMELY HIGH RISK - Likely scam"
        elif risk.get('score', 0) < 60:
            main_message = "⚠️ HIGH RISK - Proceed with extreme caution"
        elif risk.get('score', 0) < 80:
            main_message = "⚠️ MODERATE RISK - Research thoroughly"
        else:
            main_message = "✅ RELATIVELY LOW RISK - But always DYOR"
        
        return {
            'verdict': risk.get('verdict', '❓ UNKNOWN'),
            'risk_score': risk.get('score', 0),
            'risk_level': risk.get('risk_level', 'UNKNOWN'),
            'main_message': main_message,
            'key_findings': risk.get('key_factors', [])[:5],
            'scan_completed': True
        }
    
    def _format_token_info(self, scan_data: dict) -> dict:
        """Formatear información del token"""
        token_info = scan_data.get('token_info', {})
        
        return {
            'name': token_info.get('name', 'Unknown'),
            'symbol': token_info.get('symbol', 'Unknown'),
            'decimals': token_info.get('decimals', 18),
            'total_supply': token_info.get('total_supply_formatted', 'Unknown'),
            'contract_verified': scan_data.get('is_contract', False),
            'bytecode_size': scan_data.get('bytecode_size', 0),
            'has_source_code': False  # Se determinaría con explorador API
        }
    
    def _format_security_analysis(self, scan_data: dict) -> dict:
        """Formatear análisis de seguridad"""
        bytecode = scan_data.get('bytecode_analysis', {})
        functions = scan_data.get('functions', {})
        honeypot = scan_data.get('honeypot_analysis', {})
        ownership = scan_data.get('ownership', {})
        
        return {
            'contract_analysis': {
                'dangerous_patterns': len(bytecode.get('dangerous_patterns', [])),
                'suspicious_opcodes': len(bytecode.get('suspicious_opcodes', [])),
                'complexity_score': bytecode.get('complexity', {}).get('complexity_score', 0),
                'has_critical_issues': any(
                    p['severity'] == 'critical' 
                    for p in bytecode.get('dangerous_patterns', [])
                )
            },
            'function_analysis': {
                'standard_functions': len(functions.get('standard_functions', [])),
                'admin_functions': len(functions.get('admin_functions', [])),
                'dangerous_functions': len(functions.get('dangerous_functions', [])),
                'has_pause': functions.get('risk_summary', {}).get('has_pause', False),
                'has_mint': functions.get('risk_summary', {}).get('has_mint', False),
                'has_blacklist': functions.get('risk_summary', {}).get('has_blacklist', False)
            },
            'honeypot_check': {
                'is_honeypot': honeypot.get('is_honeypot', False),
                'confidence': honeypot.get('confidence', 0),
                'risk_level': honeypot.get('risk_level', 'unknown'),
                'indicators': honeypot.get('indicators', [])
            },
            'ownership_status': {
                'has_owner': ownership.get('has_owner', False),
                'owner_address': ownership.get('owner_address'),
                'ownership_renounced': ownership.get('ownership_renounced', False),
                'centralization_risk': ownership.get('centralization_risk', 'unknown')
            }
        }
    
    def _generate_warnings(self, scan_data: dict) -> list:
        """Generar lista de advertencias prioritizadas"""
        warnings = []
        
        # Honeypot warning (máxima prioridad)
        honeypot = scan_data.get('honeypot_analysis', {})
        if honeypot.get('is_honeypot'):
            warnings.append({
                'level': 'CRITICAL',
                'icon': '🚨',
                'message': 'HONEYPOT DETECTED - You will not be able to sell!',
                'details': honeypot.get('indicators', [])
            })
        
        # Dangerous patterns
        bytecode = scan_data.get('bytecode_analysis', {})
        for pattern in bytecode.get('dangerous_patterns', []):
            if pattern['severity'] == 'critical':
                warnings.append({
                    'level': 'CRITICAL',
                    'icon': '🚨',
                    'message': f"{pattern['pattern']}: {pattern['description']}"
                })
        
        # Function warnings
        functions = scan_data.get('functions', {})
        if functions.get('risk_summary', {}).get('has_blacklist'):
            warnings.append({
                'level': 'HIGH',
                'icon': '⚠️',
                'message': 'Contract can blacklist addresses from trading'
            })
        
        if functions.get('risk_summary', {}).get('has_pause'):
            warnings.append({
                'level': 'HIGH',
                'icon': '⚠️',
                'message': 'Contract can be paused, stopping all trading'
            })
        
        # Ownership warnings
        ownership = scan_data.get('ownership', {})
        if ownership.get('centralization_risk') == 'high' and not ownership.get('ownership_renounced'):
            warnings.append({
                'level': 'HIGH',
                'icon': '⚠️',
                'message': 'High centralization risk - owner has significant control'
            })
        
        # Ordenar por nivel de severidad
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        warnings.sort(key=lambda x: severity_order.get(x['level'], 99))
        
        return warnings[:10]  # Limitar a 10 warnings más importantes
    
    def _format_advanced_analysis(self, scan_data: dict) -> dict:
        """Formatear análisis avanzado (PRO)"""
        return {
            'pattern_analysis': scan_data.get('advanced_patterns', {}),
            'complexity_metrics': scan_data.get('complexity_analysis', {}),
            'similarity_check': scan_data.get('similarity_check', {}),
            'gas_optimization': scan_data.get('gas_analysis', {})
        }
    
    def _format_detailed_findings(self, scan_data: dict) -> dict:
        """Formatear hallazgos detallados (PRO)"""
        findings = {
            'critical_issues': [],
            'high_risk_issues': [],
            'medium_risk_issues': [],
            'low_risk_issues': [],
            'informational': []
        }
        
        # Categorizar hallazgos por severidad
        bytecode = scan_data.get('bytecode_analysis', {})
        
        for pattern in bytecode.get('dangerous_patterns', []):
            severity = pattern.get('severity', 'low')
            finding = {
                'type': pattern['pattern'],
                'description': pattern['description'],
                'recommendation': self._get_recommendation_for_pattern(pattern['pattern'])
            }
            
            if severity == 'critical':
                findings['critical_issues'].append(finding)
            elif severity == 'high':
                findings['high_risk_issues'].append(finding)
            elif severity == 'medium':
                findings['medium_risk_issues'].append(finding)
            else:
                findings['low_risk_issues'].append(finding)
        
        # Agregar información sobre funciones peligrosas
        functions = scan_data.get('functions', {})
        for func in functions.get('dangerous_functions', []):
            risk = func.get('risk', 'medium')
            finding = {
                'type': f"Function: {func['name']}",
                'description': func['description'],
                'recommendation': f"Monitor usage of {func['name']} function"
            }
            
            if risk == 'high':
                findings['high_risk_issues'].append(finding)
            else:
                findings['medium_risk_issues'].append(finding)
        
        return findings
    
    def _format_technical_details(self, scan_data: dict) -> dict:
        """Formatear detalles técnicos (PRO)"""
        bytecode = scan_data.get('bytecode_analysis', {})
        
        return {
            'bytecode_analysis': {
                'size_bytes': scan_data.get('bytecode_size', 0),
                'complexity_score': bytecode.get('complexity', {}).get('complexity_score', 0),
                'unique_opcodes': bytecode.get('complexity', {}).get('unique_opcodes', 0),
                'suspicious_opcodes': [
                    {
                        'opcode': op['opcode'],
                        'count': op['count'],
                        'risk': op['risk']
                    }
                    for op in bytecode.get('suspicious_opcodes', [])
                ]
            },
            'function_signatures': {
                'total_functions': (
                    len(scan_data.get('functions', {}).get('standard_functions', [])) +
                    len(scan_data.get('functions', {}).get('admin_functions', [])) +
                    len(scan_data.get('functions', {}).get('dangerous_functions', []))
                ),
                'standard_erc20': scan_data.get('functions', {}).get('standard_functions', []),
                'admin_functions': scan_data.get('functions', {}).get('admin_functions', []),
                'unknown_functions': len(scan_data.get('functions', {}).get('unknown_functions', []))
            },
            'advanced_metrics': {
                'has_proxy_pattern': any(
                    p['pattern'] == 'proxy_pattern'
                    for p in bytecode.get('dangerous_patterns', [])
                ),
                'obfuscation_detected': scan_data.get('advanced_patterns', {}).get('obfuscation_detected', False),
                'gas_efficiency': scan_data.get('gas_analysis', {}).get('estimated_transfer_gas', 'Unknown')
            }
        }
    
    def _generate_risk_visualization(self, risk_assessment: dict) -> dict:
        """Generar visualización del riesgo"""
        score = risk_assessment.get('score', 0)
        
        # Crear barra de progreso visual
        filled = int(score / 10)
        empty = 10 - filled
        
        if score >= 80:
            color = 'green'
            bar_char = '🟢'
        elif score >= 60:
            color = 'yellow'
            bar_char = '🟡'
        elif score >= 40:
            color = 'orange'
            bar_char = '🟠'
        else:
            color = 'red'
            bar_char = '🔴'
        
        progress_bar = bar_char * filled + '⚪' * empty
        
        return {
            'score': score,
            'score_out_of': 100,
            'risk_level': risk_assessment.get('risk_level', 'UNKNOWN'),
            'color': color,
            'progress_bar': progress_bar,
            'percentage': f"{score}%",
            'grade': self._get_letter_grade(score)
        }
    
    def _get_recommendation_for_pattern(self, pattern: str) -> str:
        """Obtener recomendación para un patrón específico"""
        recommendations = {
            'selfdestruct': 'Avoid - contract can be destroyed',
            'proxy_pattern': 'Be cautious - contract logic can be changed',
            'ownership_transfer': 'Check if ownership is renounced',
            'mint_function': 'Verify max supply or minting limits',
            'pausable': 'Ensure pause mechanism has time limits',
            'blacklist': 'Avoid - high risk of selective blocking',
            'modifiable_fees': 'Check maximum fee limits in code'
        }
        return recommendations.get(pattern, 'Exercise caution')
    
    def _get_letter_grade(self, score: int) -> str:
        """Convertir score a calificación de letra"""
        if score >= 90:
            return 'A+'
        elif score >= 85:
            return 'A'
        elif score >= 80:
            return 'A-'
        elif score >= 75:
            return 'B+'
        elif score >= 70:
            return 'B'
        elif score >= 65:
            return 'B-'
        elif score >= 60:
            return 'C+'
        elif score >= 55:
            return 'C'
        elif score >= 50:
            return 'C-'
        elif score >= 45:
            return 'D+'
        elif score >= 40:
            return 'D'
        else:
            return 'F'
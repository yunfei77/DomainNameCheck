import requests
import json
import time
import hashlib
from typing import Dict, Any, List, Tuple
import re
import dns.resolver
from urllib.parse import urlparse
import socket
import whois
from datetime import datetime
from colorama import Fore, Style, init
import base64
import concurrent.futures
import threading

init(autoreset=True)

class ThreatIntelligence:
    def __init__(self):
        # 基础API密钥
        self.vt_api_key = ""
        self.abuseipdb_api_key = ""
        self.urlscan_api_key = ""
        self.otx_api_key = ""
        self.abuse_api_key = ""
        self.gsb_api_key = "-"
        self.cloudflare_api_token = ""
        self.spamhaus_api_key = ""
        self.ipqs_api_key = ""  # 添加IPQualityScore API密钥
        self.pulsedive_api_key = ""

    def check_url_with_multiple_sources(self, url: str) -> Dict[str, Any]:
        """使用多个威胁情报源检查URL"""
        # 如果输入没有协议前缀，添加一个临时前缀用于解析
        if not url.startswith(('http://', 'https://')):
            parsed_url = urlparse('http://' + url)
            domain = parsed_url.netloc or url
        else:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

        # 尝试解析域名获取IP
        try:
            ip_address = socket.gethostbyname(domain)
        except socket.gaierror:
            ip_address = None

        result = {
            'url': url,
            'domain': domain,
            'ip': ip_address,
            'is_malicious': False,
            'risk_level': 'low',
            'risk_score': 0.0,
            'findings': [],
            'source_results': {}
        }

        # 定义所有检查函数及其权重
        checks = [
            ('urlscan', self.check_urlscan, 3.0, 'URLScan.io'),
            ('otx', self.check_otx, 3.0, 'AlienVault OTX'),
            ('urlhaus', self.check_urlhaus, 4.0, 'URLhaus'),
            ('maltiverse', self.check_maltiverse, 3.0, 'Maltiverse'),
            ('threatfox', self.check_threatfox, 3.0, 'ThreatFox'),
            ('virustotal', self.check_virustotal, 3.0, 'VirusTotal'),
            ('talos', self.check_talos, 2.0, 'Cisco Talos'),
            ('abuseipdb', self.check_abuseipdb, 3.0, 'AbuseIPDB'),
            ('abuse', self.check_abuse, 2.0, 'Abuse.ch'),
            ('surbl', self.check_surbl, 3.0, 'SURBL'),
            ('spamhaus', self.check_spamhaus, 3.0, 'Spamhaus'),
            ('google_safebrowsing', self.check_google_safebrowsing, 3.0, 'Google Safe Browsing'),
            ('ipqualityscore', self.check_ipqualityscore, 3.0, 'IPQualityScore'),
            ('spamcop', self.check_spamcop, 2.0, 'SpamCop'),
            ('mxtoolbox', self.check_mxtoolbox, 2.0, 'MXToolbox'),
            ('threatminer', self.check_threatminer, 3.0, 'ThreatMiner'),
            ('pulsedive', self.check_pulsedive, 3.0, 'Pulsedive'),
        ]

        def run_check(check_info: Tuple[str, callable, float, str]) -> Tuple[str, Dict[str, Any], float, str]:
            """执行单个检查的函数"""
            source_key, check_func, weight, source_name = check_info
            print(f"\n{Fore.CYAN}[{source_name}] 开始检查...{Style.RESET_ALL}")
            
            try:
                # 根据检查函数的需求传递URL或域名
                if source_key in ['urlhaus', 'virustotal', 'google_safebrowsing', 'ipqualityscore']:
                    check_result = check_func(url)
                else:
                    check_result = check_func(domain)
                
                # 检查结果状态
                if 'error' in check_result:
                    print(f"{Fore.RED}[{source_name}] 检查失败: {check_result['error']}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[{source_name}] 检查完成{Style.RESET_ALL}")
                
                return source_key, check_result, weight, source_name
            except Exception as e:
                error_msg = f"检查失败: {str(e)}"
                print(f"{Fore.RED}[{source_name}] {error_msg}{Style.RESET_ALL}")
                return source_key, {
                    'is_malicious': False,
                    'findings': [],
                    'error': error_msg
                }, weight, source_name

        # 使用线程池执行所有检查
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # 提交所有检查任务
            future_to_check = {
                executor.submit(run_check, check_info): check_info[0]
                for check_info in checks
            }
            
            # 显示进度
            total_checks = len(checks)
            completed_checks = 0
            
            print(f"\n{Fore.CYAN}开始执行检查...{Style.RESET_ALL}")
            print(f"总共 {total_checks} 个检查项")
            
            # 收集所有检查结果
            for future in concurrent.futures.as_completed(future_to_check):
                completed_checks += 1
                source_key, check_result, weight, source_name = future.result()
                
                # 显示进度
                print(f"\r{Fore.YELLOW}进度: {completed_checks}/{total_checks} ({completed_checks/total_checks*100:.1f}%){Style.RESET_ALL}", end="")
                
                if check_result is not None:
                    result['source_results'][source_key] = check_result
                    if check_result.get('malicious') or check_result.get('is_malicious'):
                        result['is_malicious'] = True
                        result['risk_score'] += weight
                        if check_result.get('findings'):
                            result['findings'].extend(check_result['findings'])
            
            print("\n")  # 换行，避免进度显示影响后续输出

        # 更新风险等级
        if result['risk_score'] >= 7.0:
            result['risk_level'] = 'critical'
        elif result['risk_score'] >= 5.0:
            result['risk_level'] = 'high'
        elif result['risk_score'] >= 3.0:
            result['risk_level'] = 'medium'

        return result

    def check_urlscan(self, url: str) -> Dict[str, Any]:
        """使用URLScan.io检查URL"""
        try:
            query_url = f"https://urlscan.io/api/v1/search/?q=domain:{url}"
            headers = {
                'API-Key': self.urlscan_api_key,
                'User-Agent': 'Mozilla/5.0'
            }
            response = requests.get(query_url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                findings = []
                
                if data.get('results'):
                    for result in data['results']:
                        if result.get('verdicts', {}).get('overall', {}).get('malicious'):
                            findings.append(f"URLScan发现可疑行为: {result.get('verdicts', {}).get('overall', {}).get('categories', [])}")
                    
                    return {
                        'malicious': bool(findings),
                        'findings': findings,
                        'scan_time': data['results'][0].get('task', {}).get('time') if data['results'] else None
                    }
                else:
                    return {
                        'malicious': False,
                        'findings': [],
                        'info': "未找到相关扫描记录"
                    }
            elif response.status_code == 401:
                print(f"URLScan.io API密钥无效")
            elif response.status_code == 429:
                print(f"URLScan.io API请求次数超限")
            else:
                print(f"URLScan.io API返回状态码: {response.status_code}")
            
            # 即使没有结果也返回一个基本结构
            return {
                'malicious': False,
                'findings': [],
                'error': f"API返回状态码: {response.status_code}"
            }
        except Exception as e:
            print(f"URLScan.io 检查失败: {str(e)}")
            return {
                'malicious': False,
                'findings': [],
                'error': str(e)
            }

    def check_otx(self, url: str) -> Dict[str, Any]:
        """使用AlienVault OTX检查URL"""
        try:
            api_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{url}/general"
            headers = {'X-OTX-API-KEY': self.otx_api_key}
            
            response = requests.get(api_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                findings = []
                malicious_indicators = []
                
                if data.get('pulse_info', {}).get('pulses'):
                    for pulse in data['pulse_info']['pulses']:
                        findings.append(f"OTX警报: {pulse.get('name', '未知威胁')}")
                        malicious_indicators.append(pulse.get('name'))
                
                return {
                    'malicious': len(malicious_indicators) > 0,
                    'findings': findings,
                    'reputation': data.get('reputation', 0)
                }
            elif response.status_code == 401:
                print(f"OTX API密钥无效")
            elif response.status_code == 429:
                print(f"OTX API请求次数超限")
            else:
                print(f"OTX API返回状态码: {response.status_code}")
        except Exception as e:
            print(f"OTX检查失败: {str(e)}")
        
        return {
            'malicious': False,
            'findings': [],
            'error': f"检查失败"
        }

    def check_urlhaus(self, url: str) -> Dict[str, Any]:
        """使用URLhaus检查URL"""
        try:
            api_url = "https://urlhaus-api.abuse.ch/v1/url/"
            data = {'url': url}
            response = requests.post(api_url, data=data)
            
            if response.status_code == 200:
                result = response.json()
                findings = []
                
                if result.get('query_status') == 'ok' and result.get('threat'):
                    findings.append(f"URLhaus发现威胁: {result['threat']}")
                
                return {
                    'is_malicious': result.get('blacklisted') == True,
                    'findings': findings,
                    'threat_type': result.get('threat'),
                    'first_seen': result.get('date_added')
                }
        except Exception as e:
            print(f"URLhaus检查失败: {str(e)}")
        
        return {
            'is_malicious': False,
            'findings': [],
            'error': f"检查失败"
        }

    def check_maltiverse(self, url: str) -> Dict[str, Any]:
        """使用Maltiverse检查URL"""
        try:
            api_url = f"https://api.maltiverse.com/hostname/{url}"
            headers = {
                'User-Agent': 'Mozilla/5.0'
            }
            
            response = requests.get(api_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                findings = []
                
                if data.get('status') == 'active':
                    if data.get('blacklist') or data.get('classification'):
                        findings.append(f"Maltiverse分类: {data.get('classification', '未知')}")
                
                return {
                    'is_malicious': bool(findings),
                    'findings': findings,
                    'classification': data.get('classification')
                }
            elif response.status_code == 404:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'info': "域名未收录"
                }
        except Exception as e:
            print(f"Maltiverse检查失败: {str(e)}")
        
        return {
            'is_malicious': False,
            'findings': [],
            'error': f"检查失败"
        }

    def check_threatfox(self, url: str) -> Dict[str, Any]:
        """使用ThreatFox检查URL"""
        try:
            api_url = "https://threatfox-api.abuse.ch/api/v1/"
            data = {
                "query": "search_ioc",
                "search_term": url,
                "days": 30
            }
            
            response = requests.post(api_url, json=data)
            if response.status_code == 200:
                result = response.json()
                findings = []
                
                if result.get('query_status') == 'ok':
                    if result.get('data'):
                        for ioc in result['data']:
                            findings.append(f"ThreatFox发现IOC: {ioc.get('threat_type', '未知威胁')}")
                    
                    return {
                        'is_malicious': bool(findings),
                        'findings': findings,
                        'ioc_count': len(result.get('data', []))
                    }
                return {
                    'is_malicious': False,
                    'findings': [],
                    'info': "未发现威胁"
                }
        except Exception as e:
            print(f"ThreatFox检查失败: {str(e)}")
        
        return {
            'is_malicious': False,
            'findings': [],
            'error': f"检查失败"
        }

    def check_virustotal(self, url: str) -> Dict[str, Any]:
        """使用VirusTotal检查URL"""
        try:
            # 确保URL格式正确
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # 使用 v3 API
            api_url = "https://www.virustotal.com/api/v3/urls"
            
            headers = {
                'x-apikey': self.vt_api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            # 先尝试获取URL的ID
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            response = requests.get(f"{api_url}/{url_id}", headers=headers)
            
            if response.status_code == 404:
                return {
                    'malicious': False,
                    'findings': [],
                    'info': "URL未在VirusTotal中记录，请先在官网扫描"
                }
            
            if response.status_code == 200:
                data = response.json()
                findings = []
                
                # 获取检测结果
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                if malicious > 0 or suspicious > 0:
                    findings.append(f"VirusTotal检测到 {malicious} 个引擎报告恶意，{suspicious} 个引擎报告可疑")
                    # 获取具体的检测结果
                    results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
                    for engine, result in results.items():
                        if result.get('category') in ['malicious', 'suspicious']:
                            findings.append(f"- {engine}: {result.get('result', '未知威胁')}")
                
                return {
                    'malicious': malicious > 0 or suspicious > 0,
                    'findings': findings,
                    'total_engines': total,
                    'malicious_engines': malicious,
                    'suspicious_engines': suspicious,
                    'scan_date': data.get('data', {}).get('attributes', {}).get('last_analysis_date')
                }
            elif response.status_code == 401:
                return {
                    'malicious': False,
                    'findings': [],
                    'error': "API密钥无效"
                }
            elif response.status_code == 429:
                return {
                    'malicious': False,
                    'findings': [],
                    'error': "API请求次数超限"
                }
            else:
                return {
                    'malicious': False,
                    'findings': [],
                    'error': f"API返回状态码: {response.status_code} - {response.text}"
                }
        except Exception as e:
            print(f"VirusTotal检查失败: {str(e)}")
            return {
                'malicious': False,
                'findings': [],
                'error': f"检查失败: {str(e)}"
            }

    def check_talos(self, url: str) -> Dict[str, Any]:
        """使用Cisco Talos检查域名声誉"""
        try:
            query = f"{url}.senderscore.org"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5  # 设置超时时间
            resolver.lifetime = 5
            
            try:
                answers = resolver.resolve(query, 'TXT')
                findings = []
                for rdata in answers:
                    for txt_string in rdata.strings:
                        txt_data = txt_string.decode()
                        if "poor" in txt_data.lower() or "bad" in txt_data.lower():
                            findings.append(f"Cisco Talos声誉信息: {txt_data}")
                
                return {
                    'is_malicious': len(findings) > 0,
                    'findings': findings,
                    'info': "域名存在" if not findings else None
                }
            except dns.resolver.NXDOMAIN:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'info': "域名未在SenderBase注册"
                }
            except dns.resolver.NoAnswer:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'info': "域名无SenderBase记录"
                }
        except Exception as e:
            print(f"Talos检查失败: {str(e)}")
            return {
                'is_malicious': False,
                'findings': [],
                'error': f"DNS查询失败: {str(e)}"
            }

    def check_abuseipdb(self, url: str) -> Dict[str, Any]:
        """使用 AbuseIPDB 检查 URL"""
        try:
            # 先尝试解析域名获取IP
            try:
                ip_address = socket.gethostbyname(url)
            except socket.gaierror:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'info': f"域名 {url} 无法解析为IP地址"
                }

            api_url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json',
            }
            params = {
                'ipAddress': ip_address,  # 使用解析后的IP地址
                'maxAgeInDays': 30
            }
            
            print(f"正在请求 AbuseIPDB API...")
            print(f"API URL: {api_url}")
            print(f"域名: {url}")
            print(f"IP地址: {ip_address}")
            
            response = requests.get(api_url, headers=headers, params=params)
            print(f"API 响应状态码: {response.status_code}")
            print(f"API 响应内容: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                findings = []
                
                if data.get('data', {}).get('abuseConfidenceScore', 0) > 0:
                    score = data['data']['abuseConfidenceScore']
                    findings.append(f"AbuseIPDB 风险评分: {score}/100")
                    if data['data'].get('reports'):
                        findings.append(f"报告数量: {len(data['data']['reports'])}")
                
                return {
                    'is_malicious': data.get('data', {}).get('abuseConfidenceScore', 0) > 25,
                    'findings': findings,
                    'score': data.get('data', {}).get('abuseConfidenceScore', 0),
                    'reports': data.get('data', {}).get('reports', [])
                }
            elif response.status_code == 401:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': "API密钥无效"
                }
            elif response.status_code == 429:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': "API请求次数超限"
                }
            else:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': f"API返回状态码: {response.status_code}"
                }
        except Exception as e:
            print(f"AbuseIPDB 检查失败: {str(e)}")
            return {
                'is_malicious': False,
                'findings': [],
                'error': f"检查失败: {str(e)}"
            }

    def check_spamhaus(self, domain: str) -> Dict[str, Any]:
        """使用 Spamhaus 检查域名"""
        try:
            # 使用 DNS 查询方式
            query = f"{domain}.dbl.spamhaus.org"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            print(f"\n[spamhaus] Spamhaus检查:")
            print(f"[spamhaus] 原始域名: {domain}")
            print(f"[spamhaus] Spamhaus查询域名: {query}")
            
            try:
                answers = resolver.resolve(query, 'A')
                findings = []
                
                # 如果域名在 Spamhaus 黑名单中，会返回一个 IP 地址
                if answers:
                    findings.append("域名在 Spamhaus 黑名单中")
                    for rdata in answers:
                        ip = str(rdata)
                        # 检查所有可能的返回码
                        if ip in ["127.0.0.2", "127.0.1.2", "127.0.2.2"]:
                            findings.append("垃圾邮件域名")
                        elif ip in ["127.0.0.4", "127.0.1.4", "127.0.2.4"]:
                            findings.append("钓鱼网站")
                        elif ip in ["127.0.0.8", "127.0.1.8", "127.0.2.8"]:
                            findings.append("恶意软件")
                        elif ip in ["127.0.0.16", "127.0.1.16", "127.0.2.16"]:
                            findings.append("垃圾邮件发送者")
                        else:
                            findings.append(f"未知威胁类型 (IP: {ip})")
                    
                    return {
                        'malicious': True,
                        'is_malicious': True,
                        'findings': findings
                    }
            except dns.resolver.NXDOMAIN:
                return {
                    'malicious': False,
                    'is_malicious': False,
                    'findings': [],
                    'info': "域名未在 Spamhaus 黑名单中"
                }
            except dns.resolver.NoAnswer:
                return {
                    'malicious': False,
                    'is_malicious': False,
                    'findings': [],
                    'info': "域名无 Spamhaus 记录"
                }
        except Exception as e:
            print(f"Spamhaus检查失败: {str(e)}")
            return {
                'malicious': False,
                'is_malicious': False,
                'findings': [],
                'error': f"检查失败: {str(e)}"
            }

    def check_abuse(self, domain: str) -> Dict[str, Any]:
        """使用abuse.ch Hunting API检查域名"""
        try:
            api_url = "https://hunting-api.abuse.ch/api/v1/"
            headers = {
                'Auth-Key': self.abuse_api_key,
                'Content-Type': 'application/json'
            }
            data = {
                'query': 'get_fplist',
                'format': 'json'
            }
            
            print(f"正在请求 abuse API...")
            print(f"API URL: {api_url}")
            print(f"域名: {domain}")
            
            response = requests.post(api_url, headers=headers, json=data)
            # print(f"API 响应状态码: {response.status_code}")
            # print(f"API 响应内容: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                findings = []
                
                # 检查域名是否在误报列表中
                if data.get('data'):
                    for item in data['data']:
                        if item.get('domain') == domain:
                            findings.append(f"域名在误报列表中: {item.get('reason', '未知原因')}")
                
                return {
                    'is_malicious': False,  # 误报列表中的域名被认为是安全的
                    'findings': findings,
                    'in_fplist': bool(findings)
                }
            elif response.status_code == 401:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': "API密钥无效"
                }
        except Exception as e:
            print(f"abuse API检查失败: {str(e)}")
        
        return {
            'is_malicious': False,
            'findings': [],
            'error': "检查失败"
        }

    def check_surbl(self, domain: str) -> Dict[str, Any]:
        """使用SURBL检查域名"""
        try:
            # SURBL使用DNS查询方式
            query = f"{domain}.multi.surbl.org"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            print(f"\n[surbl] SURBL检查:")
            print(f"[surbl] 原始域名: {domain}")
            print(f"[surbl] SURBL查询域名: {query}")
            
            try:
                answers = resolver.resolve(query, 'A')
                findings = []
                
                # 如果域名在SURBL黑名单中，会返回一个IP地址
                if answers:
                    findings.append("域名在SURBL黑名单中")
                    # 解析返回的IP地址对应的黑名单类型
                    for rdata in answers:
                        ip = str(rdata)
                        if ip == "127.0.0.2":
                            findings.append("垃圾邮件域名")
                        elif ip == "127.0.0.4":
                            findings.append("钓鱼网站")
                        elif ip == "127.0.0.8":
                            findings.append("恶意软件")
                        elif ip == "127.0.0.16":
                            findings.append("垃圾邮件发送者")
                    
                    return {
                        'is_malicious': True,
                        'findings': findings
                    }
            except dns.resolver.NXDOMAIN:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'info': "域名未在SURBL黑名单中"
                }
            except dns.resolver.NoAnswer:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'info': "域名无SURBL记录"
                }
        except Exception as e:
            print(f"SURBL检查失败: {str(e)}")
        
        return {
            'is_malicious': False,
            'findings': [],
            'error': "检查失败"
        }

    def check_google_safebrowsing(self, url: str) -> Dict[str, Any]:
        """使用Google Safe Browsing检查URL"""
        try:
            # 确保URL格式正确
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_api_key}"
            data = {
                "client": {
                    "clientId": "url-checker",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            print(f"\n[Google] Google Safe Browsing检查:")
            print(f"[Google] URL: {url}")
            print(f"[Google] API URL: {api_url}")
            
            response = requests.post(api_url, json=data, headers=headers, timeout=10)
            print(f"[Google] 响应状态码: {response.status_code}")
            # print(f"[DEBUG] 响应内容: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                findings = []
                
                if data.get('matches'):
                    for match in data['matches']:
                        threat_type = match.get('threatType', '未知威胁')
                        platform = match.get('platformType', '未知平台')
                        findings.append(f"Google Safe Browsing发现威胁: {threat_type} (平台: {platform})")
                
                return {
                    'is_malicious': bool(findings),
                    'findings': findings,
                    'threat_types': [match.get('threatType') for match in data.get('matches', [])]
                }
            elif response.status_code == 400:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'info': "URL格式无效"
                }
            elif response.status_code == 401:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': "API密钥无效"
                }
            elif response.status_code == 429:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': "请求频率超限，请稍后再试"
                }
        except requests.exceptions.Timeout:
            return {
                'is_malicious': False,
                'findings': [],
                'error': "请求超时"
            }
        except Exception as e:
            print(f"Google Safe Browsing检查失败: {str(e)}")
        
        return {
            'is_malicious': False,
            'findings': [],
            'error': "检查失败"
        }

    def check_ipqualityscore(self, url: str) -> Dict[str, Any]:
        """使用IPQualityScore检查URL"""
        try:
            # 确保URL格式正确
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # URL编码
            encoded_url = requests.utils.quote(url, safe='')
            
            # 使用正确的API端点
            api_url = f"https://www.ipqualityscore.com/api/json/url/{self.ipqs_api_key}/{encoded_url}"
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'application/json'
            }
            
            print(f"\n[IPQuality] IPQualityScore检查:")
            print(f"[IPQuality] 原始URL: {url}")
            print(f"[IPQuality] 编码后URL: {encoded_url}")
            print(f"[IPQuality] API URL: {api_url}")
            
            response = requests.get(api_url, headers=headers, timeout=10)
            print(f"[IPQuality] 响应状态码: {response.status_code}")
            print(f"[IPQuality] 响应内容: {response.text}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    findings = []
                    
                    # 检查各种风险指标
                    if data.get('unsafe'):
                        findings.append("IPQualityScore发现可疑URL")
                    if data.get('risk_score', 0) > 75:
                        findings.append(f"风险评分较高: {data.get('risk_score')}")
                    if data.get('spamming'):
                        findings.append("疑似垃圾网站")
                    if data.get('malware'):
                        findings.append("疑似恶意软件")
                    if data.get('phishing'):
                        findings.append("疑似钓鱼网站")
                    if data.get('suspicious'):
                        findings.append("疑似可疑网站")
                    if data.get('adult'):
                        findings.append("疑似成人内容")
                    if data.get('risky_tld'):
                        findings.append("疑似风险域名")
                    if data.get('category'):
                        findings.append(f"网站分类: {data.get('category')}")
                    
                    return {
                        'is_malicious': bool(findings),
                        'findings': findings,
                        'risk_score': data.get('risk_score', 0),
                        'domain_rank': data.get('domain_rank'),
                        'server': data.get('server'),
                        'content_type': data.get('content_type'),
                        'status_code': data.get('status_code'),
                        'page_size': data.get('page_size'),
                        'domain': data.get('domain'),
                        'ip_address': data.get('ip_address'),
                        'country_code': data.get('country_code'),
                        'language_code': data.get('language_code'),
                        'request_id': data.get('request_id')
                    }
                except json.JSONDecodeError as e:
                    print(f"JSON解析错误: {str(e)}")
                    return {
                        'is_malicious': False,
                        'findings': [],
                        'error': f"响应解析失败: {str(e)}"
                    }
            elif response.status_code == 401:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': "API密钥无效"
                }
            elif response.status_code == 429:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': "请求频率超限，请稍后再试"
                }
        except requests.exceptions.Timeout:
            return {
                'is_malicious': False,
                'findings': [],
                'error': "请求超时"
            }
        except Exception as e:
            print(f"IPQualityScore检查失败: {str(e)}")
            return {
                'is_malicious': False,
                'findings': [],
                'error': f"检查失败: {str(e)}"
            }

    def check_spamcop(self, domain: str) -> Dict[str, Any]:
        """使用SpamCop检查域名"""
        try:
            # SpamCop使用DNS查询方式
            query = f"{domain}.bl.spamcop.net"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            print(f"\n[spamcop] SpamCop检查:")
            print(f"[spamcop] 原始域名: {domain}")
            print(f"[spamcop] SpamCop查询域名: {query}")
            
            try:
                answers = resolver.resolve(query, 'A')
                findings = []
                
                # 如果域名在SpamCop黑名单中，会返回一个IP地址
                if answers:
                    findings.append("域名在SpamCop黑名单中")
                    for rdata in answers:
                        ip = str(rdata)
                        # 解析返回的IP地址对应的黑名单类型
                        if ip == "127.0.0.2":
                            findings.append("垃圾邮件发送者")
                        elif ip == "127.0.0.3":
                            findings.append("垃圾邮件服务器")
                        elif ip == "127.0.0.4":
                            findings.append("垃圾邮件中继")
                        elif ip == "127.0.0.5":
                            findings.append("垃圾邮件来源")
                        else:
                            findings.append(f"未知威胁类型 (IP: {ip})")
                    
                    return {
                        'is_malicious': True,
                        'findings': findings
                    }
            except dns.resolver.NXDOMAIN:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'info': "域名未在SpamCop黑名单中"
                }
            except dns.resolver.NoAnswer:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'info': "域名无SpamCop记录"
                }
        except Exception as e:
            print(f"SpamCop检查失败: {str(e)}")
            return {
                'is_malicious': False,
                'findings': [],
                'error': f"检查失败: {str(e)}"
            }

    def check_mxtoolbox(self, domain: str) -> Dict[str, Any]:
        """使用MXToolbox检查域名和IP黑名单（自动兼容域名和IP）"""
        try:
            api_url = "https://api.mxtoolbox.com/api/v1/lookup"
            headers = {
                'Authorization': 'e95e8592-b2e3-4f39-a4ed-a4cd4a172ba4',
                'Accept': 'application/json'
            }

            findings = []
            is_malicious = False

            # 1. 先查域名本身（如Spamhaus DBL等支持域名的黑名单）
            params_domain = {
                'command': 'blacklist',
                'argument': domain
            }
            response_domain = requests.get(api_url, headers=headers, params=params_domain, timeout=10)
            if response_domain.status_code == 200:
                data_domain = response_domain.json()
                if data_domain.get('Failed'):
                    for blacklist in data_domain.get('Failed', []):
                        if blacklist.get('Name'):
                            findings.append(f"域名列入黑名单: {blacklist.get('Name')}")
                            if blacklist.get('Description'):
                                findings.append(f"原因: {blacklist.get('Description')}")
                            is_malicious = True

            # 2. 如果输入不是IP，再查解析出来的IP
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
            if not is_ip:
                try:
                    ip_to_check = socket.gethostbyname(domain)
                    params_ip = {
                        'command': 'blacklist',
                        'argument': ip_to_check
                    }
                    response_ip = requests.get(api_url, headers=headers, params=params_ip, timeout=10)
                    if response_ip.status_code == 200:
                        data_ip = response_ip.json()
                        if data_ip.get('Failed'):
                            for blacklist in data_ip.get('Failed', []):
                                if blacklist.get('Name'):
                                    findings.append(f"IP列入黑名单: {blacklist.get('Name')}")
                                    if blacklist.get('Description'):
                                        findings.append(f"原因: {blacklist.get('Description')}")
                                    is_malicious = True
                except Exception as e:
                    findings.append(f"域名解析IP失败: {str(e)}")

            return {
                'is_malicious': is_malicious,
                'findings': findings,
                'info': "黑名单检查完成" if findings else "未被主流黑名单收录"
            }
        except Exception as e:
            print(f"MXToolbox检查失败: {str(e)}")
            return {
                'is_malicious': False,
                'findings': [],
                'error': f"检查失败: {str(e)}"
            }

    def check_threatminer(self, domain: str) -> Dict[str, Any]:
        """使用ThreatMiner检查域名"""
        try:
            # ThreatMiner API
            api_url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=1"
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0'
            }
            
            print(f"\n[ThreatMiner] ThreatMiner检查:")
            print(f"[ThreatMiner] 检查域名: {domain}")
            
            response = requests.get(api_url, headers=headers, timeout=10)
            print(f"[ThreatMiner] 响应状态码: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                findings = []
                
                # 检查域名是否在威胁情报中
                if data.get('status_code') == '200':
                    # 检查域名信息
                    if data.get('results'):
                        for result in data.get('results', []):
                            # 检查域名分类
                            if result.get('classification'):
                                findings.append(f"域名分类: {result.get('classification')}")
                            
                            # 检查威胁类型
                            if result.get('threat_type'):
                                findings.append(f"威胁类型: {result.get('threat_type')}")
                            
                            # 检查首次发现时间
                            if result.get('first_seen'):
                                findings.append(f"首次发现: {result.get('first_seen')}")
                            
                            # 检查最后更新
                            if result.get('last_updated'):
                                findings.append(f"最后更新: {result.get('last_updated')}")
                            
                            # 检查相关标签
                            if result.get('tags'):
                                findings.append(f"相关标签: {', '.join(result.get('tags', []))}")
                
                return {
                    'is_malicious': bool(findings),
                    'findings': findings,
                    'info': "检查完成" if findings else "未发现威胁"
                }
            elif response.status_code == 429:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': "请求频率超限"
                }
            else:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': f"API返回状态码: {response.status_code}"
                }
        except Exception as e:
            print(f"ThreatMiner检查失败: {str(e)}")
            return {
                'is_malicious': False,
                'findings': [],
                'error': f"检查失败: {str(e)}"
            }

    def check_pulsedive(self, indicator: str) -> Dict[str, Any]:
        """使用 Pulsedive 检查域名或 IP 是否存在风险"""
        try:
            # 使用正确的 API 端点和参数
            api_url = "https://pulsedive.com/api/explore.php"
            params = {
                "q": f"ioc={indicator}",
                "limit": 10,
                "pretty": 1,
                "key": self.pulsedive_api_key
            }

            print(f"\n[Pulsedive] 检查目标: {indicator}")

            response = requests.get(api_url, params=params, timeout=10)
            print(f"[Pulsedive] 响应状态码: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    findings = []
                    is_malicious = False
                    risk_level = 'none'
                    last_seen = None
                    first_seen = None

                    # 检查是否有结果
                    if isinstance(data, dict) and 'results' in data:
                        results = data['results']
                        if not isinstance(results, list):
                            results = [results]  # 如果结果不是列表，转换为列表
                        
                        for result in results:
                            if isinstance(result, dict):
                                # 检查风险等级
                                risk_level = result.get('risk', 'none')
                                if risk_level != 'none':
                                    findings.append(f"风险等级: {risk_level}")
                                    if risk_level in ['high', 'critical', 'medium']:
                                        is_malicious = True

                                # 检查时间信息
                                if result.get('stamp_added'):
                                    first_seen = result['stamp_added']
                                    findings.append(f"首次发现: {first_seen}")
                                if result.get('stamp_seen'):
                                    last_seen = result['stamp_seen']
                                    findings.append(f"最后发现: {last_seen}")

                                # 检查地理位置信息
                                summary = result.get('summary', {})
                                if isinstance(summary, dict) and summary.get('properties', {}).get('geo'):
                                    geo = summary['properties']['geo']
                                    location = []
                                    if geo.get('country'):
                                        location.append(geo['country'])
                                    if geo.get('region'):
                                        location.append(geo['region'])
                                    if geo.get('city'):
                                        location.append(geo['city'])
                                    if location:
                                        findings.append(f"地理位置: {', '.join(location)}")

                                # 检查 HTTP 信息
                                if isinstance(summary, dict) and summary.get('properties', {}).get('http'):
                                    http = summary['properties']['http']
                                    if http.get('++code'):
                                        findings.append(f"HTTP状态码: {http['++code']}")
                                    if http.get('++content-type'):
                                        findings.append(f"内容类型: {http['++content-type']}")

                    return {
                        'is_malicious': is_malicious,
                        'findings': findings,
                        'risk_level': risk_level,
                        'last_seen': last_seen,
                        'first_seen': first_seen
                    }
                except json.JSONDecodeError:
                    return {
                        'is_malicious': False,
                        'findings': [],
                        'error': "JSON 解析失败：响应内容不是合法 JSON"
                    }
            elif response.status_code == 401:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': "API 密钥无效"
                }
            elif response.status_code == 429:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': "请求频率超限"
                }
            else:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': f"API返回状态码: {response.status_code}"
                }
        except requests.exceptions.Timeout:
            return {
                'is_malicious': False,
                'findings': [],
                'error': "请求超时"
            }
        except Exception as e:
            print(f"Pulsedive 检查失败: {str(e)}")
            return {
                'is_malicious': False,
                'findings': [],
                'error': f"检查失败: {str(e)}"
            }


def display_check_results(results: Dict[str, Any]) -> None:
    """显示检查结果"""
    print("\n" + "="*50)
    print(f"{Fore.CYAN}威胁情报检查结果{Style.RESET_ALL}")
    print("="*50)
    
    # 显示基本信息
    print(f"\n{Fore.YELLOW}基本信息:{Style.RESET_ALL}")
    print(f"URL: {results['url']}")
    print(f"域名: {results['domain']}")
    if results.get('ip'):
        print(f"IP地址: {results['ip']}")
    
    # 显示风险等级和分数
    risk_color = {
        'critical': Fore.RED,
        'high': Fore.RED,
        'medium': Fore.YELLOW,
        'low': Fore.GREEN
    }.get(results['risk_level'], Fore.WHITE)
    
    print(f"\n{Fore.YELLOW}风险评估:{Style.RESET_ALL}")
    print(f"风险等级: {risk_color}{results['risk_level'].upper()}{Style.RESET_ALL}")
    print(f"风险分数: {risk_color}{results['risk_score']:.1f}{Style.RESET_ALL}")

    # 显示各个情报源的结果
    if results.get('source_results'):
        print(f"\n{Fore.YELLOW}详细检查结果:{Style.RESET_ALL}")
        
        # 定义所有情报源的显示顺序和权重
        sources = [
            ('urlscan', 'URLScan.io'),
            ('otx', 'AlienVault OTX'),
            ('urlhaus', 'URLhaus'),
            ('maltiverse', 'Maltiverse'),
            ('threatfox', 'ThreatFox'),
            ('virustotal', 'VirusTotal'),
            ('talos', 'Cisco Talos'),
            ('abuseipdb', 'AbuseIPDB'),
            ('abuse', 'Abuse.ch'),
            ('surbl', 'SURBL'),
            ('spamhaus', 'Spamhaus'),
            ('google_safebrowsing', 'Google Safe Browsing'),
            ('ipqualityscore', 'IPQualityScore'),
            ('spamcop', 'SpamCop'),
            ('mxtoolbox', 'MXToolbox'),
            ('threatminer', 'ThreatMiner'),
            ('pulsedive', 'Pulsedive'),
        ]
        
        # 按顺序显示每个情报源的结果
        for source_key, source_name in sources:
            if source_key in results['source_results']:
                print(f"\n{Fore.CYAN}{source_name} 检查结果:{Style.RESET_ALL}")
                source_result = results['source_results'][source_key]
                
                # 检查是否有错误
                if 'error' in source_result:
                    print(f"{Fore.RED}检查失败: {source_result['error']}{Style.RESET_ALL}")
                    continue
                
                # 显示威胁信息
                is_malicious = source_result.get('malicious') or source_result.get('is_malicious')
                if is_malicious:
                    print(f"{Fore.RED}发现威胁:{Style.RESET_ALL}")
                    if 'findings' in source_result:
                        for finding in source_result['findings']:
                            print(f"  - {finding}")
                else:
                    print(f"{Fore.GREEN}未发现威胁{Style.RESET_ALL}")
                
                # 显示额外信息
                if 'info' in source_result:
                    print(f"{Fore.BLUE}额外信息: {source_result['info']}{Style.RESET_ALL}")

    print("\n" + "="*50)
    print(f"{Fore.CYAN}检查结束{Style.RESET_ALL}")
    print("="*50 + "\n")

# 使用示例
if __name__ == "__main__":
    # 创建威胁情报检查器实例
    checker = ThreatIntelligence()
    
    while True:
        print("\n=== 威胁情报检查工具 ===")
        print("请输入要检查的URL/域名/IP地址（输入 'q' 退出）：")
        user_input = input().strip()
        
        if user_input.lower() == 'q':
            print("感谢使用，再见！")
            break
            
        print(f"\n开始检查: {user_input}")
        results = checker.check_url_with_multiple_sources(user_input)
        display_check_results(results)

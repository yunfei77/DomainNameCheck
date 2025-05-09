import requests
import json
import time
import hashlib
from typing import Dict, Any, List
import re
import dns.resolver
from urllib.parse import urlparse
import socket
import whois
from datetime import datetime
from colorama import Fore, Style, init
import base64

init(autoreset=True)

class ThreatIntelligence:
    def __init__(self):
        # 基础API密钥
        self.vt_api_key = ""
        self.abuseipdb_api_key = ""
        self.urlscan_api_key = ""
        self.otx_api_key = ""
        self.xforce_api_key = ""
        self.xforce_api_pass = ""
        self.abuse_api_key = ""  # 需要用户自己添加
        # self.hybrid_analysis_api_key = ""
        
        # 新增API密钥
        self.gsb_api_key = ""

        # 添加 Cloudflare Radar API 密钥
        self.cloudflare_api_token = ""  # 需要替换为你的 API Token"

        # self.cloudflare_api_token = ""

        # 初始化威胁情报缓存
        self.cache = {
            'urls': {},
            'domains': {},
            'ips': {}
        }
        
        # 加载本地威胁情报数据库（可以定期更新）
        self.load_local_threat_db()

    def load_local_threat_db(self):
        """加载本地威胁情报数据库"""
        try:
            # 这里可以添加你的本地恶意URL/域名/IP数据库
            self.malicious_domains = set([
                'malware.com',
                'phishing.com',
                # 添加更多已知恶意域名
            ])
            
            self.malicious_ips = set([
                '1.2.3.4',
                '5.6.7.8',
                # 添加更多已知恶意IP
            ])
            
        except Exception as e:
            print(f"加载本地威胁情报数据库失败: {str(e)}")
            self.malicious_domains = set()
            self.malicious_ips = set()

    def check_url_with_multiple_sources(self, url: str) -> Dict[str, Any]:
        """使用多个威胁情报源检查URL"""
        # 如果输入没有协议前缀，添加一个临时前缀用于解析
        if not url.startswith(('http://', 'https://')):
            parsed_url = urlparse('http://' + url)
            domain = parsed_url.netloc or url  # 如果netloc为空，使用原始输入
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
            'ip': ip_address,  # 添加IP地址
            'is_malicious': False,
            'risk_level': 'low',
            'risk_score': 0.0,
            'findings': [],
            'source_results': {}
        }

        try:
            # 定义所有检查函数及其权重
            checks = [
                ('urlscan', self.check_urlscan, 3.0),
                ('otx', self.check_otx, 3.0),
                ('urlhaus', self.check_urlhaus, 4.0),
                ('maltiverse', self.check_maltiverse, 3.0),
                ('threatfox', self.check_threatfox, 3.0),
                ('virustotal', self.check_virustotal, 3.0),
                ('talos', self.check_talos, 2.0),
                ('abuseipdb', self.check_abuseipdb, 3.0),
                ('abuse', self.check_abuse, 2.0),
                ('surbl', self.check_surbl, 3.0)
            ]

            # 执行所有检查
            for source_name, check_func, weight in checks:
                print(f"\n正在检查 {source_name.upper()}...")
                # 根据检查函数的需求传递URL或域名
                if source_name in ['urlhaus', 'virustotal', 'phishtank', 'google_safebrowsing']:
                    check_result = check_func(url)  # 使用完整URL
                else:
                    check_result = check_func(domain)  # 使用域名

                if check_result is not None:
                    result['source_results'][source_name] = check_result
                    if check_result.get('malicious') or check_result.get('is_malicious'):
                        result['is_malicious'] = True
                        result['risk_score'] += weight
                        if check_result.get('findings'):
                            result['findings'].extend(check_result['findings'])
            
            # 更新风险等级
            if result['risk_score'] >= 7.0:
                result['risk_level'] = 'critical'
            elif result['risk_score'] >= 5.0:
                result['risk_level'] = 'high'
            elif result['risk_score'] >= 3.0:
                result['risk_level'] = 'medium'

        except Exception as e:
            result['findings'].append(f"多源检查过程出错: {str(e)}")

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
            # 使用 v3 API
            api_url = "https://www.virustotal.com/api/v3/urls"
            
            # 对URL进行base64编码
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            headers = {
                'x-apikey': self.vt_api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            # 先获取URL的ID
            response = requests.get(f"{api_url}/{url_id}", headers=headers)
            
            if response.status_code == 404:
                # 如果URL不存在，先提交扫描
                submit_url = f"{api_url}"
                submit_data = {
                    'url': url
                }
                
                print(f"提交URL到VirusTotal进行扫描...")
                submit_response = requests.post(
                    submit_url, 
                    headers=headers, 
                    json=submit_data
                )
                
                if submit_response.status_code == 200:
                    print("URL已提交扫描，等待结果...")
                    # 等待几秒钟让扫描完成
                    time.sleep(5)
                    # 重新获取结果
                    response = requests.get(f"{api_url}/{url_id}", headers=headers)
                else:
                    return {
                        'malicious': False,
                        'findings': [],
                        'error': f"提交扫描失败: {submit_response.status_code} - {submit_response.text}"
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

    def check_phishtank(self, url: str) -> Dict[str, Any]:
        """使用PhishTank检查URL"""
        try:
            api_url = "https://checkurl.phishtank.com/checkurl/"
            data = {'url': url}
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Content-Type': 'application/x-www-form-urlencoded'  # 添加Content-Type
            }
            
            print(f"正在请求 PhishTank API...")
            print(f"API URL: {api_url}")
            print(f"URL: {url}")
            
            response = requests.post(api_url, data=data, headers=headers)
            print(f"API 响应状态码: {response.status_code}")
            print(f"API 响应内容: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                findings = []
                
                if data.get('in_database'):
                    findings.append(f"PhishTank发现钓鱼网站")
                    if data.get('verified'):
                        findings.append("已验证为钓鱼网站")
                
                return {
                    'is_malicious': data.get('in_database', False),
                    'findings': findings,
                    'verified': data.get('verified', False)
                }
        except Exception as e:
            print(f"PhishTank检查失败: {str(e)}")
        
        return {
            'is_malicious': False,
            'findings': [],
            'error': "检查失败"
        }

    def check_google_safebrowsing(self, url: str) -> Dict[str, Any]:
        """使用Google Safe Browsing检查URL"""
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_api_key}"
            data = {
                "client": {
                    "clientId": "url-checker",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            print(f"正在请求 Google Safe Browsing API...")
            print(f"API URL: {api_url}")
            print(f"URL: {url}")
            
            response = requests.post(api_url, json=data)
            print(f"API 响应状态码: {response.status_code}")
            print(f"API 响应内容: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                findings = []
                
                if data.get('matches'):
                    for match in data['matches']:
                        findings.append(f"Google Safe Browsing发现威胁: {match.get('threatType')}")
                
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
        except Exception as e:
            print(f"Google Safe Browsing检查失败: {str(e)}")
        
        return {
            'is_malicious': False,
            'findings': [],
            'error': "检查失败"
        }

    def check_spamhaus(self, domain: str) -> Dict[str, Any]:
        """使用Spamhaus检查域名"""
        try:
            # 使用正确的Spamhaus DBL API地址
            api_url = f"https://dbl.spamhaus.org/lookup/{domain}"
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'application/json'
            }
            
            print(f"正在请求 Spamhaus API...")
            print(f"API URL: {api_url}")
            print(f"域名: {domain}")
            
            response = requests.get(api_url, headers=headers)
            print(f"API 响应状态码: {response.status_code}")
            print(f"API 响应内容: {response.text}")
            
            if response.status_code == 200:
                findings = []
                data = response.json()
                
                if data.get('listed'):
                    findings.append(f"Spamhaus发现威胁: {data.get('reason', '未知威胁')}")
                    if data.get('category'):
                        findings.append(f"威胁类别: {data.get('category')}")
                
                return {
                    'is_malicious': data.get('listed', False),
                    'findings': findings,
                    'category': data.get('category'),
                    'reason': data.get('reason')
                }
            else:
                return {
                    'is_malicious': False,
                    'findings': [],
                    'error': f"API返回状态码: {response.status_code}",
                    'info': "无法确定域名状态"
                }
        except Exception as e:
            print(f"Spamhaus检查失败: {str(e)}")
        
        return {
            'is_malicious': False,
            'findings': [],
            'error': "检查失败"
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
            
            print(f"\n[DEBUG] SURBL检查:")
            print(f"[DEBUG] 原始域名: {domain}")
            print(f"[DEBUG] SURBL查询域名: {query}")
            
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

def display_check_results(results: Dict[str, Any]) -> None:
    """显示检查结果"""
    print("\n=== 威胁情报检查结果 ===")
    
    # 显示基本信息
    print(f"\nURL: {results['url']}")
    print(f"域名: {results['domain']}")
    if results.get('ip'):
        print(f"IP地址: {results['ip']}")
    print(f"风险等级: {Fore.RED if results['risk_level'] in ['critical', 'high'] else Fore.YELLOW if results['risk_level'] == 'medium' else Fore.GREEN}{results['risk_level'].upper()}{Style.RESET_ALL}")
    print(f"风险分数: {Fore.RED if results['risk_score'] >= 5.0 else Fore.YELLOW}{results['risk_score']:.1f}{Style.RESET_ALL}")

    # 显示各个情报源的结果
    if results.get('source_results'):
        print("\n各情报源检查结果:")
        
        # 定义所有情报源的显示顺序
        sources = [
            'urlscan', 'otx', 'urlhaus', 'maltiverse', 'threatfox',
            'virustotal', 'talos', 'abuseipdb', 'abuse', 'surbl'
        ]
        
        # 按顺序显示每个情报源的结果
        for source in sources:
            if source in results['source_results']:
                print(f"\n{source.upper()} 结果:")
                source_result = results['source_results'][source]
                
                # 检查是否有错误
                if 'error' in source_result:
                    print(f"{Fore.YELLOW}检查失败: {source_result['error']}{Style.RESET_ALL}")
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

    print("\n=== 检查结束 ===")

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

# DomainNameCheck
多情报源检查域名安全
# URL 威胁情报检查工具

这是一个基于 Python 的多源威胁情报检查工具，可以对 URL、域名和 IP 地址进行全面的安全分析。

## 功能特点

- 支持多个威胁情报源的集成检查
- 自动解析域名和 IP 地址
- 提供详细的风险评分和威胁分析

## 支持的威胁情报源

1. **VirusTotal**
   - 提供全面的恶意软件检测
   - 支持 URL 扫描和结果分析

2. **URLScan.io**
   - 提供网站行为分析
   - 检测可疑行为和恶意活动

3. **AlienVault OTX**
   - 提供威胁情报数据
   - 包含恶意域名和 IP 信息

4. **URLhaus**
   - 专注于恶意 URL 检测
   - 提供详细的威胁分类

5. **Maltiverse**
   - 提供域名和 IP 的威胁分析
   - 包含黑名单检查

6. **ThreatFox**
   - 提供 IOC 威胁情报
   - 支持多种威胁类型检测

7. **Cisco Talos**
   - 提供域名声誉检查
   - 包含垃圾邮件和恶意活动检测

8. **AbuseIPDB**
   - 提供 IP 地址声誉检查
   - 包含滥用报告统计

9. **Abuse.ch**
   - 提供误报列表检查
   - 支持域名验证

10. **SURBL**
    - 提供垃圾邮件域名检测
    - 包含多种黑名单检查

## 安装要求

```bash
pip install requests
pip install dnspython
pip install python-whois
pip install colorama
```

## 使用方法

1. 配置 API 密钥：
   - 在 `ThreatIntelligence` 类的 `__init__` 方法中设置各个服务的 API 密钥

2. 运行检查：
```python
from urlcheck import ThreatIntelligence

# 创建检查器实例
checker = ThreatIntelligence()

# 检查 URL
results = checker.check_url_with_multiple_sources("example.com")
```

## 输出结果

检查结果包含以下信息：
- URL/域名/IP 地址
- 风险等级（critical/high/medium/low）
- 风险评分
- 各情报源的详细检查结果
- 发现的威胁和可疑行为

## 风险评分说明

- 0-3.0: 低风险
- 3.0-5.0: 中等风险
- 5.0-7.0: 高风险
- 7.0+: 严重风险

## 注意事项

1. 需要有效的 API 密钥才能使用各个威胁情报源
2. 部分 API 可能有请求频率限制
3. 建议适当调整检查间隔，避免触发 API 限制
4. 本地威胁情报数据库需要定期更新

## 错误处理

- 自动处理 API 请求失败
- 提供详细的错误信息
- 支持重试机制
- 异常情况下的优雅降级

## 贡献

欢迎提交 Issue 和 Pull Request 来帮助改进这个工具。

## 许可证

MIT License

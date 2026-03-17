# This file is auto-generated to provide the AI Assistant with summarized security skills.
ALL_SKILLS_SUMMARY = {
    "api-security-testing": {
        "title": "API安全测试",
        "overview": "API安全测试是确保API接口安全性的重要环节。本技能提供API安全测试的方法、工具和最佳实践。",
        "methodologies": [
            "1. API发现",
            "使用目录扫描",
            "使用Burp Suite被动扫描",
            "浏览应用，观察API调用",
            "分析JavaScript文件"
        ],
        "payloads": [
            "gobuster dir -u https://target.com -w api-wordlist.txt",
            "**JWT测试：**",
            "**水平权限：**",
            "**垂直权限：**",
            "**SQL注入：**",
            "**命令注入：**",
            "**XXE：**",
            "**测试速率限制：**",
            "**创建测试集合：**",
            "1. 导入API文档"
        ]
    },
    "business-logic-testing": {
        "title": "业务逻辑漏洞测试",
        "overview": "业务逻辑漏洞是应用程序在业务处理流程中的设计缺陷，可能导致未授权操作、数据篡改、资金损失等。本技能提供业务逻辑漏洞的检测、利用和防护方法。",
        "methodologies": [
            "1. 工作流分析",
            "注册流程",
            "购买流程",
            "提现流程",
            "审核流程"
        ],
        "payloads": [
            "正常流程: 步骤1 → 步骤2 → 步骤3",
            "测试: 直接访问步骤3",
            "测试: 步骤1 → 步骤3（跳过步骤2）",
            "**负数测试：**",
            "**同时发送请求：**",
            "**修改订单状态：**",
            "**回退状态：**",
            "**负数价格：**",
            "**修改前端价格：**",
            "**API价格修改：**"
        ]
    },
    "cloud-security-audit": {
        "title": "云安全审计",
        "overview": "云安全审计是评估云环境安全性的重要环节。本技能提供云安全审计的方法、工具和最佳实践，涵盖AWS、Azure、GCP等主流云平台。",
        "methodologies": [],
        "payloads": [
            "aws iam list-users",
            "aws iam list-policies",
            "aws iam list-user-policies --user-name username",
            "aws s3 ls",
            "aws s3api get-bucket-policy --bucket bucketname",
            "aws s3api get-bucket-acl --bucket bucketname",
            "aws ec2 describe-security-groups",
            "aws ec2 describe-security-groups --group-ids sg-xxx",
            "aws cloudtrail describe-trails",
            "aws cloudtrail get-trail-status --name trailname"
        ]
    },
    "command-injection-testing": {
        "title": "命令注入漏洞测试",
        "overview": "命令注入是一种通过应用程序执行系统命令的漏洞。当应用程序将用户输入直接传递给系统命令时，攻击者可以执行任意命令。本技能提供命令注入的检测、利用和防护方法。",
        "methodologies": [
            "1. 识别命令执行点",
            "Ping功能",
            "DNS查询",
            "文件操作",
            "系统信息"
        ],
        "payloads": [
            "**常见功能：**",
            "- Ping功能",
            "- DNS查询",
            "**测试Payload：**",
            "**时间延迟检测：**",
            "**外带数据：**",
            "**DNS外带：**",
            "**Linux：**",
            "**Windows：**",
            "**读取文件：**"
        ]
    },
    "container-security-testing": {
        "title": "容器安全测试",
        "overview": "容器安全测试是确保容器化应用安全性的重要环节。本技能提供容器安全测试的方法、工具和最佳实践，涵盖Docker、Kubernetes等容器技术。",
        "methodologies": [],
        "payloads": [
            "trivy image nginx:latest",
            "trivy image --input nginx.tar",
            "trivy image --severity HIGH,CRITICAL nginx:latest",
            "docker run -d --name clair clair:latest",
            "clair-scanner --ip 192.168.1.100 nginx:latest",
            "docker run --rm --net host --pid host --userns host --cap-add audit_control \\",
            "-e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \\",
            "-v /etc:/etc:ro \\",
            "**安全最佳实践：**",
            "**检查容器权限：**"
        ]
    },
    "csrf-testing": {
        "title": "CSRFCross-Site Request Forgery (CSRF)测试",
        "overview": "CSRF（Cross-Site Request Forgery）是一种利用用户已登录状态进行未授权操作的攻击方式。本技能提供CSRF漏洞的检测、利用和防护方法。",
        "methodologies": [
            "1. 识别敏感操作",
            "密码修改",
            "邮箱修改",
            "转账操作",
            "权限变更"
        ],
        "payloads": [
            "<!-- 有Token保护 -->",
            "<form method=\"POST\" action=\"/change-password\">",
            "<input type=\"hidden\" name=\"csrf_token\" value=\"abc123\">",
            "// 正常请求",
            "Referer: https://target.com/change-password",
            "// 测试绕过",
            "<form action=\"https://target.com/api/transfer\" method=\"POST\" id=\"csrf\">",
            "<input type=\"hidden\" name=\"to\" value=\"attacker_account\">",
            "<input type=\"hidden\" name=\"amount\" value=\"10000\">",
            "<!-- 使用form表单提交JSON -->"
        ]
    },
    "deserialization-testing": {
        "title": "反序列化漏洞测试",
        "overview": "反序列化漏洞是一种利用应用程序反序列化不可信数据导致的漏洞，可能导致远程代码执行、拒绝服务等。本技能提供反序列化漏洞的检测、利用和防护方法。",
        "methodologies": [
            "1. 识别序列化数据"
        ],
        "payloads": [
            "AC ED 00 05 (十六进制)",
            "rO0 (Base64)",
            "O:8:\"stdClass\"",
            "a:2:{s:4:\"test\";s:4:\"data\";}",
            "\\x80\\x03",
            "**常见Gadget链：**",
            "- CommonsCollections1-7",
            "- Spring1-2",
            "**魔术方法利用：**",
            "- __destruct()"
        ]
    },
    "file-upload-testing": {
        "title": "文件上传漏洞测试",
        "overview": "文件上传功能是Web应用常见功能，但存在多种安全风险。本技能提供文件上传漏洞的检测、利用和防护方法。",
        "methodologies": [
            "1. Detecção básica",
            ".php, .jsp, .asp, .aspx",
            ".php3, .php4, .php5, .phtml",
            ".jspx, .jspf",
            ".htaccess, .htpasswd"
        ],
        "payloads": [
            "// 可被绕过",
            "if (!file.name.endsWith('.jpg')) {",
            "alert('只允许上传图片');",
            "**未过滤文件名：**",
            "**可预测的文件名：**",
            "**测试各种文件类型：**",
            "- .php, .jsp, .asp, .aspx",
            "- .php3, .php4, .php5, .phtml",
            "**测试大小写：**",
            "**修改Content-Type：**"
        ]
    },
    "idor-testing": {
        "title": "IDOR不安全的直接对象引用测试",
        "overview": "IDOR（Insecure Direct Object Reference）是一种访问控制漏洞，当应用程序直接使用用户提供的输入来访问资源，而未验证用户是否有权限访问该资源时发生。本技能提供IDOR漏洞的检测、利用和防护方法。",
        "methodologies": [
            "1. 识别直接对象引用",
            "用户ID",
            "文件ID/文件名",
            "订单ID",
            "文档ID"
        ],
        "payloads": [
            "**常见资源类型：**",
            "- 用户ID",
            "- 文件ID/文件名",
            "**UUID测试：**",
            "**文件名测试：**",
            "**访问其他用户资源：**",
            "**访问其他用户文件：**",
            "**普通用户访问管理员资源：**",
            "**枚举用户资料：**",
            "**访问其他用户文件：**"
        ]
    },
    "incident-response": {
        "title": "安全事件响应",
        "overview": "安全事件响应是处理安全事件的关键流程。本技能提供安全事件响应的方法、工具和最佳实践。",
        "methodologies": [],
        "payloads": [
            "index=security event_type=\"failed_login\"",
            "index=security | stats count by src_ip",
            "index=security | timechart count by event_type",
            "GET /logs/_search",
            "{",
            "\"query\": {",
            "volatility -f memory.dump imageinfo",
            "volatility -f memory.dump --profile=Win7SP1x64 pslist",
            "volatility -f memory.dump --profile=Win7SP1x64 memdump -p 1234 -D output/",
            "wireshark -i eth0"
        ]
    },
    "ldap-injection-testing": {
        "title": "LDAP注入漏洞测试",
        "overview": "LDAP注入是一种类似于SQL注入的漏洞，利用LDAP查询语句的构造缺陷，可能导致信息泄露、权限绕过等。本技能提供LDAP注入的检测、利用和防护方法。",
        "methodologies": [
            "1. 识别LDAP输入点",
            "用户登录",
            "用户搜索",
            "目录浏览",
            "权限验证"
        ],
        "payloads": [
            "**基础查询：**",
            "**需要转义的字符：**",
            "- `(` `)` - 括号",
            "- `*` - 通配符",
            "**测试逻辑操作符：**",
            "**基础绕过：**",
            "**更精确的绕过：**",
            "**枚举用户：**",
            "**获取属性：**",
            "**方法1：逻辑绕过**"
        ]
    },
    "mobile-app-security-testing": {
        "title": "移动应用安全测试",
        "overview": "移动应用安全测试是确保移动应用安全性的重要环节。本技能提供移动应用安全测试的方法、工具和最佳实践，涵盖Android和iOS平台。",
        "methodologies": [],
        "payloads": [
            "apktool d app.apk",
            "cat app/AndroidManifest.xml",
            "find app/smali -name \"*.smali\"",
            "jadx -d output app.apk",
            "find output -name \"*.java\"",
            "docker run -it -p 8000:8000 opensecurity/mobsf",
            "// Hook函数",
            "Java.perform(function() {",
            "var MainActivity = Java.use(\"com.example.MainActivity\");",
            "objection -g com.example.app explore"
        ]
    },
    "network-penetration-testing": {
        "title": "网络渗透测试",
        "overview": "网络渗透测试是评估网络基础设施安全性的重要环节。本技能提供网络渗透测试的方法、工具和最佳实践。",
        "methodologies": [],
        "payloads": [
            "nmap -sn 192.168.1.0/24",
            "nmap -sS -p- 192.168.1.100",
            "nmap -sV -sC 192.168.1.100",
            "masscan -p1-65535 192.168.1.0/24 --rate=1000",
            "smbclient -L //192.168.1.100 -N",
            "enum4linux -U 192.168.1.100",
            "nmap --script smb-enum-shares,smb-enum-users 192.168.1.100",
            "rpcclient -U \"\" -N 192.168.1.100",
            "nmap --script rpc-enum 192.168.1.100",
            "snmpwalk -v2c -c public 192.168.1.100"
        ]
    },
    "secure-code-review": {
        "title": "安全代码审查",
        "overview": "安全代码审查是识别代码中安全漏洞的重要方法。本技能提供安全代码审查的方法、工具和最佳实践。",
        "methodologies": [],
        "payloads": [
            "sonar-scanner",
            "sourceanalyzer -b project build.sh",
            "sourceanalyzer -b project -scan",
            "**危险代码：**",
            "**安全代码：**",
            "**危险代码：**",
            "**安全代码：**",
            "**危险代码：**",
            "**安全代码：**",
            "**危险代码：**"
        ]
    },
    "security-automation": {
        "title": "安全自动化",
        "overview": "安全自动化是提高安全运营效率的重要手段。本技能提供安全自动化的方法、工具和最佳实践。",
        "methodologies": [],
        "payloads": [
            "**使用OpenVAS API：**",
            "**Jenkins Pipeline：**",
            "**GitHub Actions：**",
            "**使用OWASP ZAP：**",
            "**使用Burp Suite：**",
            "**使用Splunk：**",
            "**使用ELK Stack：**"
        ]
    },
    "security-awareness-training": {
        "title": "安全意识培训",
        "overview": "安全意识培训是提高组织整体安全水平的重要措施。本技能提供安全意识培训的方法、内容和最佳实践。",
        "methodologies": [],
        "payloads": []
    },
    "sql-injection-testing": {
        "title": "Habilidades de Teste de Injeção SQL",
        "overview": "SQL注入是一种常见且危险的Web应用漏洞。本技能提供了系统化的SQL注入Métodos de Teste、检测技术和利用策略。",
        "methodologies": [
            "1. 参数识别",
            "识别所有用户输入点：URL参数、POST数据、HTTP头、Cookie等",
            "重点关注：id、search、filter、sort等参数",
            "使用Burp Suite或类似工具拦截和修改请求"
        ],
        "payloads": [
            "sqlmap -u \"http://target.com/page?id=1\"",
            "sqlmap -u \"http://target.com/page\" --data=\"id=1\" --method=POST",
            "sqlmap -u \"http://target.com/page?id=1\" --dbms=mysql",
            "原始：' UNION SELECT NULL--",
            "绕过1：'/**/UNION/**/SELECT/**/NULL--",
            "绕过2：'%55nion%20select%20null--"
        ]
    },
    "ssrf-testing": {
        "title": "SSRFServer-Side Request Forgery (SSRF)测试",
        "overview": "SSRF（Server-Side Request Forgery）是一种利用服务器发起请求的漏洞，可以访问内网资源、进行端口扫描或绕过防火墙。本技能提供SSRF漏洞的检测、利用和防护方法。",
        "methodologies": [
            "1. 识别SSRF输入点",
            "URL预览/截图",
            "文件上传（远程URL）",
            "Webhook回调",
            "API代理"
        ],
        "payloads": [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "file:///etc/passwd",
            "file:///C:/Windows/System32/drivers/etc/hosts",
            "127.0.0.1 → 2130706433 (十进制)",
            "127.0.0.1 → 0x7f000001 (十六进制)"
        ]
    },
    "vulnerability-assessment": {
        "title": "漏洞评估",
        "overview": "漏洞评估是识别和评估系统漏洞的重要环节。本技能提供漏洞评估的方法、工具和最佳实践。",
        "methodologies": [],
        "payloads": [
            "gvm-setup",
            "nmap --script vuln target",
            "nmap --script smb-vuln-ms17-010 target",
            "zap.sh",
            "zap-cli quick-scan http://target.com",
            "zap-cli full-scan http://target.com",
            "sonar-scanner",
            "低影响    中影响    高影响",
            "高可能性    中       高       严重",
            "中可能性    低       中       高"
        ]
    },
    "xpath-injection-testing": {
        "title": "XPath注入漏洞测试",
        "overview": "XPath注入是一种类似于SQL注入的漏洞，利用XPath查询语句的构造缺陷，可能导致信息泄露、认证绕过等。本技能提供XPath注入的检测、利用和防护方法。",
        "methodologies": [
            "1. 识别XPath输入点",
            "用户登录",
            "数据搜索",
            "XML数据查询",
            "配置查询"
        ],
        "payloads": [
            "**基础查询：**",
            "**常用函数：**",
            "- `text()` - 获取文本内容",
            "- `count()` - 计数",
            "**测试逻辑操作符：**",
            "**基础绕过：**",
            "**更精确的绕过：**",
            "**枚举用户：**",
            "**获取节点数量：**",
            "**获取特定节点：**"
        ]
    },
    "xss-testing": {
        "title": "Habilidades de Teste de XSS",
        "overview": "Cross-Site Scripting (XSS)(XSS)允许攻击者在受害者的浏览器中执行恶意JavaScript代码。本技能涵盖Refletido、Armazenado和Baseado em DOMXSS的Métodos de Teste。",
        "methodologies": [
            "基础Payload"
        ],
        "payloads": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
            "<div onmouseover=alert('XSS')>hover</div>",
            "<input onfocus=alert('XSS') autofocus>",
            "<a href=\"javascript:alert('XSS')\">click</a>"
        ]
    },
    "xxe-testing": {
        "title": "XXE XMLXML External Entity (XXE)测试",
        "overview": "XXE（XML External Entity）注入是一种利用XML解析器处理外部实体的漏洞。本技能提供XXE漏洞的检测、利用和防护方法。",
        "methodologies": [
            "1. 识别XML输入点",
            "文件上传功能",
            "API接口接受XML数据",
            "SOAP请求",
            "Office文档处理"
        ],
        "payloads": [
            "**测试网络请求（SSRF）：**",
            "**当响应不直接显示内容时：**",
            "**使用参数实体：**",
            "**evil.dtd内容：**",
            "**读取本地文件：**",
            "**Windows路径：**",
            "**内网探测：**",
            "**端口扫描：**",
            "**Billion Laughs攻击：**",
            "**docx文件结构：**"
        ]
    }
}

class MasterSkillsManager:
    @staticmethod
    def get_master_prompt():
        """Generates a dense, high-impact prompt block containing all 22 skills."""
        prompt = "[MASTER SKILLS KNOWLEDGE BASE - OMNISCIENTE PERFORMANCE]\n"
        for folder, data in ALL_SKILLS_SUMMARY.items():
            prompt += f"\n### SKILL: {data['title']}\n"
            if data['overview']:
                prompt += f"- Info: {data['overview']}\n"
            if data['methodologies']:
                prompt += f"- Methods: {', '.join(data['methodologies'][:3])}\n"
            if data['payloads']:
                prompt += f"- Key Payloads: {', '.join(data['payloads'][:4])}\n"
        return prompt

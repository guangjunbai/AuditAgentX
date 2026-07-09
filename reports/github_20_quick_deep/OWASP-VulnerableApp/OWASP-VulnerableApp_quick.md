# OWASP-VulnerableApp 安全审计报告

> 生成工具：AuditAgentX　生成时间：2026-07-09 10:01:29 UTC

## 1. 执行摘要

本次审计对象为 OWASP-VulnerableApp，来源为 https://github.com/SasanLabs/VulnerableApp，项目主要语言为 Java、JavaScript、Shell，框架识别结果为 Spring、Spring Boot，共解析 197 个文件、24219 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC 并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 147 条风险，其中 Critical 0 条、High 56 条、Medium 83 条、Low 8 条；静态分析覆盖 147 条，动态验证覆盖 0 条，其中 0 条已复现。主要风险类型集中在 Hardcoded Secret(22)、no-new-privileges(20)、writable-filesystem-service(20)、github-actions-mutable-action-tag(19)，总体风险评级为 HIGH。

**总体风险等级：HIGH**

### 1.1 项目概况总结

项目 OWASP-VulnerableApp 来源于 https://github.com/SasanLabs/VulnerableApp，主要语言为 Java、JavaScript、Shell，框架为 Spring、Spring Boot，共 197 个文件、24219 行代码。

### 1.2 漏洞结果总结

本次共发现 147 条漏洞，其中 Critical 0 条、High 56 条、Medium 83 条、Low 8 条。

**静态分析总结：** 静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 147 条静态风险。主要来源分布为 semgrep(108)、custom-taint(39)。这些结果先作为候选项进入 VerifyAgent，避免仅凭规则命中直接下结论。

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
| 项目名称 | OWASP-VulnerableApp |
| 来源 | https://github.com/SasanLabs/VulnerableApp |
| 语言 | Java, JavaScript, Shell |
| 框架 | Spring, Spring Boot |
| 文件数 | 197 |
| 代码行数 | 24219 |
| 扫描任务 | scan_201d5e74（static / done） |

## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | 0 |
| High | 56 |
| Medium | 83 |
| Low | 8 |
| **合计** | **147** |

## 4. 漏洞明细


### 4.1 command-injection-process-builder（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\commandInjection\CommandInjection.java:52`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.2 tainted-file-path（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\fileupload\PreflightController.java:46`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.3 tainted-url-host（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\rfi\UrlParamBasedRFI.java:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.4 tainted-url-host（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\rfi\UrlParamBasedRFI.java:63`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.5 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\BlindSQLInjectionVulnerability.java:58`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.6 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\BlindSQLInjectionVulnerability.java:82`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.7 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\BlindSQLInjectionVulnerability.java:132`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.8 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\ErrorBasedSQLInjectionVulnerability.java:67`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.9 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\ErrorBasedSQLInjectionVulnerability.java:112`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.10 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\ErrorBasedSQLInjectionVulnerability.java:160`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.11 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\ErrorBasedSQLInjectionVulnerability.java:211`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.12 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\UnionBasedSQLInjectionVulnerability.java:69`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.13 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\UnionBasedSQLInjectionVulnerability.java:84`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.14 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\UnionBasedSQLInjectionVulnerability.java:99`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.15 tainted-url-host（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\ssrf\SSRFVulnerability.java:66`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.16 tainted-url-host（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\ssrf\SSRFVulnerability.java:129`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.17 tainted-url-host（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\ssrf\SSRFVulnerability.java:146`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.18 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:56`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.19 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:72`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.20 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:91`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.21 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:115`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.22 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:147`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.23 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:170`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.24 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:200`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.25 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSWithHtmlTagInjection.java:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.26 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSWithHtmlTagInjection.java:66`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.27 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSWithHtmlTagInjection.java:91`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.28 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSWithHtmlTagInjection.java:111`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.29 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSWithHtmlTagInjection.java:131`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.30 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\resources\attackvectors\JWTVulnerabilityPayload.properties:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.31 detected-bcrypt-hash（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\resources\scripts\Authentication\db\data.sql:27`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.32 detected-bcrypt-hash（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\resources\scripts\Authentication\db\data.sql:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.33 detected-bcrypt-hash（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\resources\scripts\Authentication\db\data.sql:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.34 detected-private-key（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\resources\static\templates\JWTVulnerability\keys\private_key.pem:5`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.35 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/cryptographicFailures/repo/CryptographicFailuresSeeder.java:84`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String level10Secret = "aa123456";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.36 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/idor/IDORLoginService.java:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
private static final String INVALID_TOKEN = "Invalid token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.37 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/idor/IDORVulnerability.java:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
private static final String INVALID_TOKEN = "Invalid token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.38 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/idor/IDORVulnerability.java:26`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
private static final String PROVIDE_LOGIN_OR_TOKEN = "Provide login or token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.39 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/jwt/bean/JWTUtils.java:65`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
public static final String BEGIN_PRIVATE_KEY_TOKEN = "-----BEGIN PRIVATE KEY-----";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.40 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/jwt/bean/JWTUtils.java:67`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
public static final String END_PRIVATE_KEY_TOKEN = "-----END PRIVATE KEY-----";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.41 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/jwt/bean/JWTUtils.java:68`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
public static final String BEGIN_PUBLIC_KEY_TOKEN = "-----BEGIN PUBLIC KEY-----";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.42 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/jwt/bean/JWTUtils.java:69`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
public static final String END_PUBLIC_KEY_TOKEN = "-----END PUBLIC KEY-----";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.43 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/jwt/keys/JWTAlgorithmKMS.java:41`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
private static final String KEY_STORE_PASSWORD = "changeIt";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.44 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/internal/utility/PasswordHashingUtilsTest.java:41`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String rawPassword = "securePassword123";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.45 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/internal/utility/PasswordHashingUtilsTest.java:53`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String password = "mySecretPassword";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.46 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORLoginServiceTest.java:47`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String rawPassword = "P@ssw0rd!2026";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.47 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORLoginServiceTest.java:83`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String rawPassword = "P@ssw0rd!2026";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.48 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORLoginServiceTest.java:116`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String rawPassword = "P@ssw0rd!2026";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.49 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORVulnerabilityTest.java:38`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String validToken = "valid-token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.50 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORVulnerabilityTest.java:59`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String validToken = "valid-token-level2";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.51 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORVulnerabilityTest.java:163`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String invalidToken = "invalid-token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.52 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/ldapInjection/LDAPInjectionVulnerabilityTest.java:57`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String username = "*)(uid=*", password = "alicePass123";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.53 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/ldapInjection/LDAPInjectionVulnerabilityTest.java:90`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String password = "antrikshPass123";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.54 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/sessionManagement/SessionManagementServiceTest.java:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
private static final String PASSWORD = "password123";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.55 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/sessionManagement/SessionManagementServiceTest.java:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
private static final String BAD_PASSWORD = "wrong-password";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.56 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/sessionManagement/SessionManagementServiceTest.java:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
private static final String FIXED_TOKEN = "attacker-fixed-token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.57 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\create-release.yml:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.58 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\create-release.yml:29`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.59 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\create-release.yml:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.60 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\docker.yml:20`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.61 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\docker.yml:25`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.62 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\docker.yml:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.63 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\docker.yml:34`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.64 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\docker.yml:37`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.65 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\docker.yml:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.66 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\docker.yml:46`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.67 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\docker.yml:55`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.68 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\gradle.yml:15`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.69 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\gradle.yml:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.70 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\gradle.yml:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.71 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\onboard_sasanlabs.yml:19`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.72 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\onboard_sasanlabs.yml:51`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.73 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\onboard_sasanlabs.yml:83`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.74 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\onboard_sasanlabs.yml:96`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.75 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\.github\workflows\stats.yml:16`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.76 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.local.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.77 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.local.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.78 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.local.yml:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.79 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.local.yml:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.80 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.local.yml:10`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.81 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.local.yml:10`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.82 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.local.yml:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.83 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.local.yml:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.84 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.local.yml:28`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.85 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.local.yml:28`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.86 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.prod.yml:4`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.87 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.prod.yml:4`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.88 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.prod.yml:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.89 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.prod.yml:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.90 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.without_llm.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.91 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.without_llm.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.92 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.without_llm.yml:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.93 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.without_llm.yml:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.94 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.without_llm.yml:9`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.95 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.without_llm.yml:9`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.96 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.without_llm.yml:12`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.97 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.without_llm.yml:12`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.98 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.without_llm.yml:27`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.99 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.without_llm.yml:27`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.100 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.101 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.102 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:8`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.103 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:8`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.104 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.105 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.106 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.107 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.108 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.109 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.110 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:57`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.111 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:57`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.112 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:76`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.113 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:76`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.114 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:95`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.115 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\docker-compose.yml:95`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.116 jdbc-sql-formatted-string（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\configuration\VulnerableAppConfiguration.java:134`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.117 spring-sqli（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\configuration\VulnerableAppConfiguration.java:135`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.118 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.119 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:58`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.120 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:76`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.121 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:91`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.122 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:120`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.123 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:136`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.124 ecb-cipher（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\internal\utility\EncryptionUtils.java:88`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.125 use-of-aes-ecb（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\internal\utility\EncryptionUtils.java:88`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.126 spring-sqli（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\authentication\AuthLoginService.java:51`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.127 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\fileupload\PreflightController.java:37`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.128 cookie-missing-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\idor\IDORLoginController.java:136`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.129 cookie-missing-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\idor\IDORLoginController.java:145`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.130 cookie-missing-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\idor\IDORLoginController.java:161`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.131 Weak Cryptography（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/internal/utility/EncryptionUtils.java:88`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.132 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/internal/utility/PasswordHashingUtils.java:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
MD5("MD5"),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.133 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/internal/utility/PasswordHashingUtils.java:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
SHA1("SHA-1"),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.134 Weak Cryptography（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/internal/utility/PasswordHashingUtils.java:150`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
Cipher des = Cipher.getInstance("DES/ECB/NoPadding", "BC");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.135 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/cryptographicFailures/repo/CryptographicFailuresSeeder.java:68`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
// Level 6: MD5 (Broken Hash)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.136 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/fileupload/UnrestrictedFileUpload.java:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
private static final Random RANDOM = new Random(new Date().getTime());
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.137 XSS（MEDIUM）

- 文件：`src/main/resources/static/templates/ClickjackingVulnerability/LEVEL_1/ClickjackingVulnerability.js:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if (!doc || doc.body.innerHTML === "") {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.138 XSS（MEDIUM）

- 文件：`src/main/resources/static/templates/CryptographicFailures/LEVEL_1/CryptographicFailures.js:44`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
resultDiv.innerHTML = "<strong>Result:</strong> " + data.content;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.139 XSS（MEDIUM）

- 文件：`src/main/resources/static/templates/CryptographicFailures/LEVEL_1/CryptographicFailures.js:47`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
resultDiv.innerHTML = "<strong>Result:</strong> " + data.content;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.140 XSS（LOW）

- 文件：`scripts/productionize/startup_script.sh:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.141 XSS（LOW）

- 文件：`scripts/productionize/startup_script.sh:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo ".env generated with random credentials"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.142 XSS（LOW）

- 文件：`src/main/resources/static/vulnerableApp.js:338`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
document.getElementById("helpText").innerHTML = helpText;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.143 XSS（LOW）

- 文件：`src/main/resources/static/templates/ClickjackingVulnerability/LEVEL_1/ClickjackingVulnerability.js:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
responseDiv.innerHTML = lines.join("<br/>");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.144 XSS（LOW）

- 文件：`src/main/resources/static/templates/ClickjackingVulnerability/LEVEL_4/ClickjackingVulnerability.js:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
r.innerHTML = lines.join("<br/>");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.145 XSS（LOW）

- 文件：`src/main/resources/static/templates/CryptographicFailures/LEVEL_1/CryptographicFailures.js:8`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
challengeDiv.innerHTML = "<strong>" + data.content + "</strong>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.146 XSS（LOW）

- 文件：`src/main/resources/static/templates/PathTraversal/LEVEL_1/PathTraversal.js:35`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
document.getElementById("Information").innerHTML = tableInformation;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.147 XSS（LOW）

- 文件：`src/main/resources/static/templates/SSRFVulnerability/LEVEL_1/SSRF.js:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
document.getElementById("projectsResponse").innerHTML = tableInformation;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。





## 5. 关键风险

- HIGH command-injection-process-builder 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\commandInjection\CommandInjection.java:52，状态为 confirmed。
- HIGH tainted-file-path 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\fileupload\PreflightController.java:46，状态为 confirmed。
- HIGH tainted-url-host 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\rfi\UrlParamBasedRFI.java:43，状态为 confirmed。
- HIGH tainted-url-host 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\rfi\UrlParamBasedRFI.java:63，状态为 confirmed。
- HIGH tainted-sql-string 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_e8a0436f\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\BlindSQLInjectionVulnerability.java:58，状态为 confirmed。


## 6. 修改建议

- **P0 优先修复 Critical/High 漏洞：** 先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。
- **P1 按漏洞类型批量治理：** 对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。
- **P1 补充动态验证覆盖：** 为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。
- **P2 纳入持续审计流程：** 将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。


## 7. 结论

综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 HIGH 风险水平。建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
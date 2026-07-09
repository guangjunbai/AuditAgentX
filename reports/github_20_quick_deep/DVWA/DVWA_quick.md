# DVWA 安全审计报告

> 生成工具：AuditAgentX　生成时间：2026-07-09 09:14:21 UTC

## 1. 执行摘要

本次审计对象为 DVWA，来源为 https://github.com/digininja/DVWA，项目主要语言为 PHP、JavaScript、Python，框架识别结果为 未识别，共解析 179 个文件、13777 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC 并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 187 条风险，其中 Critical 0 条、High 54 条、Medium 95 条、Low 38 条；静态分析覆盖 187 条，动态验证覆盖 0 条，其中 0 条已复现。主要风险类型集中在 Weak Hash(31)、XSS(25)、SQL Injection(18)、tainted-sql-string(14)，总体风险评级为 HIGH。

**总体风险等级：HIGH**

### 1.1 项目概况总结

项目 DVWA 来源于 https://github.com/digininja/DVWA，主要语言为 PHP、JavaScript、Python，框架为 未识别，共 179 个文件、13777 行代码。

### 1.2 漏洞结果总结

本次共发现 187 条漏洞，其中 Critical 0 条、High 54 条、Medium 95 条、Low 38 条。

**静态分析总结：** 静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 187 条静态风险。主要来源分布为 custom-taint(111)、semgrep(75)、bandit(1)。这些结果先作为候选项进入 VerifyAgent，避免仅凭规则命中直接下结论。

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
| 项目名称 | DVWA |
| 来源 | https://github.com/digininja/DVWA |
| 语言 | PHP, JavaScript, Python |
| 框架 |  |
| 文件数 | 179 |
| 代码行数 | 13777 |
| 扫描任务 | scan_594023d6（static / done） |

## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | 0 |
| High | 54 |
| Medium | 95 |
| Low | 38 |
| **合计** | **187** |

## 4. 漏洞明细


### 4.1 run-shell-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\docker-image.yml:29`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.2 md5-loose-equality（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\login.php:41`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.3 phpinfo-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\phpinfo.php:8`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.4 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\api\src\HealthController.php:88`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.5 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\bac\source\low.php:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.6 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\bac\source\low.php:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.7 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\bac\source\low.php:79`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.8 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\bac\source\medium.php:21`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.9 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\bac\source\medium.php:28`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.10 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\bac\source\medium.php:71`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.11 md5-loose-equality（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\brute\source\high.php:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.12 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\brute\source\low.php:12`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.13 md5-loose-equality（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\brute\source\low.php:15`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.14 md5-loose-equality（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\brute\source\medium.php:17`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.15 md5-loose-equality（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\captcha\source\impossible.php:46`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.16 md5-loose-equality（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\cryptography\source\ecb_attack.php:92`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.17 md5-loose-equality（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\csrf\test_credentials.php:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.18 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\high.php:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.19 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\high.php:30`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.20 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\impossible.php:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.21 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\impossible.php:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.22 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\low.php:10`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.23 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\low.php:14`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.24 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\medium.php:19`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.25 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\medium.php:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.26 md5-loose-equality（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\javascript\index.php:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.27 md5-loose-equality（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\javascript\index.php:57`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.28 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\sqli\source\low.php:10`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.29 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\sqli\source\low.php:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.30 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\sqli_blind\source\high.php:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.31 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\sqli_blind\source\high.php:33`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.32 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\sqli_blind\source\low.php:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.33 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\sqli_blind\source\low.php:32`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.34 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\sqli_blind\source\medium.php:34`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.35 eval-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\view_help.php:20`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.36 eval-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\view_help.php:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.37 Command Injection（HIGH）

- 文件：`vulnerabilities/view_help.php:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
eval( '?>' . file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.php" ) . '<?php ' );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.38 Command Injection（HIGH）

- 文件：`vulnerabilities/view_help.php:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
eval( '?>' . file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.{$locale}.php" ) . '<?php ' );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.39 SQL Injection（HIGH）

- 文件：`vulnerabilities/bac/source/low.php:8`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.40 SQL Injection（HIGH）

- 文件：`vulnerabilities/bac/source/medium.php:8`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.41 SQL Injection（HIGH）

- 文件：`vulnerabilities/brute/source/low.php:13`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_e
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.42 Hardcoded Secret（HIGH）

- 文件：`vulnerabilities/captcha/source/high.php:30`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "' LIMIT 1;";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.43 Hardcoded Secret（HIGH）

- 文件：`vulnerabilities/captcha/source/low.php:60`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.44 Hardcoded Secret（HIGH）

- 文件：`vulnerabilities/captcha/source/medium.php:68`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.45 Hardcoded Secret（HIGH）

- 文件：`vulnerabilities/cryptography/source/token_library_high.php:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$token = "userid:2";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.46 Hardcoded Secret（HIGH）

- 文件：`vulnerabilities/cryptography/source/token_library_high.php:40`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
print "Clear text token: " . $token . "\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.47 Hardcoded Secret（HIGH）

- 文件：`vulnerabilities/cryptography/source/token_library_impossible.php:40`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$token = "userid:2";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.48 Hardcoded Secret（HIGH）

- 文件：`vulnerabilities/csrf/source/low.php:16`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.49 Hardcoded Secret（HIGH）

- 文件：`vulnerabilities/csrf/source/medium.php:18`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.50 Command Injection（HIGH）

- 文件：`vulnerabilities/exec/source/impossible.php:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cmd = shell_exec( 'ping  ' . $target );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.51 Command Injection（HIGH）

- 文件：`vulnerabilities/exec/source/low.php:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cmd = shell_exec( 'ping  ' . $target );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.52 Command Injection（HIGH）

- 文件：`vulnerabilities/exec/source/low.php:14`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cmd = shell_exec( 'ping  -c 4 ' . $target );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.53 Command Injection（HIGH）

- 文件：`vulnerabilities/exec/source/medium.php:19`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cmd = shell_exec( 'ping  ' . $target );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.54 Hardcoded Secret（HIGH）

- 文件：`vulnerabilities/sqli/test.php:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$password = "password";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.55 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\codeql-analysis.yml:37`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.56 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\codeql-analysis.yml:45`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.57 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\codeql-analysis.yml:56`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.58 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\codeql-analysis.yml:70`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.59 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\docker-image.yml:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.60 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\docker-image.yml:16`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.61 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\docker-image.yml:19`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.62 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\docker-image.yml:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.63 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\pytest.yml:19`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.64 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\shiftleft-analysis.yml:19`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.65 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\shiftleft-analysis.yml:24`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.66 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\shiftleft-analysis.yml:33`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.67 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\vulnerable.yml:25`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.68 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\instructions.php:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.69 php-permissive-cors（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\api\gen_openapi.php:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.70 php-permissive-cors（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\api\public\index.php:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.71 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\api\src\HealthController.php:88`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.72 openssl-decrypt-validate（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\api\src\Token.php:39`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.73 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\high.php:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.74 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\high.php:30`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.75 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\impossible.php:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.76 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\impossible.php:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.77 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\low.php:10`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.78 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\low.php:14`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.79 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\medium.php:19`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.80 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\exec\source\medium.php:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.81 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\fi\source\high.php:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.82 eval-detected（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\javascript\source\high.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.83 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\javascript\source\high.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.84 unlink-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\upload\source\impossible.php:54`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.85 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\view_help.php:20`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.86 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\view_help.php:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.87 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\view_source.php:63`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.88 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\view_source.php:67`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.89 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\view_source.php:68`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.90 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\view_source_all.php:14`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.91 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\view_source_all.php:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.92 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\view_source_all.php:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.93 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\view_source_all.php:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.94 Path Traversal（MEDIUM）

- 文件：`instructions.php:26`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$instructions = file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.95 SSRF（MEDIUM）

- 文件：`instructions.php:26`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$instructions = file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.96 Weak Hash（MEDIUM）

- 文件：`login.php:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass = md5( $pass );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.97 SQL Injection（MEDIUM）

- 文件：`login.php:33`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = @mysqli_query($GLOBALS["___mysqli_ston"],  $query );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.98 Weak Randomness（MEDIUM）

- 文件：`dvwa/includes/dvwaPage.inc.php:88`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
* generate a new random id. This is good security practice because it
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.99 Weak Hash（MEDIUM）

- 文件：`dvwa/includes/dvwaPage.inc.php:651`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$_SESSION[ 'session_token' ] = md5( uniqid() );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.100 SQL Injection（MEDIUM）

- 文件：`dvwa/includes/DBMS/MySQL.php:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if( !@((bool)mysqli_query($GLOBALS["___mysqli_ston"], "USE " . $_DVWA[ 'db_database' ])) ) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.101 Weak Hash（MEDIUM）

- 文件：`dvwa/includes/DBMS/MySQL.php:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
('1','admin','admin','admin',MD5('password'),'{$avatarUrl}admin.jpg', NOW(), '0'),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.102 Weak Hash（MEDIUM）

- 文件：`dvwa/includes/DBMS/MySQL.php:56`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
('2','Gordon','Brown','gordonb',MD5('abc123'),'{$avatarUrl}gordonb.jpg', NOW(), '0'),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.103 Weak Hash（MEDIUM）

- 文件：`dvwa/includes/DBMS/MySQL.php:57`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
('3','Hack','Me','1337',MD5('charley'),'{$avatarUrl}1337.jpg', NOW(), '0'),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.104 Weak Hash（MEDIUM）

- 文件：`dvwa/includes/DBMS/MySQL.php:58`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
('4','Pablo','Picasso','pablo',MD5('letmein'),'{$avatarUrl}pablo.jpg', NOW(), '0'),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.105 Weak Hash（MEDIUM）

- 文件：`dvwa/includes/DBMS/MySQL.php:59`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
('5','Bob','Smith','smithy',MD5('password'),'{$avatarUrl}smithy.jpg', NOW(), '0');";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.106 Weak Hash（MEDIUM）

- 文件：`dvwa/includes/DBMS/PGSQL.php:61`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
('1','admin','admin','admin',MD5('password'),'{$baseUrl}admin.jpg'),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.107 Weak Hash（MEDIUM）

- 文件：`dvwa/includes/DBMS/PGSQL.php:62`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
('2','Gordon','Brown','gordonb',MD5('abc123'),'{$baseUrl}gordonb.jpg'),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.108 Weak Hash（MEDIUM）

- 文件：`dvwa/includes/DBMS/PGSQL.php:63`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
('3','Hack','Me','1337',MD5('charley'),'{$baseUrl}1337.jpg'),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.109 Weak Hash（MEDIUM）

- 文件：`dvwa/includes/DBMS/PGSQL.php:64`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
('4','Pablo','Picasso','pablo',MD5('letmein'),'{$baseUrl}pablo.jpg'),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.110 Weak Hash（MEDIUM）

- 文件：`dvwa/includes/DBMS/PGSQL.php:65`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
('5','bob','smith','smithy',MD5('password'),'{$baseUrl}smithy.jpg');";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.111 Path Traversal（MEDIUM）

- 文件：`vulnerabilities/view_help.php:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
eval( '?>' . file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.php" ) . '<?php ' );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.112 SSRF（MEDIUM）

- 文件：`vulnerabilities/view_help.php:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
eval( '?>' . file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.php" ) . '<?php ' );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.113 Path Traversal（MEDIUM）

- 文件：`vulnerabilities/view_help.php:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
eval( '?>' . file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.{$locale}.php" ) . '<?php ' );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.114 SSRF（MEDIUM）

- 文件：`vulnerabilities/view_help.php:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
eval( '?>' . file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.{$locale}.php" ) . '<?php ' );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.115 XSS（MEDIUM）

- 文件：`vulnerabilities/view_source_all.php:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$lowsrc = str_replace(array('$html .='), array('echo'), $lowsrc);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.116 XSS（MEDIUM）

- 文件：`vulnerabilities/view_source_all.php:19`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$medsrc = str_replace(array('$html .='), array('echo'), $medsrc);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.117 XSS（MEDIUM）

- 文件：`vulnerabilities/view_source_all.php:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$highsrc = str_replace(array('$html .='), array('echo'), $highsrc);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.118 XSS（MEDIUM）

- 文件：`vulnerabilities/view_source_all.php:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$impsrc = str_replace(array('$html .='), array('echo'), $impsrc);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.119 Weak Randomness（MEDIUM）

- 文件：`vulnerabilities/api/src/Order.php:34`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$id = mt_rand(50,100);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.120 Weak Randomness（MEDIUM）

- 文件：`vulnerabilities/api/src/User.php:30`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$id = mt_rand(50,100);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.121 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/brute/source/high.php:16`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass = md5( $pass );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.122 SQL Injection（MEDIUM）

- 文件：`vulnerabilities/brute/source/high.php:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_e
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.123 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/brute/source/impossible.php:16`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass = md5( $pass );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.124 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/brute/source/low.php:9`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass = md5( $pass );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.125 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/brute/source/medium.php:11`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass = md5( $pass );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.126 SQL Injection（MEDIUM）

- 文件：`vulnerabilities/brute/source/medium.php:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_e
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.127 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/captcha/source/high.php:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass_new = md5( $pass_new );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.128 SQL Injection（MEDIUM）

- 文件：`vulnerabilities/captcha/source/high.php:31`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.129 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/captcha/source/impossible.php:14`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass_new  = md5( $pass_new );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.130 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/captcha/source/impossible.php:19`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass_conf = md5( $pass_conf );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.131 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/captcha/source/impossible.php:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass_curr = md5( $pass_curr );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.132 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/captcha/source/low.php:57`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass_new = md5( $pass_new );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.133 SQL Injection（MEDIUM）

- 文件：`vulnerabilities/captcha/source/low.php:61`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.134 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/captcha/source/medium.php:65`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass_new = md5( $pass_new );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.135 SQL Injection（MEDIUM）

- 文件：`vulnerabilities/captcha/source/medium.php:69`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.136 XSS（MEDIUM）

- 文件：`vulnerabilities/csp/source/jsonp.php:12`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $callback . "(".json_encode($outp).")";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.137 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/csrf/test_credentials.php:19`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass = md5( $pass );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.138 SQL Injection（MEDIUM）

- 文件：`vulnerabilities/csrf/test_credentials.php:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = @mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>'.  mysqli_connect_error() . '.<br />Try <a href="setup.php">installing again</a>.</pre>' );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.139 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/csrf/source/high.php:39`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass_new = md5( $pass_new );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.140 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/csrf/source/impossible.php:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass_curr = md5( $pass_curr );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.141 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/csrf/source/impossible.php:29`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass_new = md5( $pass_new );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.142 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/csrf/source/low.php:12`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass_new = md5( $pass_new );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.143 SQL Injection（MEDIUM）

- 文件：`vulnerabilities/csrf/source/low.php:17`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.144 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/csrf/source/medium.php:14`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$pass_new = md5( $pass_new );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.145 SQL Injection（MEDIUM）

- 文件：`vulnerabilities/csrf/source/medium.php:19`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.146 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/javascript/index.php:43`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if ($token == md5(str_rot13("success"))) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.147 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/javascript/source/low.php:18`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
document.getElementById("token").value = md5(rot13(phrase));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.148 SQL Injection（MEDIUM）

- 文件：`vulnerabilities/sqli/source/medium.php:12`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.149 Weak Hash（MEDIUM）

- 文件：`vulnerabilities/weak_id/source/high.php:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cookie_value = md5($_SESSION['last_session_id_high']);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.150 assert_used（LOW）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\tests\test_url.py:124`
- 来源：bandit
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
123 
124     assert len(broken_urls) == 0, "Broken URLs Detected."

```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.151 SQL Injection（LOW）

- 文件：`login.php:40`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = @mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.152 SQL Injection（LOW）

- 文件：`dvwa/includes/dvwaPage.inc.php:571`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
|| !@((bool)mysqli_query($GLOBALS["___mysqli_ston"], "USE " . $_DVWA[ 'db_database' ])) ) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.153 Path Traversal（LOW）

- 文件：`dvwa/js/dvwaPage.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
window.open(URL, '" + id + "', 'toolbar=0,scrollbars=1,location=0,statusbar=0,menubar=0,resizable=1,width=800,height=300,left=540,top=250');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.154 Command Injection（LOW）

- 文件：`dvwa/js/dvwaPage.js:7`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
//eval("page" + id + " = window.open(URL, '" + id + "', 'toolbar=0,scrollbars=1,location=0,statusbar=0,menubar=0,resizable=1,width=800,height=300,left=540,top=250');");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.155 Path Traversal（LOW）

- 文件：`dvwa/js/dvwaPage.js:7`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
//eval("page" + id + " = window.open(URL, '" + id + "', 'toolbar=0,scrollbars=1,location=0,statusbar=0,menubar=0,resizable=1,width=800,height=300,left=540,top=250');");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.156 XSS（LOW）

- 文件：`hackable/flags/fi.php:17`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $line3 . "\n\n<br /><br />\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.157 XSS（LOW）

- 文件：`hackable/flags/fi.php:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo base64_decode( $line4 );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.158 XSS（LOW）

- 文件：`vulnerabilities/view_source.php:64`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$source = str_replace( array( '$html .=' ), array( 'echo' ), $source );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.159 XSS（LOW）

- 文件：`vulnerabilities/api/source/low.php:34`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
user_info.innerHTML = 'User details: ' + user_json.name + ' (' + level + ')';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.160 SSRF（LOW）

- 文件：`vulnerabilities/api/source/low.php:49`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
fetch(url, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.161 XSS（LOW）

- 文件：`vulnerabilities/api/source/medium.php:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
user_info.innerHTML = 'User details: ' + user_json.name + ' (' + level + ')';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.162 SSRF（LOW）

- 文件：`vulnerabilities/api/source/medium.php:33`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
fetch(url, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.163 SSRF（LOW）

- 文件：`vulnerabilities/api/source/medium.php:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
fetch(url, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.164 Command Injection（LOW）

- 文件：`vulnerabilities/api/src/HealthController.php:88`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
exec ("ping -c 4 " . $target, $output, $ret_var);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.165 XSS（LOW）

- 文件：`vulnerabilities/authbypass/authbypass.js:43`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
cell0.innerHTML = user['user_id'] + '<input type="hidden" id="user_id_' + user['user_id'] + '" name="user_id" value="' + user['user_id'] + '" />';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.166 XSS（LOW）

- 文件：`vulnerabilities/authbypass/authbypass.js:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
cell1.innerHTML = '<input type="text" id="first_name_' + user['user_id'] + '" name="first_name" value="' + user['first_name'] + '" />';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.167 XSS（LOW）

- 文件：`vulnerabilities/authbypass/authbypass.js:47`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
cell2.innerHTML = '<input type="text" id="surname_' + user['user_id'] + '" name="surname" value="' + user['surname'] + '" />';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.168 XSS（LOW）

- 文件：`vulnerabilities/authbypass/authbypass.js:49`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
cell3.innerHTML = '<input type="button" value="Update" onclick="submit_change(' + user['user_id'] + ')" />';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.169 SQL Injection（LOW）

- 文件：`vulnerabilities/authbypass/change_user_details.php:48`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_e
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.170 XSS（LOW）

- 文件：`vulnerabilities/cryptography/source/xor_theory.php:12`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
//echo 'i=' . $i . ', ' . 'j=' . $j . ', ' . $outText{$i} . '<br />'; // For debugging
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.171 XSS（LOW）

- 文件：`vulnerabilities/csp/source/jsonp_impossible.php:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "solveSum (".json_encode($outp).")";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.172 Path Traversal（LOW）

- 文件：`vulnerabilities/csrf/index.php:38`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
window.open(\"" . DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/csrf/test_credentials.php\", \"_blank\",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.173 XSS（LOW）

- 文件：`vulnerabilities/csrf/help/help.php:70`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<p>Reference: <?php echo dvwaExternalLinkUrlGet( 'https://owasp.org/www-community/attacks/csrf' ); ?></p>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.174 SQL Injection（LOW）

- 文件：`vulnerabilities/csrf/source/high.php:44`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.175 Command Injection（LOW）

- 文件：`vulnerabilities/exec/source/high.php:26`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cmd = shell_exec( 'ping  ' . $target );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.176 Command Injection（LOW）

- 文件：`vulnerabilities/exec/source/high.php:30`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cmd = shell_exec( 'ping  -c 4 ' . $target );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.177 Command Injection（LOW）

- 文件：`vulnerabilities/exec/source/impossible.php:26`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cmd = shell_exec( 'ping  -c 4 ' . $target );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.178 Command Injection（LOW）

- 文件：`vulnerabilities/exec/source/medium.php:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cmd = shell_exec( 'ping  -c 4 ' . $target );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.179 Command Injection（LOW）

- 文件：`vulnerabilities/javascript/source/high.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var a=['fromCharCode','toString','replace','BeJ','\x5cw+','Lyg','SuR','(w(){\x273M\x203L\x27;q\x201l=\x273K\x203I\x203J\x20T\x27;q\x201R=1c\x202I===\x271n\x27;q\x20Y=1R?2I:{};p(Y.3N){1R=1O}q\x202L=!1R
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.180 XSS（LOW）

- 文件：`vulnerabilities/sqli/test.php:12`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $record["first_name"] .", ". $record["password"] ."<br />";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.181 XSS（LOW）

- 文件：`vulnerabilities/sqli/source/high.php:33`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo 'Caught exception: ' . $e->getMessage();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.182 XSS（LOW）

- 文件：`vulnerabilities/sqli/source/high.php:47`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "Error in fetch ".$sqlite_db->lastErrorMsg();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.183 XSS（LOW）

- 文件：`vulnerabilities/sqli/source/low.php:36`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo 'Caught exception: ' . $e->getMessage();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.184 XSS（LOW）

- 文件：`vulnerabilities/sqli/source/low.php:50`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "Error in fetch ".$sqlite_db->lastErrorMsg();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.185 XSS（LOW）

- 文件：`vulnerabilities/sqli/source/medium.php:32`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo 'Caught exception: ' . $e->getMessage();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.186 XSS（LOW）

- 文件：`vulnerabilities/sqli/source/medium.php:46`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "Error in fetch ".$sqlite_db->lastErrorMsg();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.187 XSS（LOW）

- 文件：`vulnerabilities/xss_d/index.php:53`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
document.write("<option value='" + lang + "'>" + $decodeURI(lang) + "</option>");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。





## 5. 关键风险

- HIGH run-shell-injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\.github\workflows\docker-image.yml:29，状态为 confirmed。
- HIGH md5-loose-equality 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\login.php:41，状态为 confirmed。
- HIGH phpinfo-use 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\phpinfo.php:8，状态为 confirmed。
- HIGH exec-use 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\api\src\HealthController.php:88，状态为 confirmed。
- HIGH tainted-sql-string 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_7918e435\vulnerabilities\bac\source\low.php:22，状态为 confirmed。


## 6. 修改建议

- **P0 优先修复 Critical/High 漏洞：** 先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。
- **P1 按漏洞类型批量治理：** 对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。
- **P1 补充动态验证覆盖：** 为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。
- **P2 纳入持续审计流程：** 将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。


## 7. 结论

综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 HIGH 风险水平。建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
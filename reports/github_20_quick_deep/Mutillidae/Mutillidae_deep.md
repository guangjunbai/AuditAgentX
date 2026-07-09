# Mutillidae 安全审计报告

> 生成工具：AuditAgentX　生成时间：2026-07-09 10:00:58 UTC

## 1. 执行摘要

本次审计对象为 Mutillidae，来源为 https://github.com/webpwnized/mutillidae，项目主要语言为 PHP、JavaScript、Shell，框架识别结果为 未识别，共解析 191 个文件、39411 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC 并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 336 条风险，其中 Critical 0 条、High 32 条、Medium 112 条、Low 192 条；静态分析覆盖 336 条，动态验证覆盖 1 条，其中 0 条已复现。主要风险类型集中在 XSS(182)、github-actions-mutable-action-tag(29)、Command Injection(25)、SQL Injection(18)，总体风险评级为 HIGH。

**总体风险等级：HIGH**

### 1.1 项目概况总结

项目 Mutillidae 来源于 https://github.com/webpwnized/mutillidae，主要语言为 PHP、JavaScript、Shell，框架为 未识别，共 191 个文件、39411 行代码。

### 1.2 漏洞结果总结

本次共发现 336 条漏洞，其中 Critical 0 条、High 32 条、Medium 112 条、Low 192 条。

**静态分析总结：** 静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 336 条静态风险。主要来源分布为 custom-taint(265)、semgrep(71)。这些结果先作为候选项进入 VerifyAgent，避免仅凭规则命中直接下结论。

**动态验证总结：** 动态验证阶段对 1 条漏洞保存了运行证据，其中 0 条具备可复现结果。报告中的 Source、Sink、调用路径、PoC 和 runtime 证据共同构成证据链。

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
| 项目名称 | Mutillidae |
| 来源 | https://github.com/webpwnized/mutillidae |
| 语言 | PHP, JavaScript, Shell |
| 框架 |  |
| 文件数 | 191 |
| 代码行数 | 39411 |
| 扫描任务 | scan_ae28a44b（full / done） |

## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | 0 |
| High | 32 |
| Medium | 112 |
| Low | 192 |
| **合计** | **336** |

## 4. 漏洞明细


### 4.1 curl-ssl-verifypeer-off（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\classes\RemoteFileHandler.php:62`
- 来源：semgrep
- 置信度：0.55
- 已验证：是
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。


**证据链：**

- 知识增强：CWE-22 / A01:2021 Broken Access Control、A05:2021 Security Misconfiguration
- 知识库验证条件：

  1. Confirm the user-controlled value is concatenated or joined into a filesystem path.

  2. Check whether the code canonicalizes the path (realpath/abspath) and enforces an allowlisted base directory.

  3. If a local target runs, send ../ or encoded ..%2f payloads for a known file (app config, /etc/passwd) and look for file contents in the response.

  4. If no target exists, record dynamic_verdict=not_executed instead of not_reproduced.

- 误报判据：

  1. The resolved path is validated to stay under an allowlisted base directory.

  2. The filename is a fixed server-side constant or comes from a strict allowlist.

  3. The framework normalizes and rejects traversal sequences before use.

- 知识库修复建议：Canonicalize the path and confirm it stays under an allowlisted base directory.；Reject traversal sequences and use safe file APIs.

- Source：`unknown (parameter $pPage)`
- Sink：`curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false) at line 62`

- 调用路径：

  1. path：RemoteFileHandler::remoteSiteIsReachable($pPage)


- 利用路径：User-controlled parameter $pPage -> RemoteFileHandler::remoteSiteIsReachable() -> curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false) -> curl_exec() makes HTTP request without verifying SSL certificate
- 触发位置：`RemoteFileHandler.php:62`
- Payload：`http://127.0.0.1:4444/AUDITAGENTX_RCE_1337 / https://self-signed.badssl.com/`
- Docker 沙箱：launch_not_detected（健康检查 failed，镜像 `auditagentx-scanae28a44b`，启动命令 `N/A`）
- 动态验证状态：not_executed
- 命中特征：`N/A`
- 响应状态：N/A
- 请求：`N/A`
- 原因：未配置本地授权靶场 base_url，未执行动态 HTTP 探测

- 动态证据流：

  1. source：unknown (parameter $pPage)

  2. sink：curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false) at line 62

  3. payload：http://127.0.0.1:4444/AUDITAGENTX_RCE_1337

  4. response：{'status': None, 'matched_indicator': '', 'reason': '未配置本地授权靶场 base_url，未执行动态 HTTP 探测'}


- Harness：unsafe_harness_blocked，触发=否，原因=unsafe_harness_blocked: php real network
- 验证裁决：静态=confirmed；动态=not_runtime_verifiable；最终=statically_verified
- Skill：`{'name': '', 'version': None}`
- 证据链日志：候选漏洞由 AuditAgent 产生；VerifyAgent 独立复核通过；ExploitAgent 生成利用方案: CURLOPT_SSL_VERIFYPEER disabled (SSL certificate verification disabled)；HTTP 动态验证跳过: 未配置本地授权靶场 base_url，未执行动态 HTTP 探测；未配置本地授权靶场 base_url，未执行动态 HTTP 探测；Fuzzing Harness 验证: unsafe_harness_blocked；Docker 沙箱: launch_not_detected（健康检查 failed）；安全知识增强: CWE-22




### 4.2 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\database-offline.php:40`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.3 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\database-offline.php:46`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.4 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\database-offline.php:52`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.5 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\database-offline.php:86`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.6 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\database-offline.php:92`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.7 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\database-offline.php:98`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.8 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\dns-lookup.php:165`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.9 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\echo.php:148`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.10 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\edit-account-profile.php:125`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.11 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\includes\hints\jwt-hint.inc:46`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.12 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\includes\hints\jwt-hint.inc:50`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.13 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\includes\hints\jwt-hint.inc:76`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.14 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\includes\hints\jwt-hint.inc:100`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.15 phpinfo-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\phpinfo.php:29`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.16 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\test-connectivity.php:94`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.17 md5-loose-equality（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\view-user-privilege-level.php:131`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.18 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\rest\ws-dns-lookup.php:100`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.19 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\rest\ws-echo.php:95`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.20 eval-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\soap\lib\nusoap.php:4188`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.21 eval-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\soap\lib\nusoap.php:8186`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.22 eval-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\soap\lib\nusoap.php:8189`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.23 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\soap\ws-dns-lookup.php:147`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.24 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\soap\ws-echo.php:131`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.25 Command Injection（HIGH）

- 文件：`src/echo.php:148`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<pre class="output">'.shell_exec("echo " . $lMessage).'</pre>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.26 Command Injection（HIGH）

- 文件：`src/pen-test-tool-lookup.php:213`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
gPenTestToolsJSON = eval("(" + gPenTestToolsJSONString + ")");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.27 Command Injection（HIGH）

- 文件：`src/test-connectivity.php:95`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
shell_exec("curl --silent -H 'Origin: http://$lCurrentOrigin' " . $lServerURL) .
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.28 Hardcoded Secret（HIGH）

- 文件：`src/user-info-xpath.php:191`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lXPathQueryString = "//Employee[UserName='{USERNAME}' and Password='{PASSWORD}']";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.29 Hardcoded Secret（HIGH）

- 文件：`src/ajax/jwt.php:88`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if($lObfuscatePassword) { $row->password = "********"; }
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.30 Hardcoded Secret（HIGH）

- 文件：`src/classes/MySQLHandler.php:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
static public $MUTILLIDAE_DBV2_PASSWORD = "mutillidae";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.31 Hardcoded Secret（HIGH）

- 文件：`src/classes/MySQLHandler.php:56`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
static public $SAMURAI_WTF_PASSWORD = "samurai";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.32 Insecure Deserialization（HIGH）

- 文件：`src/webservices/soap/lib/nusoap.php:8588`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return (!is_null($s)) ? unserialize($s) : null;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.33 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\build-scan-push-to-dockerhub.yml:34`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.34 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\build-scan-push-to-dockerhub.yml:41`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.35 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\build-scan-push-to-dockerhub.yml:58`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.36 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\build-scan-push-to-dockerhub.yml:62`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.37 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\build-scan-push-to-dockerhub.yml:66`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.38 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\build-scan-push-to-dockerhub.yml:73`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.39 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\build-scan-push-to-dockerhub.yml:92`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.40 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\build-scan-push-to-dockerhub.yml:101`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.41 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\build-scan-push-to-dockerhub.yml:115`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.42 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\build-scan-push-to-dockerhub.yml:122`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.43 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\build-scan-push-to-dockerhub.yml:131`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.44 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-application-with-stackhawk.yml:37`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.45 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-application-with-stackhawk.yml:45`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.46 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-application-with-stackhawk.yml:95`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.47 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-application-with-stackhawk.yml:102`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.48 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-application-with-stackhawk.yml:115`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.49 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-codeql.yml:36`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.50 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-codeql.yml:41`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.51 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-codeql.yml:47`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.52 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-owasp-dependency-check.yml:32`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.53 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-owasp-dependency-check.yml:38`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.54 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-owasp-dependency-check.yml:53`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.55 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-semgrep.yml:40`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.56 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-semgrep.yml:60`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.57 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-semgrep.yml:68`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.58 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-snyk-code.yml:37`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.59 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-snyk-code.yml:57`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.60 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-trufflehog.yml:36`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.61 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\.github\workflows\scan-with-trufflehog.yml:44`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.62 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\content-security-policy.php:119`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.63 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\dns-lookup.php:165`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.64 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\echo.php:148`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.65 react-unsanitized-method（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\javascript\ddsmoothmenu\ddsmoothmenu.js:137`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.66 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\javascript\jQuery\jquery.js:2786`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.67 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\javascript\jQuery\jquery.js:2883`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.68 prototype-pollution-loop（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\javascript\jQuery\jquery.js:4754`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.69 prototype-pollution-loop（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\javascript\jQuery\jquery.js:4768`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.70 prototype-pollution-loop（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\javascript\jQuery\jquery.js:4787`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.71 prototype-pollution-loop（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\javascript\jQuery\jquery.js:5597`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.72 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\source-viewer.php:219`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.73 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\test-connectivity.php:95`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.74 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\text-file-viewer.php:219`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.75 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\rest\ws-dns-lookup.php:100`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.76 tainted-exec（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\rest\ws-echo.php:95`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.77 unlink-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\soap\lib\nusoap.php:8566`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.78 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\soap\lib\nusoap.php:8588`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.79 unlink-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\webservices\soap\lib\nusoap.php:8676`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.80 XSS（MEDIUM）

- 文件：`src/browser-info.php:86`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<tr><th class="report-label">Cookie '.$Encoder->encodeForHTML($key).'</th><td class="report-data">'.$Encoder->encodeForHTML($value).'</pre></td></tr>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.81 XSS（MEDIUM）

- 文件：`src/browser-info.php:90`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<tr><th class="report-label" class="non-wrapping-label">Cookie '.$key.'</th><td class="report-data">'.$value.'</pre></td></tr>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.82 Weak Randomness（MEDIUM）

- 文件：`src/client-side-control-challenge.php:247`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$_SESSION['cscc-random-flag'] = mt_rand(0, mt_getrandmax());;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.83 XSS（MEDIUM）

- 文件：`src/cors.php:127`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
document.getElementById("idMessageOutput").innerHTML = "<pre>" + prettyJson + "</pre>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.84 Command Injection（MEDIUM）

- 文件：`src/dns-lookup.php:165`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<pre class="output">'.shell_exec("nslookup " . $lTargetHost).'</pre>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.85 XSS（MEDIUM）

- 文件：`src/dns-lookup.php:165`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<pre class="output">'.shell_exec("nslookup " . $lTargetHost).'</pre>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.86 XSS（MEDIUM）

- 文件：`src/dns-lookup.php:173`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Input: " . $lTargetHost);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.87 XSS（MEDIUM）

- 文件：`src/echo.php:142`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<div class="report-header">Results for '.$lMessageText.'</div>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.88 XSS（MEDIUM）

- 文件：`src/echo.php:145`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<pre class="output">'.$lMessageText.'</pre>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.89 XSS（MEDIUM）

- 文件：`src/echo.php:146`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$LogHandler->writeToLog("Executed PHP command: echo " . $lMessageText);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.90 XSS（MEDIUM）

- 文件：`src/echo.php:148`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<pre class="output">'.shell_exec("echo " . $lMessage).'</pre>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.91 XSS（MEDIUM）

- 文件：`src/echo.php:149`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$LogHandler->writeToLog("Executed operating system command: echo " . $lMessageText);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.92 XSS（MEDIUM）

- 文件：`src/echo.php:153`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Input: " . $lMessageText);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.93 XSS（MEDIUM）

- 文件：`src/password-generator.php:40`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Input: " . $lUsernameForHTML);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.94 Weak Randomness（MEDIUM）

- 文件：`src/password-generator.php:52`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
lPasswordText += lPasswordCharset.charAt(Math.floor(Math.random() * lPasswordCharset.length));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.95 XSS（MEDIUM）

- 文件：`src/pen-test-tool-lookup.php:69`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
//echo '<option value="' . $lToolID . '">' . $lToolName . '</option>' . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.96 XSS（MEDIUM）

- 文件：`src/redirectandlog.php:32`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<meta http-equiv="refresh" content="0;url='.$forwardurl.'">';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.97 XSS（MEDIUM）

- 文件：`src/set-background-color.php:46`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Input: " . $lBackgroundColor);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.98 XSS（MEDIUM）

- 文件：`src/set-background-color.php:60`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo 'var lValidateInput = "true"' . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.99 XSS（MEDIUM）

- 文件：`src/set-background-color.php:62`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo 'var lValidateInput = "false"' . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.100 XSS（MEDIUM）

- 文件：`src/set-up-database.php:1438`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Warning: No records found when trying to build XML and text version of accounts table ".$lQueryResult,"W");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.101 XSS（MEDIUM）

- 文件：`src/source-viewer.php:90`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<option value="' . $lPHPFileName . '">' . $lPHPFileName . "</option>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.102 XSS（MEDIUM）

- 文件：`src/source-viewer.php:217`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<span class="label">File: '.$lFilename.'</span>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.103 XSS（MEDIUM）

- 文件：`src/styling.php:83`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
I've been framed by <?php echo $_SERVER['PHP_SELF']; ?>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.104 XSS（MEDIUM）

- 文件：`src/test-connectivity.php:93`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<div class="report-header">Results for '.$lServerURLText.'</div>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.105 XSS（MEDIUM）

- 文件：`src/test-connectivity.php:99`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Input: " . $lServerURLText);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.106 XSS（MEDIUM）

- 文件：`src/user-info-xpath.php:208`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<br /><span style="font-weight:bold;">Executed query:</span>&nbsp;' . $lHTMLXPathQueryString . '<br /><br />';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.107 XSS（MEDIUM）

- 文件：`src/user-info-xpath.php:228`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
document.getElementById('xml').innerHTML = '<pre>'+decoded_data+'</pre>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.108 XSS（MEDIUM）

- 文件：`src/user-info.php:63`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"TRUE\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.109 XSS（MEDIUM）

- 文件：`src/user-info.php:65`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"FALSE\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.110 XSS（MEDIUM）

- 文件：`src/view-someones-blog.php:162`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<table border="1px" width="90%" class="results-table">';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.111 Weak Hash（MEDIUM）

- 文件：`src/view-user-privilege-level.php:78`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lCryptoKey = MD5("SecretSauce12345");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.112 XSS（MEDIUM）

- 文件：`src/view-user-privilege-level.php:137`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "<div class=\"error-message\">".$lErrorMessage."</div>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.113 Weak Randomness（MEDIUM）

- 文件：`src/classes/CSRFTokenHandler.php:84`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lCSRFToken = mt_rand();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.114 Path Traversal（MEDIUM）

- 文件：`src/includes/capture-data.php:96`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lCapturedData .= file_get_contents('php://input');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.115 SSRF（MEDIUM）

- 文件：`src/includes/capture-data.php:96`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lCapturedData .= file_get_contents('php://input');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.116 Command Injection（MEDIUM）

- 文件：`src/javascript/ddsmoothmenu/jquery.min.js:12`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
(function(){var l=this,g,y=l.jQuery,p=l.$,o=l.jQuery=l.$=function(E,F){return new o.fn.init(E,F)},D=/^[^<]*(<(.|\s)+>)[^>]*$|^#([\w-]+)$/,f=/^.[^:#\[\.,]*$/;o.fn=o.prototype={init:function(E,H){E=E||d
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.117 XSS（MEDIUM）

- 文件：`src/javascript/ddsmoothmenu/jquery.min.js:12`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
(function(){var l=this,g,y=l.jQuery,p=l.$,o=l.jQuery=l.$=function(E,F){return new o.fn.init(E,F)},D=/^[^<]*(<(.|\s)+>)[^>]*$|^#([\w-]+)$/,f=/^.[^:#\[\.,]*$/;o.fn=o.prototype={init:function(E,H){E=E||d
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.118 Command Injection（MEDIUM）

- 文件：`src/javascript/ddsmoothmenu/jquery.min.js:19`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
(function(){var R=/((?:\((?:\([^()]+\)|[^()]+)+\)|\[(?:\[[^[\]]*\]|['"][^'"]*['"]|[^[\]'"]+)+\]|\\.|[^ >+~,(\[\\]+)+|[>+~])(\s*,\s*)?/g,L=0,H=Object.prototype.toString;var F=function(Y,U,ab,ac){ab=ab|
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.119 Path Traversal（MEDIUM）

- 文件：`src/javascript/ddsmoothmenu/jquery.min.js:19`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
(function(){var R=/((?:\((?:\([^()]+\)|[^()]+)+\)|\[(?:\[[^[\]]*\]|['"][^'"]*['"]|[^[\]'"]+)+\]|\\.|[^ >+~,(\[\\]+)+|[>+~])(\s*,\s*)?/g,L=0,H=Object.prototype.toString;var F=function(Y,U,ab,ac){ab=ab|
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.120 XSS（MEDIUM）

- 文件：`src/javascript/ddsmoothmenu/jquery.min.js:19`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
(function(){var R=/((?:\((?:\([^()]+\)|[^()]+)+\)|\[(?:\[[^[\]]*\]|['"][^'"]*['"]|[^[\]'"]+)+\]|\\.|[^ >+~,(\[\\]+)+|[>+~])(\s*,\s*)?/g,L=0,H=Object.prototype.toString;var F=function(Y,U,ab,ac){ab=ab|
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.121 Weak Randomness（MEDIUM）

- 文件：`src/javascript/jQuery/jquery.js:1522`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
expando: "jQuery" + ( jQuery.fn.jquery + Math.random() ).replace( /\D/g, "" ),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.122 Weak Randomness（MEDIUM）

- 文件：`src/javascript/jQuery/jquery.js:3685`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
expando = ( "sizcache" + Math.random() ).replace( ".", "" ),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.123 Path Traversal（MEDIUM）

- 文件：`src/webservices/rest/ws-cors-echo.php:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
parse_str(file_get_contents('php://input'), $lParameters);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.124 SSRF（MEDIUM）

- 文件：`src/webservices/rest/ws-cors-echo.php:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
parse_str(file_get_contents('php://input'), $lParameters);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.125 XSS（MEDIUM）

- 文件：`src/webservices/rest/ws-echo.php:88`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lCommand = "echo " . $lMessage; // Vulnerable: Direct input usage
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.126 XSS（MEDIUM）

- 文件：`src/webservices/rest/ws-echo.php:91`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lCommand = escapeshellcmd("echo " . escapeshellarg($lMessage));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.127 Path Traversal（MEDIUM）

- 文件：`src/webservices/rest/ws-user-account.php:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
parse_str(file_get_contents('php://input'), $lParameters);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.128 SSRF（MEDIUM）

- 文件：`src/webservices/rest/ws-user-account.php:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
parse_str(file_get_contents('php://input'), $lParameters);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.129 XSS（MEDIUM）

- 文件：`src/webservices/soap/ws-echo.php:88`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo ERROR_MESSAGE_UNAUTHORIZED_PREFIX . 'Unauthorized: ' . htmlspecialchars($e->getMessage()) . ERROR_MESSAGE_UNAUTHORIZED_SUFFIX;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.130 XSS（MEDIUM）

- 文件：`src/webservices/soap/ws-test-connectivity.php:94`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo ERROR_MESSAGE_UNAUTHORIZED_PREFIX . 'Unauthorized: ' . htmlspecialchars($e->getMessage()) . ERROR_MESSAGE_UNAUTHORIZED_SUFFIX;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.131 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:2694`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
// H(A1) = MD5(A1)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.132 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:2695`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$HA1 = md5($A1);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.133 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:2701`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$HA2 = md5($A2);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.134 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:2722`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$hashedDigest = md5($unhashedDigest);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.135 Weak Randomness（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:8178`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$r = rand();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.136 Weak Randomness（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:8286`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$r = rand();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.137 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:8540`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return $this->cache_dir.'/wsdlcache-' . md5($wsdl);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.138 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:8604`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if (isset($this->fplock[md5($filename)])) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.139 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:8608`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$this->fplock[md5($filename)] = fopen($filename.".lock", "w");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.140 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:8610`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return flock($this->fplock[md5($filename)], LOCK_SH);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.141 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:8612`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return flock($this->fplock[md5($filename)], LOCK_EX);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.142 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:8652`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$ret = flock($this->fplock[md5($filename)], LOCK_UN);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.143 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:8653`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
fclose($this->fplock[md5($filename)]);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.144 Weak Hash（MEDIUM）

- 文件：`src/webservices/soap/lib/nusoap.php:8654`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
unset($this->fplock[md5($filename)]);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.145 XSS（LOW）

- 文件：`.tools/create-feature-branch.sh:7`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "$(date +"%Y-%m-%d %H:%M:%S") - $1"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.146 XSS（LOW）

- 文件：`.tools/git.sh:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "$(date +"%Y-%m-%d %H:%M:%S") - $1"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.147 XSS（LOW）

- 文件：`.tools/push-development-branch.sh:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "$(date +"%Y-%m-%d %H:%M:%S") - $1"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.148 XSS（LOW）

- 文件：`.tools/push-feature-branch.sh:9`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "$(date +"%Y-%m-%d %H:%M:%S") - $1"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.149 XSS（LOW）

- 文件：`.tools/push-feature-branch.sh:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "This script pushes the feature branch using 'git.sh'."
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.150 XSS（LOW）

- 文件：`.tools/push-main-branch.sh:9`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "$(date +"%Y-%m-%d %H:%M:%S") - $1"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.151 XSS（LOW）

- 文件：`src/add-to-your-blog.php:143`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Error inserting blog for " . $lLoggedInUser);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.152 XSS（LOW）

- 文件：`src/add-to-your-blog.php:257`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Error selecting blog entries for " . $lLoggedInUser . ": " . $lQuery);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.153 XSS（LOW）

- 文件：`src/add-to-your-blog.php:273`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<table border="1px" width="90%" class="results-table">';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.154 XSS（LOW）

- 文件：`src/captured-data.php:110`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<table border="1px;" width="100%" class="results-table">';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.155 XSS（LOW）

- 文件：`src/captured-data.php:111`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<tr class="report-header"><td colspan="7">'.$lQueryResult->num_rows.' captured records found</td></tr>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.156 XSS（LOW）

- 文件：`src/client-side-control-challenge.php:262`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lSubmitOccured = true" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.157 XSS（LOW）

- 文件：`src/client-side-control-challenge.php:264`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lSubmitOccured = false" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.158 XSS（LOW）

- 文件：`src/client-side-control-challenge.php:268`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = true" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.159 XSS（LOW）

- 文件：`src/client-side-control-challenge.php:270`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = false" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.160 XSS（LOW）

- 文件：`src/conference-room-lookup.php:170`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Input: " . $lRoomCommonNameText);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.161 XSS（LOW）

- 文件：`src/content-security-policy.php:113`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<div class="report-header">Results for '.$lMessageText.'</div>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.162 XSS（LOW）

- 文件：`src/content-security-policy.php:116`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<pre class="output">'.$lMessageText.'</pre>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.163 XSS（LOW）

- 文件：`src/content-security-policy.php:117`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$LogHandler->writeToLog("Executed PHP command: echo " . $lMessageText);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.164 Command Injection（LOW）

- 文件：`src/content-security-policy.php:119`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<pre class="output">'.shell_exec("echo -n " . $lMessage).'</pre>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.165 XSS（LOW）

- 文件：`src/content-security-policy.php:119`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<pre class="output">'.shell_exec("echo -n " . $lMessage).'</pre>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.166 XSS（LOW）

- 文件：`src/content-security-policy.php:120`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$LogHandler->writeToLog("Executed operating system command: echo " . $lMessageText);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.167 XSS（LOW）

- 文件：`src/content-security-policy.php:124`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Input: " . $lMessage);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.168 XSS（LOW）

- 文件：`src/content-security-policy.php:152`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "if(!onSubmitOfForm(this)){event.preventDefault()}";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.169 XSS（LOW）

- 文件：`src/cors.php:136`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
document.getElementById("idMessageOutput").innerHTML = "<pre>" + rawResponse + "</pre>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.170 Path Traversal（LOW）

- 文件：`src/cors.php:149`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
lXMLHTTP.open(lMethod, lURL + "?" + lQueryParameters, lAsynchronously);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.171 XSS（LOW）

- 文件：`src/dns-lookup.php:151`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<div class="report-header">Results for '.$lTargetHostText.'</div>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.172 XSS（LOW）

- 文件：`src/dns-lookup.php:158`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $lRecord.': '.$lValue.'<br />';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.173 XSS（LOW）

- 文件：`src/document-viewer.php:127`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
<?php if ($lEnableHTMLControls) {echo $lHTMLControls;} ?>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.174 XSS（LOW）

- 文件：`src/document-viewer.php:131`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
<?php if ($lEnableHTMLControls) {echo $lHTMLControls;} ?>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.175 XSS（LOW）

- 文件：`src/edit-account-profile.php:119`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<div class="success-message">Profile updated for ' . $lUsernameText . '</div>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.176 XSS（LOW）

- 文件：`src/edit-account-profile.php:202`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"TRUE\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.177 XSS（LOW）

- 文件：`src/edit-account-profile.php:204`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"FALSE\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.178 XSS（LOW）

- 文件：`src/login.php:40`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var l_loggedIn = true;" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.179 XSS（LOW）

- 文件：`src/login.php:42`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var l_loggedIn = false;" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.180 XSS（LOW）

- 文件：`src/login.php:46`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lAuthenticationAttemptResultFlag = {$lAuthenticationAttemptResult};" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.181 XSS（LOW）

- 文件：`src/login.php:48`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lAuthenticationAttemptResultFlag = -1;".PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.182 XSS（LOW）

- 文件：`src/login.php:52`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"TRUE\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.183 XSS（LOW）

- 文件：`src/login.php:54`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"FALSE\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.184 XSS（LOW）

- 文件：`src/password-generator.php:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
document.getElementById("idPasswordInput").innerHTML = "Password: <span style=\"color:red;border-width:1px;border-color:black;\">" + lPasswordText + "</span>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.185 XSS（LOW）

- 文件：`src/pen-test-tool-lookup-ajax.php:83`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var gUseSafeJSONParser = \"TRUE\";".PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.186 XSS（LOW）

- 文件：`src/pen-test-tool-lookup-ajax.php:85`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var gUseSafeJSONParser = \"FALSE\";".PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.187 XSS（LOW）

- 文件：`src/pen-test-tool-lookup-ajax.php:89`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var gUseJavaScriptValidation = \"TRUE\";".PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.188 XSS（LOW）

- 文件：`src/pen-test-tool-lookup-ajax.php:91`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var gUseJavaScriptValidation = \"FALSE\";".PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.189 Command Injection（LOW）

- 文件：`src/pen-test-tool-lookup-ajax.php:110`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
var lPenTestToolsJSON = eval("(" + lXMLHTTP.response + ")");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.190 XSS（LOW）

- 文件：`src/pen-test-tool-lookup-ajax.php:116`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
lErrorMessage.innerHTML = "Error Message: " + e.message + " JSON Response:" + lXMLHTTP.response;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.191 XSS（LOW）

- 文件：`src/pen-test-tool-lookup.php:134`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var gUseSafeJSONParser = \"TRUE\";".PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.192 XSS（LOW）

- 文件：`src/pen-test-tool-lookup.php:136`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var gUseSafeJSONParser = \"FALSE\";".PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.193 XSS（LOW）

- 文件：`src/pen-test-tool-lookup.php:140`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var gUseJavaScriptValidation = \"TRUE\";".PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.194 XSS（LOW）

- 文件：`src/pen-test-tool-lookup.php:142`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var gUseJavaScriptValidation = \"FALSE\";".PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.195 XSS（LOW）

- 文件：`src/pen-test-tool-lookup.php:146`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var gDisplayError = \"TRUE\";".PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.196 XSS（LOW）

- 文件：`src/pen-test-tool-lookup.php:148`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var gDisplayError = \"FALSE\";".PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.197 XSS（LOW）

- 文件：`src/pen-test-tool-lookup.php:151`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var gPenTestToolsJSONString = '" . $lPenTestToolsJSON . "'";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.198 XSS（LOW）

- 文件：`src/redirectandlog.php:83`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<meta http-equiv="refresh" content="0;url='.$lURL.'">';/* Redirect browser */
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.199 XSS（LOW）

- 文件：`src/register.php:119`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<h2 class="success-message">Account created for ' . $lUsernameText .'. '.$lRowsAffected.' rows inserted.</h2>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.200 XSS（LOW）

- 文件：`src/register.php:134`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"" . ($lEnableJavaScriptValidation ? "TRUE" : "FALSE") . "\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.201 XSS（LOW）

- 文件：`src/register.php:225`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
<?php if ($lEnableHTMLControls) {echo $lHTMLControls;} ?>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.202 XSS（LOW）

- 文件：`src/repeater.php:92`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "<div class=\"error-message\">".$lErrorMessage."</div>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.203 XSS（LOW）

- 文件：`src/repeater.php:101`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var l_submit_occured = true;" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.204 XSS（LOW）

- 文件：`src/repeater.php:103`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var l_submit_occured = false;" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.205 XSS（LOW）

- 文件：`src/repeater.php:107`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = true" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.206 XSS（LOW）

- 文件：`src/repeater.php:109`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = false" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.207 XSS（LOW）

- 文件：`src/set-up-database.php:65`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Attempting to connect to MySQL server on host " . MySQLHandler::$mMySQLDatabaseHost . " with user name " . MySQLHandler::$mMySQLDatabaseUsername,"I");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.208 XSS（LOW）

- 文件：`src/set-up-database.php:67`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Connected to MySQL server at " . MySQLHandler::$mMySQLDatabaseHost . " as " . MySQLHandler::$mMySQLDatabaseUsername,"I");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.209 XSS（LOW）

- 文件：`src/set-up-database.php:70`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Preparing to drop database " . MySQLHandler::$mMySQLDatabaseName,"I");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.210 SQL Injection（LOW）

- 文件：`src/set-up-database.php:72`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lQueryResult = $MySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.211 XSS（LOW）

- 文件：`src/set-up-database.php:75`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Was not able to drop database " . MySQLHandler::$mMySQLDatabaseName,"F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.212 XSS（LOW）

- 文件：`src/set-up-database.php:77`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Executed query 'DROP DATABASE IF EXISTS' for database " . MySQLHandler::$mMySQLDatabaseName . " with result ".$lQueryResult,"S");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.213 XSS（LOW）

- 文件：`src/set-up-database.php:81`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Error was reported while attempting to drop database " . MySQLHandler::$mMySQLDatabaseName,"F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.214 XSS（LOW）

- 文件：`src/set-up-database.php:83`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, $lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.215 XSS（LOW）

- 文件：`src/set-up-database.php:86`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Preparing to create database " . MySQLHandler::$mMySQLDatabaseName,"I");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.216 SQL Injection（LOW）

- 文件：`src/set-up-database.php:88`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lQueryResult = $MySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.217 XSS（LOW）

- 文件：`src/set-up-database.php:91`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Was not able to create database " . MySQLHandler::$mMySQLDatabaseName,"F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.218 XSS（LOW）

- 文件：`src/set-up-database.php:93`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Executed query 'CREATE DATABASE' for database " . MySQLHandler::$mMySQLDatabaseName . " with result ".$lQueryResult,"S");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.219 XSS（LOW）

- 文件：`src/set-up-database.php:96`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Switching to use database " . MySQLHandler::$mMySQLDatabaseName,"I");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.220 SQL Injection（LOW）

- 文件：`src/set-up-database.php:98`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lQueryResult = $MySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.221 XSS（LOW）

- 文件：`src/set-up-database.php:101`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Was not able to use database " . MySQLHandler::$mMySQLDatabaseName,"F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.222 XSS（LOW）

- 文件：`src/set-up-database.php:103`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Executed query 'USE DATABASE' " . MySQLHandler::$mMySQLDatabaseName . " with result ".$lQueryResult,"I");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.223 XSS（LOW）

- 文件：`src/set-up-database.php:117`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'security_level' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.224 XSS（LOW）

- 文件：`src/set-up-database.php:127`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to set AUTO_INCREMENT to 1.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.225 XSS（LOW）

- 文件：`src/set-up-database.php:139`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to insert initial security level.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.226 XSS（LOW）

- 文件：`src/set-up-database.php:153`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'user_poll_results' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.227 XSS（LOW）

- 文件：`src/set-up-database.php:167`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'blogs_table' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.228 XSS（LOW）

- 文件：`src/set-up-database.php:188`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'accounts' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.229 XSS（LOW）

- 文件：`src/set-up-database.php:204`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'hitlog' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.230 SQL Injection（LOW）

- 文件：`src/set-up-database.php:250`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lQueryResult = $MySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.231 XSS（LOW）

- 文件：`src/set-up-database.php:253`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to insert data into 'accounts' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.232 XSS（LOW）

- 文件：`src/set-up-database.php:285`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to insert data into 'blogs_table' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.233 SQL Injection（LOW）

- 文件：`src/set-up-database.php:296`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lQueryResult = $MySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.234 XSS（LOW）

- 文件：`src/set-up-database.php:299`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'credit_cards' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.235 SQL Injection（LOW）

- 文件：`src/set-up-database.php:316`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lQueryResult = $MySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.236 XSS（LOW）

- 文件：`src/set-up-database.php:319`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to insert data into 'credit_cards' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.237 XSS（LOW）

- 文件：`src/set-up-database.php:335`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'pen_test_tools' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.238 XSS（LOW）

- 文件：`src/set-up-database.php:377`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to populate 'pen_test_tools' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.239 XSS（LOW）

- 文件：`src/set-up-database.php:397`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'captured_data' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.240 XSS（LOW）

- 文件：`src/set-up-database.php:412`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'page_hints' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.241 SQL Injection（LOW）

- 文件：`src/set-up-database.php:424`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lQueryResult = $MySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.242 XSS（LOW）

- 文件：`src/set-up-database.php:427`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'page_help' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.243 XSS（LOW）

- 文件：`src/set-up-database.php:872`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to insert data into 'page_help' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.244 XSS（LOW）

- 文件：`src/set-up-database.php:887`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'level_1_help_include_files' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.245 XSS（LOW）

- 文件：`src/set-up-database.php:1023`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to insert data into 'level_1_help_include_files' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.246 XSS（LOW）

- 文件：`src/set-up-database.php:1037`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'help_texts' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.247 XSS（LOW）

- 文件：`src/set-up-database.php:1109`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to insert data into 'help_texts' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.248 XSS（LOW）

- 文件：`src/set-up-database.php:1123`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to create 'youTubeVideos' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.249 XSS（LOW）

- 文件：`src/set-up-database.php:1318`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Failed to insert data into 'youTubeVideos' table.", "F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.250 XSS（LOW）

- 文件：`src/set-up-database.php:1329`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Trying to build XML version of accounts table to update accounts XML ".$lAccountXMLFilePath,"I");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.251 XSS（LOW）

- 文件：`src/set-up-database.php:1332`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Trying to build text version of accounts table to update password text file ".$lPasswordFilePath,"I");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.252 XSS（LOW）

- 文件：`src/set-up-database.php:1347`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Executed query 'SELECT * FROM accounts'. Found ".$lRecordsFound." records.","S");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.253 XSS（LOW）

- 文件：`src/set-up-database.php:1391`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Oh no. Trying to create an XML version of the accounts file did not work out. The directory " . $lAccountXMLFilePath . " does not exist.","F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.254 XSS（LOW）

- 文件：`src/set-up-database.php:1394`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Oh no. Trying to create a text version of the accounts file did not work out. The directory " . $lPasswordFilePath . " does not exist.","F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.255 XSS（LOW）

- 文件：`src/set-up-database.php:1397`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Oh no. Trying to create an XML version of the accounts file did not work out. The directory " . $lAccountXMLFilePath . " is not writable.","F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.256 XSS（LOW）

- 文件：`src/set-up-database.php:1400`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Oh no. Trying to create a text version of the accounts file did not work out. The directory " . $lPasswordFilePath . " is not writable.","F");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.257 XSS（LOW）

- 文件：`src/set-up-database.php:1407`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Wrote accounts to " . $lAccountXMLFilePath, "S");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.258 XSS（LOW）

- 文件：`src/set-up-database.php:1409`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Could not write accounts XML to " . $lAccountXMLFilePath . " - Directory not writable", "W");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.259 XSS（LOW）

- 文件：`src/set-up-database.php:1413`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Could not write accounts XML to " . $lAccountXMLFilePath . " - " . $e->getMessage(), "W");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.260 XSS（LOW）

- 文件：`src/set-up-database.php:1421`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Wrote accounts to " . $lPasswordFilePath, "S");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.261 XSS（LOW）

- 文件：`src/set-up-database.php:1423`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Could not write accounts text to " . $lPasswordFilePath . " - Directory not writable", "W");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.262 XSS（LOW）

- 文件：`src/set-up-database.php:1427`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo format("Could not write accounts text to " . $lPasswordFilePath . " - " . $e->getMessage(), "W");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.263 XSS（LOW）

- 文件：`src/show-log.php:126`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Error writing log table rows.".$lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.264 XSS（LOW）

- 文件：`src/source-viewer.php:100`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<option value="' . $lCounter . '">' . $lPHPFileName . "</option>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.265 XSS（LOW）

- 文件：`src/text-file-viewer.php:77`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
<option value="<?php if ($lUseTokenization){echo 1;}else{echo 'http://www.textfiles.com/hacking/auditool.txt';}?>">Intrusion Detection in Computers by Victor H. Marshall (January 29, 1991)</option>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.266 XSS（LOW）

- 文件：`src/text-file-viewer.php:78`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
<option value="<?php if ($lUseTokenization){echo 2;}else{echo 'http://www.textfiles.com/hacking/atms';}?>">An Overview of ATMs and Information on the Encoding System</option>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.267 XSS（LOW）

- 文件：`src/text-file-viewer.php:79`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
<option value="<?php if ($lUseTokenization){echo 3;}else{echo 'http://www.textfiles.com/hacking/backdoor.txt';}?>">How to Hold Onto UNIX Root Once You Have It</option>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.268 XSS（LOW）

- 文件：`src/text-file-viewer.php:80`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
<option value="<?php if ($lUseTokenization){echo 4;}else{echo 'http://www.textfiles.com/hacking/hack1.hac';}?>">The Basics of Hacking, by the Knights of Shadow (Intro)</option>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.269 XSS（LOW）

- 文件：`src/text-file-viewer.php:81`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
<option value="<?php if ($lUseTokenization){echo 5;}else{echo 'http://www.textfiles.com/hacking/hacking101.hac';}?>">HACKING 101 - By Johnny Rotten - Course #1 - Hacking, Telenet, Life</option>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.270 XSS（LOW）

- 文件：`src/text-file-viewer.php:220`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<span class="label">File: '.$lTextFileDescription.'</span>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.271 XSS（LOW）

- 文件：`src/upload-file.php:129`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"true\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.272 XSS（LOW）

- 文件：`src/upload-file.php:131`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"false\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.273 Path Traversal（LOW）

- 文件：`src/user-agent-impersonation.php:142`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
lXMLHTTP.open(lRequestMethod, lURL+"?"+encodeURI("Browser Fingerprint:" + lBrowserFingerprint), lAsyncronousRequestFlag);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.274 XSS（LOW）

- 文件：`src/user-info-xpath.php:74`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"TRUE\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.275 XSS（LOW）

- 文件：`src/user-info-xpath.php:76`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"FALSE\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.276 XSS（LOW）

- 文件：`src/user-poll.php:133`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Error inserting user vote for " . $lLoggedInUser);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.277 XSS（LOW）

- 文件：`src/user-poll.php:222`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<table style="width:50%;" class="results-table">';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.278 XSS（LOW）

- 文件：`src/user-poll.php:223`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<tr class="report-header"><th class="report-label" colspan="2">'.$lQueryResult->num_rows.' Records Found</th></tr>';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.279 XSS（LOW）

- 文件：`src/view-someones-blog.php:112`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<option value="' . $lUsername . '">' . $lUsername . '</option>\n';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.280 XSS（LOW）

- 文件：`src/view-user-privilege-level.php:173`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
<td style="text-align: left;"><?php echo $lUserIDValue . " ( Hint: " . prettyPrintStringToHex($lUserIDValue) . ")"; ?></td>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.281 XSS（LOW）

- 文件：`src/view-user-privilege-level.php:177`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
<td style="text-align: left;"><?php echo $lUserGroupIDValue . " ( Hint: " . prettyPrintStringToHex($lUserGroupIDValue) . ")"; ?></td>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.282 XSS（LOW）

- 文件：`src/view-user-privilege-level.php:199`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var l_user_is_root = true;" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.283 XSS（LOW）

- 文件：`src/view-user-privilege-level.php:201`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var l_user_is_root = false;" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.284 XSS（LOW）

- 文件：`src/xml-validator.php:99`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"true\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.285 XSS（LOW）

- 文件：`src/xml-validator.php:101`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "var lValidateInput = \"false\"" . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.286 XSS（LOW）

- 文件：`src/xml-validator.php:179`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "<div width='600px' class=\"important-code\">" . $Encoder->encodeForXML($lXML) . "</div>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.287 XSS（LOW）

- 文件：`src/xml-validator.php:194`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "<div width='600px'>" . $lDOMDocument->textContent . "</div>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.288 SQL Injection（LOW）

- 文件：`src/classes/SQLQueryHandler.php:279`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return $this->mMySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.289 SQL Injection（LOW）

- 文件：`src/classes/SQLQueryHandler.php:292`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return $this->mMySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.290 SQL Injection（LOW）

- 文件：`src/classes/SQLQueryHandler.php:305`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lQueryResult = $this->mMySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.291 SQL Injection（LOW）

- 文件：`src/classes/SQLQueryHandler.php:313`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return $this->mMySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.292 SQL Injection（LOW）

- 文件：`src/classes/SQLQueryHandler.php:372`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return $this->mMySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.293 SQL Injection（LOW）

- 文件：`src/classes/SQLQueryHandler.php:383`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return $this->mMySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.294 SQL Injection（LOW）

- 文件：`src/classes/SQLQueryHandler.php:402`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return $this->mMySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.295 SQL Injection（LOW）

- 文件：`src/classes/SQLQueryHandler.php:415`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return $this->mMySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.296 SQL Injection（LOW）

- 文件：`src/classes/SQLQueryHandler.php:559`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if ($this->mMySQLHandler->executeQuery($lQueryString)){
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.297 SQL Injection（LOW）

- 文件：`src/classes/SQLQueryHandler.php:575`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if ($this->mMySQLHandler->executeQuery($lQueryString)){
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.298 SQL Injection（LOW）

- 文件：`src/classes/SQLQueryHandler.php:588`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return $this->mMySQLHandler->executeQuery($lQueryString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.299 XSS（LOW）

- 文件：`src/classes/YouTubeVideoHandler.php:307`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
onclick="document.getElementById(\'the-player'.$lRandomNumber.'\').innerHTML=lYouTubeFrameCode'.$lRandomNumber.';"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.300 Path Traversal（LOW）

- 文件：`src/includes/capture-data.php:115`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lFileHandle = fopen($lFilepath, "a");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.301 XSS（LOW）

- 文件：`src/includes/header.php:128`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo '<a href="index.php?do=toggle-hints&page='.$lPage.'">Toggle Hints</a> |';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.302 XSS（LOW）

- 文件：`src/includes/pop-up-help-context-generator.php:42`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo $CustomErrorHandler->FormatError($e, "Error selecting help text entries for page " . $lPageName);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.303 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:2688`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
tns = rtypenamespace.exec( types[t] ) || [];
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.304 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:2770`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
tns = rtypenamespace.exec( types[t] ) || [];
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.305 XSS（LOW）

- 文件：`src/javascript/jQuery/jquery.js:3849`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
div.innerHTML = "<a name='" + expando + "'></a><div name='" + expando + "'></div>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.306 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:4699`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if ( !matched || (match = rcomma.exec( soFar )) ) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.307 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:4710`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if ( (match = rcombinators.exec( soFar )) ) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.308 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:4720`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if ( (match = matchExpr[ type ].exec( soFar )) && (!preFilters[ type ] ||
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.309 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:5883`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
!wrapMap[ ( rtagName.exec( value ) || ["", ""] )[1].toLowerCase() ] ) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.310 XSS（LOW）

- 文件：`src/javascript/jQuery/jquery.js:5893`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
elem.innerHTML = value;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.311 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:6019`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
jQuery.globalEval( ( elem.text || elem.textContent || elem.innerHTML || "" ).replace( rcleanScript, "" ) );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.312 XSS（LOW）

- 文件：`src/javascript/jQuery/jquery.js:6019`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
jQuery.globalEval( ( elem.text || elem.textContent || elem.innerHTML || "" ).replace( rcleanScript, "" ) );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.313 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:6322`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
tag = ( rtagName.exec( elem ) || ["", ""] )[1].toLowerCase();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.314 XSS（LOW）

- 文件：`src/javascript/jQuery/jquery.js:6325`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
div.innerHTML = wrap[1] + elem + wrap[2];
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.315 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:6486`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
var match = /(chrome)[ \/]([\w.]+)/.exec( ua ) ||
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.316 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:6487`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
/(webkit)[ \/]([\w.]+)/.exec( ua ) ||
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.317 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:6488`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
/(opera)(?:.*version|)[ \/]([\w.]+)/.exec( ua ) ||
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.318 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:6489`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
/(msie) ([\w.]+)/.exec( ua ) ||
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.319 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:6490`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
ua.indexOf("compatible") < 0 && /(mozilla)(?:.*? rv:([\w.]+)|)/.exec( ua ) ||
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.320 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:6728`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if ( type === "string" && (ret = rrelNum.exec( value )) ) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.321 Command Injection（LOW）

- 文件：`src/javascript/jQuery/jquery.js:7332`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
ajaxLocParts = rurl.exec( ajaxLocation.toLowerCase() ) || [];
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.322 Command Injection（LOW）

- 文件：`src/webservices/rest/ws-echo.php:95`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lOutput = shell_exec($lCommand);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.323 XSS（LOW）

- 文件：`src/webservices/rest/ws-echo.php:96`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$LogHandler->writeToLog("Command executed from web service ws-echo.php: " . $lCommand);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.324 XSS（LOW）

- 文件：`src/webservices/rest/ws-echo.php:105`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo json_encode(['message' => $lMessage, 'command' => $lCommand, 'security-level' => $lSecurityLevel, 'timestamp' => date(DATE_TIME_FORMAT), 'result' => $lOutput], JSON_PRETTY_PRINT);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.325 XSS（LOW）

- 文件：`src/webservices/soap/ws-dns-lookup.php:92`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo ERROR_MESSAGE_UNAUTHORIZED_PREFIX . 'Unauthorized: ' . htmlspecialchars($e->getMessage()) . ERROR_MESSAGE_UNAUTHORIZED_SUFFIX;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.326 XSS（LOW）

- 文件：`src/webservices/soap/ws-echo.php:127`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
? escapeshellcmd("echo " . escapeshellarg($pMessage))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.327 XSS（LOW）

- 文件：`src/webservices/soap/ws-echo.php:148`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$LogHandler->writeToLog("Executed echo on: $lMessage");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.328 XSS（LOW）

- 文件：`src/webservices/soap/ws-echo.php:153`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$lMessage = "Error executing method echoMessage in webservice ws-echo.php: " . $e->getMessage();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.329 XSS（LOW）

- 文件：`src/webservices/soap/ws-user-account.php:136`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo ERROR_MESSAGE_UNAUTHORIZED_PREFIX . 'Unauthorized: ' . htmlspecialchars($e->getMessage()) . ERROR_MESSAGE_UNAUTHORIZED_SUFFIX;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.330 Path Traversal（LOW）

- 文件：`src/webservices/soap/lib/nusoap.php:2419`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$this->fp = @fsockopen($host, $this->port, $this->errno, $this->error_str, $connection_timeout);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.331 Path Traversal（LOW）

- 文件：`src/webservices/soap/lib/nusoap.php:2421`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$this->fp = @fsockopen($host, $this->port, $this->errno, $this->error_str);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.332 Insecure Cookie（LOW）

- 文件：`src/webservices/soap/lib/nusoap.php:3485`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
function getCookiesForRequest($cookies, $secure = false)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.333 Command Injection（LOW）

- 文件：`src/webservices/soap/lib/nusoap.php:4188`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
@eval($funcCall);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.334 Path Traversal（LOW）

- 文件：`src/webservices/soap/lib/nusoap.php:4979`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if ($fp = @fopen($path, 'r')) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.335 XSS（LOW）

- 文件：`src/webservices/soap/lib/nusoap.php:8239`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return "echo \"" . $this->getError() . "\";";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.336 Path Traversal（LOW）

- 文件：`src/webservices/soap/lib/nusoap.php:8608`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
$this->fplock[md5($filename)] = fopen($filename.".lock", "w");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。





## 5. 关键风险

- HIGH curl-ssl-verifypeer-off 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\classes\RemoteFileHandler.php:62，状态为 confirmed。
- HIGH exec-use 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\database-offline.php:40，状态为 needs_review。
- HIGH exec-use 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\database-offline.php:46，状态为 needs_review。
- HIGH exec-use 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\database-offline.php:52，状态为 needs_review。
- HIGH exec-use 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_33e88d21\src\database-offline.php:86，状态为 needs_review。


## 6. 修改建议

- **P0 优先修复 Critical/High 漏洞：** 先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。
- **P1 按漏洞类型批量治理：** 对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。
- **P1 补充动态验证覆盖：** 为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。
- **P2 纳入持续审计流程：** 将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。


## 7. 结论

综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 HIGH 风险水平。建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
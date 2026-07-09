# WebGoat 安全审计报告

> 生成工具：AuditAgentX　生成时间：2026-07-09 09:41:10 UTC

## 1. 执行摘要

本次审计对象为 WebGoat，来源为 https://github.com/WebGoat/WebGoat，项目主要语言为 Java、JavaScript、Shell，框架识别结果为 Express、Spring、Spring Boot，共解析 498 个文件、82163 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC 并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 408 条风险，其中 Critical 0 条、High 138 条、Medium 219 条、Low 51 条；静态分析覆盖 408 条，动态验证覆盖 0 条，其中 0 条已复现。主要风险类型集中在 Hardcoded Secret(99)、django-no-csrf-token(87)、Command Injection(37)、XSS(27)，总体风险评级为 HIGH。

**总体风险等级：HIGH**

### 1.1 项目概况总结

项目 WebGoat 来源于 https://github.com/WebGoat/WebGoat，主要语言为 Java、JavaScript、Shell，框架为 Express、Spring、Spring Boot，共 498 个文件、82163 行代码。

### 1.2 漏洞结果总结

本次共发现 408 条漏洞，其中 Critical 0 条、High 138 条、Medium 219 条、Low 51 条。

**静态分析总结：** 静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 408 条静态风险。主要来源分布为 custom-taint(220)、semgrep(187)、custom-java-taint(1)。这些结果先作为候选项进入 VerifyAgent，避免仅凭规则命中直接下结论。

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
| 项目名称 | WebGoat |
| 来源 | https://github.com/WebGoat/WebGoat |
| 语言 | Java, JavaScript, Shell |
| 框架 | Express, Spring, Spring Boot |
| 文件数 | 498 |
| 代码行数 | 82163 |
| 扫描任务 | scan_1a45a119（static / done） |

## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | 0 |
| High | 138 |
| Medium | 219 |
| Low | 51 |
| **合计** | **408** |

## 4. 漏洞明细


### 4.1 run-shell-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:24`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.2 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\it\java\org\owasp\webgoat\playwright\webwolf\JwtUITest.java:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.3 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\challenges\challenge5\Assignment5.java:45`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.4 formatted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\challenges\challenge5\Assignment5.java:50`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.5 tainted-url-host（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\jwt\claimmisuse\JWTHeaderJKUEndpoint.java:57`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.6 httpservlet-path-traversal（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\pathtraversal\ProfileUploadRetrieval.java:100`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.7 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\advanced\SqlInjectionChallenge.java:60`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.8 formatted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\advanced\SqlInjectionChallenge.java:62`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.9 formatted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson10.java:56`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.10 formatted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson5a.java:52`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.11 formatted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson5b.java:69`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.12 formatted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson8.java:62`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.13 formatted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson8.java:142`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.14 formatted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson9.java:65`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.15 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\mitigation\Servers.java:51`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.16 tainted-file-path（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\webwolf\FileServer.java:79`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.17 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\documentation\JWT_decode.adoc:21`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.18 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\documentation\JWT_libraries.adoc:28`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.19 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\documentation\JWT_libraries.adoc:40`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.20 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\documentation\JWT_libraries.adoc:56`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.21 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\documentation\JWT_libraries_assignment.adoc:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.22 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\documentation\JWT_libraries_assignment2.adoc:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.23 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\documentation\JWT_libraries_solution.adoc:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.24 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\documentation\JWT_signing_solution.adoc:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.25 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\documentation\JWT_signing_solution.adoc:77`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.26 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\html\JWT.html:323`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.27 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\html\JWT.html:389`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.28 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\images\logs.txt:2`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.29 Hardcoded Secret（HIGH）

- 文件：`src/it/java/org/owasp/webgoat/playwright/webgoat/RegistrationUITest.java:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var password = "password123";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.30 Hardcoded Secret（HIGH）

- 文件：`src/it/java/org/owasp/webgoat/playwright/webgoat/RegistrationUITest.java:43`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var password = "password123";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.31 Insecure Deserialization（HIGH）

- 文件：`src/main/java/org/dummy/insecure/framework/VulnerableTaskHolder.java:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
import java.io.ObjectInputStream;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.32 Insecure Deserialization（HIGH）

- 文件：`src/main/java/org/dummy/insecure/framework/VulnerableTaskHolder.java:46`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
private void readObject(ObjectInputStream stream) throws Exception {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.33 Insecure Deserialization（HIGH）

- 文件：`src/main/java/org/dummy/insecure/framework/VulnerableTaskHolder.java:47`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
// unserialize data so taskName and taskAction are available
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.34 Insecure Deserialization（HIGH）

- 文件：`src/main/java/org/dummy/insecure/framework/VulnerableTaskHolder.java:48`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
stream.defaultReadObject();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.35 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/SolutionConstants.java:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String PASSWORD = "!!webgoat_admin_1234!!";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.36 Insecure Deserialization（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java:13`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
import java.io.ObjectInputStream;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.37 Insecure Deserialization（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java:42`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
try (ObjectInputStream ois =
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.38 Insecure Deserialization（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java:43`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(b64token)))) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.39 Insecure Deserialization（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
Object o = ois.readObject();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.40 Insecure Deserialization（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/deserialization/SerializationHelper.java:11`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
import java.io.ObjectInputStream;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.41 Insecure Deserialization（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/deserialization/SerializationHelper.java:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.42 Insecure Deserialization（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/deserialization/SerializationHelper.java:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
Object o = ois.readObject();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.43 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
public static final String PASSWORD = "bm5nhSkxCXZkKRy4";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.44 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java:46`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
private static final String JWT_PASSWORD = "bm5n3SkxCX4kKRy4";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.45 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/openredirect/OpenRedirectTask3.java:60`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
debug.append("Token: ").append(escape(token)).append("\n");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.46 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/securitymisconfiguration/ActuatorExposureTask.java:28`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
static final String LEAKED_API_KEY = "INTERNAL-API-KEY-987";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.47 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/owasp/webgoat/lessons/securitymisconfiguration/VerboseErrorTask.java:29`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
static final String LEAKED_TOKEN = "STAGING-TOKEN-42";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.48 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/lessons/jwt/js/jwt-refresh.js:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
data: JSON.stringify({user: user, password: "bm5nhSkxCXZkKRy4"})
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.49 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:6581`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "empty_line",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.50 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "comment.doc.tag",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.51 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
defaultToken : "comment.doc",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.52 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "comment.doc.tag.storage.type",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.53 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:32`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "comment.doc", // doc comment
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.54 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:40`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "comment.doc", // closing comment
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.55 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:100`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.56 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:104`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.57 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:108`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "constant.numeric", // hexadecimal, octal and binary
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.58 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:111`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "constant.numeric", // decimal integers and floats
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.59 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:162`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "keyword",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.60 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:165`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "keyword",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.61 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:178`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "punctuation.operator",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.62 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:182`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "storage.type",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.63 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:186`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "keyword.operator",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.64 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:190`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "punctuation.operator",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.65 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:194`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "paren.lparen",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.66 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:198`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "paren.rparen",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.67 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:201`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "comment",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.68 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:217`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "punctuation.operator",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.69 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:220`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "support.function",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.70 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:223`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "support.function.dom",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.71 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:226`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token :  "support.constant",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.72 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:229`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "identifier",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.73 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:241`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "string.regexp",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.74 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:256`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "regexp.keyword.operator",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.75 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:259`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "string.regexp",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.76 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:263`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "invalid",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.77 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:266`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "constant.language.escape",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.78 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:269`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "constant.language.delimiter",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.79 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:272`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "constant.language.escape",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.80 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:280`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
defaultToken: "string.regexp"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.81 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:285`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "regexp.charclass.keyword.operator",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.82 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:288`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "constant.language.escape",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.83 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:292`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "constant.language.escape",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.84 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:299`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
defaultToken: "string.regexp.charachterclass"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.85 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:304`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "variable.parameter",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.86 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:307`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "punctuation.operator",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.87 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:310`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "punctuation.operator",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.88 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:320`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "constant.language.escape",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.89 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:323`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.90 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:327`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.91 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:331`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
defaultToken: "string"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.92 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:336`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "constant.language.escape",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.93 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:339`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.94 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:343`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.95 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:347`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
defaultToken: "string"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.96 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:370`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string.quasi.start",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.97 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:373`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "constant.language.escape",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.98 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:376`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "paren.quasi.start",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.99 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:380`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string.quasi.end",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.100 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:384`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
defaultToken: "string.quasi"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.101 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:435`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "paren.quasi.start",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.102 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:442`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
{defaultToken: "string"}
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.103 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:445`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "meta.tag.punctuation.tag-close.xml",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.104 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:465`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "entity.other.attribute-name.xml",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.105 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:468`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "keyword.operator.attribute-equals.xml",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.106 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:471`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "text.tag-whitespace.xml",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.107 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:474`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string.attribute-value.xml",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.108 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:478`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
{token : "string.attribute-value.xml", regex: "'", next: "pop"},
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.109 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:480`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
{defaultToken : "string.attribute-value.xml"}
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.110 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:483`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string.attribute-value.xml",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.111 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:487`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
{token : "string.attribute-value.xml", regex: '"', next: "pop"},
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.112 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:489`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
{defaultToken : "string.attribute-value.xml"}
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.113 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:495`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "constant.language.escape.reference.xml",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.114 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:503`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "comment", // multi line comment
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.115 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:507`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
{token : "comment", regex : "\\*\\/", next : next || "pop"},
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.116 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:508`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
{defaultToken : "comment", caseInsensitive: true}
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.117 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:511`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "comment",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.118 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:515`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
{token : "comment", regex : "$|^", next : next || "pop"},
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.119 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:516`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
{defaultToken : "comment", caseInsensitive: true}
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.120 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:852`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "comment",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.121 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:857`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "comment", // multi line comment
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.122 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:861`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string", // single line
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.123 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:864`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "string", // single line
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.124 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:867`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "constant.numeric", // hex
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.125 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:870`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "constant.numeric", // float
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.126 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:873`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "constant.language.boolean",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.127 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:877`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "keyword",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.128 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:880`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "paren.lparen",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.129 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:883`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "paren.rparen",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.130 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:887`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token: "keyword"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.131 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:893`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "identifier",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.132 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:896`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "punctuation.operator",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.133 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:909`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "keyword.operator",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.134 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:912`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "lparen",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.135 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:915`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "rparen",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.136 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:924`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
token : "comment", // closing comment
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.137 Hardcoded Secret（HIGH）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:928`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
defaultToken : "comment"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.138 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/owasp/webgoat/lessons/spoofcookie/SpoofCookieAssignmentTest.java:53`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String password = "webgoat";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.139 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\actions\java-setup\action.yml:15`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.140 dependabot-missing-cooldown（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\dependabot.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.141 dependabot-missing-cooldown（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\dependabot.yml:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.142 dependabot-missing-cooldown（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\dependabot.yml:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.143 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\build.yml:19`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.144 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\build.yml:21`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.145 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\build.yml:29`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.146 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\build.yml:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.147 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\build.yml:42`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.148 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:16`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.149 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:34`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.150 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:68`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.151 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:73`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.152 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:76`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.153 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:82`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.154 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:95`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.155 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:112`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.156 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:126`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.157 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:134`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.158 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\welcome.yml:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.159 missing-integrity（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\docs\index.html:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.160 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\container\service\LabelDebugService.java:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.161 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\container\service\LabelDebugService.java:48`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.162 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\container\service\LessonMenuService.java:45`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.163 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\container\service\SessionService.java:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.164 weak-random（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\challenges\challenge1\ImageServlet.java:21`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.165 weak-random（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\cryptography\EncodingAssignment.java:37`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.166 tainted-session-from-http-request（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\cryptography\EncodingAssignment.java:39`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.167 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\cryptography\HashingAssignment.java:30`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.168 weak-random（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\cryptography\HashingAssignment.java:37`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.169 use-of-md5（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\cryptography\HashingAssignment.java:39`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.170 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\cryptography\HashingAssignment.java:49`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.171 weak-random（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\cryptography\HashingAssignment.java:55`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.172 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\cryptography\SigningAssignment.java:37`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.173 object-deserialization（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\deserialization\InsecureDeserializationTask.java:42`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.174 object-deserialization（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\deserialization\SerializationHelper.java:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.175 cookie-missing-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\hijacksession\HijackSessionAssignment.java:70`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.176 weak-random（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\hijacksession\cas\HijackSessionAuthenticationProvider.java:25`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.177 weak-random（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\jwt\JWTSecretKeyEndpoint.java:38`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.178 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\jwt\JWTSecretKeyEndpoint.java:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.179 cookie-issecure-false（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\jwt\JWTVotesEndpoint.java:120`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.180 cookie-missing-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\jwt\JWTVotesEndpoint.java:121`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.181 cookie-missing-secure-flag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\jwt\JWTVotesEndpoint.java:121`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.182 cookie-issecure-false（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\jwt\JWTVotesEndpoint.java:125`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.183 cookie-missing-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\jwt\JWTVotesEndpoint.java:126`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.184 cookie-missing-secure-flag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\jwt\JWTVotesEndpoint.java:126`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.185 spring-unvalidated-redirect（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\openredirect\OpenRedirectRealRedirect.java:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.186 cookie-issecure-false（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\spoofcookie\SpoofCookieAssignment.java:58`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.187 cookie-missing-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\spoofcookie\SpoofCookieAssignment.java:60`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.188 cookie-missing-secure-flag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\spoofcookie\SpoofCookieAssignment.java:60`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.189 cookie-missing-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\spoofcookie\SpoofCookieAssignment.java:77`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.190 jdbc-sqli（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\advanced\SqlInjectionChallenge.java:62`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.191 jdbc-sqli（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson10.java:56`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.192 jdbc-sqli（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson2.java:49`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.193 jdbc-sqli（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson8.java:62`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.194 jdbc-sqli（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson8.java:142`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.195 jdbc-sqli（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson9.java:65`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.196 jdbc-sqli（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\sqlinjection\introduction\SqlInjectionLesson9.java:94`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.197 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\xxe\SimpleXXE.java:77`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.198 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\webwolf\FileServer.java:56`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.199 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\authbypass\html\AuthBypass.html:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.200 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\authbypass\html\AuthBypass.html:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.201 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\challenges\html\Challenge1.html:15`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.202 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\challenges\html\Challenge1.html:37`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.203 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\challenges\html\Challenge5.html:69`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.204 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\challenges\html\Challenge6.html:102`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.205 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\challenges\html\Challenge7.html:60`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.206 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\challenges\html\Challenge8.html:234`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.207 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\chromedevtools\html\ChromeDevTools.html:25`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.208 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\chromedevtools\html\ChromeDevTools.html:46`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.209 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\chromedevtools\html\ChromeDevTools.html:67`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.210 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\cia\html\CIA.html:30`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.211 plaintext-http-link（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\clientsidefiltering\html\ClientSideFiltering.html:96`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.212 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\cryptography\html\Cryptography.html:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.213 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\cryptography\html\Cryptography.html:48`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.214 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\cryptography\html\Cryptography.html:65`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.215 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\cryptography\html\Cryptography.html:90`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.216 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\cryptography\html\Cryptography.html:113`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.217 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\csrf\html\CSRF.html:16`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.218 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\csrf\html\CSRF.html:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.219 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\csrf\html\CSRF.html:93`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.220 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\csrf\html\CSRF.html:213`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.221 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\csrf\html\CSRF.html:237`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.222 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\deserialization\html\InsecureDeserialization.html:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.223 missing-integrity（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\hijacksession\html\HijackSession.html:5`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.224 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\hijacksession\templates\hijackform.html:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.225 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\httpbasics\html\HttpBasics.html:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.226 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\httpbasics\html\HttpBasics.html:45`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.227 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\httpbasics\html\HttpBasics.html:114`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.228 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\httpproxies\html\HttpProxies.html:17`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.229 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\httpproxies\html\HttpProxies.html:42`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.230 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\idor\html\IDOR.html:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.231 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\idor\html\IDOR.html:81`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.232 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\idor\html\IDOR.html:108`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.233 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\insecurelogin\html\InsecureLogin.html:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.234 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\insecurelogin\html\InsecureLogin.html:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.235 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\html\JWT.html:20`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.236 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\html\JWT.html:125`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.237 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\jwt\html\JWT.html:158`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.238 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\lessontemplate\html\LessonTemplate.html:48`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.239 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\logging\html\LogSpoofing.html:17`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.240 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\logging\html\LogSpoofing.html:39`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.241 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\missingac\html\MissingFunctionAC.html:53`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.242 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\missingac\html\MissingFunctionAC.html:76`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.243 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\missingac\html\MissingFunctionAC.html:98`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.244 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\openredirect\html\OpenRedirect.html:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.245 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\openredirect\html\OpenRedirect.html:33`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.246 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\openredirect\html\OpenRedirect.html:48`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.247 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\openredirect\html\OpenRedirect.html:64`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.248 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\openredirect\html\OpenRedirect.html:100`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.249 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\openredirect\html\OpenRedirect.html:116`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.250 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\passwordreset\html\PasswordReset.html:144`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.251 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\passwordreset\templates\password_reset.html:12`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.252 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\pathtraversal\html\PathTraversal.html:192`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.253 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\securepasswords\html\SecurePasswords.html:21`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.254 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\securitymisconfiguration\html\SecurityMisconfiguration.html:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.255 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\securitymisconfiguration\html\SecurityMisconfiguration.html:47`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.256 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\securitymisconfiguration\html\SecurityMisconfiguration.html:72`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.257 missing-integrity（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\spoofcookie\html\SpoofCookie.html:5`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.258 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjection.html:16`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.259 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjection.html:40`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.260 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjection.html:64`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.261 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjection.html:88`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.262 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjection.html:189`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.263 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjection.html:217`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.264 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjection.html:245`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.265 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjection.html:274`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.266 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjectionAdvanced.html:21`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.267 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjectionAdvanced.html:34`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.268 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjectionAdvanced.html:169`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.269 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjectionMitigations.html:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.270 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjectionMitigations.html:45`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.271 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjectionMitigations.html:73`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.272 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjectionMitigations.html:96`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.273 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\sqlinjection\html\SqlInjectionMitigations.html:176`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.274 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\ssrf\html\SSRF.html:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.275 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\ssrf\html\SSRF.html:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.276 missing-integrity（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\vulnerablecomponents\html\VulnerableComponents.html:5`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.277 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\vulnerablecomponents\html\VulnerableComponents.html:104`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.278 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\webgoatintroduction\html\WebGoatIntroduction.html:14`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.279 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\webgoatintroduction\html\WebGoatIntroduction.html:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.280 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\webwolfintroduction\html\WebWolfIntroduction.html:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.281 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\xss\html\CrossSiteScripting.html:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.282 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\xss\html\CrossSiteScripting.html:134`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.283 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\xss\html\CrossSiteScripting.html:149`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.284 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\xss\html\CrossSiteScripting.html:169`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.285 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\xss\html\CrossSiteScriptingMitigation.html:24`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.286 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\xss\html\CrossSiteScriptingMitigation.html:44`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.287 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\lessons\xss\html\CrossSiteScriptingStored.html:68`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.288 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\webgoat\static\js\libs\backbone-min.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.289 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\webgoat\static\js\libs\mode-java.js:573`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.290 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\webgoat\static\js\libs\mode-java.js:576`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.291 prototype-pollution-loop（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\webgoat\static\js\libs\underscore-min.js:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.292 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\webgoat\static\js\libs\underscore-min.js:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.293 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\webgoat\static\plugins\bootstrap-wysihtml5\js\wysihtml5-0.3.0.js:843`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.294 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\webgoat\static\plugins\bootstrap-wysihtml5\js\wysihtml5-0.3.0.js:4079`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.295 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\webgoat\static\plugins\bootstrap-wysihtml5\js\wysihtml5-0.3.0.js:4088`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.296 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\webgoat\templates\login.html:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.297 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\resources\webwolf\templates\files.html:32`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.298 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/challenge1/ImageServlet.java:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
public static final int PINCODE = new Random().nextInt(10000);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.299 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/MD5.java:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
public MD5() {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.300 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/MD5.java:103`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
MD5 md5 = new MD5();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.301 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/MD5.java:116`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
MD5 md5 = new MD5();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.302 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/MD5.java:130`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
MD5 md5 = new MD5();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.303 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/MD5.java:148`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
MD5 md5 = new MD5();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.304 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/MD5.java:198`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
MD5 md5 = new MD5();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.305 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/MD5.java:212`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
MD5 md5 = new MD5();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.306 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/MD5.java:227`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
MD5 md5 = new MD5();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.307 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/MD5.java:242`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
MD5 md5 = new MD5();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.308 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/PasswordResetLink.java:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
Random random = new Random();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.309 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/cryptography/EncodingAssignment.java:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
HashingAssignment.SECRETS[new Random().nextInt(HashingAssignment.SECRETS.length)];
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.310 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String secret = SECRETS[new Random().nextInt(SECRETS.length)];
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.311 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java:39`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
MessageDigest md = MessageDigest.getInstance("MD5");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.312 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
String secret = SECRETS[new Random().nextInt(SECRETS.length)];
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.313 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/csrf/CSRFGetFlag.java:39`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
Random random = new Random();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.314 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/csrf/CSRFGetFlag.java:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
Random random = new Random();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.315 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/csrf/CSRFGetFlag.java:56`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
Random random = new Random();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.316 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/hijacksession/cas/HijackSessionAuthenticationProvider.java:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
private static long id = new Random().nextLong() & Long.MAX_VALUE;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.317 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/httpbasics/HttpBasicsExternal.java:35`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.random = new Random();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.318 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/jwt/JWTSecretKeyEndpoint.java:38`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
TextCodec.BASE64.encode(SECRETS[new Random().nextInt(SECRETS.length)]);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.319 Path Traversal（MEDIUM）

- 文件：`src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java:101`
- 来源：custom-java-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
new File
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.320 Weak Randomness（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/modernizr.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(e,t,n){function r(e){var t=N.className,n=Modernizr._config.classPrefix||"";if(z&&(t=t.baseVal),Modernizr._config.enableJSClass){var r=new RegExp("(^|\\s)"+n+"no-js(\\s|$)");t=t.replace(r,"$1
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.321 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-1.10.2.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e,t){var n,r,i=typeof t,o=e.location,a=e.document,s=a.documentElement,l=e.jQuery,u=e.$,c={},p=[],f="1.10.2",d=p.concat,h=p.push,g=p.slice,m=p.indexOf,y=c.toString,v=c.hasOwnProperty,b=f.trim
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.322 XSS（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-1.10.2.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e,t){var n,r,i=typeof t,o=e.location,a=e.document,s=a.documentElement,l=e.jQuery,u=e.$,c={},p=[],f="1.10.2",d=p.concat,h=p.push,g=p.slice,m=p.indexOf,y=c.toString,v=c.hasOwnProperty,b=f.trim
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.323 Weak Randomness（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-1.10.2.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e,t){var n,r,i=typeof t,o=e.location,a=e.document,s=a.documentElement,l=e.jQuery,u=e.$,c={},p=[],f="1.10.2",d=p.concat,h=p.push,g=p.slice,m=p.indexOf,y=c.toString,v=c.hasOwnProperty,b=f.trim
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.324 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-1.10.2.min.js:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
}({});var B=/(?:\{[\s\S]*\}|\[[\s\S]*\])$/,P=/([A-Z])/g;function R(e,n,r,i){if(x.acceptData(e)){var o,a,s=x.expando,l=e.nodeType,u=l?x.cache:e,c=l?e[s]:e[s]&&s;if(c&&u[c]&&(i||u[c].data)||r!==t||"stri
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.325 XSS（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-1.10.2.min.js:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
}({});var B=/(?:\{[\s\S]*\}|\[[\s\S]*\])$/,P=/([A-Z])/g;function R(e,n,r,i){if(x.acceptData(e)){var o,a,s=x.expando,l=e.nodeType,u=l?x.cache:e,c=l?e[s]:e[s]&&s;if(c&&u[c]&&(i||u[c].data)||r!==t||"stri
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.326 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-1.10.2.min.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
u[o]&&(delete u[o],c?delete n[l]:typeof n.removeAttribute!==i?n.removeAttribute(l):n[l]=null,p.push(o))}},_evalUrl:function(e){return x.ajax({url:e,type:"GET",dataType:"script",async:!1,global:!1,"thr
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.327 Path Traversal（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-1.10.2.min.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
u[o]&&(delete u[o],c?delete n[l]:typeof n.removeAttribute!==i?n.removeAttribute(l):n[l]=null,p.push(o))}},_evalUrl:function(e){return x.ajax({url:e,type:"GET",dataType:"script",async:!1,global:!1,"thr
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.328 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-ui-1.10.4.custom.min.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e,t){function i(t,i){var a,n,r,o=t.nodeName.toLowerCase();return"area"===o?(a=t.parentNode,n=a.name,t.href&&n&&"map"===a.nodeName.toLowerCase()?(r=e("img[usemap=#"+n+"]")[0],!!r&&s(r)):!1):(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.329 XSS（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-ui-1.10.4.custom.min.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e,t){function i(t,i){var a,n,r,o=t.nodeName.toLowerCase();return"area"===o?(a=t.parentNode,n=a.name,t.href&&n&&"map"===a.nodeName.toLowerCase()?(r=e("img[usemap=#"+n+"]")[0],!!r&&s(r)):!1):(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.330 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-ui-1.10.4.custom.min.js:7`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return isNaN(t)?c:t},m=p(d[0]),f=Math.max(m,p(d[1]||"")),m=s?Math.max(m,s.getFullYear()):m,f=a?Math.min(f,a.getFullYear()):f,e.yearshtml+="<select class='ui-datepicker-year' data-handler='selectYear' 
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.331 Path Traversal（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-ui-1.10.4.custom.min.js:7`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return isNaN(t)?c:t},m=p(d[0]),f=Math.max(m,p(d[1]||"")),m=s?Math.max(m,s.getFullYear()):m,f=a?Math.min(f,a.getFullYear()):f,e.yearshtml+="<select class='ui-datepicker-year' data-handler='selectYear' 
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.332 XSS（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery/jquery-ui-1.10.4.custom.min.js:7`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return isNaN(t)?c:t},m=p(d[0]),f=Math.max(m,p(d[1]||"")),m=s?Math.max(m,s.getFullYear()):m,f=a?Math.min(f,a.getFullYear()):f,e.yearshtml+="<select class='ui-datepicker-year' data-handler='selectYear' 
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.333 XSS（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/jquery_form/jquery.form.js:660`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if (!isXml && window.opera && (doc.body === null || !doc.body.innerHTML)) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.334 SQL Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/backbone-min.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(t){var e=typeof self=="object"&&self.self===self&&self||typeof global=="object"&&global.global===global&&global;if(typeof define==="function"&&define.amd){define(["underscore","jquery","expo
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.335 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/backbone-min.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(t){var e=typeof self=="object"&&self.self===self&&self||typeof global=="object"&&global.global===global&&global;if(typeof define==="function"&&define.amd){define(["underscore","jquery","expo
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.336 Path Traversal（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/backbone-min.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(t){var e=typeof self=="object"&&self.self===self&&self||typeof global=="object"&&global.global===global&&global;if(typeof define==="function"&&define.amd){define(["underscore","jquery","expo
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.337 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-2.1.4.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(a,b){"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a document");return 
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.338 XSS（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-2.1.4.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(a,b){"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a document");return 
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.339 Weak Randomness（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-2.1.4.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(a,b){"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a document");return 
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.340 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-2.1.4.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return M.access(a,b,c)},removeData:function(a,b){M.remove(a,b)},_data:function(a,b,c){return L.access(a,b,c)},_removeData:function(a,b){L.remove(a,b)}}),n.fn.extend({data:function(a,b){var c,d,e,f=thi
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.341 XSS（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-2.1.4.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return M.access(a,b,c)},removeData:function(a,b){M.remove(a,b)},_data:function(a,b,c){return L.access(a,b,c)},_removeData:function(a,b){L.remove(a,b)}}),n.fn.extend({data:function(a,b){var c,d,e,f=thi
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.342 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-2.1.4.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
void 0===c?d&&"get"in d&&null!==(e=d.get(a,b))?e:(e=n.find.attr(a,b),null==e?void 0:e):null!==c?d&&"set"in d&&void 0!==(e=d.set(a,c,b))?e:(a.setAttribute(b,c+""),c):void n.removeAttr(a,b))},removeAttr
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.343 Path Traversal（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-2.1.4.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
void 0===c?d&&"get"in d&&null!==(e=d.get(a,b))?e:(e=n.find.attr(a,b),null==e?void 0:e):null!==c?d&&"set"in d&&void 0!==(e=d.set(a,c,b))?e:(a.setAttribute(b,c+""),c):void n.removeAttr(a,b))},removeAttr
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.344 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-ui.min.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(t){"function"==typeof define&&define.amd?define(["jquery"],t):t(jQuery)})(function(t){function e(t){for(var e=t.css("visibility");"inherit"===e;)t=t.parent(),e=t.css("visibility");return"hid
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.345 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-ui.min.js:7`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
}}(t.fn.show),hide:function(t){return function(s){if(i(s))return t.apply(this,arguments);var n=e.apply(this,arguments);return n.mode="hide",this.effect.call(this,n)}}(t.fn.hide),toggle:function(t){ret
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.346 Path Traversal（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-ui.min.js:7`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
}}(t.fn.show),hide:function(t){return function(s){if(i(s))return t.apply(this,arguments);var n=e.apply(this,arguments);return n.mode="hide",this.effect.call(this,n)}}(t.fn.hide),toggle:function(t){ret
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.347 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-ui.min.js:9`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
}},_updateDatepicker:function(e){this.maxRows=4,m=e,e.dpDiv.empty().append(this._generateHTML(e)),this._attachHandlers(e);var i,s=this._getNumberOfMonths(e),n=s[1],a=17,r=e.dpDiv.find("."+this._dayOve
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.348 Path Traversal（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-ui.min.js:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
},_cacheMargins:function(){this.margins={left:parseInt(this.element.css("marginLeft"),10)||0,top:parseInt(this.element.css("marginTop"),10)||0,right:parseInt(this.element.css("marginRight"),10)||0,bot
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.349 Path Traversal（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-ui.min.js:13`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this._delay(function(){n===this.counter&&this.refreshPositions(!s)})},_clear:function(t,e){function i(t,e,i){return function(s){i._trigger(t,s,e._uiHash(e))}}this.reverting=!1;var s,n=[];if(!this._noF
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.350 XSS（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-ui.min.js:13`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this._delay(function(){n===this.counter&&this.refreshPositions(!s)})},_clear:function(t,e){function i(t,e,i){return function(s){i._trigger(t,s,e._uiHash(e))}}this.reverting=!1;var s,n=[];if(!this._noF
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.351 XSS（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery.form.js:660`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if (!isXml && window.opera && (doc.body === null || !doc.body.innerHTML)) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.352 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(e,t){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error("jQuery requires a window with a docum
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.353 Path Traversal（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(e,t){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error("jQuery requires a window with a docum
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.354 XSS（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(e,t){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error("jQuery requires a window with a docum
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.355 Weak Randomness（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(e,t){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error("jQuery requires a window with a docum
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.356 Weak Randomness（MEDIUM）

- 文件：`src/main/resources/webgoat/static/js/libs/underscore-min.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var n="object"==typeof self&&self.self===self&&self||"object"==typeof global&&global.global===global&&global||Function("return this")()||{},e=Array.prototype,i=Object.prototype,p="undefined"!=typeof S
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.357 Command Injection（MEDIUM）

- 文件：`src/main/resources/webgoat/static/plugins/nanoScroller/jquery.nanoscroller.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(a,b,c){"use strict";var d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F;x={paneClass:"nano-pane",sliderClass:"nano-slider",contentClass:"nano-content",iOSNativeScrolling:!1,prevent
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.358 XSS（LOW）

- 文件：`src/main/resources/lessons/clientsidefiltering/js/clientSideFiltering.js:38`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
newdiv.innerHTML = html;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.359 Path Traversal（LOW）

- 文件：`src/main/resources/webgoat/static/js/modernizr.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(e,t,n){function r(e){var t=N.className,n=Modernizr._config.classPrefix||"";if(z&&(t=t.baseVal),Modernizr._config.enableJSClass){var r=new RegExp("(^|\\s)"+n+"no-js(\\s|$)");t=t.replace(r,"$1
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.360 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/js/modernizr.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(e,t,n){function r(e){var t=N.className,n=Modernizr._config.classPrefix||"";if(z&&(t=t.baseVal),Modernizr._config.enableJSClass){var r=new RegExp("(^|\\s)"+n+"no-js(\\s|$)");t=t.replace(r,"$1
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.361 Path Traversal（LOW）

- 文件：`src/main/resources/webgoat/static/js/quiz.js:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
client.open('GET', 'lesson_js/questions_' + quiz_id + '.json');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.362 Server-Side Template Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/goatApp/view/MenuView.js:58`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
//var lessons = new MenuItemView({items:items[i].get('children')}).render();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.363 SSRF（LOW）

- 文件：`src/main/resources/webgoat/static/js/goatApp/view/PaginationControlView.js:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.collection.fetch({reset:true});
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.364 SSRF（LOW）

- 文件：`src/main/resources/webgoat/static/js/goatApp/view/PaginationControlView.js:35`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.collection.fetch({reset:true});
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.365 SSRF（LOW）

- 文件：`src/main/resources/webgoat/static/js/goatApp/view/PaginationControlView.js:147`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.collection.fetch({reset:true});
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.366 SSRF（LOW）

- 文件：`src/main/resources/webgoat/static/js/goatApp/view/PaginationControlView.js:164`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.collection.fetch({reset:true});
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.367 Path Traversal（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:138`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return _require(moduleName, module, callback);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.368 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:4970`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
success = commands.exec(toExecute.command, this.$editor, toExecute.args, e);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.369 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:4983`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
success = commands.exec("insertstring", this.$editor, keyString);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.370 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:5475`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.fontMetrics.$main.innerHTML = (this.line.charAt(this.line.length - 1) == bidiUtil.DOT) ? this.line.substr(0, this.line.length - 1) : this.line;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.371 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:6291`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var matchcount = new RegExp("(?:(" + adjustedregex + ")|(.))").exec("a").length - 2;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.372 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:12175`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return e.command.exec(e.editor, e.args || {});
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.373 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:13676`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.commands.exec("paste", this, e);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.374 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:16592`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
while (m = re.exec(value)) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.375 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:17320`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.$measureNode.innerHTML = lang.stringRepeat("X", CHAR_COUNT);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.376 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:17409`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.$main.innerHTML = lang.stringRepeat(ch, CHAR_COUNT);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.377 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:20315`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var result = command.exec(editor, e.args || {});
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.378 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:20324`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
result = command.exec(editor, e.args || {});
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.379 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:20342`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return cmd.exec ? cmd.exec(this, args || {}) : cmd(this, args || {});
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.380 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:20357`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var cmdResult = cmd.exec ? cmd.exec(this, args || {}) : cmd(this, args || {});
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.381 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/ace.js:21469`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
el.innerHTML = gutterAnno.text.join("<br>");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.382 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-ui-1.10.4.js:249`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$.ui.ie = !!/msie [\w.]+/.exec( navigator.userAgent.toLowerCase() );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.383 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-ui-1.10.4.js:5343`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
match = rplusequals.exec( value );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.384 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-ui-1.10.4.js:10825`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
percent = /([0-9]+)%/.exec( size ),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.385 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/jquery-ui-1.10.4.js:12179`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
horizontalOffset = roffset.exec( pos[ 0 ] );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.386 Path Traversal（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/mode-java.js:876`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
regex: "(open(?:\\s+))?module(?=\\s*\\w)",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.387 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/require.min.js:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var requirejs,require,define;!function(global,setTimeout){var req,s,head,baseElement,dataMain,src,interactiveScript,currentlyAddingScript,mainScript,subPath,version="2.3.6",commentRegExp=/\/\*[\s\S]*?
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.388 Path Traversal（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/require.min.js:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var requirejs,require,define;!function(global,setTimeout){var req,s,head,baseElement,dataMain,src,interactiveScript,currentlyAddingScript,mainScript,subPath,version="2.3.6",commentRegExp=/\/\*[\s\S]*?
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.389 SSRF（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/require.min.js:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var requirejs,require,define;!function(global,setTimeout){var req,s,head,baseElement,dataMain,src,interactiveScript,currentlyAddingScript,mainScript,subPath,version="2.3.6",commentRegExp=/\/\*[\s\S]*?
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.390 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/js/libs/underscore-min.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var n="object"==typeof self&&self.self===self&&self||"object"==typeof global&&global.global===global&&global||Function("return this")()||{},e=Array.prototype,i=Object.prototype,p="undefined"!=typeof S
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.391 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:3658`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
returnValue                 = innerHTML === "<p></p><div></div>" || innerHTML === "<p><div></div></p>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.392 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:4011`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
tempElement.innerHTML = "<span></span>" + _convertUrlsToLinks(textNode.data);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.393 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:4394`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
tempElement = _innerHTMLShiv(html, context);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.394 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:5706`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if (innerHTML == "<p>&nbsp;</p>" ||
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.395 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:5784`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if (innerHTML.indexOf(TILDE_ESCAPED) === -1) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.396 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:5796`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
innerHTML   = wysihtml5.lang.string(innerHTML).replace(urlToSearch).by(url);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.397 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:6918`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
wysihtml5.commands.formatInline.exec(composer, undef, NODE_NAME, tempClass, tempClassRegExp);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.398 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:6992`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return wysihtml5.commands.formatInline.exec(composer, command, "span", "wysiwyg-font-size-" + size, REG_EXP);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.399 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:7015`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return wysihtml5.commands.formatInline.exec(composer, command, "span", "wysiwyg-color-" + color, REG_EXP);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.400 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:7481`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
composer.commands.exec("insertHTML", LINE_BREAK);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.401 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:7531`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
isEmpty = tempElement.innerHTML === "" || tempElement.innerHTML === wysihtml5.INVISIBLE_SPACE;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.402 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:7588`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
isEmpty = tempElement.innerHTML === "" || tempElement.innerHTML === wysihtml5.INVISIBLE_SPACE;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.403 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:7635`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return wysihtml5.commands.formatBlock.exec(composer, "formatBlock", null, CLASS_NAME, REG_EXP);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.404 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:7653`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return wysihtml5.commands.formatBlock.exec(composer, "formatBlock", null, CLASS_NAME, REG_EXP);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.405 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:7671`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return wysihtml5.commands.formatBlock.exec(composer, "formatBlock", null, CLASS_NAME, REG_EXP);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.406 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:8022`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return innerHTML === ""              ||
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.407 XSS（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:8023`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
innerHTML === this.CARET_HACK ||
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.408 Command Injection（LOW）

- 文件：`src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js:8526`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
that.commands.exec("insertHTML", data);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。





## 5. 关键风险

- HIGH run-shell-injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\.github\workflows\release.yml:24，状态为 confirmed。
- HIGH detected-jwt-token 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\it\java\org\owasp\webgoat\playwright\webwolf\JwtUITest.java:31，状态为 confirmed。
- HIGH tainted-sql-string 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\challenges\challenge5\Assignment5.java:45，状态为 confirmed。
- HIGH formatted-sql-string 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\challenges\challenge5\Assignment5.java:50，状态为 confirmed。
- HIGH tainted-url-host 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_28876629\src\main\java\org\owasp\webgoat\lessons\jwt\claimmisuse\JWTHeaderJKUEndpoint.java:57，状态为 confirmed。


## 6. 修改建议

- **P0 优先修复 Critical/High 漏洞：** 先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。
- **P1 按漏洞类型批量治理：** 对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。
- **P1 补充动态验证覆盖：** 为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。
- **P2 纳入持续审计流程：** 将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。


## 7. 结论

综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 HIGH 风险水平。建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
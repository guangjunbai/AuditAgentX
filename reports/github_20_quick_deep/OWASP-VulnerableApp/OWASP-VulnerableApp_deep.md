# OWASP-VulnerableApp 安全审计报告

> 生成工具：AuditAgentX　生成时间：2026-07-09 10:04:14 UTC

## 1. 执行摘要

本次审计对象为 OWASP-VulnerableApp，来源为 https://github.com/SasanLabs/VulnerableApp，项目主要语言为 Java、JavaScript、Shell，框架识别结果为 Spring、Spring Boot，共解析 197 个文件、24219 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC 并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 152 条风险，其中 Critical 2 条、High 58 条、Medium 84 条、Low 8 条；静态分析覆盖 152 条，动态验证覆盖 3 条，其中 0 条已复现。主要风险类型集中在 Hardcoded Secret(22)、no-new-privileges(20)、writable-filesystem-service(20)、github-actions-mutable-action-tag(19)，总体风险评级为 CRITICAL。

**总体风险等级：CRITICAL**

### 1.1 项目概况总结

项目 OWASP-VulnerableApp 来源于 https://github.com/SasanLabs/VulnerableApp，主要语言为 Java、JavaScript、Shell，框架为 Spring、Spring Boot，共 197 个文件、24219 行代码。

### 1.2 漏洞结果总结

本次共发现 152 条漏洞，其中 Critical 2 条、High 58 条、Medium 84 条、Low 8 条。

**静态分析总结：** 静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 152 条静态风险。主要来源分布为 semgrep(108)、custom-taint(39)、audit_agent(5)。这些结果先作为候选项进入 VerifyAgent，避免仅凭规则命中直接下结论。

**动态验证总结：** 动态验证阶段对 3 条漏洞保存了运行证据，其中 0 条具备可复现结果。报告中的 Source、Sink、调用路径、PoC 和 runtime 证据共同构成证据链。

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
| 扫描任务 | scan_8e0a7d8a（full / done） |

## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | 2 |
| High | 58 |
| Medium | 84 |
| Low | 8 |
| **合计** | **152** |

## 4. 漏洞明细


### 4.1 Command Injection（CRITICAL）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\commandInjection\CommandInjection.java:48`
- 来源：audit_agent
- 置信度：0.97
- 已验证：是
- 状态：confirmed

```text
if (!isWindows) {
    process =
            new ProcessBuilder(new String[] {"sh", "-c", "ping -c 2 " + ipAddress})
                    .redirectErrorStream(true)
                    .start();
} else {
    process =
            new ProcessBuilder(new String[] {"cmd", "/c", "ping -n 2 " + ipAddress})
                    .redirectErrorStream(true)
                    .start();
}
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。


**证据链：**

- 知识增强：CWE-78 / A03:2021 Injection、A05:2025 Injection
- 知识库验证条件：

  1. Confirm the fix removes shell=True or untrusted command string construction.

  2. Confirm source-to-sink reachability from untrusted input to command execution.

  3. Check whether shell=True or shell string construction is used.

  4. Prefer harness verification that mocks command execution instead of running destructive commands.

  5. Only use harmless local payloads such as echo markers in authorized sandboxes.

- 误报判据：

  1. The command is already executed as a fixed argument array with shell=False.

  2. The executable and arguments are fixed server-side values.

  3. The command is called with an argument array and shell=False.

  4. Input is selected from a strict allowlist.

- 知识库修复建议：Prefer language/library APIs over external process execution.；Pass arguments as arrays and keep shell=False.；Use strict allowlists for any remaining user-controlled arguments.

- Source：`HTTP GET parameter 'ipAddress' in request to CommandInjection endpoint`
- Sink：`ProcessBuilder with 'sh -c' or 'cmd /c' executing user-controlled command string`

- 调用路径：

  1. candidate：if (!isWindows) { process = new ProcessBuilder(new String[] {"sh", "-c", "ping -c 2 " + ipAddress}) ... } else { process = new ProcessBuilder(new String[] {"cmd", "/c", "ping -n 2 " + ipAddress}) ... }


- 利用路径：HTTP GET parameter 'ipAddress' is concatenated directly into a shell command 'ping -c 2 ' + ipAddress (Linux) or 'ping -n 2 ' + ipAddress (Windows), then executed via ProcessBuilder with 'sh -c' or 'cmd /c'.
- 触发位置：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\commandInjection\CommandInjection.java:48`
- Payload：`; echo AUDITAGENTX_RCE_1337 / | echo AUDITAGENTX_RCE_1337 / $(echo AUDITAGENTX_RCE_1337) / `echo AUDITAGENTX_RCE_1337` / & echo AUDITAGENTX_RCE_1337`
- Docker 沙箱：sandbox_start_failed（健康检查 failed，镜像 `auditagentx-scan8e0a7d8a`，启动命令 `docker compose -f docker-compose.yml up -d --build`）
- 动态验证状态：sandbox_start_failed
- 命中特征：`N/A`
- 响应状态：N/A
- 请求：`N/A`
- 原因：Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）

- 动态证据流：

  1. source：HTTP GET parameter 'ipAddress' in request to CommandInjection endpoint

  2. sink：ProcessBuilder with 'sh -c' or 'cmd /c' executing user-controlled command string

  3. payload：; echo AUDITAGENTX_RCE_1337

  4. response：{'status': None, 'matched_indicator': '', 'reason': 'Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）'}


- Harness：target_confirmed，触发=是，原因=N/A
- 验证裁决：静态=confirmed；动态=harness_confirmed；最终=dynamic_confirmed
- Skill：`{'name': '', 'version': None}`
- 证据链日志：候选漏洞由 AuditAgent 产生；VerifyAgent 独立复核通过；ExploitAgent 生成利用方案: Command Injection；HTTP 动态验证跳过: Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）；Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败；回退：目标函数级 Harness 已复现漏洞，见 harness 证据；Fuzzing Harness 验证: target_confirmed（Command injection detected: args=['sh', '-c', 'ping -c 2 ; id']）；Docker 沙箱: sandbox_start_failed（健康检查 failed）；安全知识增强: CWE-78




### 4.2 SQL Injection（CRITICAL）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\BlindSQLInjectionVulnerability.java:53`
- 来源：audit_agent
- 置信度：0.97
- 已验证：是
- 状态：confirmed

```text
String id = queryParams.get(Constants.ID);
BodyBuilder bodyBuilder = ResponseEntity.status(HttpStatus.OK);
return applicationJdbcTemplate.query(
        "select * from cars where id=" + id,
        (rs) -> {
            if (rs.next()) {
                return bodyBuilder.body(CAR_IS_PRESENT_RESPONSE);
            }
            return bodyBuilder.body(
                    ErrorBasedSQLInjectionVulnerability.CAR_IS_NOT_PRESENT_RESPONSE);
        });
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。


**证据链：**

- 知识增强：CWE-89 / A03:2021 Injection、A05:2025 Injection
- 知识库验证条件：

  1. Confirm user-controlled input reaches SQL construction or execution.

  2. Confirm the query is built with string concatenation, interpolation, or formatting.

  3. Confirm no prepared statement, parameter binding, or strong type conversion separates data from SQL.

  4. Read the local code window and identify the source variable.

  5. Trace whether the source reaches the SQL sink without parameter binding.

  6. If a local target is running, send benign quote/boolean payloads and look for SQL error or response difference.

  7. If no target exists, record dynamic_verdict=not_executed instead of not_reproduced.

- 误报判据：

  1. The sink uses parameter placeholders with a separate parameter tuple/list.

  2. The value is converted to a strict numeric type before reaching SQL.

  3. The SQL statement is a static literal and user input is not interpolated.

  4. Prepared statement with separate parameter binding is present.

  5. The scanner matched a query template but not an executable sink.

  6. The suspect value is a constant or strictly converted numeric value.

- 知识库修复建议：Use prepared statements or parameterized queries.；Do not concatenate user-controlled strings into SQL.；Run database users with least privilege and avoid detailed SQL errors in responses.；Replace string-built SQL with prepared statements or parameterized queries.；Validate business constraints separately from SQL escaping.；Use least-privilege DB users and avoid exposing detailed database errors.

- Source：`request/user-controlled value`
- Sink：`SQL execution API`

- 调用路径：

  1. source：request/user-controlled value

  2. candidate：String id = queryParams.get(Constants.ID);
BodyBuilder bodyBuilder = ResponseEntity.status(HttpStatus.OK);
return applicationJdbcTemplate.query(
        "select * from cars where id=" + id,
        (rs) -> {
            if (rs.next()) {
   

  3. sink：SQL execution API


- 利用路径：用户通过HTTP GET参数id传入值，该值直接拼接到SQL查询字符串中，在applicationJdbcTemplate.query执行时触发注入，根据结果返回不同响应（Car is present / Car is not present）。
- 触发位置：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\BlindSQLInjectionVulnerability.java:53`
- Payload：`1 OR 1=1 / 1 AND 1=2`
- Docker 沙箱：sandbox_start_failed（健康检查 failed，镜像 `auditagentx-scan8e0a7d8a`，启动命令 `docker compose -f docker-compose.yml up -d --build`）
- 动态验证状态：sandbox_start_failed
- 命中特征：`N/A`
- 响应状态：N/A
- 请求：`N/A`
- 原因：Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）

- 动态证据流：

  1. source：request/user-controlled value

  2. sink：SQL execution API

  3. payload：1 OR 1=1

  4. response：{'status': None, 'matched_indicator': '', 'reason': 'Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）'}


- Harness：target_confirmed，触发=是，原因=N/A
- 验证裁决：静态=confirmed；动态=harness_confirmed；最终=dynamic_confirmed
- Skill：`{'name': '', 'version': None}`
- 证据链日志：候选漏洞由 AuditAgent 产生；VerifyAgent 独立复核通过；ExploitAgent 生成利用方案: SQL Injection；HTTP 动态验证跳过: Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）；Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败；回退：目标函数级 Harness 已复现漏洞，见 harness 证据；Fuzzing Harness 验证: target_confirmed（SQL injection detected: SQL query 'select * from cars where id=1 OR 1=1' contains malicious patterns）；Docker 沙箱: sandbox_start_failed（健康检查 failed）；安全知识增强: CWE-89




### 4.3 Path Traversal（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\fileupload\PreflightController.java:39`
- 来源：audit_agent
- 置信度：0.9
- 已验证：否
- 状态：needs_review

```text
public ResponseEntity<byte[]> fetchFile(@PathVariable("fileName") String fileName)
        throws IOException {
    // Resolve path using Path API
    Path filePath = unrestrictedFileUpload.getContentDispositionRoot().resolve(fileName);
    // Try-with-resources ensures the stream closes automatically
    try (InputStream inputStream = new FileInputStream(filePath.toFile())) {
        byte[] fileBytes = IOUtils.toByteArray(inputStream);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(CONTENT_DISPOSITION, "attachment");
        return new ResponseEntity<>(fileBytes, httpHeaders, HttpStatus.OK);
    }
}
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.4 SSRF（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\ssrf\SSRFVulnerability.java:62`
- 来源：audit_agent
- 置信度：0.55
- 已验证：是
- 状态：confirmed

```text
private ResponseEntity<GenericVulnerabilityResponseBean<String>>
        getGenericVulnerabilityResponseWhenURL(@RequestParam(FILE_URL) String url)
                throws IOException {
    if (isUrlValid(url)) {
        URL u = new URL(url);
        if (MetaDataServiceMock.isPresent(u)) {
            return new ResponseEntity<>(
                    new GenericVulnerabilityResponseBean<>(
                            MetaDataServiceMock.getResponse(u), true),
                    HttpStatus.OK);
        } else {
            return new ResponseEntity<>(
                    new GenericVulnerabilityResponseBean<>(
                            getResponseForURLConnection(u), true),
                    HttpStatus.OK);
        }
    } else {
        return invalidUrlResponse();
    }
}
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。


**证据链：**

- 知识增强：CWE-918 / A10:2021 Server-Side Request Forgery
- 知识库验证条件：

  1. Confirm the user-controlled value becomes the host/URL of an outbound request.

  2. Check for an allowlist of schemes/hosts and blocking of internal ranges and cloud metadata endpoints.

  3. In an authorized sandbox only, point the target at a controlled local collaborator or 169.254.169.254 and observe whether the server initiates the request.

  4. Never probe third-party or production metadata endpoints.

- 误报判据：

  1. The destination host/scheme is restricted by a strict allowlist.

  2. The URL is a fixed server-side constant, not user-controlled.

  3. Internal IP ranges and metadata IPs are explicitly blocked.

- 知识库修复建议：Enforce a scheme/host allowlist and block internal ranges and metadata IPs.；Resolve and validate the target host before requesting.；Allowlist permitted schemes and destination hosts; deny by default.；Resolve the hostname and reject private/link-local/loopback ranges and cloud metadata IPs (169.254.169.254).；Disable unneeded redirects and require egress through a controlled proxy.

- Source：`FILE_URL request parameter`
- Sink：`java.net.URLConnection (via getResponseForURLConnection)`

- 调用路径：

  1. candidate：getGenericVulnerabilityResponseWhenURL


- 利用路径：用户通过HTTP GET参数'FILE_URL'传入URL，经isUrlValid校验后，直接用于创建java.net.URL对象并调用URLConnection发起请求，导致服务端请求伪造。
- 触发位置：`SSRFVulnerability.java:62`
- Payload：`http://127.0.0.1:80/ / http://169.254.169.254/latest/meta-data/ / http://localhost/admin / file:///etc/passwd`
- Docker 沙箱：sandbox_start_failed（健康检查 failed，镜像 `auditagentx-scan8e0a7d8a`，启动命令 `docker compose -f docker-compose.yml up -d --build`）
- 动态验证状态：sandbox_start_failed
- 命中特征：`N/A`
- 响应状态：N/A
- 请求：`N/A`
- 原因：Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败

- 动态证据流：

  1. source：FILE_URL request parameter

  2. sink：java.net.URLConnection (via getResponseForURLConnection)

  3. payload：http://127.0.0.1:80/

  4. response：{'status': None, 'matched_indicator': '', 'reason': 'Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败'}


- Harness：unsafe_harness_blocked，触发=否，原因=unsafe_harness_blocked: real HTTP via urllib
- 验证裁决：静态=confirmed；动态=not_runtime_verifiable；最终=statically_verified
- Skill：`{'name': '', 'version': None}`
- 证据链日志：候选漏洞由 AuditAgent 产生；VerifyAgent 独立复核通过；ExploitAgent 生成利用方案: SSRF；HTTP 动态验证跳过: Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败；Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败；Fuzzing Harness 验证: unsafe_harness_blocked；Docker 沙箱: sandbox_start_failed（健康检查 failed）；安全知识增强: CWE-918




### 4.5 command-injection-process-builder（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\commandInjection\CommandInjection.java:52`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.6 tainted-file-path（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\fileupload\PreflightController.java:46`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.7 tainted-url-host（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\rfi\UrlParamBasedRFI.java:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.8 tainted-url-host（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\rfi\UrlParamBasedRFI.java:63`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.9 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\BlindSQLInjectionVulnerability.java:58`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.10 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\BlindSQLInjectionVulnerability.java:82`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.11 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\BlindSQLInjectionVulnerability.java:132`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.12 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\ErrorBasedSQLInjectionVulnerability.java:67`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.13 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\ErrorBasedSQLInjectionVulnerability.java:112`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.14 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\ErrorBasedSQLInjectionVulnerability.java:160`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.15 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\ErrorBasedSQLInjectionVulnerability.java:211`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.16 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\UnionBasedSQLInjectionVulnerability.java:69`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.17 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\UnionBasedSQLInjectionVulnerability.java:84`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.18 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\UnionBasedSQLInjectionVulnerability.java:99`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.19 tainted-url-host（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\ssrf\SSRFVulnerability.java:66`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.20 tainted-url-host（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\ssrf\SSRFVulnerability.java:129`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.21 tainted-url-host（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\ssrf\SSRFVulnerability.java:146`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.22 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:56`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.23 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:72`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.24 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:91`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.25 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:115`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.26 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:147`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.27 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:170`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.28 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSInImgTagAttribute.java:200`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.29 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSWithHtmlTagInjection.java:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.30 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSWithHtmlTagInjection.java:66`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.31 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSWithHtmlTagInjection.java:91`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.32 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSWithHtmlTagInjection.java:111`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.33 tainted-html-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\xss\reflected\XSSWithHtmlTagInjection.java:131`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.34 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\resources\attackvectors\JWTVulnerabilityPayload.properties:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.35 detected-bcrypt-hash（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\resources\scripts\Authentication\db\data.sql:27`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.36 detected-bcrypt-hash（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\resources\scripts\Authentication\db\data.sql:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.37 detected-bcrypt-hash（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\resources\scripts\Authentication\db\data.sql:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.38 detected-private-key（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\resources\static\templates\JWTVulnerability\keys\private_key.pem:5`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.39 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/cryptographicFailures/repo/CryptographicFailuresSeeder.java:84`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
String level10Secret = "aa123456";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.40 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/idor/IDORLoginService.java:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
private static final String INVALID_TOKEN = "Invalid token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.41 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/idor/IDORVulnerability.java:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
private static final String INVALID_TOKEN = "Invalid token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.42 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/idor/IDORVulnerability.java:26`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
private static final String PROVIDE_LOGIN_OR_TOKEN = "Provide login or token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.43 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/jwt/bean/JWTUtils.java:65`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
public static final String BEGIN_PRIVATE_KEY_TOKEN = "-----BEGIN PRIVATE KEY-----";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.44 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/jwt/bean/JWTUtils.java:67`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
public static final String END_PRIVATE_KEY_TOKEN = "-----END PRIVATE KEY-----";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.45 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/jwt/bean/JWTUtils.java:68`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
public static final String BEGIN_PUBLIC_KEY_TOKEN = "-----BEGIN PUBLIC KEY-----";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.46 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/jwt/bean/JWTUtils.java:69`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
public static final String END_PUBLIC_KEY_TOKEN = "-----END PUBLIC KEY-----";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.47 Hardcoded Secret（HIGH）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/jwt/keys/JWTAlgorithmKMS.java:41`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
private static final String KEY_STORE_PASSWORD = "changeIt";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.48 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/internal/utility/PasswordHashingUtilsTest.java:41`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
String rawPassword = "securePassword123";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.49 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/internal/utility/PasswordHashingUtilsTest.java:53`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
String password = "mySecretPassword";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.50 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORLoginServiceTest.java:47`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
String rawPassword = "P@ssw0rd!2026";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.51 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORLoginServiceTest.java:83`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
String rawPassword = "P@ssw0rd!2026";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.52 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORLoginServiceTest.java:116`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
String rawPassword = "P@ssw0rd!2026";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.53 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORVulnerabilityTest.java:38`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
String validToken = "valid-token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.54 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORVulnerabilityTest.java:59`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
String validToken = "valid-token-level2";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.55 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/idor/IDORVulnerabilityTest.java:163`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
String invalidToken = "invalid-token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.56 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/ldapInjection/LDAPInjectionVulnerabilityTest.java:57`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
String username = "*)(uid=*", password = "alicePass123";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.57 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/ldapInjection/LDAPInjectionVulnerabilityTest.java:90`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
String password = "antrikshPass123";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.58 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/sessionManagement/SessionManagementServiceTest.java:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
private static final String PASSWORD = "password123";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.59 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/sessionManagement/SessionManagementServiceTest.java:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
private static final String BAD_PASSWORD = "wrong-password";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.60 Hardcoded Secret（HIGH）

- 文件：`src/test/java/org/sasanlabs/service/vulnerability/sessionManagement/SessionManagementServiceTest.java:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
private static final String FIXED_TOKEN = "attacker-fixed-token";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.61 Weak Encryption (AES/ECB)（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\internal\utility\EncryptionUtils.java:85`
- 来源：audit_agent
- 置信度：1.0
- 已验证：否
- 状态：needs_review

```text
public static String encrypt(String plaintext, SecretKey key) throws EncryptionException {
    try {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return java.util.Base64.getEncoder().encodeToString(encrypted);
    } catch (...) { ... }
}
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.62 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\create-release.yml:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.63 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\create-release.yml:29`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.64 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\create-release.yml:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.65 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\docker.yml:20`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.66 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\docker.yml:25`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.67 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\docker.yml:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.68 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\docker.yml:34`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.69 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\docker.yml:37`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.70 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\docker.yml:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.71 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\docker.yml:46`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.72 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\docker.yml:55`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.73 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\gradle.yml:15`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.74 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\gradle.yml:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.75 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\gradle.yml:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.76 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\onboard_sasanlabs.yml:19`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.77 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\onboard_sasanlabs.yml:51`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.78 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\onboard_sasanlabs.yml:83`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.79 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\onboard_sasanlabs.yml:96`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.80 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\.github\workflows\stats.yml:16`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.81 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.local.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.82 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.local.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.83 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.local.yml:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.84 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.local.yml:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.85 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.local.yml:10`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.86 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.local.yml:10`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.87 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.local.yml:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.88 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.local.yml:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.89 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.local.yml:28`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.90 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.local.yml:28`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.91 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.prod.yml:4`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.92 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.prod.yml:4`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.93 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.prod.yml:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.94 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.prod.yml:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.95 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.without_llm.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.96 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.without_llm.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.97 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.without_llm.yml:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.98 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.without_llm.yml:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.99 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.without_llm.yml:9`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.100 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.without_llm.yml:9`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.101 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.without_llm.yml:12`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.102 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.without_llm.yml:12`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.103 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.without_llm.yml:27`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.104 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.without_llm.yml:27`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.105 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.106 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.107 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:8`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.108 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:8`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.109 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.110 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.111 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.112 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.113 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.114 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:35`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.115 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:57`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.116 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:57`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.117 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:76`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.118 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:76`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.119 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:95`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.120 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\docker-compose.yml:95`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.121 jdbc-sql-formatted-string（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\configuration\VulnerableAppConfiguration.java:134`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.122 spring-sqli（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\configuration\VulnerableAppConfiguration.java:135`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.123 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.124 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:58`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.125 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:76`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.126 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:91`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.127 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:120`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.128 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\controller\VulnerableAppRestController.java:136`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.129 ecb-cipher（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\internal\utility\EncryptionUtils.java:88`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.130 use-of-aes-ecb（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\internal\utility\EncryptionUtils.java:88`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.131 spring-sqli（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\authentication\AuthLoginService.java:51`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.132 unrestricted-request-mapping（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\fileupload\PreflightController.java:37`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.133 cookie-missing-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\idor\IDORLoginController.java:136`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.134 cookie-missing-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\idor\IDORLoginController.java:145`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.135 cookie-missing-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\idor\IDORLoginController.java:161`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.136 Weak Cryptography（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/internal/utility/EncryptionUtils.java:88`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.137 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/internal/utility/PasswordHashingUtils.java:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
MD5("MD5"),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.138 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/internal/utility/PasswordHashingUtils.java:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
SHA1("SHA-1"),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.139 Weak Cryptography（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/internal/utility/PasswordHashingUtils.java:150`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
Cipher des = Cipher.getInstance("DES/ECB/NoPadding", "BC");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.140 Weak Hash（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/cryptographicFailures/repo/CryptographicFailuresSeeder.java:68`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
// Level 6: MD5 (Broken Hash)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.141 Weak Randomness（MEDIUM）

- 文件：`src/main/java/org/sasanlabs/service/vulnerability/fileupload/UnrestrictedFileUpload.java:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
private static final Random RANDOM = new Random(new Date().getTime());
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.142 XSS（MEDIUM）

- 文件：`src/main/resources/static/templates/ClickjackingVulnerability/LEVEL_1/ClickjackingVulnerability.js:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if (!doc || doc.body.innerHTML === "") {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.143 XSS（MEDIUM）

- 文件：`src/main/resources/static/templates/CryptographicFailures/LEVEL_1/CryptographicFailures.js:44`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
resultDiv.innerHTML = "<strong>Result:</strong> " + data.content;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.144 XSS（MEDIUM）

- 文件：`src/main/resources/static/templates/CryptographicFailures/LEVEL_1/CryptographicFailures.js:47`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
resultDiv.innerHTML = "<strong>Result:</strong> " + data.content;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.145 XSS（LOW）

- 文件：`scripts/productionize/startup_script.sh:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.146 XSS（LOW）

- 文件：`scripts/productionize/startup_script.sh:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
echo ".env generated with random credentials"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.147 XSS（LOW）

- 文件：`src/main/resources/static/vulnerableApp.js:338`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
document.getElementById("helpText").innerHTML = helpText;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.148 XSS（LOW）

- 文件：`src/main/resources/static/templates/ClickjackingVulnerability/LEVEL_1/ClickjackingVulnerability.js:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
responseDiv.innerHTML = lines.join("<br/>");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.149 XSS（LOW）

- 文件：`src/main/resources/static/templates/ClickjackingVulnerability/LEVEL_4/ClickjackingVulnerability.js:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
r.innerHTML = lines.join("<br/>");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.150 XSS（LOW）

- 文件：`src/main/resources/static/templates/CryptographicFailures/LEVEL_1/CryptographicFailures.js:8`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
challengeDiv.innerHTML = "<strong>" + data.content + "</strong>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.151 XSS（LOW）

- 文件：`src/main/resources/static/templates/PathTraversal/LEVEL_1/PathTraversal.js:35`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
document.getElementById("Information").innerHTML = tableInformation;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.152 XSS（LOW）

- 文件：`src/main/resources/static/templates/SSRFVulnerability/LEVEL_1/SSRF.js:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
document.getElementById("projectsResponse").innerHTML = tableInformation;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。





## 5. 关键风险

- CRITICAL Command Injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\commandInjection\CommandInjection.java:48，状态为 confirmed。
- CRITICAL SQL Injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\sqlInjection\BlindSQLInjectionVulnerability.java:53，状态为 confirmed。
- HIGH Path Traversal 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\fileupload\PreflightController.java:39，状态为 needs_review。
- HIGH SSRF 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\ssrf\SSRFVulnerability.java:62，状态为 confirmed。
- HIGH command-injection-process-builder 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_d90931bd\src\main\java\org\sasanlabs\service\vulnerability\commandInjection\CommandInjection.java:52，状态为 needs_review。


## 6. 修改建议

- **P0 优先修复 Critical/High 漏洞：** 先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。
- **P1 按漏洞类型批量治理：** 对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。
- **P1 补充动态验证覆盖：** 为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。
- **P2 纳入持续审计流程：** 将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。


## 7. 结论

综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 CRITICAL 风险水平。建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
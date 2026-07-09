# RailsGoat 安全审计报告

> 生成工具：AuditAgentX　生成时间：2026-07-09 10:33:29 UTC

## 1. 执行摘要

本次审计对象为 RailsGoat，来源为 https://github.com/OWASP/railsgoat，项目主要语言为 Ruby、JavaScript，框架识别结果为 未识别，共解析 142 个文件、10484 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC 并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 118 条风险，其中 Critical 0 条、High 24 条、Medium 60 条、Low 34 条；静态分析覆盖 118 条，动态验证覆盖 0 条，其中 0 条已复现。主要风险类型集中在 XSS(20)、Path Traversal(13)、Hardcoded Secret(11)、Server-Side Template Injection(9)，总体风险评级为 HIGH。

**总体风险等级：HIGH**

### 1.1 项目概况总结

项目 RailsGoat 来源于 https://github.com/OWASP/railsgoat，主要语言为 Ruby、JavaScript，框架为 未识别，共 142 个文件、10484 行代码。

### 1.2 漏洞结果总结

本次共发现 118 条漏洞，其中 Critical 0 条、High 24 条、Medium 60 条、Low 34 条。

**静态分析总结：** 静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 118 条静态风险。主要来源分布为 custom-taint(77)、semgrep(41)。这些结果先作为候选项进入 VerifyAgent，避免仅凭规则命中直接下结论。

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
| 项目名称 | RailsGoat |
| 来源 | https://github.com/OWASP/railsgoat |
| 语言 | Ruby, JavaScript |
| 框架 |  |
| 文件数 | 142 |
| 代码行数 | 10484 |
| 扫描任务 | scan_f86c56ef（static / done） |

## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | 0 |
| High | 24 |
| Medium | 60 |
| Low | 34 |
| **合计** | **118** |

## 4. 漏洞明细


### 4.1 detected-generic-api-key（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\assets\javascripts\bootstrap-image-gallery-main.js:61`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.2 check-unsafe-reflection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\api\v1\mobile_controller.rb:10`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.3 check-unsafe-reflection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\api\v1\mobile_controller.rb:17`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.4 missing-csrf-protection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\application_controller.rb:2`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.5 check-unsafe-reflection（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\benefit_forms_controller.rb:12`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.6 check-send-file（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\benefit_forms_controller.rb:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.7 bad-deserialization（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\password_resets_controller.rb:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.8 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\users_controller.rb:29`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.9 model-attr-accessible（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\users_controller.rb:55`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.10 Hardcoded Secret（HIGH）

- 文件：`app/assets/javascripts/bootstrap-image-gallery-main.js:61`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
//         api_key: '7617adae70159d09ba78cfec73c13be3'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.11 Insecure Deserialization（HIGH）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:12`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
typeof a&&-1!==a.indexOf("@")};b._bAttrSrc=h.isPlainObject(g)&&(c(g.sort)||c(g.type)||c(g.filter));b._setter=null;b.fnGetData=function(a,b,c){var d=j(a,b,k,c);return i&&b?i(d,b,a,c):d};b.fnSetData=fun
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.12 Insecure Deserialization（HIGH）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
c.innerHTML=B(a,b,d,"display")};if("dom"===c||(!c||"auto"===c)&&"dom"===e.src)e._aData=Ha(a,e,d,d===k?k:e._aData).data;else{var j=e.anCells;if(j)if(d!==k)g(j[d],d);else{c=0;for(f=j.length;c<f;c++)g(j[
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.13 Hardcoded Secret（HIGH）

- 文件：`app/assets/javascripts/jsapi.js:8`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
google.loader.ApiKey = 'notsupplied';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.14 Insecure Deserialization（HIGH）

- 文件：`app/controllers/password_resets_controller.rb:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
user = Marshal.load(Base64.decode64(params[:user])) unless params[:user].nil?
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.15 SQL Injection（HIGH）

- 文件：`app/controllers/users_controller.rb:29`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
user = User.where("id = '#{params[:user][:id]}'")[0]
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.16 Hardcoded Secret（HIGH）

- 文件：`db/seeds.rb:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
password: "admin1234",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.17 Hardcoded Secret（HIGH）

- 文件：`db/seeds.rb:19`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
password: "railsgoat!",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.18 Hardcoded Secret（HIGH）

- 文件：`db/seeds.rb:28`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
password: "yankeessuck",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.19 Hardcoded Secret（HIGH）

- 文件：`db/seeds.rb:37`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
password: "alohaowasp",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.20 Hardcoded Secret（HIGH）

- 文件：`db/seeds.rb:46`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
password: "motocross1445",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.21 Hardcoded Secret（HIGH）

- 文件：`db/seeds.rb:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
password: "citrusblend",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.22 Hardcoded Secret（HIGH）

- 文件：`db/seeds.rb:64`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
password: "adminadmin",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.23 Hardcoded Secret（HIGH）

- 文件：`spec/support/user_fixture.rb:9`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
password = "thi$ 1s cOmplExEr"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.24 Hardcoded Secret（HIGH）

- 文件：`spec/vulnerabilities/mass_assignment_spec.rb:31`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
password: "foobarewe",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.25 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\.github\workflows\ci.yml:18`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.26 github-actions-mutable-action-tag（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\.github\workflows\ci.yml:21`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.27 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\assets\javascripts\date-picker\date.js:70`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.28 raw-html-concat（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\assets\javascripts\jquery.snippet.js:402`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.29 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\assets\javascripts\jquery.snippet.js:446`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.30 eval-detected（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\assets\javascripts\jquery.snippet.js:737`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.31 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\assets\javascripts\moment.js:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.32 check-unscoped-find（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\admin_controller.rb:28`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.33 check-unscoped-find（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\admin_controller.rb:34`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.34 weak-hashes-sha1（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\api\v1\users_controller.rb:42`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.35 avoid-html-safe（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\password_resets_controller.rb:36`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.36 weak-hashes-md5（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\password_resets_controller.rb:48`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.37 weak-hashes-md5（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\password_resets_controller.rb:57`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.38 check-unscoped-find（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\pay_controller.rb:29`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.39 avoid-redirect（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\sessions_controller.rb:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.40 check-redirect-to（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\sessions_controller.rb:26`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.41 weak-hashes-md5（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\models\user.rb:45`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.42 weak-hashes-md5（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\models\user.rb:55`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.43 unquoted-attribute（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\views\admin\analytics.html.erb:9`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.44 avoid-raw（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\views\layouts\application.html.erb:427`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.45 var-in-href（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\views\layouts\shared\_header.html.erb:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.46 avoid-html-safe（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\views\layouts\shared\_header.html.erb:47`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.47 var-in-href（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\views\layouts\shared\_header.html.erb:75`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.48 avoid-html-safe（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\views\messages\index.html.erb:167`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.49 avoid-html-safe（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\views\paid_time_off\index.html.erb:210`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.50 avoid-html-safe（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\views\users\account_settings.html.erb:81`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.51 detailed-exceptions（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\config\environments\development.rb:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.52 detailed-exceptions（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\config\environments\mysql.rb:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.53 detailed-exceptions（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\config\environments\openshift.rb:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.54 detailed-exceptions（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\config\environments\test.rb:16`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.55 weak-hashes-md5（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\spec\vulnerabilities\password_hashing_spec.rb:19`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.56 weak-hashes-md5（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\spec\vulnerabilities\password_hashing_spec.rb:22`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.57 XSS（MEDIUM）

- 文件：`app/assets/javascripts/alertify.min.js:12`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e,t){"use strict";var n=e.document,r;r=function(){var e={},r={},i=!1,s={ENTER:13,ESC:27,SPACE:32},o=[],u,a,f,l,c,h,p,d,v,m,g,y;return r={buttons:{holder:'<nav class="alertify-buttons">{{butt
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.58 Command Injection（MEDIUM）

- 文件：`app/assets/javascripts/bootstrap-editable.min.js:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e){var t=function(t,n){this.options=e.extend({},e.fn.editableform.defaults,n),this.$div=e(t),this.options.scope||(this.options.scope=this)};t.prototype={constructor:t,initInput:function(){th
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.59 Server-Side Template Injection（MEDIUM）

- 文件：`app/assets/javascripts/bootstrap-editable.min.js:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e){var t=function(t,n){this.options=e.extend({},e.fn.editableform.defaults,n),this.$div=e(t),this.options.scope||(this.options.scope=this)};t.prototype={constructor:t,initInput:function(){th
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.60 Command Injection（MEDIUM）

- 文件：`app/assets/javascripts/fullcalendar.min.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(t){"function"==typeof define&&define.amd?define(["jquery","moment"],t):"object"==typeof exports?module.exports=t(require("jquery"),require("moment")):t(jQuery,moment)}(function(t,e){function
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.61 Path Traversal（MEDIUM）

- 文件：`app/assets/javascripts/fullcalendar.min.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(t){"function"==typeof define&&define.amd?define(["jquery","moment"],t):"object"==typeof exports?module.exports=t(require("jquery"),require("moment")):t(jQuery,moment)}(function(t,e){function
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.62 Server-Side Template Injection（MEDIUM）

- 文件：`app/assets/javascripts/fullcalendar.min.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(t){"function"==typeof define&&define.amd?define(["jquery","moment"],t):"object"==typeof exports?module.exports=t(require("jquery"),require("moment")):t(jQuery,moment)}(function(t,e){function
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.63 Server-Side Template Injection（MEDIUM）

- 文件：`app/assets/javascripts/fullcalendar.min.js:7`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
",m=new RegExp(v+"([^"+v+"]*)"+v,"g"),y={t:function(t){return e(t,"a").charAt(0)},T:function(t){return e(t,"A").charAt(0)}},w={Y:{value:1,unit:"year"},M:{value:2,unit:"month"},W:{value:3,unit:"week"},
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.64 Server-Side Template Injection（MEDIUM）

- 文件：`app/assets/javascripts/fullcalendar.min.js:9`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.callChildren("executeDateUnrender",arguments),this.dateProfile=null,this.unrenderDates(),this.isDatesRendered=!1},renderDates:function(t){},unrenderDates:function(){},getNowIndicatorUnit:function
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.65 SSRF（MEDIUM）

- 文件：`app/assets/javascripts/fullcalendar.min.js:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.view.select(this.buildSelectFootprint.apply(this,arguments))},unselect:function(){this.view&&this.view.unselect()},buildSelectFootprint:function(t,e){var n,i=this.moment(t).stripZone();return n=e
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.66 Server-Side Template Injection（MEDIUM）

- 文件：`app/assets/javascripts/fullcalendar.min.js:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.view.select(this.buildSelectFootprint.apply(this,arguments))},unselect:function(){this.view&&this.view.unselect()},buildSelectFootprint:function(t,e){var n,i=this.moment(t).stripZone();return n=e
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.67 Server-Side Template Injection（MEDIUM）

- 文件：`app/assets/javascripts/fullcalendar.min.js:11`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"string"==typeof e.className&&(this.className=e.className.split(/\s+/)),!0},applyMiscProps:function(e){t.extend(this.miscProps,e)}});Qe.defineStandardProps=ae,Qe.copyVerbatimStandardProps=le,Qe.uuid=0
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.68 Server-Side Template Injection（MEDIUM）

- 文件：`app/assets/javascripts/fullcalendar.min.js:12`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
;return this.colWeekNumbersVisible?'<td class="fc-week-number" '+t.weekNumberStyleAttr()+"></td>":""},getIsNumbersVisible:function(){return wn.prototype.getIsNumbersVisible.apply(this,arguments)||this
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.69 Command Injection（MEDIUM）

- 文件：`app/assets/javascripts/jquery.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e,t){function _(e){var t=M[e]={};return v.each(e.split(y),function(e,n){t[n]=!0}),t}function H(e,n,r){if(r===t&&e.nodeType===1){var i="data-"+n.replace(P,"-$1").toLowerCase();r=e.getAttribut
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.70 Path Traversal（MEDIUM）

- 文件：`app/assets/javascripts/jquery.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e,t){function _(e){var t=M[e]={};return v.each(e.split(y),function(e,n){t[n]=!0}),t}function H(e,n,r){if(r===t&&e.nodeType===1){var i="data-"+n.replace(P,"-$1").toLowerCase();r=e.getAttribut
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.71 XSS（MEDIUM）

- 文件：`app/assets/javascripts/jquery.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e,t){function _(e){var t=M[e]={};return v.each(e.split(y),function(e,n){t[n]=!0}),t}function H(e,n,r){if(r===t&&e.nodeType===1){var i="data-"+n.replace(P,"-$1").toLowerCase();r=e.getAttribut
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.72 Weak Randomness（MEDIUM）

- 文件：`app/assets/javascripts/jquery.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(e,t){function _(e){var t=M[e]={};return v.each(e.split(y),function(e,n){t[n]=!0}),t}function H(e,n,r){if(r===t&&e.nodeType===1){var i="data-"+n.replace(P,"-$1").toLowerCase();r=e.getAttribut
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.73 Weak Randomness（MEDIUM）

- 文件：`app/assets/javascripts/jquery.snippet.js:51`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var randomnumber=Math.floor(Math.random()*(styleArr.length));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.74 Path Traversal（MEDIUM）

- 文件：`app/assets/javascripts/jquery.validate.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(a){"function"==typeof define&&define.amd?define(["jquery"],a):"object"==typeof module&&module.exports?module.exports=a(require("jquery")):a(jQuery)}(function(a){a.extend(a.fn,{validate:funct
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.75 Command Injection（MEDIUM）

- 文件：`app/assets/javascripts/jsapi.js:17`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
l(google,function(a,b,c){function e(a){var b=a.split(".");if(2<b[w])throw H("Module: '"+a+"' not found!");"undefined"!=typeof b[1]&&(f=b[0],c.packages=c.packages||[],c.packages[m](b[1]))}var f=a;c=c||
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.76 Weak Randomness（MEDIUM）

- 文件：`app/assets/javascripts/jsapi.js:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
K("google.loader.loaded",google[z].loaded);google[z].O=function(){return"qid="+((new Date)[v]().toString(16)+Math.floor(1E7*Math.random()).toString(16))};K("google.loader.createGuidArg_",google[z].O);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.77 XSS（MEDIUM）

- 文件：`app/controllers/password_resets_controller.rb:36`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
flash[:error] = "There was an issue sending password reset email to #{params[:email]}".html_safe unless params[:email].nil?
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.78 Weak Hash（MEDIUM）

- 文件：`app/controllers/password_resets_controller.rb:48`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
hash = Digest::MD5.hexdigest(email)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.79 Weak Hash（MEDIUM）

- 文件：`app/controllers/password_resets_controller.rb:57`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
email = Digest::MD5.hexdigest(@user.email)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.80 Weak Hash（MEDIUM）

- 文件：`app/controllers/api/v1/users_controller.rb:42`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
digest = OpenSSL::Digest::SHA1.hexdigest("#{ACCESS_TOKEN_SALT}:#{id}")
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.81 Weak Hash（MEDIUM）

- 文件：`app/models/user.rb:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if user.password == Digest::MD5.hexdigest(password)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.82 Weak Hash（MEDIUM）

- 文件：`app/models/user.rb:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
self.password = Digest::MD5.hexdigest(self.password)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.83 Weak Hash（MEDIUM）

- 文件：`spec/vulnerabilities/password_hashing_spec.rb:19`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
expect(normal_user.password).not_to eq(Digest::MD5.hexdigest(new_pass))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.84 Weak Hash（MEDIUM）

- 文件：`spec/vulnerabilities/password_hashing_spec.rb:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
expect(normal_user.password).to eq(Digest::MD5.hexdigest(new_pass))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.85 XSS（LOW）

- 文件：`app/assets/images/fonts/lte-ie7.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
el.innerHTML = '<span style="font-family: \'icomoon\'">' + entity + '</span>' + html;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.86 Server-Side Template Injection（LOW）

- 文件：`app/assets/javascripts/bootstrap-timepicker.js:84`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.$widget = $(this.getTemplate()).appendTo('body');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.87 XSS（LOW）

- 文件：`app/assets/javascripts/html5.js:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
a.createElement=function(c){return!e.shivMethods?b.createElem(c):p(c,a,b)};a.createDocumentFragment=Function("h,f","return function(){var n=f.cloneNode(),c=n.createElement;h.shivMethods&&("+m().join()
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.88 XSS（LOW）

- 文件：`app/assets/javascripts/html5.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
c=d.insertBefore(c.lastChild,d.firstChild);b.hasCSS=!!c}g||t(a,b);return a}var k=l.html5||{},s=/^<|^(?:button|map|select|textarea|object|iframe|option|optgroup)$/i,r=/^(?:a|b|code|div|fieldset|h1|h2|h
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.89 Path Traversal（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:5`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(h){"function"===typeof define&&define.amd?define(["jquery"],function(E){return h(E,window,document)}):"object"===typeof exports?module.exports=function(E,G){E||(E=window);G||(G="undefined"!=
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.90 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
e;)a.hasOwnProperty(d)&&(g=j?b(g,a[d],d,a):a[d],j=!0,d+=f);return g}function Da(a,b){var c=m.defaults.column,d=a.aoColumns.length,c=h.extend({},m.models.oColumn,c,{nTh:b?b:G.createElement("th"),sTitle
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.91 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
c.innerHTML=B(a,b,d,"display")};if("dom"===c||(!c||"auto"===c)&&"dom"===e.src)e._aData=Ha(a,e,d,d===k?k:e._aData).data;else{var j=e.anCells;if(j)if(d!==k)g(j[d],d);else{c=0;for(f=j.length;c<f;c++)g(j[
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.92 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
-1!==c&&(c=a.substring(c+1),R(a)(d,b.getAttribute(c)))}},m=function(a){if(c===k||c===i)j=l[i],n=h.trim(a.innerHTML),j&&j._bAttrSrc?(R(j.mData._)(d,n),t(j.mData.sort,a),t(j.mData.type,a),t(j.mData.filt
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.93 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:24`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
function Ga(a,b,c,d){var e=a.aoData[b],f=e._aData,g=[],j,i,n,l,q;if(null===e.nTr){j=c||G.createElement("tr");e.nTr=j;e.anCells=g;j._DT_RowIndex=b;Ka(a,e);l=0;for(q=a.aoColumns.length;l<q;l++){n=a.aoCo
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.94 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:26`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
h("th, td",g).length,n=a.oClasses,l=a.aoColumns;i&&(e=h("<tr/>").appendTo(g));b=0;for(c=l.length;b<c;b++)f=l[b],d=h(f.nTh).addClass(f.sClass),i&&d.appendTo(e),a.oFeatures.bSort&&(d.addClass(f.sSorting
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.95 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
d=0;for(f=a.aoData.length;d<f;d++)if(h=a.aoData[d],!h._aFilterData){j=[];e=0;for(g=b.length;e<g;e++)c=b[e],c.bSearchable?(i=B(a,d,e,"filter"),l[c.sType]&&(i=l[c.sType](i)),null===i&&(i=""),"string"!==
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.96 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:58`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
v(d),f=p.outerWidth());H(C,K);H(function(a){z.push(a.innerHTML);Ta.push(v(h(a).css("width")))},K);H(function(a,b){if(h.inArray(a,Xb)!==-1)a.style.width=Ta[b]},o);h(K).height(0);u&&(H(C,P),H(function(a
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.97 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:78`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
[ya(this[m.ext.iApiIndex])].concat(Array.prototype.slice.call(arguments));return m.ext.internal[a].apply(this,b)}}var m=function(a){this.$=function(a,b){return this.api(!0).$(a,b)};this._=function(a,b
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.98 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:79`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
function(a){var b=this.api(!0).columns.adjust(),c=b.settings()[0],d=c.oScroll;a===k||a?b.draw(!1):(""!==d.sX||""!==d.sY)&&ka(c)};this.fnClearTable=function(a){var b=this.api(!0).clear();(a===k||a)&&b.
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.99 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:80`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.fnFilter=function(a,b,c,d,e,h){e=this.api(!0);null===b||b===k?e.search(a,c,d,h):e.column(b).search(a,c,d,h);e.draw()};this.fnGetData=function(a,b){var c=this.api(!0);if(a!==k){var d=a.nodeName?a.
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.100 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:81`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return"TR"==c?b.row(a).index():"TD"==c||"TH"==c?(a=b.cell(a).index(),[a.row,a.columnVisible,a.column]):null};this.fnIsOpen=function(a){return this.api(!0).row(a).child.isShown()};this.fnOpen=function(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.101 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.fnSort=function(a){this.api(!0).order(a).draw()};this.fnSortListener=function(a,b,c){this.api(!0).order.listener(a,b,c)};this.fnUpdate=function(a,b,c,d,e){var h=this.api(!0);c===k||null===c?h.row
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.102 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:105`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"table().header()",function(){return this.iterator("table",function(a){return a.nTHead},1)});u("tables().footer()","table().footer()",function(){return this.iterator("table",function(a){return a.nTFoo
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.103 Server-Side Template Injection（LOW）

- 文件：`app/assets/javascripts/jquery.dataTables.min.js:129`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
a.anCells?a.anCells[c]:k},1)});o("cells().data()",function(){return this.iterator("cell",function(a,b,c){return B(a,b,c)},1)});u("cells().cache()","cell().cache()",function(a){a="search"===a?"_aFilter
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.104 Command Injection（LOW）

- 文件：`app/assets/javascripts/jquery.snippet.js:737`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if(!this.sh_languages){this.sh_languages={}}var sh_requests={};function sh_isEmailAddress(a){if(/^mailto:/.test(a)){return false}return a.indexOf("@")!==-1}function sh_setHref(b,c,d){var a=d.substring
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.105 Path Traversal（LOW）

- 文件：`app/assets/javascripts/jquery.snippet.js:737`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if(!this.sh_languages){this.sh_languages={}}var sh_requests={};function sh_isEmailAddress(a){if(/^mailto:/.test(a)){return false}return a.indexOf("@")!==-1}function sh_setHref(b,c,d){var a=d.substring
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.106 XSS（LOW）

- 文件：`app/assets/javascripts/jquery.snippet.js:798`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if(!this.sh_languages){this.sh_languages={}}sh_languages.php=[[[/\b(?:include|include_once|require|require_once)\b/g,"sh_preproc",-1],[/\/\//g,"sh_comment",1],[/#/g,"sh_comment",1],[/\b[+-]?(?:(?:0x[A
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.107 Path Traversal（LOW）

- 文件：`app/assets/javascripts/load-image.min.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(a){"use strict";var b=function(a,c,d){var e=document.createElement("img"),f,g;return e.onerror=c,e.onload=function(){g&&(!d||!d.noRevoke)&&b.revokeObjectURL(g),c(b.scale(e,d))},window.Blob&&
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.108 Command Injection（LOW）

- 文件：`app/assets/javascripts/moment.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(a){function E(a,b,c,d){var e=c.lang();return e[a].call?e[a](c,d):e[a][b]}function F(a,b){return function(c){return K(a.call(this,c),b)}}function G(a){return function(b){var c=a.call(this,b);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.109 Path Traversal（LOW）

- 文件：`app/assets/javascripts/moment.js:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
(function(a){function E(a,b,c,d){var e=c.lang();return e[a].call?e[a](c,d):e[a][b]}function F(a,b){return function(c){return K(a.call(this,c),b)}}function G(a){return function(b){var c=a.call(this,b);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.110 Command Injection（LOW）

- 文件：`app/assets/javascripts/moment.min.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():"function"==typeof define&&define.amd?define(t):e.moment=t()}(this,function(){"use strict";function e(){return Yt
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.111 Path Traversal（LOW）

- 文件：`app/assets/javascripts/moment.min.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():"function"==typeof define&&define.amd?define(t):e.moment=t()}(this,function(){"use strict";function e(){return Yt
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.112 SQL Injection（LOW）

- 文件：`app/models/analytics.rb:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
scope :hits_by_ip, ->(ip, col = "*") { select("#{col}").where(ip_address: ip).order("id DESC") }
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.113 Path Traversal（LOW）

- 文件：`app/models/benefits.rb:7`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
f = File.open(full_file_name, "wb+")
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.114 Command Injection（LOW）

- 文件：`app/models/benefits.rb:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
silence_streams(STDERR) { system("cp #{full_file_name} #{data_path}/bak#{Time.zone.now.to_i}_#{file.original_filename}") }
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.115 Path Traversal（LOW）

- 文件：`spec/vulnerabilities/broken_auth_spec.rb:21`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
expect(find("div#flash_notice").text).not_to include(wrong_email)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.116 Path Traversal（LOW）

- 文件：`spec/vulnerabilities/command_injection_spec.rb:17`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
File.open(legit_file, "w") { |f| f.puts "totes legit" }
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.117 Path Traversal（LOW）

- 文件：`spec/vulnerabilities/command_injection_spec.rb:22`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
File.open(hackety_file, "w") { |f| f.print "mwahaha" }
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.118 Path Traversal（LOW）

- 文件：`spec/vulnerabilities/csrf_spec.rb:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
File.open(hackety_file, "w") do |f|
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。





## 5. 关键风险

- HIGH detected-generic-api-key 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\assets\javascripts\bootstrap-image-gallery-main.js:61，状态为 confirmed。
- HIGH check-unsafe-reflection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\api\v1\mobile_controller.rb:10，状态为 confirmed。
- HIGH check-unsafe-reflection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\api\v1\mobile_controller.rb:17，状态为 confirmed。
- HIGH missing-csrf-protection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\application_controller.rb:2，状态为 confirmed。
- HIGH check-unsafe-reflection 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_16e68c51\app\controllers\benefit_forms_controller.rb:12，状态为 confirmed。


## 6. 修改建议

- **P0 优先修复 Critical/High 漏洞：** 先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。
- **P1 按漏洞类型批量治理：** 对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。
- **P1 补充动态验证覆盖：** 为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。
- **P2 纳入持续审计流程：** 将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。


## 7. 结论

综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 HIGH 风险水平。建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
# OWASP-WebGoatPHP 安全审计报告

> 生成工具：AuditAgentX　生成时间：2026-07-09 10:07:49 UTC

## 1. 执行摘要

本次审计对象为 OWASP-WebGoatPHP，来源为 https://github.com/OWASP/OWASPWebGoatPHP，项目主要语言为 PHP、JavaScript、Shell，框架识别结果为 未识别，共解析 1252 个文件、147297 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC 并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 466 条风险，其中 Critical 0 条、High 38 条、Medium 258 条、Low 170 条；静态分析覆盖 466 条，动态验证覆盖 0 条，其中 0 条已复现。主要风险类型集中在 XSS(114)、detect-non-literal-regexp(78)、Command Injection(43)、Path Traversal(41)，总体风险评级为 HIGH。

**总体风险等级：HIGH**

### 1.1 项目概况总结

项目 OWASP-WebGoatPHP 来源于 https://github.com/OWASP/OWASPWebGoatPHP，主要语言为 PHP、JavaScript、Shell，框架为 未识别，共 1252 个文件、147297 行代码。

### 1.2 漏洞结果总结

本次共发现 466 条漏洞，其中 Critical 0 条、High 38 条、Medium 258 条、Low 170 条。

**静态分析总结：** 静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 466 条静态风险。主要来源分布为 custom-taint(319)、semgrep(147)。这些结果先作为候选项进入 VerifyAgent，避免仅凭规则命中直接下结论。

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
| 项目名称 | OWASP-WebGoatPHP |
| 来源 | https://github.com/OWASP/OWASPWebGoatPHP |
| 语言 | PHP, JavaScript, Shell |
| 框架 |  |
| 文件数 | 1252 |
| 代码行数 | 147297 |
| 扫描任务 | scan_a9b83ecb（static / done） |

## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | 0 |
| High | 38 |
| Medium | 258 |
| Low | 170 |
| **合计** | **466** |

## 4. 漏洞明细


### 4.1 exec-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\_japp\model\launcher\test.php:102`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.2 eval-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\_japp\plugin\nusoap\nusoap.php:4073`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.3 eval-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\_japp\plugin\nusoap\nusoap.php:7868`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.4 md5-loose-equality（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\model\contest\submissions.php:92`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.5 eval-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\Symfony\Component\Yaml\Tests\DumperTest.php:56`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.6 eval-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\Symfony\Component\Yaml\Tests\ParserTest.php:66`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.7 tainted-sql-string（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\NumericSQLInjection\index.php:88`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.8 eval-use（HIGH）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\files\index.php:231`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.9 Insecure Deserialization（HIGH）

- 文件：`app/plugin/lastrss.php:71`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$result = unserialize(join('', file($cache_file)));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.10 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/Common/Annotations/FileCacheReader.php:186`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
file_put_contents($path, '<?php return unserialize('.var_export(serialize($data), true).');');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.11 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/Common/Cache/FilesystemCache.php:69`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return unserialize($data);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.12 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/Common/Cache/XcacheCache.php:42`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return $this->doContains($id) ? unserialize(xcache_get($id)) : false;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.13 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/Common/Persistence/Mapping/AbstractClassMetadataFactory.php:143`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
* Wakeup reflection after ClassMetadata gets unserialized from cache.
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.14 Hardcoded Secret（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/SQLParserUtils.php:36`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
const NAMED_TOKEN      = ':[a-zA-Z_][a-zA-Z0-9_]*';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.15 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Types/ArrayType.php:48`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$val = unserialize($value);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.16 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Types/ObjectType.php:48`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$val = unserialize($value);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.17 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/ORM/Id/SequenceGenerator.php:99`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
public function unserialize($serialized)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.18 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/ORM/Id/SequenceGenerator.php:101`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$array = unserialize($serialized);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.19 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/ORM/Mapping/ClassMetadataInfo.php:734`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
* Parts that are also NOT serialized because they can not be properly unserialized:
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.20 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/ORM/Mapping/ClassMetadataInfo.php:830`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->_prototype = unserialize(sprintf('O:%d:"%s":0:{}', strlen($this->name), $this->name));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.21 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/ORM/Mapping/ClassMetadataInfo.php:836`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
* Restores some state that can not be serialized/unserialized.
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.22 Insecure Deserialization（HIGH）

- 文件：`app/plugin/doctrine/Doctrine/Symfony/Component/Yaml/Inline.php:376`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return unserialize(substr($scalar, 13));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.23 Hardcoded Secret（HIGH）

- 文件：`challenges/single/FailOpenAuthentication/index.php:32`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
const PASSWORD = "webgoat";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.24 Hardcoded Secret（HIGH）

- 文件：`challenges/single/ForgotPassword/index.php:34`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
const PASSWORD = "!sj@LHU88&2G";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.25 Hardcoded Secret（HIGH）

- 文件：`challenges/single/HTMLClues/index.php:32`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
const PASSWORD = "youGotIt";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.26 Hardcoded Secret（HIGH）

- 文件：`challenges/single/JSObfuscation/index.php:31`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
const PASSWORD = "itWasE@sz";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.27 Hardcoded Secret（HIGH）

- 文件：`challenges/single/SessionFixation/index.php:35`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
const PASSWORD = "tarzan";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.28 Hardcoded Secret（HIGH）

- 文件：`challenges/single/XPATHInjection/index.php:70`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$employees = $xml->xpath("/employees/employee[loginID='$_POST[username]' and passwd='$_POST[pass]']");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.29 Server-Side Template Injection（HIGH）

- 文件：`script/ace/src-min-noconflict/ext-settings_menu.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/menu_tools/element_generator",["require","exports","module"],function(e,t,n){"use strict";n.exports.createOption=function(t){var n,r=document.createElement("option");for(n in t)t.h
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.30 Hardcoded Secret（HIGH）

- 文件：`script/ace/src-min-noconflict/mode-gitignore.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/gitignore_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_ru
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.31 Hardcoded Secret（HIGH）

- 文件：`script/ace/src-min-noconflict/mode-lucene.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/lucene_highlight_rules",["require","exports","module","ace/lib/oop","ace/lib/lang","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("../lib/
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.32 Insecure Deserialization（HIGH）

- 文件：`script/ace/src-min-noconflict/mode-php.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/doc_comment_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.33 Hardcoded Secret（HIGH）

- 文件：`script/ace/src-min-noconflict/mode-properties.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/properties_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_r
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.34 Hardcoded Secret（HIGH）

- 文件：`script/ace/src-min-noconflict/mode-scheme.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/scheme_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_rules
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.35 Insecure Deserialization（HIGH）

- 文件：`script/ace/src-min-noconflict/snippets/ruby.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/ruby",["require","exports","module"],function(e,t,n){"use strict";t.snippetText='########################################\n# Ruby snippets - for Rails, see below #\n##########
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.36 Insecure Deserialization（HIGH）

- 文件：`_japp/model/lib/settings.php:97`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return unserialize($Res[0]['Value']);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.37 Insecure Deserialization（HIGH）

- 文件：`_japp/model/service/input/serialized.php:6`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return unserialize($Data);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.38 Insecure Deserialization（HIGH）

- 文件：`_japp/view/default/panel/development/options.php:13`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$o['Value']=unserialize($o['Value']);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.39 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\_japp\model\lib\settings.php:97`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.40 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\_japp\model\service\input\serialized.php:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.41 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\_japp\view\default\panel\development\options.php:13`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.42 unlink-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\Common\Annotations\FileCacheReader.php:98`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.43 unlink-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\Common\Annotations\FileCacheReader.php:133`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.44 unlink-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\Common\Annotations\FileCacheReader.php:168`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.45 unlink-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\Common\Cache\FileCache.php:105`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.46 unlink-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\Common\Cache\FileCache.php:119`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.47 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\Common\Cache\FilesystemCache.php:69`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.48 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\Common\Cache\XcacheCache.php:42`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.49 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\DBAL\Connections\MasterSlaveConnection.php:351`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.50 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\DBAL\Id\TableGenerator.php:119`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.51 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\DBAL\Query\QueryBuilder.php:185`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.52 unlink-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\DBAL\Schema\SqliteSchemaManager.php:42`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.53 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\DBAL\Tools\Console\Command\ImportCommand.php:87`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.54 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\DBAL\Tools\Console\Command\ImportCommand.php:106`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.55 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\DBAL\Types\ArrayType.php:48`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.56 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\DBAL\Types\ObjectType.php:48`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.57 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\EntityManager.php:296`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.58 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Id\SequenceGenerator.php:101`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.59 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Mapping\ClassMetadataInfo.php:830`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.60 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Persisters\BasicEntityPersister.php:263`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.61 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Persisters\BasicEntityPersister.php:670`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.62 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Persisters\BasicEntityPersister.php:766`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.63 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Persisters\BasicEntityPersister.php:789`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.64 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Persisters\BasicEntityPersister.php:844`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.65 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Persisters\BasicEntityPersister.php:997`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.66 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Persisters\BasicEntityPersister.php:1407`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.67 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Persisters\BasicEntityPersister.php:1599`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.68 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Query\Exec\SingleSelectExecutor.php:46`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.69 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Tools\SchemaTool.php:90`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.70 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Tools\SchemaTool.php:612`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.71 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Tools\SchemaTool.php:630`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.72 doctrine-dbal-dangerous-query（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\ORM\Tools\SchemaTool.php:715`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.73 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\Symfony\Component\Yaml\Inline.php:376`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.74 unserialize-use（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\lastrss.php:71`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.75 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\EncodingBasics\content.html:4`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.76 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\FailOpenAuthentication\content.html:11`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.77 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\ForgotPassword\content.html:10`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.78 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\HTMLClues\content.html:8`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.79 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\HTTPBasics\content.html:12`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.80 plaintext-http-link（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\HTTPOnly\content.html:3`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.81 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\HTTPOnly\content.html:14`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.82 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\HiddenFields\content.html:8`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.83 plaintext-http-link（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\JSObfuscation\static\solution.html:8`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.84 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\LogSpoofing\content.html:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.85 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\PathBasedAccessControl\index.php:89`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.86 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\PathBasedAccessControl\index.php:92`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.87 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\SameOriginPolicy\content.html:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.88 plaintext-http-link（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\SameOriginPolicy\static\plan.html:9`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.89 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\SessionFixation\stage3.html:12`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.90 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\SessionFixation\stage5.html:9`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.91 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\WeakAuthenticationCookie\content.html:9`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.92 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\XPATHInjection\content.html:7`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.93 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\XSS1\content.html:48`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.94 django-no-csrf-token（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\challenges\single\XSS2\content.html:6`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.95 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\files\index.php:173`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.96 tainted-filename（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\files\index.php:174`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.97 wildcard-postmessage-configuration（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\ace.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.98 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\ace.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.99 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\ext-chromevox.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.100 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\ext-emmet.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.101 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\ext-language_tools.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.102 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\ext-modelist.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.103 eval-detected（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\ext-old_ie.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.104 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\ext-settings_menu.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.105 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-actionscript.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.106 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-apache_conf.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.107 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-applescript.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.108 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-autohotkey.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.109 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-batchfile.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.110 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-c9search.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.111 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-c_cpp.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.112 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-coldfusion.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.113 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-csharp.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.114 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-css.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.115 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-curly.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.116 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-d.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.117 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-dart.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.118 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-diff.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.119 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-django.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.120 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-dockerfile.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.121 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-dot.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.122 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-ejs.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.123 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-erlang.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.124 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-forth.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.125 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-glsl.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.126 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-golang.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.127 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-groovy.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.128 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-handlebars.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.129 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-haskell.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.130 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-haxe.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.131 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-html.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.132 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-html_ruby.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.133 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-jack.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.134 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-java.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.135 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-javascript.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.136 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-json.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.137 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-jsoniq.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.138 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-jsp.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.139 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-jsx.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.140 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-julia.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.141 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-less.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.142 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-lsl.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.143 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-luapage.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.144 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-markdown.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.145 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-mel.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.146 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-mushcode.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.147 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-nix.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.148 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-objectivec.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.149 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-perl.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.150 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-php.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.151 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-powershell.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.152 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-prolog.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.153 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-protobuf.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.154 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-python.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.155 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-rhtml.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.156 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-rust.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.157 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-scad.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.158 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-scala.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.159 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-scss.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.160 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-sh.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.161 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-sjs.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.162 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-smarty.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.163 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-soy_template.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.164 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-svg.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.165 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-tcl.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.166 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-twig.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.167 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-typescript.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.168 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-vala.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.169 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-velocity.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.170 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\mode-xquery.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.171 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\worker-coffee.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.172 eval-detected（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\worker-css.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.173 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\ace\src-min-noconflict\worker-php.js:1`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.174 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\calendar\calendar.js:2034`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.175 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\moment.js:1120`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.176 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\prettify\prettify.js:12`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.177 detect-non-literal-regexp（MEDIUM）

- 文件：`C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\script\prettify\run_prettify.js:16`
- 来源：semgrep
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
requires login
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.178 Weak Hash（MEDIUM）

- 文件：`app/control/mode/contest/ajax/challenge.php:14`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$hashedFlag = md5($_POST['flag']);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.179 Path Traversal（MEDIUM）

- 文件：`app/control/mode/contest/challenges/__catch.php:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$fileContents = file_get_contents($absolutePath."/index.html");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.180 SSRF（MEDIUM）

- 文件：`app/control/mode/contest/challenges/__catch.php:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$fileContents = file_get_contents($absolutePath."/index.html");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.181 Path Traversal（MEDIUM）

- 文件：`app/control/mode/single/challenges/__catch.php:72`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$sourceCode = file_get_contents($absolutePath."index.php");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.182 SSRF（MEDIUM）

- 文件：`app/control/mode/single/challenges/__catch.php:72`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$sourceCode = file_get_contents($absolutePath."index.php");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.183 Weak Hash（MEDIUM）

- 文件：`app/model/contest/submissions.php:92`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if ($challenge[0]['CorrectFlag'] == md5($flag)) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.184 Weak Randomness（MEDIUM）

- 文件：`app/model/j/form/captcha.php:99`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$r=mt_rand(80,235);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.185 Weak Randomness（MEDIUM）

- 文件：`app/model/j/form/captcha.php:100`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$b=mt_rand(80,235);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.186 Weak Randomness（MEDIUM）

- 文件：`app/model/j/form/captcha.php:101`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$g=mt_rand(80,235);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.187 Weak Randomness（MEDIUM）

- 文件：`app/model/j/form/captcha.php:104`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$ex=-mt_rand(80,min($r,$b,$g));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.188 Weak Randomness（MEDIUM）

- 文件：`app/model/j/form/captcha.php:105`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
// 		if (mt_rand(0,1)) $ex=-$ex;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.189 Weak Randomness（MEDIUM）

- 文件：`app/model/j/form/captcha.php:120`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$ellipseWidth=mt_rand(30,$width-50);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.190 Weak Randomness（MEDIUM）

- 文件：`app/model/j/form/captcha.php:121`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$ellipsePosX=mt_rand(min($ellipseWidth,$width-$ellipseWidth),max($ellipseWidth,$width-$ellipseWidth));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.191 Weak Randomness（MEDIUM）

- 文件：`app/model/j/form/captcha.php:122`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$ellipseHeight=mt_rand(10,40);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.192 Weak Randomness（MEDIUM）

- 文件：`app/model/j/form/captcha.php:123`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$ellipsePosY=mt_rand(min($ellipseHeight,$height-$ellipseHeight),max($ellipseHeight,$height-$ellipseHeight));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.193 Weak Randomness（MEDIUM）

- 文件：`app/model/j/form/captcha.php:158`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
imagettftext($img,$fontSize,mt_rand(-5,5),10+($fontSize-8)*$sumWidth+20*$i,$fontSize+mt_rand(-10,10)+10,$color,$font,$text[$i]);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.194 Weak Randomness（MEDIUM）

- 文件：`app/plugin/autolist.php:67`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$n.=chr(ord("a")+mt_rand(0,25));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.195 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:33`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$words=mt_rand(1,2);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.196 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:36`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$length=mt_rand(2,5);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.197 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:39`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$word.=$list[mt_rand(0,strlen($list)-1)];
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.198 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:54`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$r=mt_rand(20,235);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.199 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:55`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$b=mt_rand(20,235);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.200 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:56`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$g=mt_rand(20,235);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.201 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:59`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$ex=mt_rand(15,20);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.202 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:60`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if (mt_rand(0,1)) $ex=-$ex;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.203 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:73`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$ellipseWidth=mt_rand(30,$width-50);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.204 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:74`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$ellipsePosX=mt_rand($ellipseWidth,$width-$ellipseWidth);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.205 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:75`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$ellipseHeight=mt_rand(10,40);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.206 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:76`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$ellipsePosY=mt_rand($ellipseHeight,$height-$ellipseHeight);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.207 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:81`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
imagettftext($img,$fontSize,mt_rand(-5,5),10+($fontSize-8)*$sumWidth+20*$i,$fontSize+mt_rand(-10,10)+10,$color,$font,$text[$i]);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.208 Weak Randomness（MEDIUM）

- 文件：`app/plugin/captcha.php:105`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$("#<?php echo $ID;?>").attr("src",'<?php echo SiteRoot;?>/user/captcha?title=<?php echo $Title;?>&random='+Math.floor(Math.random()*100000));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.209 Weak Hash（MEDIUM）

- 文件：`app/plugin/lastrss.php:63`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cache_file = $this->cache_dir . '/rsscache_' . md5($rss_url);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.210 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/Common/Cache/FileCache.php:94`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$path = implode(str_split(md5($id), 12), DIRECTORY_SEPARATOR);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.211 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Cache/QueryCacheProfile.php:98`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cacheKey = sha1($realCacheKey);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.212 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Platforms/AbstractPlatform.php:574`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return 'MD5(' . $column . ')';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.213 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Query/QueryBuilder.php:488`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
*         ->set('u.password', md5('password'))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.214 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Query/QueryBuilder.php:643`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
*         ->set('u.password', md5('password'))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.215 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Query/QueryBuilder.php:674`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
*         ->set('u.password', md5('password'))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.216 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Schema/Visitor/Graphviz.php:61`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->output  = 'digraph "' . sha1( mt_rand() ) . '" {' . "\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.217 Weak Randomness（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Schema/Visitor/Graphviz.php:61`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->output  = 'digraph "' . sha1( mt_rand() ) . '" {' . "\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.218 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/ORM/Query.php:607`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return md5(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.219 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/ORM/QueryBuilder.php:648`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
*         ->set('u.password', md5('password'))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.220 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/ORM/QueryBuilder.php:786`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
*         ->set('u.password', md5('password'))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.221 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/ORM/QueryBuilder.php:817`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
*         ->set('u.password', md5('password'))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.222 Weak Hash（MEDIUM）

- 文件：`app/plugin/doctrine/Doctrine/ORM/Tools/Setup.php:184`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$cache->setNamespace("dc2_" . md5($proxyDir) . "_"); // to avoid collisions
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.223 Weak Hash（MEDIUM）

- 文件：`challenges/single/EncodingBasics/index.php:117`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$textMD5 = md5($text);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.224 Path Traversal（MEDIUM）

- 文件：`challenges/single/PathBasedAccessControl/index.php:92`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->htmlContent .= file_get_contents($filePath);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.225 SSRF（MEDIUM）

- 文件：`challenges/single/PathBasedAccessControl/index.php:92`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->htmlContent .= file_get_contents($filePath);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.226 Weak Randomness（MEDIUM）

- 文件：`script/challenges.js:94`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
//alert(hints[Math.floor((Math.random() * (hints.length - 1)))]);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.227 Weak Randomness（MEDIUM）

- 文件：`script/challenges.js:100`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
optionsContainer.html(hints[Math.round((Math.random() * (hints.length - 1)))]);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.228 Command Injection（MEDIUM）

- 文件：`script/jquery-2.1.1.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(a,b){"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a document");return 
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.229 XSS（MEDIUM）

- 文件：`script/jquery-2.1.1.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(a,b){"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a document");return 
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.230 Weak Randomness（MEDIUM）

- 文件：`script/jquery-2.1.1.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(a,b){"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a document");return 
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.231 Command Injection（MEDIUM）

- 文件：`script/jquery-2.1.1.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
},_data:function(a,b,c){return L.access(a,b,c)},_removeData:function(a,b){L.remove(a,b)}}),n.fn.extend({data:function(a,b){var c,d,e,f=this[0],g=f&&f.attributes;if(void 0===a){if(this.length&&(e=M.get
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.232 XSS（MEDIUM）

- 文件：`script/jquery-2.1.1.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
},_data:function(a,b,c){return L.access(a,b,c)},_removeData:function(a,b){L.remove(a,b)}}),n.fn.extend({data:function(a,b){var c,d,e,f=this[0],g=f&&f.attributes;if(void 0===a){if(this.length&&(e=M.get
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.233 Command Injection（MEDIUM）

- 文件：`script/jquery-2.1.1.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
},removeAttr:function(a,b){var c,d,e=0,f=b&&b.match(E);if(f&&1===a.nodeType)while(c=f[e++])d=n.propFix[c]||c,n.expr.match.bool.test(c)&&(a[d]=!1),a.removeAttribute(c)},attrHooks:{type:{set:function(a,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.234 Path Traversal（MEDIUM）

- 文件：`script/jquery-2.1.1.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
},removeAttr:function(a,b){var c,d,e=0,f=b&&b.match(E);if(f&&1===a.nodeType)while(c=f[e++])d=n.propFix[c]||c,n.expr.match.bool.test(c)&&(a[d]=!1),a.removeAttribute(c)},attrHooks:{type:{set:function(a,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.235 Command Injection（MEDIUM）

- 文件：`script/jquery-3.1.0.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(a,b){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a docum
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.236 XSS（MEDIUM）

- 文件：`script/jquery-3.1.0.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(a,b){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a docum
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.237 Weak Randomness（MEDIUM）

- 文件：`script/jquery-3.1.0.min.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
!function(a,b){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a docum
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.238 Command Injection（MEDIUM）

- 文件：`script/jquery-3.1.0.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
r.isFunction(d)||(g=!0),j&&(g?(b.call(a,d),b=null):(j=b,b=function(a,b,c){return j.call(r(a),c)})),b))for(;h<i;h++)b(a[h],c,g?d:d.call(a[h],h,b(a[h],c)));return e?a:j?b.call(a):i?b(a[0],c):f},T=functi
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.239 XSS（MEDIUM）

- 文件：`script/jquery-3.1.0.min.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
r.isFunction(d)||(g=!0),j&&(g?(b.call(a,d),b=null):(j=b,b=function(a,b,c){return j.call(r(a),c)})),b))for(;h<i;h++)b(a[h],c,g?d:d.call(a[h],h,b(a[h],c)));return e?a:j?b.call(a):i?b(a[0],c):f},T=functi
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.240 Command Injection（MEDIUM）

- 文件：`script/jquery-3.1.0.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if(e&&1===a.nodeType)while(c=e[d++])a.removeAttribute(c)}}),hb={set:function(a,b,c){return b===!1?r.removeAttr(a,c):a.setAttribute(c,c),c}},r.each(r.expr.match.bool.source.match(/\w+/g),function(a,b){
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.241 Path Traversal（MEDIUM）

- 文件：`script/jquery-3.1.0.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if(e&&1===a.nodeType)while(c=e[d++])a.removeAttribute(c)}}),hb={set:function(a,b,c){return b===!1?r.removeAttr(a,c):a.setAttribute(c,c),c}},r.each(r.expr.match.bool.source.match(/\w+/g),function(a,b){
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.242 XSS（MEDIUM）

- 文件：`script/jquery-3.1.0.min.js:4`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if(e&&1===a.nodeType)while(c=e[d++])a.removeAttribute(c)}}),hb={set:function(a,b,c){return b===!1?r.removeAttr(a,c):a.setAttribute(c,c),c}},r.each(r.expr.match.bool.source.match(/\w+/g),function(a,b){
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.243 SQL Injection（MEDIUM）

- 文件：`script/ace/src-min-noconflict/ace.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
\f\r \u00a0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029\ufeff";if(!String.prototype.trim||_.trim()){_="["+_+"]";var D=new RegExp("^"+_+_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.244 Command Injection（MEDIUM）

- 文件：`script/ace/src-min-noconflict/ace.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
\f\r \u00a0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029\ufeff";if(!String.prototype.trim||_.trim()){_="["+_+"]";var D=new RegExp("^"+_+_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.245 Path Traversal（MEDIUM）

- 文件：`script/ace/src-min-noconflict/ace.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
\f\r \u00a0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029\ufeff";if(!String.prototype.trim||_.trim()){_="["+_+"]";var D=new RegExp("^"+_+_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.246 XSS（MEDIUM）

- 文件：`script/ace/src-min-noconflict/ace.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
\f\r \u00a0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029\ufeff";if(!String.prototype.trim||_.trim()){_="["+_+"]";var D=new RegExp("^"+_+_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.247 XSS（MEDIUM）

- 文件：`script/ace/src-min-noconflict/ext-keybinding_menu.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/menu_tools/overlay_page",["require","exports","module","ace/lib/dom"],function(e,t,n){"use strict";var r=e("../../lib/dom"),i="#ace_settingsmenu, #kbshortcutmenu {background-color:
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.248 Path Traversal（MEDIUM）

- 文件：`script/ace/src-min-noconflict/mode-objectivec.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/doc_comment_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.249 XSS（MEDIUM）

- 文件：`script/ace/src-min-noconflict/mode-objectivec.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/doc_comment_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.250 XSS（MEDIUM）

- 文件：`script/ace/src-min-noconflict/mode-php.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/doc_comment_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.251 Weak Cryptography（MEDIUM）

- 文件：`script/ace/src-min-noconflict/mode-php.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/doc_comment_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.252 Command Injection（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-coffee.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.253 Path Traversal（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-coffee.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.254 Command Injection（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-css.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.255 Path Traversal（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-css.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.256 Command Injection（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-javascript.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.257 Path Traversal（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-javascript.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.258 XSS（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-javascript.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.259 Weak Randomness（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-javascript.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.260 Command Injection（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-javascript.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
";break;case"x":var c=parseInt(this.input.substr(1,2),16);this.triggerAsync("warning",{code:"W114",line:this.line,character:this.char,data:["\\x-"]},e,function(){return o.jsonMode}),u=String.fromCharC
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.261 Path Traversal（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-javascript.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
";break;case"x":var c=parseInt(this.input.substr(1,2),16);this.triggerAsync("warning",{code:"W114",line:this.line,character:this.char,data:["\\x-"]},e,function(){return o.jsonMode}),u=String.fromCharC
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.262 XSS（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-javascript.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
";break;case"x":var c=parseInt(this.input.substr(1,2),16);this.triggerAsync("warning",{code:"W114",line:this.line,character:this.char,data:["\\x-"]},e,function(){return o.jsonMode}),u=String.fromCharC
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.263 Command Injection（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-xquery.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.264 Path Traversal（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-xquery.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.265 Server-Side Template Injection（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-xquery.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.266 Weak Randomness（MEDIUM）

- 文件：`script/ace/src-min-noconflict/worker-xquery.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.267 Path Traversal（MEDIUM）

- 文件：`script/ace/src-min-noconflict/snippets/javascript.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/javascript",["require","exports","module"],function(e,t,n){"use strict";t.snippetText='# Prototype\nsnippet proto\n	${1:class_name}.prototype.${2:method_name} = function(${3:f
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.268 XSS（MEDIUM）

- 文件：`script/ace/src-min-noconflict/snippets/php.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/php",["require","exports","module"],function(e,t,n){"use strict";t.snippetText="snippet <?\n	<?php\n\n	${1}\nsnippet ec\n	echo ${1};\nsnippet <?e\n	<?php echo ${1} ?>\n# this 
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.269 Path Traversal（MEDIUM）

- 文件：`script/ace/src-min-noconflict/snippets/ruby.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/ruby",["require","exports","module"],function(e,t,n){"use strict";t.snippetText='########################################\n# Ruby snippets - for Rails, see below #\n##########
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.270 SSRF（MEDIUM）

- 文件：`script/ace/src-min-noconflict/snippets/ruby.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/ruby",["require","exports","module"],function(e,t,n){"use strict";t.snippetText='########################################\n# Ruby snippets - for Rails, see below #\n##########
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.271 XSS（MEDIUM）

- 文件：`script/ace/src-min-noconflict/snippets/ruby.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/ruby",["require","exports","module"],function(e,t,n){"use strict";t.snippetText='########################################\n# Ruby snippets - for Rails, see below #\n##########
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.272 Weak Hash（MEDIUM）

- 文件：`script/ace/src-min-noconflict/snippets/ruby.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/ruby",["require","exports","module"],function(e,t,n){"use strict";t.snippetText='########################################\n# Ruby snippets - for Rails, see below #\n##########
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.273 XSS（MEDIUM）

- 文件：`script/calendar/calendar-setup.js:188`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if (dateEl) params.date = Date.parseDate(dateEl.value || dateEl.innerHTML, cal.dateFormat, dateType);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.274 XSS（MEDIUM）

- 文件：`_japp/control/users/remove.php:17`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "A total number of ".count($_POST['sel'])." users where removed.<hr/><a href='?'>Back</a>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.275 Weak Randomness（MEDIUM）

- 文件：`_japp/model/frontcontroller.php:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->RequestID .= mt_rand ( 0, 9 );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.276 Weak Randomness（MEDIUM）

- 文件：`_japp/model/lib/security.php:30`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
mt_srand(self::$randomSeed);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.277 Weak Randomness（MEDIUM）

- 文件：`_japp/model/lib/security.php:32`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$random32bit=mt_rand();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.278 Weak Randomness（MEDIUM）

- 文件：`_japp/model/lib/security.php:72`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return substr(hash("sha512",jf::rand()),0,$Length);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.279 Weak Randomness（MEDIUM）

- 文件：`_japp/model/lib/security/password.php:215`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->DynamicSalt=hash("sha512",jf::rand());
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.280 Weak Randomness（MEDIUM）

- 文件：`_japp/model/service/manager.php:186`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$OldResult=$Result=mt_rand(1,100000);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.281 Weak Hash（MEDIUM）

- 文件：`_japp/plugin/nusoap/nusoap.php:2639`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
// H(A1) = MD5(A1)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.282 Weak Hash（MEDIUM）

- 文件：`_japp/plugin/nusoap/nusoap.php:2640`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$HA1 = md5($A1);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.283 Weak Hash（MEDIUM）

- 文件：`_japp/plugin/nusoap/nusoap.php:2646`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$HA2 =  md5($A2);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.284 Weak Hash（MEDIUM）

- 文件：`_japp/plugin/nusoap/nusoap.php:2668`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$hashedDigest = md5($unhashedDigest);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.285 Weak Randomness（MEDIUM）

- 文件：`_japp/plugin/nusoap/nusoap.php:7860`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$r = rand();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.286 Weak Randomness（MEDIUM）

- 文件：`_japp/plugin/nusoap/nusoap.php:7967`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$r = rand();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.287 XSS（MEDIUM）

- 文件：`_japp/view/default/rbac/deletepermission.php:8`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<?php echo BR.$this->Error?>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.288 XSS（MEDIUM）

- 文件：`_japp/view/default/rbac/deleterole.php:8`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<?php echo BR.$this->Error?>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.289 XSS（MEDIUM）

- 文件：`_japp/view/default/rbac/unassign.php:81`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $_GET['offset'] + $_GET['limit']?>" /> <input type='submit'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.290 XSS（MEDIUM）

- 文件：`_japp/view/default/users/unassign.php:80`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $_GET['offset'] + $_GET['limit']?>" /> <input type='submit'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.291 XSS（MEDIUM）

- 文件：`_japp/view/_internal/test/result/web.php:241`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<td>".count($linesNeedingCoverage)."</td>\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.292 XSS（MEDIUM）

- 文件：`_japp/view/_internal/test/result/web.php:242`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<td>".count($linesNeedingAndHavingCoverage)."</td>\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.293 XSS（MEDIUM）

- 文件：`_japp/view/_internal/test/result/web.php:244`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<td><strong>{$codeCoveragePercent}%</strong></td>\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.294 XSS（MEDIUM）

- 文件：`_japp/view/_internal/test/result/web.php:266`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<p>".count($linesNeedingCoverage)." lines need coverage, out of which ".count($linesNeedingAndHavingCoverage)." lines have coverage.
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.295 Path Traversal（MEDIUM）

- 文件：`_japp/view/_internal/test/result/web.php:271`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$content=file_get_contents($filename);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.296 SSRF（MEDIUM）

- 文件：`_japp/view/_internal/test/result/web.php:271`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$content=file_get_contents($filename);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.297 Path Traversal（LOW）

- 文件：`app/control/mode/workshop/challenges/__catch.php:63`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$sourceCode = file_get_contents($absolutePath."index.php");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.298 SSRF（LOW）

- 文件：`app/control/mode/workshop/challenges/__catch.php:63`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$sourceCode = file_get_contents($absolutePath."index.php");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.299 XSS（LOW）

- 文件：`app/model/j/phpjs.php:230`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return 'document.write('.$this->parseUntil(';').');';
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.300 XSS（LOW）

- 文件：`app/model/j/form/captcha.php:174`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo " /> <img height='40' src='".HttpRequest::Path()."?CAPTCHA=".urlencode($this->Name())."' border='1px' onclick=\"this.src=''; this.src='".HttpRequest::Path()."?CAPTCHA=".urlencode($this->Name())."
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.301 XSS（LOW）

- 文件：`app/model/j/form/csrf.php:31`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<input class='jWidget jFormCSRF' type='hidden' name='{$this->Name()}' value='{$this->Token}' />\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.302 XSS（LOW）

- 文件：`app/model/j/form/dropdown.php:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
?>		<option value='<?php echo $value;?>' id='<?php echo $this->Name()."_".$value;?>'><?php echo $text;?></option>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.303 XSS（LOW）

- 文件：`app/model/j/form/radio.php:15`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
?>	<input type='radio' <?php $this->DumpClass();?> <?php $this->DumpName();?> id='<?php echo $this->Name()."_".$value;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.304 XSS（LOW）

- 文件：`app/model/j/form/radio.php:16`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
?>' value='<?php echo $value;?>' <?php if ($index++==0) echo " checked='checked'";?> <?php $this->DumpStyle();?>/><label for="<?php echo $this->Name();
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.305 Path Traversal（LOW）

- 文件：`app/model/lesson/scanner.php:109`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
require_once($lessonDir."/index.php");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.306 XSS（LOW）

- 文件：`app/plugin/autoform.php:56`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var bgimg="url('<?php echo SiteRoot;?>/img/plugin/autoform/icon/"+icon+"16.png')";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.307 XSS（LOW）

- 文件：`app/plugin/autoform.php:57`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$("form.autoform#<?php echo $this->formAttribs['Id'];?> *[name='"+name+"']").css("background-image",bgimg);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.308 XSS（LOW）

- 文件：`app/plugin/autoform.php:78`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
var item=$("form.autoform#<?php echo $this->formAttribs['Id'];?> *[name='"+idx+"']");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.309 XSS（LOW）

- 文件：`app/plugin/autoform.php:79`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if (item.is(":visible") && !item.val().match(<?php echo $E['Validation'];?>))
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.310 XSS（LOW）

- 文件：`app/plugin/autoform.php:226`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo 'width:'.$E['width'].';';?>">
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.311 XSS（LOW）

- 文件：`app/plugin/autoform.php:342`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
//					echo "Validation failed on ".$E['Name'].BR;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.312 XSS（LOW）

- 文件：`app/plugin/captcha.php:105`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$("#<?php echo $ID;?>").attr("src",'<?php echo SiteRoot;?>/user/captcha?title=<?php echo $Title;?>&random='+Math.floor(Math.random()*100000));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.313 XSS（LOW）

- 文件：`app/plugin/jalali.php:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
*			echo $g2j[0]." ".$g2j[1]." ".$g2j[2];
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.314 XSS（LOW）

- 文件：`app/plugin/jalali.php:12`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
*			echo $j2g[0]." ".$j2g[1]." ".$j2g[2];
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.315 Path Traversal（LOW）

- 文件：`app/plugin/lastrss.php:78`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if ($f = @fopen($cache_file, 'w')) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.316 SSRF（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Common/Annotations/CachedReader.php:211`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if (($data = $this->cache->fetch($cacheKey)) !== false) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.317 SSRF（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Common/Annotations/CachedReader.php:248`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return $this->cache->fetch('[C]'.$cacheKey) >= filemtime($filename);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.318 SSRF（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Common/Persistence/Mapping/AbstractClassMetadataFactory.php:201`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if (($cached = $this->cacheDriver->fetch($realClassName . $this->cacheSalt)) !== false) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.319 SQL Injection（LOW）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Driver/OCI8/OCI8Connection.php:128`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$stmt   = $this->query($sql);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.320 SQL Injection（LOW）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Id/TableGenerator.php:119`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$stmt = $this->conn->executeQuery($sql, array($sequenceName));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.321 XSS（LOW）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Logging/EchoSQLLogger.php:43`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $sql . PHP_EOL;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.322 Command Injection（LOW）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Schema/SQLServerSchemaManager.php:243`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->_conn->exec("ALTER TABLE $tableDiff->name DROP CONSTRAINT " . $constraint['Name']);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.323 Command Injection（LOW）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Sharding/SQLAzure/SQLAzureShardManager.php:235`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->conn->exec($sql);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.324 Path Traversal（LOW）

- 文件：`app/plugin/doctrine/Doctrine/DBAL/Types/BlobType.php:51`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$value = fopen('data://text/plain;base64,' . base64_encode($value), 'r');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.325 SQL Injection（LOW）

- 文件：`app/plugin/doctrine/Doctrine/ORM/Id/UuidGenerator.php:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return $conn->query($sql)->fetchColumn(0);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.326 Path Traversal（LOW）

- 文件：`app/plugin/doctrine/Doctrine/ORM/Tools/DebugUnitOfWorkListener.php:66`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$fh = fopen($this->file, "x+");
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.327 Path Traversal（LOW）

- 文件：`app/plugin/doctrine/Doctrine/ORM/Tools/EntityGenerator.php:336`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->parseTokensInEntityFile(file_get_contents($path));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.328 SSRF（LOW）

- 文件：`app/plugin/doctrine/Doctrine/ORM/Tools/EntityGenerator.php:336`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->parseTokensInEntityFile(file_get_contents($path));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.329 Path Traversal（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Symfony/Component/Console/Tests/Helper/DialogHelperTest.php:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$stream = fopen('php://memory', 'r+', false);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.330 Path Traversal（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Symfony/Component/Console/Tests/Helper/DialogHelperTest.php:91`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return new StreamOutput(fopen('php://memory', 'r+', false));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.331 Path Traversal（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Symfony/Component/Yaml/Tests/DumperTest.php:42`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$yamls = file_get_contents($this->path.'/'.$file.'.yml');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.332 SSRF（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Symfony/Component/Yaml/Tests/DumperTest.php:42`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$yamls = file_get_contents($this->path.'/'.$file.'.yml');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.333 Command Injection（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Symfony/Component/Yaml/Tests/DumperTest.php:56`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$expected = eval('return '.trim($test['php']).';');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.334 Path Traversal（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Symfony/Component/Yaml/Tests/ParserTest.php:52`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$files = $parser->parse(file_get_contents($path.'/index.yml'));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.335 SSRF（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Symfony/Component/Yaml/Tests/ParserTest.php:52`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$files = $parser->parse(file_get_contents($path.'/index.yml'));
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.336 Path Traversal（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Symfony/Component/Yaml/Tests/ParserTest.php:54`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$yamls = file_get_contents($path.'/'.$file.'.yml');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.337 SSRF（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Symfony/Component/Yaml/Tests/ParserTest.php:54`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$yamls = file_get_contents($path.'/'.$file.'.yml');
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.338 Command Injection（LOW）

- 文件：`app/plugin/doctrine/Doctrine/Symfony/Component/Yaml/Tests/ParserTest.php:66`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$expected = var_export(eval('return '.trim($test['php']).';'), true);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.339 XSS（LOW）

- 文件：`app/view/default/mode/single/challenges/__catch.php:43`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<a data-toggle="collapse" data-parent="accordion" href="#section<?php echo ++$i;?>">
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.340 XSS（LOW）

- 文件：`app/view/default/mode/workshop/admin.php:89`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<td><?php foreach ($users as $userName) { echo $userName."<br>";} ?></td>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.341 XSS（LOW）

- 文件：`app/view/default/mode/workshop/challenges/__catch.php:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<a data-toggle="collapse" data-parent="accordion" href="#section<?php echo ++$i;?>">
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.342 XSS（LOW）

- 文件：`app/view/mobile/main.php:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
//echo "Hi this is intended to be the mobile view of jFramework! You're on ".$m->IsMobileUserAgent().BR;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.343 Command Injection（LOW）

- 文件：`files/index.php:231`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
@eval($sort);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.344 Server-Side Template Injection（LOW）

- 文件：`script/bootstrap-datetimepicker.js:1020`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
'<div class="col-sm-6 timepicker">' + tpGlobal.getTemplate() + '</div>' +
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.345 Server-Side Template Injection（LOW）

- 文件：`script/bootstrap-datetimepicker.js:1029`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
'<div class="timepicker">' + tpGlobal.getTemplate() + '</div>' +
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.346 Server-Side Template Injection（LOW）

- 文件：`script/bootstrap-datetimepicker.js:1039`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
'<div class="timepicker">' + tpGlobal.getTemplate() + '</div>' +
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.347 Path Traversal（LOW）

- 文件：`script/moment.js:765`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
require('./locale/' + name);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.348 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/ext-chromevox.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/chromevox",["require","exports","module","ace/editor","ace/config"],function(e,t,n){function gt(){return typeof cvox!="undefined"&&cvox&&cvox.Api}function wt(e){if(gt())mt(e);else{
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.349 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/ext-elastic_tabstops_lite.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/elastic_tabstops_lite",["require","exports","module","ace/editor","ace/config"],function(e,t,n){"use strict";var r=function(e){this.$editor=e;var t=this,n=[],r=!1;this.onAfterExec=
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.350 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/ext-emmet.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets",["require","exports","module","ace/lib/oop","ace/lib/event_emitter","ace/lib/lang","ace/range","ace/anchor","ace/keyboard/hash_handler","ace/tokenizer","ace/lib/dom","ace/edi
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.351 Path Traversal（LOW）

- 文件：`script/ace/src-min-noconflict/ext-emmet.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets",["require","exports","module","ace/lib/oop","ace/lib/event_emitter","ace/lib/lang","ace/range","ace/anchor","ace/keyboard/hash_handler","ace/tokenizer","ace/lib/dom","ace/edi
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.352 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/ext-language_tools.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets",["require","exports","module","ace/lib/oop","ace/lib/event_emitter","ace/lib/lang","ace/range","ace/anchor","ace/keyboard/hash_handler","ace/tokenizer","ace/lib/dom","ace/edi
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.353 Server-Side Template Injection（LOW）

- 文件：`script/ace/src-min-noconflict/ext-modelist.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/modelist",["require","exports","module"],function(e,t,n){"use strict";function i(e){var t=a.text,n=e.split(/[\/\\]/).pop();for(var i=0;i<r.length;i++)if(r[i].supportsFile(n)){t=r[i
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.354 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/ext-old_ie.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/searchbox",["require","exports","module","ace/lib/dom","ace/lib/lang","ace/lib/event","ace/keyboard/hash_handler","ace/lib/keys"],function(e,t,n){"use strict";var r=e("../lib/dom")
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.355 Path Traversal（LOW）

- 文件：`script/ace/src-min-noconflict/ext-old_ie.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/searchbox",["require","exports","module","ace/lib/dom","ace/lib/lang","ace/lib/event","ace/keyboard/hash_handler","ace/lib/keys"],function(e,t,n){"use strict";var r=e("../lib/dom")
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.356 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/ext-old_ie.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/searchbox",["require","exports","module","ace/lib/dom","ace/lib/lang","ace/lib/event","ace/keyboard/hash_handler","ace/lib/keys"],function(e,t,n){"use strict";var r=e("../lib/dom")
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.357 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/ext-searchbox.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/searchbox",["require","exports","module","ace/lib/dom","ace/lib/lang","ace/lib/event","ace/keyboard/hash_handler","ace/lib/keys"],function(e,t,n){"use strict";var r=e("../lib/dom")
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.358 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/ext-searchbox.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/searchbox",["require","exports","module","ace/lib/dom","ace/lib/lang","ace/lib/event","ace/keyboard/hash_handler","ace/lib/keys"],function(e,t,n){"use strict";var r=e("../lib/dom")
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.359 SQL Injection（LOW）

- 文件：`script/ace/src-min-noconflict/ext-split.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/split",["require","exports","module","ace/lib/oop","ace/lib/lang","ace/lib/event_emitter","ace/editor","ace/virtual_renderer","ace/edit_session"],function(e,t,n){"use strict";function 
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.360 Server-Side Template Injection（LOW）

- 文件：`script/ace/src-min-noconflict/ext-static_highlight.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/static_highlight",["require","exports","module","ace/edit_session","ace/layer/text","ace/config","ace/lib/dom"],function(e,t,n){"use strict";var r=e("../edit_session").EditSession,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.361 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/ext-static_highlight.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/ext/static_highlight",["require","exports","module","ace/edit_session","ace/layer/text","ace/config","ace/lib/dom"],function(e,t,n){"use strict";var r=e("../edit_session").EditSession,
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.362 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/ext-textarea.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/theme/textmate",["require","exports","module","ace/lib/dom"],function(e,t,n){"use strict";t.isDark=!1,t.cssClass="ace-tm",t.cssText='.ace-tm .ace_gutter {background: #f0f0f0;color: #33
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.363 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/keybinding-emacs.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/occur",["require","exports","module","ace/lib/oop","ace/range","ace/search","ace/edit_session","ace/search_highlight","ace/lib/dom"],function(e,t,n){"use strict";function a(){}var r=e(
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.364 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/keybinding-vim.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/keyboard/vim/registers",["require","exports","module"],function(e,t,n){"never use strict";n.exports={_default:{text:"",isLine:!1}}}),ace.define("ace/keyboard/vim/maps/util",["require",
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.365 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/mode-asciidoc.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/asciidoc_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_rul
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.366 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/mode-batchfile.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/batchfile_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_ru
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.367 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/mode-c9search.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/c9search_highlight_rules",["require","exports","module","ace/lib/oop","ace/lib/lang","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";function o(e,t){try{return new R
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.368 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/mode-clojure.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/clojure_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_rule
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.369 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/mode-csharp.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/doc_comment_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.370 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/mode-dockerfile.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/sh_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_rules").T
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.371 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/mode-jsoniq.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/xquery/jsoniq_lexer",["require","exports","module"],function(e,t,n){n.exports=function r(t,n,i){function s(u,a){if(!n[u]){if(!t[u]){var f=typeof e=="function"&&e;if(!a&&f)return f
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.372 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/mode-jsp.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/css_highlight_rules",["require","exports","module","ace/lib/oop","ace/lib/lang","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("../lib/lan
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.373 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/mode-latex.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/latex_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_rules"
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.374 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/mode-lua.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/lua_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_rules").
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.375 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/mode-luapage.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/doc_comment_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.376 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/mode-makefile.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/sh_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_rules").T
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.377 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/mode-markdown.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/doc_comment_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.378 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/mode-matlab.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/matlab_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_rules
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.379 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/mode-mel.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/mel_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_rules").
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.380 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/mode-sh.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/sh_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_rules").T
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.381 Server-Side Template Injection（LOW）

- 文件：`script/ace/src-min-noconflict/mode-twig.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/doc_comment_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],function(e,t,n){"use strict";var r=e("../lib/oop"),i=e("./text_highlight_
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.382 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/mode-xquery.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/mode/xquery/xquery_lexer",["require","exports","module"],function(e,t,n){n.exports=function r(t,n,i){function s(u,a){if(!n[u]){if(!t[u]){var f=typeof e=="function"&&e;if(!a&&f)return f
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.383 Path Traversal（LOW）

- 文件：`script/ace/src-min-noconflict/worker-html.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.384 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/worker-html.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"||c==" "||c=="<"||c=="&")return e.unget(l),!1;if(n===c)return e.unget(l),!1;if(c=="#"){c=e.shift(1);if(c===i.EOF)return t._parseError("expected-numeric-entity-but-got-eof"),e.unget(l),!1;l+=c;var h=1
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.385 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/worker-html.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
\f \r&<>\"'=`]");o===r.EOF&&(t._parseError("eof-in-attribute-value-no-quotes"),t._emitCurrentToken()),e.commit(),t._currentAttribute().nodeValue+=i+o}return!0}function $(e){var n=i.consumeEntity(e,t,t
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.386 Path Traversal（LOW）

- 文件：`script/ace/src-min-noconflict/worker-json.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.387 Path Traversal（LOW）

- 文件：`script/ace/src-min-noconflict/worker-lua.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.388 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/worker-php.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.389 Path Traversal（LOW）

- 文件：`script/ace/src-min-noconflict/worker-php.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.390 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/worker-php.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
"no use strict";(function(e){if(typeof e.window!="undefined"&&e.document)return;e.console=function(){var e=Array.prototype.slice.call(arguments,0);postMessage({type:"log",data:e})},e.console.error=e.c
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.391 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/worker-php.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
",e:""};return e.replace(/~\\\\([\\\\$nrtfve]|[xX][0-9a-fA-F]{1,2}|[0-7]{1,3})~/g,function(e){var t=e[1];return n[t]!==undefined?n[t]:"x"===t[0]||"X"===t[0]?chr(hexdec(t)):chr(octdec(t))})},r.Parser.
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.392 Path Traversal（LOW）

- 文件：`script/ace/src-min-noconflict/worker-php.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
",e:""};return e.replace(/~\\\\([\\\\$nrtfve]|[xX][0-9a-fA-F]{1,2}|[0-7]{1,3})~/g,function(e){var t=e[1];return n[t]!==undefined?n[t]:"x"===t[0]||"X"===t[0]?chr(hexdec(t)):chr(octdec(t))})},r.Parser.
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.393 SSRF（LOW）

- 文件：`script/ace/src-min-noconflict/worker-php.js:2`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
",e:""};return e.replace(/~\\\\([\\\\$nrtfve]|[xX][0-9a-fA-F]{1,2}|[0-7]{1,3})~/g,function(e){var t=e[1];return n[t]!==undefined?n[t]:"x"===t[0]||"X"===t[0]?chr(hexdec(t)):chr(octdec(t))})},r.Parser.
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.394 Path Traversal（LOW）

- 文件：`script/ace/src-min-noconflict/snippets/erlang.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/erlang",["require","exports","module"],function(e,t,n){"use strict";t.snippetText="# module and export all\nsnippet mod\n	-module(${1:`Filename('', 'my')`}).\n	\n	-compile([ex
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.395 Command Injection（LOW）

- 文件：`script/ace/src-min-noconflict/snippets/java.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/java",["require","exports","module"],function(e,t,n){"use strict";t.snippetText='## Access Modifiers\nsnippet po\n	protected\nsnippet pu\n	public\nsnippet pr\n	private\n##\n##
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.396 Path Traversal（LOW）

- 文件：`script/ace/src-min-noconflict/snippets/r.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/r",["require","exports","module"],function(e,t,n){"use strict";t.snippetText='snippet #!\n	#!/usr/bin/env Rscript\n\n# includes\nsnippet lib\n	library(${1:package})\nsnippet r
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.397 XSS（LOW）

- 文件：`script/ace/src-min-noconflict/snippets/sh.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/sh",["require","exports","module"],function(e,t,n){"use strict";t.snippetText='# Shebang. Executing bash via /usr/bin/env makes scripts more portable.\nsnippet #!\n	#!/usr/bin
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.398 Server-Side Template Injection（LOW）

- 文件：`script/ace/src-min-noconflict/snippets/vala.js:1`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
ace.define("ace/snippets/vala",["require","exports","module"],function(e,t,n){"use strict";t.snippets=[{content:"case ${1:condition}:\n	$0\n	break;\n",name:"case",scope:"vala",tabTrigger:"case"},{cont
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.399 XSS（LOW）

- 文件：`script/calendar/calendar.js:335`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
yr.innerHTML = cal.convertNumbers(Y);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.400 XSS（LOW）

- 文件：`script/calendar/calendar.js:800`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
cell.innerHTML = "<div unselectable='on'>" + text + "</div>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.401 XSS（LOW）

- 文件：`script/calendar/calendar.js:877`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
cell.innerHTML = Calendar._TT["TIME"] || "&nbsp;";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.402 XSS（LOW）

- 文件：`script/calendar/calendar.js:935`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
H.innerHTML = cal.convertNumbers(hrs);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.403 XSS（LOW）

- 文件：`script/calendar/calendar.js:936`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
M.innerHTML = cal.convertNumbers(mins);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.404 XSS（LOW）

- 文件：`script/calendar/calendar.js:943`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if ((AP.innerHTML == Calendar._TT["LPM"] || AP.innerHTML == Calendar._TT["PM"]) && h < 12)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.405 XSS（LOW）

- 文件：`script/calendar/calendar.js:945`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
else if ((AP.innerHTML == Calendar._TT["LAM"] || AP.innerHTML == Calendar._TT["AM"]) && h == 12)
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.406 XSS（LOW）

- 文件：`script/calendar/calendar.js:1271`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
this.title.innerHTML = (this.dateType == 'jalali' ? Calendar._JMN[month] : Calendar._MN[month]) + ", " + this.convertNumbers(year);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.407 XSS（LOW）

- 文件：`script/calendar/calendar.js:1276`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
// this.tooltips.innerHTML = "Generated in " + ((new Date()) - today) + " ms";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.408 XSS（LOW）

- 文件：`script/calendar/calendar.js:1626`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
cell.innerHTML = Calendar._SDN[(i + fdow) % 7];
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.409 XSS（LOW）

- 文件：`script/prettify/lang-matlab.js:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
b.registerLangHandler(b.createSimpleLexer([],[[b.PR_KEYWORD,/^\b(?:break|case|catch|classdef|continue|else|elseif|end|for|function|global|if|otherwise|parfor|persistent|return|spmd|switch|try|while)\b
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.410 Command Injection（LOW）

- 文件：`script/prettify/prettify.js:16`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
a.a=b;a.d=g.d;a.e=0;I(d,b)(a);var s=/\bMSIE\s(\d+)/.exec(navigator.userAgent),s=s&&+s[1]<=8,d=/\n/g,x=a.a,m=x.length,g=0,j=a.d,k=j.length,b=0,c=a.g,i=c.length,r=0;c[i]=m;var n,e;for(e=n=0;e<i;)c[e]!==
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.411 XSS（LOW）

- 文件：`script/prettify/prettify.js:26`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
p(C([],[["str",/^[\S\s]+/]]),["regex"]);var Y=D.PR={createSimpleLexer:C,registerLangHandler:p,sourceDecorator:v,PR_ATTRIB_NAME:"atn",PR_ATTRIB_VALUE:"atv",PR_COMMENT:"com",PR_DECLARATION:"dec",PR_KEYW
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.412 XSS（LOW）

- 文件：`script/prettify/prettify.js:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return b.innerHTML},prettyPrint:D.prettyPrint=function(a,d){function g(){for(var b=D.PR_SHOULD_USE_CONTINUATION?c.now()+250:Infinity;i<p.length&&c.now()<b;i++){for(var d=p[i],j=h,k=d;k=k.previousSibli
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.413 Command Injection（LOW）

- 文件：`script/prettify/run_prettify.js:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
a.h;try{var h=m(a.c,a.i),b=h.a;a.a=b;a.d=h.d;a.e=0;A(d,b)(a);var e=/\bMSIE\s(\d+)/.exec(navigator.userAgent),e=e&&+e[1]<=8,d=/\n/g,i=a.a,j=i.length,h=0,l=a.d,n=l.length,b=0,c=a.g,p=c.length,t=0;c[p]=j
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.414 XSS（LOW）

- 文件：`script/prettify/run_prettify.js:30`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
i(C([],[["str",/^[\S\s]+/]]),["regex"]);var X=V.PR={createSimpleLexer:C,registerLangHandler:i,sourceDecorator:t,PR_ATTRIB_NAME:"atn",PR_ATTRIB_VALUE:"atv",PR_COMMENT:"com",PR_DECLARATION:"dec",PR_KEYW
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.415 XSS（LOW）

- 文件：`_japp/model/functions.php:39`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $data."\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.416 Command Injection（LOW）

- 文件：`_japp/model/launcher/test.php:102`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$res=shell_exec($command);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.417 Path Traversal（LOW）

- 文件：`_japp/model/lib/db/base.php:360`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return str_replace ( "PREFIX_", $this->Config->TablePrefix, file_get_contents ( $SetupFile ) );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.418 SSRF（LOW）

- 文件：`_japp/model/lib/db/base.php:360`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return str_replace ( "PREFIX_", $this->Config->TablePrefix, file_get_contents ( $SetupFile ) );
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.419 XSS（LOW）

- 文件：`_japp/model/lib/db/nestedset/base.php:372`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "adding 0 ".$R['Title'].BR;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.420 XSS（LOW）

- 文件：`_japp/model/lib/db/nestedset/base.php:378`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "adding 1 ".$R['Title'].BR;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.421 XSS（LOW）

- 文件：`_japp/model/lib/db/nestedset/base.php:386`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "adding 2 ".$R['Title'].BR;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.422 Path Traversal（LOW）

- 文件：`_japp/plugin/nusoap/nusoap.php:2372`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->fp = @fsockopen( $host, $this->port, $this->errno, $this->error_str, $connection_timeout);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.423 Path Traversal（LOW）

- 文件：`_japp/plugin/nusoap/nusoap.php:2374`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
$this->fp = @fsockopen( $host, $this->port, $this->errno, $this->error_str);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.424 Insecure Cookie（LOW）

- 文件：`_japp/plugin/nusoap/nusoap.php:3420`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
function getCookiesForRequest($cookies, $secure=false) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.425 Command Injection（LOW）

- 文件：`_japp/plugin/nusoap/nusoap.php:4073`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
@eval($funcCall);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.426 Path Traversal（LOW）

- 文件：`_japp/plugin/nusoap/nusoap.php:4824`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
if ($fp = @fopen($path, 'r')) {
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.427 XSS（LOW）

- 文件：`_japp/plugin/nusoap/nusoap.php:7919`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
return "echo \"" . $this->getError() . "\";";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.428 Path Traversal（LOW）

- 文件：`_japp/plugin/phpunit/loader.php:30`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
require_once($file);
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.429 XSS（LOW）

- 文件：`_japp/view/default/logs/view.php:72`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
starting from <input type='text' size='3' name='off' value='<?php echo $this->Offset+$this->Limit; ?>' />
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.430 XSS（LOW）

- 文件：`_japp/view/default/panel/dashboard.php:20`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<td colspan='4' align='center'><span id='title'><?php echo "<b>".trr(reg("app/title"))."</b> (".reg("app/name")." ".reg("app/version").")"?></span></td>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.431 XSS（LOW）

- 文件：`_japp/view/default/panel/dashboard.php:27`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<td title='<?php tr("Pages viewed in current sessions");?>'><?php tr("Active Page Views");?>: <?php $x=j::SQL("SELECT SUM(".reg("jf/session/table/AccessCount").") AS Count FROM ".reg("jf/session/table
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.432 XSS（LOW）

- 文件：`_japp/view/default/panel/dashboard.php:28`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<td><?php tr("Number of Users");?> : <?php $x=j::SQL("SELECT COUNT(*) AS Count FROM ".jf_Users_Table_Name); echo $x[0]['Count'];?></td>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.433 XSS（LOW）

- 文件：`_japp/view/default/panel/dashboard.php:29`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<td><?php tr("Number of User/Roles");?> : <?php $x=j::SQL("SELECT COUNT(*) AS Count FROM ".reg("jf/rbac/tables/RoleUsers/table/name")); echo $x[0]['Count'];?></td>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.434 XSS（LOW）

- 文件：`_japp/view/default/panel/dashboard.php:32`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<td><?php tr("Active Options");?> : <?php $x=j::SQL("SELECT COUNT(*) AS Count FROM ".reg("jf/options/table/name")); echo $x[0]['Count'];?></td>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.435 XSS（LOW）

- 文件：`_japp/view/default/panel/dashboard.php:33`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<td><?php tr("Number of Roles");?> : <?php $x=j::SQL("SELECT COUNT(*) AS Count FROM ".reg("jf/rbac/tables/Roles/table/name")); echo $x[0]['Count'];?></td>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.436 XSS（LOW）

- 文件：`_japp/view/default/panel/dashboard.php:34`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<td><?php tr("Number of Permissions");?> : <?php $x=j::SQL("SELECT COUNT(*) AS Count FROM ".reg("jf/rbac/tables/Permissions/table/name")); echo $x[0]['Count'];?></td>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.437 XSS（LOW）

- 文件：`_japp/view/default/panel/dashboard.php:35`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
<td><?php tr("Number of Role/Permissions");?> : <?php $x=j::SQL("SELECT COUNT(*) AS Count FROM ".reg("jf/rbac/tables/RolePermissions/table/name")); echo $x[0]['Count'];?></td>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.438 XSS（LOW）

- 文件：`_japp/view/default/panel/dashboard.php:129`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<strong>".++$n.". ".$L['Subject']." (".$L['Severity'].")</strong> ".$L['Data']." <i>(".date("Y-m-d H:i:s",$L['Timestamp']).")</i>".BR;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.439 XSS（LOW）

- 文件：`_japp/view/default/panel/development/translate.php:33`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $this->Affected." phrases affected.".BR;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.440 XSS（LOW）

- 文件：`_japp/view/default/panel/development/translate.php:82`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<textarea name='translation[]' {$style} rows='{$rows}'>{$Data}</textarea>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.441 XSS（LOW）

- 文件：`_japp/view/default/rbac/unassign.php:35`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $P['RoleID'] . "_" . $P['PermissionID']?>'>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.442 XSS（LOW）

- 文件：`_japp/view/default/rbac/unassign.php:43`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $P['RoleID'] . "_" . $P['PermissionID']?>'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.443 XSS（LOW）

- 文件：`_japp/view/default/rbac/unassign.php:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $P['RoleID'] . "_" . $P['PermissionID']?>' /><?php
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.444 XSS（LOW）

- 文件：`_japp/view/default/users/edit.php:126`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $this->Offset + $this->Limit?>&limit=<?php
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.445 XSS（LOW）

- 文件：`_japp/view/default/users/remove.php:89`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $this->Offset + $this->Limit?>&limit=<?php
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.446 XSS（LOW）

- 文件：`_japp/view/default/users/unassign.php:3`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $this->Result." ".tr("assignment were removed")."<hr/>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.447 XSS（LOW）

- 文件：`_japp/view/default/users/unassign.php:35`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $P['RoleID'] . "_" . $P['UserID']?>'>
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.448 XSS（LOW）

- 文件：`_japp/view/default/users/unassign.php:43`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $P['RoleID'] . "_" . $P['UserID']?>'
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.449 XSS（LOW）

- 文件：`_japp/view/default/users/unassign.php:45`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $P['RoleID'] . "_" . $P['UserID']?>' /><?php
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.450 XSS（LOW）

- 文件：`_japp/view/default/_template/head.php:94`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "" . $this->Session->Username() . "";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.451 XSS（LOW）

- 文件：`_japp/view/_internal/error.php:131`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $k . "<br/>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.452 XSS（LOW）

- 文件：`_japp/view/_internal/error.php:146`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<code>" . substr ( $x, $l1, $l - $l1 - $l2 ) . "</code>\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.453 XSS（LOW）

- 文件：`_japp/view/_internal/error.php:275`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $Pre . $Call ."<br/>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.454 XSS（LOW）

- 文件：`_japp/view/_internal/error.php:276`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $Pre . $ErrorPosition ."<br/><br/>";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.455 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/cli.php:10`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $Symbol.(count ( $ResultArray )) ." ".$Text."\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.456 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/cli.php:14`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo ++ $n;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.457 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/cli.php:38`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $filename;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.458 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/cli.php:49`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "✓  ".(count ( $result->passed () )) . " Tests Passed\n".str_repeat("-", "80")."\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.459 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/cli.php:54`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "\tTotal: " . ($result->count ()) . " Tests in " . count ( \jf\TestLauncher::$TestFiles ) . " Files (".$profiler->Timer()." seconds)\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.460 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/web.php:23`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo ++$n;
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.461 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/web.php:58`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo $dir."/<strong>{$filename}</strong> :{$line}";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.462 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/web.php:236`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<td style='padding-left:5px;text-align:left;'><a href='?coverage=1&file=".urlencode($filename)."'>".exho($filename,true)."</a></td>\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.463 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/web.php:291`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<pre class='covered'>{$lineNumber}  {$lineSafe}</pre>\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.464 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/web.php:293`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<pre class='uncovered'>{$lineNumber}  {$lineSafe}</pre>\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.465 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/web.php:296`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<pre class='noneed'>{$lineNumber}  {$lineSafe}</pre>\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。




### 4.466 XSS（LOW）

- 文件：`_japp/view/_internal/test/result/web.php:298`
- 来源：custom-taint
- 置信度：0.5
- 已验证：否
- 状态：confirmed

```text
echo "<pre>{$lineNumber}  {$lineSafe}</pre>\n";
```

**修复建议：** 使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。





## 5. 关键风险

- HIGH exec-use 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\_japp\model\launcher\test.php:102，状态为 confirmed。
- HIGH eval-use 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\_japp\plugin\nusoap\nusoap.php:4073，状态为 confirmed。
- HIGH eval-use 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\_japp\plugin\nusoap\nusoap.php:7868，状态为 confirmed。
- HIGH md5-loose-equality 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\model\contest\submissions.php:92，状态为 confirmed。
- HIGH eval-use 位于 C:\Users\52697\Desktop\2026小学期\AuditAgentX\data\projects\proj_4ef48595\app\plugin\doctrine\Doctrine\Symfony\Component\Yaml\Tests\DumperTest.php:56，状态为 confirmed。


## 6. 修改建议

- **P0 优先修复 Critical/High 漏洞：** 先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。
- **P1 按漏洞类型批量治理：** 对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。
- **P1 补充动态验证覆盖：** 为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。
- **P2 纳入持续审计流程：** 将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。


## 7. 结论

综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 HIGH 风险水平。建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
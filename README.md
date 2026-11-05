# Casbin Lean 4

[Apache Casbin](https://github.com/apache/casbin) 的 Lean 4 移植：加载访问控制模型和策略，判断请求是否允许，并返回决定结果的策略。Go 源码、原始示例和参考用例保留；上游说明见 [README-go.md](README-go.md)。

例如，策略允许 `reader` 读取 `report`，Alice 属于 `reader`，那么 Alice 读取报告会被允许，写入会被拒绝。

## 快速运行

需要 **Lean 4.35.0 / Lake、Python 3 和 C++11 编译器**。SQLite 功能需要 `sqlite3`，可选的 AI 接口需要 `curl`。macOS 的命令行开发工具和 Linux 的 `g++` 均可用于编译。首次构建会下载固定版本、SHA-256 校验的 [RE2](https://github.com/google/re2)；授权和策略逻辑由 Lean 实现，RE2 只提供正则原语，不需要 Go 工具链。

Ubuntu 26.04 还需要 Lean 共享库使用的 C++ 和 LLVM unwind 运行库（其他发行版需安装对应的软件包）：

```sh
sudo apt-get install g++ libc++1 libc++abi1 llvm-libunwind1 sqlite3
```

```sh
lake build
lake exe casbin demo
lake test
python3 scripts/lean-cli-smoke.py
```

演示中 Alice 读取报告被允许，Alice 写入报告和 Bob 读取报告被拒绝。

```sh
lake exe casbin enforce examples/basic_model.conf examples/basic_policy.csv alice data1 read
# {"allow":true,"explain":["alice","data1","read"]}

lake exe casbin batch examples/rbac_model.conf examples/rbac_policy.csv lean-examples/requests.json
```

请求顺序由模型的 `r = ...` 决定。单次判断的退出码：0 允许、1 拒绝、2 输入或执行错误。批处理正常完成返回 0，即使其中有拒绝结果。

对象、数字、布尔值和数组通过 JSON 输入：

```sh
lake exe casbin enforce-json MODEL.conf POLICY.csv REQUEST.json
# REQUEST.json: [{"Name":"alice","Age":21},{"Owner":"alice"},"read"]
```

`batch` 接受上述请求数组的数组，并兼容原先的字符串请求。

```sh
lake exe casbin validate MODEL.conf POLICY.csv
lake exe casbin export-js MODEL.conf POLICY.csv alice
lake exe casbin save-db MODEL.conf POLICY.csv policy.sqlite
lake exe casbin enforce-db MODEL.conf policy.sqlite REQUEST.json
```

`validate` 检查模型、策略、约束及角色循环。`export-js` 与 Go 前端接口一样导出整个模型及策略。数据库采用本项目的 `casbin_rule(seq, ptype, vals)` 表结构。

## 在 Lean 中使用

```lean
import Casbin
open Casbin

def main : IO Unit := do
  let e ← Enforcer.fromFiles "examples/basic_model.conf" "examples/basic_policy.csv"
  let runtime ← RuntimeEnforcer.new e (some (← Adapter.memory e.rules))
  runtime.enableCache true 60000 100
  let _ ← runtime.addPolicy ["bob", "report", "read"]
  IO.println (← runtime.enforce ["bob", "report", "read"])
```

运行独立 Lean 文件时，用包装脚本加载解释器需要的原生正则模块：

```sh
python3 scripts/run-lean.py lean-examples/Usage.lean
python3 scripts/run-lean.py lean-examples/Abac.lean
python3 scripts/run-lean.py lean-examples/Runtime.lean
```

`Enforcer` 是不可变状态，`addPolicy` 等操作返回新的执行器和变更标记；`RuntimeEnforcer` 使用真正的互斥锁共享状态，提供缓存、持久化、通知和事务。原 Go 的 synced / cached / distributed / transactional 类型对应同一个可配置运行执行器。命名策略可以传 `ptype`，也可以使用 `addNamedPolicy` 等兼容命名接口。

```lean
-- 不可变 API，在 Except String 中使用：
let (updated, changed) ← e.addPolicy ["bob", "data1", "read"]
let allowed ← updated.enforce ["bob", "data1", "read"]

-- 共享执行器的事务，在 IO 中使用：
runtime.withTransaction fun tx => do
  let _ ← tx.addPolicy ["bob", "report", "read"]
  pure ()
```

完整的接口对应、状态语义及配置方式见 [Lean API](docs/lean-api.md)。

## 移植范围

| 部分 | 实现 |
| --- | --- |
| 模型与策略 | CONF / CSV、注释、续行、命名定义、CSV 转义、模型序列化、字段索引、策略去重 |
| 权限模型 | ACL、RBAC、继承、域、资源角色、ReBAC、对象属性 ABAC、动态 `eval` |
| 效果 | allow / deny override、allow + deny、priority、subjectPriority、自定义 effector |
| 表达式 | 数字与算术、独立的位运算优先级、移位、比较、逻辑短路、列表成员、三元和合并运算、正则运算、日期字面量 |
| 匹配 | keyMatch 1–5、keyGet 1–3、RE2 正则、glob 目录和花括号、IPv4 / IPv6 / mapped IP 与 CIDR |
| 管理与 RBAC | 批量增删改、Ex 去重、过滤更新、命名策略、直接与隐式角色/用户/权限/资源查询、域和权限删除、对象条件提取 |
| 条件与约束 | 条件角色、严格时间边界、条件参数更新、sod / sodMax / roleMax / rolePre、角色循环检测 |
| 运行 | Mutex、决策缓存容量和过期、变更失效、过滤加载、自动重载、按键 LRU 执行器池 |
| 持久化 | 原子文件保存、字符串和内存适配器、SQLite、增量修改、共享存储冲突检查 |
| 事务与同步 | 隔离快照、提交/回滚、不相交修改合并、冲突检测、事务 ID/查询、Watcher/Dispatcher、版本化远程快照 |
| 扩展 | 字符串和类型值 matcher 函数、角色/域匹配、自定义角色管理器、日志、取消和超时上下文适配器 |
| 前端与解释 | Casbin.js 模型/策略导出、可注入 AI 传输、显式配置的兼容聊天接口 |

可选的自然语言解释需要调用者指定端点。下面的命令会将请求、模型和策略发给所提供的端点；测试仅使用本机模拟服务器。

```sh
# CASBIN_AI_KEY 从环境读取，密钥和请求通过 curl 的 stdin 传入
lake exe casbin explain MODEL.conf POLICY.csv REQUEST.json ENDPOINT AI_MODEL
```

## 验证与兼容边界

当前测试包含 **33 组、5,282 次 Go 参考权限请求，零跳过**，同时比较 `allow` 和 `explain`。另有 **357 条上游匹配函数用例**、**166 条** Go `govaluate` 生成的表达式用例，以及 ABAC、时间条件、约束、持久化失败、并发更新、事务冲突、缓存、后台重载、执行器池、取消上下文和本地复制测试。

```sh
CASBIN_CONFORMANCE_DIR=/path/to/conformance lake test
python3 scripts/generate-operator-fixtures.py
TZ=UTC go run ./scripts/lean-reference > Test/data/arithmetic.json
```

旧式 Go 匹配函数对非法正则返回 false/空字符串，matcher 包装函数返回错误；`evaluateLegacyBuiltin` 和普通 matcher 调用分别保留这两种语义。诊断文字不要求与 Go 完全相同。

这是功能移植与程序测试，**没有形式化证明，也没有声称每个 Go API 和输入均百分之百等价**。下列语言和环境差异需要调用者了解：

- Go 反射对象、方法及函数值用 Lean 的 `Value`、`ValueFunction` 和 `RoleManager` 接口表达，Go 对象本身不能直接传入 Lean。第三方数据库适配器和网络消息中间件需要实现相应回调；本项目提供的是可运行接口与 SQLite 实现。
- 无时区的日期字面量按 UTC 解析，Go 的 `govaluate` 使用本地时区；跨时区应用应使用带偏移的日期。RE2 固定为 2023-03-01，Unicode 表随该版本固定。
- 动态 `eval` 的嵌套深度限制为 64；默认权限角色查找最多经过 10 条边，可以修改 `maxHierarchyDepth`。
- 取消是协作式的，适配器负责在长 IO 中检查上下文。已经提交的写入不因后续取消或通知失败而回滚。Watcher/Dispatcher 的测试是本地同步和乱序检查，不能代替具体网络部署测试。
- 内置文件和字符串适配器与 Go 文件适配器一样，需要显式 `savePolicy`；内存和 SQLite 支持自动增量保存。过滤快照禁止整份保存。Linux 和 macOS 由 CI 验证，Windows 尚未验证。

## 代码与许可证

公共入口是 `Casbin.lean`。解析、模型、策略和权限逻辑位于 `Casbin/`；`Adapter`、`Runtime`、`Operations`、`Support` 分别负责持久化、共享状态、运行功能和外部接口。`Test/Main.lean` 读取原 Go 参考请求，`Test/Extended.lean` 检查扩展行为。

沿用上游 [Apache License 2.0](LICENSE) 和 [NOTICE](NOTICE)。RE2 使用 BSD 许可证，其许可证随下载保存在 `.lake/native/RE2-LICENSE`，版本及归属见 [native/README.md](native/README.md)。

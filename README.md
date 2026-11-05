# Casbin Lean 4

把 [Apache Casbin](https://github.com/apache/casbin) 的权限控制核心移植到 Lean 4。给定模型、策略和请求，返回“允许 / 拒绝”及决定结果的策略。

例如：策略规定 `reader` 可以读取 `report`，Alice 属于 `reader`，那么 Alice 读取报告会被允许，写入会被拒绝。

这是可运行的核心版本，使用 **Lean 4.35.0**，只依赖工具链自带的 `Std`；命令行和测试使用工具链自带的 JSON 库。Go 源码及示例保留，原项目说明见 [README-go.md](README-go.md)。

## 快速运行

安装 [elan](https://github.com/leanprover/elan) 后，在仓库目录运行：

```sh
lake build
lake exe casbin demo
lake test
```

演示输出三条 JSON：Alice 读取报告被允许，Alice 写入报告和 Bob 读取报告被拒绝。

也可以直接读取原 Casbin 的模型和策略文件：

```sh
lake exe casbin enforce examples/basic_model.conf examples/basic_policy.csv alice data1 read
# {"allow":true,"explain":["alice","data1","read"]}

lake exe casbin enforce examples/rbac_model.conf examples/rbac_policy.csv alice data2 write
```

请求参数顺序由模型的 `r = ...` 决定。`enforce` 退出码：0 表示允许，1 表示拒绝，2 表示输入或执行错误。拒绝属于正常权限判断结果。

批量执行：

```sh
lake exe casbin batch examples/rbac_model.conf examples/rbac_policy.csv lean-examples/requests.json
```

批量输入是字符串数组的数组，输出是对应的决策数组。批量处理成功返回 0，错误返回 2。

## 在 Lean 程序中使用

```lean
import Casbin

open Casbin

def main : IO Unit := do
  let enforcer ← Enforcer.fromFiles "examples/rbac_model.conf" "examples/rbac_policy.csv"
  match enforcer.enforceEx ["alice", "data2", "write"] with
  | .ok decision => IO.println s!"allow={decision.allow}, explain={decision.explain}"
  | .error error => throw (IO.userError error)
```

完整例子见 [lean-examples/Usage.lean](lean-examples/Usage.lean)，可以用 `lake env lean --run lean-examples/Usage.lean` 运行。

状态更新采用 Lean 的不可变数据方式：`addPolicy` 等函数返回新执行器以及是否发生变更，后续请求使用新执行器。内存更新不会自动写文件。

```lean
-- 在 Except String 中调用：
let (updated, changed) ← enforcer.addPolicy ["bob", "data1", "write"]
let allowed ← updated.enforce ["bob", "data1", "write"]
```

## 已实现的范围

| 部分 | 支持内容 |
| --- | --- |
| 模型 | `.conf` 的请求、策略、角色、效果、matcher；注释、多行续写、自定义字段名 |
| 策略 | `.csv` 加载与保存；双引号、逗号及转义双引号；重复策略去重 |
| 权限 | ACL、RBAC、角色继承、域 / 租户隔离、资源角色、多种角色关系 |
| 效果 | allow override、deny override、allow + deny、普通顺序优先级及整数显式优先级 |
| 表达式 | 字符串 / 布尔值、`==`、`!=`、`&&`、`||`、`!`、括号、`in` 元组或列表、短路求值 |
| 匹配 | `keyMatch`、`keyMatch2`、`keyMatch3`、`keyMatch5`、`regexMatch`、`globMatch`、`ipMatch` |
| 管理 | `getPolicy`、`hasPolicy`、`addPolicy`、`removePolicy`、分组策略增删、直接角色查询、清空和重新加载 |
| 执行 | `enforce`、`enforceEx`、`batchEnforce`、命名策略 / matcher 的 `Context` |
| 扩展 | 构造时注册布尔 matcher 函数；注册角色名称和域匹配函数 |

角色继承默认最多经过 10 条边，带循环的关系能够终止。可以设置 `maxHierarchyDepth`。

普通域默认精确匹配。与本仓库的 Go 版一致，当默认 matcher 对请求和策略的第二个字段使用 `keyMatch(r.<field>, p.<field>)` 时，会自动对三字段角色关系启用域通配符匹配；其他域规则可以调用 `addMatchingFunction` 显式注册。

`Context` 默认选择 `r/p/e/m`。选择第二套定义时，例如：

```lean
enforcer.enforce request { policyType := "p2", effectType := "e2", matcherType := "m2" }
```

matcher 中的变量应属于所选的请求和策略定义。

## 验证与边界

测试读取仓库自带的 [conformance](conformance/README.md) JSON，用 Go 版产生的预期结果比较 Lean 的 `allow` 和 `explain`。当前通过 **29 组、4,318 个请求**。另外有独立回归测试覆盖策略变更、CSV 往返、域隔离、角色循环、优先级、非法输入、命名上下文和自定义函数。

```sh
lake test
# 或指定另一份同格式的参考用例目录：
CASBIN_CONFORMANCE_DIR=/path/to/conformance lake test
```

当前明确跳过 4 组用例：动态 `eval` 一组、条件 / 时间角色一组、`subjectPriority` 两组。相应功能在加载模型时返回错误。新发现的其他用例不会自动跳过。

首版还有这些范围限制：

- 请求值均为字符串；对象属性 ABAC、算术、数值比较和动态 `eval` 尚未实现。
- 时间条件角色、`subjectPriority`、`keyMatch4`、`keyGet` 系列和 Go 的完整 API 尚未实现。
- `regexMatch` 支持普通分组、`|`、`.`、`*`、`+`、`?`、`^`、`$`、字符 / 范围类、转义标点，以及类外的 `\d`、`\w`、`\s` 及其否定形式。计数重复、非贪婪量词、组扩展、词边界、POSIX 类、类内字符类别转义不支持，返回错误。
- `globMatch` 支持 `*`、`**`、`?`、字符类与转义；不支持花括号展开。单个 `*` 和 `?` 不跨越 `/`。
- IP 匹配支持普通 IPv4、IPv6 地址和各自 CIDR。IPv4 与 IPv4-mapped IPv6 之间的跨表示匹配尚未实现。
- 显式 `priority` 必须为整数；非数值优先级返回错误。
- 存储仅提供文本 / 文件读写；数据库适配器、缓存执行器、Watcher、分布式同步、事务和 HTTP 服务尚未实现。

这是程序移植和测试验证，尚未对 Casbin 语义或权限性质做形式化证明。通过当前参考请求不代表完整 Go API 或所有模型已经兼容。

## 代码结构

```text
Casbin/Expression.lean   matcher 的词法和语法解析
Casbin/Model.lean        模型定义与效果解析
Casbin/Policy.lean       CSV 解析、校验与序列化
Casbin/Pattern.lean      路径、正则和 glob 匹配
Casbin/IP.lean           IPv4 / IPv6 与 CIDR
Casbin/Enforcer.lean     权限判断、角色继承和管理 API
Casbin.lean             公共库入口
Main.lean               命令行
Test/Main.lean          回归与 Go 参考用例测试
```

GitHub Actions 在 Linux 和 macOS 构建并运行 Lean 测试及命令行检查。

## 许可证

沿用上游的 [Apache License 2.0](LICENSE)，上游版权和归属信息见 [NOTICE](NOTICE)。

# scripts/kit/ — 常用能力入口（动手前先看这里，别重复造轮子）

> 2026-09-19 立。**为什么**：一场会话里手写 CDP 脚本连烧 4 轮，而 `revisit_check.py` 用的是同一套 CDP
> 且一直是好的 —— 根因是「没先查这个轮子有没有」。本目录只放**经过验证、参数化、可直接调用**的工具。

## 现有工具

| 工具 | 用途 | 例子 |
| --- | --- | --- |
| `cdp_nav.py` | CDP 导航 / 只读标签内容 | `$py scripts/kit/cdp_nav.py --url <URL> --expect <域名片段>` |
| `db_query.py` | 查 / 改 workspace.db | `$py scripts/kit/db_query.py --sql "SELECT ..."`；写要 `--exec "..." --apply` |
| `db_vocab.py` | 字段值域体检 + 安全备份 | `$py scripts/kit/db_vocab.py --enum-only`；备份 `--backup state/workspace.db.bak` |
| `probe.py` | **一次性探测四件套**：HTTP / 排序 md5 签名还原 / 错误信息 oracle / 带 ts 落盘 | 当库用：`sys.path.insert(0,"scripts/kit"); from probe import fetch, save_json, Oracle, sign_sorted_md5`；单发：`$py scripts/kit/probe.py --url <URL> --mobile --out results/x.json` |

| `verdict.py` | **基线闸门**：判读型脚本结论前先验仪器（baseline / appraise / sources_report）；坏了就 UNSURE | `$py scripts/kit/verdict.py --url <URL>`（exit 2 = 仪器不可信）；当库用见文件头 |

### 为什么有 verdict.py（2026-09-21 三次实测损失）

**同一个形状栽了三次**：① 泛解析噪声 -> 「华律 54/56 可达」这种**正常数字**；
② §7 编码规则被泛化 -> 中文乱码；③ 万华 418 封禁 -> 「无注册入口 => 不可得」这种**正常结论**。

**都是「仪器坏了，却报出一个看似正常的结论」。** 对应案例库 P5「结论必须能回答『如果我错了，会看到什么』」——
机制一直写在手册里，但**没变成脚本的默认动作**。verdict.py 就是那个默认动作。

判据边界（写错会让闸门变"狼来了"，比没闸门更糟）：**「一个 200 都没有」且「出现明确拦截码」**才算可疑。
**纯 404 是正常否定结果**，不许报 UNSURE。

### 为什么有 probe.py（2026-09-21 记账）

一场会话里手写了 `_wh1.py`~`_wh49.py` 共 **49 个**一次性脚本，同一段签名逻辑抄 5 遍、fetch 抄 40 遍，
末尾全删 ⇒ **零复用**。四件套固定下来后，"写 5 行就开工"应该成为默认姿势，而不是复制上一轮的文件再改。
**判断标准：如果你正准备复制上一个脚本改参数，先看这里有没有现成的。**

### 脏数据比崩溃更危险（2026-09-19 实录）

`platform` 字段里混着 `butian`(9) 与 `补天`(23) —— 任何 `WHERE platform="butian"` 都会**静默漏掉 23 条**，
不报错、不告警，只是结果少一半。**源头**是 `workspace_db.py` 的 `default="补天"`（代码在持续生产脏数据）。
修法是两段：**先改代码默认值，再 UPDATE 存量**，否则改完又会被写回中文。
（同类排查用 `db_vocab.py --enum-only`：只看值域 <=12 的枚举字段，自由文本字段中英混用是正常的，不报警。）

更全的能力索引：`scripts/archive/INDEX.md`（按能力分组的全部历史脚本，可 grep 参考）。

## 别用 pwsh 全盘递归（2026-09-24 实测卡死）

`Get-ChildItem <dir> -Recurse -Include ...` 对着 `results/` 这种上万文件的目录跑，
在**单次工具调用 30s 上限**内跑不完 ⇒ 整个调用被掐断、拿不到任何结论（本轮真发生了一次）。
⇒ 列目录**只给窄路径**（单目录、单批次）；跨目录找文件用 `tools.glob`（但它在中文工作目录的
`results/` 下会返回空，不可靠）或 `tools.grep` 给窄路径；不要用 pwsh 递归当搜索引擎。

## CDP 的两个坑（2026-09-19 实测）

1. **标签多，别乱 attach**：`/json/list` 常有 20+ 个标签、多个 `about:blank`。
   attach 到**不活跃**的那个 => 导航**静默失效**（URL 停在 about:blank）。
   - 优先用 `--match <域名片段>` 复用**已知业务标签**（登录态也在那边）；
   - 只想读现有页面用 `--no-nav`。
2. **`eval_js` 不抛异常**：JS 出错时返回 `{"__error__": ...}`。
   **不检查返回值 = 静默吞错**（这就是我烧掉 3 轮的地方）。本目录模板已内置上报。

## 数据文件约定（2026-09-19 立，治"跑出来的数据没人看得见"）

`scripts/next.py` 开场会**自动扫 `state/*.json`** 列出「条数 + 多少天没更新」，
并检测「resume.md 比数据集旧」→ 提示补跑 checkpoint。**不需要任何人维护这张表。**

- **别给已有的 `{id: {...}}` 结构硬塞 `_meta` 键** —— 读它的脚本会把 `_meta` 当成一条记录。
- **新写的数据文件建议自带**（next.py 会显示 `how`，下次就知道怎么更新）：
  `{"_meta": {"updated": "2026-09-19", "count": 242, "how": "gongyi_scope_batch.py"}, ...}`
- 看到「全集 N / 已跑 M」不一致（如 247 vs 242）就是**没跑完**，续跑而不是重跑。

## 探针关键词设计（2026-09-19 两例假阳性教训）

往 `arsenal.py` 的 `PROBES` / `JS_KEYWORDS` 加词时，**只放三类**，放错必出幻影目标：

| 该放 | 例 |
| --- | --- |
| **通用参数名** | `downloadUrl` / `fileUrl` / `previewUrl` / `remoteUrl` / `imageUrl` / `callbackUrl` |
| **响应特征串** | `ListBucketResult` / `hudson.model.Hudson` / `project_id` / `_links` |
| **固定路径** | `/.git/config` / `/actuator/env` / `/api/v2.0/projects` |

**不该放（实测各误报一次）**：

- **通用前端 API 名**：`uploadimage`（layui/UEditor 都有 `uploadImage`）、`description`（HTML 属性名）
  —— 命中一堆无关页面，会让人去挖不存在的洞。
- **产品专属词**：`onlinefile` / `getFileByHttp` 是永中特有的 —— 那属于**载体地图**，不属于手法探针。
  手法探针要能在**任意目标**上跑；产品词写进探针 = 换一家就失效。

**判据一句话**：这个词在「**跟漏洞无关的正常网站**」上会不会出现？会 → 不能放。

## 写新脚本时的规矩（一场会话炸 5 次的教训）

1. **先查现成的**：本 README -> `archive/INDEX.md` -> `arsenal.py board`。
2. **必须新写时，从模板 `Copy-Item` 再改参数** —— 复制文件**不经过字符串转义**，比从零写安全得多。
3. **长文本传输**（在 run_code 里构造 Python/markdown）：
   - **绝不用模板字符串写含反引号的内容**（markdown、代码块必炸）；
   - 长文本一律**数组 join**，元素用单引号；内容里的 ASCII 单引号改中文引号「」；
   - 内容含 `${` 时**绝不用模板字符串**（会被当成插值）。
4. **写完先冒烟**：`--help` 或 `--tables` 跑一次，再进业务逻辑。TS 层过了不代表 Python 层对。
   **反例（2026-09-19 实录）**：为了躲 ASCII 单引号，把 SQL 的 `type='table'` 硬写成 `chr(116)||chr(97)...`，
   结果 SQLite 没有 `chr` 函数直接报错 —— **转义恐惧会写出次生 bug，比转义本身更贵**。
   正确做法是换定界符（TS 那层用双引号包，内部就能自由用单引号），不是把代码写歪。
5. **静默失败要显式检查**：外部调用的返回值先判 `__error__` / `errorText` / 退出码。

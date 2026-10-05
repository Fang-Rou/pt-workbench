# -*- coding: utf-8 -*-
"""playbook_hint.py — **信号 → 该读哪本手册** 的路由表（2026-09-17 立）。

为什么要有它（用户口径：沉淀必须落到「会自己触发」的位置）：
  playbook_lookup.py 解决的是「我主动去查」，但**新手侦察完不会主动查** ——
  脚本跑出一堆 hostname，人不会拿它去 lookup。于是知识在场却没人读。
  本模块把「信号」直接翻译成「该读的手册 + 下一步动作」，供侦察脚本内联调用。

与 playbook_lookup.py 的分工：
  · playbook_hint = 信号驱动、**被动触发**（侦察输出里出现特征就提示），不记 LEDGER；
  · playbook_lookup = 人/预检主动查询、记 LEDGER（"被用过"的证据）。
  两者指向**同一批 references/ 文档**，口径以 playbook_lookup 的目录级 glob 为准。

用法：
  python scripts/playbook_hint.py --text "harbor.corp.com /api/v2.0/projects"
  python scripts/playbook_hint.py --file results/recon-xxx/subs.txt
  from playbook_hint import hints_for; print("\n".join(hints_for(text)))
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
S = "skills/pt-engagement/references"
P = "skills/product-playbooks/references"

# (信号名, 正则, [(该读的文档, 说明)], 下一步动作)
SIGNALS: list[tuple[str, str, list[tuple[str, str]], str]] = [
    ("Spring Boot Actuator / 微服务端点暴露",
     r"actuator|heapdump|/jolokia|/env\b|/metrics\b|spring-boot",
     [(f"{S}/hit-case-library-2026.md", "§4 多环境暴露 + §33 Actuator 纵深三级跳")],
     "metrics 路由标签 → 顺标签找后端微服务 actuator → heapdump/env 提数据库与中间件明文凭据（三级跳），"
     "凭据必须**实测能连**才算数；只报'端点暴露'会被判理论风险。"),
    ("Harbor / 容器镜像仓",
     r"harbor|/api/v2\.0/projects|registry",
     [(f"{S}/playbook-harbor-anon.md", "Harbor 匿名枚举→拉层→提凭据全链"),
      (f"{S}/hit-case-library-2026.md", "§30 该面已饱和（两连判重且仍未修）")],
     "匿名 /api/v2.0/projects 读 metadata.public → 枚举仓库名（=内部系统清单）→ /service/token 无凭据换 JWT "
     "→ 拉 manifest 逐层下载 → 层内配置提凭据 → **凭据实测读生产数据**。层过滤别丢 <20KB 的小层。"
     "动手前先站内查重（该面重复率极高）。"),
    ("Nexus / 内部制品仓",
     r"nexus|/repository/|maven|npm\s*私服",
     [(f"{P}/nexus-artifact-repo.md", "Nexus 匿名读/写与 OPTIONS 定性法")],
     "匿名列举仓库 → 用 OPTIONS/Allow 头定性写权限（Allow: GET,HEAD,PUT,DELETE = 可写）→ "
     "上传恶意产物主张供应链投毒。先判厂商类型排序投入（内部产物 > 三方镜像）。"),
    ("对象存储桶 / 上传凭据签发（STS/uploadToken）",
     r"oss-|\.oss-|cos\.ap-|myqcloud|qiniu|bos\.|s3\.|bucket|uploadToken|getUploadToken|ossToken|\bsts\b",
     [(f"{S}/playbook-oss-anon.md", "OSS/COS/七牛/BOS 匿名写→供应链投毒"),
      (f"{S}/hit-case-library-2026.md", "§2 分发桶匿名写删 + §7/§28 上传凭据签发面")],
     "桶：随机命名标记对象 → PUT/DELETE 取证 → 立即删除并 HEAD 复验 404；"
     "主张必须落在**覆盖既有生产资产**（安装包/官网 JS/Logo），"
     "审核员明确'对象存储不执行服务端代码' ⇒ 钓鱼/资源消耗说辞=理论风险。"
     "该面重复率极高，**先站内查重再动手**；同厂商多变体合并成一单。"),
    (".git 泄露 / 源码仓库凭据",
     r"\.git/|git\s*config|codeup|gitlab|gitea",
     [(f"{S}/hit-case-library-2026.md", "§3 .git→托管仓库凭据→真实克隆")],
     "读 .git/config 提仓库凭据 → **真克隆成功**才算闭环（'文件里有凭据'会被判'影响不大'）；"
     "同时把 9 台测试环境同源问题合并成一单。"),
    ("前端 JS bundle / 接口与密钥挖掘",
     r"main\..*\.js|webpack|chunk|app\.js|sourceMappingURL|swagger|v2/api-docs|openapi",
     [(f"{S}/playbook-js-api-unauth.md", "bundle 挖 API→未授权敏感数据")],
     "拆 bundle 提 API 路径与硬编码密钥 → **直连判活**（网关密钥要复算签名证明可用，"
     "不是'密钥在前端'）；未授权接口要读到**真实敏感数据**再报。"),
    ("YApi 接口管理平台",
     r"yapi",
     [(f"{P}/yapi.md", "YApi 开放注册→管理员垂直越权/Mock RCE")],
     "判开放注册 → 注册后试管理员接口垂直越权（用户列表等）→ 敏感度不够再走 Mock 脚本 RCE。"),
    ("金蝶系（星空/苍穹/灵基）",
     r"kingdee|kdcloud|kdgalaxy|苍穹|云星空|灵基",
     [(f"{P}/kingdee-cloud.md", "金蝶资产/接口/鉴权实测记录")],
     "统一身份收束 ⇒ 先做资产测绘与接口清单，BOS 表单引擎鉴权已实测（见 §8），别重复投入。"),
    ("若依 RuoYi 系",
     r"ruoyi|/prod-api|ry-ui|若依",
     [(f"{P}/ruoyi.md", "RuoYi 指纹→候选链"),
      ("skills/ruoyi-audit/SKILL.md", "二开审计 checklist")],
     "指纹确认 → 按 checklist 走权限/数据范围/匿名白名单/文件存储/定时任务/云信任边界六类候选链。"),
    ("测试/预发环境（多环境暴露）",
     r"^(test|testing|dev|uat|stage|staging|pre|sit|demo|beta|sandbox|qa|gray)\.",
     [(f"{S}/hit-case-library-2026.md", "§4 Actuator 多环境暴露")],
     "测试环境常伴弱鉴权/调试端点/默认口令；**但别按名字预判价值**"
     "（实测 251 个子域里名字带 Harbor/Zabbix 的 224 台已死）——必须 DNS+HTTP 实测存活。"),
    ("运维面板 / CI（Jenkins/Grafana/Nacos/宝塔…）",
     r"jenkins|grafana|zabbix|kibana|sentry|prometheus|nacos|druid|adminer|jumpserver|rancher|apollo",
     [(f"{S}/hit-case-library-2026.md", "§13/§14 测量层纪律 + 制品仓挖掘")],
     "未授权访问先判**能读到什么真实数据**（targets/config/query 只读即可，别爆破）；"
     "面板里泄露的内网地址可做横向资产测绘。"),
    ("App/小程序 Hybrid 桥与深链",
     r"jsbridge|deeplink|webview|小程序",
     [("skills/mobile-iot-device-security/references/c-end-android-runbook.md", "C 端 Android 全流程"),
      (f"{S}/hit-case-library-2026.md", "§26 桥白名单 ⊗ 用户可控内容域")],
     "查桥的主机白名单 → 白名单域上是否有**用户可控内容面**（上传/UGC/CDN）→ 内容装载后桥是否交出凭据。"
     "注意项目公告口径（乐橙案例：客户端漏洞不收取）。"),
]


def hints_for(text: str, limit: int = 6) -> list[str]:
    """返回该文本命中的信号提示行（无命中则空列表）。"""
    low = text.lower()
    out: list[str] = []
    for name, rx, docs, action in SIGNALS:
        m = re.search(rx, low, flags=re.M)
        if not m:
            continue
        out.append("[信号] %s（命中: %s）" % (name, m.group(0)[:40]))
        for doc, note in docs:
            mark = "  ✓" if (ROOT / doc).exists() else "  ✗(文档缺失!)"
            out.append("%s %s —— %s" % (mark, doc, note))
        out.append("   → 下一步：%s" % action)
        if len(out) >= limit * 6:
            break
    return out


def main() -> int:
    # 编码：被管道/工具捕获(pytest、harness、重定向)时用 UTF-8；交互终端跟随控制台代码页。
    # （2026-09-14 教训：硬写 utf-8 会在 chcp 936 控制台里输出乱码毁掉证据图；
    #   2026-09-17 反向教训：只跟随代码页又会让被捕获的输出在 UTF-8 侧解码成乱码。二者按 isatty 分流。）
    if sys.stdout.isatty():
        sys.stdout.reconfigure(errors="replace")
    else:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    text = ""
    if "--text" in sys.argv:
        text = sys.argv[sys.argv.index("--text") + 1]
    elif "--file" in sys.argv:
        text = Path(sys.argv[sys.argv.index("--file") + 1]).read_text("utf-8", "ignore")
    else:
        text = sys.stdin.read()
    hits = hints_for(text)
    if not hits:
        print("（无信号命中 —— 按新面处理；仍建议先跑 playbook_lookup.py <词1> <词2> <词3>）")
        return 0
    print("# 信号 → 该读的手册（playbook_hint）")
    print("\n".join(hits))
    print("\n提示：读完请回填 python scripts/playbook_lookup.py --outcome hit|miss|partial --detail \"…\"")
    return 0


if __name__ == "__main__":
    sys.exit(main())

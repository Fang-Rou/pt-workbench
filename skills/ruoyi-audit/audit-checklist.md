# RuoYi 系二开审计 checklist（授权验证用）

> 用法：命中指纹后按「先无害探测 → 最小影响验证 → 证据 → 提交」执行。
> 红线：不爆破、不遍历越权数据、不碰真实用户数据；L1 实际影响 + L2 窗口级截图 + L3 表单齐全才提交。

## 0. 命中后先确认
- [ ] 厂商在补天公益清单且目标在其范围（gongyi-domains/surface 文件 /但天公司页）
- [ ] 版本识别：ry-ui.js?v=、接口形态、swagger/druid 是否可达
- [ ] 注册页存在？POST /register 探测服务端开关（页面存在≠功能开放）
- [ ] 公开 CVE 种子先查 vuln-catalog.json + 平台收录状态

## A. 权限/角色边界（种子 CVE-2024-57438 补丁差分）
- [ ] 注册/低权账号可访问哪些菜单与接口（对比 admin 路由表）
- [ ] 角色分配接口是否存在校验（能否把自己加进高权角色）
- [ ] 按钮级隐藏是否仅前端（直接调接口看后端校验）
- [ ] cancelAll 类批量操作接口的授权校验

## B. 数据权限/租户隔离
- [ ] 列表类接口是否带 @DataScope（user/list, role/list, 业务 list）
- [ ] 传 deptId/companyId 换值看数据范围是否变化（两账号互测）
- [ ] 二开 service 是否绕过统一查询层直查 mapper

## C. 匿名白名单
- [ ] /register /captcha/** /swagger /druid /actuator /common/download 匿名可达性
- [ ] **★ 外部集成接口命名空间（2026-09-21 新增，首个已验证链，见 product-playbooks/references/ruoyi.md §3 链 G）**：
      二开常把「外部系统对接」控制器挂在 `/api/**`（如 `user-sync` / `callback` / `picking` / `writeBack`），
      **这类控制器最容易漏配鉴权**。动作：先 `GET /v2/api-docs` 拿地图 → 找出 `*-api-controller` 这类 tag →
      **用兄弟命名空间做对照**（一个命名空间 401、另一个不拦 ＝ 漏配的实证）→
      写/删接口**只用「GET 打 POST/DELETE 路由」判鉴权，绝不用真实方法调用**。
      读接口注意两点：可能返回 `password` 字段（拿到也**严禁登录**）；报错回显可能吐完整 SQL/Mapper/构件路径（当附加证据，别当主洞）。
- [ ] 下载/通用接口是否真匿名（无 token 直连验证 + 真实文件读取确认）
- [ ] 二开新加的 anon/permitAll 路由清单（对比上游默认）

## D. 文件与对象存储
- [ ] /profile/** 上传目录静态映射；路径穿越（../）与任意下载
- [ ] 上传类型白名单/落地可执行；OSS 临时凭据（sts）权限范围
- [ ] 导出的 Excel/CSV 公式注入边界

## E. 定时任务/监控
- [ ] 任务管理接口可达性与调用目标校验（仅限授权站内自建任务测试）
- [ ] 在线用户/日志接口信息越权

## F. Cloud 信任边界（RuoYi-Cloud 家族）
- [ ] 网关与下游鉴权是否一致（直连下游端口尝试）
- [ ] Feign 内部接口外露、服务间信任头可伪造

## 证据与收尾
- [ ] 原始请求/响应落盘（results/<slug>/），窗口级浏览器截图含归属
- [ ] L0 去重 `scripts/submission_dedupe_check.py`
- [ ] 报告落 `_交付/<slug>/`（模板见 skills/pt-engagement/references/src-report-template.md）
- [ ] delta 回写：ruoyi.md 案例索引 + research-track + 本目录资产

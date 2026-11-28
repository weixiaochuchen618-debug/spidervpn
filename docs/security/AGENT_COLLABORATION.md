# SpiderVPN 多 Agent 协作规约
- 生效：2026-11-18（Asia/Singapore）；维护者 COORD-01。GitHub 唯一权威，本文仅管理协作，不替代 REMEDIATION_BACKLOG.md 的缺陷状态和 SECURITY_REMEDIATION_PLAN.md 的 DoD。
- 必读：[交接](AGENT_HANDOFF.md)、[账本](REMEDIATION_BACKLOG.md)、[技术方案](SECURITY_REMEDIATION_PLAN.md)、[任务分配](TASK_ASSIGNMENTS.md)。文档专用分支 `docs/security-remediation-handoff-20261117`，既有 PR #4；不得直接提交 main。
## 1. 权限与独占
| Agent | 权限 |
|---|---|
| COORD-01 | 唯一分配/撤销任务、锁定基准 SHA/范围、全局文档和合并管理者；完整验收且用户明确授权后才组织合并 |
| DEV-01 | 只在任务表指明的分支与文件范围内开发；不得抢占或改别的 Agent 分支 |
| DEV-02 | 同上，独立 WFP 线；不能写 DEV-01 分支 |
| REVIEW-01 | 独立只读 checkout、测试、PR review/Issue 评论，不提交业务代码，不修改开发分支，不自行合并 |
Agent ID 是逻辑角色而非 GitHub 用户名/服务账号；不冒用账号或伪造独立 review。共享账号无法提交独立批准时证据记录在 PR comment，标注角色和限制，不能当正式独立账号批准。
## 2. 恢复与锁
每次“继续推进”先读取任务表、Issue/PR、最新分支 SHA、compare、CI/日志；先检查是否有未交接 commit、其他写入者、是否已认领和允许范围。开始前在对应 PR/Issue 记录 [Agent ID][任务号]、基准、当前 HEAD、范围、预计验收；活动分支锁由总控分配。HEAD 意外移动即停止写入，报总控；禁止 force push/rebase 共享祖先、覆盖现有代码、擅自 cherry-pick、移动其他 Agent ref。原串行执行者仍写入的分支仅允许读，交接完成、总控重新锁定 SHA 后方可独占写。不得仅凭聊天声称执行。
## 3. 开发与验收
Rust 实现新增逻辑；PowerShell 仅薄包装。保持 UI、用户连接交互、WFP 持久 BLOCK、默认关闭的实验功能，未经授权不启用、不改真实 VPS/Windows。不得为了 CI 绿删除或跳过失败测试、弱化断言、加无关重构。适用 MSVC/GNU/Linux 严格构建、专项目标及完整 CI；必须列出实际命令、失败/修复、旧版复现→候选回归、commit SHA、Run ID、job/原始日志、限制和实机材料。保留既有环境依赖排除记录，不增加 skip。CI 成功≠真实安全验收；缺实际环境则标 BLOCKED_REAL_ACCEPTANCE，继续不受影响任务。PR 保持 Draft 直至所有 DoD。不得在生产 VPS 使用隔离 CI fixture。
## 4. 依赖与合并
PR #6→#7...#28 是历史堆叠链，不重写/拆散祖先；新分支基于实际依赖，PR base 指向直接父分支。#3 独立于该链但有共享文件，生产集成保留给 COORD-01 单独安排。共享文件/CI/接口修改须总控先显式解锁。依赖没满足不降低门槛，不强拆。评审以指定 SHA；任何新提交使旧签核不再覆盖新 HEAD。合并前总控重核 main/HEAD、依赖顺序、差异、准确 CI、真实验收与明确用户授权；不启用 auto-merge，不直接提交 main。
## 5. 状态和证据
REMEDIATION_BACKLOG 为缺陷唯一账本，TASK_ASSIGNMENTS 为任务所有权/锁/恢复点唯一表。原交接与历史证据保持原样；仅 COORD-01 可更新三份全局文档和任务表。DEV 与 REVIEW 在各自 Issue/PR 留进展、证据与阻塞；不要改全局文档。状态：QUEUED、ACTIVE、HANDOFF_BLOCKED、REVIEW_PENDING、BLOCKED_REAL_ACCEPTANCE、VERIFIED（全部 DoD，尚未合并）、MERGED（实际 GitHub merged SHA）。每个可验证阶段即记录，不用聊天记忆充当事实。Review 报告 PASS/PARTIAL/FAIL/BLOCKED，列出实际范围、攻击负例、缺失证据；未运行的测试明确 NOT RUN。无独立任务时保持空闲。

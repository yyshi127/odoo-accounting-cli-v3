# Dev29 真实 Odoo 只读证据门

本目录提供 Odoo Accounting CLI V3 的 Dev29 真实 Odoo 只读验证链。它是旁路验证设施，不替换 V2，不执行会计写入，也不授权生产切换。当前所有成功报告和耐久锚点都固定包含 `production_promotion_allowed=false`。

## 安全边界

- 整个生命周期只使用一个由 `systemd-run` 创建的 transient service；禁止嵌套 systemd unit。
- supervisor 必须由 `/usr/bin/python3.12 -I -S` 运行，并从已安装、只读且完整复核的唯一 release 目录加载代码。
- Odoo、签名、PostgreSQL witness 和独立 verifier 是同一 unit 内的直接子进程；身份、公司、挂载、能力集、进程组和 cgroup 都进入证据。
- `systemd-run` 和 `systemctl` 不采用“先 hash、再按路径重新打开”的执行方式。执行文件以 `O_NOFOLLOW` 打开并保持 fd，随后从 `/proc/self/fd/<fd>` 执行；exec-stop 时再用 `/proc/<pid>/exe` 核对 device/inode，执行前后 metadata 漂移均拒绝。
- 固定程序在 exec-stop 窗口设置 `PTRACE_O_EXITKILL`，核对实际执行 inode 后才 detach；detach 失败、异步异常或超时都会无条件发送 `SIGKILL` 并强制 reap，无法确认 reap 时整次运行拒绝。执行证明固定包含 `ptrace_exitkill_set`、`ptrace_exec_stop_verified`、`ptrace_detached_before_communicate` 和 `child_reaped`，且四项都必须为 `true`。
- 外层 `systemd-run --wait` 的本地等待上限固定为 3690 秒，高于 unit 的 `RuntimeMaxSec=3600s` 加 `TimeoutStopSec=30s`，但不会无限等待。
- 最终 publisher 不再按 release 路径重新打开解释器或脚本：system Python 和 manifest 指定的 publisher SHA-256 都以 `O_NOFOLLOW` fd 固定并在 exec 前最后重哈希；Python 使用 descriptor exec，publisher 只通过继承的 `/proc/self/fd/<fd>` 读取。最后复核前的路径替换会拒绝，复核后的路径替换也不能改变已固定 inode。
- 独立 verifier 的 `/usr/sbin/ldconfig.real -p` 同样绑定外部提供的 `--expected-ldconfig-sha256`，从已核验 fd 执行，并在执行后重验同一 fd 的 identity、SHA-256 与路径 inode；超时固定为 30 秒且 stdin 关闭。
- 独立 verifier 会实时重新查询 transient unit 的完整 properties；最终 publisher 在能力集全部清零后再次独立查询并比对。
- 写操作和生产账套写入不在本门范围内。不得用本门的通过结果替代写状态机、审批、幂等、冲销或生产安全验证。

## 前置条件

1. 使用 `deployment/install-release.py` 安装 canonical package。release、package、release manifest 与 trusted-artifact anchor 必须相互一致；不得从开发目录直接运行。
2. 准备专用沙箱账套和 release-bound runtime：
   `/etc/odoo-accounting-cli-v3/candidates/runtime-test-<release>.json`。
3. 下列目录必须预先存在并满足精确 owner/mode：

   - `/var/lib/odoo-accounting-cli-v3/evidence`：`root:root 0755`
   - `/var/lib/odoo-accounting-cli-v3/evidence-anchors`：`root:root 0755`
   - candidate `auth`、`receipt` 目录：`odoo:odoo 0700`
   - `/var/lib/odoo-accounting-cli-v3-broker`：`odoo:odoo 0700`
   - `/run/odoo-accounting-cli-v3-dev29`：`root:root 0700`
   - `/run/odoo-accounting-cli-v3-dev29-leases`：`root:root 0700`

   使用 exact release member
   `deployment/dev29/systemd/odoo-accounting-cli-v3-dev29-tmpfiles.conf`
   安装 `/etc/tmpfiles.d/odoo-accounting-cli-v3-dev29.conf` 并执行
   `systemd-tmpfiles --create`；`runtime_setup.py` 会再次独立验证以上共享目录。

4. 所有 `--expected-*` 值都必须来自运行外部的受信发布清单或经批准的主机基线，不能由本次运行临时读取后自我认可。至少保存以下来源和审批记录：release/version/commit、release manifest、package、能力注册表、closure anchor/image、runtime-open policy/index、system Python、`ld.so.preload`、`ldconfig.real`、`systemd-run`、`systemctl` 和 `strace` 的 SHA-256。
5. 未取得明确生产写授权时，只能指向专用沙箱。此套件本身也不会执行生产写入。

## 启动真实只读套件

以下变量仅用于缩短示例；其值必须从受信外部记录填写：

```sh
RELEASE='0.1.0.dev36-<commit12>'
EVIDENCE_NAME='dev29-<unique-run-id>'
RUNNER="/opt/odoo-accounting-cli-v3/releases/${RELEASE}/deployment/dev29/run_read_evidence.py"
```

启动命令：

```sh
sudo /usr/bin/python3.12 -I -S "$RUNNER" launch \
  --evidence-name "$EVIDENCE_NAME" \
  --expected-release "$RELEASE" \
  --expected-version '<version>' \
  --expected-commit '<40-lowercase-hex>' \
  --expected-manifest-sha256 '<64-lowercase-hex>' \
  --expected-package-sha256 '<64-lowercase-hex>' \
  --expected-closure-anchor-sha256 '<64-lowercase-hex>' \
  --expected-closure-image-sha256 '<64-lowercase-hex>' \
  --expected-system-python-sha256 '<64-lowercase-hex>' \
  --expected-ld-so-preload-sha256 '<64-lowercase-hex>' \
  --expected-ldconfig-sha256 '<64-lowercase-hex>' \
  --expected-systemd-run-sha256 '<64-lowercase-hex>' \
  --expected-systemctl-sha256 '<64-lowercase-hex>' \
  --expected-strace-sha256 '<64-lowercase-hex>' \
  --expected-runtime-open-index-sha256 '<64-lowercase-hex>' \
  --expected-registry-digest '<64-lowercase-hex>'
```

`supervise` 和 `recover-supervise` 是 transient unit 的内部动作，不是人工入口。不要直接调用。

## 证据、回执与成功语义

一次完整运行产生：

- 冻结证据包：`/var/lib/odoo-accounting-cli-v3/evidence/<evidence-name>/`
- bundle manifest：证据包内 `BUNDLE-MANIFEST.json`
- 耐久验证锚点：`/var/lib/odoo-accounting-cli-v3/evidence-anchors/<evidence-name>.json`
- 仅在发布期间使用的 root-only staging：`/run/odoo-accounting-cli-v3-dev29/<evidence-name>/`

只有下列条件同时成立，才能报告“本次只读验证通过”：真实 Odoo 返回、财税 Oracle、负向拒绝、SQLite 状态增量、审计哈希链、独立 verifier、closure 清理、publisher 实时复核以及耐久锚点全部通过。没有真实 Odoo 回执或没有耐久锚点时，不得报告业务成功。

即使锚点存在，也只表示该 Dev29 只读证据包通过；它不表示生产写能力已开放，也不表示 V3 已完成生产切换。

## 状态查询

状态查询使用与 launch 相同的 common 参数，并额外绑定外部保存的 bundle manifest SHA-256：

```sh
sudo /usr/bin/python3.12 -I -S "$RUNNER" status \
  --evidence-name "$EVIDENCE_NAME" \
  --expected-bundle-manifest-sha256 '<64-lowercase-hex>' \
  --expected-release "$RELEASE" \
  --expected-version '<version>' \
  --expected-commit '<40-lowercase-hex>' \
  --expected-manifest-sha256 '<64-lowercase-hex>' \
  --expected-package-sha256 '<64-lowercase-hex>' \
  --expected-closure-anchor-sha256 '<64-lowercase-hex>' \
  --expected-closure-image-sha256 '<64-lowercase-hex>' \
  --expected-system-python-sha256 '<64-lowercase-hex>' \
  --expected-ld-so-preload-sha256 '<64-lowercase-hex>' \
  --expected-ldconfig-sha256 '<64-lowercase-hex>' \
  --expected-systemd-run-sha256 '<64-lowercase-hex>' \
  --expected-systemctl-sha256 '<64-lowercase-hex>' \
  --expected-strace-sha256 '<64-lowercase-hex>' \
  --expected-runtime-open-index-sha256 '<64-lowercase-hex>' \
  --expected-registry-digest '<64-lowercase-hex>'
```

关键状态：

- `complete`：耐久锚点已独立验证，staging 已清除。
- `durable_anchor_cleanup_pending`：锚点已耐久提交，但 staging 清理被中断，可执行 recover。
- `durable_pending_commit_recoverable`：完整的 mode `0400` pending 与六个 staging 文档均已耐久化，但 final commit 被中断；可执行 recover。
- `prepublication_failed_or_running`：有 staging、无锚点；保留现场，不能以 recover 删除。
- `unanchored_evidence`：有证据、无锚点；不得报告成功。
- `absent`：没有该运行身份。

所有状态输出仍固定 `production_promotion_allowed=false`。

`status` 对 final anchor 和 durable pending anchor 使用同一套校验参数；两条路径都会显式传递本次外部提供的 `--expected-ldconfig-sha256`，摘要缺失或与 supervisor bootstrap 不一致时拒绝状态验证。

## 崩溃恢复

仅当 `status` 返回 `durable_anchor_cleanup_pending` 或 `durable_pending_commit_recoverable` 时运行：

```sh
sudo /usr/bin/python3.12 -I -S "$RUNNER" recover \
  --evidence-name "$EVIDENCE_NAME" \
  --expected-bundle-manifest-sha256 '<64-lowercase-hex>' \
  --expected-release "$RELEASE" \
  --expected-version '<version>' \
  --expected-commit '<40-lowercase-hex>' \
  --expected-manifest-sha256 '<64-lowercase-hex>' \
  --expected-package-sha256 '<64-lowercase-hex>' \
  --expected-closure-anchor-sha256 '<64-lowercase-hex>' \
  --expected-closure-image-sha256 '<64-lowercase-hex>' \
  --expected-system-python-sha256 '<64-lowercase-hex>' \
  --expected-ld-so-preload-sha256 '<64-lowercase-hex>' \
  --expected-ldconfig-sha256 '<64-lowercase-hex>' \
  --expected-systemd-run-sha256 '<64-lowercase-hex>' \
  --expected-systemctl-sha256 '<64-lowercase-hex>' \
  --expected-strace-sha256 '<64-lowercase-hex>' \
  --expected-runtime-open-index-sha256 '<64-lowercase-hex>' \
  --expected-registry-digest '<64-lowercase-hex>'
```

recover 会重新进入同等级硬化 transient unit，验证唯一 release、外部 bundle digest 和现有只读锚点，清除 staging 中剩余的 0 到 6 个精确文件。锚点不匹配、stage 出现未知文件、symlink、owner/mode/nlink 漂移时全部拒绝并保留现场。

原子发布规则：

- 固定 pending 文件为 `.<anchor>.pending`，并由 `.<anchor>.lock` 串行化。
- mode `0600` 的不完整 pending 不可恢复，会先安全删除再完整重建。
- mode `0400` 的完整 pending 会通过同一 fd 读取、`fsync`、稳定性复核，并与保留的六个 staging 文档逐项比对。恢复进程重新验证当前 recovery unit、cgroup、systemctl properties、closure 清理和冻结证据后，生成绑定当前恢复执行身份的新 payload，通过独立 recovery pending 以 `renameat2(RENAME_NOREPLACE)` 提交；原 pending 在 final anchor 耐久化前不会删除。
- 一旦 final anchor 已提交，后续异常绝不删除它；相同内容重试是幂等的，不同内容重试拒绝。
- closure loop 使用 `AUTOCLEAR`，publisher 还会按 backing device/inode 验证清理。若在提交前被强杀且没有锚点，必须保留证据并诊断，不能手工伪造锚点。

## 测试门槛

开发机聚焦回归：

```sh
python -m pytest -q \
  tests/test_dev29_run_read_evidence.py \
  tests/test_dev29_publish_read_evidence.py \
  tests/test_dev29_verify_read_evidence.py \
  tests/test_dev29_read_suite.py \
  tests/test_dev29_read_oracles.py \
  tests/test_dev29_odoo_closure.py \
  tests/test_dev29_runtime_open_trace.py \
  tests/test_dev29_runtime_open_policy_source.py \
  tests/test_dev29_runtime_setup.py
```

Linux/root 门必须生成 JUnit，并且上述 Linux-only 的 ptrace、路径替换、fork/SIGKILL、flock、文件 fsync 和 `renameat2` 用例不得 skip：

```sh
sudo -E python -m pytest -q \
  tests/test_dev29_run_read_evidence.py \
  tests/test_dev29_publish_read_evidence.py \
  tests/test_dev29_runtime_open_trace.py \
  tests/test_dev29_read_suite.py \
  tests/test_dev29_runtime_open_policy_source.py \
  tests/test_dev29_unit_lease_systemd.py \
  --junitxml=artifacts/dev29-linux-lifecycle.xml
```

随后必须在目标服务器的专用沙箱执行完整 launch，保存 systemd unit properties、bundle、真实 Odoo 回执、独立 verifier 报告、cleanup receipt 和 final anchor。仅有单元测试、模拟输出或命令存在不能通过此门。

## 当前未解除门槛

- suite、独立验证器与 publisher 都会从安装的 index 和全部 32 份 canonical manifest 独立重构 runtime-open policy source 摘要，并把验证器字节绑定到原始 release manifest 的唯一成员；这些校验已进入代码与 CI 门。目标 Linux/root 完整运行回执仍未取得，在该证据完成前不得开启生产 promotion。
- 本文档描述的是只读证据链，不包含生产会计写入授权。任何写能力仍须通过沙箱创建、重复请求、失败、验证和冲销闭环后逐项开放。
- 升级和回滚继续遵循仓库根目录的 `docs/DEPLOYMENT.md`；不得覆盖 V2 或从开发目录直接替换 canonical release。

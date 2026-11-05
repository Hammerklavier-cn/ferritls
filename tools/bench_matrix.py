#!/usr/bin/env python3
"""跨后端 × OpenSSL 对照矩阵的编排与报告工具（BENCHMARKS.md §8）。

依次驱动 `openssl_matrix` 基准的两条腿并在每腿后解析 criterion 落盘，
聚合出 Markdown 报告：

- 腿 A：`--no-default-features` → ferritls-标量 + openssl 锚点；
- 腿 B：默认构建 → ferritls-simd + ferritls-simd+Ni（组间安装桥）+ openssl 锚点。

标量与 simd 是编译期 feature、无法同进程共存，故分两腿；simd 与 simd+Ni
同进程先后测（直接可比），跨腿比较一律经「对本腿 openssl 锚点的比值」
归一（§3 同机同会话纪律的延伸）。两条腿共用案例名，criterion 目录
（target/criterion/matrix-*）即数据源——脚本解析 estimates.json
（criterion 0.8 的内部格式，非官方 API，格式漂移即显式报错）。

用法:
    python3 tools/bench_matrix.py                    # 全量（默认 criterion 档，约 20 分钟）
    python3 tools/bench_matrix.py --quick            # 冒烟档（统计强度降低）
    python3 tools/bench_matrix.py --out report.md    # 报告写文件（默认打印到 stdout）
    python3 tools/bench_matrix.py --extra "--sample-size 50"   # 透传 criterion 参数
    python3 tools/bench_matrix.py --skip-run         # 只解析已有 criterion 数据再出报告
"""
import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRITERION = ROOT / "target" / "criterion"

FAMILIES = ["aead", "hash", "ecdh", "sign"]
# 与 benches/openssl_matrix.rs 的案例登记严格同步（改 bench 必须同步这里）。
CASES = {
    "aead": [
        ("gcm128-seal", True), ("gcm128-open", True),
        ("gcm256-seal", True), ("gcm256-open", True),
        ("ccm128-seal", True), ("ccm128-open", True),
        ("chacha20poly1305-seal", True), ("chacha20poly1305-open", True),
    ],
    "hash": [
        ("sha256-stream", True), ("sha512-stream", True),
        ("hmac-sha256-1350", False),
        ("hkdf-sha256-extract", False), ("hkdf-sha256-expand-64", False),
    ],
    "ecdh": [("x25519-dh", False), ("p256-dh", False)],
    "sign": [
        ("ecdsa-p256-sign", False), ("ecdsa-p256-verify", False),
        ("ed25519-sign", False), ("ed25519-verify", False),
        ("rsa2048-pkcs1v15-sign", False), ("rsa2048-pkcs1v15-verify", False),
        ("rsa2048-pss-sign", False), ("rsa2048-pss-verify", False),
    ],
}
SIZES = [1350, 16384]
BACKENDS = ["ferritls-scalar", "ferritls-simd", "ferritls-simd-ni", "openssl"]
# 腿 A 只产出前两者（无安装桥）；腿 B 产出后三者。
LEG_A_BACKENDS = {"ferritls-scalar", "openssl"}
LEG_B_BACKENDS = {"ferritls-simd", "ferritls-simd-ni", "openssl"}

META_RE = re.compile(r"^FERRITLS_MATRIX_META\s+(.*)$", re.M)
KV_RE = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")
# HMAC 案例的吞吐按 1350 B 报（与 bench 的 Throughput 声明一致）。
HMAC_BYTES = 1350


def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# criterion 落盘解析
# ---------------------------------------------------------------------------

def read_estimates(path):
    """estimates.json → (mean_ns, ci_lo_ns, ci_hi_ns)；格式漂移显式报错。"""
    try:
        data = json.loads(path.read_text())
        mean = data["mean"]["point_estimate"]
        lo = data["mean"]["confidence_interval"]["lower_bound"]
        hi = data["mean"]["confidence_interval"]["upper_bound"]
        return mean, lo, hi
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        fail(f"criterion estimates.json 格式与预期不符（{path}: {e}）；"
             "criterion 升级后请核对解析层（BENCHMARKS §8）。")


def parse_snapshot():
    """解析 matrix-* 组的当前 criterion 数据。

    返回 {(family, case, size_or_None): {backend: (mean, lo, hi)}}。
    目录布局：matrix-<family>/<backend>_<case>/<size>/new/estimates.json
    （无尺寸参数的案例直接 <backend>_<case>/new/estimates.json）。
    注意 criterion 会把案例 id 里的 '/' 规范成 '_'，后端按最长前缀剥离。
    """
    results = {}
    for family in FAMILIES:
        base = CRITERION / f"matrix-{family}"
        if not base.is_dir():
            continue
        for case_dir in sorted(base.iterdir()):
            if not case_dir.is_dir() or case_dir.name == "report":
                continue
            # criterion 会为参数化组生成 <group>/<size>/report 汇总目录
            # （数字名、无 estimates.json），跳过。
            if case_dir.name.isdigit():
                continue
            backend = None
            for cand in sorted(BACKENDS, key=len, reverse=True):
                prefix = cand + "_"
                if case_dir.name.startswith(prefix):
                    backend = cand
                    case = case_dir.name[len(prefix):]
                    break
            if backend is None:
                fail(f"无法识别的案例目录 {case_dir}（后端前缀不匹配）")
            for size_dir in sorted(case_dir.iterdir()):
                if not size_dir.is_dir():
                    continue
                if size_dir.name == "new":
                    est = size_dir / "estimates.json"
                    if est.is_file():
                        results[(family, case, None)] = {
                            **results.get((family, case, None), {}),
                            backend: read_estimates(est),
                        }
                elif size_dir.name.isdigit():
                    est = size_dir / "new" / "estimates.json"
                    if est.is_file():
                        key = (family, case, int(size_dir.name))
                        results[key] = {
                            **results.get(key, {}),
                            backend: read_estimates(est),
                        }
    return results


# ---------------------------------------------------------------------------
# 腿执行
# ---------------------------------------------------------------------------

def clean_matrix_dirs():
    """清掉 matrix-* 的历史数据（这些组为本矩阵专用；避免陈旧数据混入报告）。"""
    if CRITERION.is_dir():
        for d in CRITERION.glob("matrix-*"):
            shutil.rmtree(d)


def run_leg(label, no_default_features, extra_args):
    features = ["--no-default-features"] if no_default_features else []
    cmd = ["cargo", "bench", "--locked", "-p", "ferritls-interop",
           "--bench", "openssl_matrix", *features, "--", *extra_args]
    print(f"[{label}] {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-40:])
        print(tail, file=sys.stderr)
        fail(f"腿 {label} 失败（上方为 cargo 输出末尾）")
    meta = {}
    for payload in META_RE.findall(proc.stderr):
        # banner 一行可含多个 k=v（如 `simd=true arch=x86_64`）。
        for k, v in KV_RE.findall(payload):
            meta[k] = v.strip('"')
    if "openssl crosscheck: all green" in proc.stderr:
        meta["crosscheck"] = "all green"
    # 输出行数含测量行与基线对照行（criterion 的 t 检验行同样含
    # "time:"），仅作进度参考，非精确测量数。
    n_lines = proc.stdout.count("time:")
    print(f"[{label}] 完成（criterion 输出 {n_lines} 行）；meta: {meta}", flush=True)
    return meta, parse_snapshot()


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------

def fmt_us(ns):
    us = ns / 1000.0
    if us < 10:
        return f"{us:.3f}"
    if us < 100:
        return f"{us:.2f}"
    return f"{us:.1f}"


def fmt_ratio(r):
    if r is None:
        return "—"
    if r < 10:
        return f"{r:.2f}"
    if r < 100:
        return f"{r:.1f}"
    return f"{r:.0f}"


def fmt_cell(entry, nbytes):
    """值单元：µs；字节型案例附吞吐 (MB/s)。"""
    if entry is None:
        return "—"
    mean, lo, hi = entry
    cell = fmt_us(mean)
    if nbytes:
        mbs = nbytes / (mean / 1e9) / 1e6
        cell += f" ({mbs:,.0f} MB/s)"
    # CI 半宽以 ±% 标注（判断比值是否显著时用）。
    half = (hi - lo) / 2 / mean * 100
    return f"{cell} ±{half:.0f}%"


def ratio(a, b):
    if a is None or b is None or b[0] == 0:
        return None
    return a[0] / b[0]


def case_bytes(family, case, size):
    if family == "aead":
        return size
    if family == "hash" and case.endswith("-stream"):
        return size
    if case == "hmac-sha256-1350":
        return HMAC_BYTES
    return None


def render(leg_a, leg_b, meta_a, meta_b, extra_args, quick):
    # (family, case, size) → 各后端条目（跨腿合并：标量取 A，其余取 B）。
    merged = {}
    for key, backends in leg_b.items():
        merged.setdefault(key, {}).update(backends)
    for key, backends in leg_a.items():
        merged.setdefault(key, {}).update(backends)

    lines = []
    lines.append("# ferritls × OpenSSL 原语对照矩阵")
    lines.append("")
    lines.append(f"- 生成: {datetime.now().strftime('%Y-%m-%d %H:%M')} · `tools/bench_matrix.py`")
    cpu = ""
    try:
        for ln in Path("/proc/cpuinfo").read_text().splitlines():
            if ln.startswith("model name"):
                cpu = ln.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    if cpu:
        lines.append(f"- 机器: {cpu} · {platform.machine()} · {platform.system()}")
    try:
        rustc = subprocess.run(["rustc", "-V"], cwd=ROOT, capture_output=True,
                               text=True).stdout.strip()
        lines.append(f"- 工具链: {rustc}")
    except OSError:
        pass
    try:
        rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True).stdout.strip()
        lines.append(f"- git: {rev}")
    except OSError:
        pass
    lines.append(f"- openssl（链接库）: 腿 A {meta_a.get('openssl', '—')} / 腿 B {meta_b.get('openssl', '—')}")
    lines.append(f"- Ni 后端: aead={meta_b.get('ni_aead', 'n/a')} · hash={meta_b.get('ni_hash', 'n/a')}"
                 "（腿 B banner）")
    cross = {m.get("crosscheck") for m in (meta_a, meta_b) if m.get("crosscheck")}
    if cross:
        lines.append(f"- 跨实现交叉自检: {', '.join(sorted(cross))}"
                     "（相同密钥材料下 ferritls ↔ openssl 输出逐字节核对）")
    lines.append(f"- criterion 参数: {'--quick 档' if quick else '默认档'}"
                 + (f" · 附加 `{extra_args}`" if extra_args else ""))
    lines.append("")
    lines.append("> **解读规则**（BENCHMARKS §3/§8）：绝对值仅同机同批可比；"
                 "×openssl > 1 = 比 openssl 慢。simd 与 simd+Ni 同进程测量"
                 "（Ni/simd 直接可比）；标量与 simd 跨腿（隔着一次 feature"
                 " 全量重建），标量列的 ×openssl 用腿 A 锚点、simd 列用腿 B"
                 " 锚点——跨列绝对值对比一律以锚点比值为准。±% 为 95% CI"
                 " 半宽。openssl 侧 GCM/ChaCha 为密钥编排摊销的复用形态、"
                 "CCM/HMAC/HKDF/签名为 one-shot 形态（每次完整构建上下文，"
                 "对 openssl 偏保守——openssl 侧 HMAC/HKDF 显著慢于 Ni 列时"
                 "先看形态差异，勿直接下「快于 OpenSSL」结论）。"
                 "ML-KEM 不在矩阵内（openssl crate 无 encap/decap 绑定）。")
    lines.append("")

    for family in FAMILIES:
        title = {"aead": "AEAD", "hash": "哈希 / MAC / KDF",
                 "ecdh": "ECDH（完整 derive）", "sign": "签名"}[family]
        lines.append(f"## {title}")
        lines.append("")
        lines.append("| 案例 | 标量 | simd | simd+Ni | openssl |"
                     " ×ssl 标量 | ×ssl simd | ×ssl Ni | Ni/simd |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        rows = 0
        for case, _has_size in CASES[family]:
            sizes = SIZES if _has_size else [None]
            for size in sizes:
                key = (family, case, size)
                m = merged.get(key, {})
                scalar = m.get("ferritls-scalar")
                simd = m.get("ferritls-simd")
                ni = m.get("ferritls-simd-ni")
                # 锚点：标量配腿 A 的 openssl，simd/simd+Ni 配腿 B 的——
                # 同名目录被腿 B 覆盖，两腿锚点在 run_leg 后即时快照区分。
                ossl_a = leg_a.get(key, {}).get("openssl")
                ossl_b = leg_b.get(key, {}).get("openssl")
                name = case if size is None else f"{case} / {size} B"
                nb = case_bytes(family, case, size)
                lines.append(
                    f"| {name} "
                    f"| {fmt_cell(scalar, nb)} | {fmt_cell(simd, nb)} "
                    f"| {fmt_cell(ni, nb)} | {fmt_cell(ossl_b, nb)} "
                    f"| {fmt_ratio(ratio(scalar, ossl_a))} "
                    f"| {fmt_ratio(ratio(simd, ossl_b))} "
                    f"| {fmt_ratio(ratio(ni, ossl_b))} "
                    f"| {fmt_ratio(ratio(simd, ni))} |"
                )
                rows += 1
        if rows == 0:
            lines.append("| （无数据——先运行基准） | | | | | | | | |")
        lines.append("")

    # 自洽性校验：未加速原语在 simd 与 simd+Ni 两组应重合（CI 内），
    # 显著偏离即暴露意外耦合，单独列出提醒。

    def is_accelerated(family, case):
        # Ni 后端只接管 AES-GCM 执行核心与 SHA-256 压缩（ops.rs）；
        # CCM/ChaCha/ECDH/签名/SHA-512 为软件直通。
        if family == "aead" and case.startswith("gcm"):
            return True
        if family == "hash" and (
            case.startswith("sha256") or case.startswith("hmac")
            or case.startswith("hkdf")
        ):
            return True
        return False

    warnings = []
    for (family, case, size), m in merged.items():
        simd, ni = m.get("ferritls-simd"), m.get("ferritls-simd-ni")
        if simd and ni and not is_accelerated(family, case):
            lo = max(simd[1], ni[1])
            hi = min(simd[2], ni[2])
            # CI 不相交 + 均值相对差 >2% 才列出：默认档的 CI 极窄，
            # 亚百分点级的组间漂移（顺序/热噪声）必然使 CI 不相交，
            # 不构成「意外耦合」的证据。
            rel = abs(simd[0] - ni[0]) / simd[0]
            if lo > hi and rel > 0.02:
                warnings.append(f"{family}/{case}"
                                + (f"/{size}" if size else ""))
    if warnings:
        lines.append("## 自洽性提醒")
        lines.append("")
        lines.append("未加速原语的 simd 与 simd+Ni 两组均值 95% CI 不相交。"
                     "预期应重合；但两组在腿 B 内先后测量（隔着 openssl 组），"
                     "**测量顺序/热漂移是最常见的良性解释**——先用默认档"
                     "（非 --quick）复跑，仍不相交才值得怀疑与安装桥的意外"
                     "耦合：")
        lines.append("")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--quick", action="store_true",
                    help="冒烟档（缩短 criterion 采样，统计强度降低）")
    ap.add_argument("--extra", default="",
                    help="透传给 criterion 的附加参数（如 '--sample-size 50'）")
    ap.add_argument("--out", type=Path, default=None,
                    help="报告写入文件（默认打印到 stdout）")
    ap.add_argument("--skip-run", action="store_true",
                    help="不跑基准，只解析既有 criterion 数据出报告")
    args = ap.parse_args()

    extra = args.extra.split() if args.extra else []
    if args.quick:
        extra += ["--warm-up-time", "0.2", "--measurement-time", "0.3",
                  "--sample-size", "10"]

    if not args.skip_run:
        if platform.system() != "Linux":
            print("warning: 非 linux 平台无 openssl 列（依赖按 target 门控），"
                  "矩阵仅含 ferritls 各列", file=sys.stderr)
        clean_matrix_dirs()
        meta_a, leg_a = run_leg("腿 A: 标量", True, extra)
        meta_b, leg_b = run_leg("腿 B: simd + simd+Ni", False, extra)
        if "ferritls-scalar" not in {b for m in leg_a.values() for b in m}:
            fail("腿 A 未产出标量数据（检查 cargo 输出）")
        if "ferritls-simd" not in {b for m in leg_b.values() for b in m}:
            fail("腿 B 未产出 simd 数据（检查 cargo 输出）")
        if platform.system() == "Linux" and "openssl" not in meta_a:
            # banner 缺失说明跑的不是本仓最新 bench 二进制或被旧产物干扰
            print("warning: 腿 A 未报告 openssl 版本（数据可能来自陈旧构建）",
                  file=sys.stderr)
    else:
        leg_a, leg_b = parse_snapshot(), parse_snapshot()
        meta_a, meta_b = {}, {}

    # 腿 A 快照里 openssl 锚点会在腿 B 被同名覆盖——skip_run 模式下无法
    # 区分两腿锚点，统一退化为「共用最新锚点」（运行模式则精确分腿）。
    report = render(leg_a, leg_b, meta_a, meta_b, args.extra, args.quick)
    if args.out:
        args.out.write_text(report)
        print(f"报告已写入 {args.out}")
    else:
        print(report)


if __name__ == "__main__":
    main()

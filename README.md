# VCDIFF 增量标定片校验台

深空探测器下传增量标定片的导入前校验服务：在浏览器粘贴 **Base64 VCDIFF
载荷（≤ 128 KiB）** 与 **Base64 基准字典（≤ 64 KiB）**，提交后经真实
HTTP 接口展示最终字节长度、SHA-256、每个窗口的源区间，以及按指令顺序列出的
ADD / RUN / COPY 证据；可一键清空输入与结论。

实现仅依赖 Python 3.11 标准库（含服务端与测试，pytest 仅在校验镜像中安装）。

## 接受策略（严格 RFC 3284）

- 仅接受 **RFC 3284 默认码表**（`VCD_CODETABLE=0`），自定义码表一律拒绝；
- **未启用二次压缩**：头部 `VCD_DECOMPRESS=0`，各窗口 `Delta_Indicator=0`；
- 流内 **至多 8 个窗口**；地址缓存（near×4 / same×3）**按窗口初始化**；
- 正确解释 `SOURCE`（字典段）与 `TARGET`（前序窗口已复原字节段）源段；
- 正确解释双指令码（ADD+COPY / COPY+ADD）以及 **SELF / HERE / NEAR0–3 /
  SAME0–2** 全部 9 种地址模式；
- 输出总量严格限制为 **512 KiB**；
- 检测并报告：**非最短整数、段长度不符、非法码表索引、指向未生成字节的回拷、
  源/目标跨界拷贝、任意截断、残留字节、产出长度不符** 等；
- 任何错误都定位到 **首个原始字节偏移**（连同窗口号），失败时 **不保留任何
  部分输出**。

> 注：RFC 3284 §3 允许 COPY 前向重叠（如规范示例 `COPY 12,24`），该情形按
> 字节自复制扩展，证据中以「前向重叠」标记；非法的是 *起点* 指向当前尚未生成
> 的字节，或整个拷贝跨越 S/T 边界。

## 目录

```
app/vcdiff.py        严格解码器（含证据模型与精确错误偏移）
app/server.py        stdlib HTTP 服务（/、/healthz、POST /api/decode）
app/web/index.html   单页校验台页面
tests/venc.py        测试专用最小 VCDIFF 编码器（差分预言机）
tests/test_vcdiff.py 解码器单元测试（48 例）
tests/test_http.py   真实服务接口/HTTP 冒烟测试（9 例）
scripts/smoke_http.py 独立 HTTP 冒烟脚本（含特征样本）
scripts/verify.sh    单次校验门：构建检查 → 单元测试 → HTTP 冒烟
Dockerfile           两阶段：base（运行）/ verify（校验）
docker-compose.yml   web（常驻）+ verify（单次）
```

## 本地运行（无需 Docker）

```sh
HOST=0.0.0.0 PORT=8080 python3 app/server.py
# 页面 http://localhost:8080/   健康检查 GET /healthz
```

## Compose 启动

宿主机端口可配置（容器内始终 8080）：

```sh
HOST_PORT=9090 docker compose up -d --build web
curl -s http://localhost:9090/healthz
```

启动后页面与健康响应在配置的宿主机端口可用。

## 单次校验服务 verify

名为 **verify** 的服务只运行一次，依次执行 **解码单元测试、构建检查、
接口/HTTP 冒烟**，然后以退出码结束（0 表示全通过；它会等待 `web` 健康后
再做冒烟）：

```sh
docker compose build verify
docker compose up verify          # 0 退出即通过，可查看退出码：
docker compose ps -a | grep verify
```

不在容器环境时，可直接在本机执行同一套门控：

```sh
sh scripts/verify.sh               # compileall + pytest + live HTTP smoke
echo $?
```

## 接口契约

`POST /api/decode`

```json
{ "delta": "<standard base64>", "dictionary": "<standard base64 or empty>" }
```

成功 `200`：

```json
{ "ok": true, "raw_delta_length": 23, "target_length": 28,
  "sha256": "…", "window_count": 2, "window_limit": 8,
  "windows":   [ { "index": 1,
                   "source": {"kind": "TARGET", "segment_size": 16,
                              "segment_position": 0,
                              "absolute_range": [0, 16]},
                   "target_range": [16, 28], "raw_window_range": [18, 33] } ],
  "instructions": [ { "order": 4, "window": 1, "kind": "COPY", "size": 4,
                      "mode": "NEAR0", "encoded_address": 4, "address": 5,
                      "u_offset": 5, "target_offset": 8,
                      "source": "SOURCE", "origin": "PRIOR_TARGET",
                      "overlap": false, "data_hex": "…" } ] }
```

失败 `422`（解码被拒）/ `400`（Base64/JSON 非法）/ `413`（超粘贴上限）：

```json
{ "ok": false, "error": "…", "raw_offset": 32, "window": 1 }
```

`source` 表示该 COPY 在本窗口 U 内位于源段侧（`SOURCE`）还是目标侧
（`TARGET`）；`origin` 进一步区分源段来自 `DICTIONARY`、`PRIOR_TARGET`
还是拷贝自 `CURRENT_TARGET`（本窗口已输出部分）。

## 测试中的特征样本

`test_feature_sample_prior_target_copy_near_cache_and_failure` 与
`scripts/smoke_http.py::feature_sample` 构造了一个双窗口流：

1. 窗口 0 先 ADD `abc`，再以 **SELF 前向重叠 TARGET COPY** 扩展出 16 字节；
2. 窗口 1 以该前序窗口输出为 **VCD_TARGET 源段**，先用 SELF 拷贝预热 near
   缓存，再连续使用 **NEAR0** 模式；
3. 将最后一个 near 编码增量改为越界值后，流必须被拒绝，且
   `raw_offset` 恰好指向被篡改的最后一个原始字节、`window=1`。

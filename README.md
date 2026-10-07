# Attestation Guard

卫星载荷配置下发前的**签名与版本承接校验服务**。只有供应商签名有效、且版本号承接当前已接纳版本的配置证明才会被接纳，从而防止重放、回退和并发请求造成分叉。

- 纯 Python 3.11 标准库实现（内置 RFC 8032 Ed25519），镜像构建无需联网安装依赖。
- 状态持久化在 SQLite（WAL + `BEGIN IMMEDIATE`），重启后仍可查询唯一已接纳代次。
- 提供 Dockerfile 与 Docker Compose，包含健康检查、宿主机端口 `APP_PORT` 配置，以及一次性 `verify` 服务。

## API

### `GET /healthz`

健康检查，返回 `200 {"status":"ok"}`。

### `POST /api/attestations`

请求体（UTF-8 JSON）：

| 字段 | 说明 |
| --- | --- |
| `attestationId` | 本次证明的唯一编号（全局唯一，用于重放检测） |
| `keyId` | 随部署声明的供应商公钥编号 |
| `payloadBase64` | 载荷的 Base64；载荷为 UTF-8 JSON 的原始字节 |
| `signatureBase64` | 对**载荷解码后原始字节**的 Ed25519 签名，Base64 |

载荷 JSON 必须包含：

```json
{
  "deviceId": "sat-alpha",
  "generation": 2,
  "previousGeneration": 1,
  "configSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

`configSha256` 必须是 **64 位小写十六进制**的配置 SHA-256。

载荷 JSON **可选**包含 `prerequisites`（编队基线）。省略时既有契约完全不变；启用时给出 1～8 个条目，每个条目的 `deviceId` 必须互异且不能是目标设备自身：

```json
"prerequisites": [
  {
    "deviceId": "sat-beta",
    "generation": 3,
    "configSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
]
```

接纳规则：

1. 用 `keyId` 对应的部署公钥验证签名；未知密钥 / 错误签名一律拒绝，且**不改变状态**。
2. 每台设备**首次**提交的 `previousGeneration` 必须为 `0`，且 `generation > 0`。
3. 后续提交必须 `previousGeneration == 当前已接纳 generation` 且 `generation` 严格更大（允许跳号）。
4. **相同编号 + 字节级相同内容**的重试：稳定回放首次裁决——首次接纳返回 `200`、`status:"duplicate"`；首次被冲突拒绝（含依赖不满足）则此后永远返回**相同的 HTTP 状态与稳定错误码**，即使依赖设备或目标设备状态已经变化、即使服务重启，也不重新评估、不写新状态。
5. 相同编号但内容不同、同代次异内容、过期前代：均为 `409` 冲突，状态不变。
6. 并发请求由数据库写锁串行化，同一后继代次只有一个胜者，败者得到 `409 CONCURRENT_UPDATE`/冲突码，不产生分叉。
7. 当载荷携带 `prerequisites` 时，每个依赖设备必须在**同一接纳时刻**已存在，且其当前头的 `generation` 与 `configSha256` 都与条目**精确匹配**；任一设备不存在、代次不符或摘要不符，均返回 `409 PREREQUISITE_NOT_SATISFIED`，目标设备**不推进任何代次**。
8. 依赖检查、目标证明写入以及**裁决留痕**在**同一个 `BEGIN IMMEDIATE` 写事务**内完成，裁决不可分割且持久：依赖设备与目标设备并发更新时，只有符合提交顺序的一方成功——依赖先提交则目标因基线已变而失败，目标先提交则其基线裁决生效。相同证明的重试始终回放首次裁决（无论首次是接纳还是拒绝，都不再重新评估依赖）。

成功响应：`201`（首次）或 `200`（重试）：

```json
{
  "status": "accepted",
  "deviceId": "sat-alpha",
  "generation": 2,
  "previousGeneration": 1,
  "configSha256": "...",
  "attestationId": "...",
  "acceptedAt": "2026-10-06T16:34:16Z"
}
```

### `GET /api/devices/{deviceId}/head`

返回设备当前**唯一**已接纳代次与配置摘要；服务重启后结果不变。未知设备返回 `404 DEVICE_NOT_FOUND`。

### 稳定错误码

| HTTP | code | 触发条件 |
| --- | --- | --- |
| 400 | `MALFORMED_REQUEST` | 请求字段缺失/类型错误、非 JSON |
| 400 | `INVALID_BASE64` | Base64 无法解码 |
| 400 | `INVALID_JSON_PAYLOAD` | 载荷非 UTF-8 JSON、缺字段、代次非整数、哈希格式错；`prerequisites` 非数组、条目数不在 1～8、`deviceId` 重复/指向自身、条目缺字段或格式错 |
| 401 | `UNKNOWN_KEY_ID` | 部署声明中不存在该 `keyId` |
| 401 | `INVALID_SIGNATURE` | Ed25519 验签失败 |
| 403 | `KEY_NOT_BOUND_TO_DEVICE` | 密钥绑定了其它设备 |
| 409 | `FIRST_PREDECESSOR_NOT_ZERO` | 设备首单前代非 0 |
| 409 | `GENERATION_ZERO` | 新代次为 0 |
| 409 | `GENERATION_NOT_GREATER` | 新代次未严格递增 |
| 409 | `STALE_PREDECESSOR` | 前代不等于当前头（过期/回退/重放） |
| 409 | `ATTESTATION_ID_CONTENT_MISMATCH` | 编号复用但签名内容不同 |
| 409 | `GENERATION_CONTENT_CONFLICT` | 同代次已接纳不同内容 |
| 409 | `CONCURRENT_UPDATE` | 并发竞争失败（请重新读取 head 后重试） |
| 409 | `PREREQUISITE_NOT_SATISFIED` | 依赖设备不存在，或其当前头代次/摘要与 `prerequisites` 条目不精确匹配 |

所有冲突/鉴权失败都不会推进设备状态。

## 部署声明的公钥

编辑 `deploy/keys.json`（随部署提供，不经过 API 下发）：

```json
{
  "keys": {
    "vendor-sat-alpha-1": {
      "algorithm": "Ed25519",
      "publicKeyBase64": "BASE64(32 字节公钥)",
      "deviceId": "sat-alpha"
    }
  }
}
```

`deviceId` 可省略；填写后该密钥只能为该设备签名。生成密钥：

```bash
python3 -m scripts.keytool generate --key-id vendor-x --device-id sat-x --pretty
```

> 仓库 `deploy/keys.json` 中的密钥仅用于开发/演示（对应种子见 `deploy/dev-seeds.txt`，该文件不入镜像、不提交）。生产环境请替换。

## 运行

本地（无需 Docker）：

```bash
python3 -m app.server                     # 默认 :8080，数据 /data/attestations.db
APP_PORT=9090 DB_PATH=./data/att.db KEYS_PATH=./deploy/keys.json python3 -m app.server
```

Docker Compose：

```bash
cp .env.example .env        # 设置 APP_PORT（宿主机端口）
docker compose up -d --build api
curl -s localhost:${APP_PORT:-8080}/healthz
```

容器内部固定监听 8080；宿主机发布端口由 `APP_PORT` 控制（`${APP_PORT:-8080}:8080`）。
接纳数据保存在命名卷 `attest-data`（`/data`），因此重启后 head 依旧唯一可查。

### 一次性 `verify` 服务

运行代码测试、构建检查（字节码编译）和签名接纳冒烟，结束后**自行退出并以退出码汇总结果**：

```bash
docker compose run --build --rm verify
# 全部通过 -> 退出码 0；任一失败 -> 退出码非 0
```

冒烟在容器内自起一个临时 HTTP 服务，覆盖：健康检查、首次接纳、幂等重试、错误签名/未知密钥拒绝、后继承接、过期前代冲突、**编队依赖的成功/缺失/版本不符/并发竞争裁决（竞争失败不留目标代次）**、**首次因依赖缺失被拒后、依赖补齐再重试（以及重启后重试）均稳定回放原 409 且目标 head 始终不存在**，以及**重启同一数据库后 head 仍唯一、已接纳基线仍在且分叉尝试被拒**。

## 测试

```bash
sh scripts/verify.sh        # = compileall + 全部 unittest + smoke
# 或
python3 -m unittest discover -v -s tests
```

测试包含 RFC 8032 官方向量、与 `cryptography` 库的双向互操作校验、接纳链规则、
同编号/同代次冲突、线程内与**跨进程**并发竞争、编队依赖（成功、缺失、代次/摘要不符、
非法载荷、重试回放、线程内与跨进程竞争原子性）、**失败裁决在依赖补齐后及重启后仍稳定回放**、
以及真实进程 `kill -9` 后的持久化验证。

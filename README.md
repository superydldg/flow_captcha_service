# flow_captcha_service

`flow_captcha_service` 是独立的有头浏览器打码服务，给 `flow2api`
通过 HTTP 透传调用。

## 能力范围

- 只支持有头浏览器打码（Playwright）。
- 不接第三方打码平台（yescaptcha/capsolver 等）。
- 会话化协议：`solve -> finish/error`。
- 支持 `standalone / master / subnode` 三种角色。
- 支持 API Key、额度、日志、基础统计。

## 角色说明

- `standalone`：本地直接打码。
- `master`：不本地打码，只调度子节点。
- `subnode`：本地打码，并向 master 注册/心跳。

> 关键约束：`master` 角色不会执行本地浏览器打码。

## 核心接口

### 业务接口（需要 `Authorization: Bearer <service_api_key>`）

- `POST /api/v1/solve`
- `POST /api/v1/sessions/{session_id}/finish`
- `POST /api/v1/sessions/{session_id}/error`
- `POST /api/v1/custom-score`
- `GET /api/v1/health`

`master` 返回的 `session_id` 为可路由格式：

```text
nodeId:childSessionId
```

### 集群内部接口（需要 `X-Cluster-Key`，仅 master 生效）

- `POST /api/cluster/register`
- `POST /api/cluster/heartbeat`

### 管理接口

- `POST /api/admin/login`
- `POST /api/admin/logout`
- `GET /api/admin/apikeys`
- `POST /api/admin/apikeys`
- `PATCH /api/admin/apikeys/{api_key_id}`
- `GET /api/admin/logs`
- `GET /api/admin/stats`
- `GET /api/admin/captcha-config`
- `POST /api/admin/captcha-config`
- `GET /api/admin/cluster/config`
- `POST /api/admin/cluster/config/rotate-key`
- `GET /api/admin/cluster/nodes`
- `PATCH /api/admin/cluster/nodes/{node_id}`

## 配置项

复制模板：

```bash
cp config/setting_example.toml config/setting.toml
```

### `cluster` 段说明

```toml
[cluster]
role = "standalone"              # standalone / master / subnode
master_base_url = ""             # subnode 必填
master_cluster_key = ""          # subnode 必填
node_public_base_url = ""        # subnode 对 master 暴露地址
node_api_key = ""                # subnode 被 master 调用的内部 key
heartbeat_interval_seconds = 15
node_weight = 100
node_max_concurrency = 1
master_node_stale_seconds = 120
master_dispatch_timeout_seconds = 45
```

常用环境变量：

- `FCS_CLUSTER_ROLE`
- `FCS_CLUSTER_MASTER_BASE_URL`
- `FCS_CLUSTER_MASTER_CLUSTER_KEY`
- `FCS_CLUSTER_NODE_PUBLIC_BASE_URL`
- `FCS_CLUSTER_NODE_API_KEY`
- `FCS_CLUSTER_HEARTBEAT_INTERVAL_SECONDS`
- `FCS_CLUSTER_NODE_WEIGHT`
- `FCS_CLUSTER_NODE_MAX_CONCURRENCY`

## 快速启动

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/Mac
source .venv/bin/activate

pip install -r requirements.txt
python main.py
```

默认地址：`http://127.0.0.1:8060`

## Docker（有头）

### standalone

```bash
docker compose -f docker-compose.headed.yml up -d --build
```

### master

```bash
docker compose -f docker-compose.cluster.master.yml up -d --build
```

### subnode

```bash
docker compose -f docker-compose.cluster.subnode.yml up -d --build
```

> `subnode` 启动前，需要在 `master` 管理接口获取 `cluster_key`，并写入
> `FCS_CLUSTER_MASTER_CLUSTER_KEY`。

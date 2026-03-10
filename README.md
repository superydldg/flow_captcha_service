# flow_captcha_service

`flow_captcha_service` 是给 `flow2api` 使用的自托管打码服务。

它的目标不是接第三方打码平台，而是自己托管 `Playwright + Chromium`
有头浏览器能力，并支持单机、主从集群、用户门户、管理后台和额度体系。

如果你只想快速理解一句话，可以直接记住下面这句：

> `standalone` 本地自己打码，`master` 只调度不本地打码，
> `subnode` 负责执行浏览器打码并向 `master` 上报心跳。

---

## 项目介绍

### 这个项目解决什么问题

`flow2api` 在某些场景下需要一个独立的、有头浏览器驱动的验证码服务。
`flow_captcha_service` 就是为这个场景准备的独立服务端。

它提供：

- 有头浏览器打码能力
- `solve -> finish/error` 会话协议
- 浏览器槽位复用与空闲回收
- `standalone / master / subnode` 三种部署角色
- 用户门户、管理员后台、API Key、额度和日志
- 主从集群调度

它不提供：

- `yescaptcha`、`capsolver` 这类第三方平台接入
- 子节点上的用户注册/登录首页

---

## 架构与角色

### 架构关系

```text
flow2api
   |
   | HTTP
   v
[standalone]                     直接本地打码

或

flow2api
   |
   | HTTP
   v
[master]                         只调度，不本地起浏览器
   |
   | 路由转发
   v
[subnode]                        本地执行有头浏览器打码
```

### 三种角色说明

#### 1. `standalone`

- 单机模式
- 本地直接执行浏览器打码
- 适合本地调试、单机部署、小规模使用

#### 2. `master`

- 只负责调度和转发
- 不执行本地浏览器打码
- 适合集群入口节点

#### 3. `subnode`

- 执行本地浏览器打码
- 向 `master` 注册和发送心跳
- 首页是**子节点状态页**，不是用户登录/注册页

### 访问入口差异

#### `standalone` / `master`

- `/`：用户门户
- `/portal`：用户门户别名
- `/admin`：管理后台
- `/api/v1/health`：健康检查

#### `subnode`

- `/`：子节点状态页
- `/portal`：同样返回子节点状态页
- `/subnode`：子节点状态页显式入口
- `/admin`：管理后台
- `/api/v1/health`：健康检查

> 从这个版本开始，`subnode` 不再展示用户注册/登录首页。
> 子节点首页只展示角色、健康状态和后台入口。

---

## 核心调用流程

### 标准链路

1. 上游调用 `POST /api/v1/solve`
2. 服务返回 `session_id`、`token`、`node_name`
3. 上游拿着 token 继续完成图片/视频等后续业务
4. 业务成功后调用 `POST /api/v1/sessions/{session_id}/finish`
5. 业务失败后调用 `POST /api/v1/sessions/{session_id}/error`

### 重要语义

- `solve` 只负责拿 token，不代表整个上游业务已经完成
- `finish/error` 是业务会话回收协议
- 成功时不会强制关闭共享浏览器
- 只有明确命中验证码失败类错误时，才会回收对应浏览器槽位

### 集群下的 `session_id`

如果当前角色是 `master`，返回的 `session_id` 可能是：

```text
nodeId:childSessionId
```

这表示：

- 前半段是 master 侧的节点路由信息
- 后半段是 subnode 的真实会话 ID
- 之后的 `finish/error` 会按这个路由再转发回原子节点

---

## 部署前准备

### 运行环境

- Python 本地运行：建议 `Python 3.11`
- Docker 部署：需要 `Docker` 和 `Docker Compose`
- 有头浏览器模式依赖 `Playwright + Chromium`

### 目录准备

首次部署建议先准备运行目录：

```bash
mkdir -p data
cp config/setting_example.toml data/setting.toml
```

如果你使用 Windows PowerShell，可以按自己的习惯改成等价命令。

### 本地 Python 模式额外安装

本地非 Docker 启动时，除了安装 Python 依赖，还要安装 Chromium：

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

Linux 如果缺系统依赖，可以改用：

```bash
python -m playwright install --with-deps chromium
```

---

## 配置文件与环境变量

### 配置文件位置

- 模板文件：`config/setting_example.toml`
- 运行配置：`data/setting.toml`
- 兼容迁移：如果存在旧的 `config/setting.toml`，启动时会迁移到
  `data/setting.toml`

### 配置优先级

建议记住这一条：

```text
环境变量 > data/setting.toml > 默认配置
```

`config/setting_example.toml` 只是初始化模板，不是最终优先级来源。

### 常用环境变量

#### 通用

- `FCS_CONFIG_FILE`
- `FCS_SERVER_HOST`
- `FCS_SERVER_PORT`
- `FCS_DB_PATH`
- `FCS_ADMIN_USERNAME`
- `FCS_ADMIN_PASSWORD`
- `FCS_LOG_LEVEL`
- `FCS_NODE_NAME`

#### 浏览器与打码

- `FCS_BROWSER_COUNT`
- `FCS_BROWSER_PROXY_ENABLED`
- `FCS_BROWSER_PROXY_URL`
- `FCS_BROWSER_LAUNCH_BACKGROUND`
- `FCS_BROWSER_SCORE_DOM_WAIT_SECONDS`
- `FCS_BROWSER_RECAPTCHA_SETTLE_SECONDS`
- `FCS_BROWSER_SCORE_TEST_WARMUP_SECONDS`
- `FCS_BROWSER_IDLE_TTL_SECONDS`
- `FCS_FLOW_TIMEOUT`
- `FCS_UPSAMPLE_TIMEOUT`
- `FCS_SESSION_TTL_SECONDS`

#### 集群

- `FCS_CLUSTER_ROLE`
- `FCS_CLUSTER_MASTER_BASE_URL`
- `FCS_CLUSTER_MASTER_CLUSTER_KEY`
- `FCS_CLUSTER_NODE_PUBLIC_BASE_URL`
- `FCS_CLUSTER_NODE_API_KEY`
- `FCS_CLUSTER_HEARTBEAT_INTERVAL_SECONDS`
- `FCS_CLUSTER_NODE_WEIGHT`
- `FCS_CLUSTER_NODE_MAX_CONCURRENCY`
- `FCS_CLUSTER_MASTER_NODE_STALE_SECONDS`
- `FCS_CLUSTER_MASTER_DISPATCH_TIMEOUT_SECONDS`

### 一个容易忽略的点

```text
cluster.node_max_concurrency = 0
```

实际含义是：

- 不单独指定固定并发
- 自动跟随 `browser_count`

---

## 快速开始

### 方式一：本地单机 `standalone`

这是最适合第一次跑通服务的方式。

#### 1. 创建虚拟环境

```bash
python -m venv .venv
```

Windows：

```powershell
.venv\Scripts\activate
```

Linux / macOS：

```bash
source .venv/bin/activate
```

#### 2. 安装依赖

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

#### 3. 准备配置

```bash
mkdir -p data
cp config/setting_example.toml data/setting.toml
```

确认 `data/setting.toml` 中：

```toml
[cluster]
role = "standalone"
```

#### 4. 启动服务

```bash
python main.py
```

#### 5. 启动后访问

- 用户门户：`http://127.0.0.1:8060/`
- 管理后台：`http://127.0.0.1:8060/admin`
- 健康检查：`http://127.0.0.1:8060/api/v1/health`

### 方式二：Docker 单机 `standalone`

对应文件：`docker-compose.headed.yml`

#### 1. 准备目录

```bash
mkdir -p data config
cp config/setting_example.toml data/setting.toml
```

#### 2. 启动

```bash
docker compose -f docker-compose.headed.yml up -d --build
```

#### 3. 访问

- 用户门户：`http://127.0.0.1:8060/`
- 管理后台：`http://127.0.0.1:8060/admin`
- 健康检查：`http://127.0.0.1:8060/api/v1/health`

#### 4. 说明

- 该模式使用 `Dockerfile.headed`
- 镜像内已安装 `Playwright Chromium + Xvfb + fluxbox`
- 默认角色是 `standalone`
- `./data:/app/data` 必须保留，否则数据库、日志、密钥等状态会丢失

---

## 使用教程

下面这部分是“服务已经启动之后，怎么真正接入”。

### 教程 A：管理员第一次初始化

#### 1. 打开管理后台

访问：

```text
http://127.0.0.1:8060/admin
```

默认管理员账号通常是：

```text
admin / admin
```

首次登录后建议马上修改。

#### 2. 创建对接方式

你有两种常见用法：

- 直接在后台创建服务 API Key，给上游程序直接调用
- 让用户走门户注册/登录，再在门户里创建自己的 API Key

### 教程 B：用户门户模式

只适用于 `standalone` 或 `master`。

#### 1. 打开门户

```text
http://127.0.0.1:8060/
```

#### 2. 注册或登录

门户支持：

- 登录
- 注册
- 查看额度
- 兑换 CDK
- 查看调用记录
- 自助创建自己的 API Key

#### 3. 创建个人 API Key

登录后进入 `API Key` 页面，创建自己的 Key。

### 教程 C：服务 API 直连模式

下面是最常见的接入方式。

#### 1. 调用 `solve`

```bash
curl -X POST "http://127.0.0.1:8060/api/v1/solve" \
  -H "Authorization: Bearer <YOUR_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "demo-project",
    "action": "IMAGE_GENERATION"
  }'
```

返回示例：

```json
{
  "success": true,
  "session_id": "123456",
  "token": "recaptcha-token",
  "fingerprint": {},
  "node_name": "standalone-node",
  "expires_in_seconds": 1200
}
```

如果当前入口是 `master`，`session_id` 可能是：

```text
12:child-session-id
```

这属于正常现象，后续 `finish/error` 原样带回即可。

#### 2. 业务成功后调用 `finish`

```bash
curl -X POST "http://127.0.0.1:8060/api/v1/sessions/<SESSION_ID>/finish" \
  -H "Authorization: Bearer <YOUR_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "success"
  }'
```

#### 3. 业务失败后调用 `error`

```bash
curl -X POST "http://127.0.0.1:8060/api/v1/sessions/<SESSION_ID>/error" \
  -H "Authorization: Bearer <YOUR_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "error_reason": "upstream_error"
  }'
```

### 教程 D：`custom-score`

如果你要做自定义 score 调试，可以调用：

```text
POST /api/v1/custom-score
```

请求体包含：

- `website_url`
- `website_key`
- `verify_url`
- `action`
- `enterprise`

---

## 集群部署教程

### 1. Docker 部署 `master`

对应文件：`docker-compose.cluster.master.yml`

#### 适用场景

- 作为集群统一入口
- 只调度，不本地打码
- 镜像更轻，不安装 Chromium

#### 启动步骤

1. 准备配置目录

```bash
mkdir -p data/master config
cp config/setting_example.toml data/master/setting.toml
```

2. 启动前确认角色

```text
FCS_CLUSTER_ROLE=master
```

3. 启动

```bash
docker compose -f docker-compose.cluster.master.yml up -d --build
```

#### 默认访问入口

- 管理后台：`http://127.0.0.1:8060/admin`
- 用户门户：`http://127.0.0.1:8060/`
- 健康检查：`http://127.0.0.1:8060/api/v1/health`

#### 说明

- `master` 使用 `Dockerfile.master`
- 不安装 `Playwright/Chromium`
- 当前 compose 默认挂载是 `./data/master:/app/data`

### 2. Docker 部署 `subnode`

对应文件：`docker-compose.cluster.subnode.yml`

#### 适用场景

- 集群执行节点
- 本地有头浏览器打码
- 向 `master` 注册与发送心跳

#### 启动前必须替换的变量

- `FCS_CLUSTER_MASTER_BASE_URL`
- `FCS_CLUSTER_MASTER_CLUSTER_KEY`
- `FCS_CLUSTER_NODE_PUBLIC_BASE_URL`
- `FCS_CLUSTER_NODE_API_KEY`

#### 启动步骤

1. 准备配置目录

```bash
mkdir -p data/subnode config
cp config/setting_example.toml data/subnode/setting.toml
```

2. 修改关键环境变量

默认 compose 里是示例值，不能直接拿到生产环境使用。

重点解释：

- `FCS_CLUSTER_MASTER_BASE_URL`
  - 填 `master` 实际可访问地址
- `FCS_CLUSTER_MASTER_CLUSTER_KEY`
  - 填主节点 cluster key
- `FCS_CLUSTER_NODE_PUBLIC_BASE_URL`
  - 填主节点能访问到的当前子节点地址
- `FCS_CLUSTER_NODE_API_KEY`
  - 填子节点内部认证 key

3. 启动

```bash
docker compose -f docker-compose.cluster.subnode.yml up -d --build
```

#### 默认访问入口

- 子节点状态页：`http://127.0.0.1:8061/`
- 管理后台：`http://127.0.0.1:8061/admin`
- 健康检查：`http://127.0.0.1:8061/api/v1/health`

#### 非常重要的注意事项

- `FCS_CLUSTER_NODE_PUBLIC_BASE_URL` 不能填 `127.0.0.1`
- 不能填 `localhost`
- 不能填 `0.0.0.0`
- 必须是 `master` 真正能访问到的地址

另外：

- `host.docker.internal` 只适合本机开发或 Docker Desktop 场景
- Linux 服务器或跨机器部署时，应改成真实地址

### 3. 一键启动 `master + subnode`

对应文件：`docker-compose.cluster.stack.yml`

这是最推荐的最小集群示例。

#### 1. 准备 `.env`

```env
FCS_MASTER_NODE_NAME=master-1
FCS_SUBNODE_NODE_NAME=subnode-1
FCS_CLUSTER_MASTER_CLUSTER_KEY=replace-with-master-cluster-key
FCS_CLUSTER_NODE_API_KEY=replace-with-node-internal-key
FCS_CLUSTER_MASTER_BASE_URL=http://flow-captcha-master:8060
FCS_CLUSTER_NODE_PUBLIC_BASE_URL=http://flow-captcha-subnode:8060
FCS_CLUSTER_NODE_WEIGHT=100
FCS_CLUSTER_NODE_MAX_CONCURRENCY=0
FCS_CLUSTER_HEARTBEAT_INTERVAL_SECONDS=15
FCS_LOG_LEVEL=INFO
```

#### 2. 启动

```bash
docker compose -f docker-compose.cluster.stack.yml up -d --build
```

#### 3. 访问

- master 用户门户：`http://127.0.0.1:8060/`
- master 管理后台：`http://127.0.0.1:8060/admin`
- master 健康检查：`http://127.0.0.1:8060/api/v1/health`
- subnode 状态页：`http://127.0.0.1:8061/`
- subnode 健康检查：`http://127.0.0.1:8061/api/v1/health`

#### 4. 这个 compose 的优点

- 已把 `master` 和 `subnode` 的数据目录拆开
- 默认更适合作为第一次验证集群调度的示例

挂载如下：

- `./data/master:/app/data`
- `./data/subnode:/app/data`

---

## 每种模式必须改什么

### `standalone`

- 一般可以直接启动
- 按需调整 `browser_count`
- 按需调整代理
- 建议修改管理员账号密码

### `master`

- 建议修改 `FCS_NODE_NAME`
- 建议修改管理员账号密码
- 如果有多个子节点，建议统一规划 cluster key

### `subnode`

- 必改 `FCS_CLUSTER_MASTER_BASE_URL`
- 必改 `FCS_CLUSTER_MASTER_CLUSTER_KEY`
- 必改 `FCS_CLUSTER_NODE_PUBLIC_BASE_URL`
- 必改 `FCS_CLUSTER_NODE_API_KEY`
- 建议修改 `FCS_NODE_NAME`

### `stack`

- 必改 `FCS_CLUSTER_MASTER_CLUSTER_KEY`
- 必改 `FCS_CLUSTER_NODE_API_KEY`
- 如果不是容器内互联场景，要改 master/subnode 的实际对外地址

---

## 启动后怎么验证

### 验证 1：服务是否存活

```bash
curl http://127.0.0.1:8060/api/v1/health
```

返回示例：

```json
{
  "success": true,
  "status": "ok",
  "node_name": "master-1",
  "role": "master"
}
```

### 验证 2：页面是否符合角色预期

- `standalone`：`/` 应该是用户门户
- `master`：`/` 应该是用户门户
- `subnode`：`/` 应该是子节点状态页

### 验证 3：集群是否连通

在 `master` 管理后台查看：

- 子节点是否出现
- 心跳是否持续更新
- 有效容量是否正常
- 节点是否健康

---

## GHCR 镜像

仓库支持通过 GHCR 发布镜像：

- `ghcr.io/<owner>/flow_captcha_service-master`
- `ghcr.io/<owner>/flow_captcha_service-headed`

拉取示例：

```bash
docker pull ghcr.io/genz27/flow_captcha_service-master:latest
docker pull ghcr.io/genz27/flow_captcha_service-headed:latest
```

说明：

- `master` 镜像用于主节点
- `headed` 镜像用于 `standalone` 或 `subnode`

---

## 常见问题

### 1. 为什么子节点首页没有登录/注册？

这是当前版本的设计。

`subnode` 首页现在是**子节点状态页**，只用于：

- 看当前角色
- 看健康状态
- 进后台排查

用户门户只应该放在 `master` 或 `standalone`。

### 2. 为什么主节点和子节点不能共用一个 `data` 目录？

因为会共用：

- 数据库
- API Key
- 集群状态
- 日志

结果会导致状态混乱。

### 3. 本地 Python 启动后浏览器起不来怎么办？

优先检查：

1. 是否执行过 `python -m playwright install chromium`
2. Linux 是否缺依赖，必要时使用
   `python -m playwright install --with-deps chromium`
3. 代理或显示环境是否异常

### 4. `cluster.node_max_concurrency = 0` 是什么意思？

表示：

- 不手动固定并发值
- 自动跟随 `browser_count`

### 5. `master` 会不会本地执行浏览器打码？

不会。

`master` 只负责调度和转发，真正执行浏览器打码的是 `subnode`
或者 `standalone`。

---

## 总结

如果你是第一次接触这个项目，最推荐的顺序是：

1. 先跑 `standalone`
2. 用 `/admin` 创建 API Key
3. 用 `solve -> finish/error` 跑通一遍
4. 再尝试 `master + subnode` 集群

如果你看到子节点首页不是登录页，而是状态页，这不是异常，
而是当前版本的预期行为。

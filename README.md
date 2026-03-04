# flow_captcha_service

`flow_captcha_service` 是给 `flow2api` 使用的独立打码服务，采用 HTTP 透传方式调用。

它的核心定位不是“接第三方打码平台”，而是“自己托管有头浏览器打码能力”，并支持主从集群。

---

## 项目介绍与能力范围

### 1. 能力范围

- 仅支持有头浏览器打码（Playwright + Chromium）
- 不接 yescaptcha/capsolver 等外部平台
- 支持会话化流程：`solve -> finish/error`
- 支持 `standalone / master / subnode` 三种角色
- 支持管理面板（`/admin`）做常用运维操作
- 支持 API Key、额度、日志、集群节点状态管理

### 2. 角色说明

- `standalone`：单机直接打码
- `master`：只调度子节点，不执行本地浏览器打码
- `subnode`：执行本地浏览器打码，并向 master 注册/心跳

---

## 项目架构

### 1. 逻辑架构

```text
flow2api
   |
   | HTTP
   v
[master]  (调度，不打码)
   |
   | 路由转发（nodeId:childSessionId）
   v
[subnode] (有头浏览器打码)
```

### 2. 关闭链路（主节点如何通知子节点关闭）

本项目没有单独 `/close` 业务接口，关闭语义通过会话协议完成：

1. 上游先调用 `solve`，master 返回 `nodeId:childSessionId`
2. 业务成功后调用 `finish`
3. master 按路由 session 转发到对应 subnode
4. subnode 执行本地 `runtime.finish()`，通知浏览器实例关闭
5. 业务失败则调用 `error`，subnode 走错误关闭路径

---

## 配置文件与修改方式

### 1. 配置文件位置

- 模板：`config/setting_example.toml`
- 实际：`config/setting.toml`

首次使用：

```bash
cp config/setting_example.toml config/setting.toml
```

### 2. 修改配置的两种方式

#### A. 通过管理面板（推荐）

- 入口：`http://<host>:<port>/admin`
- 可在线修改运行配置与系统配置
- 会提示哪些改动需要重启服务

#### B. 直接编辑 `setting.toml`

- 修改后重启服务生效（部分配置可热生效，但建议按重启策略执行）

### 3. 配置优先级

环境变量优先级高于 `setting.toml`。  
如果某项被环境变量覆盖，面板会显示提示。

---

## 本地部署

默认端口为 `8060`。

### 1. standalone（本地单机）

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/Mac
source .venv/bin/activate

pip install -r requirements.txt
python main.py
```

访问：

- 服务健康检查：`http://127.0.0.1:8060/api/v1/health`
- 管理面板：`http://127.0.0.1:8060/admin`

### 2. 本地主从（不走 Docker）

- 启动 master：`FCS_CLUSTER_ROLE=master`
- 启动 subnode：`FCS_CLUSTER_ROLE=subnode` 并配置：
  - `FCS_CLUSTER_MASTER_BASE_URL`
  - `FCS_CLUSTER_MASTER_CLUSTER_KEY`
  - `FCS_CLUSTER_NODE_PUBLIC_BASE_URL`
  - `FCS_CLUSTER_NODE_API_KEY`

---

## Docker 部署（含持久化）

> 推荐始终保留持久化挂载，否则重启后会丢失数据库、API Key、cluster key、日志等状态。

### 1. 持久化目录建议

- `./data`：数据库与运行状态（必须持久化）
- `./config`：配置文件（建议持久化）

### 2. standalone（有头）

```bash
docker compose -f docker-compose.headed.yml up -d --build
```

默认已挂载：

- `./data:/app/data`
- `./config:/app/config`

### 3. master（轻量镜像）

```bash
docker compose -f docker-compose.cluster.master.yml up -d --build
```

使用 `Dockerfile.master`（不安装 Playwright/Chromium，镜像更小）。

### 4. subnode（有头镜像）

```bash
docker compose -f docker-compose.cluster.subnode.yml up -d --build
```

启动前要替换：

- `FCS_CLUSTER_MASTER_CLUSTER_KEY`
- `FCS_CLUSTER_NODE_API_KEY`

---

## 一键部署（master + subnode）

```bash
docker compose -f docker-compose.cluster.stack.yml up -d --build
```

该方案同时拉起：

- `flow-captcha-master`（轻量镜像）
- `flow-captcha-subnode`（有头镜像）

默认持久化路径：

- `./data/master:/app/data`
- `./data/subnode:/app/data`
- `./config:/app/config`

启动前至少替换：

- `FCS_CLUSTER_MASTER_CLUSTER_KEY`
- `FCS_CLUSTER_NODE_API_KEY`

---

## GHCR 镜像

项目通过 GitHub Actions 自动发布到 GHCR：

- `ghcr.io/<owner>/flow_captcha_service-master`（轻量 master）
- `ghcr.io/<owner>/flow_captcha_service-headed`（有头 standalone/subnode）
- 发布架构：`linux/amd64`、`linux/arm64`

拉取示例：

```bash
docker pull ghcr.io/genz27/flow_captcha_service-master:latest
docker pull ghcr.io/genz27/flow_captcha_service-headed:latest
```

### 拉取镜像是否需要环境变量？

- `docker pull`：不需要环境变量
- `docker run / docker compose up`：需要按角色配置环境变量

如果仓库/包是私有，请先使用带 `read:packages` 权限的 PAT 登录 GHCR。

---

## 常见问题

### `exec /usr/local/bin/entrypoint.headed.sh: exec format error`

排查顺序：

1. 确认机器架构（你是 `x86_64/amd64`）
2. 确认拉到的是新镜像（重新 `docker pull`）
3. 删除旧 tag 本地缓存后再拉取并重启容器

本仓库已将有头镜像启动方式改为内联 `bash` 启动流程，不再依赖脚本文件执行，可避免该错误。

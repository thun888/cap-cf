# Cap CF - Cloudflare Workers 验证码服务

一个运行在 Cloudflare Workers 上的轻量、现代验证码替代方案，采用工作量证明（proof-of-work）挑战。

> 本项目移植自 [Cap](https://github.com/tiagozip/cap/)，Apache-2.0 协议。

## 特性

- 🔐 **工作量证明挑战** - 无需视觉谜题，仅需计算工作
- 🚀 **Cloudflare Workers** - 边缘计算，低延迟
- 💾 **D1 + KV 存储** - 持久化数据 + 可配置缓存后端
- 📊 **分析面板** - 追踪验证次数、失败记录等
- 🛡️ **速率限制** - 防止滥用
- 🌍 **IP 封锁** - 按 IP、CIDR、ASN 或国家/地区封锁
- 🔑 **API 密钥** - 安全认证
- ⚙️ **可配置缓存** - 使用 D1（默认）或 KV 作为缓存存储

## 设置步骤

### 1. 创建 Cloudflare 资源

```bash
# 创建 D1 数据库（必需）
wrangler d1 create cap-db

# 创建 KV 命名空间（仅在使用 KV 缓存后端时需要）
wrangler kv namespace create KV
```

### 2. 更新配置

编辑 `wrangler.jsonc` 文件，替换占位符 ID：

```jsonc
{
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "cap-db",
      "database_id": "your-actual-d1-id",  // 替换为实际的 D1 ID
      "preview_database_id": "cap-db-preview"
    }
  ],
  "vars": {
    "ADMIN_KEY": "",
    "CACHE_BACKEND": "d1"  // 可选 "d1" 或 "kv"
  }
}
```

**缓存后端选项：**

| 后端 | 说明 | 适用场景 |
|------|------|----------|
| `d1`（默认） | 缓存存储在 D1 数据库中 | worker免费套餐，无需 KV |
| `kv` | 缓存存储在 KV 命名空间中 | 高吞吐量场景，建议使用worker付费套餐 |

> **注意：** 如果使用 `kv` 后端，还必须配置 `kv_namespaces` 绑定。

### 3. 初始化数据库

```bash
# 应用数据库架构
wrangler d1 execute cap-db --file=./schema.sql --remote
```

### 4. 设置管理员密钥

```bash
# 设置为密钥（推荐）
wrangler secret put ADMIN_KEY

# 或在 wrangler.jsonc 的 vars 中设置（不推荐用于生产环境）
```

### 5. 部署

```bash
wrangler deploy
```

## API 端点

### 公开端点

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/:siteKey/challenge` | 生成验证码挑战 |
| `POST` | `/:siteKey/redeem` | 验证挑战解决方案 |
| `POST` | `/siteverify` | 验证令牌（用于外部服务） |
| `POST` | `/auth/login` | 管理员登录 |

### 管理端点（需认证）

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/server/keys` | 列出所有密钥 |
| `POST` | `/server/keys` | 创建新密钥 |
| `GET` | `/server/keys/:siteKey` | 获取密钥详情及指标 |
| `PUT` | `/server/keys/:siteKey/config` | 更新密钥配置 |
| `DELETE` | `/server/keys/:siteKey` | 删除密钥 |
| `POST` | `/server/keys/:siteKey/rotate-secret` | 轮换密钥 |
| `GET` | `/server/keys/:siteKey/blocked-ips` | 列出被封锁的 IP |
| `POST` | `/server/keys/:siteKey/block-ip` | 封锁 IP |
| `POST` | `/server/keys/:siteKey/unblock-ip` | 解除封锁 IP |
| `GET` | `/server/settings/sessions` | 列出会话 |
| `GET` | `/server/settings/apikeys` | 列出 API 密钥 |
| `POST` | `/server/settings/apikeys` | 创建 API 密钥 |
| `DELETE` | `/server/settings/apikeys/:id` | 删除 API 密钥 |
| `GET` | `/server/settings/headers` | 获取头部设置 |
| `PUT` | `/server/settings/headers` | 更新头部设置 |
| `GET` | `/server/settings/ratelimit` | 获取速率限制设置 |
| `PUT` | `/server/settings/ratelimit` | 更新速率限制设置 |
| `GET` | `/server/about` | 获取服务器信息 |

## 认证方式

### 会话令牌

```javascript
// 登录
const response = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ admin_key: 'your-admin-key' }),
});
const { session_token, hashed_token } = await response.json();

// 在后续请求中使用
const authHeader = btoa(JSON.stringify({ token: session_token, hash: hashed_token }));
fetch('/server/keys', {
  headers: { Authorization: `Bearer ${authHeader}` },
});
```

### API 密钥

```javascript
// 创建 API 密钥
const { apiKey } = await fetch('/server/settings/apikeys', {
  method: 'POST',
  headers: { Authorization: `Bearer ${authHeader}` },
  body: JSON.stringify({ name: 'My App' }),
}).then(r => r.json());

// 使用 API 密钥
fetch('/server/keys', {
  headers: { Authorization: `Bot ${apiKey}` },
});
```

## 客户端集成

```html
<script src="https://your-worker.workers.dev/assets/widget.js"></script>
<script>
  const cap = new Cap({
    endpoint: 'https://your-worker.workers.dev',
    siteKey: 'your-site-key',
  });

  // 获取挑战
  const challenge = await cap.challenge();

  // 在后台解决挑战
  const solution = await cap.solve(challenge);

  // 提交到你的服务器
  const response = await fetch('/verify', {
    method: 'POST',
    body: JSON.stringify({ capToken: solution.token }),
  });
</script>
```

## 环境变量

| 变量 | 必需 | 默认值 | 说明 |
|------|------|--------|------|
| `ADMIN_KEY` | 是 | - | 管理员认证密钥（最少 12 个字符） |
| `CACHE_BACKEND` | 否 | `d1` | 缓存后端：`d1` 或 `kv` |
| `DISABLE_METRICS` | 否 | `false` | 禁用统计 |

## 开发

```bash
# 启动开发服务器
npm run dev

# 运行测试
npm test

# 生成类型
npm run cf-typegen
```

## 许可证

Apache-2.0

## AI 相关

本项目完全使用DeepSeek V4移植，可能存在不足

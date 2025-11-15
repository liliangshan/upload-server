# 文件上传服务器

一个使用 Go 编写的安全文件上传服务器，支持图片、视频和音频文件上传，具备身份验证和磁盘使用监控功能。

**仓库地址：** [https://github.com/liliangshan/upload-server.git](https://github.com/liliangshan/upload-server.git)

## 功能特性

- **安全文件上传**：支持图片、视频和音频文件，带身份验证
- **身份验证**：密钥和非ce签名验证
- **文件组织**：按日期自动组织（YYYYMM/DD）
- **安全文件名**：基于 SHA256 哈希的文件名生成
- **磁盘使用监控**：实时磁盘使用情况查询 API
- **跨平台支持**：支持 Windows 和 Linux
- **CORS 支持**：可配置的 CORS 头
- **文件权限**：可配置的文件所有者和权限（Unix/Linux）
- **静态文件服务**：内置文件服务器用于访问上传的文件

## 支持的文件类型

### 图片
`.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`, `.bmp`, `.tiff`

### 视频
`.mp4`, `.avi`, `.mov`, `.wmv`, `.flv`, `.mkv`, `.webm`, `.mpeg`, `.mpg`, `.m4v`, `.3gp`

### 音频
`.mp3`, `.wav`, `.wma`, `.aac`, `.flac`, `.ogg`, `.m4a`, `.aiff`, `.alac`, `.opus`, `.webm`

## 系统要求

- Go 1.24.0 或更高版本
- Windows 或 Linux 操作系统

## 安装

### 从源码编译

1. 克隆仓库：
```bash
git clone https://github.com/liliangshan/upload-server.git
cd upload-server
```

2. 使用提供的脚本编译：
```powershell
# Windows PowerShell
.\build.ps1
```

这将生成：
- `upload.exe` - Windows 可执行文件
- `upload-linux` - Linux 可执行文件

### 手动编译

#### Windows:
```bash
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -o upload.exe -ldflags="-s -w" .
```

#### Linux:
```bash
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64
go build -o upload-linux -ldflags="-s -w" .
```

## 配置

在项目根目录创建 `.env` 文件：

```env
# CORS 允许的来源 - 设置为 * 允许所有来源，或指定特定域名
# 示例：ALLOW_ORIGIN=https://example.com
ALLOW_ORIGIN=*

# 必需：上传密钥，用于身份验证
# 此密钥必须在请求头 X-Upload-Secret-Key 中提供
# 生产环境请使用强随机字符串
UPLOAD_SECRET_KEY=hjkhYo8908HKhk

# 必需：随机密钥，用于 nonce 签名生成
# 用于生成 MD5 签名：MD5(nonce + RANDOM_SECRET_KEY)
# 请使用与 UPLOAD_SECRET_KEY 不同的强随机字符串
RANDOM_SECRET_KEY=hgj790Hhklj

# 上传目录 - 存储上传文件的路径
# 可以是绝对路径或相对路径
# 示例：UPLOAD_DIR=../public/storage/
UPLOAD_DIR=../public/storage/

# 最大上传大小，单位 MB
# 默认：50MB。对于视频上传，可能需要增大此值
# 示例：MAX_UPLOAD_SIZE=500（500MB）
MAX_UPLOAD_SIZE=500

# 服务器端口 - 必须在 1024 到 65535 之间
# 默认：8080
SERVER_PORT=18088

# 文件所有者 - 仅 Unix/Linux
# 不需要时留空。用于设置上传后的文件所有者
# 示例：FILE_OWNER=www-data
FILE_OWNER=

# 文件组 - 仅 Unix/Linux
# 不需要时留空。用于设置上传后的文件组
# 示例：FILE_GROUP=www-data
FILE_GROUP=

# SSL 证书文件路径 - 可选
# 如果同时配置了 SSL_CERT_FILE 和 SSL_KEY_FILE，服务器将使用 HTTPS
# 示例：SSL_CERT_FILE=/path/to/cert.pem
SSL_CERT_FILE=

# SSL 密钥文件路径 - 可选
# 如果同时配置了 SSL_CERT_FILE 和 SSL_KEY_FILE，服务器将使用 HTTPS
# 示例：SSL_KEY_FILE=/path/to/key.pem
SSL_KEY_FILE=

# 绑定域名 - 可选
# 逗号分隔的要绑定到服务器的域名列表
# 服务器将只响应来自这些域名的请求
# 支持通配符模式，如 *.example.com
# 如果不设置，服务器响应所有域名的请求
# 示例：BIND_HOSTS=example.com,api.example.com,*.example.com
BIND_HOSTS=
```

**SSL/HTTPS 说明：** 如果同时配置了 `SSL_CERT_FILE` 和 `SSL_KEY_FILE`，服务器将自动使用 HTTPS。否则将使用 HTTP。您也可以在服务器前使用反向代理（如 Nginx 或 Caddy）来处理 SSL/TLS 终止。

### 环境变量

| 变量 | 必需 | 默认值 | 说明 |
|------|------|--------|------|
| `ALLOW_ORIGIN` | 否 | `*` | CORS 允许的来源。使用 `*` 允许所有来源，或指定域名如 `https://example.com` |
| `UPLOAD_SECRET_KEY` | 是 | - | 上传身份验证密钥。必须在请求头 `X-Upload-Secret-Key` 中提供 |
| `RANDOM_SECRET_KEY` | 是 | - | nonce 签名生成密钥。用于计算 `MD5(nonce + RANDOM_SECRET_KEY)` |
| `UPLOAD_DIR` | 否 | `./uploads` | 存储上传文件的目录。可以是绝对路径或相对路径 |
| `MAX_UPLOAD_SIZE` | 否 | `50` | 最大上传大小（MB）。视频上传时可能需要增大（如 500 表示 500MB） |
| `SERVER_PORT` | 否 | `8080` | 服务器监听端口。必须在 1024 到 65535 之间 |
| `FILE_OWNER` | 否 | - | 文件所有者（仅 Unix/Linux）。不需要时留空 |
| `FILE_GROUP` | 否 | - | 文件组（仅 Unix/Linux）。不需要时留空 |
| `SSL_CERT_FILE` | 否 | - | SSL 证书文件路径。如果同时设置了 SSL_CERT_FILE 和 SSL_KEY_FILE，服务器将使用 HTTPS |
| `SSL_KEY_FILE` | 否 | - | SSL 私钥文件路径。如果同时设置了 SSL_CERT_FILE 和 SSL_KEY_FILE，服务器将使用 HTTPS |
| `BIND_HOSTS` | 否 | - | 逗号分隔的要绑定到服务器的域名列表。服务器将只响应来自这些域名的请求。支持通配符模式（如 `*.example.com`）。如果不设置，服务器响应所有域名的请求 |

**SSL/HTTPS 说明：** 如果同时配置了 `SSL_CERT_FILE` 和 `SSL_KEY_FILE`，服务器将自动使用 HTTPS。否则将使用 HTTP。您也可以在服务器前使用反向代理（Nginx、Caddy 等）来处理 SSL/TLS 终止。

**域名绑定说明：** 如果配置了 `BIND_HOSTS`，服务器将只响应来自指定域名的请求。这会将服务器绑定到特定域名，有助于防止 Host 头攻击。

## 使用方法

### 启动服务器

```bash
# Windows
.\upload.exe

# Linux
./upload-linux
```

服务器将在配置的端口上启动（默认：8080）。

## API 文档

### 上传文件

上传图片、视频或音频文件。

**端点：** `POST /upload-file`

**请求头：**
```
X-Upload-Secret-Key: your_secret_key
X-Upload-Nonce: random_nonce_string
X-Upload-Signature: md5(nonce + RANDOM_SECRET_KEY)
```

**请求：**
- 方法：`POST`
- Content-Type：`multipart/form-data`
- 请求体：表单数据，包含 `file` 字段的文件

**响应：**
```json
{
  "url": "/202412/15/abc123_1234567890.jpg",
  "filename": "202412/15/abc123_1234567890.jpg",
  "type": "image",
  "used": 107374182400
}
```

**响应字段：**
- `url`：上传文件的访问 URL
- `filename`：相对文件名路径
- `type`：文件类型（`image`、`video` 或 `audio`）
- `used`：磁盘已用空间（字节）

**示例（cURL）：**
```bash
# 生成 nonce 和签名
NONCE=$(openssl rand -hex 16)
SIGNATURE=$(echo -n "${NONCE}${RANDOM_SECRET_KEY}" | md5sum | cut -d' ' -f1)

curl -X POST http://localhost:8080/upload-file \
  -H "X-Upload-Secret-Key: your_secret_key" \
  -H "X-Upload-Nonce: ${NONCE}" \
  -H "X-Upload-Signature: ${SIGNATURE}" \
  -F "file=@image.jpg"
```

**示例（JavaScript）：**
```javascript
async function uploadFile(file) {
  const nonce = Math.random().toString(36).substring(2, 15);
  const signature = await generateMD5(nonce + RANDOM_SECRET_KEY);
  
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await fetch('http://localhost:8080/upload-file', {
    method: 'POST',
    headers: {
      'X-Upload-Secret-Key': 'your_secret_key',
      'X-Upload-Nonce': nonce,
      'X-Upload-Signature': signature
    },
    body: formData
  });
  
  return await response.json();
}
```

### 获取磁盘使用情况

查询磁盘使用情况信息。

**端点：** `GET /disk-usage`

**请求头（可选）：**
```
X-Upload-Secret-Key: your_secret_key
```

**响应：**
```json
{
  "total": 107374182400,
  "used": 53687091200,
  "free": 53687091200
}
```

**响应字段：**
- `total`：磁盘总空间（字节）
- `used`：已用磁盘空间（字节）
- `free`：可用磁盘空间（字节）

**示例（cURL）：**
```bash
curl http://localhost:8080/disk-usage
```

**示例（JavaScript）：**
```javascript
async function getDiskUsage() {
  const response = await fetch('http://localhost:8080/disk-usage');
  return await response.json();
}
```

### 访问上传的文件

上传的文件可通过以下方式访问：
```
http://localhost:8080/uploads/{filename}
```

示例：
```
http://localhost:8080/uploads/202412/15/abc123_1234567890.jpg
```

## 文件组织

上传的文件按日期自动组织：
```
uploads/
  └── YYYYMM/
      └── DD/
          └── {hash}_{timestamp}.{ext}
```

示例：
```
uploads/
  └── 202412/
      └── 15/
          └── a1b2c3d4e5f6_1702646400.jpg
```

## 安全说明

### 身份验证

1. **密钥验证**：必需的 `X-Upload-Secret-Key` 请求头必须与 `UPLOAD_SECRET_KEY` 匹配
2. **Nonce 签名**：
   - 生成随机 nonce
   - 计算签名：`MD5(nonce + RANDOM_SECRET_KEY)`
   - 在请求头中同时发送两者

### 文件安全

- 文件使用 SHA256 哈希重命名，防止冲突和目录遍历
- 仅接受允许的文件类型
- 强制执行文件大小限制
- 文件按日期组织，便于管理

## 错误响应

### 400 Bad Request
- 文件过大
- 无效的文件类型
- 请求中缺少文件

### 401 Unauthorized
- 无效的密钥
- 无效的 nonce 或签名

### 405 Method Not Allowed
- 错误的 HTTP 方法

### 500 Internal Server Error
- 服务器端错误（文件创建、磁盘查询等）

## 项目结构

```
upload-server/
├── main.go              # 主应用程序代码
├── disk_windows.go      # Windows 磁盘使用情况实现
├── disk_unix.go         # Unix/Linux 磁盘使用情况实现
├── build.ps1            # Windows 和 Linux 编译脚本
├── go.mod               # Go 模块定义
├── README.md            # 英文文档
├── README.zh-CN.md      # 中文文档
└── .env                 # 配置文件（需创建）
```

## 开发

### 运行测试

```bash
go test ./...
```

### 代码格式化

```bash
go fmt ./...
```

### 为不同平台编译

编译脚本（`build.ps1`）编译以下平台：
- Windows (amd64)
- Linux (amd64)

要为其他平台编译，请修改 `GOOS` 和 `GOARCH` 环境变量。

## 许可证

[在此添加许可证信息]

## 贡献

[在此添加贡献指南]

## 支持

[在此添加支持信息]


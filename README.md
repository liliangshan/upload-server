# Upload Server

A secure file upload server written in Go, supporting image, video, and audio file uploads with authentication and disk usage monitoring.

**Repository:** [https://github.com/liliangshan/upload-server.git](https://github.com/liliangshan/upload-server.git)

## Features

- **Secure File Upload**: Supports image, video, and audio files with authentication
- **Authentication**: Secret key and nonce signature verification
- **File Organization**: Automatic organization by date (YYYYMM/DD)
- **Secure Filenames**: SHA256 hash-based filename generation
- **Disk Usage Monitoring**: Real-time disk usage query API
- **Cross-Platform**: Supports Windows and Linux
- **CORS Support**: Configurable CORS headers
- **File Permissions**: Configurable file ownership and permissions (Unix/Linux)
- **Static File Serving**: Built-in file server for uploaded files

## Supported File Types

### Images
`.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`, `.bmp`, `.tiff`

### Videos
`.mp4`, `.avi`, `.mov`, `.wmv`, `.flv`, `.mkv`, `.webm`, `.mpeg`, `.mpg`, `.m4v`, `.3gp`

### Audio
`.mp3`, `.wav`, `.wma`, `.aac`, `.flac`, `.ogg`, `.m4a`, `.aiff`, `.alac`, `.opus`, `.webm`

## Requirements

- Go 1.24.0 or higher
- Windows or Linux operating system

## Installation

### Build from Source

1. Clone the repository:
```bash
git clone https://github.com/liliangshan/upload-server.git
cd upload-server
```

2. Build using the provided script:
```powershell
# Windows PowerShell
.\build.ps1
```

This will generate:
- `upload.exe` - Windows executable
- `upload-linux` - Linux executable

### Manual Build

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

## Configuration

Create a `.env` file in the project root directory:

```env
# CORS allowed origin - Set to * to allow all origins, or specify a specific domain
# Example: ALLOW_ORIGIN=https://example.com
ALLOW_ORIGIN=*

# Required: Upload secret key for authentication
# This key must be provided in the X-Upload-Secret-Key header for upload requests
# Use a strong, random string for production
UPLOAD_SECRET_KEY=hjkhYo8908HKhk

# Required: Random secret key for nonce signature generation
# Used to generate MD5 signature: MD5(nonce + RANDOM_SECRET_KEY)
# Use a strong, random string different from UPLOAD_SECRET_KEY
RANDOM_SECRET_KEY=hgj790Hhklj

# Upload directory - Path where uploaded files will be stored
# Can be absolute or relative path
# Example: UPLOAD_DIR=../public/storage/
UPLOAD_DIR=../public/storage/

# Maximum upload size in MB
# Default: 50MB. For video uploads, you may need to increase this value
# Example: MAX_UPLOAD_SIZE=500 (for 500MB)
MAX_UPLOAD_SIZE=500

# Server port - Must be between 1024 and 65535
# Default: 8080
SERVER_PORT=18088

# File owner - Unix/Linux only
# Leave empty if not needed. Used to set file ownership after upload
# Example: FILE_OWNER=www-data
FILE_OWNER=

# File group - Unix/Linux only
# Leave empty if not needed. Used to set file group ownership after upload
# Example: FILE_GROUP=www-data
FILE_GROUP=

# SSL Certificate file path - Optional
# If both SSL_CERT_FILE and SSL_KEY_FILE are provided, server will use HTTPS
# Example: SSL_CERT_FILE=/path/to/cert.pem
SSL_CERT_FILE=

# SSL Key file path - Optional
# If both SSL_CERT_FILE and SSL_KEY_FILE are provided, server will use HTTPS
# Example: SSL_KEY_FILE=/path/to/key.pem
SSL_KEY_FILE=

# Bind hosts - Optional
# Comma-separated list of hostnames to bind the server to
# Server will only respond to requests from these domains
# Supports wildcard patterns like *.example.com
# If not set, server responds to all hostnames
# Example: BIND_HOSTS=example.com,api.example.com,*.example.com
BIND_HOSTS=
```

**SSL/HTTPS Note:** If both `SSL_CERT_FILE` and `SSL_KEY_FILE` are configured, the server will automatically use HTTPS. Otherwise, it will use HTTP. You can also use a reverse proxy (Nginx, Caddy, etc.) in front of the server for SSL/TLS termination.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ALLOW_ORIGIN` | No | `*` | CORS allowed origin. Use `*` for all origins or specify a domain like `https://example.com` |
| `UPLOAD_SECRET_KEY` | Yes | - | Secret key for upload authentication. Must be provided in `X-Upload-Secret-Key` header |
| `RANDOM_SECRET_KEY` | Yes | - | Secret key for nonce signature generation. Used to calculate `MD5(nonce + RANDOM_SECRET_KEY)` |
| `UPLOAD_DIR` | No | `./uploads` | Directory for storing uploaded files. Can be absolute or relative path |
| `MAX_UPLOAD_SIZE` | No | `50` | Maximum upload size in MB. Increase for video uploads (e.g., 500 for 500MB) |
| `SERVER_PORT` | No | `8080` | Server listening port. Must be between 1024 and 65535 |
| `FILE_OWNER` | No | - | File owner (Unix/Linux only). Leave empty if not needed |
| `FILE_GROUP` | No | - | File group (Unix/Linux only). Leave empty if not needed |
| `SSL_CERT_FILE` | No | - | SSL certificate file path. If both SSL_CERT_FILE and SSL_KEY_FILE are set, server will use HTTPS |
| `SSL_KEY_FILE` | No | - | SSL private key file path. If both SSL_CERT_FILE and SSL_KEY_FILE are set, server will use HTTPS |
| `BIND_HOSTS` | No | - | Comma-separated list of hostnames to bind the server to. Server will only respond to requests from these domains. Supports wildcard patterns (e.g., `*.example.com`). If not set, server responds to all hostnames |

**SSL/HTTPS Note:** If both `SSL_CERT_FILE` and `SSL_KEY_FILE` are configured, the server will automatically use HTTPS. Otherwise, it will use HTTP. You can also use a reverse proxy (Nginx, Caddy, etc.) in front of the server for SSL/TLS termination.

**Host Binding:** If `BIND_HOSTS` is configured, the server will only respond to requests from the specified hostnames. This binds the server to specific domains and helps prevent Host header attacks.

## Usage

### Start the Server

```bash
# Windows
.\upload.exe

# Linux
./upload-linux
```

The server will start on the configured port (default: 8080).

## API Documentation

### Upload File

Upload an image, video, or audio file.

**Endpoint:** `POST /upload-file`

**Headers:**
```
X-Upload-Secret-Key: your_secret_key
X-Upload-Nonce: random_nonce_string
X-Upload-Signature: md5(nonce + RANDOM_SECRET_KEY)
```

**Request:**
- Method: `POST`
- Content-Type: `multipart/form-data`
- Body: Form data with `file` field containing the file

**Response:**
```json
{
  "url": "/202412/15/abc123_1234567890.jpg",
  "filename": "202412/15/abc123_1234567890.jpg",
  "type": "image",
  "used": 107374182400
}
```

**Response Fields:**
- `url`: Access URL for the uploaded file
- `filename`: Relative filename path
- `type`: File type (`image`, `video`, or `audio`)
- `used`: Disk used space in bytes

**Example (cURL):**
```bash
# Generate nonce and signature
NONCE=$(openssl rand -hex 16)
SIGNATURE=$(echo -n "${NONCE}${RANDOM_SECRET_KEY}" | md5sum | cut -d' ' -f1)

curl -X POST http://localhost:8080/upload-file \
  -H "X-Upload-Secret-Key: your_secret_key" \
  -H "X-Upload-Nonce: ${NONCE}" \
  -H "X-Upload-Signature: ${SIGNATURE}" \
  -F "file=@image.jpg"
```

**Example (JavaScript):**
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

### Get Disk Usage

Query disk usage information.

**Endpoint:** `GET /disk-usage`

**Headers (Optional):**
```
X-Upload-Secret-Key: your_secret_key
```

**Response:**
```json
{
  "total": 107374182400,
  "used": 53687091200,
  "free": 53687091200
}
```

**Response Fields:**
- `total`: Total disk space in bytes
- `used`: Used disk space in bytes
- `free`: Free disk space in bytes

**Example (cURL):**
```bash
curl http://localhost:8080/disk-usage
```

**Example (JavaScript):**
```javascript
async function getDiskUsage() {
  const response = await fetch('http://localhost:8080/disk-usage');
  return await response.json();
}
```

### Access Uploaded Files

Uploaded files are accessible via:
```
http://localhost:8080/uploads/{filename}
```

Example:
```
http://localhost:8080/uploads/202412/15/abc123_1234567890.jpg
```

## File Organization

Uploaded files are automatically organized by date:
```
uploads/
  └── YYYYMM/
      └── DD/
          └── {hash}_{timestamp}.{ext}
```

Example:
```
uploads/
  └── 202412/
      └── 15/
          └── a1b2c3d4e5f6_1702646400.jpg
```

## Security

### Authentication

1. **Secret Key**: Required `X-Upload-Secret-Key` header must match `UPLOAD_SECRET_KEY`
2. **Nonce Signature**: 
   - Generate a random nonce
   - Calculate signature: `MD5(nonce + RANDOM_SECRET_KEY)`
   - Send both in request headers

### File Security

- Files are renamed using SHA256 hash to prevent conflicts and directory traversal
- Only allowed file types are accepted
- File size limits are enforced
- Files are organized by date for easier management

## Error Responses

### 400 Bad Request
- File too large
- Invalid file type
- Missing file in request

### 401 Unauthorized
- Invalid secret key
- Invalid nonce or signature

### 405 Method Not Allowed
- Wrong HTTP method

### 500 Internal Server Error
- Server-side errors (file creation, disk query, etc.)

## Project Structure

```
upload-server/
├── main.go              # Main application code
├── disk_windows.go      # Windows disk usage implementation
├── disk_unix.go         # Unix/Linux disk usage implementation
├── build.ps1            # Build script for Windows and Linux
├── go.mod               # Go module definition
├── README.md            # This file
└── .env                 # Configuration file (create this)
```

## Development

### Running Tests

```bash
go test ./...
```

### Code Formatting

```bash
go fmt ./...
```

### Building for Different Platforms

The build script (`build.ps1`) compiles for:
- Windows (amd64)
- Linux (amd64)

To build for other platforms, modify the `GOOS` and `GOARCH` environment variables.

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]

## Support

[Add support information here]


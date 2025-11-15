package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	uploadSecretKey string
	uploadDir       string
	maxUploadSize   int64
	serverPort      string
	randomSecretKey string
	allowOrigin     string
	fileOwner       string
	fileGroup       string
	sslCertFile     string
	sslKeyFile      string
	bindHosts       []string
)

func init() {
	// 尝试读取 .env 文件（简单实现）
	envFile, err := os.Open(".env")
	if err == nil {
		defer envFile.Close()
		scanner := bufio.NewScanner(envFile)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// 去除行内注释
			line = strings.Split(line, "#")[0]
			line = strings.TrimSpace(line)

			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				os.Setenv(key, value)
			}
		}
	}

	// 加载环境变量
	uploadSecretKey = os.Getenv("UPLOAD_SECRET_KEY")
	randomSecretKey = os.Getenv("RANDOM_SECRET_KEY")
	serverPort = os.Getenv("SERVER_PORT")
	allowOrigin = os.Getenv("ALLOW_ORIGIN")

	// 对获取的环境变量再次过滤注释
	uploadSecretKey = strings.Split(uploadSecretKey, "#")[0]
	randomSecretKey = strings.Split(randomSecretKey, "#")[0]
	serverPort = strings.Split(serverPort, "#")[0]
	allowOrigin = strings.Split(allowOrigin, "#")[0]

	uploadSecretKey = strings.TrimSpace(uploadSecretKey)
	randomSecretKey = strings.TrimSpace(randomSecretKey)
	serverPort = strings.TrimSpace(serverPort)
	allowOrigin = strings.TrimSpace(allowOrigin)

	// 如果没有配置跨域域名，默认允许所有
	if allowOrigin == "" {
		allowOrigin = "*"
	}

	// 如果没有配置上传目录，使用当前目录下的 uploads 子目录
	uploadDir = os.Getenv("UPLOAD_DIR")
	uploadDir = strings.Split(uploadDir, "#")[0]
	uploadDir = strings.TrimSpace(uploadDir)

	if uploadDir == "" {
		// 获取当前可执行文件所在目录
		execPath, err := os.Executable()
		if err != nil {
			execPath = "."
		}
		uploadDir = filepath.Join(filepath.Dir(execPath), "uploads")
	}

	// 解析最大上传大小
	maxSizeStr := os.Getenv("MAX_UPLOAD_SIZE")
	maxSizeStr = strings.Split(maxSizeStr, "#")[0]
	maxSizeStr = strings.TrimSpace(maxSizeStr)
	maxUploadSize, _ = strconv.ParseInt(maxSizeStr, 10, 64)
	maxUploadSize *= 1024 * 1024 // 转换为字节

	// 如果没有配置最大上传大小，设置默认值
	if maxUploadSize == 0 {
		maxUploadSize = 50 * 1024 * 1024 // 默认50MB
	}

	// 如果没有配置端口，使用默认值
	if serverPort == "" {
		serverPort = "8080"
	}

	// 检查必要的配置
	if uploadSecretKey == "" {
		log.Fatal("必须配置 UPLOAD_SECRET_KEY")
	}
	if randomSecretKey == "" {
		log.Fatal("必须配置 RANDOM_SECRET_KEY")
	}

	// 确保上传目录存在
	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		log.Fatal("Cannot create upload directory:", err)
	}
	fileOwner = os.Getenv("FILE_OWNER")
	fileGroup = os.Getenv("FILE_GROUP")
	fileOwner = strings.Split(fileOwner, "#")[0]
	fileGroup = strings.Split(fileGroup, "#")[0]
	fileOwner = strings.TrimSpace(fileOwner)
	fileGroup = strings.TrimSpace(fileGroup)

	// SSL证书配置
	sslCertFile = os.Getenv("SSL_CERT_FILE")
	sslKeyFile = os.Getenv("SSL_KEY_FILE")
	sslCertFile = strings.Split(sslCertFile, "#")[0]
	sslKeyFile = strings.Split(sslKeyFile, "#")[0]
	sslCertFile = strings.TrimSpace(sslCertFile)
	sslKeyFile = strings.TrimSpace(sslKeyFile)

	// 域名绑定配置 - 服务器只响应指定域名的请求
	bindHostsStr := os.Getenv("BIND_HOSTS")
	bindHostsStr = strings.Split(bindHostsStr, "#")[0]
	bindHostsStr = strings.TrimSpace(bindHostsStr)
	if bindHostsStr != "" {
		// 支持逗号分隔的多个域名
		hosts := strings.Split(bindHostsStr, ",")
		for _, host := range hosts {
			host = strings.TrimSpace(host)
			if host != "" {
				bindHosts = append(bindHosts, host)
			}
		}
	}

}

// 验证随机数签名
func validateNonceSignature(nonce, signature string) bool {
	// 计算 MD5(随机数 + 密钥)
	data := nonce + randomSecretKey
	hash := md5.Sum([]byte(data))
	expectedSignature := hex.EncodeToString(hash[:])
	return signature == expectedSignature
}

// 生成按年月/日的子目录
func generateDateSubdir() string {
	now := time.Now()
	return fmt.Sprintf("%04d%02d/%02d", now.Year(), now.Month(), now.Day())
}

// 生成安全的文件名
func generateSecureFilename(originalFilename string) string {
	ext := filepath.Ext(originalFilename)
	timestamp := time.Now().Unix()
	hash := sha256.Sum256([]byte(originalFilename + strconv.FormatInt(timestamp, 10)))

	// 创建按日期的子目录
	subdir := generateDateSubdir()

	// 确保子目录存在
	fullSubdir := filepath.Join(uploadDir, subdir)
	if err := os.MkdirAll(fullSubdir, os.ModePerm); err != nil {
		log.Printf("Error creating subdirectory %s: %v", fullSubdir, err)
	}

	return filepath.Join(subdir, fmt.Sprintf("%s_%d%s", hex.EncodeToString(hash[:16]), timestamp, ext))
}

// 验证密钥
func validateSecretKey(key string) bool {
	return key == uploadSecretKey
}

// 验证域名绑定
func validateHost(host string) bool {
	// 如果没有配置绑定的域名，允许所有域名访问
	if len(bindHosts) == 0 {
		return true
	}

	// 移除端口号（如果有）
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// 检查请求的域名是否匹配绑定的域名
	for _, bindHost := range bindHosts {
		// 支持通配符匹配，如 *.example.com
		if matchHost(host, bindHost) {
			return true
		}
	}

	return false
}

// 匹配域名，支持通配符
func matchHost(host, pattern string) bool {
	// 完全匹配
	if host == pattern {
		return true
	}

	// 通配符匹配：*.example.com
	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:] // 移除 "*."
		if strings.HasSuffix(host, "."+domain) || host == domain {
			return true
		}
	}

	return false
}

// 检查文件类型是否为图片、视频或音频
func isAllowedFileType(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	allowedExtensions := []string{
		// 图片类型
		".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff",
		// 视频类型
		".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv", ".webm",
		".mpeg", ".mpg", ".m4v", ".3gp",
		// 音频类型
		".mp3", ".wav", ".wma", ".aac", ".flac", ".ogg", ".m4a",
		".aiff", ".alac", ".opus", ".webm",
	}
	for _, validExt := range allowedExtensions {
		if ext == validExt {
			return true
		}
	}
	return false
}

// 获取文件类型（图片、视频或音频）
func getFileType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	imageExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff"}
	videoExtensions := []string{".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv", ".webm", ".mpeg", ".mpg", ".m4v", ".3gp"}
	audioExtensions := []string{".mp3", ".wav", ".wma", ".aac", ".flac", ".ogg", ".m4a", ".aiff", ".alac", ".opus", ".webm"}

	for _, imageExt := range imageExtensions {
		if ext == imageExt {
			return "image"
		}
	}

	for _, videoExt := range videoExtensions {
		if ext == videoExt {
			return "video"
		}
	}

	for _, audioExt := range audioExtensions {
		if ext == audioExt {
			return "audio"
		}
	}

	return "unknown"
}

// 设置文件权限
func setFilePermissions(filePath string) error {
	if runtime.GOOS == "windows" {
		return nil // Windows系统不需要设置权限
	}

	if fileOwner == "" || fileGroup == "" {
		return nil // 未配置所有者信息，跳过设置
	}

	// 获取用户和组ID
	ownerUser, err := user.Lookup(fileOwner)
	if err != nil {
		return fmt.Errorf("查找用户 %s 失败: %v", fileOwner, err)
	}

	groupUser, err := user.LookupGroup(fileGroup)
	if err != nil {
		return fmt.Errorf("查找组 %s 失败: %v", fileGroup, err)
	}

	uid, err := strconv.Atoi(ownerUser.Uid)
	if err != nil {
		return fmt.Errorf("转换用户ID失败: %v", err)
	}

	gid, err := strconv.Atoi(groupUser.Gid)
	if err != nil {
		return fmt.Errorf("转换组ID失败: %v", err)
	}

	// 设置文件所有者和组
	if err := os.Chown(filePath, uid, gid); err != nil {
		return fmt.Errorf("设置文件所有者失败: %v", err)
	}

	// 设置文件权限为644
	if err := os.Chmod(filePath, 0644); err != nil {
		return fmt.Errorf("设置文件权限失败: %v", err)
	}

	return nil
}

// DiskUsage 表示磁盘使用情况
type DiskUsage struct {
	Total uint64 // 总大小（字节）
	Used  uint64 // 已用大小（字节）
	Free  uint64 // 可用大小（字节）
}

// getDiskUsage 获取指定路径所在磁盘的使用情况
func getDiskUsage(path string) (*DiskUsage, error) {
	if runtime.GOOS == "windows" {
		return getDiskUsageWindows(path)
	}
	return getDiskUsageUnix(path)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// 验证域名绑定
	if !validateHost(r.Host) {
		http.Error(w, "Forbidden: Host not bound to this server", http.StatusForbidden)
		return
	}

	// 处理跨域请求
	w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Upload-Secret-Key, X-Upload-Nonce, X-Upload-Signature")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "86400") // 24小时

	// 处理OPTIONS请求
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// 只允许POST方法
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 验证密钥
	secretKey := r.Header.Get("X-Upload-Secret-Key")
	if !validateSecretKey(secretKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 验证随机数签名
	nonce := r.Header.Get("X-Upload-Nonce")
	signature := r.Header.Get("X-Upload-Signature")
	if nonce == "" || signature == "" || !validateNonceSignature(nonce, signature) {
		http.Error(w, "Invalid nonce or signature", http.StatusUnauthorized)
		return
	}

	// 限制上传大小
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	// 解析multipart表单
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	// 获取上传文件
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 检查文件类型
	if !isAllowedFileType(handler.Filename) {
		http.Error(w, "Invalid file type. Only images, videos, and audio files are allowed", http.StatusBadRequest)
		return
	}

	// 生成安全的文件名
	secureFilename := generateSecureFilename(handler.Filename)
	fullPath := filepath.Join(uploadDir, secureFilename)

	// 创建目标文件
	dst, err := os.Create(fullPath)
	if err != nil {
		http.Error(w, "Error creating file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// 复制文件内容
	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	if runtime.GOOS != "windows" {
		//设置文件夹权限
		if err := setFilePermissions(uploadDir); err != nil {
			log.Printf("设置文件夹权限失败: %v", err)
			// 不返回错误，因为文件已经上传成功
		}
		// 设置文件权限
		if err := setFilePermissions(fullPath); err != nil {
			log.Printf("设置文件权限失败: %v", err)
			// 不返回错误，因为文件已经上传成功
		}
	}

	// 获取文件类型
	fileType := getFileType(handler.Filename)

	// 获取磁盘使用情况
	diskUsage, err := getDiskUsage(uploadDir)
	var usedSize uint64
	if err != nil {
		log.Printf("获取磁盘使用情况失败: %v", err)
		// 如果获取失败，使用0作为默认值，不中断上传流程
		usedSize = 0
	} else {
		usedSize = diskUsage.Used
	}

	// 返回成功响应
	response := map[string]interface{}{
		"url":      strings.ReplaceAll(fmt.Sprintf("/%s", secureFilename), "\\", "/"),
		"filename": strings.ReplaceAll(secureFilename, "\\", "/"),
		"type":     fileType,
		"used":     usedSize,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"url":"%s","filename":"%s","type":"%s","used":%d}`,
		response["url"], response["filename"], response["type"], response["used"])
}

// diskUsageHandler 处理磁盘使用情况查询请求
func diskUsageHandler(w http.ResponseWriter, r *http.Request) {
	// 验证域名绑定
	if !validateHost(r.Host) {
		http.Error(w, "Forbidden: Host not bound to this server", http.StatusForbidden)
		return
	}

	// 处理跨域请求
	w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Upload-Secret-Key")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "86400") // 24小时

	// 处理OPTIONS请求
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// 只允许GET方法
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 验证密钥（可选，如果提供了密钥则验证）
	secretKey := r.Header.Get("X-Upload-Secret-Key")
	if secretKey != "" {
		if !validateSecretKey(secretKey) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// 获取磁盘使用情况
	diskUsage, err := getDiskUsage(uploadDir)
	if err != nil {
		http.Error(w, fmt.Sprintf("获取磁盘使用情况失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 返回JSON响应
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"total":%d,"used":%d,"free":%d}`,
		diskUsage.Total, diskUsage.Used, diskUsage.Free)
}

func validatePort(port string) error {
	// 去除可能的注释
	port = strings.Split(port, "#")[0]
	// 去除首尾空白
	port = strings.TrimSpace(port)

	portNum, err := strconv.Atoi(port)
	if err != nil {
		log.Printf("端口转换错误: %v, 原始端口: %s", err, port)
		return fmt.Errorf("端口号必须是数字")
	}

	log.Printf("验证端口号: %d", portNum)

	if portNum < 1024 || portNum > 65535 {
		log.Printf("端口号 %d 超出有效范围", portNum)
		return fmt.Errorf("端口号必须在1024-65535范围内")
	}

	return nil
}

// hostValidationMiddleware 域名绑定验证中间件
func hostValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validateHost(r.Host) {
			http.Error(w, "Forbidden: Host not bound to this server", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	// 确保上传目录存在
	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		log.Fatal("Cannot create upload directory:", err)
	}

	// 设置文件服务，允许访问上传的图片和视频
	fs := http.FileServer(http.Dir(uploadDir))
	http.Handle("/uploads/", hostValidationMiddleware(http.StripPrefix("/uploads", fs)))

	// 上传处理器
	http.HandleFunc("/upload-file", uploadHandler) // 移除末尾的斜杠

	// 磁盘使用情况查询处理器
	http.HandleFunc("/disk-usage", diskUsageHandler)

	// 日志输出初始 serverPort
	log.Printf("初始 serverPort: %s", serverPort)

	// 启动服务器
	port := ":" + serverPort

	// 验证端口号
	if err := validatePort(serverPort); err != nil {
		log.Printf("无效的端口号 %s: %v\n", serverPort, err)

		// 交互式输入端口号
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("请输入有效的端口号 (1024-65535): ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)

			if err := validatePort(input); err == nil {
				port = ":" + input
				serverPort = input
				break
			} else {
				fmt.Println("端口号无效，请重新输入。")
			}
		}
	}

	log.Printf("服务器启动，监听端口 %s", port)

	// 如果配置了SSL证书，使用HTTPS
	if sslCertFile != "" && sslKeyFile != "" {
		// 检查证书文件是否存在
		if _, err := os.Stat(sslCertFile); os.IsNotExist(err) {
			log.Fatalf("SSL证书文件不存在: %s", sslCertFile)
		}
		if _, err := os.Stat(sslKeyFile); os.IsNotExist(err) {
			log.Fatalf("SSL密钥文件不存在: %s", sslKeyFile)
		}

		log.Printf("使用HTTPS模式，证书文件: %s, 密钥文件: %s", sslCertFile, sslKeyFile)
		log.Fatal(http.ListenAndServeTLS(port, sslCertFile, sslKeyFile, nil))
	} else {
		log.Printf("使用HTTP模式")
		log.Fatal(http.ListenAndServe(port, nil))
	}
}

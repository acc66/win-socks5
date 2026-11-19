# Windows SOCKS5 代理

适用于 Windows 10 和 11。下载 Release 中与你的电脑架构匹配的 EXE，放到一个可写文件夹中，双击启动。无需安装 Go。

程序首次启动会在 EXE 同目录生成 `socks5.ini`，默认用户名为 `proxy`，密码随机生成。用记事本打开配置即可查看或修改用户名、密码和监听地址。保存为 UTF-8，重启 EXE 后生效。账号和密码各需 1–255 字节，使用纯 ASCII 便于兼容不同客户端。

默认监听 `0.0.0.0:1080`。本机使用 `127.0.0.1:1080`，其他设备使用运行代理的 Windows 电脑的 IP 地址和端口 `1080`。需要时在 Windows 防火墙中允许该程序在专用网络接收入站连接。

代理支持 SOCKS5 用户名密码认证和 TCP CONNECT。SOCKS5 本身不加密账号密码和流量，建议在可信网络内使用。

## 编译

使用 Go 1.24 或更新版本。Windows PowerShell 中运行：

```powershell
go build -trimpath -o win-socks5.exe .
```

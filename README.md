# 加密通信工具使用说明
该工具支持String Mode（字符串模式）和File Mode（文件模式）两种运行模式，集成了自主实现的RSA、AES、DES、MD5、SHA256等加密/哈希算法（无外部包依赖），所有中间过程和中间值均可通过下方output窗口查看。

## 项目任务示意图
![加密通信任务流程图]([https://github.com/213qwe/EncryptionTool/](https://github.com/213qwe/EncryptionTool/blob/main/task.png)

## 模式功能说明
### 1. String Mode（字符串模式）
| 功能项 | 操作说明 |
|--------|----------|
| 算法选择 | 通过“Algorithm：”下拉框选择对称加密算法，通过“Hash：”下拉框选择哈希算法 |
| 输入区域 | 左侧空白区域用于输入待传输的文本信息 |
| 文件导入 | 点击【Browse...】按钮可选择.txt格式文件，文件内容会显示在下方待传输内容区域（⚠️仅支持英文路径） |
| 素数位数设置 | 在素数p和q的位数输入框中指定位数（限制：64 ~ 4096位） |
| 密钥生成 | 点击【Generate Keys】按钮，自动生成对称密钥、RSA公私钥，并展示在【Sym Key】【Private Key】【Public Key】窗口 |
| 公钥导入 | 点击【Load Peer PubKey】按钮导入通信对方的公钥 |
| 私钥导入 | 点击【Load Own PrivKey】按钮导入自己的私钥 |
| 公钥保存 | 点击【Save PubKey】按钮保存生成的RSA公钥 |
| 私钥保存 | 点击【Save PrivKey】按钮保存生成的RSA私钥 |
| 消息收发 | 通过【Send】【Receive】按钮执行消息发送/接收操作 |

### 2. File Mode（文件模式）
| 功能项 | 操作说明 |
|--------|----------|
| 文件导入 | 点击【Browse】按钮选择待发送的文件（⚠️仅支持英文路径） |
| 其他功能 | 其余按钮、编辑框的功能与String Mode完全一致 |

## 开发环境配置（Visual Studio 2022）
### 1. OpenSSL 下载
从 https://slproweb.com/products/Win32OpenSSL.html 下载 OpenSSL-Win64 版本。

### 2. 项目创建与文件准备
- 打开 Visual Studio 2022，新建空项目；
- 将 main.c 文件复制到该空项目中。

### 3. 编译模式选择
选择 Release + x64 模式进行编译配置。

### 4. 系统配置（项目属性）
右键项目 → 属性 → 配置属性，依次完成以下配置：
#### C/C++ 配置
- 附加包含目录：添加 OpenSSL 的 include 路径（如 D:\OpenSSL-Win64\include）；
- 预处理器：添加 `OPENSSL_NO_ASM WIN32_LEAN_AND_MEAN NOMINMAX`；
- 高级：编译为 → 选择 “编译为 C++ 代码 (/TP) ”。

#### 链接器 配置
- 附加库目录：添加 OpenSSL 的 lib 路径（如 D:\OpenSSL-Win64\lib）；
- 输入 → 附加依赖项：添加 `libcrypto.lib Crypt32.lib comctl32.lib comdlg32.lib`；
- 系统：设置子系统为：窗口 (/SUBSYSTEM:WINDOWS)。

## 完整操作流程
### 前提
需为通信双方（A、B）分别生成并保存公私钥对

### 步骤
1. **基础配置**：选择对称加密算法、哈希算法，设置RSA素数p/q的位数；
2. **内容准备**：String Mode下输入待传输文本，File Mode下选择待传输文件；
3. **密钥生成**：点击【Generate Keys】生成对称密钥和RSA公私钥；
4. **密钥保存**：分别点击【Save PubKey】【Save PrivKey】保存RSA公私钥（A、B双方均需执行步骤3-4）；
5. **A端发送准备**：
   - 点击【Load Peer PubKey】导入B的公钥；
   - 点击【Load Own PrivKey】导入A的私钥；
   - 点击【Send】按钮发送消息，生成加密文件等传输内容；
6. **B端接收准备**：
   - 点击【Load Peer PubKey】导入A的公钥；
   - 点击【Load Own PrivKey】导入B的私钥；
   - 点击【Receive】按钮接收并解密消息，获取原始文件/文本。

## 注意事项
- 所有文件选择操作仅支持英文路径，中文路径会导致加载失败；
- RSA素数p/q位数需严格限制在64~4096位区间，超出范围会导致密钥生成失败；
- 公私钥需妥善保管，导入错误的密钥会导致解密失败；
- 所有加密/哈希算法均为自主实现，未调用外部加密库，保证算法可控性。

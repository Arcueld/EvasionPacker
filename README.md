## 免责声明

本项目（EvasionPacker）仅供安全研究和教育目的使用。严禁用于任何非法用途,并确保获得必要的授权

开发者不对任何使用后果承担责任 如因使用不当造成任何损失，均与开发者无关

使用本工具即表示您同意：

  \- 遵守相关法律法规

  \- 接受本免责声明的所有条款

  \- 承担所有使用后果

请在使用本工具前确保完全理解并接受以上声明。如有疑虑，请勿使用本工具。

## 介绍

基于`c/cpp`开发的 Shellcode 加密免杀框架，提供了一套完整的图形化配置界面，旨在帮助安全研究人员在授权渗透测试工作过程中快速生成所需免杀文件

### 主要特性

syscall 在开启时使用间接syscall 在关闭时动态调用NT函数

多种反沙箱方式

单exe/分离加载

签名窃取

资源文件添加(icon version)

多态化 确保每次生成的文件`HASH`不一致

### 静态效果

![image-20250220211035802](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202502202113510.png)

![image-20250220211650741](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202502202116877.png)

![image-20250220211657130](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202502202116216.png)

## 环境需求

`VisualStudio`

`python3`

## 安装

确保将VisualStudio的`devenv.com`添加进环境变量

安装python相关库

```cmd
pip install -r requirement.txt 
```

`python generator.py`拉起来就行了

我也懒得打包了

## TODO

`[√]` 多payload控制

`[√]` DisableETW

`[x]` 添加更多执行方式 反沙箱方式

`[x]` Hook NtAllocVirtualMemory Sleep 函数 接管beacon行为 进行内存隐藏

`[x]` 文件捆绑

`[x]` 远程拉取

`[x]` 不走syscall的话unhook

`[x]` shellcode格式处理 降熵值

## 致谢

本项目部分功能基于如下开源项目改动 感谢以下开源项目



https://github.com/aahmad097/AlternativeShellcodeExec

https://github.com/evilashz/PigSyscall

https://github.com/hfiref0x/UACME

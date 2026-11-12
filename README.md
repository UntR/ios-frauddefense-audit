# ios-frauddefense-audit

对 iOS 27.0.1（24A446）到 iOS 27.2.1（24B156）的离线固件调查。最初的问题是，这次升级是否加入了中国大陆专属的反诈组件，以及短信或 iMessage 正文有没有可能随后台任务上传。

**这条升级路径确实新增了苹果的垃圾信息防护扩展 `frauddefensepfl.appex`。** 在检查过的文件和配置里，未发现预装「国家反诈中心」App、中国大陆专属的反诈服务，或指向中国第三方的反诈上报地址。扩展具有「信息」数据访问权限，也有提交任务结果的配置。实际任务程序未在固件中找到，因而无法确认后台载荷是否包含消息正文或正文派生信息。

## 调查方法

1. 按设备的公开硬件型号和起始构建号定位苹果 CDN 的增量 OTA。在 Mac 上单独下载，解开 Apple Encrypted Archive，再提取升级前后的文件清单。用 `aa list` 列出 `pre.24A446.manifest` 和 `post.manifest` 中的路径，排序去重后用 `comm -13` 查新增项。
2. 从 OTA 内层载荷提取扩展、差分隐私配置和 TrustKit 回退配置。用 `plutil` 读配置，使用 `codesign` 检查扩展声明的权限，再结合动态导入和反汇编确认关键调用。
3. 从苹果 CDN 单独下载对应的 24B156 完整 IPSW，核对归档大小和 SHA-256。用开源 `ipsw` 工具从系统映像提取 dyld 缓存，检查 `PriMLFoundation`、`PrivateFederatedLearning` 和 `DifferentialPrivacy`，并从固件文件系统提取 `dprivacyd`、`DPSubmissionService`、`analyticsd` 和 `priMLConfig.json`。 [ipsw 提取文档](https://blacktop.github.io/ipsw/docs/guides/extract/)

本次下载的增量 OTA 为 **4,898,947,072 字节**。手机界面曾显示约 7 GB，界面采用的体积口径未核实。对比覆盖两个构建之间的累计变化，无法据此判断每个文件究竟首次出现在 27.2 还是 27.2.1。所有分析在 Mac 上进行，未安装或恢复固件，未运行扩展，未改动手机设置，也未向任务服务请求实际任务。

## 消息数据与提交路径

| 检查点 | 固件里的证据 |
| --- | --- |
| **消息读取权限** | 扩展声明 `com.apple.private.imcore.imdpersistence.database-access`。`PriMLDataPolicy.framework/DataPolicy.plist` 对 `com.apple.priml.pfl.frauddefensepfl:messages_spam_protection` 配置了 `messages.read = ["*"]`。这层策略没有排除正文。 |
| **联邦学习结果** | `DifferentialPrivacy/Configuration/Collections` 下对应的 plist 列出元数据、指标和结果三类记录，均设有 `DirectUpload = true` 和 `TelemetryAllowed = true`，分别指定 `PINEMetadata`、`PINEMetrics` 和 `PINEResults`。配置未列出载荷的逐字段定义。 |
| **任务从哪里来** | 扩展使用任务下载器和 `executePFLMorpheusProgram`。框架支持从 CloudKit 获取任务记录、配方和附件，配方以 `morpheusProgramFileName` 指定程序附件。在检查的固件资源中未找到该用例的实际配方或程序。扩展持有苹果生产 CloudKit 容器权限，三类结果的实际网络目的地未确认。 |
| **运行统计** | `priMLConfig.json` 为 `PFLPluginReach` 定义了错误码、错误域、任务 ID、用例、插件名、执行阶段和计数，配置为按设备采样、按日聚合并通过 OHTTP 提交。这份事件定义没有消息正文字段。 |
| **常规过滤与举报** | TrustKit 回退配置把 iMessage、SMS 和 RCS 的相关检测设为 `global`，举报地址指向苹果的 `concernreports.apple.com`。苹果说明常规垃圾过滤不会向苹果披露消息内容。手动举报 iMessage 会发送该条消息和发送者信息。 |

[苹果「信息」隐私说明](https://images.apple.com/legal/privacy/data/en/messages/) · [苹果手动举报说明](https://support.apple.com/en-lamr/guide/messages/icht8358c854/mac)

## 关闭「共享 iPhone 分析」会怎样

- **新任务。** `frauddefensepfl` 注册时传入 `PluginConsent.dnu`。iOS 框架通过 `MCProfileConnection.isDiagnosticSubmissionAllowed` 读取 `MCFeatureDiagnosticsSubmissionAllowed` 的有效值。许可关闭时，检查返回 `DNUNotEnabled` 错误，拦下受该条件约束的新任务。 [苹果设备分析隐私说明](https://www.apple.com/legal/privacy/data/en/device-analytics/)
- **旧队列。** 查到的 Dedisco 路径从数据库取记录，经 XPC 交给 `DPSubmissionService`，再由 `NSURLSession` 上传。记录入口有诊断许可检查。发送服务中的 `shouldAllowOHTTPExemptionForCollectionID:` 检查集合 ID 的传输豁免。已检查的发送路径中未找到发请求前重读开关的证据，也未找到关闭开关时清除这三类旧记录的路径。旧记录最终保留、删除还是发出，仍未确认。
- **任务被拒绝后的运行统计。** 框架能用 `PFLPluginReach` 记录执行阶段和错误。尚未确认 `DNUNotEnabled` 这条分支会生成该事件，也未确认 `analyticsd` 对该事件的日聚合发送如何应用用户同意状态。
- **「过滤垃圾信息」开关。** 未找到它直接控制这个联邦学习任务或其后台上传的证据。

## 地区相关发现

两个新增的 `ChinaDataErase.loctable` 已解出正文，内容是 HomePod 重置和覆盖擦除的多语言界面文案。已检查的 TrustKit 回退配置中，垃圾信息检测项标为全球适用。

Safari 的「欺骗性网站警告」有独立的地区行为。苹果披露，系统地区设为中国大陆或香港时，Safari 可能使用腾讯安全浏览。苹果称服务商收到的是从网址计算出的信息，实际网址不会共享给服务商，腾讯可能记录 IP 地址。此次调查没有将该功能归为 27.2.1 新增。 [苹果中国 Safari 隐私说明](https://www.apple.com.cn/legal/privacy/data/zh-cn/safari/)

## 证据边界

静态分析可以确认随包文件、声明权限、已解析的代码分支和配置。实际任务程序、服务端投放条件、设备运行状态和网络载荷不在本次证据范围内。**没有发现自动上传正文的证据，同时也没有逐字段验证后台任务的载荷。** 苹果公布的 27.2.1 安全修复包括 iMessage 群聊访问权限问题。 [苹果 27.2.1 安全公告](https://support.apple.com/en-hk/149715)

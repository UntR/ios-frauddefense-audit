# 离线复现指南 / Offline reproduction

本指南针对 iOS **24A446 → 24B156**。命令在 macOS 上运行，输入为自行取得的苹果 CDN 增量 OTA 和对应完整 IPSW。请使用与 OTA 匹配的公开提取密钥。本文的输出节选已去掉本机路径和设备标识。所有操作只读固件输入，解出的文件写到工作目录。

Run these commands on macOS using your own matching Apple CDN OTA and IPSW. The output excerpts below omit device identifiers and host paths.

## 1. 解包 OTA / Unpack the OTA

准备 `update.aea`，并将变量 `OTA_KEY` 设为该归档对应的公开提取密钥（Base64）。以下外层记录格式和块大小针对本次分析的归档。换用其他 OTA 时，先看 `outer.txt` 中的嵌套块大小。

```sh
aea decrypt -i update.aea -key-value "base64:${OTA_KEY:?set OTA_KEY}" -o update.raw
aa list -v -i update.raw > outer.txt 2>&1
rg 'DAT\[128540351\]|post\.manifest|pre\.24A446\.manifest' outer.txt
```

```text
M YOP=extract LBL=main DAT[128540351]
- F PAT=AssetData/post.manifest FLG DAT
- F PAT=AssetData/pre.24A446.manifest FLG DAT
```

外层是包含嵌套 Apple Archive 的容器。本次从外层记录取出清单所在的子归档，以及六个内层载荷所跨的子归档。下面的命令按外层头中的 `DAT` 长度读取，每次只把匹配的子归档交给 `aa extract`。

```sh
mkdir -p extracted selected
python3 - <<'PY'
import struct
import subprocess

wanted = {327316690, 209226199, 165532230, 198090226,
          195282646, 220409118, 128540351}
pattern = r'/payload\.[0-9]+$|AssetData/(pre\.24A446|post)\.manifest$'
with open("update.raw", "rb") as stream:
    while header := stream.read(6):
        assert len(header) == 6 and header[:4] == b"AA01"
        length = struct.unpack("<H", header[4:])[0] - 6
        fields = stream.read(length)
        assert len(fields) == length
        offset = fields.rfind(b"DAT")
        size = int.from_bytes(fields[offset + 4:], "little") if offset >= 0 else 0
        if size not in wanted:
            stream.seek(size, 1)
            continue
        with subprocess.Popen(
            ["aa", "extract", "-d", "extracted", "-include-regex", pattern],
            stdin=subprocess.PIPE,
        ) as child:
            remaining = size
            while remaining:
                block = stream.read(min(remaining, 4 * 1024 * 1024))
                assert block, "truncated nested archive"
                child.stdin.write(block)
                remaining -= len(block)
            child.stdin.close()
            assert child.wait() == 0
PY

for part in extracted/AssetData/payloadv2/payload.00[0-5]; do
  aa extract -i "$part" -d selected -include-regex \
    'frauddefensepfl|PriMLDataPolicy.framework/DataPolicy.plist|configurations_fallback_rave|ChinaDataErase'
done
```

## 2. 对比清单和配置 / Compare manifests and configuration

```sh
aa list -i extracted/AssetData/pre.24A446.manifest | LC_ALL=C sort -u > pre.txt
aa list -i extracted/AssetData/post.manifest | LC_ALL=C sort -u > post.txt
LC_ALL=C comm -13 pre.txt post.txt > added.txt
rg 'frauddefensepfl|ChinaDataErase' added.txt

extension=selected/System/Library/ExtensionKit/Extensions/frauddefensepfl.appex
codesign -d --entitlements - "$extension/frauddefensepfl" 2>&1 |
  rg 'database-access|prod.container'
plutil -p selected/System/Library/PrivateFrameworks/PriMLDataPolicy.framework/DataPolicy.plist |
  rg -A 7 'frauddefensepfl:messages_spam_protection'
plutil -p selected/System/Library/DifferentialPrivacy/Configuration/Collections/*frauddefensepfl*.plist
```

关键输出节选 / Selected output:

```text
System/Library/ExtensionKit/Extensions/frauddefensepfl.appex
System/Library/ExtensionKit/Extensions/frauddefensepfl.appex/frauddefensepfl
System/Library/DifferentialPrivacy/Configuration/Collections/com.apple.priml.pfl.frauddefensepfl.messages_spam_protection.plist
System/Library/PrivateFrameworks/Home.framework/HFSensitiveStrings-ChinaDataErase.loctable
System/Library/PrivateFrameworks/HomeUI.framework/HUSensitiveStrings-ChinaDataErase.loctable
[Key] com.apple.private.imcore.imdpersistence.database-access
[String] com.apple.priml.prod.container
```

配置输出摘要 / Configuration summary:

| Item | Value |
| --- | --- |
| `messages_spam_protection` policy | `messages: { read: ["*"] }` |
| Metadata, metrics, results | All set `DirectUpload = true` and `TelemetryAllowed = true` |
| Privacy algorithms | `PINEMetadata`, `PINEMetrics`, `PINEResults` |

用 `plutil -p` 也可直接核对两个 `ChinaDataErase.loctable` 的 HomePod 擦除文案，以及 TrustKit 回退配置中的 `global` 和苹果举报地址。读取权限和上传配置无法单独确定载荷字段。

## 3. 反汇编关键调用 / Disassemble key calls

`restore.ipsw` 是对应的完整固件。先核对下载摘要，再提取 dyld 缓存。若工具提示选择硬件变体，使用与所选 OTA 匹配的公开产品型号。

```sh
shasum -a 256 restore.ipsw
ipsw extract --dyld --device "${PRODUCT_TYPE:?set public product type}" -o dyld restore.ipsw
# Set DSC to the extracted main dyld cache file, beside its subcaches.
ipsw dyld extract "${DSC:?set DSC}" PriMLFoundation -o frameworks
ipsw dyld extract "$DSC" PrivateFederatedLearning -o frameworks
xcrun dyld_info -imports "$extension/frauddefensepfl" |
  rg 'PluginConsentV3dnu|performCustomConsent|makeDownloader|executePFLMorpheusProgram'

ipsw dyld disass "$DSC" --symbol-image PriMLFoundation --demangle -c 20 \
  --symbol '_$s15PriMLFoundation16ConsentTargetingO12isDNUEnabledSbyFZ'
ipsw dyld disass "$DSC" --symbol-image PriMLFoundation --demangle -c 45 \
  --symbol '_$s15PriMLFoundation16ConsentTargetingO9ensureDNUyyKFZ'
ipsw class-dump "$DSC" ManagedConfiguration --class '^MCProfileConnection$' --re -V |
  rg -B 2 'isDiagnosticSubmissionAllowed;'
```

对反汇编中未标注的调用，用 `ipsw dyld disass "$DSC" --vaddr <目标地址> -c 5` 查看对应的 Objective-C selector stub。用 class dump 给出的方法地址继续反汇编，即可看到下面这组调用关系。此处是去掉地址的输出摘要。

```text
ConsentTargeting.isDNUEnabled()
  MCProfileConnection → sharedConnection → isDiagnosticSubmissionAllowed
-[MCProfileConnection(Misc) isDiagnosticSubmissionAllowed]
  MCFeatureDiagnosticsSubmissionAllowed → effectiveBoolValueForSetting:
ConsentTargeting.ensureDNU()
  false branch → TaskDiscoveryError
```

可用以下命令找到 Dedisco 的入库和提交函数，以及运行遥测的原始配置。

```sh
ipsw dyld symaddr "$DSC" --image DifferentialPrivacy |
  rg 'shouldNotRecord:|reportDediscoRecords:|reportToDediscoRecords:|markSubmitted:'
ipsw extract --files --device "$PRODUCT_TYPE" \
  --pattern '/(DPSubmissionService|analyticsd|priMLConfig\.json)$' -o inspection restore.ipsw
find inspection -name priMLConfig.json -exec rg '"name":"PFLPluginReach"|submissionMode' {} +
```

`PFLPluginReach` 的输出配置为 `Daily`，提交模式为 `ohttp`。字段包括错误码、错误域、任务 ID、用例、插件、执行阶段及计数。这个配置无法证明拒绝分支一定会生成事件，也无法证明分析关闭后事件仍会发送。上述命令没有取得实际联邦学习任务程序，无法核对短信或 iMessage 正文是否进入任务载荷，也无法确认分析关闭后旧队列的实际命运。

[提取工具文档 / Extraction documentation](https://blacktop.github.io/ipsw/docs/guides/extract/)

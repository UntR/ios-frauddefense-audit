# ios-frauddefense-audit

[简体中文](README.md) · [Offline reproduction guide](REPRODUCE.md)

An offline firmware investigation of the upgrade from iOS 27.0.1 (24A446) to iOS 27.2.1 (24B156). It examines whether the upgrade adds a mainland China-specific anti-fraud component and whether background tasks can upload SMS or iMessage content.

**This upgrade adds Apple's `frauddefensepfl.appex` spam-protection extension.** The files and configurations examined showed no bundled National Anti-Fraud Center app, mainland China-specific anti-fraud service, or anti-fraud reporting endpoint operated by a Chinese third party. The extension has access to Messages data, and its configuration permits submission of task output. The actual task program was absent from the firmware resources examined, so whether those submissions contain message bodies or data derived from them remains unknown.

## Method

1. Locate the matching incremental OTA on Apple's CDN using the public hardware model and starting build. Download it separately on a Mac and unpack the Apple Encrypted Archive. List paths from `pre.24A446.manifest` and `post.manifest` with `aa list`, sort and deduplicate them, then use `comm -13` to identify additions.
2. Extract the extension, differential privacy configuration, and TrustKit fallback configuration from the OTA payload. Read property lists with `plutil`, inspect declared entitlements with `codesign`, and trace key calls through dynamic imports and disassembly.
3. Download the matching full 24B156 IPSW from Apple's CDN and verify its size and SHA-256. Use the open-source `ipsw` tool to extract the dyld shared cache and inspect `PriMLFoundation`, `PrivateFederatedLearning`, and `DifferentialPrivacy`. Extract `dprivacyd`, `DPSubmissionService`, `analyticsd`, and `priMLConfig.json` from the firmware filesystem. [ipsw extraction documentation](https://blacktop.github.io/ipsw/docs/guides/extract/)

The incremental OTA was **4,898,947,072 bytes**. The update screen showed about 7 GB, and how it calculated that figure was not verified. The comparison covers cumulative changes between the two builds, so it cannot establish which individual files first shipped in 27.2 or 27.2.1. All analysis ran on a Mac. No firmware was installed or restored, no extension was run, no phone settings were changed, and no live task was requested.

## Messages data and submission paths

| Area | Firmware evidence |
| --- | --- |
| **Read access** | The extension declares `com.apple.private.imcore.imdpersistence.database-access`. `PriMLDataPolicy.framework/DataPolicy.plist` sets `messages.read = ["*"]` for `com.apple.priml.pfl.frauddefensepfl:messages_spam_protection`. This policy does not exclude message bodies. |
| **Federated learning output** | The collection plist under `DifferentialPrivacy/Configuration/Collections` defines metadata, metrics, and results. Each sets `DirectUpload = true` and `TelemetryAllowed = true`, with `PINEMetadata`, `PINEMetrics`, and `PINEResults` respectively. The plist does not define the individual payload fields. |
| **Task delivery** | The extension uses a task downloader and `executePFLMorpheusProgram`. The framework can retrieve task records, recipes, and attachments from CloudKit. A recipe names its program attachment through `morpheusProgramFileName`. The resources examined did not contain the recipe or program for this use case. The extension has entitlements for an Apple production CloudKit container. The actual network destination for the three output categories remains unverified. |
| **Operational telemetry** | `priMLConfig.json` defines error code, error domain, task ID, use case, plugin, execution stage, and count for `PFLPluginReach`. It configures per-device sampling, daily aggregation, and OHTTP submission. This event definition contains no message-body field. |
| **Filtering and manual reports** | The TrustKit fallback configuration marks relevant iMessage, SMS, and RCS checks as `global` and points reporting to Apple's `concernreports.apple.com`. Apple says routine spam filtering does not disclose message content to Apple. Manually reporting an iMessage sends the reported message and sender information to Apple. |

[Apple's Messages privacy notice](https://images.apple.com/legal/privacy/data/en/messages/) · [Apple's manual reporting documentation](https://support.apple.com/en-lamr/guide/messages/icht8358c854/mac)

## What turning off Share iPhone Analytics changes

- **New tasks.** The extension registers with `PluginConsent.dnu`. The iOS framework calls `MCProfileConnection.isDiagnosticSubmissionAllowed`, which reads the effective value of `MCFeatureDiagnosticsSubmissionAllowed`. With permission disabled, the check raises `DNUNotEnabled` and blocks new tasks subject to that condition. [Apple's Device Analytics privacy notice](https://www.apple.com/legal/privacy/data/en/device-analytics/)
- **Queued records.** The traced Dedisco path reads records from a database, hands them to `DPSubmissionService` over XPC, and uploads via `NSURLSession`. The recording entry point checks diagnostic permission. The submission service's `shouldAllowOHTTPExemptionForCollectionID:` checks a transport exemption by collection ID. The inspected send path did not show a fresh check of the user setting before the request, and no opt-out purge path was identified for the three record categories. Whether existing records are retained, cleared, or sent remains unverified.
- **Telemetry after task rejection.** The framework can record execution stages and errors through `PFLPluginReach`. It remains unverified whether the `DNUNotEnabled` branch emits this event and how `analyticsd` applies user consent to its daily submission route.
- **Filter Spam.** No direct link was found between this setting and the federated learning task or its background submissions.

## Region-specific findings

Two newly added `ChinaDataErase.loctable` files contain multilingual text for resetting and overwriting HomePod storage. The spam checks in the inspected TrustKit fallback configuration are marked as global.

Safari's Fraudulent Website Warning has separate regional behavior. Apple discloses that Safari may use Tencent Safe Browsing when the system region is set to mainland China or Hong Kong. Apple says the provider receives information calculated from the website address, the actual address is not shared, and Tencent may log the IP address. This investigation did not establish this feature as a 27.2.1 addition. [Apple China Safari privacy notice](https://www.apple.com.cn/legal/privacy/data/zh-cn/safari/)

## Limits of the evidence

Static analysis establishes shipped files, declared entitlements, inspected code branches, and configuration. It did not establish the live task program, server-side rollout conditions, runtime device state, or network payloads. **No evidence of automatic message-body uploads was found, and the background task payload was not verified field by field.** Apple's published 27.2.1 security fixes include iMessage group-chat access controls. [Apple's 27.2.1 security advisory](https://support.apple.com/en-hk/149715)

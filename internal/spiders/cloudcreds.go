package spiders

import (
	"github.com/cleverg0d/cyberheap/internal/heap"
)

// cloudCredsSpider extracts object-storage and cloud-IAM credentials that
// Java SDKs keep on in-memory credential objects:
//
//   - AWS SDK v1 & v2 (BasicAWSCredentials, BasicSessionCredentials, AwsBasicCredentials)
//   - Aliyun OSS (OSSClient, DefaultCredentials, BasicCredentials)
//   - Aliyun Core SDK (BasicCredentials, BasicSessionCredentials, RamRoleArnCredential)
//   - Alibaba Cloud credentials-java (AccessKeyCredential)
//   - Huawei OBS (ObsClient BasicObsCredentialsProvider)
type cloudCredsSpider struct{}

func (s *cloudCredsSpider) Name() string     { return "cloudcreds" }
func (s *cloudCredsSpider) Category() string { return "cloud" }

// target describes one Java class and the field names its SDK uses for
// the pair (id/key, secret). We keep it data-driven so adding a new SDK
// is a single table row.
type cloudTarget struct {
	fqn          string
	title        string
	idField      string   // "accessKeyId", "awsAccessKeyId", "accessKey", ...
	secretField  string   // "secretKey", "awsSecretKey", ...
	sessionField string   // optional STS session token field
	extraFields  []string // extra attribution fields (region, endpoint, ...)
}

var cloudTargets = []cloudTarget{
	// --- AWS SDK v1 ---
	{
		fqn: "com.amazonaws.auth.BasicAWSCredentials", title: "AWS SDK v1 credentials",
		idField: "accessKey", secretField: "secretKey",
	},
	{
		fqn: "com.amazonaws.auth.BasicSessionCredentials", title: "AWS SDK v1 session credentials",
		idField: "accessKey", secretField: "secretKey", sessionField: "sessionToken",
	},
	// --- AWS SDK v2 ---
	{
		fqn: "software.amazon.awssdk.auth.credentials.AwsBasicCredentials", title: "AWS SDK v2 credentials",
		idField: "accessKeyId", secretField: "secretAccessKey",
	},
	{
		fqn: "software.amazon.awssdk.auth.credentials.AwsSessionCredentials", title: "AWS SDK v2 session credentials",
		idField: "accessKeyId", secretField: "secretAccessKey", sessionField: "sessionToken",
	},
	// --- Aliyun OSS ---
	{
		fqn: "com.aliyun.oss.common.auth.DefaultCredentials", title: "Aliyun OSS credentials",
		idField: "accessKeyId", secretField: "secretAccessKey", sessionField: "securityToken",
	},
	{
		fqn: "com.aliyun.oss.common.auth.BasicCredentials", title: "Aliyun OSS basic credentials",
		idField: "accessKeyId", secretField: "secretAccessKey", sessionField: "securityToken",
	},
	// --- Aliyun Core SDK ---
	{
		fqn: "com.aliyuncs.auth.BasicCredentials", title: "Aliyun Core SDK credentials",
		idField: "accessKeyId", secretField: "accessKeySecret",
	},
	{
		fqn: "com.aliyuncs.auth.BasicSessionCredentials", title: "Aliyun Core SDK session credentials",
		idField: "accessKeyId", secretField: "accessKeySecret", sessionField: "sessionToken",
	},
	// --- Alibaba credentials-java ---
	{
		fqn: "com.aliyun.credentials.models.AccessKeyCredential", title: "Alibaba AccessKey credential",
		idField: "accessKeyId", secretField: "accessKeySecret",
	},
	// --- Huawei OBS ---
	{
		fqn: "com.obs.services.model.PartialObjectMetadata", title: "Huawei OBS credentials",
		idField: "accessKey", secretField: "secretKey",
	},
	{
		fqn: "com.obs.services.internal.security.BasicSecurityKey", title: "Huawei OBS security key",
		idField: "accessKey", secretField: "secretKey", sessionField: "securityToken",
	},
	// --- Tencent Cloud COS ---
	{
		fqn: "com.qcloud.cos.auth.BasicCOSCredentials", title: "Tencent COS credentials",
		idField: "accessKey", secretField: "secretKey",
	},
	{
		fqn: "com.qcloud.cos.auth.BasicSessionCredentials", title: "Tencent COS session credentials",
		idField: "accessKey", secretField: "secretKey", sessionField: "sessionToken",
	},
}

func (s *cloudCredsSpider) Sniff(idx *heap.Index) []Finding {
	var out []Finding
	seen := map[uint64]bool{}

	for _, t := range cloudTargets {
		for _, cls := range idx.Subclasses(t.fqn) {
			for _, inst := range idx.Instances[cls.ID] {
				if seen[inst.ID] {
					continue
				}
				seen[inst.ID] = true

				var fields []Field
				var id, secret string
				if v, err := idx.ReadField(inst, t.idField); err == nil && !v.IsNull() {
					if s, ok := idx.ReadString(v.ObjectID); ok && s != "" {
						fields = append(fields, Field{Name: t.idField, Value: s})
						id = s
					}
				}
				if v, err := idx.ReadField(inst, t.secretField); err == nil && !v.IsNull() {
					if s, ok := idx.ReadString(v.ObjectID); ok && s != "" {
						fields = append(fields, Field{Name: t.secretField, Value: s})
						secret = s
					}
				}
				if t.sessionField != "" {
					if v, err := idx.ReadField(inst, t.sessionField); err == nil && !v.IsNull() {
						if s, ok := idx.ReadString(v.ObjectID); ok && s != "" {
							fields = append(fields, Field{Name: t.sessionField, Value: s})
						}
					}
				}
				for _, extra := range t.extraFields {
					if v, err := idx.ReadField(inst, extra); err == nil && !v.IsNull() {
						if s, ok := idx.ReadString(v.ObjectID); ok && s != "" {
							fields = append(fields, Field{Name: extra, Value: s})
						}
					}
				}

				if id == "" || secret == "" {
					continue
				}
				out = append(out, Finding{
					Spider:   "cloudcreds",
					Severity: SeverityHigh,
					Category: "cloud",
					Title:    t.title,
					ClassFQN: cls.Name,
					ObjectID: inst.ID,
					Fields:   fields,
				})
			}
		}
	}
	return out
}

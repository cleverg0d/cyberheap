package spiders

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTagDefaultAndWeak(t *testing.T) {
	cases := []struct {
		name      string
		fields    []Field
		wantFlags []string
	}{
		{
			name: "admin/admin → default only (mutually exclusive with weak)",
			fields: []Field{
				{Name: "username", Value: "admin"},
				{Name: "password", Value: "admin"},
			},
			wantFlags: []string{"default-creds"},
		},
		{
			name: "tradeControl admin/admin prefixed names → default only",
			fields: []Field{
				{Name: "tradeControlUsername", Value: "admin"},
				{Name: "tradeControlPassword", Value: "admin"},
			},
			wantFlags: []string{"default-creds"},
		},
		{
			name: "root/root → default only",
			fields: []Field{
				{Name: "username", Value: "root"},
				{Name: "password", Value: "root"},
			},
			wantFlags: []string{"default-creds"},
		},
		{
			name: "user/password → weak (not default)",
			fields: []Field{
				{Name: "username", Value: "user"},
				{Name: "password", Value: "password"},
			},
			wantFlags: []string{"weak"},
		},
		{
			name: "admin/Qwerty → weak (not default)",
			fields: []Field{
				{Name: "username", Value: "admin"},
				{Name: "password", Value: "Qwerty"},
			},
			wantFlags: []string{"weak"},
		},
		{
			name: "client/secret → weak (not default)",
			fields: []Field{
				{Name: "username", Value: "client"},
				{Name: "password", Value: "secret"},
			},
			wantFlags: []string{"weak"},
		},
		{
			name: "strong unique pass → no flags",
			fields: []Field{
				{Name: "username", Value: "appuser"},
				{Name: "password", Value: "Xk7Qr2Bt9Wp4Mn8Yc3Ze"},
			},
			wantFlags: nil,
		},
		{
			name:   "no password → no flag",
			fields: []Field{{Name: "username", Value: "alice"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := []Finding{{Fields: c.fields}}
			out := TagDefaultAndWeak(findings)
			assert.Equal(t, c.wantFlags, out[0].Flags)
		})
	}
}

func TestClassifyBasicAuth(t *testing.T) {
	assert.Equal(t, "default-creds", ClassifyBasicAuth("admin:admin"))
	assert.Equal(t, "default-creds", ClassifyBasicAuth("root:root"))
	assert.Equal(t, "weak", ClassifyBasicAuth("client:secret"))
	assert.Equal(t, "weak", ClassifyBasicAuth("user:password"))
	assert.Equal(t, "weak", ClassifyBasicAuth("admin:Qwerty"))
	assert.Equal(t, "", ClassifyBasicAuth("serviceaccount:Xk7Qr2Bt9Wp4"))
	assert.Equal(t, "", ClassifyBasicAuth("noColonAtAll"))
}

/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	vault "github.com/hashicorp/vault/api"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/providers/v1/vault/fake"
	vaultutil "github.com/external-secrets/external-secrets/providers/v1/vault/util"
)

// staticCreds returns a fixed set of AWS credentials for signing, standing in
// for whatever cfg.Credentials.Retrieve resolved at runtime.
func staticCreds() awssdk.Credentials {
	return awssdk.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "session-token",
	}
}

func TestLoginWithIamCreds(t *testing.T) {
	tests := []struct {
		name          string
		iamAuth       *esv1.VaultIamAuth
		writeErr      error
		writeResult   map[string]any
		wantPath      string
		wantRole      string
		wantHeader    bool
		wantHeaderVal string
		wantToken     string
		wantErr       bool
	}{
		{
			name: "posts signed login data to the configured mount",
			iamAuth: &esv1.VaultIamAuth{
				Role: "my-role",
			},
			writeResult: map[string]any{},
			wantPath:    "auth/aws-mount/login",
			wantRole:    "my-role",
			wantToken:   "hvs.token-abc",
		},
		{
			name: "adds the server-id header when configured",
			iamAuth: &esv1.VaultIamAuth{
				Role:                "my-role",
				VaultAWSIAMServerID: "vault.example.com",
			},
			writeResult:   map[string]any{},
			wantPath:      "auth/aws-mount/login",
			wantRole:      "my-role",
			wantHeader:    true,
			wantHeaderVal: "vault.example.com",
			wantToken:     "hvs.token-abc",
		},
		{
			name: "returns error when the login write fails",
			iamAuth: &esv1.VaultIamAuth{
				Role: "my-role",
			},
			writeErr: errors.New("vault unreachable"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			var gotData map[string]any
			var gotToken string
			gotHeaders := map[string]string{}

			logical := fake.Logical{
				WriteWithContextFn: func(_ context.Context, path string, data map[string]any) (*vault.Secret, error) {
					gotPath = path
					gotData = data
					if tt.writeErr != nil {
						return nil, tt.writeErr
					}
					return &vault.Secret{Auth: &vault.SecretAuth{ClientToken: "hvs.token-abc"}}, nil
				},
			}
			vc := &vaultutil.VaultClient{
				SetTokenFunc: func(v string) { gotToken = v },
				AddHeaderFunc: func(key, value string) {
					gotHeaders[key] = value
				},
				LogicalField: logical,
			}

			c := &client{
				client:  vc,
				logical: logical,
			}

			err := c.loginWithIamCreds(context.Background(), staticCreds(), tt.iamAuth, "aws-mount", "us-east-1")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotPath != tt.wantPath {
				t.Errorf("login path: got %q, want %q", gotPath, tt.wantPath)
			}
			if role, _ := gotData["role"].(string); role != tt.wantRole {
				t.Errorf("role: got %q, want %q", role, tt.wantRole)
			}
			// GenerateLoginData must have produced the signed STS request fields.
			for _, k := range []string{"iam_http_request_method", "iam_request_url", "iam_request_headers", "iam_request_body"} {
				if _, ok := gotData[k]; !ok {
					t.Errorf("login data missing expected key %q", k)
				}
			}
			if gotToken != tt.wantToken {
				t.Errorf("token: got %q, want %q", gotToken, tt.wantToken)
			}
			if tt.wantHeader {
				if gotHeaders[iamServerIDHeader] != tt.wantHeaderVal {
					t.Errorf("server-id header: got %q, want %q", gotHeaders[iamServerIDHeader], tt.wantHeaderVal)
				}
			} else if _, ok := gotHeaders[iamServerIDHeader]; ok {
				t.Errorf("server-id header set unexpectedly: %q", gotHeaders[iamServerIDHeader])
			}
		})
	}
}

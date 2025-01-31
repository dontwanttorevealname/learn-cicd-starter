package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}{
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-api-key"},
			},
			wantAPIKey: "test-api-key",
			wantErr:    nil,
		},
		{
			name:       "missing authorization header",
			headers:    http.Header{},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer test-api-key"},
			},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name: "malformed header - no value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name: "multiple authorization headers",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-api-key-1", "ApiKey test-api-key-2"},
			},
			wantAPIKey: "test-api-key-1",
			wantErr:    nil,
		},
		{
			name: "authorization header with extra spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey    test-api-key   "},
			},
			wantAPIKey: "test-api-key",
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAPIKey, gotErr := GetAPIKey(tt.headers)

			if tt.wantErr != nil && gotErr == nil {
				t.Errorf("GetAPIKey() expected error %v, got nil", tt.wantErr)
				return
			}
			if tt.wantErr == nil && gotErr != nil {
				t.Errorf("GetAPIKey() expected no error, got %v", gotErr)
				return
			}
			if tt.wantErr != nil && gotErr != nil && tt.wantErr.Error() != gotErr.Error() {
				t.Errorf("GetAPIKey() expected error %v, got %v", tt.wantErr, gotErr)
				return
			}

			if gotAPIKey != tt.wantAPIKey {
				t.Errorf("GetAPIKey() = %v, want %v", gotAPIKey, tt.wantAPIKey)
			}
		})
	}
}

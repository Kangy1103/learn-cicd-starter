package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	malformedHeaderErr := errors.New("malformed authorization header")
	tests := []struct {
		name       string
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}{
		{
			name:       "valid API key",
			headers:    http.Header{"Authorization": []string{"ApiKey abc123"}},
			wantAPIKey: "abc123",
		},
		{
			name:    "missing authorization header",
			headers: make(http.Header),
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "nil headers",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "authorization header with no key",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantErr: malformedHeaderErr,
		},
		{
			name:    "authorization header without a scheme",
			headers: http.Header{"Authorization": []string{"abc123"}},
			wantErr: malformedHeaderErr,
		},
		{
			name:    "unsupported authorization scheme",
			headers: http.Header{"Authorization": []string{"Bearer abc123"}},
			wantErr: malformedHeaderErr,
		},
		{
			name:    "authorization scheme is case-sensitive",
			headers: http.Header{"Authorization": []string{"apikey abc123"}},
			wantErr: malformedHeaderErr,
		},
		{
			name:    "empty authorization header",
			headers: http.Header{"Authorization": []string{""}},
			wantErr: ErrNoAuthHeaderIncluded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotAPIKey, gotErr := GetAPIKey(test.headers)

			gotErrText := ""
			if gotErr != nil {
				gotErrText = gotErr.Error()
			}
			wantErrText := ""
			if test.wantErr != nil {
				wantErrText = test.wantErr.Error()
			}

			passed := gotAPIKey == test.wantAPIKey && gotErrText == wantErrText
			if test.wantErr == ErrNoAuthHeaderIncluded && !errors.Is(gotErr, ErrNoAuthHeaderIncluded) {
				passed = false
			}

			status := "FAIL"
			if passed {
				status = "PASS"
			}
			message := "%s: expected key=%q, error=%q; actual key=%q, error=%q"
			if passed {
				t.Logf(message, status, test.wantAPIKey, wantErrText, gotAPIKey, gotErrText)
				return
			}
			t.Errorf(message, status, test.wantAPIKey, wantErrText, gotAPIKey, gotErrText)
		})
	}
}

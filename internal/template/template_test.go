package template

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRender(t *testing.T) {
	tests := []struct {
		name    string
		tmpl    string
		secrets map[string]string
		want    string
		wantErr string
	}{
		{
			name:    "basic substitution",
			tmpl:    "key={{API_KEY}} pass={{DB_PASSWORD}}",
			secrets: map[string]string{"API_KEY": "abc123", "DB_PASSWORD": "s3cret"},
			want:    "key=abc123 pass=s3cret",
		},
		{
			name:    "no placeholders",
			tmpl:    "no placeholders here",
			secrets: map[string]string{"FOO": "bar"},
			want:    "no placeholders here",
		},
		{
			name:    "missing secrets",
			tmpl:    "{{FOO}} {{BAR}} {{BAZ}}",
			secrets: map[string]string{"FOO": "ok"},
			wantErr: "BAR",
		},
		{
			name:    "partial braces ignored",
			tmpl:    "{{ not valid }} and {NOPE} and {{OK}}",
			secrets: map[string]string{"OK": "yes"},
			want:    "{{ not valid }} and {NOPE} and yes",
		},
		{
			name:    "repeated key",
			tmpl:    "{{X}}-{{X}}-{{X}}",
			secrets: map[string]string{"X": "v"},
			want:    "v-v-v",
		},
		{
			name:    "empty value",
			tmpl:    "before{{KEY}}after",
			secrets: map[string]string{"KEY": ""},
			want:    "beforeafter",
		},
		{
			name:    "special chars in value",
			tmpl:    "val={{SECRET}}",
			secrets: map[string]string{"SECRET": `"quotes" & <xml> 'yaml': {json}`},
			want:    `val="quotes" & <xml> 'yaml': {json}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Render(tt.tmpl, tt.secrets)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

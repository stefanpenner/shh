package merge

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeSecrets(t *testing.T) {
	tests := []struct {
		name       string
		ancestor   map[string]string
		ours       map[string]string
		theirs     map[string]string
		want       map[string]string
		wantConf   []string
		wantErr    bool
	}{
		{
			name:     "no conflict, both add different keys",
			ancestor: map[string]string{"A": "1"},
			ours:     map[string]string{"A": "1", "B": "2"},
			theirs:   map[string]string{"A": "1", "C": "3"},
			want:     map[string]string{"A": "1", "B": "2", "C": "3"},
		},
		{
			name:     "both add same value",
			ancestor: map[string]string{},
			ours:     map[string]string{"A": "1"},
			theirs:   map[string]string{"A": "1"},
			want:     map[string]string{"A": "1"},
		},
		{
			name:     "conflicting edit",
			ancestor: map[string]string{"A": "1"},
			ours:     map[string]string{"A": "2"},
			theirs:   map[string]string{"A": "3"},
			wantConf: []string{"A"},
			wantErr:  true,
		},
		{
			name:     "both add different values",
			ancestor: map[string]string{},
			ours:     map[string]string{"A": "1"},
			theirs:   map[string]string{"A": "2"},
			wantConf: []string{"A"},
			wantErr:  true,
		},
		{
			name:     "one deletes unchanged",
			ancestor: map[string]string{"A": "1", "B": "2"},
			ours:     map[string]string{"A": "1"},
			theirs:   map[string]string{"A": "1", "B": "2"},
			want:     map[string]string{"A": "1"},
		},
		{
			name:     "delete vs modify",
			ancestor: map[string]string{"A": "1"},
			ours:     map[string]string{},
			theirs:   map[string]string{"A": "2"},
			wantConf: []string{"A"},
			wantErr:  true,
		},
		{
			name:     "only ours changed",
			ancestor: map[string]string{"A": "1"},
			ours:     map[string]string{"A": "2"},
			theirs:   map[string]string{"A": "1"},
			want:     map[string]string{"A": "2"},
		},
		{
			name:     "only theirs changed",
			ancestor: map[string]string{"A": "1"},
			ours:     map[string]string{"A": "1"},
			theirs:   map[string]string{"A": "2"},
			want:     map[string]string{"A": "2"},
		},
		{
			name:     "both delete",
			ancestor: map[string]string{"A": "1"},
			ours:     map[string]string{},
			theirs:   map[string]string{},
			want:     map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, conflicts, err := MergeSecrets(tt.ancestor, tt.ours, tt.theirs)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tt.wantConf, conflicts)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestMergeStringMaps(t *testing.T) {
	tests := []struct {
		name     string
		ancestor map[string]string
		ours     map[string]string
		theirs   map[string]string
		want     map[string]string
	}{
		{
			name:     "union of additions",
			ancestor: map[string]string{},
			ours:     map[string]string{"A": "1"},
			theirs:   map[string]string{"B": "2"},
			want:     map[string]string{"A": "1", "B": "2"},
		},
		{
			name:     "deletion by one side",
			ancestor: map[string]string{"A": "1", "B": "2"},
			ours:     map[string]string{"A": "1"},
			theirs:   map[string]string{"A": "1", "B": "2"},
			want:     map[string]string{"A": "1"},
		},
		{
			name:     "both delete",
			ancestor: map[string]string{"A": "1"},
			ours:     map[string]string{},
			theirs:   map[string]string{},
			want:     map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergeStringMaps(tt.ancestor, tt.ours, tt.theirs)
			assert.Equal(t, tt.want, result)
		})
	}
}

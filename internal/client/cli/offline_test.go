package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/app"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

func TestReads_OfflineAndStale(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		stale       bool
		warnings    []string
		wantOffline bool
		wantWarning string
	}{
		{"list online", []string{"list"}, false, nil, false, ""},
		{"list stale", []string{"list"}, true, nil, false, "showing cached data"},
		{"list offline", []string{"list", "--offline"}, true, nil, true, "showing cached data"},
		{"list cache warning", []string{"list"}, false, []string{"local cache was reset"}, false, "local cache was reset"},
		{"get online", []string{"get", "mail"}, false, nil, false, ""},
		{"get stale", []string{"get", "mail"}, true, nil, false, "showing cached data"},
		{"get offline", []string{"get", "--offline", "mail"}, true, nil, true, "showing cached data"},
		{"sync stale", []string{"sync"}, true, nil, false, "showing cached data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			items := []app.Item{item("id-1", "mail", domain.TypeText, 1)}
			h.vault.list = app.ListResult{Items: items, Stale: tt.stale, Warnings: tt.warnings}
			h.vault.found = h.vault.list
			h.vault.entry = newEntry("id-1", 1, secretOf("mail", domain.Text("hello")))
			h.vault.entry.Stale, h.vault.entry.Warnings = tt.stale, tt.warnings

			assert.Equal(t, 0, h.run(tt.args...), h.term.errOut.String())

			assert.Equal(t, tt.wantOffline, h.vault.listRO.Offline || h.vault.getRO.Offline)
			assert.Contains(t, h.term.out.String(), "mail", "данные печатаются в stdout")
			if tt.wantWarning == "" {
				assert.Empty(t, h.term.errOut.String())
				return
			}
			assert.Contains(t, h.term.errOut.String(), tt.wantWarning, "предупреждение идёт в stderr")
			assert.NotContains(t, h.term.out.String(), "warning")
		})
	}
}

func TestOfflineRejectedOnOtherCommands(t *testing.T) {
	for _, args := range [][]string{
		{"add", "text", "--name", "n", "--offline"},
		{"update", "--offline", "mail"},
		{"delete", "--offline", "mail"},
		{"sync", "--offline"},
	} {
		t.Run(args[0], func(t *testing.T) {
			h := newHarness(t)
			assert.Equal(t, 2, h.run(args...), h.term.errOut.String())
			assert.Empty(t, h.vault.added)
			assert.Zero(t, h.vault.updateCalls+h.vault.deleteCalls)
		})
	}
}

func TestWrites_PrintCacheWarnings(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"add", []string{"add", "text", "--name", "n"}, "added"},
		{"update", []string{"update", "mail"}, "updated"},
		{"delete", []string{"delete", "--yes", "mail"}, "deleted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.entry = newEntry("id-1", 1, secretOf("mail", domain.Text("x")))
			h.vault.writeWarnings = []string{"local cache was not updated"}
			h.term.lines = []string{"hello", "", "", ""}

			assert.Equal(t, 0, h.run(tt.args...), h.term.errOut.String())

			assert.Contains(t, h.term.out.String(), tt.want)
			assert.Contains(t, h.term.errOut.String(), "local cache was not updated")
		})
	}
}

func TestUpdateDelete_RequireOnlineLookup(t *testing.T) {
	for _, args := range [][]string{{"update", "mail"}, {"delete", "--yes", "mail"}} {
		t.Run(args[0], func(t *testing.T) {
			h := newHarness(t)
			h.vault.entry = newEntry("id-1", 1, secretOf("mail", domain.Text("x")))
			h.term.lines = []string{"", "", ""}

			h.run(args...)

			assert.True(t, h.vault.getRO.RequireOnline, "запись не должна опираться на устаревший кэш")
			assert.False(t, h.vault.getRO.Offline)
		})
	}
}

package api

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/rdeb/local-image-registry/internal/store"
)

// auditCSV streams matching entries (up to 50k, newest first) for compliance export.
func (a *API) auditCSV(w http.ResponseWriter, f store.AuditFilter) {
	f.Limit = 50000
	entries, err := a.opt.Store.QueryAudit(f)
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-`+time.Now().UTC().Format("20060102-150405")+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "time", "actor", "role", "action", "target", "outcome", "ip", "detail"})
	for _, e := range entries {
		d := ""
		if len(e.Detail) > 0 {
			b, _ := json.Marshal(e.Detail)
			d = string(b)
		}
		_ = cw.Write([]string{strconv.FormatInt(e.ID, 10), e.Time.Format(time.RFC3339), csvSafe(e.Actor), e.ActorRole, e.Action, csvSafe(e.Target), e.Outcome, e.IP, csvSafe(d)})
	}
	cw.Flush()
}

// csvSafe defuses spreadsheet formula injection: attacker-controlled text (usernames, repo names)
// must not start with a character Excel/Sheets would evaluate.
func csvSafe(s string) string {
	if s != "" && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' || s[0] == '\t' || s[0] == '\r') {
		return "'" + s
	}
	return s
}

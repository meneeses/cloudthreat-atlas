package server

import (
	"net/http"

	"github.com/meneeses/cloudthreat-atlas/internal/workspace"
)

func (a *API) triage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snapshotID := r.URL.Query().Get("snapshot_id")
		if snapshotID == "" {
			writeError(w, http.StatusBadRequest, "snapshot_id is required")
			return
		}
		records, err := a.store.Triage(r.Context(), snapshotID)
		if err != nil {
			writeWorkspaceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"snapshotId": snapshotID, "triage": records})
	case http.MethodPatch:
		var request struct {
			SnapshotID string                 `json:"snapshotId"`
			FindingID  string                 `json:"findingId"`
			Status     workspace.TriageStatus `json:"status"`
			Notes      string                 `json:"notes"`
		}
		if err := decodeJSONBody(r.Body, 64<<10, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid triage request: "+err.Error())
			return
		}
		if request.SnapshotID == "" || request.FindingID == "" {
			writeError(w, http.StatusBadRequest, "snapshotId and findingId are required")
			return
		}
		record, err := a.store.UpdateTriage(r.Context(), request.SnapshotID, request.FindingID, request.Status, request.Notes)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, record)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPatch)
	}
}

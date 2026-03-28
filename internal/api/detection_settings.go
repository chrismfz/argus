package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"argus/internal/detection"
)

// DetectionDB is set by main.go (same *sql.DB used by the rest of argus).
// The detection settings handlers use this directly so there's no extra global.
var DetectionDB *sql.DB

// ── Helpers ───────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func reloadExcludes() {
	if DetectionDB != nil {
		_ = detection.LoadProtectedFromDB(DetectionDB)
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// GET /detection/excludes
func handleDetectionExcludesList(w http.ResponseWriter, r *http.Request) {
	if DetectionDB == nil {
		jsonErr(w, http.StatusServiceUnavailable, "database not available")
		return
	}
	entries, err := detection.ListExcludes(DetectionDB)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []detection.ExcludeEntry{} // never return null
	}
	jsonOK(w, entries)
}

// POST /detection/excludes   body: {"cidr":"1.2.3.4/24","label":"my comment"}
func handleDetectionExcludesAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if DetectionDB == nil {
		jsonErr(w, http.StatusServiceUnavailable, "database not available")
		return
	}
	var body struct {
		CIDR  string `json:"cidr"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	id, err := detection.AddExclude(DetectionDB, body.CIDR, body.Label)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	reloadExcludes()
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]interface{}{"id": id, "ok": true})
}

// DELETE /detection/excludes/{id}
func handleDetectionExcludesDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonErr(w, http.StatusMethodNotAllowed, "DELETE required")
		return
	}
	if DetectionDB == nil {
		jsonErr(w, http.StatusServiceUnavailable, "database not available")
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/detection/excludes/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := detection.DeleteExclude(DetectionDB, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonErr(w, http.StatusNotFound, "not found")
		} else {
			jsonErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	reloadExcludes()
	jsonOK(w, map[string]bool{"ok": true})
}

// PUT /detection/excludes/{id}   body: {"cidr":"...","label":"..."}
func handleDetectionExcludesUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		jsonErr(w, http.StatusMethodNotAllowed, "PUT required")
		return
	}
	if DetectionDB == nil {
		jsonErr(w, http.StatusServiceUnavailable, "database not available")
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/detection/excludes/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var body struct {
		CIDR  string `json:"cidr"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := detection.UpdateExclude(DetectionDB, id, body.CIDR, body.Label); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonErr(w, http.StatusNotFound, "not found")
		} else {
			jsonErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	reloadExcludes()
	jsonOK(w, map[string]bool{"ok": true})
}

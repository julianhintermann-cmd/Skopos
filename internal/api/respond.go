package api

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// decodeJSON decodes a size-limited JSON request body into v.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v)
}

// readBody reads a size-limited raw request body.
func readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, max))
}

// writeJSON writes v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error envelope.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// subtleEqual compares two strings in constant time.
func subtleEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func itoa(n int) string { return strconv.Itoa(n) }

// joinSorted renders a set of keys deterministically for audit details.
func joinSorted(keys []string) string {
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

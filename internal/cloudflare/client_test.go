package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testClient(h http.Handler) (*Client, *httptest.Server) {
	srv := httptest.NewServer(h)
	c := NewClient()
	c.BaseURL = srv.URL
	c.GraphQLURL = srv.URL + "/graphql"
	return c, srv
}

func TestVerifyTokenAndAuthHeader(t *testing.T) {
	var gotAuth string
	c, srv := testClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"tok1","status":"active","expires_on":"2030-01-01T00:00:00Z"}}`))
	}))
	defer srv.Close()

	ts, err := c.VerifyToken(context.Background(), "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("auth header = %q, want bearer token", gotAuth)
	}
	if !ts.Active() || ts.ID != "tok1" {
		t.Errorf("status = %+v, want active tok1", ts)
	}
}

func TestVerifyTokenSurfacesAPIError(t *testing.T) {
	c, srv := testClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}`))
	}))
	defer srv.Close()

	if _, err := c.VerifyToken(context.Background(), "bad"); err == nil || !strings.Contains(err.Error(), "Invalid API Token") {
		t.Errorf("err = %v, want the API message surfaced", err)
	}
}

func TestListZonesPaginates(t *testing.T) {
	c, srv := testClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		switch page {
		case "1":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z1","name":"a.com","status":"active"}],"result_info":{"page":1,"total_pages":2}}`))
		default:
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z2","name":"b.com","status":"active"}],"result_info":{"page":2,"total_pages":2}}`))
		}
	}))
	defer srv.Close()

	zones, err := c.ListZones(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 || zones[0].Name != "a.com" || zones[1].Name != "b.com" {
		t.Errorf("zones = %+v, want both pages", zones)
	}
}

func TestAnalyticsParsesGroups(t *testing.T) {
	c, srv := testClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/graphql") {
			t.Errorf("analytics hit %s, want /graphql", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":{"viewer":{"zones":[{"httpRequests1hGroups":[
			{"dimensions":{"datetime":"2026-08-12T10:00:00Z"},"sum":{"requests":100,"bytes":2048,"cachedRequests":40,"cachedBytes":1024,"threats":2}},
			{"dimensions":{"datetime":"2026-08-12T11:00:00Z"},"sum":{"requests":150,"bytes":4096,"cachedRequests":60,"cachedBytes":2048,"threats":0}}
		]}]}}}`))
	}))
	defer srv.Close()

	since := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	until := since.Add(2 * time.Hour)
	series, err := c.Analytics(context.Background(), "t", "z1", since, until)
	if err != nil {
		t.Fatal(err)
	}
	if len(series.Points) != 2 {
		t.Fatalf("points = %d, want 2", len(series.Points))
	}
	if series.Points[0].Requests != 100 || series.Points[1].Bytes != 4096 {
		t.Errorf("parsed points wrong: %+v", series.Points)
	}
}

func TestAnalyticsSurfacesGraphQLError(t *testing.T) {
	c, srv := testClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":null,"errors":[{"message":"not authorized to access this resource"}]}`))
	}))
	defer srv.Close()

	_, err := c.Analytics(context.Background(), "t", "z1", time.Now().Add(-time.Hour), time.Now())
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("err = %v, want graphql error surfaced", err)
	}
}

func TestTokenRejectedOn401(t *testing.T) {
	c, srv := testClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	if _, err := c.VerifyToken(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Errorf("err = %v, want rejected", err)
	}
}

package detector_test

import (
	"encoding/json"
	"math"
	"os"
	"sort"
	"testing"

	"policy-engine/pkg/audit"
	"policy-engine/pkg/detector"
)

func loadGolden(t *testing.T) []audit.AuditRecord {
	t.Helper()
	f, err := os.Open("../../testdata/golden_audit_events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []audit.AuditRecord
	dec := json.NewDecoder(f)
	for dec.More() {
		var r audit.AuditRecord
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	return recs
}

func TestFeatures_SessionAge(t *testing.T) {
	recs := loadGolden(t)
	rb := detector.NewRingBuffer(200)
	for _, r := range recs {
		rb.Add(r)
	}
	fv := rb.Features(recs[2]) // third event, 60s after first
	if math.Abs(float64(fv.SessionAgeS)-60.0) > 1.0 {
		t.Errorf("session_age_s: got %.2f, want ~60", fv.SessionAgeS)
	}
}

func TestFeatures_SimultaneousIP(t *testing.T) {
	recs := loadGolden(t)
	rb := detector.NewRingBuffer(200)
	for _, r := range recs {
		rb.Add(r)
	}
	fv := rb.Features(recs[2]) // two distinct IPs within 30s for sess-a
	if fv.SimultaneousIPCount < 2 {
		t.Errorf("simultaneous_ip_count: got %d, want >=2", int(fv.SimultaneousIPCount))
	}
}

func TestFeatures_ReqCount1m(t *testing.T) {
	recs := loadGolden(t)
	rb := detector.NewRingBuffer(200)
	// Only add the first 3 events (all tok1, all within 1 minute of recs[2]).
	for _, r := range recs[:3] {
		rb.Add(r)
	}
	// all 3 events fall within 1 minute of the third event's timestamp
	fv := rb.Features(recs[2])
	if fv.ReqCount1m != 3 {
		t.Errorf("req_count_1m: got %d, want 3", int(fv.ReqCount1m))
	}
}

type expectedRow struct {
	EventID             string  `json:"event_id"`
	CountryHash         float64 `json:"country_hash"`
	ASN                 float64 `json:"asn"`
	EndpointHash        float64 `json:"endpoint_hash"`
	EndpointLag1Hash    float64 `json:"endpoint_lag1_hash"`
	EndpointLag2Hash    float64 `json:"endpoint_lag2_hash"`
	RoleHash            float64 `json:"role_hash"`
	RoleLag1Hash        float64 `json:"role_lag1_hash"`
	DeltaTsT1S          float64 `json:"delta_ts_t1_s"`
	IsHighPrivilege     float64 `json:"is_high_privilege_role"`
	SessionAgeS         float64 `json:"session_age_s"`
	SessionTotalActions float64 `json:"session_total_actions"`
	UniqueEndpoints     float64 `json:"unique_endpoints"`
	ReqCount1m          float64 `json:"req_count_1m"`
	FailedReqCount1m    float64 `json:"failed_req_count_1m"`
	ReqCount5m          float64 `json:"req_count_5m"`
	Reads5m             float64 `json:"reads_5m"`
	Writes5m            float64 `json:"writes_5m"`
	ReadWriteRatio5m    float64 `json:"read_write_ratio_5m"`
	InterarrivalAvg5m   float64 `json:"interarrival_avg_5m"`
	ReqCount15m         float64 `json:"req_count_15m"`
	RoleMismatchCount5m float64 `json:"role_mismatch_count_5m"`
	SimultaneousIPCount float64 `json:"simultaneous_ip_count"`
	MassRequestScore    float64 `json:"mass_request_score"`
	UniqueRoles5m       float64 `json:"unique_roles_requested_5m"`
	HourSin             float64 `json:"hour_sin"`
	HourCos             float64 `json:"hour_cos"`
	IsWeekend           float64 `json:"is_weekend"`
	IsOutsideHours      float64 `json:"is_outside_hours"`
}

func loadExpected(t *testing.T) map[string]expectedRow {
	t.Helper()
	data, err := os.ReadFile("../../testdata/golden_features_expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []expectedRow
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	m := make(map[string]expectedRow, len(rows))
	for _, r := range rows {
		m[r.EventID] = r
	}
	return m
}

func assertNear(t *testing.T, eventID, field string, got float32, want float64, tol float64) {
	t.Helper()
	diff := math.Abs(float64(got) - want)
	if diff > tol {
		t.Errorf("event %s: %s: got %v want %v (diff %v > tol %v)",
			eventID, field, got, want, diff, tol)
	}
}

func TestFeaturesParity(t *testing.T) {
	recs := loadGolden(t)
	expected := loadExpected(t)

	// Sort by timestamp because RingBuffer must receive events in chronological order
	sort.SliceStable(recs, func(i, j int) bool {
		return recs[i].Ts.Before(recs[j].Ts)
	})

	if len(recs) != len(expected) {
		t.Errorf("fixture has %d events but expected JSON has %d rows", len(recs), len(expected))
	}

	rb := detector.NewRingBuffer(200)
	for _, rec := range recs {
		rb.Add(rec)
		fv := rb.Features(rec)
		ex, ok := expected[rec.EventID]
		if !ok {
			t.Errorf("no expected row for event_id %s", rec.EventID)
			continue
		}

		id := rec.EventID
		const hashTol = 0.0
		assertNear(t, id, "country_hash",       fv.CountryHash,      ex.CountryHash,      hashTol)
		assertNear(t, id, "endpoint_hash",      fv.EndpointHash,     ex.EndpointHash,     hashTol)
		assertNear(t, id, "endpoint_lag1_hash", fv.EndpointLag1Hash, ex.EndpointLag1Hash, hashTol)
		assertNear(t, id, "endpoint_lag2_hash", fv.EndpointLag2Hash, ex.EndpointLag2Hash, hashTol)
		assertNear(t, id, "role_hash",          fv.RoleHash,         ex.RoleHash,         hashTol)
		assertNear(t, id, "role_lag1_hash",     fv.RoleLag1Hash,     ex.RoleLag1Hash,     hashTol)
		const tol = 1e-3
		assertNear(t, id, "asn",                    fv.ASN,                 ex.ASN,                 0)
		assertNear(t, id, "delta_ts_t1_s",           fv.DeltaTsT1S,          ex.DeltaTsT1S,          tol)
		assertNear(t, id, "is_high_privilege_role",  fv.IsHighPrivilege,     ex.IsHighPrivilege,     0)
		assertNear(t, id, "session_age_s",           fv.SessionAgeS,         ex.SessionAgeS,         tol)
		assertNear(t, id, "session_total_actions",   fv.SessionTotalActions, ex.SessionTotalActions, 0)
		assertNear(t, id, "unique_endpoints",        fv.UniqueEndpoints,     ex.UniqueEndpoints,     0)
		assertNear(t, id, "req_count_1m",            fv.ReqCount1m,          ex.ReqCount1m,          0)
		assertNear(t, id, "failed_req_count_1m",     fv.FailedReqCount1m,    ex.FailedReqCount1m,    0)
		assertNear(t, id, "req_count_5m",            fv.ReqCount5m,          ex.ReqCount5m,          0)
		assertNear(t, id, "reads_5m",                fv.Reads5m,             ex.Reads5m,             0)
		assertNear(t, id, "writes_5m",               fv.Writes5m,            ex.Writes5m,            0)
		assertNear(t, id, "read_write_ratio_5m",     fv.ReadWriteRatio5m,    ex.ReadWriteRatio5m,    tol)
		assertNear(t, id, "interarrival_avg_5m",     fv.InterarrivalAvg5m,   ex.InterarrivalAvg5m,   tol)
		assertNear(t, id, "req_count_15m",           fv.ReqCount15m,         ex.ReqCount15m,         0)
		assertNear(t, id, "role_mismatch_count_5m",  fv.RoleMismatchCount5m, ex.RoleMismatchCount5m, 0)
		assertNear(t, id, "simultaneous_ip_count",   fv.SimultaneousIPCount, ex.SimultaneousIPCount, 0)
		assertNear(t, id, "mass_request_score",      fv.MassRequestScore,    ex.MassRequestScore,    0)
		assertNear(t, id, "unique_roles_requested_5m", fv.UniqueRoles5m,     ex.UniqueRoles5m,       0)
		assertNear(t, id, "hour_sin",                fv.HourSin,             ex.HourSin,             tol)
		assertNear(t, id, "hour_cos",                fv.HourCos,             ex.HourCos,             tol)
		assertNear(t, id, "is_weekend",              fv.IsWeekend,           ex.IsWeekend,           0)
		assertNear(t, id, "is_outside_hours",        fv.IsOutsideHours,      ex.IsOutsideHours,      0)
	}
}

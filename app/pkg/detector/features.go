package detector

import (
	"hash/fnv"
	"math"
	"sync"
	"time"

	"policy-engine/pkg/audit"
)

// FeatureVector mirrors the columns produced by materialise.sql.
type FeatureVector struct {
	CountryHash         float32
	ASN                 float32
	EndpointHash        float32
	EndpointLag1Hash    float32
	EndpointLag2Hash    float32
	RoleHash            float32
	RoleLag1Hash        float32
	DeltaTsT1S          float32
	IsHighPrivilege     float32
	SessionAgeS         float32
	SessionTotalActions float32
	UniqueEndpoints     float32
	ReqCount1m          float32
	FailedReqCount1m    float32
	ReqCount5m          float32
	Reads5m             float32
	Writes5m            float32
	ReadWriteRatio5m    float32
	InterarrivalAvg5m   float32
	ReqCount15m         float32
	RoleMismatchCount5m float32
	SimultaneousIPCount float32
	MassRequestScore    float32
	UniqueRoles5m       float32
	HourSin             float32
	HourCos             float32
	IsWeekend           float32
	IsOutsideHours      float32
}

func (fv FeatureVector) Slice() []float32 {
	return []float32{
		fv.CountryHash, fv.ASN, fv.EndpointHash, fv.EndpointLag1Hash,
		fv.EndpointLag2Hash, fv.RoleHash, fv.RoleLag1Hash, fv.DeltaTsT1S,
		fv.IsHighPrivilege, fv.SessionAgeS, fv.SessionTotalActions, fv.UniqueEndpoints,
		fv.ReqCount1m, fv.FailedReqCount1m, fv.ReqCount5m, fv.Reads5m, fv.Writes5m,
		fv.ReadWriteRatio5m, fv.InterarrivalAvg5m, fv.ReqCount15m,
		fv.RoleMismatchCount5m, fv.SimultaneousIPCount, fv.MassRequestScore,
		fv.UniqueRoles5m, fv.HourSin, fv.HourCos, fv.IsWeekend, fv.IsOutsideHours,
	}
}

func hashStr(s string) float32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return float32(int32(h.Sum32())) // signed to match DuckDB hash()::INTEGER
}

func isHighPrivilege(role string) float32 {
	if role == "admin" || role == "cluster-admin" {
		return 1
	}
	return 0
}

// RingBuffer holds the last cap events per user_token and per session_id.
type RingBuffer struct {
	mu        sync.Mutex
	cap       int
	byUser    map[string][]audit.AuditRecord
	bySession map[string][]audit.AuditRecord
}

func NewRingBuffer(cap int) *RingBuffer {
	return &RingBuffer{
		cap:       cap,
		byUser:    make(map[string][]audit.AuditRecord),
		bySession: make(map[string][]audit.AuditRecord),
	}
}

func appendCapped(buf []audit.AuditRecord, r audit.AuditRecord, cap int) []audit.AuditRecord {
	buf = append(buf, r)
	if len(buf) > cap {
		buf = buf[len(buf)-cap:]
	}
	return buf
}

func (rb *RingBuffer) Add(r audit.AuditRecord) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.byUser[r.UserToken] = appendCapped(rb.byUser[r.UserToken], r, rb.cap)
	if r.SessionID != "" {
		rb.bySession[r.SessionID] = appendCapped(rb.bySession[r.SessionID], r, rb.cap)
	}
}

func (rb *RingBuffer) Features(cur audit.AuditRecord) FeatureVector {
	rb.mu.Lock()
	userBuf := rb.byUser[cur.UserToken]
	sessBuf := rb.bySession[cur.SessionID]
	rb.mu.Unlock()

	now := cur.Ts
	w1  := now.Add(-1 * time.Minute)
	w5  := now.Add(-5 * time.Minute)
	w15 := now.Add(-15 * time.Minute)
	w30s := now.Add(-30 * time.Second)

	var fv FeatureVector
	fv.CountryHash    = hashStr(cur.SourceGeo.Country)
	fv.ASN            = float32(cur.SourceGeo.ASN)
	fv.EndpointHash   = hashStr(cur.Endpoint)
	fv.RoleHash       = hashStr(cur.RequestRole)
	fv.IsHighPrivilege = isHighPrivilege(cur.RequestRole)

	fv.DeltaTsT1S = -1
	for i := len(userBuf) - 1; i >= 0; i-- {
		prev := userBuf[i]
		if prev.EventID == cur.EventID {
			continue
		}
		if fv.EndpointLag1Hash == 0 {
			fv.EndpointLag1Hash = hashStr(prev.Endpoint)
			fv.RoleLag1Hash     = hashStr(prev.RequestRole)
			fv.DeltaTsT1S       = float32(cur.Ts.Sub(prev.Ts).Seconds())
		} else if fv.EndpointLag2Hash == 0 {
			fv.EndpointLag2Hash = hashStr(prev.Endpoint)
			break
		}
	}

	// session features (include current event - mirrors SQL CURRENT ROW)
	if len(sessBuf) > 0 {
		first := sessBuf[0]
		fv.SessionAgeS        = float32(cur.Ts.Sub(first.Ts).Seconds())
		fv.SessionTotalActions = float32(len(sessBuf))
		seen := map[string]struct{}{}
		for _, r := range sessBuf {
			seen[r.Endpoint] = struct{}{}
		}
		fv.UniqueEndpoints = float32(len(seen))
	}

	// window aggregates over user buffer - include current event (mirrors SQL CURRENT ROW)
	var (
		reqs1m, failed1m, reqs5m, reads5m, writes5m, reqs15m int
		roles5m   = map[string]struct{}{}
		massScore int
	)
	for _, r := range userBuf {
		if !r.Ts.Before(w15) {
			reqs15m++
		}
		if !r.Ts.Before(w5) {
			reqs5m++
			roles5m[r.RequestRole] = struct{}{}
			if r.Verb == "GET" {
				reads5m++
			} else {
				writes5m++
			}
			if r.Verb == "GET" && r.Endpoint == "/requests" {
				massScore++
			}
			if isHighPrivilege(r.RequestRole) == 1 {
				fv.RoleMismatchCount5m++
			}
		}
		if !r.Ts.Before(w1) {
			reqs1m++
			if r.ResponseCode >= 400 {
				failed1m++
			}
		}
	}
	fv.ReqCount1m       = float32(reqs1m)
	fv.FailedReqCount1m = float32(failed1m)
	fv.ReqCount5m       = float32(reqs5m)
	fv.Reads5m          = float32(reads5m)
	fv.Writes5m         = float32(writes5m)
	fv.ReqCount15m      = float32(reqs15m)
	fv.UniqueRoles5m    = float32(len(roles5m))
	fv.MassRequestScore = float32(massScore)
	if writes5m > 0 {
		fv.ReadWriteRatio5m = float32(reads5m) / float32(writes5m)
	} else {
		fv.ReadWriteRatio5m = float32(reads5m)
	}

	// interarrival_avg_5m: mirrors SQL AVG(delta_ts_t1_s) OVER w5.
	// delta_ts_t1_s for each event = time since its predecessor in the user buffer.
	// Events with no predecessor contribute NULL (excluded from AVG).
	// userBuf is oldest-first (insertion order).
	var interarrivalSum float64
	var interarrivalCount int
	for i, r := range userBuf {
		if !r.Ts.Before(w5) && i > 0 {
			interarrivalSum += r.Ts.Sub(userBuf[i-1].Ts).Seconds()
			interarrivalCount++
		}
	}
	if interarrivalCount > 0 {
		fv.InterarrivalAvg5m = float32(interarrivalSum / float64(interarrivalCount))
	}

	ips := map[string]struct{}{}
	for _, r := range sessBuf {
		if !r.Ts.Before(w30s) {
			ips[r.SourceIP] = struct{}{}
		}
	}
	fv.SimultaneousIPCount = float32(len(ips))

	// circadian - mirrors SQL: sin/cos of EXTRACT(HOUR FROM ts), integer hour only.
	h := float64(now.UTC().Hour())
	fv.HourSin = float32(math.Sin(2 * math.Pi * h / 24.0))
	fv.HourCos = float32(math.Cos(2 * math.Pi * h / 24.0))
	wd := now.UTC().Weekday()
	if wd == time.Saturday || wd == time.Sunday {
		fv.IsWeekend = 1
	}
	hr := now.UTC().Hour()
	if hr < 8 || hr >= 18 {
		fv.IsOutsideHours = 1
	}

	return fv
}

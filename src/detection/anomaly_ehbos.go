package detection

import (
	"math/rand"
	"sort"
	"time"
)

// EHBOS: an ensemble of HBOS over random feature subspaces, aggregated.
type EHBOS struct {
	bins int
	eps  float64
	agg  string // "max" or "mean"

	// subspaces: each entry is a slice of feature indices (e.g., [0,2,4])
	subs  [][]int
	model []*HBOS

	// training aggregate scores (for Bound / normalization)
	trainScores []float64
}

func NewEHBOS(bins int, eps float64, nSubspaces, subspaceSize int, agg string, d int) *EHBOS {
	if bins <= 1 { bins = 10 }
	if eps <= 0  { eps  = 1e-6 }
	if subspaceSize <= 1 { subspaceSize = 2 }
	if nSubspaces <= 0 { nSubspaces = 12 }
	if agg != "max" && agg != "mean" { agg = "max" }

	// build random subspaces deterministically per process start
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	subs := make([][]int, 0, nSubspaces)
	seen := map[string]bool{}
	pick := func() []int {
		ix := make([]int, d)
		for i := 0; i < d; i++ { ix[i] = i }
		// shuffle and take first k
		for i := d-1; i > 0; i-- { j := r.Intn(i+1); ix[i], ix[j] = ix[j], ix[i] }
		out := append([]int(nil), ix[:subspaceSize]...)
		sort.Ints(out)
		return out
	}
	for len(subs) < nSubspaces {
		s := pick()
		key := fmtKey(s)
		if !seen[key] {
			seen[key] = true
			subs = append(subs, s)
		}
	}
	return &EHBOS{bins: bins, eps: eps, agg: agg, subs: subs}
}

func fmtKey(s []int) string {
	b := make([]byte, 0, len(s)*3)
	for _, v := range s {
		b = append(b, byte(v), 0)
	}
	return string(b)
}

// Train on baseline B (rows=vectors), using each subspace.
func (e *EHBOS) Train(B [][]float64) {
	if len(B) == 0 || len(e.subs) == 0 { return }
	e.model = make([]*HBOS, len(e.subs))
	// train one HBOS per subspace
	for i, sub := range e.subs {
		proj := project(B, sub)
		h := NewHBOS(e.bins, e.eps)
		h.Train(proj)
		e.model[i] = h
	}
	// build aggregate training scores for normalization/bound if needed
	e.trainScores = e.trainScores[:0]
	for _, v := range B {
		e.trainScores = append(e.trainScores, e.Score(v))
	}
sort.Float64s(e.trainScores)
}

func project(B [][]float64, sub []int) [][]float64 {
	out := make([][]float64, len(B))
	for i, v := range B {
		row := make([]float64, len(sub))
		for j, idx := range sub { row[j] = v[idx] }
		out[i] = row
	}
	return out
}

// Score: aggregate per-subspace raw HBOS scores. Larger => more anomalous.
func (e *EHBOS) Score(v []float64) float64 {
	if len(e.model) == 0 { return 0 }
	acc := 0.0
	maxv := -1e308
	for i, sub := range e.subs {
		p := make([]float64, len(sub))
		for j, idx := range sub { p[j] = v[idx] }
		s := e.model[i].Score(p)
		if s > maxv { maxv = s }
		acc += s
	}
	if e.agg == "max" {
		return maxv
	}
	return acc / float64(len(e.model))
}

// Bound(p): p-quantile over aggregate training scores.
func (e *EHBOS) Bound(p float64) float64 {
	if len(e.trainScores) == 0 { return 1e9 }
	if p <= 0 { return e.trainScores[0] }
	if p >= 1 { return e.trainScores[len(e.trainScores)-1] }
	pos := int(p*float64(len(e.trainScores)-1) + 0.5)
	return e.trainScores[pos]
}

// ScoreNorm: map aggregate raw score to [0,1] via empirical percentile.
func (e *EHBOS) ScoreNorm(v []float64) float64 {
	raw := e.Score(v)
	n := len(e.trainScores)
	if n == 0 { return 0 }
	idx := sort.Search(n, func(i int) bool { return e.trainScores[i] >= raw })
	q := (float64(idx) - 0.5) / float64(n)
	if q < 0 { q = 0 }
	if q > 1 { q = 1 }
	return q
}

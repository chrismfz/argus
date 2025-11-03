package detection

import (
	"math"
	"sort"
)

// HBOS = per-feature histograms; score is sum of -log(density).
// Works on the SAME feature space you already feed to iForest (log1pVec).
type HBOS struct {
	bins int
	eps  float64
	// per feature: edges[k] has len(bins+1); counts[k] has len(bins)
	edges  [][]float64
	counts [][]float64
	total  float64
	// cache of training scores to compute a percentile bound
	trainScores []float64
}

func NewHBOS(bins int, eps float64) *HBOS {
	if bins <= 1 { bins = 10 }
	if eps <= 0  { eps  = 1e-6 }
	return &HBOS{bins: bins, eps: eps}
}

func (h *HBOS) Train(b [][]float64) {
	if len(b) == 0 { return }
	d := len(b[0])
	h.edges = make([][]float64, d)
	h.counts = make([][]float64, d)
	minv := make([]float64, d)
	maxv := make([]float64, d)
	for j := 0; j < d; j++ {
		minv[j] = math.Inf(+1)
		maxv[j] = math.Inf(-1)
	}
	// min/max
	for _, v := range b {
		for j, x := range v {
			if x < minv[j] { minv[j] = x }
			if x > maxv[j] { maxv[j] = x }
		}
	}
	// build edges & zero counts
	for j := 0; j < d; j++ {
		lo, hi := minv[j], maxv[j]
		if !(lo < hi) {
			lo, hi = lo-0.5, hi+0.5 // avoid degenerate range
		}
		step := (hi - lo) / float64(h.bins)
		h.edges[j] = make([]float64, h.bins+1)
		for k := 0; k <= h.bins; k++ {
			h.edges[j][k] = lo + float64(k)*step
		}
		h.counts[j] = make([]float64, h.bins)
	}
	// fill counts
	for _, v := range b {
		for j, x := range v {
			idx := binSearch(h.edges[j], x)
			if idx < 0 { idx = 0 }
			if idx >= h.bins { idx = h.bins - 1 }
			h.counts[j][idx]++
		}
	}
	h.total = float64(len(b))

	// store training HBOS scores to get a bound/percentile
	h.trainScores = h.trainScores[:0]
	for _, v := range b {
		h.trainScores = append(h.trainScores, h.Score(v))
	}
	sort.Float64s(h.trainScores)
}

// Score: sum_j -log( max(count_j/binwidth, eps) / total )
func (h *HBOS) Score(v []float64) float64 {
	if len(h.edges) == 0 || len(v) == 0 { return 0 }
	score := 0.0
	for j, x := range v {
		edges := h.edges[j]
		counts := h.counts[j]
		if len(edges) < 2 { continue }
		idx := binSearch(edges, x)
		if idx < 0 { idx = 0 }
		if idx >= len(counts) { idx = len(counts)-1 }
		binWidth := edges[idx+1] - edges[idx]
		if binWidth <= 0 { binWidth = 1 } // fallback
		density := (counts[idx] / binWidth) / math.Max(h.total, 1)
		if density < h.eps { density = h.eps }
		score += -math.Log(density)
	}
	return score
}

// Bound(p): return p-quantile of training HBOS scores (e.g. p=0.99)
func (h *HBOS) Bound(p float64) float64 {
	if len(h.trainScores) == 0 { return math.Inf(+1) }
	if p <= 0 { return h.trainScores[0] }
	if p >= 1 { return h.trainScores[len(h.trainScores)-1] }
	pos := int(p*float64(len(h.trainScores)-1) + 0.5)
	return h.trainScores[pos]
}

func binSearch(edges []float64, x float64) int {
	// return k such that edges[k] <= x < edges[k+1]
	lo, hi := 0, len(edges)-2
	for lo <= hi {
		m := (lo + hi) >> 1
		if x < edges[m] {
			hi = m - 1
		} else if x >= edges[m+1] {
			lo = m + 1
		} else {
			return m
		}
	}
	if lo < 0 { return 0 }
	return lo
}

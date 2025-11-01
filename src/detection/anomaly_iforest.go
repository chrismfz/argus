package detection

import iforest "github.com/e-XpertSolutions/go-iforest/v2/iforest"

type Detector interface {
	Train(baseline [][]float64) error
	Score(vec []float64) (label int, score float64)
}

type IForestDetector struct {
	forest *iforest.Forest
}

func NewIForestDetector(trees, sample int, contamination float64) *IForestDetector {
	if trees <= 0 { trees = 100 }
	if sample <= 0 { sample = 256 }
	if contamination <= 0 { contamination = 0.01 }
	return &IForestDetector{
		forest: iforest.NewForest(trees, sample, contamination),
	}
}

func (d *IForestDetector) Train(b [][]float64) error {
    // Build trees…
    d.forest.Train(b)
    // …and derive an anomaly threshold based on contamination
    // so that Predict can yield meaningful labels.
    d.forest.Test(b)
    return nil
}

func (d *IForestDetector) Score(vec []float64) (int, float64) {
    lbls, scores, err := d.forest.Predict([][]float64{vec})
    if err != nil || len(lbls) == 0 {
        return 0, 0.0
    }
    // Extra safety: if for any reason the lib returns label=0 but a score,
    // fall back to our own comparison against the trained bound.
    label := lbls[0]
    score := scores[0]
    if label == 0 && score >= d.forest.AnomalyBound {
        label = 1
    }
    return label, score
}

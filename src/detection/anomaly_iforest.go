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
	d.forest.Train(b)
	return nil
}

func (d *IForestDetector) Score(vec []float64) (int, float64) {
	lbls, scores, err := d.forest.Predict([][]float64{vec})
	if err != nil || len(lbls) == 0 {
		return 0, 0.0
	}
	return lbls[0], scores[0] // 1=anomaly, 0=normal
}

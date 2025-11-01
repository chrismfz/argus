package detection

import "math"

type featureVector struct {
	PktsPerSec    float64
	BytesPerSec   float64
	MeanPktSize   float64
	UniqDstIPs    float64
	UniqDstPorts  float64
	TCPSYNRatio   float64
	ICMPShare     float64
}

func (v featureVector) slice() []float64 {
	return []float64{
		v.PktsPerSec, v.BytesPerSec, v.MeanPktSize,
		v.UniqDstIPs, v.UniqDstPorts, v.TCPSYNRatio, v.ICMPShare,
	}
}

func log1pVec(x []float64) []float64 {
	out := make([]float64, len(x))
	for i, v := range x {
		if v < 0 {
			out[i] = -math.Log1p(-v)
		} else {
			out[i] = math.Log1p(v)
		}
	}
	return out
}

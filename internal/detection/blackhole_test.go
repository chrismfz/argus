package detection

import "testing"

func TestEscalationTTL(t *testing.T) {
	ladder := []int{14400, 28800, 57600, 86400, 0} // 4h,8h,16h,24h,permanent

	tests := []struct {
		name      string
		durations []int
		times     int
		want      int
	}{
		{"first offense", ladder, 1, 14400},
		{"second offense", ladder, 2, 28800},
		{"fourth offense", ladder, 4, 86400},
		{"fifth offense => permanent", ladder, 5, 0},
		{"beyond ladder clamps to last", ladder, 9, 0},
		{"times below 1 clamps to first", ladder, 0, 14400},
		{"no durations => permanent", nil, 3, 0},
		{"single duration", []int{3600}, 2, 3600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escalationTTL(tt.durations, tt.times); got != tt.want {
				t.Fatalf("escalationTTL(%v, %d) = %d; want %d", tt.durations, tt.times, got, tt.want)
			}
		})
	}
}

func TestBlackholeDurations(t *testing.T) {
	// Single int (YAML scalar).
	if got := (&DetectionRule{BlackholeTime: 3600}).BlackholeDurations(); len(got) != 1 || got[0] != 3600 {
		t.Fatalf("scalar int: got %v", got)
	}
	// List (YAML sequence decodes to []interface{}).
	r := &DetectionRule{BlackholeTime: []interface{}{14400, 28800, 0}}
	got := r.BlackholeDurations()
	if len(got) != 3 || got[0] != 14400 || got[1] != 28800 || got[2] != 0 {
		t.Fatalf("list: got %v", got)
	}
	// Unset => nil (permanent via escalationTTL).
	if got := (&DetectionRule{}).BlackholeDurations(); got != nil {
		t.Fatalf("unset: expected nil, got %v", got)
	}
}

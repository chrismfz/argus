package logbackend

import (
	"argus/internal/alerter"
)

func init() {
	alerter.RegisterFactory("log", func(c alerter.Contact) (alerter.Backend, error) {
		return New(), nil
	})
}

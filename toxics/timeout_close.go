package toxics

import "time"

// The TimeoutCloseToxic allow data to go through without any toxic effects,
// untile a timeout is reached. At that point, the toxic will close the connection.
// If the timeout is set to 0, then the connection will not be closed.
// effective to test connection drops on websockets.
type TimeoutCloseToxic struct {
	// Times in milliseconds
	Timeout int64 `json:"timeout"`
}

func (t *TimeoutCloseToxic) Pipe(stub *ToxicStub) {
	timeout := time.Duration(t.Timeout) * time.Millisecond
	if timeout > 0 {
		for {
			select {
			case <-time.After(timeout):
				stub.Close()
				return
			case <-stub.Interrupt:
				return
			case c := <-stub.Input:
				if c == nil {
					stub.Close()
					return
				}
				stub.Output <- c
			}
		}
	} else {
		for {
			select {
			case <-stub.Interrupt:
				return
			case c := <-stub.Input:
				if c == nil {
					stub.Close()
					return
				}
				stub.Output <- c
			}
		}
	}
}

func (t *TimeoutCloseToxic) Cleanup(stub *ToxicStub) {
	stub.Close()
}

func init() {
	Register("timeoutclose", new(TimeoutCloseToxic))
}

package caddyhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

// Forwardproxy extends only the authenticated CONNECT's idle allowance.
// An explicit hard deadline and the next request's defaults must survive.
func TestVPNBotIdleOverrideScopeAndHardDeadline(t *testing.T) {
	w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	hard := time.Now().Add(time.Hour)
	r := &IdleTimeoutReader{
		Ctrl: http.NewResponseController(w), Logger: zap.NewNop(),
		Deadline: IdleDeadline{Timeout: time.Minute, HardDeadline: hard},
		deadlineSet: true,
	}
	ctx := ContextWithIdleTimeouts(context.Background(), r, nil)
	reader, writer := IdleTimeoutsFromContext(ctx)
	if reader != r || writer != nil {
		t.Fatal("request timeout wrappers lost")
	}
	restore := reader.Override(24*time.Hour, 0)
	deadlines := w.snapshot()
	if len(deadlines) != 1 || !deadlines[0].Equal(hard) {
		t.Fatal("hard timeout was extended by CONNECT override")
	}
	restore()
	deadlines = w.snapshot()
	if len(deadlines) != 2 || deadlines[1].After(time.Now().Add(2*time.Minute)) || r.Deadline.Timeout != time.Minute {
		t.Fatal("original idle deadline was not rearmed")
	}
	if reader, writer := IdleTimeoutsFromContext(context.Background()); reader != nil || writer != nil {
		t.Fatal("override leaked to another request")
	}
}

func TestVPNBotIdleOverrideRearmsActiveRead(t *testing.T) {
	w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := &IdleTimeoutReader{
		Ctrl: http.NewResponseController(w), Logger: zap.NewNop(),
		Deadline: IdleDeadline{Timeout: time.Minute}, deadlineSet: true,
	}
	r.Override(24*time.Hour, 0)
	deadlines := w.snapshot()
	if len(deadlines) != 1 || time.Until(deadlines[0]) < 23*time.Hour {
		t.Fatal("already armed read timeout still closes an idle CONNECT")
	}
	r.finished = true
	r.Override(time.Second, 0)
	if len(w.snapshot()) != 1 {
		t.Fatal("override rearmed a completed request")
	}
}

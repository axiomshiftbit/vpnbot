//go:build with_quic

// SPDX-License-Identifier: GPL-3.0-or-later
package tuic

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

type vpnBotLogCapture struct {
	logger.Logger
	message string
}

func (l *vpnBotLogCapture) Error(args ...any) { l.message = fmt.Sprint(args...) }
func (l *vpnBotLogCapture) Debug(args ...any) { l.message = fmt.Sprint(args...) }

func TestVPNBotTUICRevokedCredentialsNotLogged(t *testing.T) {
	for _, credential := range []string{"23fd1177-237a-4ad9-a7c1-c83cfab244ce", "23FD1177-237A-4AD9-A7C1-C83CFAB244CE"} {
		capture := new(vpnBotLogCapture)
		filtered := vpnBotTUICLogger{capture}
		for _, write := range []func(...any){filtered.Error, filtered.Debug} {
			write(errors.New("connection failed: authentication: unknown user " + credential))
			if strings.Contains(capture.message, credential) || !strings.Contains(capture.message, "authentication: unknown user [redacted UUID]") {
				t.Fatal("authentication diagnostic did not redact the UUID")
			}
			write(errors.New("listener closed: permission denied"))
			if capture.message != "listener closed: permission denied" {
				t.Fatal("unrelated diagnostic was changed")
			}
		}
	}
}

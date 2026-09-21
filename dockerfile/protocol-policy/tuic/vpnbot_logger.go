//go:build with_quic

// SPDX-License-Identifier: GPL-3.0-or-later
package tuic

import (
	"fmt"
	"regexp"

	"github.com/sagernet/sing/common/logger"
)

// sing-quic reports an unknown authentication UUID after access is revoked.
// Keep the error useful without retaining this part of the user's credentials.
var vpnBotUUID = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

type vpnBotTUICLogger struct{ logger.Logger }

func (l vpnBotTUICLogger) Error(args ...any) {
	l.Logger.Error(vpnBotUUID.ReplaceAllString(fmt.Sprint(args...), "[redacted UUID]"))
}

func (l vpnBotTUICLogger) Debug(args ...any) {
	l.Logger.Debug(vpnBotUUID.ReplaceAllString(fmt.Sprint(args...), "[redacted UUID]"))
}

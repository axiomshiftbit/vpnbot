// Built against the pinned official Mieru module. No credentials go in argv or diagnostics.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/enfein/mieru/v3/pkg/appctl"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/metrics"
	mpb "github.com/enfein/mieru/v3/pkg/metrics/metricspb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type counter struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Rolling  int64 `json:"rolling"`
}

func totals(list []*mpb.Metric, days int32) (counter, error) {
	c := counter{}
	for _, m := range list {
		if m.GetValue() < 0 {
			return c, fmt.Errorf("invalid counter")
		}
		switch m.GetName() {
		case metrics.UserMetricUploadBytes:
			c.Upload = m.GetValue()
		case metrics.UserMetricDownloadBytes:
			c.Download = m.GetValue()
		default:
			continue
		}
		if days > 0 {
			v, err := metrics.FromMetricPB(m)
			if err != nil {
				return c, err
			}
			timed, ok := v.(*metrics.Counter)
			if !ok {
				return c, fmt.Errorf("invalid counter type")
			}
			c.Rolling += timed.DeltaBetween(time.Now().Add(-24*time.Duration(days)*time.Hour), time.Now())
		}
	}
	return c, nil
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("expected operation")
	}
	op := os.Args[1]
	if op == "check" || op == "decode" || op == "baseline" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<20))
		if err != nil {
			return err
		}
		switch op {
		case "check":
			cfg := &pb.ServerConfig{}
			if err = common.UnmarshalJSON(data, cfg); err != nil {
				return err
			}
			return appctl.ValidateFullServerConfig(cfg)
		case "decode":
			url := strings.TrimSpace(string(data))
			var cfg *pb.ClientConfig
			if strings.HasPrefix(url, "mierus://") {
				var profile *pb.ClientProfile
				profile, err = appctl.URLToClientProfile(url)
				if err == nil {
					cfg = &pb.ClientConfig{Profiles: []*pb.ClientProfile{profile}, ActiveProfile: profile.ProfileName,
						Socks5Port: proto.Int32(1080), RpcPort: proto.Int32(1081)}
				}
			} else {
				cfg, err = appctl.URLToClientConfig(url)
			}
			if err != nil {
				return err
			}
			if err = appctl.ValidateFullClientConfig(cfg); err != nil {
				return err
			}
			out, err := common.MarshalJSON(cfg)
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(out)
			return err
		case "baseline":
			all := &mpb.AllMetrics{}
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
			if err != nil {
				return err
			}
			if err = proto.Unmarshal(decoded, all); err != nil {
				return err
			}
			users := map[string]counter{}
			for _, group := range all.GetGroups() {
				if !strings.HasPrefix(group.GetName(), "user - ") {
					return fmt.Errorf("invalid group")
				}
				c, err := totals(group.GetMetrics(), 0)
				if err != nil {
					return err
				}
				users[strings.TrimPrefix(group.GetName(), "user - ")] = c
			}
			return json.NewEncoder(os.Stdout).Encode(users)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := appctl.NewServerManagementRPCClient()
	if err != nil {
		return err
	}
	status, err := client.GetStatus(ctx, &emptypb.Empty{})
	if err != nil {
		return err
	}
	if op == "idle" {
		if status.GetStatus() != pb.AppStatus_IDLE {
			return fmt.Errorf("not idle")
		}
		_, err = client.GetMetrics(ctx, &emptypb.Empty{})
		return err
	}
	if op != "stats" || status.GetStatus() != pb.AppStatus_RUNNING {
		return fmt.Errorf("not running")
	}
	list, err := client.GetUsers(ctx, &emptypb.Empty{})
	if err != nil {
		return err
	}
	users := map[string]counter{}
	checkpoint := &mpb.AllMetrics{}
	// Keep histories for temporarily disabled/expired users. GetUsers only lists
	// the currently configured users; omission must not renew a rolling quota.
	previous, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<20))
	if err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(previous)))
	if err != nil {
		return err
	}
	old := &mpb.AllMetrics{}
	if err = proto.Unmarshal(decoded, old); err != nil {
		return err
	}
	active := map[string]bool{}
	for _, item := range list.GetItems() {
		name := item.GetUser().GetName()
		var days int32
		if q := item.GetUser().GetQuotas(); len(q) > 0 {
			days = q[0].GetDays()
		}
		c, err := totals(item.GetMetrics(), days)
		if err != nil {
			return err
		}
		users[name] = c
		active["user - "+name] = true
		checkpoint.Groups = append(checkpoint.Groups, &mpb.MetricGroup{Name: proto.String("user - " + name), Metrics: item.GetMetrics()})
	}
	for _, group := range old.GetGroups() {
		if !active[group.GetName()] {
			checkpoint.Groups = append(checkpoint.Groups, group)
		}
	}
	data, err := proto.Marshal(checkpoint)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"users": users, "native_metrics": base64.StdEncoding.EncodeToString(data)})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mieru control operation failed")
		os.Exit(1)
	}
}

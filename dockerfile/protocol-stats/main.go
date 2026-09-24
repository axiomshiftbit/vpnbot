// Built in the pinned sing-box source module, using its own protobuf contract.
package main

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/sagernet/sing-box/experimental/v2rayapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := grpc.NewClient("127.0.0.1:10085", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil { os.Exit(1) }
	defer conn.Close()
	// sing-box registers the V2Ray service name at runtime; its generated client
	// uses the protobuf namespace. Use the registered method and pinned types.
	stats := new(v2rayapi.QueryStatsResponse)
	err = conn.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats",
		&v2rayapi.QueryStatsRequest{Patterns: []string{"user>>>"}}, stats)
	if err != nil { os.Exit(1) }
	if json.NewEncoder(os.Stdout).Encode(stats) != nil { os.Exit(1) }
}

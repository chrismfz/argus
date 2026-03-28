package main
import (
	"context"
	"time"
	"argus/config"
	ch "github.com/ClickHouse/clickhouse-go/v2"
)

type ClickHouseInserter struct {
	conn   ch.Conn
	table  string
	fields []string
}

func NewClickHouseInserter(cfg *config.Config) (*ClickHouseInserter, error) {
	conn, err := ch.Open(&ch.Options{
		Addr: []string{cfg.ClickHouse.Host + ":9000"},
		Auth: ch.Auth{
			Database: cfg.ClickHouse.Database,
			Username: cfg.ClickHouse.User,
			Password: cfg.ClickHouse.Password,
		},
		Settings: ch.Settings{
			"send_logs_level": "trace",
		},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	return &ClickHouseInserter{
		conn:  conn,
		table: cfg.ClickHouse.Table,

fields: []string{
  "timestamp_start", "timestamp_end",  // <-- προστέθηκε
  "proto", "tcpflags", "tos",
  "src_host", "src_port", "src_host_country",
  "dst_host", "dst_port", "dst_host_country",
  "post_nat_src_ip","post_nat_dst_ip","post_nat_src_port","post_nat_dst_port",
  "peer_src_as", "peer_dst_as", "as_path", "local_pref",
  "packets", "bytes",
  "peer_dst_as_name", "peer_src_as_name", "dst_as",
  "input_interface", "output_interface",
  "input_interface_name", "output_interface_name",
  "next_hop",
  "flow_direction", "ip_protocol",
},

	}, nil
}

func (c *ClickHouseInserter) InsertFlow(ctx context.Context, flow *FlowRecord) error {
	batch, err := c.conn.PrepareBatch(ctx, "INSERT INTO "+c.table+
		" ("+joinFields(c.fields)+")")
	if err != nil {
		return err
	}

	if err := batch.AppendStruct(flow); err != nil {
		return err
	}
	return batch.Send()
}

func joinFields(fields []string) string {
	return "`" + join(fields, "`, `") + "`"
}

func join(arr []string, sep string) string {
	out := ""
	for i, v := range arr {
		if i > 0 {
			out += sep
		}
		out += v
	}
	return out
}

func (c *ClickHouseInserter) InsertBatch(ctx context.Context, flows []*FlowRecord) error {
    batch, err := c.conn.PrepareBatch(ctx, "INSERT INTO "+c.table+" ("+joinFields(c.fields)+")")
    if err != nil {
        return err
    }

    for _, flow := range flows {
        if err := batch.AppendStruct(flow); err != nil {
            return err
        }
    }

    return batch.Send()
}

package clickhouse

import (
	"context"
	"argus/internal/flow"
)

type Inserter struct {
	table  string
	fields []string
}

func NewInserter(table string) *Inserter {
	return &Inserter{
		table: table,
		fields: []string{
			"timestamp_start", "timestamp_end",
			"proto", "tcpflags", "tos",
			"src_host", "src_port", "src_host_country",
			"dst_host", "dst_port", "dst_host_country",
			"post_nat_src_ip", "post_nat_dst_ip", "post_nat_src_port", "post_nat_dst_port",
			"peer_src_as", "peer_dst_as", "as_path", "local_pref",
			"packets", "bytes",
			"peer_dst_as_name", "peer_src_as_name", "dst_as",
			"input_interface", "output_interface",
			"input_interface_name", "output_interface_name",
			"next_hop",
			"flow_direction", "ip_protocol",
		},
	}
}

func (c *Inserter) InsertBatch(ctx context.Context, flows []*flow.FlowRecord) error {
	batch, err := Global.PrepareBatch(ctx,
		"INSERT INTO "+c.table+" ("+joinFields(c.fields)+")")
	if err != nil {
		return err
	}
	for _, f := range flows {
		if err := batch.AppendStruct(f); err != nil {
			return err
		}
	}
	return batch.Send()
}

func joinFields(fs []string) string {
	return "`" + join(fs, "`, `") + "`"
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

package clickhouse

import "strings"

// FlowFields is the ordered list of columns for flow inserts.
var FlowFields = []string{
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
}

type Inserter struct {
	Table string
}

func NewInserter(table string) *Inserter {
	return &Inserter{Table: table}
}

func (c *Inserter) Query() string {
	return "INSERT INTO " + c.Table + " (`" + strings.Join(FlowFields, "`, `") + "`)"
}

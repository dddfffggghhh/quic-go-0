package congestion

import "github.com/lucas-clemente/quic-go/internal2/protocol"

type connectionStats struct {
	slowstartPacketsLost protocol.PacketNumber
	slowstartBytesLost   protocol.ByteCount
}

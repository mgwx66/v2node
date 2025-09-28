package core

import (
	"fmt"

	panel "github.com/wyx2685/v2node/api/v2board"
)

func (v *V2Core) AddNode(tag string, info *panel.NodeInfo) error {
	inBoundConfig, err := buildInbound(info, tag)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	outBoundConfig, err := buildDefaultOutbound()
	if err != nil {
		return fmt.Errorf("build outbound error: %s", err)
	}
	err = v.addOutbound(outBoundConfig)
	if err != nil {
		return fmt.Errorf("add outbound error: %s", err)
	}
	return nil
}

func (v *V2Core) DelNode(tag string) error {
	panic("unimplemented")
}

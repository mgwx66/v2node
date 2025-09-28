package core

import (
	"context"
	"fmt"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/xtls/xray-core/proxy"
)

func (v *V2Core) GetUserManager(tag string) (proxy.UserManager, error) {
	handler, err := v.ihm.GetHandler(context.Background(), tag)
	if err != nil {
		return nil, fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}
	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.UserManager", tag)
	}
	return userManager, nil
}

func (v *V2Core) AddUsers(p *AddUsersParams) (added int, err error) {
	panic("unimplemented")
}
func (v *V2Core) DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error {
	panic("unimplemented")
}

func (v *V2Core) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	panic("unimplemented")
}

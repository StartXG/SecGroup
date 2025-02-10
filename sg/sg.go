package sg

import (
	"fmt"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ecs20140526 "github.com/alibabacloud-go/ecs-20140526/v5/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
)

type SGItem struct {
	Policy       string // Accept, Drop
	IpPortocol   string // TCP, UDP, ICMP
	SourceCidrIp string // 来源IP
	PortRange    string // 端口范围
	Priority     string // 优先级 1-100
	Description  string // 描述
}

func NewAoac(accessKeyId string, accessKeySecret string) (_result *ecs20140526.Client, _err error) {
	config := &openapi.Config{
		AccessKeyId:     tea.String(accessKeyId),
		AccessKeySecret: tea.String(accessKeySecret),
	}
	config.Endpoint = tea.String("ecs.cn-hangzhou.aliyuncs.com")
	_result = &ecs20140526.Client{}
	_result, _err = ecs20140526.NewClient(config)
	return _result, _err
}

func (content *SGItem) GetRegionId(aoac *ecs20140526.Client) []*ecs20140526.DescribeRegionsResponseBodyRegionsRegion {
	// 获取地域ID
	describeRegionsRequest := &ecs20140526.DescribeRegionsRequest{}
	runtime := &util.RuntimeOptions{}
	_res, _err := aoac.DescribeRegionsWithOptions(describeRegionsRequest, runtime)
	if _err != nil {
		fmt.Println(_err)
		return nil
	}
	return _res.Body.Regions.Region
}

func (content *SGItem) CreateSecurityGroupRule(aoac *ecs20140526.Client, regionId string, securityGroupId string) {
	// 创建安全组规则
	authorizeSecurityGroupRequest := &ecs20140526.AuthorizeSecurityGroupRequest{
		RegionId:        tea.String(regionId),
		SecurityGroupId: tea.String(securityGroupId),
		Permissions: []*ecs20140526.AuthorizeSecurityGroupRequestPermissions{
			{
				IpProtocol:   tea.String(content.IpPortocol),
				PortRange:    tea.String(content.PortRange),
				SourceCidrIp: tea.String(content.SourceCidrIp),
				Policy:       tea.String(content.Policy),
				Priority:     tea.String(content.Priority),
				Description:  tea.String(content.Description),
			},
		},
	}

	runtime := &util.RuntimeOptions{}
	_res, _err := aoac.AuthorizeSecurityGroupWithOptions(authorizeSecurityGroupRequest, runtime)
	if _err != nil {
		fmt.Println(_err)
		return
	}
	fmt.Println(_res)
}

func (content *SGItem) DeleteSecurityGroupRule(aoac *ecs20140526.Client, regionId string, securityGroupId string) {
	// 删除安全组规则
	revokeSecurityGroupRequest := &ecs20140526.RevokeSecurityGroupRequest{
		RegionId:        tea.String(regionId),
		SecurityGroupId: tea.String(securityGroupId),
		IpProtocol:      tea.String(content.IpPortocol),
		PortRange:       tea.String(content.PortRange),
		SourceCidrIp:    tea.String(content.SourceCidrIp),
	}

	runtime := &util.RuntimeOptions{}
	_res, _err := aoac.RevokeSecurityGroupWithOptions(revokeSecurityGroupRequest, runtime)
	if _err != nil {
		fmt.Println(_err)
		return
	}
	fmt.Println(_res)
}

func (content *SGItem) DescribeSecurityGroupAttribute(aoac *ecs20140526.Client, regionId string, securityGroupId string) []*ecs20140526.DescribeSecurityGroupAttributeResponseBodyPermissionsPermission {
	// 查询安全组规则
	describeSecurityGroupAttributeRequest := &ecs20140526.DescribeSecurityGroupAttributeRequest{
		RegionId:        tea.String(regionId),
		SecurityGroupId: tea.String(securityGroupId),
	}

	runtime := &util.RuntimeOptions{}
	_res, _err := aoac.DescribeSecurityGroupAttributeWithOptions(describeSecurityGroupAttributeRequest, runtime)
	if _err != nil {
		fmt.Println(_err)
		return nil
	}
	return _res.Body.Permissions.Permission
}

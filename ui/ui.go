package ui

import (
	"SecGroupV2/sg"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alibabacloud-go/tea/tea"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

type Config struct {
	gorm.Model
	AccessKeyID     string
	AccessKeySecret string
	RegionID        string
	SecurityGroupID string
	PortRange       string
}

func GetCurrentPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		// 尝试备用服务
		resp, err = http.Get("https://ifconfig.me")
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()
	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ip)), nil
}

func loadConfig(db *gorm.DB) Config {
	var config Config
	db.First(&config)
	return config
}

func saveConfig(db *gorm.DB, config Config) {
	db.Save(&config)
}

func showDialog(w fyne.Window, title, message string) {
	d := dialog.NewInformation(title, message, w)
	d.Show()
	time.AfterFunc(time.Second, func() {
		d.Hide()
	})
}

func CreateUI() {
	a := app.New()
	w := a.NewWindow("Security Group Manager")

	db, err := gorm.Open(sqlite.Open("config.db"), &gorm.Config{})
	if err != nil {
		fmt.Println("failed to connect database")
		return
	}
	db.AutoMigrate(&Config{})

	config := loadConfig(db)

	if config.AccessKeyID == "" || config.AccessKeySecret == "" {
		fmt.Println("AccessKeyID or AccessKeySecret is empty, exiting...")
		return
	}

	currentIP, err := GetCurrentPublicIP()
	if err != nil {
		currentIP = "Error getting IP"
	}

	ipLabel := widget.NewLabel("我的当前IP: " + currentIP)
	akIDEntry := widget.NewEntry()
	akIDEntry.SetPlaceHolder("Access Key ID")
	akIDEntry.SetText(config.AccessKeyID)
	akSecretEntry := widget.NewEntry()
	akSecretEntry.SetPlaceHolder("Access Key Secret")
	akSecretEntry.SetText(config.AccessKeySecret)
	portRangeEntry := widget.NewEntry()
	portRangeEntry.SetPlaceHolder("Port Range [e.g.: 80/80]")
	portRangeEntry.SetText(config.PortRange)

	regionOptions := []string{}
	regionMap := map[string]string{}
	aoac, _ := sg.NewAoac(akIDEntry.Text, akSecretEntry.Text)
	sgItem := &sg.SGItem{}
	regions := sgItem.GetRegionId(aoac)
	for _, region := range regions {
		regionOptions = append(regionOptions, tea.StringValue(region.LocalName))
		regionMap[tea.StringValue(region.LocalName)] = tea.StringValue(region.RegionId)
	}
	regionIDSelect := widget.NewSelect(regionOptions, func(selected string) {
		config.RegionID = regionMap[selected]
	})
	for localName, regionID := range regionMap {
		if regionID == config.RegionID {
			regionIDSelect.SetSelected(localName)
			break
		}
	}

	securityGroupOptions := []string{}
	securityGroupMap := map[string]string{}
	securityGroups := sgItem.DescribeSecurityGroups(aoac, config.RegionID)
	for _, group := range securityGroups {
		label := fmt.Sprintf("%s - %s", tea.StringValue(group.SecurityGroupId), tea.StringValue(group.Description))
		securityGroupOptions = append(securityGroupOptions, label)
		securityGroupMap[label] = tea.StringValue(group.SecurityGroupId)
	}
	secGroupIDSelect := widget.NewSelect(securityGroupOptions, func(selected string) {
		config.SecurityGroupID = securityGroupMap[selected]
	})
	for label, groupID := range securityGroupMap {
		if groupID == config.SecurityGroupID {
			secGroupIDSelect.SetSelected(label)
			break
		}
	}

	resultContainer := container.NewVBox()

	queryButton := widget.NewButton("查询", func() {
		aoac, _ := sg.NewAoac(akIDEntry.Text, akSecretEntry.Text)
		sgItem := &sg.SGItem{}
		permissions := sgItem.DescribeSecurityGroupAttribute(aoac, config.RegionID, config.SecurityGroupID)
		// 更新 resultContainer 的数据
		resultContainer.Objects = nil
		for _, permission := range permissions {
			card := widget.NewCard(
				fmt.Sprintf("状态: %s", tea.StringValue(permission.Policy)),
				"",
				container.NewVBox(
					widget.NewLabel(fmt.Sprintf("协议: %s\n端口范围: %s\n源IP: %s\n优先级: %s\n描述: %s",
						tea.StringValue(permission.IpProtocol),
						tea.StringValue(permission.PortRange),
						tea.StringValue(permission.SourceCidrIp),
						tea.StringValue(permission.Priority),
						tea.StringValue(permission.Description))),
					widget.NewButton("删除", func() {
						sgItem := &sg.SGItem{
							IpPortocol:   tea.StringValue(permission.IpProtocol),
							PortRange:    tea.StringValue(permission.PortRange),
							SourceCidrIp: tea.StringValue(permission.SourceCidrIp),
						}
						sgItem.DeleteSecurityGroupRule(aoac, config.RegionID, config.SecurityGroupID)
						showDialog(w, "删除成功", "安全组规则已删除")
						queryButton.OnTapped() // 重新查询以刷新结果
					}),
				),
			)
			resultContainer.Add(card)
		}
		resultContainer.Refresh()
		showDialog(w, "查询成功", "安全组规则已查询")
	})

	openButton := widget.NewButton("对当前IP一键开放", func() {
		aoac, _ := sg.NewAoac(akIDEntry.Text, akSecretEntry.Text)
		sgItem := &sg.SGItem{
			Policy:       "Accept",
			IpPortocol:   "TCP",
			SourceCidrIp: currentIP + "/32",
			PortRange:    portRangeEntry.Text,
			Priority:     "1",
			Description:  "Allow HTTP",
		}
		sgItem.CreateSecurityGroupRule(aoac, config.RegionID, config.SecurityGroupID)
		showDialog(w, "开放成功", "当前IP已开放")
		queryButton.OnTapped() // 重新查询以刷新结果
	})

	saveButton := widget.NewButton("保存配置", func() {
		config := Config{
			AccessKeyID:     akIDEntry.Text,
			AccessKeySecret: akSecretEntry.Text,
			RegionID:        config.RegionID,
			SecurityGroupID: config.SecurityGroupID,
			PortRange:       portRangeEntry.Text,
		}
		saveConfig(db, config)
		showDialog(w, "保存成功", "配置已保存")
	})

	content := container.NewVBox(
		ipLabel,
		akIDEntry,
		akSecretEntry,
		regionIDSelect,
		secGroupIDSelect,
		portRangeEntry,
		queryButton,
		openButton,
		saveButton,
		resultContainer,
	)

	w.SetContent(content)
	w.ShowAndRun()
}

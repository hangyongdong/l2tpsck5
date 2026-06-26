package rosapi

import (
	"fmt"
	"strings"
)

// WiFis 获取无线网卡列表 (修复了 ROS v7 兼容性，自动适配驱动)
func (c *Client) WiFis() ([]map[string]any, error) {
	// 1. 先尝试传统无线路径 (ROS v6)
	// 去掉了 proplist 限制，防止漏抓关键属性
	rows, err := c.Run("/interface/wireless/print")
	
	// 如果没有报错，并且抓到了数据，说明是传统驱动
	if err == nil && len(rows) > 0 {
		return c.processLegacyWiFis(rows)
	}

	// 2. 如果上面报错了（或者数据为空），说明是新版，去尝试 ROS v7 的 wifi 路径
	v7Rows, v7Err := c.Run("/interface/wifi/print")
	if v7Err == nil {
		return c.processV7WiFis(v7Rows)
	}

	// 3. 两个路径都失败了才返回错误
	return nil, fmt.Errorf("未检测到无线网卡驱动 (legacy err: %v, v7 err: %v)", err, v7Err)
}

// 处理老版传统驱动数据
func (c *Client) processLegacyWiFis(rows []map[string]string) ([]map[string]any, error) {
	security, _ := c.wirelessPasswords()
	cidrs, _ := c.interfaceCIDRs()
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		name := row["name"]
		out = append(out, map[string]any{
			"id":          row[".id"],
			"name":        name,
			"ssid":        row["ssid"],
			"macAddress":  row["mac-address"],
			"disabled":    row["disabled"],
			"ipAddress":   firstNonEmpty(cidrs[name], "未分配网段"),
			"passphrase":  security[name],
			"defaultName": row["default-name"],
			"isVirtual":   row["master-interface"] != "",
			"wlanType":    "legacy",
		})
	}
	return out, nil
}

// 处理新版 ROS v7 WifiWave2 驱动数据
func (c *Client) processV7WiFis(rows []map[string]string) ([]map[string]any, error) {
	security, _ := c.v7WirelessPasswords() // 去拿 v7 专属的密码配置
	cidrs, _ := c.interfaceCIDRs()
	out := make([]map[string]any, 0, len(rows))
	
	for _, row := range rows {
		name := row["name"]

		// 自动适配 v7 的嵌套 SSID
		ssid := row["ssid"]
		if ssid == "" {
			ssid = row["configuration.ssid"]
		}

		// 自动适配 v7 的内联密码 (Inline) 或外部配置密码
		passphrase := row["security.passphrase"]
		if passphrase == "" {
			passphrase = row["configuration.security.passphrase"]
		}
		if passphrase == "" {
			secProfile := row["security"]
			if secProfile != "" {
				passphrase = security[secProfile]
			}
		}

		out = append(out, map[string]any{
			"id":          row[".id"],
			"name":        name,
			"ssid":        ssid,
			"macAddress":  row["mac-address"],
			"disabled":    row["disabled"],
			"ipAddress":   firstNonEmpty(cidrs[name], "未分配网段"),
			"passphrase":  passphrase,
			"isVirtual":   row["master-interface"] != "",
			"wlanType":    "v7",
		})
	}
	return out, nil
}

// 获取老版安全配置密码
func (c *Client) wirelessPasswords() (map[string]string, error) {
	profiles, err := c.Run("/interface/wireless/security-profiles/print", "=.proplist=name,wpa-pre-shared-key,wpa2-pre-shared-key")
	if err != nil {
		return map[string]string{}, nil
	}
	profilePass := map[string]string{}
	for _, row := range profiles {
		profilePass[row["name"]] = firstNonEmpty(row["wpa2-pre-shared-key"], row["wpa-pre-shared-key"])
	}
	wifis, err := c.Run("/interface/wireless/print", "=.proplist=name,security-profile")
	if err != nil {
		return map[string]string{}, nil
	}
	out := map[string]string{}
	for _, row := range wifis {
		out[row["name"]] = profilePass[row["security-profile"]]
	}
	return out, nil
}

// 【新增】获取新版 ROS v7 安全配置密码
func (c *Client) v7WirelessPasswords() (map[string]string, error) {
	profiles, err := c.Run("/interface/wifi/security/print")
	if err != nil {
		return map[string]string{}, nil
	}
	out := map[string]string{}
	for _, row := range profiles {
		out[row["name"]] = row["passphrase"] // ROS v7 密码存储在这里
	}
	return out, nil
}

// 获取网卡绑定的网段 IP (保持不变)
func (c *Client) interfaceCIDRs() (map[string]string, error) {
	rows, err := c.Run("/ip/address/print", "=.proplist=interface,address,network")
	if err != nil {
		return map[string]string{}, err
	}
	out := map[string]string{}
	for _, row := range rows {
		iface := row["interface"]
		addr := row["address"]
		if iface == "" || addr == "" {
			continue
		}
		out[iface] = addr
	}
	return out, nil
}

func (c *Client) ToggleWiFi(name, disabled string) error {
	if err := c.RunNoResult("/interface/wireless/set", "=.id="+name, "=disabled="+disabled); err == nil {
		return nil
	}
	return c.RunNoResult("/interface/wifi/set", "=.id="+name, "=disabled="+disabled)
}

// 修改 WiFi 配置 (修复了 v7 SSID 属性嵌套的坑)
func (c *Client) EditWiFi(data map[string]any) error {
	name := strings.TrimSpace(fmt.Sprint(data["name"]))
	if name == "" {
		return fmt.Errorf("WiFi 名称不能为空")
	}
	
	// 1. 先尝试组装老版驱动的修改命令
	args := []string{"/interface/wireless/set", "=.id=" + name}
	ssid := strings.TrimSpace(fmt.Sprint(data["ssid"]))
	if ssid != "" {
		args = append(args, "=ssid="+ssid)
	}
	if mac := strings.TrimSpace(fmt.Sprint(data["macAddress"])); mac != "" {
		args = append(args, "=mac-address="+mac)
	}
	
	if err := c.RunNoResult(args...); err != nil {
		// 2. 如果报错，说明是 ROS v7 新驱动
		args[0] = "/interface/wifi/set"
		
		// 遍历 args，把 "=ssid=" 替换为 v7 的 "=configuration.ssid="
		for i, arg := range args {
			if strings.HasPrefix(arg, "=ssid=") {
				args[i] = "=configuration.ssid=" + strings.TrimPrefix(arg, "=ssid=")
			}
		}
		
		if err2 := c.RunNoResult(args...); err2 != nil {
			return err // 返回原始错误
		}
	}
	return nil
}

func (c *Client) BatchEditWiFis(wifis []any) error {
	for _, item := range wifis {
		data, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if err := c.EditWiFi(data); err != nil {
			return err
		}
	}
	return nil
}

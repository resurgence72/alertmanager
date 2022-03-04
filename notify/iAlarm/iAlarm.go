// Copyright 2019 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iAlarm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/alertmanager/types"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/version"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/template"
)

// 定义 http header
var userAgentHeader = fmt.Sprintf("Alertmanager/%s", version.Version)

// 实现 Notifier 接口  接口只要求定义一个 Notify(context.Context, ...*types.Alert) (bool, error) 方法
type Notifier struct {
	conf    *config.InternalAlarmConfig
	tmpl    *template.Template
	logger  log.Logger
	client  *http.Client
	retrier *notify.Retrier
}

// 实现构造函数
func New(conf *config.InternalAlarmConfig, t *template.Template, l log.Logger) (*Notifier, error) {
	client, err := commoncfg.NewClientFromConfig(*conf.HTTPConfig, "webhook", false)
	if err != nil {
		return nil, err
	}

	return &Notifier{
		conf:   conf,
		tmpl:   t,
		logger: l,
		client: client,
		retrier: &notify.Retrier{
			CustomDetailsFunc: func(int, io.Reader) string {
				return conf.URL.String()
			},
		},
	}, nil
}

// Message defines the JSON object send to webhook endpoints.
type Message struct {
	*template.Data

	// The protocol version.
	Version  string `json:"version"`
	GroupKey string `json:"groupKey"`
}

// 内部请求 ruleKey 需要拿到的响应体
type RuleInstance struct {
	Data struct {
		Main string `json:"main"`
		Env  string `json:"env"`
		Sub  string `json:"sub"`
	} `json:"data"`
}

type RuleRequest struct {
	Main       string `json:"main"`
	Env        string `json:"env"`
	Sub        string `json:"sub"`
	Level      string `json:"level"`
	Subject    string `json:"subject"`
	Body       string `json:"body"`
	ReportTime int64  `json:"report_time"`
}

// 定义 Notify 函数
func (n *Notifier) Notify(ctx context.Context, alerts ...*types.Alert) (bool, error) {

	level.Info(n.logger).Log("自定义notify收到报警条数", len(alerts))
	// 核心 构建发送的结构体
	data := notify.GetTemplateData(ctx, n.tmpl, alerts, n.logger)

	groupKey, err := notify.ExtractGroupKey(ctx)
	if err != nil {
		level.Error(n.logger).Log("err", err)
	}

	// msg 为报警数据
	msg := &Message{
		Version:  "4",
		Data:     data,
		GroupKey: groupKey.String(),
	}

	// 1. 拿到所有的 rule 请求解析获取真正的参数
	// TODO 目前使用写死的内部网关
	InternalGateWay := "http://g-kong.17zuoye.net/live-manage-production.baize-serve/live/manage/baize/v1/case/detail?case_id="

	var buf bytes.Buffer

	// 构建当前所有alert
	for _, alert := range msg.Alerts {
		labels := alert.Labels
		annotations := alert.Annotations

		buf.WriteString(fmt.Sprintf("报警状态: [%s]\n", wrapAlert(alert.Status)))
		buf.WriteString(fmt.Sprintf("报警实例: [%s]\n", labels["instance"]))
		buf.WriteString(fmt.Sprintf("报警名称: [%s]\n", labels["alertname"]))
		buf.WriteString(fmt.Sprintf("报警开始时间: [%s]\n", alert.StartsAt))

		// 删除已经写入的标签
		delete(labels, "instance")
		delete(labels, "alertname")

		buf.WriteString("报警注解:\n")
		for k, v := range annotations {
			buf.WriteString(fmt.Sprintf("   [%s]   [%s]\n", k, v))
		}

		buf.WriteString("报警标签:\n")
		for k, v := range labels {
			buf.WriteString(fmt.Sprintf("   [%s]   [%s]\n", k, v))
		}
		buf.WriteString("\n\n")
	}

	for _, ruleKey := range n.conf.RuleKeySet {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("%s%s", InternalGateWay, ruleKey),
			nil,
		)
		if err != nil {
			return true, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", userAgentHeader)

		// 真正发起请求
		resp, err := n.client.Do(req.WithContext(ctx))
		if err != nil {
			level.Error(n.logger).Log("rule_key 请求失败", err)
			continue
		}

		var respBytes []byte
		if respBytes, err = ioutil.ReadAll(resp.Body); err != nil {
			level.Error(n.logger).Log("rule_key ReadAll", err)
			continue
		}

		ri := new(RuleInstance)
		if err := json.Unmarshal(respBytes, ri); err != nil {
			level.Error(n.logger).Log("RuleInstance Unmarshal", err)
			continue
		}

		// 2. 拿到参数去请求真正的报警
		// 发送 msg 消息
		ruleReq := &RuleRequest{
			Level:      "info",
			Subject:    "AlertManager报警",
			ReportTime: 1590733343156,
		}
		ruleReq.Main = ri.Data.Main
		ruleReq.Env = ri.Data.Env
		ruleReq.Sub = ri.Data.Sub
		ruleReq.Body = buf.String()

		alertBytes, err := json.Marshal([]*RuleRequest{ruleReq})
		if err != nil {
			level.Error(n.logger).Log("alertBytes Marshal", err)
			continue
		}
		level.Info(n.logger).Log("alert构建结果", string(alertBytes))

		resp, err = http.Post(n.conf.URL.String(), "application/json", bytes.NewBuffer(alertBytes))
		if err != nil {
			level.Error(n.logger).Log("最终发送失败", err)
			return true, err
		}
		level.Info(n.logger).Log("最终发送状态", resp.Status)

		notify.Drain(resp)
	}
	return true, nil
}

func wrapAlert(title string) string {
	switch title {
	case "firing":
		return wrapFiringAlert(title)
	case "resolved":
		return wrapResolvedAlert(title)
	default:
		return wrapFiringAlert(title)
	}
}

func wrapFiringAlert(title string) string {
	return fmt.Sprintf("<font color='red'>%s</font>", title)
}

func wrapResolvedAlert(title string) string {
	return fmt.Sprintf("<font color='green'>%s</font>", title)
}

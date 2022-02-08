package internal

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

	// 发送 msg 消息
	ruleReq := &RuleRequest{
		Level:      "info",
		Subject:    "AlertManager报警",
		ReportTime: 1590733343156,
	}
	// 1. 拿到所有的 rule 请求解析获取真正的参数
	// 使用写死的内部网关
	InternalGateWay := "http://g-kong.17zuoye.net/live-manage-production.baize-serve/live/manage/baize/v1/case/detail?case_id="

	var buf bytes.Buffer

	// 构建当前所有alert
	for _, alert := range msg.Alerts {
		buf.WriteString(fmt.Sprintf("状态: [%s]\n", alert.Status))
		buf.WriteString(fmt.Sprintf("开始时间: [%s]\n", alert.StartsAt))
		buf.WriteString(fmt.Sprintf("结束时间: [%s]\n", alert.EndsAt))
		buf.WriteString("标签:\n")
		for k, v := range alert.Labels {
			buf.WriteString(fmt.Sprintf(" %s: %s\n", k, v))
		}
		buf.WriteString("注解:\n")
		for k, v := range alert.Annotations {
			buf.WriteString(fmt.Sprintf(" %s: %s\n", k, v))
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
			continue
		}

		var respBytes []byte
		if respBytes, err = ioutil.ReadAll(resp.Body); err != nil {
			continue
		}

		ri := new(RuleInstance)
		if err := json.Unmarshal(respBytes, ri); err != nil {
			continue
		}

		// 2. 拿到参数去请求真正的报警
		ruleReq.Main = ri.Data.Main
		ruleReq.Env = ri.Data.Env
		ruleReq.Sub = ri.Data.Sub
		ruleReq.Body = buf.String()

		alertBytes, err := json.Marshal(ruleReq)
		if err != nil {
			continue
		}

		_, err = http.Post(n.conf.URL.String(), "application/json", bytes.NewBuffer(alertBytes))
		if err != nil {
			return true, err
		}
	}
	return true, nil
}

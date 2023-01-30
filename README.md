### 二次开发的alertmanager

#### 对接公司预警系统

### 0. 前提
由于内部告警系统的 rule_key 特性,二次开发am, 简化原先 am + webhook 的告警通道模式

### 1. 大致步骤

> 1. 需要在 notifiers.go 自定义 yaml 配置解析端;
> 2. 需要在 config/config.go 中添加上面实现的自定义结构体;
> 3. 在 notify 下创建自定义目录，就叫 iAaram, 然后在在下面创建一个 iAaram.go，实现具体内部逻辑;
> 4. 在 cmd/alertmanager/main.go 中注册 New();
>
> 详细步骤看代码即可



### 2. 最终效果

```yaml
# vim alertmanager.yml  

global:
  resolve_timeout: 5m
route:
  group_by: ['alertname']
  group_wait: 5s
  group_interval: 1m
  repeat_interval: 5m
  receiver: 'webhook-test'
  
receivers:
  - name: 'webhook-test'
    internal_config:   # 自定义预警配置段
      url: 'http://x.x.x.x:8123/live-manage-production.baize-collector/live/manage/baize/v1/report'
      rule_key_set:
        - 'xxxxxxxxxxxxx'  # 内部预警系统所需要的唯一告警id
        - 'xxxxxxxxxxxxx'
```





### 可根据步骤快速二开适配公司内部告警系统

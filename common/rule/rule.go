// Package rule is to control the audit rule behaviors
package rule

import (
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/XrayR-project/XrayR/api"
)

type Manager struct {
	InboundRule         *sync.Map // Key: Tag, Value: []api.DetectRule
	InboundDetectResult *sync.Map // key: Tag, Value: *sync.Map of api.DetectResult -> struct{}
}

func New() *Manager {
	return &Manager{
		InboundRule:         new(sync.Map),
		InboundDetectResult: new(sync.Map),
	}
}

func (r *Manager) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	if value, ok := r.InboundRule.LoadOrStore(tag, newRuleList); ok {
		oldRuleList := value.([]api.DetectRule)
		if !reflect.DeepEqual(oldRuleList, newRuleList) {
			r.InboundRule.Store(tag, newRuleList)
		}
	}
	return nil
}

func (r *Manager) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	detectResult := make([]api.DetectResult, 0)
	if value, ok := r.InboundDetectResult.LoadAndDelete(tag); ok {
		resultMap := value.(*sync.Map)
		resultMap.Range(func(key, _ interface{}) bool {
			detectResult = append(detectResult, key.(api.DetectResult))
			return true
		})
	}
	return &detectResult, nil
}

func (r *Manager) Detect(tag string, destination string, userKey string, srcIP string) (reject bool) {
	// Fast path: no rules loaded for this tag
	value, ok := r.InboundRule.Load(tag)
	if !ok {
		return false
	}

	ruleList := value.([]api.DetectRule)
	hitRuleID := -1
	for _, rule := range ruleList {
		if rule.Pattern.Match([]byte(destination)) {
			hitRuleID = rule.ID
			break
		}
	}

	if hitRuleID == -1 {
		return false
	}

	// Parse UID from userKey (format: "tag|email|uid")
	uid := 0
	if parts := strings.Split(userKey, "|"); len(parts) > 0 {
		uid, _ = strconv.Atoi(parts[len(parts)-1])
	}
	if uid == 0 {
		uid, _ = strconv.Atoi(userKey)
	}

	result := api.DetectResult{UID: uid, RuleID: hitRuleID, IP: srcIP}
	// Use sync.Map instead of mapset.Set to avoid external dependency overhead
	if v, ok := r.InboundDetectResult.Load(tag); ok {
		resultMap := v.(*sync.Map)
		resultMap.LoadOrStore(result, struct{}{})
	} else {
		newMap := &sync.Map{}
		newMap.Store(result, struct{}{})
		if v, loaded := r.InboundDetectResult.LoadOrStore(tag, newMap); loaded {
			v.(*sync.Map).LoadOrStore(result, struct{}{})
		}
	}

	return true
}

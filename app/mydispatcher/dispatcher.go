// Package mydispatcher implements a custom dispatcher with rate limiting and
// online device counting on top of the core Xray dispatcher.
package mydispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

// Type returns the feature type for the custom dispatcher itself. This keeps
// XrayR's dispatcher registered as a separate feature, without overriding the
// core routing.Dispatcher (github.com/xtls/xray-core/app/dispatcher).
//
// The controller accesses this feature via server.GetFeature(mydispatcher.Type())
// to use Limiter and RuleManager, while inbound handlers and core routing
// continue to use the official dispatcher.DefaultDispatcher for
// routing.DispatcherType(). This avoids type-assertion panics in upstream
// code that expects *dispatcher.DefaultDispatcher (e.g., vless/inbound).
func Type() interface{} {
	// Consumers should use server.GetFeature(mydispatcher.Type()) to access it.
	return (*DefaultDispatcher)(nil)
}

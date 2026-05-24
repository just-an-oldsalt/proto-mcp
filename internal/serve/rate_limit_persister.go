package serve

import (
	"context"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// rateLimitStoreAdapter bridges internal/store's rate_limit_state
// table to internal/mcp.RateLimitPersister. The two packages don't
// otherwise reference each other; this file is the only point of
// contact for Phase 6/E's bucket persistence.
//
// All translation is straight field-mapping. The composite key
// ("tool|pid" — set by middleware.runTool) passes through unchanged.
type rateLimitStoreAdapter struct {
	st *store.Store
}

func newRateLimitStoreAdapter(st *store.Store) *rateLimitStoreAdapter {
	return &rateLimitStoreAdapter{st: st}
}

func (a *rateLimitStoreAdapter) LoadAll(ctx context.Context) (map[string]mcp.PersistedBucket, error) {
	rows, err := a.st.LoadRateLimitState(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]mcp.PersistedBucket, len(rows))
	for k, v := range rows {
		out[k] = mcp.PersistedBucket{
			LimitSpec:  v.LimitSpec,
			Tokens:     v.Tokens,
			LastRefill: v.LastRefill,
		}
	}
	return out, nil
}

func (a *rateLimitStoreAdapter) Save(ctx context.Context, key string, b mcp.PersistedBucket) error {
	return a.st.SaveRateLimitBucket(ctx, store.RateLimitState{
		Key:        key,
		LimitSpec:  b.LimitSpec,
		Tokens:     b.Tokens,
		LastRefill: b.LastRefill,
	})
}

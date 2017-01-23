package context

import (
	"golang.org/x/net/context"
	"time"
)

const (
	defaultDockerTimeoutDuration = time.Duration(10) * time.Second

	defaultEtcdTimeoutDuration = time.Duration(10) * time.Second
)

/**
Just gets an injectable context that can be inlined thus:

etcdClient.Get(context.WithTimeout(time.Duration(1) * time.Second), ....)

This avoids generating the canceller func, and ignoring it, etc.

*/
func WithTimeout(timeout time.Duration) context.Context {
	return withTimeout(context.Background(), timeout)
}

func NoTimeout() context.Context {
	return context.Background()
}

func DefaultDockerTimeoutOverCtx(ctx context.Context) context.Context {
	return withTimeout(ctx, defaultDockerTimeoutDuration)
}

func DefaultDockerTimeout() context.Context {
	return DefaultDockerTimeoutOverCtx(context.Background())
}

func DefaultEtcdTimeoutOverCtx(ctx context.Context) context.Context {
	return withTimeout(ctx, defaultEtcdTimeoutDuration)
}

func DefaultEtcdTimeout() context.Context {
	return DefaultEtcdTimeoutOverCtx(context.Background())
}

func withTimeout(ctx context.Context, timeout time.Duration) context.Context {
	timeoutCtx, _ := context.WithTimeout(ctx, timeout)
	return timeoutCtx
}

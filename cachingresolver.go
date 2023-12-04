package recursive

type CachingResolver interface {
	Resolver
	Cacher
}

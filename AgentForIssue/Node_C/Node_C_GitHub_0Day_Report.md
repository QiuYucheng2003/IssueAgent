# Node C GitHub 0-Day Hunter Report

- 生成时间: 2026-07-16 01:15:09 CST
- 缺陷模式: `ThreadLocal_Lifecycle_Mismanagement_Context_Pollution_and_Resource_Leak`
- 仓库筛选: star >= 100, fork >= 10
- 候选查询数: 20
- 高置信/中置信可申报结果数: 0

## 使用的 Code Search Queries

- `language:Java stars:>100 forks:>10 "static final ThreadLocal" set -remove`
- `language:Java stars:>100 forks:>10 InheritableThreadLocal ExecutorService`
- `language:Java stars:>100 forks:>10 "ThreadLocal.withInitial" "() ->"`
- `language:Java stars:>100 forks:>10 "ThreadLocal" set password`
- `language:Java stars:>100 forks:>10 "static final" ThreadLocal Kryo`
- `language:Java stars:>100 forks:>10 ThreadLocal set -remove -finally`
- `language:Java stars:>100 forks:>10 ThreadLocal "set(" HTTP`
- `language:Java stars:>100 forks:>10 ThreadLocal "set(" Security`
- `language:Java stars:>100 forks:>10 "ThreadContext.bind" -remove`
- `language:Java stars:>100 forks:>10 "Biff8EncryptionKey.setCurrentUserPassword"`
- `language:Java stars:>100 forks:>10 "io.grpc.Context.attach" -detach`
- `language:Java stars:>100 forks:>10 "Mono.subscribeOn" ThreadLocal`
- `language:Java stars:>100 forks:>10 ThreadPoolExecutor "ThreadLocal.set"`
- `language:Java stars:>100 forks:>10 "Schedulers.boundedElastic" ThreadLocal`
- `language:Java stars:>100 forks:>10 "static final ThreadLocal" Supplier "->"`
- `language:Java stars:>100 forks:>10 ThreadLocal "set(" transaction -remove`
- `language:Java stars:>100 forks:>10 InheritableThreadLocal set -remove`
- `language:Java stars:>100 forks:>10 ThreadLocal loadClass`
- `language:Java stars:>100 forks:>10 "ThreadLocal" token set`
- `language:Java stars:>100 forks:>10 "ThreadLocal.remove" -finally`

## 结论

本次运行未发现可直接申报的中高置信候选。建议扩大查询数量、降低 star 阈值，或让 Node_B 产出更细粒度的规则后再次运行。

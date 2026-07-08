# Node C GitHub 0-Day Hunter Report

- 生成时间: 2026-07-01 08:23:33 CST
- 缺陷模式: `ThreadLocalStateLifecycleMismanagement`
- 仓库筛选: star >= 1000, fork >= 10
- 候选查询数: 8
- 高置信/中置信可申报结果数: 0

## 使用的 Code Search Queries

- `language:Java "implements Runnable" "ThreadLocal.set" stars:>100`
- `language:Java "implements Callable" "ThreadLocal.set" stars:>100`
- `language:Java "@Async" "ThreadLocal.set" stars:>100`
- `language:Java "CompletableFuture.supplyAsync" "ThreadLocal" stars:>100`
- `language:Java "executorService.submit" "ThreadLocal" stars:>100`
- `language:Java "ThreadLocal.withInitial" "this" stars:>100`
- `language:Java "ThreadLocal<Kryo>" stars:>100`
- `language:Java "ThreadContext" "SecurityUtils.getSubject" stars:>100`

## 结论

本次运行未发现可直接申报的中高置信候选。建议扩大查询数量、降低 star 阈值，或让 Node_B 产出更细粒度的规则后再次运行。

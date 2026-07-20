# Agentic Workflow 优化计划

## 当前状态

- 节点 0-4 固定顺序执行
- LLM 调用直接嵌入代码
- 无 RAG 支持
- 工具调用无统一规范

---

## 阶段一：Prompt 工程优化

### 适用节点
所有节点（节点 0、1、2、3、4）

### 目标
提升所有节点的 LLM 输出质量，减少格式错误和幻觉

### 具体实施方案

#### 1. Prompt 抽取为独立文件
- 将各节点硬编码在代码中的 prompt 抽取为独立 `.txt` 文件
- 文件路径：`prompts/node_*.txt`

#### 2. 节点 0 优化
- 增加关键词约束条件（必须包含 GitHub Issue 搜索语法）
- 增加示例输出格式
- 文件：`prompts/node_0_keyword_prompt.txt`

#### 3. 节点 1 优化
- 优化相关性过滤 prompt，增加明确的判断标准
- 文件：`prompts/node_1_filter_prompt.txt`

#### 4. 节点 2 优化
- 增强结构化输出要求（强制 JSON 格式）
- 增加多种缺陷模式的归纳引导
- 文件：`prompts/node_2_analysis_prompt.txt`

#### 5. 节点 3 优化
- 增加 GitHub Code Search 语法约束（禁止 stars/forks 限定符）
- 增加 query 多样性要求
- 文件：`prompts/node_3_query_prompt.txt`

#### 6. 节点 4 优化
- 增加误报过滤规则（明确哪些情况不算漏洞）
- 增加代码完整性判断（是否需要获取更多上下文）
- 文件：`prompts/node_4_verify_prompt.txt`

### 文件结构
```
prompts/
├── node_0_keyword_prompt.txt
├── node_1_filter_prompt.txt
├── node_2_analysis_prompt.txt
├── node_3_query_prompt.txt
└── node_4_verify_prompt.txt
```

### 需要修改的文件
- `nodes.py`：将硬编码的 prompt 改为读取文件

### 预期效果
- LLM 输出更稳定
- 减少格式错误（JSON 解析失败）
- 提高分析准确性

---

## 阶段二：RAG 增强

### 适用节点
节点 2（模式提炼）、节点 4（代码验证）

### 目标
利用知识库提高分析精度，减少幻觉，增强上下文理解

### 具体实施方案

#### 1. 节点 2 RAG 增强
- **构建知识库**：将节点 1 的漏洞案例 + 学术文献向量化存储
- **检索**：分析时检索与当前研究课题最相关的案例
- **重排**：按相关性排序后喂给 LLM
- **效果**：模式归纳更准确，减少遗漏

#### 2. 节点 4 RAG 增强
- **构建知识库**：将节点 2 的规则 + 已知漏洞模式向量化存储
- **检索**：验证时检索相似漏洞案例作为参考
- **效果**：提高误报过滤能力，减少漏报

### 文件结构
```
rag/
├── chunker.py        # 文档分片（按段落/语义切分）
├── vectorizer.py     # 向量化（使用 sentence-transformers）
├── retriever.py      # 召回 + 重排（FAISS + Cross-Encoder）
├── knowledge_store/  # 向量数据库目录
└── __init__.py
```

### 需要修改的文件
- `nodes.py`：节点 2 和节点 4 增加 RAG 检索逻辑

### 实施步骤
1. 安装依赖：`faiss-cpu`, `sentence-transformers`, `rank_bm25`
2. 实现 `chunker.py`：文档分片逻辑
3. 实现 `vectorizer.py`：向量化和向量存储
4. 实现 `retriever.py`：召回和重排
5. 修改节点 2：分析前先检索相关案例
6. 修改节点 4：验证前先检索相似漏洞

### 预期效果
- 模式归纳更准确（参考历史案例）
- 减少遗漏（检索相关但未注意到的案例）
- 提高误报过滤能力（对比已知漏洞模式）

---

## 阶段三：Function Call 规范化

### 适用节点
节点 1（漏洞打捞）、节点 3（零日搜索）、节点 4（代码验证）

### 目标
让 LLM 自主决定何时调用工具，增强可控性和智能性

### 具体实施方案

#### 1. 工具函数定义
将以下操作封装为工具函数：
```python
@tool
def search_github_issues(query: str, max_results: int = 10) -> list[dict]:
    """搜索 GitHub Issue/PR"""

@tool
def search_github_code(query: str, max_results: int = 20) -> list[dict]:
    """搜索 GitHub 代码"""

@tool
def get_file_content(repo: str, path: str) -> str:
    """获取 GitHub 文件完整内容"""

@tool
def search_repo_issues(repo: str, keywords: list[str]) -> list[dict]:
    """搜索指定仓库的相关 issues"""
```

#### 2. 节点 1 修改
- LLM 自主决定搜索哪些关键词
- 自主决定是否需要生成新关键词

#### 3. 节点 3 修改
- LLM 自主决定生成哪些搜索 query
- 自主决定是否需要调整搜索策略

#### 4. 节点 4 修改
- LLM 自主决定是否需要获取更多上下文（跨文件分析）
- 自主决定是否需要搜索相关 issues

### 文件结构
```
tools/
├── github_tools.py   # GitHub API 工具封装
├── __init__.py
```

### 需要修改的文件
- `nodes.py`：使用工具调用模式替代直接 API 调用

### 实施步骤
1. 安装依赖：`langchain-core`（Function Call 支持）
2. 实现 `tools/github_tools.py`
3. 修改节点 1：使用 Function Call 进行搜索
4. 修改节点 3：使用 Function Call 生成和执行搜索
5. 修改节点 4：使用 Function Call 获取文件内容

### 预期效果
- API 调用更规范
- LLM 可自主决策何时调用工具
- 增强智能性（根据结果调整策略）

---

## 阶段四：ReAct 智能循环

### 适用节点
节点 1（漏洞打捞）、节点 3（零日搜索）

### 目标
实现搜索-分析-再搜索的智能迭代，提高搜索效率

### 具体实施方案

#### 1. 节点 1 ReAct 循环
```
思考: 当前关键词搜索效果如何？结果够不够？
  ↓
行动: 调用搜索工具或生成新关键词
  ↓
观察: 评估结果数量和质量
  ↓
思考: 是否满足条件？
  ↓
循环直到满足条件或达到最大迭代次数
```

**具体实现**：
- 在 LangGraph 中添加 `think_node_1` 和 `action_node_1`
- `think_node_1`：评估当前搜索结果，决定下一步行动
- `action_node_1`：执行搜索或生成新关键词
- 终止条件：案例数达到目标 或 迭代次数达到上限

#### 2. 节点 3 ReAct 循环
```
思考: 当前 query 召回率如何？是否需要调整？
  ↓
行动: 执行搜索或生成新 query
  ↓
观察: 评估候选质量
  ↓
思考: 是否满足条件？
  ↓
循环直到满足条件
```

**具体实现**：
- 在 LangGraph 中添加 `think_node_3` 和 `action_node_3`
- `think_node_3`：评估当前搜索策略，决定是否调整
- `action_node_3`：执行搜索或生成新 query

### 需要修改的文件
- `workflow.py`：添加 ReAct 节点和条件分支
- `nodes.py`：实现思考和行动逻辑

### 实施步骤
1. 在 `workflow.py` 中定义 ReAct 状态（增加 `thoughts`, `iteration` 字段）
2. 实现 `think_node_1()`：评估搜索效果
3. 实现 `action_node_1()`：执行搜索或生成关键词
4. 添加条件分支：根据思考结果决定下一步
5. 对节点 3 重复以上步骤

### 预期效果
- 搜索更高效（自动调整关键词/query）
- 减少无效搜索（评估后再决定）
- 提高案例收集质量（智能迭代）

---

## 阶段五：SSE 流式输出

### 适用节点
节点 2（模式提炼）、节点 4（代码验证）

### 目标
实时反馈分析进度，提升用户体验

### 具体实施方案

#### 1. 节点 2 流式输出
- 将 LLM 响应改为流式输出
- 实时显示分析进度（正在分析第几个案例...）
- 实时显示已发现的缺陷模式

#### 2. 节点 4 流式输出
- 将 LLM 响应改为流式输出
- 实时显示验证进度（正在验证第几个候选...）
- 实时显示验证结果（✅/❌）

### 需要修改的文件
- `nodes.py`：将 `chat.completions.create()` 改为流式调用
- `main.py`：处理流式输出

### 实施步骤
1. 修改节点 2 的 LLM 调用：添加 `stream=True`
2. 修改节点 4 的 LLM 调用：添加 `stream=True`
3. 在 `main.py` 中处理流式输出，实时打印

### 预期效果
- 实时显示分析进度
- 减少等待焦虑
- 提升交互体验

---

## 阶段六：MCP 标准化

### 适用节点
节点 1（漏洞打捞）、节点 3（零日搜索）、节点 4（代码验证）

### 目标
统一外部工具调用接口，便于维护和扩展

### 具体实施方案

#### 1. GitHub API MCP 封装
```python
class GithubSearchMCP:
    def search_issues(self, query: str, max_results: int) -> list[dict]:
        """搜索 GitHub Issue/PR"""
    
    def search_code(self, query: str, max_results: int) -> list[dict]:
        """搜索 GitHub 代码"""
    
    def get_file(self, repo: str, path: str) -> str:
        """获取 GitHub 文件内容"""
    
    def get_repo_info(self, repo: str) -> dict:
        """获取仓库信息"""
```

#### 2. LLM API MCP 封装
```python
class LLMServiceMCP:
    def chat(self, messages: list[dict], stream: bool = False) -> str:
        """调用 LLM 进行对话"""
    
    def embed(self, text: str) -> list[float]:
        """向量化文本"""
```

#### 3. 统一调用接口
所有节点通过 MCP 接口调用外部服务，不直接调用原始 API

### 文件结构
```
mcp/
├── github_mcp.py     # GitHub API MCP 封装
├── llm_mcp.py        # LLM API MCP 封装
└── __init__.py
```

### 需要修改的文件
- `nodes.py`：使用 MCP 接口替代直接 API 调用

### 实施步骤
1. 实现 `mcp/github_mcp.py`
2. 实现 `mcp/llm_mcp.py`
3. 修改节点 1/3/4：使用 MCP 接口

### 预期效果
- 工具调用标准化
- 便于维护和扩展（更换 API 只需修改 MCP）
- 降低耦合

---

## 优先级

| 优先级 | 阶段 | 理由 | 适用节点 |
|--------|------|------|---------|
| P0 | 阶段一：Prompt 工程 | 成本低，效果显著 | 所有节点 |
| P0 | 阶段二：RAG 增强 | 提高分析准确性 | 节点 2、4 |
| P1 | 阶段三：Function Call | 增强可控性和智能性 | 节点 1、3、4 |
| P1 | 阶段四：ReAct 循环 | 智能搜索迭代 | 节点 1、3 |
| P2 | 阶段五：SSE 输出 | 体验提升 | 节点 2、4 |
| P2 | 阶段六：MCP 标准化 | 架构优化 | 节点 1、3、4 |

---

## 依赖关系

```
阶段一 → 阶段二 → 阶段三 → 阶段四 → 阶段五 → 阶段六
            ↓              ↓
            └──── 阶段六 ──┘
```

**建议**：按顺序执行，阶段五和阶段六可并行。

---

## 总结

| 阶段 | 核心价值 | 实施难度 |
|------|---------|---------|
| 阶段一 | 提升 LLM 输出质量 | 低 |
| 阶段二 | 提高分析准确性 | 中 |
| 阶段三 | LLM 自主工具调用 | 中 |
| 阶段四 | 智能搜索迭代 | 高 |
| 阶段五 | 实时反馈 | 低 |
| 阶段六 | 架构标准化 | 中 |

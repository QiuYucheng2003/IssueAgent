# Research-SE-Agent: Node A (Issue Explorer)

## 📌 简介
本脚本为自动化漏洞挖掘智能体系统的**节点 A（历史缺陷溯源节点）**。其核心使命是针对指定的软件安全或程序分析研究课题，利用大语言模型（LLM）泛化专业检索词，自动从 GitHub 历史关闭的 Issue/PR 中打捞、清洗、筛选出高价值的真实漏洞案例，为后续的缺陷模式提取（节点 B）及零日漏洞挖掘（节点 C）建立原始数据集。

## 🚀 核心功能
1. **关键词泛化 (Query Expansion)**：利用 DeepSeek 将高层研究课题泛化为符合工业界报题习惯的 3 个精准英文检索词。
2. **本地历史记忆与增量去重 (Incremental Crawling & Local Deduplication)**：**[🔥 新增]** 脚本在检索前会自动读取并解析本地已有的 `Node_A_result.json` 数据。若发现 GitHub 捞取到的 Issue URL 已存在于历史数据中，将在第一阶段直接跳过，杜绝跨运行重复写入，并大幅节省大模型的语义判定 Token 费用。
3. **自动化打捞 (GitHub Retrieval)**：通过 `PyGithub` 跨仓库精准检索指定编程语言、高星（Star）且已修复（Closed）的真实缺陷记录。
4. **语义数据清洗 (Semantic Filtering)**：使用大模型对检索结果进行高层语义的课题相关性过滤，剔除纯代码重构、新特性开发等背景噪声。
5. **安全路径定位 (Path Anchor)**：基于当前脚本物理位置动态锚定存储路径，确保在任何终端工作目录下执行，数据均能准确落地至 `Node_A` 文件夹。

## 🛠️ 环境依赖
```bash
pip install openai PyGithub


Node_A_keywords.txt: 记录大模型生成并采用过的所有学术泛化检索词。
Node_A_result.json: 高价值 Issue 数据集。采用标准 JSONL 格式（每行一个独立的 JSON 对象），字段包含：
{"title": "漏洞标题", "url": "GitHub链接", "repository": "组织/仓库名", "body": "Issue正文/讨论切片"}
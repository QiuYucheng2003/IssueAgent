# Research-SE-Agent: Node B (Pattern Analyzer)

## 📌 简介
本脚本为自动化漏洞挖掘智能体系统的**节点 B（缺陷模式总结节点）**。其核心使命是充当“AI 学术导师”，自动读取节点 A 长期打捞并去重落盘的真实漏洞原始数据（`Node_A_result.json`），利用大语言模型的长上下文与高级推理能力，横向对比、提炼出漏洞的底层共性、触发路径、代码特征及修复方案，最终将其转化为结构化的**缺陷模式规则通缉令**，为节点 C（猎手 Agent）提供精准的漏洞扫射依据。

## 🚀 核心任务
1. **数据跨模块加载 (Data Ingestion)**：自动锚定并跨目录读取 `Node_A/Node_A_result.json` 中的所有高质量 Issue 语料。
2. **共性模式横向对比 (Cross-Case Synthesis)**：将离散的、不同开源项目的缺陷描述打包，投喂给大模型进行多样本深度审计。
3. **缺陷通缉令提炼 (Vulnerability Profile Extraction)**：从语义层面强力归纳出：
   * **核心缺陷成因**：到底是什么代码结构没写好（如动态代理拦截器缺失 `finally` 块）。
   * **共性污点源与汇聚点 (Source & Sink)**：变量从哪里流入，在哪个危险函数触发。
   * **静态特征规则 (Static Signatures)**：哪些类、方法或模式可以作为静态代码检测（Soot/Infer）的目标。
4. **结构化双规则输出 (Structured Output)**：同时以追加或覆盖形式持久化输出两种格式：
   * `Node_B_profile.md`: 供人类学者阅读的高质量学术模式研究报告。
   * `Node_B_rules.json`: 供下一阶段代码自动解析的结构化规则配置文件。

## 📥 输入说明
* **文件路径**：`../Node_A/Node_A_result.json` (自动向上寻址)
* **文件格式**：JSONL (每行一个完整的 GitHub Issue 漏洞切片对象)

## 📤 产出物说明
执行成功后，本目录下将落地两个核心资产：
1. `Node_B_profile.md`：深入剖析误用场景的学术级 Rulebook。
2. `Node_B_rules.json`：包含 `Target_Classes`, `Vulnerable_Methods`, `Regex_Patterns` 的结构化检测字典。
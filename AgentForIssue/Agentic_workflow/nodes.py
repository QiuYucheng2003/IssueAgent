import argparse
import base64
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from dotenv import load_dotenv
from github import Auth, Github, GithubException
from openai import OpenAI

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROMPTS_DIR = os.path.join(BASE_DIR, "prompts")

def _load_prompt(filename: str) -> str:
    path = os.path.join(PROMPTS_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

NODE_0_KEYWORDS_FILE = os.path.join(BASE_DIR, "node_0_keywords.txt")

NODE_1_KEYWORDS_FILE = os.path.join(BASE_DIR, "node_1_keywords.txt")
NODE_1_RESULT_FILE = os.path.join(BASE_DIR, "node_1_result.json")

NODE_2_INPUT_FILE = NODE_1_RESULT_FILE
NODE_2_OUTPUT_MD = os.path.join(BASE_DIR, "node_2_profile.md")
NODE_2_OUTPUT_JSON = os.path.join(BASE_DIR, "node_2_rules.json")

NODE_3_PATHS = {
    "rules": NODE_2_OUTPUT_JSON,
    "profile": NODE_2_OUTPUT_MD,
    "report": os.path.join(BASE_DIR, "node_3_0day_report.md"),
    "candidates": os.path.join(BASE_DIR, "node_3_candidates.jsonl"),
    "findings": os.path.join(BASE_DIR, "node_3_findings.jsonl"),
}

NODE_4_PATHS = {
    "candidates": NODE_3_PATHS["candidates"],
    "rules": NODE_2_OUTPUT_JSON,
    "verified": os.path.join(BASE_DIR, "node_4_verified.jsonl"),
    "report": os.path.join(BASE_DIR, "node_4_verification_report.md"),
}

DEFAULT_POLICY = {
    "fallback_queries": [],
    "required_all": [],
    "required_any": [],
    "issue_keywords": [],
    "extra_anchors": [],
}


@dataclass
class Node3Config:
    language: str
    max_queries: int
    max_per_query: int
    max_candidates_to_judge: int
    min_stars: int
    min_forks: int
    context_lines: int
    llm_snippet_chars: int
    sleep: float
    api_key: str
    github_token: str
    model: str
    base_url: str

    @classmethod
    def from_params(cls, **kwargs) -> "Node3Config":
        return cls(
            language=kwargs.get("language", "Java"),
            max_queries=kwargs.get("max_queries", 20),
            max_per_query=kwargs.get("max_per_query", 20),
            max_candidates_to_judge=kwargs.get("max_candidates_to_judge", 20),
            min_stars=kwargs.get("min_stars", 100),
            min_forks=kwargs.get("min_forks", 10),
            context_lines=kwargs.get("context_lines", 45),
            llm_snippet_chars=kwargs.get("llm_snippet_chars", 9000),
            sleep=kwargs.get("sleep", 0.8),
            api_key=os.environ.get("DEEPSEEK_API_KEY").strip(),
            github_token=os.environ.get("GITHUB_TOKEN").strip(),
            model=os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-pro"),
            base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
        )

    def validate(self) -> None:
        missing = []
        if not self.api_key:
            missing.append("DEEPSEEK_API_KEY")
        if not self.github_token:
            missing.append("GITHUB_TOKEN")
        if missing:
            raise RuntimeError(f"缺少环境变量: {', '.join(missing)}。请先配置后再运行节点 3。")


@dataclass
class Node4Config:
    max_candidates: int
    sleep: float
    github_token: str
    api_key: str
    model: str
    base_url: str
    max_code_chars: int

    @classmethod
    def from_params(cls, **kwargs) -> "Node4Config":
        return cls(
            max_candidates=kwargs.get("max_candidates", 5),
            sleep=kwargs.get("sleep", 2.0),
            github_token=os.environ.get("GITHUB_TOKEN").strip(),
            api_key=os.environ.get("DEEPSEEK_API_KEY").strip(),
            model=os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-pro"),
            base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
            max_code_chars=kwargs.get("max_code_chars", 8000),
        )

    def validate(self) -> None:
        missing = []
        if not self.github_token:
            missing.append("GITHUB_TOKEN")
        if not self.api_key:
            missing.append("DEEPSEEK_API_KEY")
        if missing:
            raise RuntimeError(f"缺少环境变量: {', '.join(missing)}。请先配置后再运行节点 4。")


@dataclass
class RuleBook:
    raw: dict[str, Any]
    targets: list[str]
    methods: list[str]
    sinks: list[str]
    patterns: list[dict]

    @classmethod
    def from_file(cls, path: str) -> "RuleBook":
        rules = _load_json(path)
        
        if isinstance(rules, list):
            patterns = rules
            all_targets = []
            all_methods = []
            all_sinks = []
            for pattern in patterns:
                all_targets.extend(pattern.get("target_frameworks_or_classes", []))
                all_methods.extend(pattern.get("vulnerable_methods", []))
                all_sinks.extend(pattern.get("sink_functions", []))
            
            raw = {
                "misuse_pattern_name": f"MultiplePatterns({len(patterns)})",
                "target_frameworks_or_classes": all_targets,
                "vulnerable_methods": all_methods,
                "sink_functions": all_sinks,
                "_patterns": patterns,
            }
            return cls(
                raw=raw,
                targets=_clean_list(all_targets),
                methods=_clean_list(all_methods),
                sinks=_clean_list(all_sinks),
                patterns=patterns,
            )
        else:
            return cls(
                raw=rules,
                targets=_clean_list(rules.get("target_frameworks_or_classes")),
                methods=_clean_list(rules.get("vulnerable_methods")),
                sinks=_clean_list(rules.get("sink_functions")),
                patterns=[rules],
            )

    @property
    def name(self) -> str:
        return str(self.raw.get("misuse_pattern_name", "UnknownPattern"))

    def anchors(self) -> list[str]:
        anchors = []
        for item in self.targets + self.methods + self.sinks:
            anchors.extend([item, _short_name(item), _method_name(item)])
        return _unique([anchor for anchor in anchors if anchor])

    def issue_keywords(self) -> list[str]:
        keywords = [self.name] + [_short_name(target) for target in self.targets[:3]]
        return _unique([keyword for keyword in keywords if keyword])

    def fallback_queries(self, language: str, limit: int) -> list[str]:
        queries = [f'"{_short_name(target)}" language:{language}' for target in self.targets if len(_short_name(target)) > 2]
        for method in self.methods:
            name = _method_name(method)
            queries.append(f'"{name}(" language:{language}')
        return _unique([query for query in queries if query])[:limit]


@dataclass
class CodeCandidate:
    repository: str
    repository_stars: int
    repository_forks: int
    repository_updated_at: str
    file_path: str
    file_url: str
    query: str
    code_snippet: str
    known_issue_hits: list[dict[str, str]]


@dataclass
class Finding:
    repository: str
    file_path: str
    file_url: str
    misuse_type: str
    confidence: str
    root_cause_zh: str
    root_cause_en: str
    evidence_lines: list[str]
    query: str
    repository_stars: int
    repository_forks: int
    repository_updated_at: str


@dataclass
class VerifiedFinding:
    repository: str
    repository_stars: int
    repository_forks: int
    file_path: str
    file_url: str
    is_misuse: bool
    misuse_type: str
    confidence: float
    root_cause: str
    evidence: list[str]
    suggestion: str


def _load_json(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"未找到输入文件: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_text(path: str) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _load_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"未找到输入文件: {path}")
    results = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                results.append(json.loads(line))
    return results


def _save_jsonl(path: str, items: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


def _append_jsonl(path: str, item: dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")


def _clean_list(value: Any) -> list[str]:
    return _unique([str(item).strip() for item in value]) if isinstance(value, list) else []


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def _short_name(value: str) -> str:
    return value.rsplit(".", 1)[-1].strip()


def _method_name(value: str) -> str:
    return _short_name(value).replace("()", "")


def _parse_json_from_llm(content: str, expected_type: type) -> Any:
    content = _strip_fence(content)
    try:
        parsed = json.loads(content)
        if isinstance(parsed, expected_type):
            return parsed
    except json.JSONDecodeError:
        pass

    pattern = r"\[[\s\S]*\]" if expected_type is list else r"\{[\s\S]*\}"
    match = re.search(pattern, content)
    if not match:
        return expected_type()
    parsed = json.loads(match.group(0))
    return parsed if isinstance(parsed, expected_type) else expected_type()


def _strip_fence(content: str) -> str:
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    return content.strip()


def _seen_urls(*paths: str) -> set[str]:
    seen = set()
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    item = json.loads(line)
                    url = item.get("file_url") or item.get("url")
                    if url:
                        seen.add(url)
                except json.JSONDecodeError:
                    continue
    return seen


def _get_llm_client() -> OpenAI:
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
    return OpenAI(api_key=api_key, base_url=base_url)


def _get_github_client() -> Github:
    token = os.environ.get("GITHUB_TOKEN")
    return Github(auth=Auth.Token(token), per_page=30)

# 搜索8个关键词
def run_node_0(topic: str, num_queries: int = 10) -> Dict[str, Any]:
    print(f"\n{'='*60}")
    print(f"🚀 启动节点 0 | 关键词泛化")
    print(f"{'='*60}")

    existing_queries = []
    if os.path.exists(NODE_0_KEYWORDS_FILE):
        with open(NODE_0_KEYWORDS_FILE, "r", encoding="utf-8") as f:
            existing_queries = [line.strip() for line in f if line.strip()]
        print(f"📄 已读取已有关键词: {len(existing_queries)} 个")

    if len(existing_queries) >= num_queries:
        print(f"✅ 关键词已足够（{len(existing_queries)} >= {num_queries}），跳过 LLM 生成")
        print(f"📋 使用已有关键词:")
        for i, query in enumerate(existing_queries, 1):
            print(f"   {i}. {query}")
        print(f"\n✨ 节点 0 执行完毕！")
        return {"queries": existing_queries, "topic": topic, "keywords_file": NODE_0_KEYWORDS_FILE, "generated": False}

    llm_client = _get_llm_client()
    needed = num_queries - len(existing_queries)

    used_clause = f"\n\n以下关键词已用过，请避免重复：\n{chr(10).join(existing_queries)}" if existing_queries else ""
    base_prompt = _load_prompt("node_0_keyword_prompt.txt")
    if not base_prompt:
        base_prompt = f"你是一个程序分析与软件测试领域的专家。正在研究课题: '{topic}'。请帮我生成 {needed} 个最可能出现在 GitHub Issue 标题或描述中的英文搜索关键词（Query）。请直接输出关键词列表，每行一个，不要包含任何多余的解释、序号或 Markdown 标记。{used_clause}"
    else:
        base_prompt = base_prompt.format(topic=topic, num_queries=needed) + used_clause
    prompt = base_prompt

    response = llm_client.chat.completions.create(
        model="deepseek-v4-pro",
        messages=[
            {"role": "system", "content": "You are a helpful assistant and a senior software engineering researcher."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2
    )
    new_queries = [line.strip() for line in response.choices[0].message.content.strip().split('\n') if line.strip()][:needed]

    queries = existing_queries + new_queries

    with open(NODE_0_KEYWORDS_FILE, "w", encoding="utf-8") as f:
        for q in queries:
            f.write(f"{q}\n")

    print(f"🤖 课题: {topic}")
    print(f"📋 关键词列表（已有 {len(existing_queries)} + 新生成 {len(new_queries)} = {len(queries)}）:")
    for i, query in enumerate(queries, 1):
        print(f"   {i}. {query}")

    print(f"\n✨ 节点 0 执行完毕！生成了 {len(new_queries)} 个新关键词。")
    return {"queries": queries, "topic": topic, "keywords_file": NODE_0_KEYWORDS_FILE, "generated": True}


def run_node_1(queries: List[str], topic: str, language: str = "Java", max_cases: int = 50, issues_per_query: int = 10) -> Dict[str, Any]:
    print(f"\n{'='*60}")
    print(f"🚀 启动节点 1 | 历史缺陷溯源")
    print(f"{'='*60}")

    llm_client = _get_llm_client()
    github_client = _get_github_client()

    total_added = 0
    seen_urls = set()

    print(f"⚙️ 参数配置:")
    print(f"   - 每个关键词最多检索: {issues_per_query} 个 issue")
    print(f"   - 最多保留案例数: {max_cases}")

    if os.path.exists(NODE_1_RESULT_FILE):
        try:
            with open(NODE_1_RESULT_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        historical_data = json.loads(line.strip())
                        if "url" in historical_data:
                            seen_urls.add(historical_data["url"])
            print(f"💾 成功加载本地历史数据，已自动锁定 {len(seen_urls)} 个已存在漏洞，本次将彻底跳过它们。")
        except Exception as e:
            print(f"⚠️ 读取历史数据失败: {e}")

    print(f"🔍 使用节点 0 生成的关键词进行搜索: {queries}\n")

    all_issues = []
    for query in queries:
        print(f"🔍 正在检索关键词: '{query}' ...")
        try:
            count = 0
            for issue in github_client.search_issues(query=f"{query} language:{language} state:closed"):
                if count >= issues_per_query:
                    break
                if not issue.body or len(issue.body) < 50 or issue.html_url in seen_urls:
                    continue
                seen_urls.add(issue.html_url)
                all_issues.append({
                    "title": issue.title,
                    "url": issue.html_url,
                    "repository": issue.repository.full_name,
                    "body": issue.body[:1500]
                })
                count += 1
        except Exception as e:
            print(f"⚠️ 检索 '{query}' 失败: {e}")

    print("\n🧹 正在使用大模型对结果进行课题相关性精炼...")
    final_issues = []
    for issue in all_issues:
        base_prompt = _load_prompt("node_1_filter_prompt.txt")
        if not base_prompt:
            base_prompt = f"评估该 GitHub Issue 是否属于【{topic}】相关的缺陷/缺陷讨论。只需回答 YES 或 NO：\n\n标题: {issue['title']}\n描述: {issue['body'][:500]}"
        else:
            base_prompt = base_prompt.format(topic=topic, title=issue['title'], body=issue['body'][:500])
        prompt = base_prompt
        try:
            res = llm_client.chat.completions.create(
                model="deepseek-v4-pro",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            ).choices[0].message.content.strip().upper()
            if "YES" in res:
                print(f"  [保留] -> {issue['repository']}: {issue['title']}")
                final_issues.append(issue)
            else:
                print(f"  [过滤] -> {issue['repository']}: {issue['title']}")
        except Exception:
            final_issues.append(issue)

    if max_cases > 0 and len(final_issues) > max_cases:
        print(f"\n📝 保留前 {max_cases} 个案例（共发现 {len(final_issues)} 个）")
        final_issues = final_issues[:max_cases]

    if final_issues:
        with open(NODE_1_RESULT_FILE, "a", encoding="utf-8") as f_res:
            for issue in final_issues:
                f_res.write(json.dumps(issue, ensure_ascii=False) + "\n")
        print(f"\n💾 高价值 Issue 结果已成功追加写入 -> {NODE_1_RESULT_FILE}")

        added_count = len(final_issues)
        total_added += added_count
        print(f"\n✨ 成功录入 {added_count} 个高价值学术素材。")
    else:
        print("\n⚠️ 未发现高度相关的案例，未执行文件写入。")

    print(f"\n{'='*50}")
    print(f"✨ 节点 1 执行完毕！本次成功录入 {total_added} 个高价值学术素材。")

    return {"added_count": total_added, "result_file": NODE_1_RESULT_FILE, "used_queries": queries}


def run_node_2() -> Dict[str, Any]:
    print(f"\n{'='*60}")
    print(f"🚀 启动节点 2 | 缺陷模式提炼")
    print(f"{'='*60}")

    llm_client = _get_llm_client()

    try:
        dataset = []
        if not os.path.exists(NODE_2_INPUT_FILE):
            raise FileNotFoundError(f"❌ 未找到节点 1 的数据集文件：{NODE_2_INPUT_FILE}，请先运行节点 1！")

        with open(NODE_2_INPUT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    dataset.append(json.loads(line.strip()))
        print(f"📥 成功吃入节点 1 历史沉淀的 {len(dataset)} 个高质量真实漏洞案例。")

        print("🧠 正在启动 DeepSeek 导师模式进行跨案例学术级横向对比...")

        formatted_corpus = ""
        for i, item in enumerate(dataset, 1):
            formatted_corpus += f"--- Case #{i} ---\nRepository: {item['repository']}\nTitle: {item['title']}\nDescription: {item['body']}\n\n"

        system_prompt = (
            "你是一个顶级的静态程序分析专家与系统安全科学家。你需要横向对比输入的多个真实漏洞案例，"
            "提炼出它们底层共性的【代码误用/缺陷模式规则】。你需要同时输出人类可读的深度学术报告以及计算机可读的结构化检测配置。"
        )

        base_prompt = _load_prompt("node_2_analysis_prompt.txt")
        if not base_prompt:
            user_prompt = f"""请仔细审计以下来自真实开源项目的缺陷上下文语料：

{formatted_corpus}

请完成以下两项任务：

任务 1：生成人类学者可读的学术模式研究报告。
要求语言干练、技术切中要害，包含：核心成因（Root Cause）、共性触发路径（Data Flow Path）、以及在静态分析（如Soot/Infer）或代码审查时的特征信号。

任务 2：生成静态分析器可解析的结构化规则。
请识别所有不同的代码误用模式，每种模式使用一个对象表示。
必须严格遵循 JSON 数组格式，每个对象包含以下字段：
- `misuse_pattern_name`: 缺陷模式名称
- `description`: 该模式的详细描述
- `target_frameworks_or_classes`: 涉及的常见危险类/接口/框架特征
- `vulnerable_methods`: 共性的缺陷触发或未清理方法名列表
- `sink_functions`: 最终造成危害或泄漏的汇聚点函数
- `detection_strategy`: 给静态分析器（如Soot、AST检查、Infer）的检测逻辑建议

【输出格式格式要求】：
请在回复中严格使用以下标记分隔两部分内容（不要包含任何多余的开头解释）：
[START_MARKDOWN]
(这里填写任务 1 的 Markdown 报告内容)
[END_MARKDOWN]
[START_JSON]
(这里填写任务 2 的纯 JSON 数组字符串，确保可以直接被 json.loads 解析)
[END_JSON]
"""
        else:
            user_prompt = base_prompt.format(corpus=formatted_corpus)

        response = llm_client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2
        ).choices[0].message.content.strip()

        md_content = response.split("[START_MARKDOWN]")[1].split("[END_MARKDOWN]")[0].strip()
        json_content = response.split("[START_JSON]")[1].split("[END_JSON]")[0].strip()

        with open(NODE_2_OUTPUT_MD, "w", encoding="utf-8") as f_md:
            f_md.write(md_content)
        print(f"📝 学术级模式报告已更新 -> {NODE_2_OUTPUT_MD}")

        try:
            parsed_json = json.loads(json_content)
            with open(NODE_2_OUTPUT_JSON, "w", encoding="utf-8") as f_json:
                json.dump(parsed_json, f_json, ensure_ascii=False, indent=2)
            print(f"📊 结构化检测规则通缉令已落地 -> {NODE_2_OUTPUT_JSON}")
        except Exception as e:
            print(f"⚠️ 大模型吐出的 JSON 格式有误，降级保存原始文本。错误: {e}")
            with open(NODE_2_OUTPUT_JSON, "w", encoding="utf-8") as f_json:
                f_json.write(json_content)

        print("\n✨ 节点 2 执行完毕！成功为您武装好下一阶段所需的检测规则库。")
        return {"success": True, "rules_file": NODE_2_OUTPUT_JSON, "report_file": NODE_2_OUTPUT_MD}

    except Exception as e:
        print(f"\n❌ 节点 2 运行失败: {e}")
        return {"success": False, "error": str(e)}


def run_node_3(language: str = "Java", max_queries: int = 20, max_per_query: int = 20) -> Dict[str, Any]:
    print(f"\n{'='*60}")
    print(f"🚀 启动节点 3 | 零日漏洞搜索")
    print(f"{'='*60}")

    try:
        config = Node3Config.from_params(
            language=language,
            max_queries=max_queries,
            max_per_query=max_per_query,
        )
        config.validate()

        llm_client = OpenAI(api_key=config.api_key, base_url=config.base_url)
        github_client = Github(auth=Auth.Token(config.github_token), per_page=30)

        rules_raw = _load_json(NODE_3_PATHS["rules"])
        patterns = rules_raw if isinstance(rules_raw, list) else [rules_raw]
        profile = _load_text(NODE_3_PATHS["profile"])

        print(f"📥 已加载 {len(patterns)} 种缺陷模式")

        total_candidates = 0

        for pattern_index, pattern in enumerate(patterns, 1):
            print(f"\n{'='*60}")
            print(f"🎯 处理模式 {pattern_index}/{len(patterns)}: {pattern.get('misuse_pattern_name', 'Unknown')}")
            print(f"{'='*60}")

            pattern_rules = RuleBook(
                raw=pattern,
                targets=_clean_list(pattern.get("target_frameworks_or_classes")),
                methods=_clean_list(pattern.get("vulnerable_methods")),
                sinks=_clean_list(pattern.get("sink_functions")),
                patterns=[pattern],
            )

            mode_candidates_file = NODE_3_PATHS["candidates"].replace("node_3_candidates", f"node_3_mode{pattern_index}_candidates")

            fallback = pattern_rules.fallback_queries(config.language, config.max_queries)
            base_prompt = _load_prompt("node_3_query_prompt.txt")
            if not base_prompt:
                prompt = f"""你是程序分析与软件测试方向的 GitHub Code Search 专家。

节点 2 已总结出以下缺陷规则：
{json.dumps(pattern, ensure_ascii=False, indent=2)}

补充学术报告摘要：
{profile[:2500]}

请生成 {config.max_queries} 条 GitHub Code Search 查询语句，用于寻找尚未被申报 issue 的真实代码误用候选。
要求：
1. 每条 query 必须能直接传给 GitHub Code Search。
2. 每条 query 必须包含 language:{config.language} 限定符。
3. 不要使用 stars: 或 forks: 限定符，这些在 Code Search 中不支持。
4. 不要搜索 issue，只搜索代码。
5. 直接输出 JSON 数组字符串，不要 Markdown。
"""
            else:
                prompt = base_prompt.format(
                    max_queries=config.max_queries,
                    language=config.language,
                    pattern=json.dumps(pattern, ensure_ascii=False, indent=2),
                    profile=profile[:2500]
                )
            try:
                response = llm_client.chat.completions.create(
                    model=config.model,
                    messages=[
                        {"role": "system", "content": "You generate precise GitHub code search queries for software testing research."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.2,
                )
                llm_queries = _parse_json_from_llm(response.choices[0].message.content or "", list)
                queries = [str(query).strip() for query in llm_queries if str(query).strip()]
                queries += [query for query in fallback if query not in queries]
                queries = queries[:config.max_queries]
            except Exception as exc:
                print(f"⚠️ LLM 生成 query 失败，降级使用本地规则生成 query: {exc}")
                queries = fallback

            if not queries:
                print(f"⚠️ 模式 {pattern_index} 未能生成任何 query，跳过")
                continue

            print(f"🤖 模式 {pattern_index} 生成 {len(queries)} 条搜索 query。")

            candidates: list[CodeCandidate] = []
            visited = _seen_urls(mode_candidates_file)

            for query in queries:
                print(f"🔍 Code Search: {query}")
                try:
                    kept = 0
                    result_count = 0
                    for result in github_client.search_code(query=query):
                        result_count += 1
                        if kept >= config.max_per_query:
                            break
                        repo = result.repository
                        if repo.stargazers_count < config.min_stars or repo.forks_count < config.min_forks:
                            print(f"  [{result_count}] 跳过: {repo.full_name} (stars={repo.stargazers_count}, forks={repo.forks_count})")
                            continue
                        if result.html_url in visited:
                            print(f"  [{result_count}] 跳过: {repo.full_name} (已访问)")
                            continue

                        path_lower = result.path.lower()
                        excluded_patterns = ["test/", "/test/", "tests/", "/tests/", "_test.java", ".test.java",
                                             "example/", "/example/", "tutorial/", "/tutorial/",
                                             "learning/", "/learning/", "demo/", "/demo/", "samples/"]
                        if any(pattern_str in path_lower for pattern_str in excluded_patterns):
                            print(f"  [{result_count}] 跳过: {repo.full_name} (路径包含测试/教程文件)")
                            continue

                        try:
                            raw = result.decoded_content
                        except Exception:
                            try:
                                raw = base64.b64decode(result.content)
                            except Exception:
                                continue

                        lines = raw.decode("utf-8", errors="replace").splitlines()
                        if len(lines) <= config.context_lines * 2:
                            snippet = "\n".join(f"{i + 1}: {line}" for i, line in enumerate(lines))
                        else:
                            hit_indexes = [i for i, line in enumerate(lines) if any(anchor in line for anchor in pattern_rules.anchors())]
                            if not hit_indexes:
                                snippet = "\n".join(f"{i + 1}: {line}" for i, line in enumerate(lines[: config.context_lines * 2]))
                            else:
                                selected = []
                                for start, end in _merge_windows(hit_indexes[:4], len(lines), config.context_lines):
                                    if selected:
                                        selected.append("...")
                                    selected.extend(f"{i + 1}: {lines[i]}" for i in range(start, end))
                                snippet = "\n".join(selected)

                        if not snippet.strip():
                            print(f"  [{result_count}] 跳过: {repo.full_name} (代码片段为空)")
                            continue

                        if pattern_rules.is_threadlocal:
                            if not (all(term in snippet for term in THREADLOCAL_POLICY["required_all"]) and
                                    any(term in snippet for term in THREADLOCAL_POLICY["required_any"])):
                                print(f"  [{result_count}] 跳过: {repo.full_name} (静态过滤不通过)")
                                continue

                        candidate = CodeCandidate(
                            repository=repo.full_name,
                            repository_stars=repo.stargazers_count,
                            repository_forks=repo.forks_count,
                            repository_updated_at=repo.updated_at.isoformat() if repo.updated_at else "",
                            file_path=result.path,
                            file_url=result.html_url,
                            query=query,
                            code_snippet=snippet,
                            known_issue_hits=[],
                        )
                        candidates.append(candidate)
                        _append_jsonl(mode_candidates_file, asdict(candidate))
                        visited.add(result.html_url)
                        kept += 1
                        print(f"  [{result_count}] 保留: {repo.full_name}/{result.path} (stars={repo.stargazers_count})")
                        if config.sleep:
                            time.sleep(config.sleep)
                except GithubException as exc:
                    print(f"⚠️ GitHub 搜索失败: {query} | {exc.status} {exc.data}")
                except Exception as exc:
                    print(f"⚠️ GitHub 搜索失败: {query} | {exc}")

            print(f"📦 模式 {pattern_index} 获得 {len(candidates)} 个静态候选。")

            total_candidates += len(candidates)

        print(f"\n{'='*60}")
        print(f"✨ 节点 3 执行完毕！")
        print(f"   总候选数: {total_candidates}")
        print(f"   模式数: {len(patterns)}")
        return {"success": True, "candidates_count": total_candidates, "patterns_count": len(patterns)}

    except Exception as e:
        print(f"\n❌ 节点 3 运行失败: {e}")
        return {"success": False, "error": str(e)}


def run_node_4(max_candidates: int = 5) -> Dict[str, Any]:
    print(f"\n{'='*60}")
    print(f"🚀 启动节点 4 | 代码验证确认")
    print(f"{'='*60}")

    try:
        config = Node4Config.from_params(
            max_candidates=max_candidates,
        )
        config.validate()

        auth = Auth.Token(config.github_token)
        github_client = Github(auth=auth)

        llm_client = OpenAI(api_key=config.api_key, base_url=config.base_url)

        rules = _load_json(NODE_4_PATHS["rules"])

        print(f"📋 已加载规则: {NODE_4_PATHS['rules']}")
        print(f"🤖 LLM 模型: {config.model}")

        candidates_data = []
        import glob
        candidates_pattern = NODE_4_PATHS["candidates"].replace("node_3_candidates", "node_3_mode*_candidates")
        for candidates_file in glob.glob(candidates_pattern):
            print(f"📥 加载候选文件: {candidates_file}")
            candidates_data.extend(_load_jsonl(candidates_file))
        
        if not candidates_data:
            print(f"⚠️ 未找到任何候选文件，尝试加载默认文件: {NODE_4_PATHS['candidates']}")
            candidates_data = _load_jsonl(NODE_4_PATHS["candidates"])
        candidates = [
            CodeCandidate(
                repository=data.get("repository", ""),
                repository_stars=data.get("repository_stars", 0),
                repository_forks=data.get("repository_forks", 0),
                repository_updated_at=data.get("repository_updated_at", ""),
                file_path=data.get("file_path", ""),
                file_url=data.get("file_url", ""),
                query=data.get("query", ""),
                code_snippet=data.get("code_snippet", ""),
                known_issue_hits=data.get("known_issue_hits", []),
            )
            for data in candidates_data
        ]

        if max_candidates > 0:
            candidates = candidates[:max_candidates]

        print(f"🔍 待验证候选数: {len(candidates)}")

        verified_findings = []
        for i, candidate in enumerate(candidates, 1):
            print(f"\n{'='*60}")
            print(f"第 {i}/{len(candidates)} 个候选")
            print(f"🔍 验证: {candidate.repository}/{candidate.file_path}")

            try:
                repo = github_client.get_repo(candidate.repository)
                contents = repo.get_contents(candidate.file_path)
                if hasattr(contents, "decoded_content"):
                    full_content = contents.decoded_content.decode("utf-8", errors="replace")
                elif hasattr(contents, "content"):
                    full_content = base64.b64decode(contents.content).decode("utf-8", errors="replace")
                else:
                    full_content = ""
            except GithubException as exc:
                print(f"  ⚠️ 获取文件失败: {exc.status} {exc.data}")
                full_content = ""
            except Exception as exc:
                print(f"  ⚠️ 获取文件失败: {exc}")
                full_content = ""

            if not full_content:
                print("  ❌ 获取文件内容失败")
                finding = VerifiedFinding(
                    repository=candidate.repository,
                    repository_stars=candidate.repository_stars,
                    repository_forks=candidate.repository_forks,
                    file_path=candidate.file_path,
                    file_url=candidate.file_url,
                    is_misuse=False,
                    misuse_type="FETCH_FAILED",
                    confidence=0.0,
                    root_cause="无法获取完整文件内容",
                    evidence=[],
                    suggestion="跳过此候选",
                )
                verified_findings.append(finding)
                _append_jsonl(NODE_4_PATHS["verified"], asdict(finding))
                if i < len(candidates):
                    time.sleep(config.sleep)
                continue

            print(f"  📄 文件共 {len(full_content.splitlines())} 行")
            print(f"  🤖 正在调用 LLM 分析...")

            code_with_lines = "\n".join(f"{i + 1}: {line}" for i, line in enumerate(full_content.splitlines()))
            code_for_llm = code_with_lines[:config.max_code_chars]
            rules_summary = json.dumps(rules, ensure_ascii=False, indent=2)

            base_prompt = _load_prompt("node_4_verify_prompt.txt")
            if not base_prompt:
                prompt = f"""你是一位资深的 Java 代码安全审计专家。

## 分析任务

请分析以下 GitHub 代码文件，判断是否存在节点 2 规则中描述的代码误用/漏洞/bug。

## 缺陷规则

{rules_summary}

## 代码文件信息

- Repository: {candidate.repository}
- File: {candidate.file_path}
- URL: {candidate.file_url}
- 搜索 Query: {candidate.query}

## 代码内容

```java
{code_for_llm}
```

## 判断标准

请严格依据上述【缺陷规则】中的每个误用模式进行判断：
1. 检查代码是否匹配某个误用模式的 `target_frameworks_or_classes`
2. 检查代码是否包含该模式的 `vulnerable_methods` 调用
3. 检查代码是否缺少该模式的 `sink_functions`（清理/修复方法）
4. 根据 `detection_strategy` 描述的检测逻辑进行分析

## 输出要求

请严格按照以下 JSON 格式输出分析结果：

```json
{{
    "is_misuse": true/false,
    "misuse_type": "匹配的误用模式名称或 NOT_MISUSE",
    "confidence": 0.0-1.0,
    "root_cause": "详细的中文根因分析",
    "evidence": ["第 X 行: 关键代码片段1", "第 Y 行: 关键代码片段2"],
    "suggestion": "中文修复建议"
}}
```

注意：
- is_misuse 必须是布尔值
- confidence 必须是 0 到 1 之间的浮点数
- evidence 必须是字符串数组，包含关键代码行号和内容
- misuse_type 应填写匹配到的具体误用模式名称，如果不匹配任何模式则填写 "NOT_MISUSE"
- 请基于代码内容和缺陷规则给出准确的判断，不要编造信息
- 如果文件内容不完整或无法判断，请明确说明
"""
            else:
                prompt = base_prompt.format(
                    rules=rules_summary,
                    repository=candidate.repository,
                    file_path=candidate.file_path,
                    file_url=candidate.file_url,
                    query=candidate.query,
                    code=code_for_llm
                )

            try:
                response = llm_client.chat.completions.create(
                    model=config.model,
                    messages=[
                        {"role": "system", "content": "你是一位资深的 Java 代码安全审计专家。"},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.1,
                )

                content = response.choices[0].message.content.strip()
                json_match = re.search(r"\{[\s\S]*\}", content)
                if json_match:
                    result = json.loads(json_match.group())
                else:
                    result = {
                        "is_misuse": False,
                        "misuse_type": "PARSE_ERROR",
                        "confidence": 0.0,
                        "root_cause": "LLM 返回格式错误，无法解析结果",
                        "evidence": [],
                        "suggestion": "跳过此候选",
                    }

                finding = VerifiedFinding(
                    repository=candidate.repository,
                    repository_stars=candidate.repository_stars,
                    repository_forks=candidate.repository_forks,
                    file_path=candidate.file_path,
                    file_url=candidate.file_url,
                    is_misuse=result.get("is_misuse", False),
                    misuse_type=result.get("misuse_type", "UNKNOWN"),
                    confidence=result.get("confidence", 0.0),
                    root_cause=result.get("root_cause", ""),
                    evidence=result.get("evidence", []),
                    suggestion=result.get("suggestion", ""),
                )

            except Exception as exc:
                print(f"  ⚠️ LLM 分析失败: {exc}")
                finding = VerifiedFinding(
                    repository=candidate.repository,
                    repository_stars=candidate.repository_stars,
                    repository_forks=candidate.repository_forks,
                    file_path=candidate.file_path,
                    file_url=candidate.file_url,
                    is_misuse=False,
                    misuse_type="LLM_ERROR",
                    confidence=0.0,
                    root_cause=f"LLM 调用失败: {str(exc)}",
                    evidence=[],
                    suggestion="跳过此候选",
                )

            verified_findings.append(finding)
            _append_jsonl(NODE_4_PATHS["verified"], asdict(finding))

            if finding.is_misuse:
                print(f"  ✅ 确认存在误用！类型: {finding.misuse_type} | 置信度: {finding.confidence * 100:.1f}%")
            else:
                print(f"  ❌ 不是误用 ({finding.misuse_type})")

            if i < len(candidates):
                time.sleep(config.sleep)

        lines = [
            "# Node 4 验证报告",
            "",
            f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## 验证结果统计",
            "",
        ]

        total = len(verified_findings)
        misuse_count = sum(1 for f in verified_findings if f.is_misuse)
        non_misuse_count = total - misuse_count

        lines.append(f"- 验证候选总数: {total}")
        lines.append(f"- 确认误用: {misuse_count}")
        lines.append(f"- 排除误报: {non_misuse_count}")
        lines.append("")

        if misuse_count > 0:
            lines.append("## 确认的误用案例")
            lines.append("")
            for i, finding in enumerate([f for f in verified_findings if f.is_misuse], 1):
                lines.append(f"### {i}. {finding.repository}")
                lines.append("")
                lines.append(f"- **文件**: [{finding.file_path}]({finding.file_url})")
                lines.append(f"- **Stars**: {finding.repository_stars}")
                lines.append(f"- **Forks**: {finding.repository_forks}")
                lines.append(f"- **误用类型**: {finding.misuse_type}")
                lines.append(f"- **置信度**: {finding.confidence * 100:.1f}%")
                lines.append(f"- **根因分析**: {finding.root_cause}")
                lines.append("")
                lines.append("**证据**:")
                for ev in finding.evidence:
                    lines.append(f"- {ev}")
                lines.append("")
                lines.append(f"**修复建议**: {finding.suggestion}")
                lines.append("")

        if non_misuse_count > 0:
            lines.append("## 排除的误报")
            lines.append("")
            for finding in [f for f in verified_findings if not f.is_misuse]:
                lines.append(f"- **{finding.repository}/{finding.file_path}**: {finding.misuse_type} - {finding.root_cause}")
                lines.append("")

        with open(NODE_4_PATHS["report"], "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"\n📝 Node_4 报告已写入 -> {NODE_4_PATHS['report']}")

        print(f"\n✨ 节点 4 执行完毕！确认误用: {misuse_count} / {len(verified_findings)}")

        return {"success": True, "verified_count": len(verified_findings), "misuse_count": misuse_count}

    except Exception as e:
        print(f"\n❌ 节点 4 运行失败: {e}")
        return {"success": False, "error": str(e)}


def _merge_windows(indexes: list[int], total: int, context: int) -> list[Tuple[int, int]]:
    windows = sorted((max(0, i - context), min(total, i + context + 1)) for i in indexes)
    merged: list[Tuple[int, int]] = []
    for start, end in windows:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged
import argparse
import base64
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from github import Auth, Github, GithubException
from openai import OpenAI

load_dotenv()

# ==================== 1. 可调配置 ====================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PATHS = {
    "rules": os.path.abspath(os.path.join(BASE_DIR, "..", "Node_B", "Node_B_rules.json")),
    "profile": os.path.abspath(os.path.join(BASE_DIR, "..", "Node_B", "Node_B_profile.md")),
    "report": os.path.join(BASE_DIR, "Node_C_GitHub_0Day_Report.md"),
    "candidates": os.path.join(BASE_DIR, "Node_C_candidates.jsonl"),
    "findings": os.path.join(BASE_DIR, "Node_C_findings.jsonl"),
}

THREADLOCAL_POLICY = {
    "fallback_queries": [
        '"ThreadLocal" ".set(" "ExecutorService" language:{language}',
        '"ThreadLocal" ".set(" "CompletableFuture" language:{language}',
        '"ThreadLocal" ".set(" "Runnable" language:{language}',
        '"ThreadLocal" ".set(" -"remove(" language:{language}',
    ],
    "required_all": ["ThreadLocal"],
    "required_any": [".set(", ".withInitial("],
    "issue_keywords": ["ThreadLocal leak", "ThreadLocal remove", "ThreadLocal misuse", "context leak"],
    "extra_anchors": ["ThreadLocal", ".set(", ".remove(", ".get(", "ExecutorService", "Runnable", "Callable"],
}


@dataclass
class Config:
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
    def from_args(cls, args: argparse.Namespace) -> "Config":
        return cls(
            language=args.language,
            max_queries=args.max_queries,
            max_per_query=args.max_per_query,
            max_candidates_to_judge=args.max_candidates_to_judge,
            min_stars=args.min_stars,
            min_forks=args.min_forks,
            context_lines=args.context_lines,
            llm_snippet_chars=args.llm_snippet_chars,
            sleep=args.sleep,
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
            raise RuntimeError(f"缺少环境变量: {', '.join(missing)}。请先配置后再运行节点 C。")


@dataclass
class RuleBook:
    raw: dict[str, Any]
    targets: list[str]
    methods: list[str]
    sinks: list[str]

    @classmethod
    def from_file(cls, path: str) -> "RuleBook":
        rules = load_json(path)
        return cls(
            raw=rules,
            targets=clean_list(rules.get("target_frameworks_or_classes")),
            methods=clean_list(rules.get("vulnerable_methods")),
            sinks=clean_list(rules.get("sink_functions")),
        )

    @property
    def name(self) -> str:
        return str(self.raw.get("misuse_pattern_name", "UnknownPattern"))

    @property
    def is_threadlocal(self) -> bool:
        return "ThreadLocal" in self.name or "ThreadLocal" in json.dumps(self.raw, ensure_ascii=False)

    def anchors(self) -> list[str]:
        anchors = []
        for item in self.targets + self.methods + self.sinks:
            anchors.extend([item, short_name(item), method_name(item)])
        if self.is_threadlocal:
            anchors.extend(THREADLOCAL_POLICY["extra_anchors"])
        return unique([anchor for anchor in anchors if anchor])

    def issue_keywords(self) -> list[str]:
        keywords = [self.name] + [short_name(target) for target in self.targets[:3]]
        if self.is_threadlocal:
            keywords = THREADLOCAL_POLICY["issue_keywords"] + keywords
        return unique([keyword for keyword in keywords if keyword])

    def fallback_queries(self, language: str, limit: int, min_stars: int = 100, min_forks: int = 10) -> list[str]:
        queries = [f'"{short_name(target)}" language:{language}' for target in self.targets if len(short_name(target)) > 2]
        for method in self.methods:
            name = method_name(method)
            queries.append(f'"ThreadLocal" "{name}(" language:{language}' if name in {"set", "get", "remove", "withInitial"} else f'"{name}(" language:{language}')
        if self.is_threadlocal:
            queries.extend(query.format(language=language) for query in THREADLOCAL_POLICY["fallback_queries"])
        return unique([query for query in queries if query])[:limit]


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


# ==================== 2. 基础工具 ====================

def load_json(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"未找到输入文件: {path}。请先运行节点 B。")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_text(path: str) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def append_jsonl(path: str, item: dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")


def clean_list(value: Any) -> list[str]:
    return unique([str(item).strip() for item in value]) if isinstance(value, list) else []


def unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def short_name(value: str) -> str:
    return value.rsplit(".", 1)[-1].strip()


def method_name(value: str) -> str:
    return short_name(value).replace("()", "")


def parse_json_from_llm(content: str, expected_type: type) -> Any:
    content = strip_fence(content)
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


def strip_fence(content: str) -> str:
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    return content.strip()


def seen_urls(*paths: str) -> set[str]:
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


def clients(config: Config) -> tuple[OpenAI, Github]:
    config.validate()
    return (
        OpenAI(api_key=config.api_key, base_url=config.base_url),
        Github(auth=Auth.Token(config.github_token), per_page=30),
    )


# ==================== 3. 搜索与候选生成 ====================

def generate_queries(llm: OpenAI, rules: RuleBook, profile: str, config: Config) -> list[str]:
    fallback = rules.fallback_queries(config.language, config.max_queries, config.min_stars, config.min_forks)
    prompt = f"""你是程序分析与软件测试方向的 GitHub Code Search 专家。

节点 B 已总结出以下缺陷规则：
{json.dumps(rules.raw, ensure_ascii=False, indent=2)}

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
    try:
        response = llm.chat.completions.create(
            model=config.model,
            messages=[
                {"role": "system", "content": "You generate precise GitHub code search queries for software testing research."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        llm_queries = parse_json_from_llm(response.choices[0].message.content or "", list)
        merged = [str(query).strip() for query in llm_queries if str(query).strip()]
        merged += [query for query in fallback if query not in merged]
        return merged[:config.max_queries]
    except Exception as exc:
        print(f"⚠️ LLM 生成 query 失败，降级使用本地规则生成 query: {exc}")
        return fallback


def search_candidates(github: Github, queries: list[str], rules: RuleBook, config: Config) -> list[CodeCandidate]:
    candidates: list[CodeCandidate] = []
    visited = seen_urls(PATHS["candidates"], PATHS["findings"])

    for query in queries:
        print(f"🔍 Code Search: {query}")
        try:
            kept = 0
            result_count = 0
            for result in github.search_code(query=query):
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
                if any(pattern in path_lower for pattern in excluded_patterns):
                    print(f"  [{result_count}] 跳过: {repo.full_name} (路径包含测试/教程文件)")
                    continue

                snippet = fetch_snippet(result, rules, config.context_lines)
                if not passes_static_filter(snippet, rules):
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
                append_jsonl(PATHS["candidates"], asdict(candidate))
                visited.add(result.html_url)
                kept += 1
                print(f"  [{result_count}] 保留: {repo.full_name}/{result.path} (stars={repo.stargazers_count})")
                sleep(config)
        except GithubException as exc:
            print(f"⚠️ GitHub 搜索失败: {query} | {exc.status} {exc.data}")
        except Exception as exc:
            print(f"⚠️ GitHub 搜索失败: {query} | {exc}")
    return candidates


def fetch_snippet(result: Any, rules: RuleBook, context_lines: int) -> str:
    try:
        raw = result.decoded_content
    except Exception:
        try:
            raw = base64.b64decode(result.content)
        except Exception:
            return ""

    lines = raw.decode("utf-8", errors="replace").splitlines()
    if len(lines) <= context_lines * 2:
        return number_lines(lines)

    hit_indexes = [i for i, line in enumerate(lines) if any(anchor in line for anchor in rules.anchors())]
    if not hit_indexes:
        return number_lines(lines[: context_lines * 2])

    selected = []
    for start, end in merge_windows(hit_indexes[:4], len(lines), context_lines):
        if selected:
            selected.append("...")
        selected.extend(f"{i + 1}: {lines[i]}" for i in range(start, end))
    return "\n".join(selected)


def merge_windows(indexes: list[int], total: int, context: int) -> list[tuple[int, int]]:
    windows = sorted((max(0, i - context), min(total, i + context + 1)) for i in indexes)
    merged: list[tuple[int, int]] = []
    for start, end in windows:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def number_lines(lines: list[str]) -> str:
    return "\n".join(f"{i + 1}: {line}" for i, line in enumerate(lines))


def passes_static_filter(snippet: str, rules: RuleBook) -> bool:
    if not snippet.strip():
        return False
    if not rules.is_threadlocal:
        return True

    # 基本检查：必须包含 ThreadLocal 和 .set( 或 .withInitial(
    return (
        all(term in snippet for term in THREADLOCAL_POLICY["required_all"])
        and any(term in snippet for term in THREADLOCAL_POLICY["required_any"])
    )


def search_related_issues(github: Github, repo: str, rules: RuleBook, limit: int = 3) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for keyword in rules.issue_keywords():
        try:
            for issue in github.search_issues(query=f'repo:{repo} "{keyword}" type:issue'):
                if len(hits) >= limit:
                    return hits
                if not getattr(issue, "pull_request", None):
                    hits.append({"title": issue.title, "url": issue.html_url, "state": issue.state})
        except Exception:
            continue
    return hits


# ==================== 4. LLM 判定与报告 ====================

def judge_candidate(github: Github, llm: OpenAI, candidate: CodeCandidate, rules: RuleBook, profile: str, config: Config) -> Finding | None:
    print(f"🔍 搜索相关 issues: {candidate.repository}")
    known_issue_hits = search_related_issues(github, candidate.repository, rules)
    known_issue_text = json.dumps(known_issue_hits, ensure_ascii=False, indent=2) if known_issue_hits else "未发现相关 issue 命中。"
    prompt = f"""你是程序分析与软件测试研究员，正在判断一个 GitHub 代码候选是否值得作为“尚未申报 issue 的误用/缺陷”提交给开源项目。

节点 B 的结构化缺陷规则：
{json.dumps(rules.raw, ensure_ascii=False, indent=2)}

节点 B 的学术报告摘要：
{profile[:2200]}

候选项：
Repository: {candidate.repository}
File: {candidate.file_path}
URL: {candidate.file_url}
GitHub issue 检索结果: {known_issue_text}

代码片段：
```text
{candidate.code_snippet[:config.llm_snippet_chars]}
```

判断规则：
1. 如果代码中已有 `.remove()` 调用或使用 `try-finally` 正确清理 ThreadLocal，则直接判定为 is_reportable=false
2. 如果代码不在线程池环境（没有 ExecutorService/ThreadPool/Runnable/Callable），则不是 ThreadLocal 误用场景
3. 请严格基于代码片段和规则判断，不要编造跨文件事实
4. 你的任务是为后续 Node_D 验证阶段筛选候选。若已有相关 issue 命中，除非代码证据显示这是完全不同的新缺陷，否则应判定为不适合申报。

只输出一个可被 json.loads 解析的 JSON 对象，字段如下：
{{
  "is_reportable": true/false,
  "confidence": "High/Medium/Low",
  "misuse_type": "中文缺陷分类",
  "root_cause_zh": "中文根因，说明控制流/数据流为什么会泄漏或误用",
  "root_cause_en": "English root cause explanation",
  "evidence_lines": ["带行号的关键证据1", "带行号的关键证据2"]
}}
"""
    try:
        response = llm.chat.completions.create(
            model=config.model,
            messages=[
                {"role": "system", "content": "You are a conservative static analysis researcher. Prefer false negatives over unsupported claims."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )
        result = parse_json_from_llm(response.choices[0].message.content or "", dict)
    except Exception as exc:
        print(f"⚠️ LLM 判定失败: {candidate.file_url} | {exc}")
        return None

    if not result.get("is_reportable"):
        print(f"  [跳过] {candidate.repository}/{candidate.file_path}")
        return None
    if str(result.get("confidence", "Low")).lower() == "low":
        print(f"  [低置信跳过] {candidate.repository}/{candidate.file_path}")
        return None

    finding = Finding(
        repository=candidate.repository,
        file_path=candidate.file_path,
        file_url=candidate.file_url,
        misuse_type=str(result.get("misuse_type", "")),
        confidence=str(result.get("confidence", "")),
        root_cause_zh=str(result.get("root_cause_zh", "")),
        root_cause_en=str(result.get("root_cause_en", "")),
        evidence_lines=[str(item) for item in result.get("evidence_lines", [])],
        query=candidate.query,
        repository_stars=candidate.repository_stars,
        repository_forks=candidate.repository_forks,
        repository_updated_at=candidate.repository_updated_at,
    )
    append_jsonl(PATHS["findings"], asdict(finding))
    print(f"  [命中] {finding.repository}/{finding.file_path} | {finding.confidence}")
    return finding


def write_report(findings: list[Finding], rules: RuleBook, queries: list[str], config: Config) -> None:
    lines = [
        "# Node C GitHub 0-Day Hunter Report",
        "",
        f"- 生成时间: {datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"- 缺陷模式: `{rules.name}`",
        f"- 仓库筛选: star >= {config.min_stars}, fork >= {config.min_forks}",
        f"- 候选查询数: {len(queries)}",
        f"- 高置信/中置信可申报结果数: {len(findings)}",
        "",
        "## 使用的 Code Search Queries",
        "",
        *[f"- `{query}`" for query in queries],
        "",
    ]

    if not findings:
        lines += ["## 结论", "", "本次运行未发现可直接申报的中高置信候选。建议扩大查询数量、降低 star 阈值，或让 Node_B 产出更细粒度的规则后再次运行。", ""]
    else:
        lines += ["## 可申报候选", ""]
        for index, finding in enumerate(findings, 1):
            lines += [
                f"### {index}. {finding.repository}",
                "",
                "- 判定: 真实未申报缺陷候选，等待 Node_D 进一步验证",
                f"- 文件: `{finding.file_path}`",
                f"- 链接: {finding.file_url}",
                f"- Star: {finding.repository_stars}",
                f"- Fork: {finding.repository_forks}",
                f"- 仓库更新时间: {finding.repository_updated_at}",
                f"- 置信度: {finding.confidence}",
                f"- 缺陷分类: {finding.misuse_type}",
                "",
                "**中文根因**",
                "",
                finding.root_cause_zh or "未提供",
                "",
                "**English Root Cause**",
                "",
                finding.root_cause_en or "Not provided.",
                "",
                "**关键证据**",
                "",
            ]
            lines += [f"- {line}" for line in finding.evidence_lines] if finding.evidence_lines else ["- 未提供"]
            lines.append("")

    with open(PATHS["report"], "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"📝 Node_C 报告已写入 -> {PATHS['report']}")


# ==================== 5. 入口 ====================

def run(args: argparse.Namespace) -> None:
    config = Config.from_args(args)
    llm, github = clients(config)
    rules = RuleBook.from_file(PATHS["rules"])
    profile = load_text(PATHS["profile"])

    print("🚀 启动节点 C | GitHub 代码误用候选猎手")
    print(f"📥 已加载规则: {PATHS['rules']}")

    queries = generate_queries(llm, rules, profile, config)
    if not queries:
        raise RuntimeError("未能生成任何 GitHub Code Search query。")

    print(f"🤖 本次生成 {len(queries)} 条搜索 query。")
    candidates = search_candidates(github, queries, rules, config)
    print(f"📦 本次获得 {len(candidates)} 个静态候选，开始 LLM 判定。")

    findings = []
    for candidate in candidates[: config.max_candidates_to_judge]:
        finding = judge_candidate(github, llm, candidate, rules, profile, config)
        if finding:
            findings.append(finding)
        sleep(config)

    write_report(findings, rules, queries, config)
    print(f"✨ 节点 C 执行完毕。本次可申报候选: {len(findings)}")


def sleep(config: Config) -> None:
    if config.sleep:
        time.sleep(config.sleep)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Node C: search GitHub code for new misuse candidates from Node_B rules.")
    parser.add_argument("--language", default="Java", help="GitHub Code Search language qualifier, default: Java")
    parser.add_argument("--max-queries", type=int, default=20, help="最多生成/执行多少条 Code Search query")
    parser.add_argument("--max-per-query", type=int, default=20, help="每条 query 最多保留多少个候选")
    parser.add_argument("--max-candidates-to-judge", type=int, default=20, help="最多送入 LLM 判定的候选数量")
    parser.add_argument("--min-stars", type=int, default=100, help="候选仓库最低 star 数，用于优先寻找热门、有名气项目")
    parser.add_argument("--min-forks", type=int, default=10, help="候选仓库最低 fork 数，默认不启用 fork 过滤")
    parser.add_argument("--context-lines", type=int, default=45, help="源码命中点前后保留的上下文行数")
    parser.add_argument("--llm-snippet-chars", type=int, default=9000, help="送入 LLM 判定的最大源码字符数")
    parser.add_argument("--sleep", type=float, default=0.8, help="GitHub/LLM 请求之间的间隔秒数")
    return parser


if __name__ == "__main__":
    try:
        run(build_arg_parser().parse_args())
    except Exception as exc:
        print(f"\n❌ 节点 C 运行失败: {exc}")

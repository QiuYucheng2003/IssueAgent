import argparse
import base64
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from typing import Any

from dotenv import load_dotenv
from github import Auth, Github, GithubException
from openai import OpenAI

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PATHS = {
    "candidates": os.path.abspath(os.path.join(BASE_DIR, "..", "Node_C", "Node_C_candidates.jsonl")),
    "rules": os.path.abspath(os.path.join(BASE_DIR, "..", "Node_B", "Node_B_rules.json")),
    "verified": os.path.join(BASE_DIR, "Node_D_verified.jsonl"),
    "report": os.path.join(BASE_DIR, "Node_D_Verification_Report.md"),
}


@dataclass
class Config:
    max_candidates: int
    sleep: float
    github_token: str
    api_key: str
    model: str
    base_url: str
    max_code_chars: int

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "Config":
        return cls(
            max_candidates=args.max_candidates,
            sleep=args.sleep,
            github_token=os.environ.get("GITHUB_TOKEN").strip(),
            api_key=os.environ.get("DEEPSEEK_API_KEY").strip(),
            model=os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-pro"),
            base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
            max_code_chars=args.max_code_chars,
        )

    def validate(self) -> None:
        missing = []
        if not self.github_token:
            missing.append("GITHUB_TOKEN")
        if not self.api_key:
            missing.append("DEEPSEEK_API_KEY")
        if missing:
            raise RuntimeError(f"缺少环境变量: {', '.join(missing)}。请先配置后再运行节点 D。")


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


def load_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"未找到输入文件: {path}。请先运行节点 C。")
    results = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                results.append(json.loads(line))
    return results


def load_json(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"未找到输入文件: {path}。请先运行节点 B。")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_jsonl(path: str, items: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


def parse_candidate(data: dict) -> CodeCandidate:
    return CodeCandidate(
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


def fetch_full_file(github: Github, repo_name: str, file_path: str) -> str:
    try:
        repo = github.get_repo(repo_name)
        contents = repo.get_contents(file_path)
        if hasattr(contents, "decoded_content"):
            return contents.decoded_content.decode("utf-8", errors="replace")
        elif hasattr(contents, "content"):
            return base64.b64decode(contents.content).decode("utf-8", errors="replace")
        return ""
    except GithubException as exc:
        print(f"  ⚠️ 获取文件失败: {exc.status} {exc.data}")
        return ""
    except Exception as exc:
        print(f"  ⚠️ 获取文件失败: {exc}")
        return ""


def analyze_with_llm(llm: OpenAI, full_content: str, candidate: CodeCandidate, rules: dict, config: Config) -> VerifiedFinding:
    code_with_lines = "\n".join(f"{i + 1}: {line}" for i, line in enumerate(full_content.splitlines()))
    code_for_llm = code_with_lines[:config.max_code_chars]

    rules_summary = json.dumps(rules, ensure_ascii=False, indent=2)

    prompt = f"""你是一位资深的 Java 代码安全审计专家，专门研究 ThreadLocal 相关的代码误用问题。

## 分析任务

请分析以下 GitHub 代码文件，判断是否存在 Node_B 规则中描述的 ThreadLocal 误用/漏洞/bug。

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

请按照以下标准判断是否存在误用：

1. **ThreadLocal 内存泄漏风险**: 如果 ThreadLocal 在线程池环境（ExecutorService/ThreadPool/Runnable/Callable/CompletableFuture）中被 .set() 设置值，但没有在 finally 块中调用 .remove() 进行清理，则属于误用。

2. **数据污染风险**: 如果同一个 ThreadLocal 在线程池中的多个任务之间被共享使用，且没有正确隔离，则属于误用。

3. **InheritableThreadLocal 滥用**: 如果 InheritableThreadLocal 在不适合的场景（如线程池）中使用，可能导致子线程继承了错误的上下文。

4. **非线程池环境**: 如果 ThreadLocal 的使用不在线程池环境中（即线程用完即销毁），则通常不属于误用场景。

## 输出要求

请严格按照以下 JSON 格式输出分析结果：

```json
{{
    "is_misuse": true/false,
    "misuse_type": "THREADLOCAL_LEAK" / "DATA_POLLUTION" / "INHERITABLE_THREADLOCAL_ABUSE" / "NOT_MISUSE" / "NOT_IN_THREADPOOL" / "HAS_CORRECT_CLEANUP",
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
- 请基于代码内容给出准确的判断，不要编造信息
- 如果文件内容不完整或无法判断，请明确说明
"""

    try:
        response = llm.chat.completions.create(
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

        return VerifiedFinding(
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
        return VerifiedFinding(
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


def verify_candidate(github: Github, llm: OpenAI, candidate: CodeCandidate, rules: dict, config: Config) -> VerifiedFinding:
    print(f"\n🔍 验证: {candidate.repository}/{candidate.file_path}")

    full_content = fetch_full_file(github, candidate.repository, candidate.file_path)
    if not full_content:
        print("  ❌ 获取文件内容失败")
        return VerifiedFinding(
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

    print(f"  📄 文件共 {len(full_content.splitlines())} 行")
    print(f"  🤖 正在调用 LLM 分析...")

    finding = analyze_with_llm(llm, full_content, candidate, rules, config)

    if finding.is_misuse:
        print(f"  ✅ 确认存在误用！类型: {finding.misuse_type} | 置信度: {finding.confidence * 100:.1f}%")
    else:
        print(f"  ❌ 不是误用 ({finding.misuse_type})")

    return finding


def write_report(findings: list[VerifiedFinding]) -> None:
    lines = [
        "# Node D 验证报告",
        "",
        f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## 验证结果统计",
        "",
    ]

    total = len(findings)
    misuse_count = sum(1 for f in findings if f.is_misuse)
    non_misuse_count = total - misuse_count

    lines.append(f"- 验证候选总数: {total}")
    lines.append(f"- 确认误用: {misuse_count}")
    lines.append(f"- 排除误报: {non_misuse_count}")
    lines.append("")

    if misuse_count > 0:
        lines.append("## 确认的误用案例")
        lines.append("")
        for i, finding in enumerate([f for f in findings if f.is_misuse], 1):
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
        for finding in [f for f in findings if not f.is_misuse]:
            lines.append(f"- **{finding.repository}/{finding.file_path}**: {finding.misuse_type} - {finding.root_cause}")
            lines.append("")

    with open(PATHS["report"], "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n📝 Node_D 报告已写入 -> {PATHS['report']}")


def run(args: argparse.Namespace) -> None:
    config = Config.from_args(args)
    config.validate()

    auth = Auth.Token(config.github_token)
    github = Github(auth=auth)

    llm = OpenAI(api_key=config.api_key, base_url=config.base_url)

    rules = load_json(PATHS["rules"])

    print("🚀 启动节点 D | GitHub 代码误用验证器 (LLM 驱动)")
    print(f"📥 已加载候选: {PATHS['candidates']}")
    print(f"📋 已加载规则: {PATHS['rules']}")
    print(f"🤖 LLM 模型: {config.model}")

    candidates_data = load_jsonl(PATHS["candidates"])
    candidates = [parse_candidate(data) for data in candidates_data]

    if args.max_candidates > 0:
        candidates = candidates[: args.max_candidates]

    print(f"🔍 待验证候选数: {len(candidates)}")

    verified_findings = []
    for i, candidate in enumerate(candidates, 1):
        print(f"\n{'='*60}")
        print(f"第 {i}/{len(candidates)} 个候选")
        finding = verify_candidate(github, llm, candidate, rules, config)
        verified_findings.append(finding)
        save_jsonl(PATHS["verified"], [asdict(f) for f in verified_findings])

        if i < len(candidates):
            time.sleep(config.sleep)

    write_report(verified_findings)

    misuse_count = sum(1 for f in verified_findings if f.is_misuse)
    print(f"\n✨ 节点 D 执行完毕！确认误用: {misuse_count} / {len(verified_findings)}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Node D: verify GitHub code candidates from Node_C using DeepSeek LLM.")
    parser.add_argument("--max-candidates", type=int, default=5, help="最多验证多少个候选")
    parser.add_argument("--sleep", type=float, default=2.0, help="请求之间的间隔秒数")
    parser.add_argument("--max-code-chars", type=int, default=8000, help="送入 LLM 的最大代码字符数")
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    run(args)
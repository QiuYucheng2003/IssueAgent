import os
import json

from dotenv import load_dotenv
from openai import OpenAI
from github import Github, Auth

load_dotenv()
# ==================== 1. 配置与初始化模块 ====================
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

llm_client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com/v1")
github_client = Github(auth=Auth.Token(GITHUB_TOKEN))

# ✨ 新增：动态定位当前脚本所在的目录（即 Node_A 文件夹绝对路径），确保文件读写永远绝对对齐
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYWORDS_FILE = os.path.join(BASE_DIR, "Node_A_keywords.txt")
RESULT_FILE = os.path.join(BASE_DIR, "Node_A_result.json")


# ==================== 2. 核心通用解耦节点 ====================

def generate_search_queries(topic: str, num_queries: int = 3) -> list[str]:
    """【通用大模型能力】：给任何课题，生成 N 个专业 GitHub 检索词"""
    prompt = f"你是一个程序分析与软件测试领域的专家。正在研究课题: '{topic}'。请帮我生成 {num_queries} 个最可能出现在 GitHub Issue 标题或描述中的英文搜索关键词（Query）。请直接输出关键词列表，每行一个，不要包含任何多余的解释、序号或 Markdown 标记。"

    response = llm_client.chat.completions.create(
        model="deepseek-v4-pro", # 统一为标准模型名
        messages=[
            {"role": "system", "content": "You are a helpful assistant and a senior software engineering researcher."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2
    )
    return [line.strip() for line in response.choices[0].message.content.strip().split('\n') if line.strip()][:num_queries]


def search_github_issues(queries: list[str], lang: str = "Java", max_per_query: int = 3) -> list[dict]:
    """【通用检索能力】：无视课题，根据任意关键词、任意语言捞取高价值 Issue（带本地文件去重）"""
    all_issues = []
    seen_urls = set()

    # ====== 🌟 优化：使用确定的绝对路径 RESULT_FILE 加载历史“记忆” =======
    if os.path.exists(RESULT_FILE):
        try:
            with open(RESULT_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        historical_data = json.loads(line.strip())
                        if "url" in historical_data:
                            seen_urls.add(historical_data["url"])
            print(f"💾 成功加载本地历史数据，已自动锁定 {len(seen_urls)} 个已存在漏洞，本次将彻底跳过它们。")
        except Exception as e:
            print(f"⚠️ 读取历史数据失败: {e}")

    for query in queries:
        print(f"🔍 正在检索关键词: '{query}' ...")
        try:
            count = 0
            for issue in github_client.search_issues(query=f"{query} language:{lang} state:closed"):
                if count >= max_per_query: break
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
    return all_issues


def filter_issues_by_semantic(issues: list[dict], topic: str) -> list[dict]:
    """【通用清洗能力】：让大模型判断 Issue 是否与目标课题高度相关"""
    print("\n🧹 正在使用大模型对结果进行课题相关性精炼...")
    filtered_issues = []

    for issue in issues:
        prompt = f"评估该 GitHub Issue 是否属于【{topic}】相关的缺陷/缺陷讨论。只需回答 YES 或 NO：\n\n标题: {issue['title']}\n描述: {issue['body'][:500]}"
        try:
            res = llm_client.chat.completions.create(
                model="deepseek-v4-pro",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            ).choices[0].message.content.strip().upper()

            if "YES" in res:
                print(f"  [保留] -> {issue['repository']}: {issue['title']}")
                filtered_issues.append(issue)
            else:
                print(f"  [过滤] -> {issue['repository']}: {issue['title']}")
        except Exception:
            filtered_issues.append(issue)
    return filtered_issues


# ==================== 3. 💾 数据持久化保存模块 ====================

def save_data_append(queries: list[str], issues: list[dict]):
    """以追加(append)形式将产生的关键词与高价值 Issue 落地到确定的绝对路径文件"""
    # 1. 优化：追加保存至全局锚定的关键词绝对路径
    with open(KEYWORDS_FILE, "a", encoding="utf-8") as f_kw:
        for kw in queries:
            f_kw.write(f"{kw}\n")
    print(f"\n💾 关键词已成功追加写入 -> {KEYWORDS_FILE}")

    # 2. 优化：追加保存至全局锚定的结果绝对路径
    with open(RESULT_FILE, "a", encoding="utf-8") as f_res:
        for issue in issues:
            f_res.write(json.dumps(issue, ensure_ascii=False) + "\n")
    print(f"💾 高价值 Issue 结果已成功追加写入 -> {RESULT_FILE}")


# ==================== 4. 业务流执行入口 ====================
if __name__ == "__main__":
    # 你的研究主题
    our_topic = "ThreadLocal misuse in Java thread pools"
    language = "Java"

    print(f"🚀 启动自动化研究工作流 | 课题: {our_topic} | 语言: {language}\n")

    # 1. 通用生成
    queries = generate_search_queries(topic=our_topic, num_queries=3)
    print(f"🤖 泛化关键词: {queries}\n")

    # 2. 通用检索
    raw_results = search_github_issues(queries=queries, lang=language, max_per_query=3)

    # 3. 通用过滤
    final_issues = filter_issues_by_semantic(issues=raw_results, topic=our_topic)

    # 4. 持久化数据
    if final_issues:
        save_data_append(queries, final_issues)
        print(f"\n✨ 节点 A 执行完毕！本次成功追加录入 {len(final_issues)} 个高价值学术素材。")
    else:
        print("\n⚠️ 节点 A 执行完毕！本次未发现高度相关的案例，未执行文件写入。")
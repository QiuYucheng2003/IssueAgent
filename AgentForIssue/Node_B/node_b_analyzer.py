import os
import json
from openai import OpenAI
from dotenv import load_dotenv  # ✨ 新增：引入 dotenv

# ✨ 新增：加载 .env 文件
load_dotenv()
# ==================== 1. 配置与物理路径锚定 ====================
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")
llm_client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com/v1")

# 动态定位路径：定位到 Node_B 目录，并向上寻址锁定 Node_A 的结果文件
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.abspath(os.path.join(BASE_DIR, "..", "Node_A", "Node_A_result.json"))

# 本节点产出物路径
OUTPUT_MD = os.path.join(BASE_DIR, "Node_B_profile.md")
OUTPUT_JSON = os.path.join(BASE_DIR, "Node_B_rules.json")


# ==================== 2. 核心通用解耦能力节点 ====================

def load_node_a_dataset(file_path: str) -> list[dict]:
    """【通用数据加载】：加载本地 JSONL 数据集，恢复为高价值语料列表"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"❌ 未找到节点 A 的数据集文件：{file_path}，请先运行节点 A！")

    dataset = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                dataset.append(json.loads(line.strip()))
    print(f"📥 成功吃入节点 A 历史沉淀的 {len(dataset)} 个高质量真实漏洞案例。")
    return dataset


def analyze_vulnerability_patterns(dataset: list[dict]) -> tuple[str, str]:
    """【模式提炼能力】：多样本横向对比，一口气生成学术级研究报告与结构化检测规则"""
    print("🧠 正在启动 DeepSeek 导师模式进行跨案例学术级横向对比...")

    # 将离散的语料打包成大模型审计上下文
    formatted_corpus = ""
    for i, item in enumerate(dataset, 1):
        formatted_corpus += f"--- Case #{i} ---\nRepository: {item['repository']}\nTitle: {item['title']}\nDescription: {item['body']}\n\n"

    # 系统提示词：规约大模型的分析范式
    system_prompt = (
        "你是一个顶级的静态程序分析专家与系统安全科学家。你需要横向对比输入的多个真实漏洞案例，"
        "提炼出它们底层共性的【代码误用/缺陷模式规则】。你需要同时输出人类可读的深度学术报告以及计算机可读的结构化检测配置。"
    )

    # 复合指令：通过固定标记一次性拿到两种格式，精简请求
    user_prompt = f"""请仔细审计以下来自真实开源项目的缺陷上下文语料：

{formatted_corpus}

请完成以下两项任务：

任务 1：生成人类学者可读的学术模式研究报告。
要求语言干练、技术切中要害，包含：核心成因（Root Cause）、共性触发路径（Data Flow Path）、以及在静态分析（如Soot/Infer）或代码审查时的特征信号。

任务 2：生成静态分析器可解析的结构化规则。
必须严格遵循 JSON 格式，包含以下字段：
- `misuse_pattern_name`: 缺陷模式总名称
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
(这里填写任务 2 的纯 JSON 字符串，确保可以直接被 json.loads 解析)
[END_JSON]
"""

    response = llm_client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.2
    ).choices[0].message.content.strip()

    # 精准切片提取
    md_content = response.split("[START_MARKDOWN]")[1].split("[END_MARKDOWN]")[0].strip()
    json_content = response.split("[START_JSON]")[1].split("[END_JSON]")[0].strip()

    return md_content, json_content


# ==================== 3. 💾 持久化落地模块 ====================

def save_node_b_outputs(md_report: str, json_rules: str):
    """持久化保存：报告采用覆盖写入（更新最新共性研究），确保规则库最新"""
    # 1. 落地 Markdown 学术报告
    with open(OUTPUT_MD, "w", encoding="utf-8") as f_md:
        f_md.write(md_report)
    print(f"📝 学术级模式报告已更新 -> {OUTPUT_MD}")

    # 2. 落地结构化规则库 JSON (校验其合法性后规范化保存)
    try:
        parsed_json = json.loads(json_rules)
        with open(OUTPUT_JSON, "w", encoding="utf-8") as f_json:
            json.dump(parsed_json, f_json, ensure_ascii=False, indent=2)
        print(f"📊 结构化检测规则通缉令已落地 -> {OUTPUT_JSON}")
    except Exception as e:
        print(f"⚠️ 大模型吐出的 JSON 格式有误，降级保存原始文本。错误: {e}")
        with open(OUTPUT_JSON, "w", encoding="utf-8") as f_json:
            f_json.write(json_rules)


# ==================== 4. 业务流执行入口 ====================
if __name__ == "__main__":
    print("🚀 启动节点 B | 缺陷共性模式总结器...\n")
    try:
        # 1. 加载节点 A 沉淀的数据集
        raw_dataset = load_node_a_dataset(INPUT_FILE)

        # 2. 多样本深度横向审计
        md_report, json_rules = analyze_vulnerability_patterns(raw_dataset)

        # 3. 数据落盘
        save_node_b_outputs(md_report, json_rules)

        print("\n✨ 节点 B 执行完毕！成功为您武装好下一阶段所需的检测规则库。")

    except Exception as e:
        print(f"\n❌ 节点 B 运行失败: {e}")
import json
import os
from typing import TypedDict, Dict, Any, List
from langgraph.graph import StateGraph, END

from .nodes import run_node_0, run_node_1, run_node_2, run_node_3, run_node_4, NODE_1_RESULT_FILE


class ResearchState(TypedDict):
    topic: str
    language: str
    queries: List[str]
    node_0_result: Dict[str, Any]
    node_1_result: Dict[str, Any]
    node_2_result: Dict[str, Any]
    node_3_result: Dict[str, Any]
    node_4_result: Dict[str, Any]


NODE_CONFIG = {
    # ============================================================
    # 节点 0：关键词泛化配置
    # ============================================================
    "node_0": {
        # num_queries: 生成的搜索关键词数量（建议 8-10 个）
        "num_queries": 10,
    },

    # ============================================================
    # 节点 1：漏洞打捞配置
    # ============================================================
    "node_1": {
        # max_cases: 最多保留的漏洞案例总数（建议 50-100 个用于分析）
        "max_cases": 10,
        # issues_per_query: 每个关键词最多检索的 GitHub Issue/PR 数量
        "issues_per_query": 3,
    },

    # ============================================================
    # 节点 3：零日搜索配置（每个模式独立搜索）
    # ============================================================
    "node_3": {
        # max_queries: 每个缺陷模式生成的搜索 query 数量（建议 20 个）
        "max_queries": 1,
        # max_per_query: 每个搜索 query 最多返回的代码结果数量
        "max_per_query": 2,
    },

    # ============================================================
    # 节点 4：代码验证配置
    # ============================================================
    "node_4": {
        # max_candidates: 最多验证的候选数，0 表示不限制（验证所有候选）
        "max_candidates": 0,
    },
}


def node_0_step(state: ResearchState) -> Dict[str, Any]:
    result = run_node_0(
        topic=state["topic"],
        **NODE_CONFIG["node_0"],
    )
    return {"node_0_result": result, "queries": result["queries"]}


def node_1_step(state: ResearchState) -> Dict[str, Any]:
    result = run_node_1(
        queries=state["queries"],
        topic=state["topic"],
        language=state["language"],
        **NODE_CONFIG["node_1"],
    )
    return {"node_1_result": result}


def decide_after_node1(state: ResearchState) -> str:
    count = 0
    if os.path.exists(NODE_1_RESULT_FILE):
        with open(NODE_1_RESULT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1

    print(f"\n{'='*60}")
    print(f"📊 当前 node_1_result.json 记录数: {count}")
    print(f"{'='*60}")

    while True:
        choice = input("\n请选择下一步操作:\n"
                       "  1. 继续运行节点 2（提炼缺陷模式）\n"
                       "  2. 再跑一遍节点 1（继续收集案例）\n"
                       "请输入 1 或 2: ").strip()
        if choice == "1":
            print("✓ 选择继续运行节点 2")
            return "node_2"
        elif choice == "2":
            print("✓ 选择再跑一遍节点 1")
            return "node_1"
        else:
            print("⚠️ 无效输入，请输入 1 或 2")


def node_2_step(state: ResearchState) -> Dict[str, Any]:
    result = run_node_2()
    return {"node_2_result": result}


def node_3_step(state: ResearchState) -> Dict[str, Any]:
    result = run_node_3(
        language=state["language"],
        **NODE_CONFIG["node_3"],
    )
    return {"node_3_result": result}


def node_4_step(state: ResearchState) -> Dict[str, Any]:
    result = run_node_4(
        **NODE_CONFIG["node_4"],
    )
    return {"node_4_result": result}


def build_workflow() -> StateGraph:
    workflow = StateGraph(ResearchState)

    workflow.add_node("node_0", node_0_step)
    workflow.add_node("node_1", node_1_step)
    workflow.add_node("node_2", node_2_step)
    workflow.add_node("node_3", node_3_step)
    workflow.add_node("node_4", node_4_step)

    workflow.add_edge("node_0", "node_1")
    workflow.add_conditional_edges("node_1", decide_after_node1)
    workflow.add_edge("node_2", "node_3")
    workflow.add_edge("node_3", "node_4")
    workflow.add_edge("node_4", END)

    workflow.set_entry_point("node_0")

    return workflow


def build_workflow_direct_queries(queries: List[str], topic: str) -> StateGraph:
    workflow = StateGraph(ResearchState)

    workflow.add_node("node_1", node_1_step)
    workflow.add_node("node_2", node_2_step)
    workflow.add_node("node_3", node_3_step)
    workflow.add_node("node_4", node_4_step)

    workflow.add_conditional_edges("node_1", decide_after_node1)
    workflow.add_edge("node_2", "node_3")
    workflow.add_edge("node_3", "node_4")
    workflow.add_edge("node_4", END)

    workflow.set_entry_point("node_1")

    return workflow
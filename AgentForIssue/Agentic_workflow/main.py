# ============================================================
# 自动化漏洞挖掘智能体 - 主启动文件
# ============================================================
# 使用方式:
#   python -m Agentic_workflow.main
#   python -m Agentic_workflow.main --topic "你的研究课题"
# ============================================================

import argparse
import os
import sys

# 添加项目根目录到 Python 路径，确保能正确导入模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 导入 LangGraph 工作流构建函数
from Agentic_workflow.workflow import build_workflow, build_workflow_direct_queries

def run_complete_workflow(args):
    use_direct_queries = args.query is not None and len(args.query) > 0

    if use_direct_queries:
        workflow = build_workflow_direct_queries(queries=args.query, topic=args.topic)
        initial_state = {
            "topic": args.topic,
            "language": args.language,
            "queries": args.query,
            "node_0_result": {},
            "node_1_result": {},
            "node_2_result": {},
            "node_3_result": {},
            "node_4_result": {},
        }
    else:
        workflow = build_workflow()
        initial_state = {
            "topic": args.topic,
            "language": args.language,
            "queries": [],
            "node_0_result": {},
            "node_1_result": {},
            "node_2_result": {},
            "node_3_result": {},
            "node_4_result": {},
        }

    app = workflow.compile()

    try:
        final_state = app.invoke(initial_state)

        print(f"\n{'='*60}")
        print(f"🎉 工作流执行完成！")
        print(f"{'='*60}")

        if not use_direct_queries:
            zero_result = final_state.get("node_0_result", {})
            if zero_result:
                print(f"\n📊 节点 0 结果:")
                print(f"   - 生成关键词: {zero_result.get('queries', [])}")

        one_result = final_state.get("node_1_result", {})
        if one_result:
            print(f"\n📊 节点 1 结果:")
            print(f"   - 新增漏洞案例: {one_result.get('added_count', 0)}")

        two_result = final_state.get("node_2_result", {})
        if two_result:
            print(f"\n📊 节点 2 结果:")
            print(f"   - 执行状态: {'✅ 成功' if two_result.get('success') else '❌ 失败'}")
            if two_result.get("error"):
                print(f"   - 错误信息: {two_result['error']}")

        three_result = final_state.get("node_3_result", {})
        if three_result:
            print(f"\n📊 节点 3 结果:")
            print(f"   - 执行状态: {'✅ 成功' if three_result.get('success') else '❌ 失败'}")
            if three_result.get("success"):
                print(f"   - 发现候选数: {three_result.get('candidates_count', 0)}")
            if three_result.get("error"):
                print(f"   - 错误信息: {three_result['error']}")

        four_result = final_state.get("node_4_result", {})
        if four_result:
            print(f"\n📊 节点 4 结果:")
            print(f"   - 执行状态: {'✅ 成功' if four_result.get('success') else '❌ 失败'}")
            if four_result.get("success"):
                print(f"   - 验证候选数: {four_result.get('verified_count', 0)}")
                print(f"   - 确认误用数: {four_result.get('misuse_count', 0)}")
            if four_result.get("error"):
                print(f"   - 错误信息: {four_result['error']}")

        print(f"\n{'='*60}")

    except Exception as e:
        print(f"\n❌ 工作流执行失败: {e}")
        import traceback
        traceback.print_exc()


def run_single_node(node_choice, args):
    from Agentic_workflow.nodes import run_node_0, run_node_1, run_node_2, run_node_3, run_node_4
    from Agentic_workflow.workflow import NODE_CONFIG

    if node_choice == 0:
        print(f"\n🚀 单独运行节点 0...")
        result = run_node_0(topic=args.topic, **NODE_CONFIG["node_0"])
        print(f"\n📊 节点 0 结果:")
        print(f"   - 生成关键词: {result.get('queries', [])}")
    elif node_choice == 1:
        print(f"\n🚀 单独运行节点 1...")
        queries_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "node_0_keywords.txt")
        if os.path.exists(queries_file):
            with open(queries_file, "r") as f:
                queries = [line.strip() for line in f if line.strip()]
        else:
            queries = args.query or []
        
        if not queries:
            print("❌ 没有找到关键词，请先运行节点 0 或使用 --query 参数")
            return
        
        result = run_node_1(queries=queries, topic=args.topic, language=args.language, **NODE_CONFIG["node_1"])
        print(f"\n📊 节点 1 结果:")
        print(f"   - 新增漏洞案例: {result.get('added_count', 0)}")
    elif node_choice == 2:
        print(f"\n🚀 单独运行节点 2...")
        result = run_node_2()
        print(f"\n📊 节点 2 结果:")
        print(f"   - 执行状态: {'✅ 成功' if result.get('success') else '❌ 失败'}")
    elif node_choice == 3:
        print(f"\n🚀 单独运行节点 3...")
        result = run_node_3(language=args.language, **NODE_CONFIG["node_3"])
        print(f"\n📊 节点 3 结果:")
        print(f"   - 执行状态: {'✅ 成功' if result.get('success') else '❌ 失败'}")
        if result.get("success"):
                print(f"   - 发现候选数: {result.get('candidates_count', 0)}")
    elif node_choice == 4:
        print(f"\n🚀 单独运行节点 4...")
        result = run_node_4(**NODE_CONFIG["node_4"])
        print(f"\n📊 节点 4 结果:")
        print(f"   - 执行状态: {'✅ 成功' if result.get('success') else '❌ 失败'}")
        if result.get("success"):
            print(f"   - 验证候选数: {result.get('verified_count', 0)}")
            print(f"   - 确认误用数: {result.get('misuse_count', 0)}")

    print(f"\n{'='*60}")
    print(f"🎉 单独节点执行完成！")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description="自动化漏洞挖掘智能体 - LangGraph 工作流")

    parser.add_argument(
        "--topic",
        default="ThreadLocal misuse in Java thread pools",
        help="研究课题",
    )

    parser.add_argument(
        "--language",
        default="Java", 
        help="目标编程语言",
    )

    parser.add_argument(
        "--query",
        action="append",
        help="直接指定搜索关键词（可多次使用，跳过节点 0 的 LLM 泛化）",
    )

    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"� 自动化漏洞挖掘智能体 - LangGraph Workflow")
    print(f"{'='*60}")
    print(f"研究课题: {args.topic}")
    print(f"目标语言: {args.language}")
    if args.query:
        print(f"直接关键词: {args.query}")
    print(f"{'='*60}\n")

    while True:
        print(f"\n{'='*60}")
        print(f"请选择运行模式:")
        print(f"{'='*60}")
        print(f"  1. 完整流程（节点 0→1→2→3→4）")
        print(f"  2. 单独运行某个节点")
        print(f"  3. 退出")
        print(f"{'='*60}")
        
        while True:
            choice = input("请输入 1、2 或 3: ").strip()
            if choice in ["1", "2", "3"]:
                break
            print("请输入有效的选项（1、2 或 3）")

        if choice == "3":
            print(f"\n{'='*60}")
            print(f"👋 感谢使用！再见！")
            print(f"{'='*60}")
            return

        if choice == "1":
            run_complete_workflow(args)
        else:
            print(f"\n{'='*60}")
            print(f"请选择要运行的节点:")
            print(f"{'='*60}")
            print(f"  0. 节点 0 - 关键词泛化")
            print(f"  1. 节点 1 - 漏洞打捞")
            print(f"  2. 节点 2 - 模式提炼")
            print(f"  3. 节点 3 - 零日搜索")
            print(f"  4. 节点 4 - 代码验证")
            print(f"{'='*60}")
            
            while True:
                node_choice = input("请输入 0-4: ").strip()
                if node_choice in ["0", "1", "2", "3", "4"]:
                    node_choice = int(node_choice)
                    break
                print("请输入有效的选项（0-4）")

            run_single_node(node_choice, args)


if __name__ == "__main__":
    main()
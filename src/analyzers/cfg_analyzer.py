from .cfg_builder import ControlFlowGraph, CFGNode
from typing import Dict, Set

class CFGAnalyzer:
    """
    Analyzes a Control Flow Graph (CFG) for unreachable code, infinite loops, and exception handling paths.
    """
    def analyze(self, cfg: ControlFlowGraph) -> Dict[str, list]:
        findings = {
            'unreachable': [],
            'infinite_loops': [],
            'exception_paths': []
        }
        if not cfg.entry:
            return findings
        reachable = self._find_reachable(cfg)
        for node in cfg.nodes:
            if node not in reachable:
                findings['unreachable'].append(node)
        # Simple infinite loop detection: loop node with no exit
        for node in cfg.nodes:
            if getattr(node, 'name', '').startswith('loop'):
                if all(succ == node for succ in node.successors):
                    findings['infinite_loops'].append(node)
        # Exception path analysis: placeholder (extend as needed)
        # For now, just note try/except nodes
        for node in cfg.nodes:
            if hasattr(node.ast_node, 'body') and hasattr(node.ast_node, 'handlers'):
                findings['exception_paths'].append(node)
        return findings

    def _find_reachable(self, cfg: ControlFlowGraph) -> Set[CFGNode]:
        visited = set()
        def dfs(node):
            if node in visited:
                return
            visited.add(node)
            for succ in node.successors:
                dfs(succ)
        if cfg.entry:
            dfs(cfg.entry)
        return visited 
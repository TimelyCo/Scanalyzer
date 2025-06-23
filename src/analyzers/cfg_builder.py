import ast
from typing import List, Dict, Set, Optional

class CFGNode:
    def __init__(self, ast_node, name: Optional[str] = None):
        self.ast_node = ast_node
        self.name = name or str(id(self))
        self.successors: List['CFGNode'] = []

    def add_successor(self, node: 'CFGNode'):
        self.successors.append(node)

class ControlFlowGraph:
    def __init__(self):
        self.entry: Optional[CFGNode] = None
        self.nodes: Set[CFGNode] = set()

    def add_node(self, node: CFGNode):
        self.nodes.add(node)

class CFGBuilder:
    """
    Builds a simple Control Flow Graph (CFG) from a Python AST.
    """
    def build_cfg(self, ast_node) -> ControlFlowGraph:
        self.graph = ControlFlowGraph()
        self.last_node = None
        self._build(ast_node)
        return self.graph

    def _build(self, node):
        if isinstance(node, ast.Module):
            prev = None
            for stmt in node.body:
                n = CFGNode(stmt)
                self.graph.add_node(n)
                if prev:
                    prev.add_successor(n)
                else:
                    self.graph.entry = n
                prev = n
                self._build(stmt)
        elif isinstance(node, ast.If):
            cond_node = CFGNode(node.test, name='if_cond')
            self.graph.add_node(cond_node)
            if self.last_node:
                self.last_node.add_successor(cond_node)
            self.last_node = cond_node
            prev = cond_node
            for stmt in node.body:
                n = CFGNode(stmt)
                self.graph.add_node(n)
                prev.add_successor(n)
                prev = n
                self._build(stmt)
            if node.orelse:
                prev_else = cond_node
                for stmt in node.orelse:
                    n = CFGNode(stmt)
                    self.graph.add_node(n)
                    prev_else.add_successor(n)
                    prev_else = n
                    self._build(stmt)
        elif isinstance(node, (ast.While, ast.For)):
            loop_node = CFGNode(node, name='loop')
            self.graph.add_node(loop_node)
            if self.last_node:
                self.last_node.add_successor(loop_node)
            self.last_node = loop_node
            prev = loop_node
            for stmt in node.body:
                n = CFGNode(stmt)
                self.graph.add_node(n)
                prev.add_successor(n)
                prev = n
                self._build(stmt)
            # Loop back
            prev.add_successor(loop_node)
            if node.orelse:
                for stmt in node.orelse:
                    n = CFGNode(stmt)
                    self.graph.add_node(n)
                    loop_node.add_successor(n)
                    self._build(stmt)
        elif isinstance(node, ast.FunctionDef):
            # Build CFG for function body
            func_entry = CFGNode(node, name=f'func_{node.name}')
            self.graph.add_node(func_entry)
            if self.last_node:
                self.last_node.add_successor(func_entry)
            prev = func_entry
            for stmt in node.body:
                n = CFGNode(stmt)
                self.graph.add_node(n)
                prev.add_successor(n)
                prev = n
                self._build(stmt)
        # Add more AST node types as needed 
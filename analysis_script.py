import idaapi
import idautils
import idc
import ida_funcs
import ida_gdl
import ida_pro
import ida_bytes
import json
import sys
from collections import defaultdict

class ControlFlowAnalyzer:
    def __init__(self):
        self.function_cfgs = {}
        self.cfg_stats = {}
        
    def analyze_function_cfg(self, func_ea):
        """Extract control flow graph for a single function"""
        func = ida_funcs.get_func(func_ea)
        if not func:
            return None
        
        cfg_data = {
            'basic_blocks': [],
            'edges': [],
            'entry_block': None,
            'exit_blocks': []
        }
        
        # Get flowchart (CFG) for the function
        flowchart = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
        
        block_map = {}  # Map block start address to block index
        
        # Process each basic block
        for i, block in enumerate(flowchart):
            block_info = {
                'id': i,
                'start': block.start_ea,
                'end': block.end_ea,
                'size': block.end_ea - block.start_ea,
                'instructions': [],
                'type': self._get_block_type(block)
            }
            
            # Extract instructions in this block
            for head in idautils.Heads(block.start_ea, block.end_ea):
                insn = idautils.DecodeInstruction(head)
                if insn:
                    block_info['instructions'].append({
                        'address': head,
                        'mnemonic': idc.print_insn_mnem(head),
                        'disasm': idc.GetDisasm(head)
                    })
            
            cfg_data['basic_blocks'].append(block_info)
            block_map[block.start_ea] = i
            
            # Identify entry block
            if block.start_ea == func.start_ea:
                cfg_data['entry_block'] = i
        
        # Process edges between blocks
        for i, block in enumerate(flowchart):
            # Successors
            for succ_block in block.succs():
                if succ_block.start_ea in block_map:
                    edge_type = self._classify_edge(block, succ_block)
                    cfg_data['edges'].append({
                        'from': i,
                        'to': block_map[succ_block.start_ea],
                        'type': edge_type
                    })
            
            # Check if this is an exit block (no successors)
            if not list(block.succs()):
                cfg_data['exit_blocks'].append(i)
        
        # Calculate CFG statistics
        cfg_stats = self._calculate_cfg_stats(cfg_data, flowchart)
        
        return cfg_data, cfg_stats
    
    def _get_block_type(self, block):
        """Determine the type of basic block"""
        # Check the last instruction
        last_ea = idc.prev_head(block.end_ea)
        if last_ea == idaapi.BADADDR:
            return 'unknown'
        
        mnem = idc.print_insn_mnem(last_ea)
        
        if mnem in ['ret', 'retn', 'retf']:
            return 'return'
        elif mnem in ['jmp']:
            return 'unconditional_jump'
        elif mnem.startswith('j'):  # jz, jnz, je, jne, etc.
            return 'conditional_jump'
        elif mnem in ['call']:
            return 'call'
        else:
            return 'sequential'
    
    def _classify_edge(self, from_block, to_block):
        """Classify the type of edge between blocks"""
        last_ea = idc.prev_head(from_block.end_ea)
        if last_ea == idaapi.BADADDR:
            return 'unknown'
        
        mnem = idc.print_insn_mnem(last_ea)
        
        # Check if it's a conditional branch
        if mnem.startswith('j') and mnem != 'jmp':
            # Determine if this is the taken or not-taken branch
            # Typically, fall-through is not-taken, jump target is taken
            if to_block.start_ea == from_block.end_ea:
                return 'false_branch'  # Fall-through
            else:
                return 'true_branch'   # Jump taken
        elif mnem == 'jmp':
            return 'unconditional'
        else:
            return 'sequential'
    
    def _calculate_cfg_stats(self, cfg_data, flowchart):
        """Calculate various CFG complexity metrics"""
        num_blocks = len(cfg_data['basic_blocks'])
        num_edges = len(cfg_data['edges'])
        
        # Cyclomatic complexity: M = E - N + 2P (P=1 for single connected component)
        cyclomatic_complexity = num_edges - num_blocks + 2
        
        # Calculate average block size
        total_size = sum(b['size'] for b in cfg_data['basic_blocks'])
        avg_block_size = total_size / num_blocks if num_blocks > 0 else 0
        
        # Count block types
        block_types = defaultdict(int)
        for block in cfg_data['basic_blocks']:
            block_types[block['type']] += 1
        
        # Calculate branching factor
        out_degrees = defaultdict(int)
        for edge in cfg_data['edges']:
            out_degrees[edge['from']] += 1
        
        avg_branching = sum(out_degrees.values()) / len(out_degrees) if out_degrees else 0
        max_branching = max(out_degrees.values()) if out_degrees else 0
        
        return {
            'num_basic_blocks': num_blocks,
            'num_edges': num_edges,
            'cyclomatic_complexity': cyclomatic_complexity,
            'num_exit_blocks': len(cfg_data['exit_blocks']),
            'avg_block_size': avg_block_size,
            'block_types': dict(block_types),
            'avg_branching_factor': avg_branching,
            'max_branching_factor': max_branching
        }
    
    def analyze_all_functions(self):
        """Analyze CFG for all functions"""
        print("[*] Analyzing control flow graphs for all functions...")
        
        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)
            result = self.analyze_function_cfg(func_ea)
            
            if result:
                cfg_data, cfg_stats = result
                self.function_cfgs[func_ea] = cfg_data
                self.cfg_stats[func_ea] = cfg_stats
        
        print(f"[+] Analyzed CFG for {len(self.function_cfgs)} functions")
    
    def find_complex_functions(self, min_complexity=10):
        """Find functions with high cyclomatic complexity"""
        complex_funcs = []
        
        for func_ea, stats in self.cfg_stats.items():
            if stats['cyclomatic_complexity'] >= min_complexity:
                complex_funcs.append({
                    'address': func_ea,
                    'name': idc.get_func_name(func_ea),
                    'complexity': stats['cyclomatic_complexity'],
                    'blocks': stats['num_basic_blocks']
                })
        
        return sorted(complex_funcs, key=lambda x: x['complexity'], reverse=True)
    
    def find_functions_with_loops(self):
        """Find functions that contain loops (back edges in CFG)"""
        functions_with_loops = []
        
        for func_ea, cfg_data in self.function_cfgs.items():
            # Check for back edges (edge to a block with lower or equal ID)
            has_loop = False
            for edge in cfg_data['edges']:
                if edge['to'] <= edge['from']:
                    has_loop = True
                    break
            
            if has_loop:
                functions_with_loops.append({
                    'address': func_ea,
                    'name': idc.get_func_name(func_ea),
                    'blocks': self.cfg_stats[func_ea]['num_basic_blocks']
                })
        
        return functions_with_loops
    
    def export_cfg_to_dot(self, func_ea, output_file):
        """Export a single function's CFG to Graphviz format"""
        if func_ea not in self.function_cfgs:
            print(f"[-] No CFG data for function at 0x{func_ea:x}")
            return
        
        cfg_data = self.function_cfgs[func_ea]
        func_name = idc.get_func_name(func_ea)
        
        with open(output_file, 'w') as f:
            f.write(f"digraph CFG_{func_name} {{\n")
            f.write("  rankdir=TB;\n")
            f.write("  node [shape=box, fontname=\"Courier\"];\n\n")
            
            # Write nodes (basic blocks)
            for block in cfg_data['basic_blocks']:
                label = f"Block {block['id']}\\n0x{block['start']:x}-0x{block['end']:x}\\n"
                label += f"Size: {block['size']} bytes\\n"
                label += f"Type: {block['type']}\\n\\n"
                
                # Add first few instructions
                for insn in block['instructions'][:5]:
                    disasm = insn['disasm'].replace('"', '\\"')
                    label += f"{disasm}\\l"
                
                if len(block['instructions']) > 5:
                    label += "...\\l"
                
                # Color entry/exit blocks
                color = ""
                if block['id'] == cfg_data['entry_block']:
                    color = ', fillcolor=lightgreen, style=filled'
                elif block['id'] in cfg_data['exit_blocks']:
                    color = ', fillcolor=lightcoral, style=filled'
                
                f.write(f'  block_{block["id"]} [label="{label}"{color}];\n')
            
            f.write("\n")
            
            # Write edges
            for edge in cfg_data['edges']:
                edge_attr = ""
                if edge['type'] == 'true_branch':
                    edge_attr = ' [label="T", color=green]'
                elif edge['type'] == 'false_branch':
                    edge_attr = ' [label="F", color=red]'
                elif edge['type'] == 'unconditional':
                    edge_attr = ' [color=blue]'
                
                f.write(f'  block_{edge["from"]} -> block_{edge["to"]}{edge_attr};\n')
            
            f.write("}\n")
        
        print(f"[+] CFG exported to {output_file}")
        print(f"    Render with: dot -Tpng {output_file} -o {output_file}.png")


class CallGraphAnalyzer:
    def __init__(self):
        self.call_graph = defaultdict(list)
        self.reverse_call_graph = defaultdict(list)
        self.function_info = {}
        
    def analyze_function_calls(self, func_ea):
        """Extract all function calls from a given function"""
        func = ida_funcs.get_func(func_ea)
        if not func:
            return []
        
        callees = []
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if idc.print_insn_mnem(head) in ['call', 'jmp']:
                for xref in idautils.XrefsFrom(head, 0):
                    if xref.type in [ida_gdl.fl_CN, ida_gdl.fl_CF]:
                        target_func = ida_funcs.get_func(xref.to)
                        if target_func:
                            callees.append(target_func.start_ea)
        
        return callees
    
    def build_call_graph(self):
        """Build complete call graph for all functions in binary"""
        print("[*] Building call graph...")
        
        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)
            func = ida_funcs.get_func(func_ea)
            
            self.function_info[func_ea] = {
                'name': func_name,
                'start': func_ea,
                'end': func.end_ea if func else func_ea,
                'size': (func.end_ea - func.start_ea) if func else 0
            }
            
            callees = self.analyze_function_calls(func_ea)
            
            for callee_ea in callees:
                self.call_graph[func_ea].append(callee_ea)
                self.reverse_call_graph[callee_ea].append(func_ea)
        
        print(f"[+] Found {len(self.function_info)} functions")
        print(f"[+] Found {sum(len(v) for v in self.call_graph.values())} call edges")
    
    def find_leaf_functions(self):
        """Find functions that don't call anything"""
        leaves = []
        for func_ea in self.function_info.keys():
            if not self.call_graph[func_ea]:
                leaves.append(func_ea)
        return leaves
    
    def find_root_functions(self):
        """Find functions that are never called"""
        roots = []
        for func_ea in self.function_info.keys():
            if not self.reverse_call_graph[func_ea]:
                roots.append(func_ea)
        return roots
    
    def find_highly_connected_functions(self, min_connections=5):
        """Find functions with many callers or callees"""
        hubs = []
        
        for func_ea in self.function_info.keys():
            caller_count = len(self.reverse_call_graph[func_ea])
            callee_count = len(self.call_graph[func_ea])
            total = caller_count + callee_count
            
            if total >= min_connections:
                hubs.append({
                    'address': func_ea,
                    'name': self.function_info[func_ea]['name'],
                    'callers': caller_count,
                    'callees': callee_count,
                    'total': total
                })
        
        return sorted(hubs, key=lambda x: x['total'], reverse=True)
    
    def find_recursive_functions(self):
        """Find functions that call themselves"""
        recursive = []
        
        for func_ea in self.function_info.keys():
            if self._is_recursive(func_ea, func_ea, set()):
                recursive.append(func_ea)
        
        return recursive
    
    def _is_recursive(self, start_ea, current_ea, visited):
        """Helper to detect recursion via DFS"""
        if current_ea in visited:
            return False
        
        visited.add(current_ea)
        
        for callee in self.call_graph[current_ea]:
            if callee == start_ea:
                return True
            if self._is_recursive(start_ea, callee, visited.copy()):
                return True
        
        return False
    
    def export_to_graphviz(self, output_file="call_graph.dot", max_nodes=100):
        """Export call graph to Graphviz DOT format"""
        print(f"[*] Exporting call graph to {output_file}...")
        
        with open(output_file, 'w') as f:
            f.write("digraph CallGraph {\n")
            f.write("  rankdir=LR;\n")
            f.write("  node [shape=box];\n\n")
            
            funcs_to_include = list(self.function_info.keys())[:max_nodes]
            
            for func_ea in funcs_to_include:
                func_name = self.function_info[func_ea]['name']
                label = f"{func_name}\\n0x{func_ea:x}"
                f.write(f'  "func_{func_ea:x}" [label="{label}"];\n')
            
            f.write("\n")
            
            for caller_ea in funcs_to_include:
                for callee_ea in self.call_graph[caller_ea]:
                    if callee_ea in funcs_to_include:
                        f.write(f'  "func_{caller_ea:x}" -> "func_{callee_ea:x}";\n')
            
            f.write("}\n")
        
        print(f"[+] Graph exported. Render with: dot -Tpng {output_file} -o call_graph.png")
    
    def export_to_json(self, output_file="call_graph.json"):
        """Export call graph data to JSON"""
        print(f"[*] Exporting call graph to {output_file}...")
        
        data = {
            'functions': {},
            'call_graph': {},
            'statistics': {
                'total_functions': len(self.function_info),
                'total_calls': sum(len(v) for v in self.call_graph.values()),
                'leaf_functions': len(self.find_leaf_functions()),
                'root_functions': len(self.find_root_functions())
            }
        }
        
        for func_ea, info in self.function_info.items():
            data['functions'][f"0x{func_ea:x}"] = info
        
        for caller_ea, callees in self.call_graph.items():
            data['call_graph'][f"0x{caller_ea:x}"] = [f"0x{ea:x}" for ea in callees]
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Call graph JSON exported successfully")
    
    def print_analysis_report(self):
        """Print call graph analysis report"""
        print("\n" + "="*60)
        print("CALL GRAPH ANALYSIS REPORT")
        print("="*60)
        
        print(f"\nTotal Functions: {len(self.function_info)}")
        print(f"Total Call Edges: {sum(len(v) for v in self.call_graph.values())}")
        
        leaves = self.find_leaf_functions()
        print(f"\nLeaf Functions: {len(leaves)}")
        for func_ea in leaves[:5]:
            print(f"  - {self.function_info[func_ea]['name']} @ 0x{func_ea:x}")
        if len(leaves) > 5:
            print(f"  ... and {len(leaves) - 5} more")
        
        roots = self.find_root_functions()
        print(f"\nRoot Functions: {len(roots)}")
        for func_ea in roots[:5]:
            print(f"  - {self.function_info[func_ea]['name']} @ 0x{func_ea:x}")
        if len(roots) > 5:
            print(f"  ... and {len(roots) - 5} more")
        
        hubs = self.find_highly_connected_functions()
        print(f"\nHighly Connected Functions:")
        for hub in hubs[:5]:
            print(f"  - {hub['name']} @ 0x{hub['address']:x}")
            print(f"    Callers: {hub['callers']}, Callees: {hub['callees']}")
        
        recursive = self.find_recursive_functions()
        print(f"\nRecursive Functions: {len(recursive)}")
        for func_ea in recursive[:5]:
            print(f"  - {self.function_info[func_ea]['name']} @ 0x{func_ea:x}")


def main():
    print("[*] Waiting for IDA auto-analysis to complete...")
    idaapi.auto_wait()
    
    binary_name = idc.get_input_file_path().split('/')[-1].split('\\')[-1]
    base_name = binary_name.rsplit('.', 1)[0]
    
    # Call Graph Analysis
    print("\n" + "="*60)
    print("PHASE 1: CALL GRAPH ANALYSIS")
    print("="*60)
    call_analyzer = CallGraphAnalyzer()
    call_analyzer.build_call_graph()
    call_analyzer.print_analysis_report()
    call_analyzer.export_to_json(f"{base_name}_call_graph.json")
    call_analyzer.export_to_graphviz(f"{base_name}_call_graph.dot")
    
    # Control Flow Analysis
    print("\n" + "="*60)
    print("PHASE 2: CONTROL FLOW ANALYSIS")
    print("="*60)
    cfg_analyzer = ControlFlowAnalyzer()
    cfg_analyzer.analyze_all_functions()
    
    # Print CFG statistics
    print("\n" + "="*60)
    print("CONTROL FLOW ANALYSIS REPORT")
    print("="*60)
    
    # Find complex functions
    complex_funcs = cfg_analyzer.find_complex_functions(min_complexity=10)
    print(f"\nComplex Functions (Cyclomatic Complexity >= 10): {len(complex_funcs)}")
    for func in complex_funcs[:10]:
        print(f"  - {func['name']} @ 0x{func['address']:x}")
        print(f"    Complexity: {func['complexity']}, Blocks: {func['blocks']}")
    
    # Find functions with loops
    loop_funcs = cfg_analyzer.find_functions_with_loops()
    print(f"\nFunctions with Loops: {len(loop_funcs)}")
    for func in loop_funcs[:10]:
        print(f"  - {func['name']} @ 0x{func['address']:x} ({func['blocks']} blocks)")
    
    # Export CFG data to JSON
    cfg_export = {
        'functions': {}
    }
    
    for func_ea, cfg_data in cfg_analyzer.function_cfgs.items():
        func_name = idc.get_func_name(func_ea)
        cfg_export['functions'][f"0x{func_ea:x}"] = {
            'name': func_name,
            'cfg': cfg_data,
            'stats': cfg_analyzer.cfg_stats[func_ea]
        }
    
    with open(f"{base_name}_cfg_data.json", 'w') as f:
        json.dump(cfg_export, f, indent=2)
    print(f"\n[+] CFG data exported to {base_name}_cfg_data.json")
    
    # Export individual CFGs for most complex functions
    print("\n[*] Exporting CFG graphs for top 5 most complex functions...")
    for i, func in enumerate(complex_funcs[:5]):
        output_file = f"{base_name}_cfg_{func['name']}_0x{func['address']:x}.dot"
        cfg_analyzer.export_cfg_to_dot(func['address'], output_file)
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE!")
    print("="*60)
    print("\nGenerated files:")
    print(f"  - {base_name}_call_graph.json (call graph data)")
    print(f"  - {base_name}_call_graph.dot (call graph visualization)")
    print(f"  - {base_name}_cfg_data.json (control flow data)")
    print(f"  - {base_name}_cfg_*.dot (individual CFG visualizations)")
    print("\nRender .dot files with: dot -Tpng input.dot -o output.png")

if __name__ == "__main__":
    main()
    ida_pro.qexit(0)
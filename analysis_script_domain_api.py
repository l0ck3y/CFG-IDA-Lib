"""
IDA CFG & Call Graph Analyzer using IDA Domain API
Rewritten from l0ck3y/CFG-IDA-Lib to use the modern IDA Domain API

This script extracts:
- Call graphs (function relationships)  
- Control flow graphs (basic blocks and edges)
- Cyclomatic complexity metrics

Usage:
    python analysis_script_domain_api.py <binary_path>
    
Or from within IDA:
    Run as an IDA script via File -> Script file
"""

import json
import os
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict

try:
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions
    from ida_domain.flowchart import FlowChart, FlowChartFlags
    HAS_IDA_DOMAIN = True
except ImportError:
    HAS_IDA_DOMAIN = False
    print("Warning: ida_domain not found. This script requires IDA Domain API.")
    print("Install with: pip install ida-domain")

# Fallback to regular IDA API if running inside IDA
try:
    import ida_auto
    import ida_pro
    import idaapi
    RUNNING_IN_IDA = True
except ImportError:
    RUNNING_IN_IDA = False


@dataclass
class BasicBlockInfo:
    """Information about a basic block"""
    id: int
    start_ea: int
    end_ea: int
    size: int
    predecessors: List[int]
    successors: List[int]
    instructions: List[str]


@dataclass
class FunctionCFG:
    """Control Flow Graph information for a function"""
    name: str
    address: int
    size: int
    blocks: List[BasicBlockInfo]
    edges: List[Tuple[int, int]]  # (from_block_id, to_block_id)
    cyclomatic_complexity: int
    num_blocks: int


@dataclass
class FunctionInfo:
    """Basic information about a function"""
    name: str
    address: int
    size: int
    calls_to: List[int]  # Addresses of functions this calls
    called_from: List[int]  # Addresses of functions that call this


class CFGAnalyzer:
    """Main analyzer class using IDA Domain API"""
    
    def __init__(self, db: Database):
        self.db = db
        self.functions_info: Dict[int, FunctionInfo] = {}
        self.cfgs: Dict[int, FunctionCFG] = {}
        
    def analyze_all(self):
        """Perform complete analysis of call graph and CFGs"""
        print("[*] Starting analysis...")
        self._build_call_graph()
        self._analyze_all_cfgs()
        print("[*] Analysis complete!")
        
    def _build_call_graph(self):
        """Build call graph by analyzing all functions and their xrefs"""
        print("[*] Building call graph...")
        
        # First pass: collect all functions
        function_count = 0
        for func in self.db.functions:
            func_name = self.db.names.get(func.start_ea) or f"sub_{func.start_ea:X}"
            
            self.functions_info[func.start_ea] = FunctionInfo(
                name=func_name,
                address=func.start_ea,
                size=func.end_ea - func.start_ea,
                calls_to=[],
                called_from=[]
            )
            function_count += 1
        
        print(f"[*] Found {function_count} functions")
        
        # Second pass: analyze calls between functions
        for func_ea, func_info in self.functions_info.items():
            # Get all code xrefs from this function
            for xref in self.db.xrefs.get_code_from(func_ea):
                if xref.is_call():
                    target_ea = xref.to_ea
                    # Check if target is a known function
                    if target_ea in self.functions_info:
                        func_info.calls_to.append(target_ea)
                        self.functions_info[target_ea].called_from.append(func_ea)
        
        print(f"[*] Call graph built with {len(self.functions_info)} functions")
    
    def _analyze_all_cfgs(self):
        """Analyze CFG for all functions"""
        print("[*] Analyzing control flow graphs...")
        
        for func_ea, func_info in self.functions_info.items():
            try:
                cfg = self._analyze_function_cfg(func_ea)
                if cfg:
                    self.cfgs[func_ea] = cfg
            except Exception as e:
                print(f"[!] Error analyzing CFG for {func_info.name} at 0x{func_ea:X}: {e}")
                
        print(f"[*] Analyzed {len(self.cfgs)} function CFGs")
    
    def _analyze_function_cfg(self, func_ea: int) -> Optional[FunctionCFG]:
        """Analyze CFG for a single function using IDA Domain API"""
        func_info = self.functions_info.get(func_ea)
        if not func_info:
            return None
        
        # Get the function object
        func = self.db.functions.get(func_ea)
        if not func:
            return None
        
        # Create flowchart with predecessor information
        flowchart = FlowChart(
            database=self.db,
            func=func,
            flags=FlowChartFlags.PREDS
        )
        
        blocks_info = []
        edges = []
        
        # Analyze each basic block
        for block in flowchart:
            # Get predecessors
            predecessors = [pred.id for pred in block.get_predecessors()]
            
            # Get successors
            successors = [succ.id for succ in block.get_successors()]
            
            # Collect edges from this block to successors
            for succ_id in successors:
                edges.append((block.id, succ_id))
            
            # Get instructions in this block
            instructions = []
            try:
                for insn in block.get_instructions():
                    # Get disassembly text
                    disasm = self.db.instructions.get_disasm(insn.ea)
                    instructions.append(f"{insn.ea:X}: {disasm}")
            except Exception as e:
                print(f"[!] Error getting instructions for block {block.id}: {e}")
            
            block_info = BasicBlockInfo(
                id=block.id,
                start_ea=block.start_ea,
                end_ea=block.end_ea,
                size=block.end_ea - block.start_ea,
                predecessors=predecessors,
                successors=successors,
                instructions=instructions
            )
            blocks_info.append(block_info)
        
        # Calculate cyclomatic complexity: M = E - N + 2
        # E = number of edges, N = number of nodes
        num_blocks = len(blocks_info)
        num_edges = len(edges)
        cyclomatic_complexity = num_edges - num_blocks + 2 if num_blocks > 0 else 0
        
        cfg = FunctionCFG(
            name=func_info.name,
            address=func_ea,
            size=func_info.size,
            blocks=blocks_info,
            edges=edges,
            cyclomatic_complexity=cyclomatic_complexity,
            num_blocks=num_blocks
        )
        
        return cfg
    
    def export_call_graph(self, output_path: str):
        """Export call graph to JSON"""
        call_graph_data = {
            "functions": {},
            "call_edges": [],
            "statistics": {
                "total_functions": len(self.functions_info),
                "total_call_edges": 0
            }
        }
        
        for func_ea, func_info in self.functions_info.items():
            call_graph_data["functions"][f"0x{func_ea:X}"] = {
                "name": func_info.name,
                "address": f"0x{func_ea:X}",
                "size": func_info.size,
                "calls_to": [f"0x{ea:X}" for ea in func_info.calls_to],
                "called_from": [f"0x{ea:X}" for ea in func_info.called_from]
            }
            
            # Add call edges
            for target_ea in func_info.calls_to:
                call_graph_data["call_edges"].append({
                    "from": f"0x{func_ea:X}",
                    "to": f"0x{target_ea:X}"
                })
                call_graph_data["statistics"]["total_call_edges"] += 1
        
        with open(output_path, 'w') as f:
            json.dump(call_graph_data, f, indent=2)
        
        print(f"[+] Call graph exported to {output_path}")
    
    def export_cfg_data(self, output_path: str):
        """Export CFG data to JSON"""
        cfg_data = {
            "functions": {},
            "statistics": {
                "total_functions": len(self.cfgs),
                "total_basic_blocks": sum(cfg.num_blocks for cfg in self.cfgs.values()),
                "complex_functions": []  # Functions with complexity > 10
            }
        }
        
        for func_ea, cfg in self.cfgs.items():
            # Convert blocks to dict format
            blocks_dict = {}
            for block in cfg.blocks:
                blocks_dict[str(block.id)] = {
                    "id": block.id,
                    "start_ea": f"0x{block.start_ea:X}",
                    "end_ea": f"0x{block.end_ea:X}",
                    "size": block.size,
                    "predecessors": block.predecessors,
                    "successors": block.successors,
                    "instruction_count": len(block.instructions),
                    "instructions": block.instructions[:10]  # Limit to first 10 for size
                }
            
            cfg_data["functions"][f"0x{func_ea:X}"] = {
                "name": cfg.name,
                "address": f"0x{func_ea:X}",
                "size": cfg.size,
                "basic_blocks": blocks_dict,
                "edges": [[src, dst] for src, dst in cfg.edges],
                "metrics": {
                    "num_blocks": cfg.num_blocks,
                    "cyclomatic_complexity": cfg.cyclomatic_complexity
                }
            }
            
            # Track complex functions
            if cfg.cyclomatic_complexity > 10:
                cfg_data["statistics"]["complex_functions"].append({
                    "name": cfg.name,
                    "address": f"0x{func_ea:X}",
                    "complexity": cfg.cyclomatic_complexity
                })
        
        # Sort complex functions by complexity
        cfg_data["statistics"]["complex_functions"].sort(
            key=lambda x: x["complexity"],
            reverse=True
        )
        
        with open(output_path, 'w') as f:
            json.dump(cfg_data, f, indent=2)
        
        print(f"[+] CFG data exported to {output_path}")
        
        # Print some statistics
        if cfg_data["statistics"]["complex_functions"]:
            print(f"[*] Found {len(cfg_data['statistics']['complex_functions'])} complex functions:")
            for func in cfg_data["statistics"]["complex_functions"][:5]:
                print(f"    - {func['name']} (complexity: {func['complexity']})")


def main_standalone(binary_path: str):
    """Main function for standalone execution using idalib"""
    if not HAS_IDA_DOMAIN:
        print("[!] IDA Domain API is not available. Please install ida-domain.")
        return 1
    
    binary_path = Path(binary_path).resolve()
    if not binary_path.exists():
        print(f"[!] Binary not found: {binary_path}")
        return 1
    
    print(f"[*] Analyzing binary: {binary_path}")
    
    # Determine output paths
    output_dir = binary_path.parent
    base_name = binary_path.stem
    call_graph_path = output_dir / f"{base_name}_call_graph.json"
    cfg_data_path = output_dir / f"{base_name}_cfg_data.json"
    
    # Setup IDA options for analysis
    ida_options = IdaCommandOptions(
        auto_analysis=True,  # Run auto-analysis
        new_database=False   # Use existing DB if available
    )
    
    # Open database and perform analysis
    try:
        with Database.open(str(binary_path), ida_options) as db:
            print(f"[*] Database opened: {db.metadata.version}")
            print(f"[*] Address range: 0x{db.minimum_ea:X} - 0x{db.maximum_ea:X}")
            
            # Wait for auto-analysis to complete
            print("[*] Waiting for auto-analysis to complete...")
            # Auto-analysis is handled by IdaCommandOptions
            
            # Create analyzer and run
            analyzer = CFGAnalyzer(db)
            analyzer.analyze_all()
            
            # Export results
            analyzer.export_call_graph(str(call_graph_path))
            analyzer.export_cfg_data(str(cfg_data_path))
            
            print("[+] Analysis complete!")
            print(f"[+] Results saved to:")
            print(f"    - {call_graph_path}")
            print(f"    - {cfg_data_path}")
            
    except Exception as e:
        print(f"[!] Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


def main_ida_script():
    """Main function when running as IDA script"""
    if not RUNNING_IN_IDA:
        print("[!] This function should only be called when running inside IDA")
        return
    
    print("[*] Running CFG analysis inside IDA...")
    
    # Wait for auto-analysis
    print("[*] Waiting for auto-analysis to complete...")
    ida_auto.auto_wait()
    
    # Get current database path
    from idc import get_idb_path
    idb_path = Path(get_idb_path())
    binary_path = idb_path.with_suffix('')  # Remove .i64/.idb extension
    
    # Determine output paths
    output_dir = binary_path.parent
    base_name = binary_path.stem
    call_graph_path = output_dir / f"{base_name}_call_graph.json"
    cfg_data_path = output_dir / f"{base_name}_cfg_data.json"
    
    try:
        # Create database wrapper
        db = Database()
        
        # Create analyzer and run
        analyzer = CFGAnalyzer(db)
        analyzer.analyze_all()
        
        # Export results
        analyzer.export_call_graph(str(call_graph_path))
        analyzer.export_cfg_data(str(cfg_data_path))
        
        print("[+] Analysis complete!")
        print(f"[+] Results saved to:")
        print(f"    - {call_graph_path}")
        print(f"    - {cfg_data_path}")
        
    except Exception as e:
        print(f"[!] Error during analysis: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Exit IDA if running headless
        if idaapi.is_batch_mode():
            ida_pro.qexit(0)


if __name__ == "__main__":
    if RUNNING_IN_IDA:
        # Running as IDA script
        main_ida_script()
    else:
        # Running standalone with idalib
        parser = argparse.ArgumentParser(
            description="IDA CFG & Call Graph Analyzer using IDA Domain API"
        )
        parser.add_argument(
            "binary",
            help="Path to binary file to analyze"
        )
        args = parser.parse_args()
        
        sys.exit(main_standalone(args.binary))

import idaapi
import idautils
import idc
import ida_funcs
import ida_xref
import json
import os
from collections import defaultdict

def log(msg):
    print(msg)

# Wait for auto-analysis
idaapi.auto_wait()

log("="*60)
log("IDA CFG & CALL GRAPH ANALYZER")
log("="*60)

# Get output directory
idb_path = idc.get_idb_path()
output_dir = os.path.dirname(idb_path) if idb_path else os.getcwd()

input_path = idc.get_input_file_path()
base_name = os.path.basename(input_path)
if '.' in base_name:
    base_name = base_name.rsplit('.', 1)[0]

log(f"Output directory: {output_dir}")
log(f"Base filename: {base_name}")

# ===== CALL GRAPH ANALYSIS =====
log("\nPhase 1: Building call graph...")
call_graph = defaultdict(list)
function_info = {}

for func_ea in idautils.Functions():
    func_name = idc.get_func_name(func_ea)
    func = ida_funcs.get_func(func_ea)
    
    if func:
        function_info[func_ea] = {
            'name': func_name,
            'start': func_ea,
            'end': func.end_ea,
            'size': func.end_ea - func.start_ea
        }
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if idc.print_insn_mnem(head) == 'call':
                for xref in idautils.XrefsFrom(head, 0):
                    if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                        target_func = ida_funcs.get_func(xref.to)
                        if target_func:
                            call_graph[func_ea].append(target_func.start_ea)

log(f"Found {len(function_info)} functions")
log(f"Found {sum(len(v) for v in call_graph.values())} call edges")

# Export call graph
call_data = {
    'functions': {},
    'call_graph': {}
}

for func_ea, info in function_info.items():
    call_data['functions'][f"0x{func_ea:x}"] = info

for caller_ea, callees in call_graph.items():
    call_data['call_graph'][f"0x{caller_ea:x}"] = [f"0x{ea:x}" for ea in callees]

call_json = os.path.join(output_dir, f"{base_name}_call_graph.json")
with open(call_json, 'w') as f:
    json.dump(call_data, f, indent=2)

log(f"Saved call graph to: {call_json}")

# ===== CFG ANALYSIS =====
log("\nPhase 2: Analyzing control flow graphs...")

function_cfgs = {}
cfg_stats = {}

func_count = 0
for func_ea in idautils.Functions():
    func = ida_funcs.get_func(func_ea)
    if not func:
        continue
    
    try:
        flowchart = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
        
        cfg_data = {
            'basic_blocks': [],
            'edges': [],
            'entry_block': None,
            'exit_blocks': []
        }
        
        block_map = {}
        
        # Extract basic blocks
        for i, block in enumerate(flowchart):
            block_info = {
                'id': i,
                'start': block.start_ea,
                'end': block.end_ea,
                'size': block.end_ea - block.start_ea
            }
            
            cfg_data['basic_blocks'].append(block_info)
            block_map[block.start_ea] = i
            
            if block.start_ea == func.start_ea:
                cfg_data['entry_block'] = i
        
        # Extract edges
        for i, block in enumerate(flowchart):
            for succ_block in block.succs():
                if succ_block.start_ea in block_map:
                    cfg_data['edges'].append({
                        'from': i,
                        'to': block_map[succ_block.start_ea]
                    })
            
            if not list(block.succs()):
                cfg_data['exit_blocks'].append(i)
        
        # Calculate statistics
        num_blocks = len(cfg_data['basic_blocks'])
        num_edges = len(cfg_data['edges'])
        cyclomatic_complexity = num_edges - num_blocks + 2
        
        cfg_stats[func_ea] = {
            'num_basic_blocks': num_blocks,
            'num_edges': num_edges,
            'cyclomatic_complexity': cyclomatic_complexity,
            'num_exit_blocks': len(cfg_data['exit_blocks'])
        }
        
        function_cfgs[func_ea] = cfg_data
        func_count += 1
        
    except:
        pass

log(f"Analyzed CFG for {func_count} functions")

# Find complex functions
complex_funcs = []
for func_ea, stats in cfg_stats.items():
    if stats['cyclomatic_complexity'] >= 10:
        complex_funcs.append({
            'address': func_ea,
            'name': idc.get_func_name(func_ea),
            'complexity': stats['cyclomatic_complexity'],
            'blocks': stats['num_basic_blocks']
        })

complex_funcs.sort(key=lambda x: x['complexity'], reverse=True)
log(f"Found {len(complex_funcs)} complex functions (complexity >= 10)")

# Export CFG data
cfg_export = {
    'functions': {},
    'summary': {
        'total_functions': len(function_cfgs),
        'complex_functions': len(complex_funcs)
    }
}

for func_ea, cfg_data in function_cfgs.items():
    cfg_export['functions'][f"0x{func_ea:x}"] = {
        'name': idc.get_func_name(func_ea),
        'cfg': cfg_data,
        'stats': cfg_stats[func_ea]
    }

cfg_json = os.path.join(output_dir, f"{base_name}_cfg_data.json")
with open(cfg_json, 'w') as f:
    json.dump(cfg_export, f, indent=2)

log(f"Saved CFG data to: {cfg_json}")

log("\n" + "="*60)
log("ANALYSIS COMPLETE!")
log("="*60)
log(f"\nGenerated files:")
log(f"  - {os.path.basename(call_json)}")
log(f"  - {os.path.basename(cfg_json)}")

# Exit IDA
import ida_pro
ida_pro.qexit(0)
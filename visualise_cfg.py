import json
import sys
import subprocess
import os

def create_cfg_dot(cfg_data, func_name, output_file):
    """Create a DOT file for a single function's CFG"""
    
    with open(output_file, 'w') as f:
        # Sanitize function name for DOT
        safe_name = func_name.replace('<', '_').replace('>', '_').replace(':', '_')
        f.write(f'digraph "{safe_name}" {{\n')
        f.write('  rankdir=TB;\n')
        f.write('  node [shape=box, fontname="Courier New"];\n\n')
        
        # Write nodes (basic blocks)
        for block in cfg_data['basic_blocks']:
            label = f"Block {block['id']}\\n"
            label += f"0x{block['start']:x} - 0x{block['end']:x}\\n"
            label += f"Size: {block['size']} bytes"
            
            # Color entry/exit blocks
            style = ""
            if block['id'] == cfg_data['entry_block']:
                style = ', fillcolor=lightgreen, style=filled'
            elif block['id'] in cfg_data['exit_blocks']:
                style = ', fillcolor=lightcoral, style=filled'
            
            f.write(f'  block_{block["id"]} [label="{label}"{style}];\n')
        
        f.write('\n')
        
        # Write edges
        for edge in cfg_data['edges']:
            f.write(f'  block_{edge["from"]} -> block_{edge["to"]};\n')
        
        f.write('}\n')

def visualize_most_complex(cfg_json_file, output_dir, top_n=5):
    """Visualize the N most complex functions"""
    
    print(f"[*] Loading {cfg_json_file}...")
    with open(cfg_json_file, 'r') as f:
        data = json.load(f)
    
    # Find most complex functions
    complex_funcs = []
    for addr, func_data in data['functions'].items():
        complexity = func_data['stats']['cyclomatic_complexity']
        complex_funcs.append({
            'address': addr,
            'name': func_data['name'],
            'complexity': complexity,
            'cfg': func_data['cfg']
        })
    
    complex_funcs.sort(key=lambda x: x['complexity'], reverse=True)
    
    print(f"\n[*] Top {top_n} most complex functions:")
    for i, func in enumerate(complex_funcs[:top_n], 1):
        print(f"  {i}. {func['name']} @ {func['address']} (complexity: {func['complexity']})")
    
    # Create DOT files and render
    os.makedirs(output_dir, exist_ok=True)
    
    for i, func in enumerate(complex_funcs[:top_n], 1):
        safe_name = func['name'].replace('<', '_').replace('>', '_').replace(':', '_')
        dot_file = os.path.join(output_dir, f"{i}_{safe_name}_{func['address']}.dot")
        png_file = os.path.join(output_dir, f"{i}_{safe_name}_{func['address']}.png")
        
        print(f"\n[*] Creating CFG for {func['name']}...")
        create_cfg_dot(func['cfg'], func['name'], dot_file)
        
        # Render with Graphviz
        try:
            subprocess.run(['dot', '-Tpng', dot_file, '-o', png_file], check=True)
            print(f"[+] Saved to {png_file}")
        except FileNotFoundError:
            print(f"[-] Graphviz not found. Install it and add to PATH.")
            print(f"    DOT file saved to {dot_file}")
        except subprocess.CalledProcessError as e:
            print(f"[-] Error rendering: {e}")

def visualize_specific_function(cfg_json_file, func_name, output_dir):
    """Visualize a specific function by name"""
    
    with open(cfg_json_file, 'r') as f:
        data = json.load(f)
    
    # Find function by name
    for addr, func_data in data['functions'].items():
        if func_data['name'] == func_name or func_name in func_data['name']:
            print(f"[*] Found function: {func_data['name']} @ {addr}")
            
            safe_name = func_data['name'].replace('<', '_').replace('>', '_').replace(':', '_')
            dot_file = os.path.join(output_dir, f"{safe_name}_{addr}.dot")
            png_file = os.path.join(output_dir, f"{safe_name}_{addr}.png")
            
            create_cfg_dot(func_data['cfg'], func_data['name'], dot_file)
            
            try:
                subprocess.run(['dot', '-Tpng', dot_file, '-o', png_file], check=True)
                print(f"[+] Saved to {png_file}")
            except FileNotFoundError:
                print(f"[-] Graphviz not found. DOT file saved to {dot_file}")
            
            return
    
    print(f"[-] Function '{func_name}' not found")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} <cfg_json_file> [output_dir] [top_n]")
        print(f"  {sys.argv[0]} <cfg_json_file> --function <function_name> [output_dir]")
        sys.exit(1)
    
    cfg_json = sys.argv[1]
    
    if '--function' in sys.argv:
        idx = sys.argv.index('--function')
        func_name = sys.argv[idx + 1]
        output_dir = sys.argv[idx + 2] if len(sys.argv) > idx + 2 else './cfg_graphs'
        visualize_specific_function(cfg_json, func_name, output_dir)
    else:
        output_dir = sys.argv[2] if len(sys.argv) > 2 else './cfg_graphs'
        top_n = int(sys.argv[3]) if len(sys.argv) > 3 else 5
        visualize_most_complex(cfg_json, output_dir, top_n)
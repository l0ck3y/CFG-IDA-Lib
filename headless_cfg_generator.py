# Headless CFG Generator for Ghidra (Windows Compatible)
# Analyzes a binary and generates CFG JSON for all functions with timing
# @author David
# @category Analysis

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
import json
import time
import os

def get_function_cfg(function, program):
    """
    Extract CFG data for a given function
    Returns a dictionary with nodes and edges
    """
    cfg_data = {
        'function_name': function.getName(),
        'entry_point': str(function.getEntryPoint()),
        'nodes': [],
        'edges': []
    }
    
    # Create basic block model
    blockModel = BasicBlockModel(program)
    monitor = ConsoleTaskMonitor()
    
    try:
        # Get all basic blocks for this function
        blocks = blockModel.getCodeBlocksContaining(function.getBody(), monitor)
        
        block_map = {}
        node_id = 0
        
        # Process each basic block
        while blocks.hasNext():
            block = blocks.next()
            block_start = block.getMinAddress()
            block_end = block.getMaxAddress()
            
            # Store block info
            block_map[str(block_start)] = node_id
            
            # Get instructions in this block
            instructions = []
            listing = program.getListing()
            inst = listing.getInstructionAt(block_start)
            
            while inst is not None and inst.getAddress().compareTo(block_end) <= 0:
                inst_data = {
                    'address': str(inst.getAddress()),
                    'mnemonic': inst.getMnemonicString()
                }
                
                # Get operands
                if inst.getNumOperands() > 0:
                    operands = []
                    for i in range(inst.getNumOperands()):
                        operands.append(str(inst.getDefaultOperandRepresentation(i)))
                    inst_data['operands'] = operands
                
                instructions.append(inst_data)
                inst = inst.getNext()
            
            node_data = {
                'id': node_id,
                'start_address': str(block_start),
                'end_address': str(block_end),
                'size': block.getNumAddresses(),
                'instruction_count': len(instructions),
                'instructions': instructions
            }
            
            cfg_data['nodes'].append(node_data)
            node_id += 1
        
        # Now get edges (control flow between blocks)
        blocks = blockModel.getCodeBlocksContaining(function.getBody(), monitor)
        
        while blocks.hasNext():
            block = blocks.next()
            block_start = str(block.getMinAddress())
            
            if block_start in block_map:
                source_id = block_map[block_start]
                
                # Get destination blocks
                destinations = block.getDestinations(monitor)
                while destinations.hasNext():
                    dest = destinations.next()
                    dest_addr = str(dest.getDestinationAddress())
                    
                    if dest_addr in block_map:
                        edge_data = {
                            'source': source_id,
                            'target': block_map[dest_addr],
                            'type': str(dest.getFlowType())
                        }
                        cfg_data['edges'].append(edge_data)
    except Exception as e:
        print("[!] Error processing function {}: {}".format(function.getName(), str(e)))
    
    return cfg_data

def analyze_program(program, output_path):
    """
    Analyze all functions in the program and generate CFG data
    """
    start_time = time.time()
    
    print("[*] Starting CFG generation...")
    print("[*] Program: {}".format(program.getName()))
    
    # Get all functions
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)  # True = forward iteration
    
    all_cfgs = {
        'program_name': program.getName(),
        'program_path': str(program.getExecutablePath()) if program.getExecutablePath() else "Unknown",
        'functions': []
    }
    
    function_count = 0
    total_blocks = 0
    total_edges = 0
    
    # Process each function
    print("[*] Processing functions...")
    for function in functions:
        function_count += 1
        func_name = function.getName()
        
        if function_count % 100 == 0:
            print("[*] Processed {} functions...".format(function_count))
        
        try:
            cfg_data = get_function_cfg(function, program)
            all_cfgs['functions'].append(cfg_data)
            
            total_blocks += len(cfg_data['nodes'])
            total_edges += len(cfg_data['edges'])
        except Exception as e:
            print("[!] Error processing function {}: {}".format(func_name, str(e)))
    
    # Save output
    print("[*] Writing output to: {}".format(output_path))
    try:
        with open(output_path, 'w') as f:
            json.dump(all_cfgs, f, indent=2)
    except Exception as e:
        print("[!] Error writing output file: {}".format(str(e)))
        raise
    
    end_time = time.time()
    elapsed = end_time - start_time
    
    # Print summary
    print("")
    print("="*60)
    print("CFG Generation Complete")
    print("="*60)
    print("Program:        {}".format(program.getName()))
    print("Functions:      {}".format(function_count))
    print("Basic Blocks:   {}".format(total_blocks))
    print("Edges:          {}".format(total_edges))
    print("Output:         {}".format(output_path))
    print("Time Elapsed:   {:.2f} seconds".format(elapsed))
    print("Avg per func:   {:.3f} seconds".format(elapsed / function_count if function_count > 0 else 0))
    print("="*60)
    
    return elapsed

# Main execution for headless mode
if currentProgram is None:
    print("[!] Error: No program loaded")
else:
    # Determine output path
    program_name = currentProgram.getName()
    
    # Get script arguments (output path passed from command line)
    try:
        script_args = getScriptArgs()
        if script_args and len(script_args) > 0:
            output_path = script_args[0]
        else:
            # Default output path for Windows
            output_path = "C:\\temp\\{}_cfg.json".format(program_name)
    except:
        # Fallback if getScriptArgs() doesn't work
        output_path = "C:\\temp\\{}_cfg.json".format(program_name)
    
    print("[*] Output path: {}".format(output_path))
    
    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print("[*] Created output directory: {}".format(output_dir))
        except Exception as e:
            print("[!] Warning: Could not create output directory: {}".format(str(e)))
    
    # Run analysis
    try:
        elapsed = analyze_program(currentProgram, output_path)
        print("[+] Analysis complete!")
    except Exception as e:
        print("[!] Fatal error: {}".format(str(e)))
        import traceback
        traceback.print_exc()

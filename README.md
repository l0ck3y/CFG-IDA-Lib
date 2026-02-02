# CFG & Call Graph Analysis Toolkit

Automated toolkit for extracting Control Flow Graphs (CFG) and call graphs from binaries using both **IDA Pro** and **Ghidra** in headless mode. Perfect for malware analysis pipelines, binary analysis automation, and security research.

## 🚀 Features

- **Dual Platform Support**: Works with both IDA Pro and Ghidra
- **Call Graph Extraction**: Maps all function call relationships throughout binaries
- **Control Flow Graph Analysis**: Extracts basic blocks and control flow for each function
- **Cyclomatic Complexity Calculation**: Automatically identifies complex functions
- **Headless Operation**: Runs completely automated for batch processing
- **JSON Export**: Structured data output for further processing or visualization
- **Modern APIs**: Supports both traditional IDA SDK and modern IDA Domain API

## 📋 Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [IDA Pro](#ida-pro-usage)
  - [Ghidra](#ghidra-usage)
- [Output Format](#output-format)
- [Batch Processing](#batch-processing)
- [Platform Comparison](#platform-comparison)
- [Advanced Usage](#advanced-usage)
- [Visualization](#visualization)
- [Troubleshooting](#troubleshooting)

## 🛠️ Requirements

### IDA Pro Option
- **IDA Pro 9.1+** (with valid license)
- **Python 3.8+**
- **idapro package**: `pip install idapro` (for standalone mode)
- **ida-domain**: `pip install ida-domain` (for Domain API version)

### Ghidra Option
- **Ghidra 10.4+** (free, open source)
- **Java JDK 11+** (required by Ghidra)
- **Python 3.x** (for visualization scripts)

### Optional
- **Graphviz** (for CFG visualization)
- **ElasticSearch** (for indexing results)

## 📦 Installation

### Clone Repository
```bash
git clone https://github.com/yourusername/CFG-Analysis-Toolkit.git
cd CFG-Analysis-Toolkit
```

### IDA Pro Setup
```bash
# Set IDA installation directory
export IDADIR="/path/to/ida"  # Linux/Mac
set IDADIR=C:\path\to\ida     # Windows

# Install Python packages
pip install idapro ida-domain
```

### Ghidra Setup
1. Download Ghidra from https://ghidra-sre.org/
2. Extract to your preferred location (e.g., `C:\ghidra`)
3. Ensure Java JDK 11+ is installed
4. No additional Python packages required for basic usage

## 🎯 Quick Start

### IDA Pro Usage

#### Option 1: Standalone Mode (Recommended)
Uses the `idapro` package to run completely outside IDA GUI:

```bash
python analysis_ida_lib.py /path/to/binary.exe
```

#### Option 2: IDA Domain API (Modern)
Uses the new Domain API for cleaner, more Pythonic code:

```bash
python analysis_script_domain_api.py /path/to/binary.exe
```

#### Option 3: Headless IDA
Traditional headless execution:

**Windows:**
```cmd
"C:\Program Files\IDA Professional 9.2\idat.exe" -A -S"analysis_script.py" "C:\path\to\binary.exe"
```

**Linux:**
```bash
/opt/ida/idat -A -S"analysis_script.py" /path/to/binary
```

### Ghidra Usage

#### Option 1: PowerShell Wrapper (Windows - Recommended)
```powershell
.\Run-GhidraCFG.ps1 -BinaryPath "C:\malware\sample.exe" -OutputPath "C:\output\cfg.json"
```

#### Option 2: Batch File (Windows - Simple)
```cmd
run_ghidra_cfg.bat C:\malware\sample.exe C:\output\cfg.json
```

#### Option 3: Direct Command Line
```cmd
# First create project directory
mkdir C:\Temp\ghidra_projects

# Then run analysis
C:\ghidra\support\analyzeHeadless.bat ^
    C:\Temp\ghidra_projects ^
    MyProject ^
    -import "C:\malware\sample.exe" ^
    -scriptPath "C:\path\to\scripts" ^
    -postScript headless_cfg_generator.py "C:\output\cfg.json" ^
    -deleteProject
```

**Important:** Use `-postScript` for the Python script, not `-import`. Only the binary should be imported.

## 📊 Output Format

Both tools generate two JSON files:

### 1. Call Graph (`{filename}_call_graph.json`)

```json
{
  "functions": {
    "0x401000": {
      "name": "main",
      "address": "0x401000",
      "size": 256,
      "calls_to": ["0x401100", "0x401200"],
      "called_from": []
    }
  },
  "call_edges": [
    {"from": "0x401000", "to": "0x401100"}
  ],
  "statistics": {
    "total_functions": 150,
    "total_call_edges": 320
  }
}
```

### 2. CFG Data (`{filename}_cfg_data.json`)

```json
{
  "functions": {
    "0x401000": {
      "name": "main",
      "address": "0x401000",
      "basic_blocks": {
        "0": {
          "id": 0,
          "start_address": "0x401000",
          "end_address": "0x401010",
          "size": 16,
          "predecessors": [],
          "successors": [1, 2],
          "instructions": [
            {
              "address": "0x401000",
              "mnemonic": "push",
              "operands": ["rbp"]
            }
          ]
        }
      },
      "edges": [[0, 1], [0, 2]],
      "stats": {
        "num_basic_blocks": 8,
        "cyclomatic_complexity": 5
      }
    }
  }
}
```

### Timing Output (Ghidra)

```
============================================================
CFG Generation Complete
============================================================
Program:        malware.exe
Functions:      1234
Basic Blocks:   5678
Edges:          7890
Output:         C:\output\cfg.json
Time Elapsed:   45.23 seconds
Avg per func:   0.037 seconds
============================================================
```

## 🔄 Batch Processing

### IDA Pro Batch Processing

```python
import subprocess

samples = [
    "sample1.exe",
    "sample2.exe",
    "sample3.exe"
]

for sample in samples:
    print(f"[*] Analyzing {sample}...")
    subprocess.run([
        "python",
        "analysis_ida_lib.py",
        sample
    ])
```

### Ghidra Batch Processing

**PowerShell:**
```powershell
$samples = Get-ChildItem "C:\malware\samples\*.exe"
foreach ($sample in $samples) {
    $outputPath = "C:\output\$($sample.BaseName)_cfg.json"
    .\Run-GhidraCFG.ps1 -BinaryPath $sample.FullName -OutputPath $outputPath
}
```

**Batch File:**
```cmd
for %%f in (C:\malware\samples\*.exe) do (
    call run_ghidra_cfg.bat "%%f" "C:\output\%%~nf_cfg.json"
)
```

### Python Integration (Both Platforms)

```python
import subprocess
import json
from pathlib import Path

def analyze_with_ida(binary_path):
    """Analyze using IDA Pro"""
    subprocess.run([
        "python", "analysis_ida_lib.py", binary_path
    ], check=True)
    
    # Load results
    base_name = Path(binary_path).stem
    cfg_file = Path(binary_path).parent / f"{base_name}_cfg_data.json"
    
    with open(cfg_file, 'r') as f:
        return json.load(f)

def analyze_with_ghidra(binary_path, output_path):
    """Analyze using Ghidra"""
    subprocess.run([
        "powershell.exe", "-ExecutionPolicy", "Bypass",
        "-File", "Run-GhidraCFG.ps1",
        "-BinaryPath", binary_path,
        "-OutputPath", output_path
    ], check=True)
    
    with open(output_path, 'r') as f:
        return json.load(f)

# Choose the tool you have available
binary = "C:\\malware\\sample.exe"
output = "C:\\output\\sample_cfg.json"

# Option 1: IDA Pro
cfg_data = analyze_with_ida(binary)

# Option 2: Ghidra
cfg_data = analyze_with_ghidra(binary, output)

print(f"Analyzed {len(cfg_data['functions'])} functions")
```

## ⚖️ Platform Comparison

| Feature | IDA Pro | Ghidra | Notes |
|---------|---------|--------|-------|
| **Cost** | Commercial (~$1800+) | Free | IDA requires license |
| **Analysis Quality** | Excellent | Very Good | IDA slightly better on obfuscated code |
| **Speed** | Fast | Moderate | IDA typically 20-30% faster |
| **Automation** | Excellent | Excellent | Both support headless mode |
| **API Quality** | Mature | Good | IDA has more documentation |
| **Platform Support** | Windows, Linux, Mac | Windows, Linux, Mac | Both cross-platform |
| **Processor Support** | Extensive (50+) | Extensive (many) | IDA has slight edge |
| **Decompilation** | Best-in-class | Very Good | IDA Hex-Rays is superior |
| **Learning Curve** | Moderate | Steeper | Ghidra requires Java knowledge |
| **Community** | Large | Growing | Both have active communities |
| **Scripting** | Python, IDC | Python, Java | IDA more Python-friendly |

### When to Use IDA Pro
- ✅ Maximum analysis accuracy required
- ✅ Working with exotic or custom architectures
- ✅ Need best-in-class decompilation
- ✅ Already have IDA Pro license
- ✅ Production malware analysis pipeline
- ✅ Commercial/enterprise use

### When to Use Ghidra
- ✅ Budget constraints (free)
- ✅ Open source requirements
- ✅ Good enough accuracy for most cases
- ✅ Learning reverse engineering
- ✅ Academic or research projects
- ✅ Need to analyze source code

## 🔧 Advanced Usage

### IDA Pro: Using Domain API

The modern Domain API provides cleaner, more Pythonic code:

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions
from ida_domain.flowchart import FlowChart, FlowChartFlags

options = IdaCommandOptions(auto_analysis=True, new_database=False)

with Database.open(binary_path, options) as db:
    # Iterate functions
    for func in db.functions:
        func_name = db.names.get(func.start_ea) or f"sub_{func.start_ea:X}"
        print(f"Function: {func_name} at 0x{func.start_ea:X}")
        
        # Analyze CFG
        flowchart = FlowChart(db, func=func, flags=FlowChartFlags.PREDS)
        
        for block in flowchart:
            predecessors = [p.id for p in block.get_predecessors()]
            successors = [s.id for s in block.get_successors()]
            print(f"  Block {block.id}: 0x{block.start_ea:X}")
            print(f"    Preds: {predecessors}, Succs: {successors}")
```

See [README_DOMAIN_API.md](README_DOMAIN_API.md) and [SDK_vs_DOMAIN_API_COMPARISON.md](SDK_vs_DOMAIN_API_COMPARISON.md) for full documentation.

### Ghidra: Custom Analysis Options

```cmd
# Skip auto-analysis for faster processing (less accurate)
C:\ghidra\support\analyzeHeadless.bat ^
    C:\Temp\ghidra_projects MyProject ^
    -import "sample.exe" ^
    -noanalysis ^
    -scriptPath "." ^
    -postScript headless_cfg_generator.py "output.json" ^
    -deleteProject

# Force specific processor/architecture
C:\ghidra\support\analyzeHeadless.bat ^
    C:\Temp\ghidra_projects MyProject ^
    -import "sample.bin" ^
    -processor x86:LE:64:default ^
    -cspec windows ^
    -scriptPath "." ^
    -postScript headless_cfg_generator.py "output.json" ^
    -deleteProject
```

### ElasticSearch Integration

```python
from elasticsearch import Elasticsearch
from datetime import datetime
import json

es = Elasticsearch(['localhost:9200'])

def index_cfg(cfg_path, sample_hash):
    """Index CFG data in ElasticSearch"""
    with open(cfg_path, 'r') as f:
        cfg_data = json.load(f)
    
    # Calculate statistics
    functions = cfg_data.get('functions', {})
    total_blocks = 0
    total_edges = 0
    complexities = []
    
    for func_data in functions.values():
        blocks = func_data.get('basic_blocks', {})
        total_blocks += len(blocks)
        
        edges = func_data.get('edges', [])
        total_edges += len(edges)
        
        stats = func_data.get('stats', {})
        complexity = stats.get('cyclomatic_complexity', 0)
        if complexity:
            complexities.append(complexity)
    
    # Prepare document
    doc = {
        'sha256': sample_hash,
        'program_name': cfg_data.get('program_name', 'unknown'),
        'function_count': len(functions),
        'total_blocks': total_blocks,
        'total_edges': total_edges,
        'avg_complexity': sum(complexities) / len(complexities) if complexities else 0,
        'max_complexity': max(complexities) if complexities else 0,
        'timestamp': datetime.now().isoformat(),
        'cfg_data': cfg_data
    }
    
    # Index
    es.index(index='malware-cfgs', id=sample_hash, document=doc)
    print(f"[+] Indexed {sample_hash}")

# Usage
index_cfg(
    "C:\\output\\sample_cfg.json",
    "392de99bfb9c2afaf632f8f5319e536e095e3a458d9aeca66b6c9c70ad43b7f0"
)
```

## 📈 Visualization

### Visualizing Complex Functions (IDA)

```bash
# Visualize top 5 most complex functions
python visualise_cfg.py sample_cfg_data.json ./graphs 5

# Visualize specific function by name
python visualise_cfg.py sample_cfg_data.json --function "main" ./graphs
```

This creates DOT files and PNG images using Graphviz.

### Manual CFG Graph Creation

```python
import subprocess

def create_cfg_dot(cfg_data, function_name, output_file):
    """Create DOT file for a function's CFG"""
    with open(output_file, 'w') as f:
        f.write(f'digraph "{function_name}" {{\n')
        f.write('  rankdir=TB;\n')
        f.write('  node [shape=box];\n\n')
        
        # Write nodes
        for block in cfg_data['basic_blocks'].values():
            label = f"Block {block['id']}\\n{block['start_address']}"
            f.write(f'  block_{block["id"]} [label="{label}"];\n')
        
        # Write edges
        for src, dst in cfg_data['edges']:
            f.write(f'  block_{src} -> block_{dst};\n')
        
        f.write('}\n')

def render_dot(dot_file, output_png):
    """Convert DOT to PNG using Graphviz"""
    subprocess.run(['dot', '-Tpng', dot_file, '-o', output_png], check=True)
```

## 🐛 Troubleshooting

### IDA Pro Issues

**Problem: "idapro package not found"**
```bash
pip install idapro
```

**Problem: "Cannot locate IDA installation"**
```bash
# Set IDADIR environment variable
export IDADIR=/opt/ida          # Linux/Mac
set IDADIR=C:\Program Files\IDA Professional 9.2   # Windows
```

**Problem: "Database locked"**
- Close any open IDA instances using the file
- Delete `.i64` or `.idb` files and re-analyze
- Check for zombie IDA processes in Task Manager

**Problem: "Analysis timeout"**
- Large binaries can take time
- Increase timeout in script if needed
- Consider using `-noanalysis` flag for faster (less accurate) processing

### Ghidra Issues

**Problem: "Directory not found: C:\Temp\ghidra_projects"**
```cmd
mkdir C:\Temp\ghidra_projects
```

**Problem: "Could not find analyzeHeadless.bat"**
- Verify Ghidra installation
- Update `GHIDRA_PATH` variable in wrapper scripts
- Ensure Ghidra is properly extracted (not just downloaded)

**Problem: "Import failed for Python script"**
- **Critical**: Use `-postScript` for Python files, NOT `-import`
- Only use `-import` for the binary/executable
- Verify script path is correct
- Check that script is in the `-scriptPath` directory

**Problem: "No program loaded"**
- Ensure binary is imported before running script
- Check binary format is supported by Ghidra
- Try importing manually in Ghidra GUI first

**Problem: "Java heap space error"**
- Edit `analyzeHeadless.bat` to increase heap size
- Add: `-Xmx4G` for 4GB heap (adjust as needed)

## 📚 Project Structure

```
CFG-Analysis-Toolkit/
├── ida/
│   ├── analysis_script.py              # Traditional IDA SDK script
│   ├── analysis_ida_lib.py             # Standalone IDA with idapro package
│   ├── analysis_script_domain_api.py   # Modern Domain API script
│   ├── example_usage.py                # Domain API examples
│   └── visualise_cfg.py                # CFG visualization tool
├── ghidra/
│   ├── headless_cfg_generator.py       # Ghidra Python script
│   ├── Run-GhidraCFG.ps1              # PowerShell wrapper
│   └── run_ghidra_cfg.bat             # Batch file wrapper
├── docs/
│   ├── README_DOMAIN_API.md            # Domain API documentation
│   └── SDK_vs_DOMAIN_API_COMPARISON.md # API comparison guide
├── examples/
│   └── batch_processing.py             # Batch processing examples
├── tests/
│   └── test_analysis.py                # Unit tests
├── README.md                           # This file
├── requirements.txt                    # Python dependencies
└── LICENSE                             # MIT License
```

## 🔬 Research & Analysis Use Cases

### Malware Family Classification

```python
def extract_cfg_features(cfg_data):
    """Extract structural features for ML classification"""
    features = {
        'num_functions': len(cfg_data['functions']),
        'avg_complexity': 0,
        'max_complexity': 0,
        'total_blocks': 0,
        'avg_block_size': 0,
        'avg_edges_per_func': 0
    }
    
    complexities = []
    block_sizes = []
    edge_counts = []
    
    for func in cfg_data['functions'].values():
        stats = func.get('stats', {})
        complexity = stats.get('cyclomatic_complexity', 0)
        complexities.append(complexity)
        
        blocks = func.get('basic_blocks', {})
        edges = func.get('edges', [])
        edge_counts.append(len(edges))
        
        for block in blocks.values():
            block_sizes.append(block.get('size', 0))
    
    if complexities:
        features['avg_complexity'] = sum(complexities) / len(complexities)
        features['max_complexity'] = max(complexities)
    
    if block_sizes:
        features['total_blocks'] = len(block_sizes)
        features['avg_block_size'] = sum(block_sizes) / len(block_sizes)
    
    if edge_counts:
        features['avg_edges_per_func'] = sum(edge_counts) / len(edge_counts)
    
    return features
```

### Binary Similarity Analysis

```python
def calculate_cfg_similarity(cfg1, cfg2):
    """Calculate structural similarity between two binaries"""
    
    # Compare function count
    func1 = len(cfg1['functions'])
    func2 = len(cfg2['functions'])
    func_sim = min(func1, func2) / max(func1, func2) if max(func1, func2) > 0 else 0
    
    # Compare complexity distributions
    comp1 = [f.get('stats', {}).get('cyclomatic_complexity', 0) 
             for f in cfg1['functions'].values()]
    comp2 = [f.get('stats', {}).get('cyclomatic_complexity', 0) 
             for f in cfg2['functions'].values()]
    
    avg_comp1 = sum(comp1) / len(comp1) if comp1 else 0
    avg_comp2 = sum(comp2) / len(comp2) if comp2 else 0
    
    comp_sim = 1 - abs(avg_comp1 - avg_comp2) / max(avg_comp1, avg_comp2) if max(avg_comp1, avg_comp2) > 0 else 0
    
    # Combined similarity
    similarity = (func_sim + comp_sim) / 2
    
    return {
        'overall_similarity': similarity,
        'function_count_similarity': func_sim,
        'complexity_similarity': comp_sim
    }
```

## 🤝 Contributing

Contributions welcome! Areas of interest:

- Additional disassembler support (Binary Ninja, radare2)
- Enhanced visualization options (interactive graphs, web UI)
- ML-based CFG analysis and classification
- Performance optimizations
- Additional output formats (GraphML, Neo4j, DOT)
- Cloud-based batch processing (AWS, Azure, GCP)
- Docker containerization

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Original IDA CFG analyzer concept
- IDA Pro by Hex-Rays
- Ghidra by NSA Research Directorate
- Python community for excellent libraries
- Security researchers and reverse engineers worldwide

## 📧 Contact & Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/yourusername/CFG-Analysis-Toolkit/issues)
- **Discussions**: [Ask questions or share ideas](https://github.com/yourusername/CFG-Analysis-Toolkit/discussions)

---

**Made with ❤️ for the security research community**

*If you find this tool useful, please consider starring the repository!*

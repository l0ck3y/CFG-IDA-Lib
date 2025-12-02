# IDA CFG & Call Graph Analyzer

Automated analysis tool for extracting control flow graphs (CFG) and call graphs from binaries using IDA Pro in headless mode.

## Features

- **Call Graph Extraction**: Maps all function calls throughout the binary
- **Control Flow Graph (CFG) Analysis**: Extracts basic blocks and control flow for each function
- **Cyclomatic Complexity Calculation**: Identifies complex functions automatically
- **Headless Operation**: Runs completely automated via IDA Pro's text interface (`idat.exe`)
- **JSON Export**: Outputs structured data for further processing or visualization

## Requirements

- **IDA Pro 9.2+** (with valid license)
- **Python 3.x** (for visualization scripts)
- **Graphviz** (optional, for CFG visualization)

## Installation

1. Clone this repository:

git clone https://github.com/yourusername/CFG-IDA-Lib.git
cd CFG-IDA-Lib

2. Copy `analysis_script.py` to IDA's user directory:

### Windows
Copy-Item "analysis_script.py" "$env:APPDATA\Hex-Rays\IDA Pro\idapythonrc.py"

### Linux/Mac
cp analysis_script.py ~/.idapro/idapythonrc.py

## Usage

### Basic Analysis

Run IDA in headless mode with the `-A` flag to perform automatic analysis:
#### Windows
& "C:\Program Files\IDA Professional 9.2\idat.exe" -A -o "C:\path\to\binary.exe"

#### Linux
/path/to/idat -A -o /path/to/binary

The script will:
1. Wait for IDA's auto-analysis to complete
2. Extract all functions and their relationships
3. Build the call graph
4. Analyze control flow for each function
5. Export results to JSON files
6. Exit automatically

### Output Files

The script generates two JSON files in the same directory as the analyzed binary:

1. **`{filename}_call_graph.json`** - Contains:
   - Function metadata (name, address, size)
   - Call relationships between functions
   - Statistics (total functions, call edges)

2. **`{filename}_cfg_data.json`** - Contains:
   - Basic blocks for each function
   - Control flow edges between blocks
   - Entry and exit blocks
   - Complexity metrics (cyclomatic complexity, block count)

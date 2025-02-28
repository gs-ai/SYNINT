Below is the regenerated and neatly formatted **README.md** file:

```markdown
# SYNINT OSINT Framework

SYNINT is a modular, stealth-optimized Open-Source Intelligence (OSINT) framework designed to integrate multiple agents for comprehensive data gathering, analysis, and threat intelligence. The system is self-contained, does not rely on external APIs, and emphasizes minimal network noise and low resource usage.

---

## Table of Contents

- [Features](#features)
- [Directory Structure](#directory-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Agents Overview](#agents-overview)
- [Extending the Framework](#extending-the-framework)
- [Testing](#testing)
- [License](#license)

---

## Features

- **Modular Architecture:**  
  Every agent inherits from a common abstract base class (`OSINTAgent`) defined in `agents/base_agent.py` and implements a standard `run(target)` method. This design enables easy integration of new agents.

- **Stealth and Efficiency:**  
  The framework minimizes external API calls and network noise by performing all operations locally. It utilizes optimized algorithms and minimal logging to remain unobtrusive.

- **Parallel Execution:**  
  Agents are executed concurrently through the `AgentManager` (located in `agent_manager.py`) using Python’s `ThreadPoolExecutor`, reducing overall processing time.

- **Self-Contained:**  
  The system does not depend on external APIs. All intelligence is derived using local computations (e.g., ML-based anomaly detection, graph analysis, Fourier transforms).

---

## 📂 Project Structure

The following is the directory structure of **SYNINT**:

```plaintext
SYNINT/
│── README.MD
│── agent_manager.py
│── main.py
│── requirements.txt
│
├── agents/
│   ├── __init__.py
│   ├── base_agent.py
│   ├── cybint_agent.py
│   ├── ids_agent.py
│   ├── mitm_agent.py
│   ├── siem_agent.py
│   ├── social_media_agent.py
│   ├── techint_agent.py
│   ├── threat_analyzer_agent.py
│   └── whois_agent.py

---

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/SYNINT.git
   cd SYNINT
   ```

2. **Create a Virtual Environment (Recommended):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

   The `requirements.txt` file includes required packages such as:
   - `requests`
   - `numpy`
   - `scikit-learn`
   - `networkx`
   - `opencv-python`
   - `scipy`

---

## Usage

You can run the framework as a whole or execute individual agents. The `AgentManager` (located in the root-level `agent_manager.py`) orchestrates the agents.

### Running All Agents

In your `main.py` file, you might have code similar to the following:

```python
#!/usr/bin/env python3
import json
import sys

# Import AgentManager from the root-level file
from agent_manager import AgentManager

# Import agent classes from the agents package
from agents.cybint_agent import CybintAgent
from agents.social_media_agent import SocialMediaAgent
from agents.whois_agent import WhoisAgent
from agents.ids_agent import IDSAgent
from agents.mitm_agent import MITMAgent
from agents.siem_agent import SIEMAgent
from agents.techint_agent import TechIntAgent
from agents.threat_analyzer_agent import ThreatAnalyzerAgent

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    manager = AgentManager()

    # Register all desired agents
    manager.register_agent(CybintAgent())
    manager.register_agent(SocialMediaAgent())
    manager.register_agent(WhoisAgent())
    manager.register_agent(IDSAgent())
    manager.register_agent(MITMAgent())
    manager.register_agent(SIEMAgent())
    manager.register_agent(TechIntAgent())
    manager.register_agent(ThreatAnalyzerAgent())

    # Run all agents on the target
    results = manager.run_all(target)
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()
```

### Running an Individual Agent

For example, to run the IDSAgent on a string of IDS log entries:

```python
from agent_manager import AgentManager
from agents.ids_agent import IDSAgent

manager = AgentManager()
manager.register_agent(IDSAgent())

ids_logs = """2021-01-01 12:00:00 Failed login from 10.0.0.5
2021-01-01 12:05:00 Successful login from 10.0.0.5"""

result = manager.run_agent("IDSAgent", ids_logs)
print(result)
```

---

## Agents Overview

- **SocialMediaAgent:** Searches popular social media platforms (Twitter, Facebook, LinkedIn) for a specified username.
- **WhoisAgent:** Performs a WHOIS lookup for a target domain or IP by invoking the system's `whois` command.
- **CybintAgent:** Scans a target for vulnerabilities using heuristic algorithms (resolves domain to IP and computes a pseudo intelligence score).
- **IDSAgent:** Detects anomalies in IDS logs using a combination of machine learning techniques (IsolationForest, LOF, and One-Class SVM).
- **MITMAgent:** Analyzes network logs to detect potential Man-in-the-Middle nodes using graph centrality measures.
- **SIEMAgent:** Clusters SIEM log events via TF-IDF, SVD, and agglomerative clustering to reveal patterns.
- **TechIntAgent:** Assesses technical indicators (or images) to compute risk scores using mathematical functions.
- **ThreatAnalyzerAgent:** Aggregates various threat indicators to compute an overall risk score and highlight high-risk items.

---

## Extending the Framework

To add a new agent:

1. Create a new file (e.g., `xxxx_agent.py`) in the `agents/` directory.
2. Inherit from `OSINTAgent` (imported from `agents/base_agent.py`).
3. Implement the `run(target)` method with your agent’s specific logic.
4. Register your new agent in your main script or within the AgentManager.

---

## Testing

Each agent gracefully handles incorrect input by returning an error message in its output dictionary. You can write unit tests for each agent, or run manual tests using the command line. For example:

```bash
python -m unittest discover tests
```

*(Create a `tests/` directory with test cases for each agent if you wish to automate testing.)*

---

## License

This project is licensed under the [MIT License](LICENSE).
```

This README.md is fully regenerated with neat alignment and clear formatting for every section. Adjust the details (e.g., repository URL, license information) as needed for your project.

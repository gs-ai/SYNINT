#!/usr/bin/env python3
"""
Main script for SYNINT OSINT Framework

This script demonstrates how to register all available agents with the AgentManager
and run them on a specified target. The results are printed in JSON format.
"""

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

    # Create an instance of the AgentManager
    manager = AgentManager()

    # Register all agents
    manager.register_agent(CybintAgent())
    manager.register_agent(SocialMediaAgent())
    manager.register_agent(WhoisAgent())
    manager.register_agent(IDSAgent())
    manager.register_agent(MITMAgent())
    manager.register_agent(SIEMAgent())
    manager.register_agent(TechIntAgent())
    manager.register_agent(ThreatAnalyzerAgent())

    # Run all registered agents on the given target
    results = manager.run_all(target)

    # Print the results in JSON format for readability
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()

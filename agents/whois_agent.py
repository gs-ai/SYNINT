#!/usr/bin/env python3
"""
whois_agent.py - Performs a WHOIS lookup on a target domain/IP.

This module defines the WhoisAgent class, which inherits from OSINTAgent,
and executes a WHOIS lookup using the system's 'whois' command.
"""

from agents.base_agent import OSINTAgent
import subprocess

class WhoisAgent(OSINTAgent):
    def run(self, target):
        target_str = str(target).strip()
        try:
            output = subprocess.check_output(["whois", target_str], timeout=5)
            data = output.decode("utf-8", errors="ignore")
        except Exception as e:
            data = f"Error during whois lookup: {e}"
        result = {
            "agent": "WhoisAgent",
            "target": target_str,
            "whois_data": data
        }
        self.results = result
        return result

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python whois_agent.py <target>")
    else:
        agent = WhoisAgent()
        print(agent.run(sys.argv[1]))

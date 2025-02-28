#!/usr/bin/env python3
"""
whois_agent.py - Performs a robust WHOIS lookup on a target domain/IP.

This module defines the WhoisAgent class, which inherits from OSINTAgent,
and executes a WHOIS lookup using the system's 'whois' command. It includes
enhanced error handling, input validation, and logging to ensure reliability.
"""

import re
import subprocess
import logging
from agents.base_agent import OSINTAgent

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class WhoisAgent(OSINTAgent):
    def validate_target(self, target: str) -> bool:
        """
        Validates the target string to ensure it is a plausible domain or IPv4 address.
        Returns True if valid, False otherwise.
        """
        # Simple regex for domain (e.g., example.com) and IPv4 address.
        domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        ipv4_regex = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        if re.match(domain_regex, target) or re.match(ipv4_regex, target):
            return True
        return False

    def run(self, target) -> dict:
        """
        Performs a WHOIS lookup on the target domain/IP with robust error handling and logging.
        """
        target_str = str(target).strip()
        logger.info(f"Starting WHOIS lookup for target: {target_str}")

        if not self.validate_target(target_str):
            error_msg = f"Invalid target format: {target_str}"
            logger.error(error_msg)
            result = {
                "agent": "WhoisAgent",
                "target": target_str,
                "whois_data": None,
                "error": error_msg
            }
            self.results = result
            return result

        try:
            # Execute the whois command with a 10-second timeout.
            output = subprocess.check_output(["whois", target_str], timeout=10)
            data = output.decode("utf-8", errors="ignore")
            logger.info(f"WHOIS lookup successful for {target_str}")
        except subprocess.TimeoutExpired:
            error_msg = f"WHOIS lookup timed out for {target_str}"
            logger.error(error_msg)
            data = error_msg
        except FileNotFoundError:
            error_msg = "WHOIS command not found. Please install whois."
            logger.error(error_msg)
            data = error_msg
        except Exception as e:
            error_msg = f"Error during WHOIS lookup: {e}"
            logger.exception(error_msg)
            data = error_msg

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
        result = agent.run(sys.argv[1])
        print(result)

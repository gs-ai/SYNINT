#!/usr/bin/env python3
"""
AgentManager Module
---------------------
This module defines the AgentManager class, a critical component of the SYNINT framework.
It orchestrates multiple OSINT agents by registering and executing them concurrently,
aggregating their results. Designed for high-stakes operations, it includes per-agent timing,
detailed logging, robust error handling, and a method to list all registered agents.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

class AgentManager:
    """
    Manages the registration and concurrent execution of multiple OSINT agents.
    """
    def __init__(self):
        # List to store registered agent instances.
        self.agents = []

    def register_agent(self, agent):
        """
        Register an OSINT agent with the manager.

        Parameters:
            agent: An instance of a class that inherits from OSINTAgent.
        """
        if agent not in self.agents:
            self.agents.append(agent)
            logger.info(f"Registered agent: {type(agent).__name__}")
        else:
            logger.warning(f"Agent {type(agent).__name__} is already registered.")

    def remove_agent(self, agent):
        """
        Remove an OSINT agent from the registry.

        Parameters:
            agent: The agent instance to remove.
        """
        if agent in self.agents:
            self.agents.remove(agent)
            logger.info(f"Removed agent: {type(agent).__name__}")
        else:
            logger.warning(f"Agent {type(agent).__name__} is not registered.")

    def list_agents(self) -> list:
        """
        Returns a list of class names of all registered agents.

        Returns:
            List[str]: A list of agent class names.
        """
        return [type(agent).__name__ for agent in self.agents]

    def run_all(self, target) -> dict:
        """
        Run all registered agents concurrently against the provided target.

        Parameters:
            target: The target data to be passed to each agent's run() method.

        Returns:
            dict: A dictionary mapping each agent's class name to a dictionary with keys:
                  'result' (the agent's output) and 'execution_time' (in seconds).
        """
        results = {}
        if not self.agents:
            logger.warning("No agents registered to run.")
            return results

        logger.info(f"Executing {len(self.agents)} agents on target: {target}")

        with ThreadPoolExecutor(max_workers=len(self.agents)) as executor:
            future_to_agent = {}
            for agent in self.agents:
                start_time = time.time()
                future = executor.submit(agent.run, target)
                future_to_agent[future] = (agent, start_time)

            for future in as_completed(future_to_agent):
                agent, start_time = future_to_agent[future]
                elapsed = time.time() - start_time
                try:
                    result = future.result()
                    logger.info(f"Agent {type(agent).__name__} completed in {elapsed:.2f} seconds.")
                except Exception as e:
                    logger.exception(f"Error executing agent {type(agent).__name__}: {e}")
                    result = {"error": str(e)}
                results[type(agent).__name__] = {"result": result, "execution_time": elapsed}
        return results

    def run_agent(self, agent_name, target) -> dict:
        """
        Run a specific agent by its class name.

        Parameters:
            agent_name (str): The class name of the agent.
            target: The target data for the agent's run() method.

        Returns:
            dict: The result from the agent's run() method along with its execution time,
                  or an error message if no such agent is registered.
        """
        for agent in self.agents:
            if type(agent).__name__ == agent_name:
                logger.info(f"Running agent: {agent_name}")
                try:
                    start_time = time.time()
                    result = agent.run(target)
                    elapsed = time.time() - start_time
                    logger.info(f"Agent {agent_name} completed in {elapsed:.2f} seconds.")
                    return {"result": result, "execution_time": elapsed}
                except Exception as e:
                    logger.exception(f"Error running agent {agent_name}: {e}")
                    return {"error": str(e)}
        error_msg = f"No agent found with name: {agent_name}"
        logger.error(error_msg)
        return {"error": error_msg}

if __name__ == "__main__":
    # This module is intended for integration with the SYNINT framework.
    print("AgentManager is part of the SYNINT framework and is not intended to be run standalone.")

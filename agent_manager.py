# framework/agent_manager.py

from concurrent.futures import ThreadPoolExecutor, as_completed

class AgentManager:
    """Orchestrates multiple OSINT agents and manages their execution."""
    
    def __init__(self):
        # List to store registered agent instances
        self.agents = []
    
    def register_agent(self, agent):
        """Add an OSINT agent to the manager's registry."""
        self.agents.append(agent)
    
    def remove_agent(self, agent):
        """Remove an OSINT agent from the registry (if present)."""
        if agent in self.agents:
            self.agents.remove(agent)
    
    def run_all(self, target):
        """
        Run all registered agents against the given target.
        Returns a dictionary of results collected from each agent.
        """
        results = {}
        if not self.agents:
            return results  # No agents to run
        
        # Use ThreadPoolExecutor to run agents in parallel for performance
        with ThreadPoolExecutor(max_workers=len(self.agents)) as executor:
            # Dictionary to map futures to agent instances for identification
            future_to_agent = {
                executor.submit(agent.run, target): agent for agent in self.agents
            }
            # as_completed yields futures as they complete
            for future in as_completed(future_to_agent):
                agent = future_to_agent[future]
                try:
                    result = future.result()  # get the result from agent.run
                except Exception as e:
                    result = {"error": str(e)}
                # Use agent's class name or a defined name as key for results
                agent_name = type(agent).__name__
                results[agent_name] = result
        return results
    
    def run_agent(self, agent_name, target):
        """
        Run a specific agent by class name on the target.
        Returns that agent's result, or None if not found.
        """
        for agent in self.agents:
            if type(agent).__name__ == agent_name:
                return agent.run(target)
        return None

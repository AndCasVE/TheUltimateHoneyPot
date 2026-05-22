class OfflineAIEngine:
    def __init__(self, settings):
        self.settings=settings
    def render(self, system_prompt:str, user_input:str)->str:
        return ""  # placeholder for local provider adapter; service-level simulators remain primary safety mechanism.

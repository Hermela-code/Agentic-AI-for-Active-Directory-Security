from agent.config import MODEL_NAME
from agent.models import Investigation


class ADAgent:
    def __init__(self):
        self.model_name = MODEL_NAME

    def start_investigation(self, target: str) -> Investigation:
        investigation = Investigation(
            id="investigation-001",
            target=target,
            status="running"
        )

        print(f"Starting investigation against: {target}")
        print(f"AI model: {self.model_name}")

        return investigation


if __name__ == "__main__":
    agent = ADAgent()
    investigation = agent.start_investigation("192.168.56.10")

    print(investigation)
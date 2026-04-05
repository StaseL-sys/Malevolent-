import requests

# Custom User Agent Strings
USER_AGENTS = {
    "research-bot": "Mozilla/5.0 (compatible; ResearchBot/1.0; +http://example.com/research-bot)",
    "competitor-analyzer": "Mozilla/5.0 (compatible; CompetitorAnalyzer/1.0; +http://example.com/competitor-analyzer)",
    "marketing-research": "Mozilla/5.0 (compatible; MarketingResearch/1.0; +http://example.com/marketing-research)",
    "distribution-research": "Mozilla/5.0 (compatible; DistributionResearch/1.0; +http://example.com/distribution-research)",
}

def make_http_request(url, user_agent_key):
    """
    Make an HTTP GET request to the specified URL using the specified user agent.

    Args:
        url (str): The URL to request.
        user_agent_key (str): The key for the user agent to use.

    Returns:
        Response: The HTTP response object.
    """
    headers = {"User-Agent": USER_AGENTS.get(user_agent_key, USER_AGENTS["research-bot"])}
    response = requests.get(url, headers=headers)
    return response

# Example usage
if __name__ == "__main__":
    # Researching a competitor security product
    url = "https://www.kaspersky.com/"
    response = make_http_request(url, "research-bot")
    print(f"Response Code: {response.status_code}")
    print(f"Response Content: {response.text[:200]}")  # Print the first 200 characters of the response
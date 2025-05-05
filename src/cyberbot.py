import os
import requests
from typing import Dict, List, Optional, Union

class CyberBot:
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the CyberBot with Groq API integration.
        
        Args:
            api_key: Groq API key. If not provided, will look for GROQ_API_KEY env variable.
        """
        # First try the provided API key
        self.api_key = api_key
        
        # If not provided, try environment variable
        if not self.api_key:
            self.api_key = os.environ.get("GROQ_API_KEY")
            
        # If still not available, use a hardcoded key (only for development)
        if not self.api_key:
            self.api_key = "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"
            
        # Validate API key
        if not self.api_key:
            raise ValueError("Groq API key is required. Set GROQ_API_KEY environment variable or pass as argument.")
        
        self.base_url = "https://api.groq.com/openai/v1"
        self.model = "llama3-70b-8192"  # Default model
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Store conversation history
        self.conversation_history = []
    
    def query(self, message: str, system_prompt: Optional[str] = None) -> str:
        """Send a query to the Groq API and get a response.
        
        Args:
            message: User message
            system_prompt: Optional system prompt to guide the model
            
        Returns:
            Response from the model
        """
        if system_prompt is None:
            system_prompt = (
                "You are CyberBot, an AI assistant specialized in cybersecurity. "
                "Provide clear, accurate information about security threats, malware, "
                "network security, and best practices. When unsure, acknowledge limitations "
                "rather than providing potentially incorrect information."
            )
        
        # Add user message to history
        self.conversation_history.append({"role": "user", "content": message})
        
        # Prepare messages with system prompt and history
        messages = [{"role": "system", "content": system_prompt}] + self.conversation_history
        
        # Make request to Groq API
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self.headers,
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 2048
                }
            )
            response.raise_for_status()
            result = response.json()
            
            # Extract the assistant's response
            assistant_message = result["choices"][0]["message"]["content"]
            
            # Add assistant response to history
            self.conversation_history.append({"role": "assistant", "content": assistant_message})
            
            return assistant_message
        
        except requests.exceptions.RequestException as e:
            return f"Error communicating with Groq API: {str(e)}"
    
    def get_security_response(self, query: str) -> str:
        """Get a security-focused response for the user query.
        
        Args:
            query: User's security-related question
            
        Returns:
            Security-focused response
        """
        system_prompt = (
            "You are CyberBot, a cybersecurity expert assistant. Analyze the user's query "
            "and provide accurate, helpful information about cybersecurity threats, "
            "vulnerabilities, attack vectors, or security best practices. Include practical "
            "advice when appropriate. If the query is about a specific malware or attack, "
            "provide information about detection, prevention, and mitigation."
        )
        
        return self.query(query, system_prompt)
    
    def clear_conversation(self) -> None:
        """Clear the conversation history."""
        self.conversation_history = []
        
    def set_model(self, model: str) -> None:
        """Set the model to use for generating responses.
        
        Args:
            model: Model name (e.g., "llama3-70b-8192", "llama3-8b-8192")
        """
        self.model = model 
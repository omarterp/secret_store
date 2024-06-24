import os

class Config:
    @staticmethod
    def get_vault_url(environment):
        vault_urls = {
            "local": "http://localhost:8200",
            "dev": "https://dev.vault.example.com",
            "qa": "https://qa.vault.example.com",
            "prod": "https://vault.example.com"
        }
        return vault_urls.get(environment, "http://localhost:8200")
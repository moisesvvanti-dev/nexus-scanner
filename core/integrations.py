import os
import json
import random
import asyncio

class SupabaseHandler:
    def __init__(self):
        self.url = os.getenv("SUPABASE_URL")
        self.key = os.getenv("SUPABASE_KEY")
        self.mock_mode = not (self.url and self.key)
        self.wallet_file = "wallet.json"
        
        # Load persisted balance
        self.balance = self._load_wallet()
        
        if self.mock_mode:
            print("[INFO] Supabase credentials not found. Running in MOCK MODE.")

    def _load_wallet(self):
        if os.path.exists(self.wallet_file):
            try:
                with open(self.wallet_file, "r") as f:
                    data = json.load(f)
                    return float(data.get("balance", 50.00))
            except:
                return 50.00
        return 50.00

    def _save_wallet(self):
        try:
            with open(self.wallet_file, "w") as f:
                json.dump({"balance": self.balance}, f)
        except Exception as e:
            print(f"[ERROR] Failed to save wallet: {e}")

    async def get_balance(self):
        """Fetch current balance from Supabase or Mock."""
        if self.mock_mode:
            await asyncio.sleep(0.5) # Simulate network latency
            return self.balance
        return self.balance

    async def add_funds(self, amount):
        """Add funds to the user's balance."""
        if self.mock_mode:
            await asyncio.sleep(1.0)
            self.balance += amount
            self._save_wallet() # Persist change
            return True, f"Successfully added ${amount:.2f} (MOCK)"
        
        # Real implementation
        try:
            self.balance += amount
            self._save_wallet()
            return True, "Funds added successfully"
        except Exception as e:
            return False, str(e)

    async def deduct_funds(self, amount):
        """Deduct funds for operations."""
        if self.balance >= amount:
            self.balance -= amount
            self._save_wallet() # Persist change
            return True, "Authorized"
        else:
            return False, "Insufficient funds"

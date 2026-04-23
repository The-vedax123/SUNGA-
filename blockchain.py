import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import List


@dataclass
class Block:
    index: int
    timestamp: str
    sender: str
    receiver: str
    amount: float
    previous_hash: str
    block_hash: str

    @staticmethod
    def calculate_hash(
        index: int,
        timestamp: str,
        sender: str,
        receiver: str,
        amount: float,
        previous_hash: str,
    ) -> str:
        payload = f"{index}|{timestamp}|{sender}|{receiver}|{amount:.8f}|{previous_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Blockchain:
    def __init__(self) -> None:
        self.chain: List[Block] = []
        self.create_genesis_block()

    def create_genesis_block(self) -> None:
        timestamp = datetime.utcnow().isoformat()
        genesis_hash = Block.calculate_hash(0, timestamp, "GENESIS", "GENESIS", 0.0, "0")
        self.chain.append(
            Block(
                index=0,
                timestamp=timestamp,
                sender="GENESIS",
                receiver="GENESIS",
                amount=0.0,
                previous_hash="0",
                block_hash=genesis_hash,
            )
        )

    def add_block(self, sender: str, receiver: str, amount: float, timestamp: str) -> Block:
        previous = self.chain[-1]
        index = previous.index + 1
        block_hash = Block.calculate_hash(
            index=index,
            timestamp=timestamp,
            sender=sender,
            receiver=receiver,
            amount=amount,
            previous_hash=previous.block_hash,
        )
        block = Block(
            index=index,
            timestamp=timestamp,
            sender=sender,
            receiver=receiver,
            amount=amount,
            previous_hash=previous.block_hash,
            block_hash=block_hash,
        )
        self.chain.append(block)
        return block

    def rebuild_from_transactions(self, transactions: list) -> None:
        self.chain = []
        self.create_genesis_block()
        for tx in transactions:
            timestamp = tx["timestamp"]
            self.add_block(tx["sender"], tx["receiver"], float(tx["amount"]), timestamp)

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            recalculated = Block.calculate_hash(
                index=current.index,
                timestamp=current.timestamp,
                sender=current.sender,
                receiver=current.receiver,
                amount=current.amount,
                previous_hash=current.previous_hash,
            )
            if current.block_hash != recalculated:
                return False
            if current.previous_hash != previous.block_hash:
                return False
        return True

    def verify_chain(self) -> bool:
        return self.is_chain_valid()

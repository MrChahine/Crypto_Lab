import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, List

import tkinter as tk
from tkinter import messagebox, simpledialog


# -------------------- Core blockchain --------------------


@dataclass
class Block:
    index: int
    timestamp: float
    data: Any
    previous_hash: str
    nonce: int = 0
    hash: str = field(default="", init=False)

    def compute_hash(self) -> str:
        block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()


def proof_of_work(block: Block, difficulty: int = 3) -> str:
    prefix = "0" * difficulty
    while True:
        h = block.compute_hash()
        if h.startswith(prefix):
            return h
        block.nonce += 1


class Blockchain:
    def __init__(self, difficulty: int = 3):
        self.difficulty = difficulty
        self.chain: List[Block] = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            data="Genesis block",
            previous_hash="0" * 64,
        )
        genesis_block.hash = proof_of_work(genesis_block, self.difficulty)
        self.chain.append(genesis_block)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, data: Any) -> Block:
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            data=data,
            previous_hash=self.last_block.hash,
        )
        new_block.hash = proof_of_work(new_block, self.difficulty)
        self.chain.append(new_block)
        return new_block

    def is_valid(self) -> bool:
        prefix = "0" * self.difficulty

        for i in range(1, len(self.chain)):
            prev = self.chain[i - 1]
            curr = self.chain[i]

            # Check link
            if curr.previous_hash != prev.hash:
                print(f"Link error between blocks {i-1} and {i}")
                return False

            # Check hash consistency
            if curr.hash != curr.compute_hash():
                print(f"Invalid hash for block {i}")
                return False

            # Check difficulty
            if not curr.hash.startswith(prefix):
                print(f"Invalid proof of work for block {i}")
                return False

        return True
    def get_confirmations(self, index: int) -> int:
        """
        Nombre de confirmations pour le bloc d'indice index.
        Le dernier bloc a 1 confirmation, l'avant-dernier 2, etc.
        """
        if index < 0 or index >= len(self.chain):
            return 0
        return len(self.chain) - index


# -------------------- Tkinter UI --------------------


class BlockchainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Blockchain - TP Crypto")

        self.blockchain = Blockchain(difficulty=3)

        # Left: list of blocks
        self.listbox = tk.Listbox(root, width=60, height=15)
        self.listbox.grid(row=0, column=0, rowspan=5, padx=10, pady=10, sticky="ns")
        self.listbox.bind("<<ListboxSelect>>", self.on_select_block)

        # Right: block details
        self.details_text = tk.Text(root, width=80, height=15)
        self.details_text.grid(row=0, column=1, padx=10, pady=10)

        # Buttons
        self.btn_add = tk.Button(root, text="Add transaction block", command=self.add_block_dialog)
        self.btn_add.grid(row=1, column=1, sticky="w", padx=10, pady=2)

        self.btn_tamper = tk.Button(root, text="Simulate tampering", command=self.tamper_block)
        self.btn_tamper.grid(row=2, column=1, sticky="w", padx=10, pady=2)

        self.btn_check = tk.Button(root, text="Check blockchain", command=self.check_blockchain)
        self.btn_check.grid(row=3, column=1, sticky="w", padx=10, pady=2)

        self.btn_balances = tk.Button(root, text="Show balances", command=self.show_balances)
        self.btn_balances.grid(row=4, column=1, sticky="w", padx=10, pady=2)

        # Initial display
        self.refresh_listbox()


    def refresh_listbox(self):
        self.listbox.delete(0, tk.END)
        for block in self.blockchain.chain:
            label = f"Block {block.index} - {time.strftime('%H:%M:%S', time.localtime(block.timestamp))}"
            self.listbox.insert(tk.END, label)
        if self.blockchain.chain:
            self.listbox.select_set(0)
            self.show_block_details(0)

    def show_block_details(self, index: int):
        if index < 0 or index >= len(self.blockchain.chain):
            return
        block = self.blockchain.chain[index]

        self.details_text.delete("1.0", tk.END)
        self.details_text.insert(tk.END, f"Block {block.index}\n")
        self.details_text.insert(tk.END, f"Timestamp     : {time.ctime(block.timestamp)}\n")

        # If data is a transaction dict, show it nicely
        if isinstance(block.data, dict):
            frm = block.data.get("from")
            to = block.data.get("to")
            amount = block.data.get("amount")
            self.details_text.insert(tk.END, f"Data (raw)    : {block.data}\n")
            self.details_text.insert(tk.END, f"From          : {frm}\n")
            self.details_text.insert(tk.END, f"To            : {to}\n")
            self.details_text.insert(tk.END, f"Amount        : {amount} Coins\n")
        else:
            self.details_text.insert(tk.END, f"Data          : {block.data}\n")

        self.details_text.insert(tk.END, f"Previous hash : {block.previous_hash}\n")
        self.details_text.insert(tk.END, f"Hash          : {block.hash}\n")
        self.details_text.insert(tk.END, f"Nonce         : {block.nonce}\n")


    def on_select_block(self, event):
        selection = self.listbox.curselection()
        if selection:
            index = selection[0]
            self.show_block_details(index)

    def add_block_dialog(self):
        # Ask for transaction fields
        sender = simpledialog.askstring("New transaction", "Sender address (from):")
        if sender is None or sender.strip() == "":
            return

        receiver = simpledialog.askstring("New transaction", "Receiver address (to):")
        if receiver is None or receiver.strip() == "":
            return

        amount_str = simpledialog.askstring("New transaction", "Amount (coins):")
        if amount_str is None or amount_str.strip() == "":
            return
        try:
            amount = float(amount_str)
        except ValueError:
            messagebox.showerror("Error", "Amount must be a number.")
            return

        tx = {
            "from": sender.strip(),
            "to": receiver.strip(),
            "amount": amount,
        }

        # Mine and add block
        self.root.config(cursor="watch")
        self.root.update_idletasks()
        new_block = self.blockchain.add_block(tx)
        self.root.config(cursor="")

        self.refresh_listbox()
        self.listbox.select_set(new_block.index)
        self.show_block_details(new_block.index)


    def tamper_block(self):
        # Tamper with block 1 if it exists (not genesis)
        if len(self.blockchain.chain) < 2:
            messagebox.showinfo("Tampering", "No block to tamper (need at least 2 blocks).")
            return

        block = self.blockchain.chain[1]

        # Change the transaction data without updating hash
        if isinstance(block.data, dict):
            block.data = {
                "from": "Attacker",
                "to": block.data.get("to", "Bob"),
                "amount": 1000.0,
            }
        else:
            block.data = "Tampered transaction: attacker stole coins"

        messagebox.showwarning(
            "Tampering",
            "Block 1 transaction has been modified without updating its hash."
        )
        self.show_block_details(1)


    def check_blockchain(self):
        valid, statuses = self._validate_chain_for_summary()

        if valid:
            messagebox.showinfo("Blockchain check", "Blockchain is valid.")
        else:
            messagebox.showerror(
                "Blockchain check",
                "Blockchain is NOT valid.\nSee summary window for details."
            )

        # Ouvre une fenetre graphique de resume
        self._show_summary_window(statuses, valid)

    def _validate_chain_for_summary(self):
        """
        Valide la blockchain et retourne :
          - valid_chain : bool global
          - statuses : liste de tuples (block, ok, issues)
            ok = True/False, issues = liste de strings
        """
        difficulty = self.blockchain.difficulty
        prefix = "0" * difficulty

        statuses = []
        valid_chain = True
        prefix_is_valid = True  # prefixe de chaine valide jusqu'au bloc precedent

        for i, block in enumerate(self.blockchain.chain):
            issues = []

            # Verification du hash lui-meme
            if block.hash != block.compute_hash():
                issues.append("hash mismatch")

            # Verification de la preuve de travail
            if not block.hash.startswith(prefix):
                issues.append("invalid proof-of-work")

            # Verification du chaînage avec le bloc precedent
            if i > 0:
                prev = self.blockchain.chain[i - 1]
                if block.previous_hash != prev.hash:
                    issues.append("previous_hash != hash(prev)")

            # Si un bloc precedent est deja invalide, celui-ci est forcement suspect
            if not prefix_is_valid:
                issues.append("ancestor invalid")

            ok = (len(issues) == 0)

            if not ok:
                valid_chain = False
                prefix_is_valid = False  # a partir de maintenant tous les blocs suivants sont suspects

            statuses.append((block, ok, issues))

        return valid_chain, statuses


    def _show_summary_window(self, statuses, global_valid):
        """
        Affiche une fenetre avec :
          - un schema des blocs sur un Canvas
          - un resume texte des transactions et erreurs
        """
        win = tk.Toplevel(self.root)
        win.title("Blockchain summary")

        # Canvas pour les blocs
        canvas = tk.Canvas(win, width=900, height=200, bg="white")
        canvas.pack(side="top", fill="both", expand=True, padx=10, pady=10)

        n = len(statuses)
        if n == 0:
            return

        block_width = 150
        block_height = 70
        h_margin = 40
        start_x = 20

        for i, (block, ok, issues) in enumerate(statuses):
            x0 = start_x + i * (block_width + h_margin)
            y0 = 20
            x1 = x0 + block_width
            y1 = y0 + block_height

            # Nombre de confirmations
            conf = self.blockchain.get_confirmations(block.index)

            # Couleur selon etat / confirmations
            if not ok:
                color = "#ffb0b0"      # rouge : bloc invalide
            else:
                if conf >= 3:
                    color = "#b0ffb0"  # vert : valide et bien confirme
                else:
                    color = "#fff0b0"  # jaune : valide mais peu de confirmations

            canvas.create_rectangle(x0, y0, x1, y1, fill=color, outline="black")

            canvas.create_text(
                (x0 + x1) // 2,
                y0 + 15,
                text=f"Block {block.index}",
                font=("Arial", 10, "bold")
            )
            canvas.create_text(
                (x0 + x1) // 2,
                y0 + 35,
                text=time.strftime("%H:%M:%S", time.localtime(block.timestamp)),
                font=("Arial", 8)
            )

            status_txt = "OK" if ok else "ERROR"
            canvas.create_text(
                (x0 + x1) // 2,
                y0 + 50,
                text=f"{status_txt} / {conf} conf",
                font=("Arial", 9)
            )

            # Fleche depuis le bloc precedent
            if i > 0:
                canvas.create_line(
                    x0 - 20,
                    y0 + block_height // 2,
                    x0,
                    y0 + block_height // 2,
                    arrow=tk.LAST
                )


        # Zone texte pour les transactions / erreurs
        txt = tk.Text(win, height=10)
        txt.pack(side="bottom", fill="both", expand=True, padx=10, pady=(0, 10))

        txt.insert(tk.END, f"Global chain status: {'VALID' if global_valid else 'INVALID'}\n\n")

        for block, ok, issues in statuses:
            txt.insert(tk.END, f"Block {block.index} - {'OK' if ok else 'ERROR'}\n")

            # Si c'est une transaction
            if isinstance(block.data, dict):
                frm = block.data.get("from")
                to = block.data.get("to")
                amount = block.data.get("amount")
                txt.insert(tk.END, f"  Tx: {frm} -> {to} : {amount} Coins\n")
            else:
                txt.insert(tk.END, f"  Data: {block.data}\n")

            if issues:
                txt.insert(tk.END, "  Issues: " + ", ".join(issues) + "\n")

            txt.insert(tk.END, "\n")

        txt.config(state="disabled")


    def show_block_details(self, index: int):
        if index < 0 or index >= len(self.blockchain.chain):
            return
        block = self.blockchain.chain[index]

        self.details_text.delete("1.0", tk.END)
        self.details_text.insert(tk.END, f"Block {block.index}\n")
        self.details_text.insert(tk.END, f"Timestamp     : {time.ctime(block.timestamp)}\n")

        # Affichage des donnees
        if isinstance(block.data, dict):
            frm = block.data.get("from")
            to = block.data.get("to")
            amount = block.data.get("amount")
            self.details_text.insert(tk.END, f"Data (raw)    : {block.data}\n")
            self.details_text.insert(tk.END, f"From          : {frm}\n")
            self.details_text.insert(tk.END, f"To            : {to}\n")
            self.details_text.insert(tk.END, f"Amount        : {amount} Coins\n")
        else:
            self.details_text.insert(tk.END, f"Data          : {block.data}\n")

        # <<< NOUVEAU : confirmations >>>
        conf = self.blockchain.get_confirmations(index)
        self.details_text.insert(tk.END, f"Confirmations : {conf}\n")

        self.details_text.insert(tk.END, f"Previous hash : {block.previous_hash}\n")
        self.details_text.insert(tk.END, f"Hash          : {block.hash}\n")
        self.details_text.insert(tk.END, f"Nonce         : {block.nonce}\n")



    def show_balances(self):
        balances = {}

        # Skip genesis block (index 0)
        for block in self.blockchain.chain[1:]:
            if not isinstance(block.data, dict):
                continue
            sender = block.data.get("from")
            receiver = block.data.get("to")
            amount = block.data.get("amount", 0)

            # Check amount type
            try:
                amount = float(amount)
            except (TypeError, ValueError):
                continue

            if sender:
                balances[sender] = balances.get(sender, 0.0) - amount
            if receiver:
                balances[receiver] = balances.get(receiver, 0.0) + amount

        if not balances:
            messagebox.showinfo("Balances", "No transactions yet.")
            return

        lines = []
        for name, bal in balances.items():
            lines.append(f"{name}: {bal:.2f} Coins")

        messagebox.showinfo("Balances", "\n".join(lines))


if __name__ == "__main__":
    root = tk.Tk()
    app = BlockchainApp(root)
    root.mainloop()

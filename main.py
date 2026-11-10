"""
Mobile Wallet Fraud Detection & Prevention System - Main Entry Point.
Supports both Interactive Command Line Interface (CLI) and Desktop GUI.
"""
import argparse
import sys
from pathlib import Path
from typing import Optional

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.admin import AdminService
from app.auth import AuthService
from app.config import Config
from app.db import Database
from app.fraud_engine import FraudEngine
from app.simulator import FraudSimulator
from app.wallet import WalletService

# Text styling helpers
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    banner = f"""{CYAN}
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║       🛡️  MOBILE WALLET FRAUD DETECTION & DEFENSE SHIELD  🛡️      ║
║            Real-time Behavioral Analytics & Fraud Lab             ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)


class MobileWalletCLI:
    def __init__(self):
        self.db = Database()
        self.auth = AuthService(self.db)
        self.fraud = FraudEngine(self.db)
        self.wallet_service = WalletService(self.db, self.fraud)
        self.admin = AdminService(self.db)
        self.simulator = FraudSimulator(self.db)
        self.active_user = None
        self.active_wallet = None

        # Default to Alice for convenience
        self._set_active_user("alice")

    def _set_active_user(self, username: str):
        user = self.db.fetch_one("SELECT * FROM users WHERE username = ?", (username,))
        if user:
            self.active_user = user
            self.active_wallet = self.db.fetch_one("SELECT * FROM wallets WHERE user_id = ?", (user["id"],))

    def run(self):
        while True:
            u_name = self.active_user["username"] if self.active_user else "None"
            bal = f"${self.active_wallet['balance']:,.2f}" if self.active_wallet else "$0.00"
            status = self.active_wallet["status"].upper() if self.active_wallet else "-"

            status_colored = f"{GREEN}{status}{RESET}" if status == "ACTIVE" else f"{RED}{status}{RESET}"

            print("\n" + "=" * 65)
            print(f" Current User: {BOLD}{u_name}{RESET} | Balance: {BOLD}{GREEN}{bal}{RESET} | Wallet: {status_colored}")
            print("=" * 65)
            print(f" {BOLD}[1]{RESET} User Wallet Operations (Send Money, Deposit, Balance)")
            print(f" {BOLD}[2]{RESET} Switch Active User Account")
            print(f" {BOLD}[3]{RESET} Admin & Fraud Operations Center (Alerts, Metrics, Decisions)")
            print(f" {BOLD}[4]{RESET} Fraud Rules Configuration & Tuning")
            print(f" {BOLD}[5]{RESET} Fraud Attack Simulator Lab (ATO, Smurfing, Geo-speed)")
            print(f" {BOLD}[6]{RESET} Launch Modern Desktop GUI")
            print(f" {BOLD}[0]{RESET} Exit")
            print("-" * 65)

            choice = input(f"{BOLD}Select an option [0-6]: {RESET}").strip()

            if choice == "1":
                self._menu_wallet()
            elif choice == "2":
                self._menu_switch_user()
            elif choice == "3":
                self._menu_admin()
            elif choice == "4":
                self._menu_rules()
            elif choice == "5":
                self._menu_simulator()
            elif choice == "6":
                self.launch_gui()
            elif choice == "0":
                print(f"\n{CYAN}Exiting Mobile Wallet Fraud Detection System. Goodbye!{RESET}\n")
                break
            else:
                print(f"{RED}Invalid selection. Please choose a valid number.{RESET}")

    # -----------------------------------------------------------------
    # Menu 1: User Wallet Operations
    # -----------------------------------------------------------------
    def _menu_wallet(self):
        while True:
            # Refresh wallet
            self.active_wallet = self.wallet_service.get_wallet_by_id(self.active_wallet["id"])
            print(f"\n--- {BOLD}WALLET TERMINAL ({self.active_user['username'].upper()}){RESET} ---")
            print(f"Wallet Number: {self.active_wallet['wallet_number']}")
            print(f"Balance:       ${self.active_wallet['balance']:,.2f}")
            print(f"Status:        {self.active_wallet['status']}")
            print("-" * 45)
            print(" [1] Deposit Funds")
            print(" [2] Send Money (P2P Transfer)")
            print(" [3] Withdraw Funds")
            print(" [4] View Transaction Statement")
            print(" [0] Back to Main Menu")

            ch = input("Enter choice: ").strip()
            if ch == "1":
                try:
                    amt = float(input("Deposit Amount ($): ").strip())
                    res = self.wallet_service.deposit(self.active_wallet["id"], amt, "CLI Top-up")
                    if res["success"]:
                        print(f"{GREEN}✔ {res['message']} New balance: ${res['new_balance']:,.2f}{RESET}")
                    else:
                        print(f"{RED}✘ {res['message']}{RESET}")
                except ValueError:
                    print(f"{RED}Invalid number.{RESET}")

            elif ch == "2":
                dest_wallet = input("Recipient Wallet Number (e.g. MW-1000000002): ").strip()
                try:
                    amt = float(input("Amount ($): ").strip())
                except ValueError:
                    print(f"{RED}Invalid amount.{RESET}")
                    continue

                city = input("Your City/Location (press enter for New York): ").strip() or "New York"
                note = input("Transfer Note: ").strip() or "CLI P2P Transfer"

                print(f"{YELLOW}⏳ Submitting transaction to Real-time Fraud Engine...{RESET}")
                res = self.wallet_service.transfer(
                    sender_wallet_id=self.active_wallet["id"],
                    receiver_wallet_number=dest_wallet,
                    amount=amt,
                    location={"city": city, "country": "US", "lat": 40.7128, "lon": -74.0060, "ip": "127.0.0.1"},
                    device_fingerprint=f"cli-session-{self.active_user['username']}",
                    notes=note
                )

                ev = res.get("evaluation", {})
                score = ev.get("risk_score", 0.0)
                level = ev.get("risk_level", "LOW")

                if res["success"]:
                    print(f"{GREEN}✔ [APPROVED] {res['message']}{RESET}")
                    print(f"  Risk Score: {score}/100 ({level})")
                elif res["status"] == "PENDING_REVIEW":
                    print(f"{YELLOW}⚠ [PENDING REVIEW] {res['message']}{RESET}")
                    print(f"  Risk Score: {score}/100 ({level})")
                    print(f"  Rules: {[r['name'] for r in ev.get('flagged_rules', [])]}")
                else:
                    print(f"{RED}✘ [BLOCKED] {res['message']}{RESET}")
                    print(f"  Risk Score: {score}/100 ({level})")
                    print(f"  Triggered Violations: {[r['name'] for r in ev.get('flagged_rules', [])]}")

            elif ch == "3":
                try:
                    amt = float(input("Withdrawal Amount ($): ").strip())
                    res = self.wallet_service.withdraw(self.active_wallet["id"], amt)
                    if res["success"]:
                        print(f"{GREEN}✔ {res['message']}{RESET}")
                    else:
                        print(f"{RED}✘ {res['message']}{RESET}")
                except ValueError:
                    print(f"{RED}Invalid amount.{RESET}")

            elif ch == "4":
                txs = self.wallet_service.get_transaction_history(self.active_wallet["id"], limit=15)
                print("\n" + "-" * 85)
                print(f"{'TX UUID':<14} {'TYPE':<10} {'AMOUNT':<10} {'STATUS':<15} {'RISK':<8} {'TIMESTAMP'}")
                print("-" * 85)
                for tx in txs:
                    st_col = GREEN if tx["status"] == "COMPLETED" else (YELLOW if tx["status"] == "PENDING_REVIEW" else RED)
                    print(f"{tx['transaction_uuid'][:12]:<14} {tx['transaction_type']:<10} ${tx['amount']:<9.2f} {st_col}{tx['status']:<15}{RESET} {tx['risk_score']:<8.1f} {tx['timestamp']}")
                print("-" * 85)

            elif ch == "0":
                break

    # -----------------------------------------------------------------
    # Menu 2: Switch User
    # -----------------------------------------------------------------
    def _menu_switch_user(self):
        users = self.admin.list_all_users()
        print("\nAvailable User Accounts:")
        for idx, u in enumerate(users, 1):
            locked = f"{RED}[LOCKED]{RESET}" if u["is_locked"] else ""
            print(f" [{idx}] @{u['username']} ({u['full_name']}) - Balance: ${u['balance']:,.2f} {locked}")
        
        sel = input("Select user number or enter username: ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(users):
            self._set_active_user(users[int(sel)-1]["username"])
        else:
            self._set_active_user(sel)
        print(f"{GREEN}Switched to user: {self.active_user['username']}{RESET}")

    # -----------------------------------------------------------------
    # Menu 3: Admin & Fraud Operations Center
    # -----------------------------------------------------------------
    def _menu_admin(self):
        while True:
            m = self.admin.get_dashboard_metrics()
            print(f"\n--- {BOLD}FRAUD MONITORING & COMPLIANCE CENTER{RESET} ---")
            print(f"Total Transactions: {BOLD}{m['total_transactions']}{RESET} | Volume: {BOLD}${m['total_volume']:,.2f}{RESET}")
            print(f"Approved: {GREEN}{m['approved_count']}{RESET} | Held for Review: {YELLOW}{m['review_count']}{RESET} | Blocked: {RED}{m['blocked_count']}{RESET}")
            print(f"System Fraud Rate: {BOLD}{m['fraud_rate_percent']:.2f}%{RESET} | Open Fraud Alerts: {BOLD}{m['open_alerts_count']}{RESET}")
            print("-" * 55)
            print(" [1] View Incident Alerts Queue")
            print(" [2] Adjudicate / Review Fraud Alert (Approve/Block/Dismiss)")
            print(" [3] Manage Blacklist (Wallets, IPs, Devices)")
            print(" [4] Account Freeze / Unfreeze Management")
            print(" [0] Return to Main Menu")

            ch = input("Enter choice: ").strip()
            if ch == "1":
                alerts = self.admin.get_alerts(limit=20)
                print("\n" + "-" * 90)
                print(f"{'ID':<5} {'USER':<12} {'WALLET':<14} {'AMOUNT':<10} {'SCORE':<7} {'ALERT TYPE':<22} {'STATUS'}")
                print("-" * 90)
                for a in alerts:
                    amt_str = f"${a['amount']:,.2f}" if a.get("amount") is not None else "-"
                    st_col = YELLOW if a["status"] == "OPEN" else (RED if a["status"] == "CONFIRMED_FRAUD" else GREEN)
                    print(f"{a['id']:<5} {str(a.get('username') or ''):<12} {str(a.get('wallet_number') or ''):<14} {amt_str:<10} {a['risk_score']:<7.1f} {a['alert_type']:<22} {st_col}{a['status']}{RESET}")
                print("-" * 90)

            elif ch == "2":
                try:
                    aid = int(input("Enter Alert ID to adjudicate: ").strip())
                    print("Actions:")
                    print("  [1] Approve & Release Held Funds")
                    print("  [2] Confirm Fraud & Freeze Account")
                    print("  [3] Dismiss (False Alarm)")
                    act_num = input("Choose action [1-3]: ").strip()
                    note = input("Analyst Justification / Notes: ").strip() or "CLI Adjudication"

                    action_map = {"1": "APPROVE_RELEASE", "2": "CONFIRM_FRAUD_BLOCK", "3": "DISMISS"}
                    if act_num in action_map:
                        res = self.admin.review_alert(aid, action_map[act_num], note, self.active_user["id"])
                        print(f"{GREEN if res['success'] else RED}{res['message']}{RESET}")
                    else:
                        print(f"{RED}Invalid action choice.{RESET}")
                except ValueError:
                    print(f"{RED}Invalid Alert ID.{RESET}")

            elif ch == "3":
                self._menu_blacklist()

            elif ch == "4":
                wid = int(input("Enter Wallet ID to toggle freeze: ").strip())
                w = self.wallet_service.get_wallet_by_id(wid)
                if w:
                    if w["status"] == "frozen":
                        self.admin.unfreeze_wallet(wid, self.active_user["id"])
                        print(f"{GREEN}Wallet {wid} un-frozen.{RESET}")
                    else:
                        self.admin.freeze_wallet(wid, self.active_user["id"], "CLI Admin Manual Freeze")
                        print(f"{RED}Wallet {wid} is now FROZEN.{RESET}")
                else:
                    print(f"{RED}Wallet not found.{RESET}")

            elif ch == "0":
                break

    def _menu_blacklist(self):
        bl_items = self.admin.list_blacklist()
        print("\n--- Current Blacklist Entries ---")
        for b in bl_items:
            print(f"  #{b['id']} [{b['entity_type']}] {b['entity_value']} | Reason: {b['reason']}")
        print("\n [1] Add New Blacklist Entity")
        print(" [2] Remove Entity by ID")
        print(" [0] Back")
        b_ch = input("Choice: ").strip()
        if b_ch == "1":
            etype = input("Entity Type (WALLET, IP, USER, DEVICE): ").strip().upper()
            evalue = input("Entity Value (e.g. 192.168.1.100 or MW-9999999999): ").strip()
            reason = input("Reason: ").strip() or "Fraud suspect"
            res = self.admin.add_to_blacklist(etype, evalue, reason)
            print(f"{GREEN if res['success'] else RED}{res['message']}{RESET}")
        elif b_ch == "2":
            bid = int(input("Enter ID to delete: ").strip())
            self.admin.remove_from_blacklist(bid)
            print(f"{GREEN}Removed from blacklist.{RESET}")

    # -----------------------------------------------------------------
    # Menu 4: Fraud Rules Configuration
    # -----------------------------------------------------------------
    def _menu_rules(self):
        while True:
            rules = self.admin.get_rules()
            print(f"\n--- {BOLD}FRAUD DETECTION RULES ENGINE CONFIGURATION{RESET} ---")
            print(f"{'CODE':<24} {'WEIGHT':<8} {'ACTION':<10} {'ACTIVE':<8} {'NAME'}")
            print("-" * 75)
            for r in rules:
                active_str = f"{GREEN}YES{RESET}" if r["is_enabled"] else f"{RED}NO{RESET}"
                print(f"{r['rule_code']:<24} {r['weight']:<8.1f} {r['action_if_triggered']:<10} {active_str:<17} {r['name']}")
            print("-" * 75)
            print(" [1] Modify Rule Weight / Enforcement")
            print(" [2] Enable / Disable Rule")
            print(" [0] Back")

            ch = input("Enter choice: ").strip()
            if ch == "1":
                rcode = input("Enter Rule Code: ").strip()
                try:
                    w = float(input("New Weight (0-100): ").strip())
                    act = input("Action (FLAG, REVIEW, BLOCK): ").strip().upper()
                    res = self.admin.update_rule(rcode, weight=w, action=act)
                    print(f"{GREEN if res['success'] else RED}{res['message']}{RESET}")
                except ValueError:
                    print(f"{RED}Invalid input.{RESET}")
            elif ch == "2":
                rcode = input("Enter Rule Code to toggle: ").strip()
                r = self.db.fetch_one("SELECT is_enabled FROM rules_config WHERE rule_code = ?", (rcode,))
                if r:
                    new_val = 0 if r["is_enabled"] else 1
                    self.admin.update_rule(rcode, is_enabled=new_val)
                    print(f"{GREEN}Rule {rcode} is now {'ENABLED' if new_val else 'DISABLED'}.{RESET}")
            elif ch == "0":
                break

    # -----------------------------------------------------------------
    # Menu 5: Attack Simulator Lab
    # -----------------------------------------------------------------
    def _menu_simulator(self):
        while True:
            print(f"\n--- {BOLD}FRAUD ATTACK SIMULATOR LAB{RESET} ---")
            print(" [1] ⚡ Legitimate P2P Everyday Transfer")
            print(" [2] 🚨 Account Takeover (ATO) & Rapid Balance Drain (92%)")
            print(" [3] ⚡ Velocity Burst Attack (5 transfers in milliseconds)")
            print(" [4] 🤖 Micro-Transaction Bot Probing (< $2.50)")
            print(" [5] ✈️ Impossible Travel (New York to London in 15 mins)")
            print(" [6] 💼 AML Structuring / Smurfing ($9,850.00)")
            print(" [7] 🛑 Blacklist Hit Attempt (Target: Flagged Mule)")
            print(" [8] 🎲 Run Automated Mixed Batch Simulation (15 Transactions)")
            print(" [0] Back")

            ch = input(f"{BOLD}Choose attack scenario [0-8]: {RESET}").strip()
            if ch == "1":
                res = self.simulator.run_normal_transaction()
                print(f"\n{GREEN}✔ Normal Transaction Passed:{RESET}")
                print(f"  Result: {res['result']['status']} | Score: {res['result']['evaluation']['risk_score']} | {res['result']['message']}")
            elif ch == "2":
                res = self.simulator.run_account_takeover_attack()
                print(f"\n{RED}🚨 Account Takeover Evaluated:{RESET}")
                print(f"  Result: {res['result']['status']} | Score: {res['result']['evaluation']['risk_score']} | {res['result']['message']}")
            elif ch == "3":
                results = self.simulator.run_velocity_burst_attack(5)
                print(f"\n{YELLOW}⚡ Velocity Burst Attack Results:{RESET}")
                for r in results:
                    st_col = GREEN if r["status"] == "COMPLETED" else RED
                    print(f"  #{r['iteration']}: {st_col}{r['status']}{RESET} (Score: {r['risk_score']}) -> {r['message']}")
            elif ch == "4":
                results = self.simulator.run_micro_transaction_probing(4)
                print(f"\n{YELLOW}🤖 Micro-Transaction Probing Results:{RESET}")
                for r in results:
                    st_col = GREEN if r["status"] == "COMPLETED" else RED
                    print(f"  #{r['iteration']} (${r['amount']}): {st_col}{r['status']}{RESET} (Score: {r['risk_score']}) -> {r['message']}")
            elif ch == "5":
                res = self.simulator.run_impossible_travel_attack()
                print(f"\n{RED}✈️ Impossible Travel Attack Results:{RESET}")
                print(f"  Origin: {res['origin']} -> Destination: {res['destination']}")
                print(f"  Result: {res['result']['status']} | Score: {res['result']['evaluation']['risk_score']} | {res['result']['message']}")
            elif ch == "6":
                res = self.simulator.run_structuring_attack()
                print(f"\n{YELLOW}💼 AML Structuring Results:{RESET}")
                print(f"  Result: {res['result']['status']} | Score: {res['result']['evaluation']['risk_score']} | {res['result']['message']}")
            elif ch == "7":
                res = self.simulator.run_blacklist_attack()
                print(f"\n{RED}🛑 Blacklist Hit Results:{RESET}")
                print(f"  Result: {res['result']['status']} | Score: {res['result']['evaluation']['risk_score']} | {res['result']['message']}")
            elif ch == "8":
                print(f"\n{CYAN}🎲 Running mixed batch simulation of 15 transactions...{RESET}")
                def on_tx(idx, total, entry):
                    sc = entry.get("scenario", "Tx")
                    res = entry.get("result", {})
                    st = res.get("status", "UNKNOWN")
                    sc_col = GREEN if st == "COMPLETED" else (YELLOW if st == "PENDING_REVIEW" else RED)
                    print(f"  [{idx:02d}/{total:02d}] {sc:<35} -> {sc_col}{st:<15}{RESET} (Risk Score: {res.get('evaluation', {}).get('risk_score', 0):.1f})")
                self.simulator.run_batch_simulation(15, 0.4, on_tx)
                print(f"{GREEN}✔ Batch simulation complete. Check Admin Center for alerts!{RESET}")
            elif ch == "0":
                break

    def launch_gui(self):
        print(f"{CYAN}Starting Desktop GUI...{RESET}")
        from gui import launch_gui
        launch_gui()


def main():
    parser = argparse.ArgumentParser(description="Mobile Wallet Fraud Detection & Defense System (Desktop Base)")
    parser.add_argument("--cli", action="store_true", help="Launch interactive Command Line Interface (CLI) instead of Desktop GUI")
    parser.add_argument("--gui", action="store_true", help="Explicitly launch Desktop GUI (default)")
    args = parser.parse_args()

    if args.cli:
        print_banner()
        cli = MobileWalletCLI()
        cli.run()
    else:
        # Default behavior: Launch Desktop GUI
        print_banner()
        print(f"{CYAN}Starting Desktop GUI application...{RESET}")
        from gui import launch_gui
        launch_gui()


if __name__ == "__main__":
    main()

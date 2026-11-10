"""
Desktop Graphical User Interface (GUI) for Mobile Wallet Fraud Detection.
Built with Tkinter & TTK (Zero external GUI dependencies, native Windows desktop app).
Features multi-tab workstation:
  1. 📱 User Mobile Wallet (P2P Transfers, Deposits, Real-time Risk Gauge)
  2. 🚨 Fraud Center & Alerts (Incident Queue, Review & Adjudication, Blacklist)
  3. ⚙️ Fraud Rules Engine (Live Dynamic Tuning, Weights, Policy Actions)
  4. 🧪 Attack Simulator Lab (One-Click Scenarios, Bot Probing, Event Stream)
  5. 📊 Forensic Reports & SQL Analytics (Smurfing Scans, Velocity Spikes, Audit)
"""
import json
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.admin import AdminService
from app.auth import AuthService
from app.config import Config
from app.db import Database
from app.fraud_engine import FraudEngine
from app.simulator import FraudSimulator
from app.wallet import WalletService


class MobileWalletFraudApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mobile Wallet Fraud Detection & Defense Workstation [Desktop Edition]")
        self.geometry("1240x800")
        self.minsize(1020, 680)

        # Core Services
        self.db = Database()
        self.auth_service = AuthService(self.db)
        self.fraud_engine = FraudEngine(self.db)
        self.wallet_service = WalletService(self.db, self.fraud_engine)
        self.admin_service = AdminService(self.db)
        self.simulator = FraudSimulator(self.db)

        # Active Session State
        self.current_user = None
        self.current_wallet = None

        self._configure_styles()
        self._create_header()
        self._create_tabs()
        self._create_status_bar()

        # Default Active Account
        self._set_active_user("alice")
        self._refresh_all_views()

    def _configure_styles(self):
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # Color Palette
        self.c_bg_dark = "#0F172A"       # Slate 900
        self.c_header_bg = "#1E293B"     # Slate 800
        self.c_primary = "#2563EB"       # Blue 600
        self.c_primary_hover = "#1D4ED8"
        self.c_success = "#16A34A"       # Green 600
        self.c_warning = "#D97706"       # Amber 600
        self.c_danger = "#DC2626"        # Red 600
        self.c_card_bg = "#F8FAFC"

        self.style.configure(".", font=("Segoe UI", 9))
        self.style.configure("Header.TFrame", background=self.c_header_bg)
        self.style.configure("HeaderTitle.TLabel", background=self.c_header_bg, foreground="#F8FAFC", font=("Segoe UI", 16, "bold"))
        self.style.configure("HeaderSub.TLabel", background=self.c_header_bg, foreground="#94A3B8", font=("Segoe UI", 9))
        self.style.configure("HeaderBadge.TLabel", background="#334155", foreground="#38BDF8", font=("Segoe UI", 8, "bold"), padding=4)
        
        self.style.configure("Card.TFrame", background=self.c_card_bg, relief="groove")
        self.style.configure("CardTitle.TLabel", font=("Segoe UI", 11, "bold"), foreground="#0F172A")
        self.style.configure("MetricValue.TLabel", font=("Segoe UI", 18, "bold"), foreground="#1E293B")
        self.style.configure("MetricLabel.TLabel", font=("Segoe UI", 9), foreground="#64748B")

        # Treeview styling
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), background="#E2E8F0")
        self.style.configure("Treeview", rowheight=25)

    def _create_header(self):
        header_frame = ttk.Frame(self, style="Header.TFrame", padding=(16, 12))
        header_frame.pack(fill="x", side="top")

        left_box = ttk.Frame(header_frame, style="Header.TFrame")
        left_box.pack(side="left")

        title_row = ttk.Frame(left_box, style="Header.TFrame")
        title_row.pack(anchor="w")
        ttk.Label(title_row, text="🛡️ Mobile Wallet Fraud Shield", style="HeaderTitle.TLabel").pack(side="left")
        ttk.Label(title_row, text=" DESKTOP WORKSTATION ", style="HeaderBadge.TLabel").pack(side="left", padx=10)

        ttk.Label(
            left_box, 
            text="Real-time Behavioral Analytics, Velocity Scoring, Geo-speed & Forensic Engine", 
            style="HeaderSub.TLabel"
        ).pack(anchor="w", pady=(2, 0))

        right_box = ttk.Frame(header_frame, style="Header.TFrame")
        right_box.pack(side="right")

        ttk.Label(right_box, text="Current Wallet User: ", style="HeaderSub.TLabel").pack(side="left", padx=5)
        self.user_switcher_var = tk.StringVar(value="alice")
        user_menu = ttk.Combobox(
            right_box, 
            textvariable=self.user_switcher_var, 
            values=["alice", "bob", "charlie", "mule_account", "admin"],
            width=15, 
            state="readonly"
        )
        user_menu.pack(side="left", padx=5)
        user_menu.bind("<<ComboboxSelected>>", lambda e: self._on_user_switched())

        refresh_btn = ttk.Button(right_box, text="🔄 Refresh Data", command=self._refresh_all_views)
        refresh_btn.pack(side="left", padx=8)

    def _create_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=6)

        # Tab 1: User Mobile Wallet
        self.tab_wallet = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_wallet, text=" 📱 User Mobile Wallet ")
        self._init_wallet_tab()

        # Tab 2: Fraud Operations & Alerts
        self.tab_admin = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_admin, text=" 🚨 Fraud Center & Alerts ")
        self._init_admin_tab()

        # Tab 3: Dynamic Fraud Rules Config
        self.tab_rules = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_rules, text=" ⚙️ Fraud Rules Engine ")
        self._init_rules_tab()

        # Tab 4: Fraud Attack Simulator Lab
        self.tab_sim = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sim, text=" 🧪 Attack Simulator Lab ")
        self._init_simulator_tab()

        # Tab 5: Forensic Reports & SQL Analytics
        self.tab_reports = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_reports, text=" 📊 Forensic Reports & Analytics ")
        self._init_reports_tab()

    def _create_status_bar(self):
        status_bar = ttk.Frame(self, relief="groove", padding=(12, 4))
        status_bar.pack(fill="x", side="bottom")

        self.lbl_status_left = ttk.Label(
            status_bar, 
            text="🟢 Engine Active | DB: SQLite Embedded | Rules: 11 Active | Auto-Freeze: ON",
            font=("Segoe UI", 8),
            foreground="#475569"
        )
        self.lbl_status_left.pack(side="left")

        self.lbl_status_right = ttk.Label(
            status_bar,
            text=f"Database: {Config.SQLITE_PATH}",
            font=("Segoe UI", 8),
            foreground="#64748B"
        )
        self.lbl_status_right.pack(side="right")

    # =========================================================================
    # Visual Risk Meter Canvas Helper
    # =========================================================================
    def _draw_risk_meter(self, canvas: tk.Canvas, score: float, level: str):
        """Draw a visual risk gauge bar on a tkinter canvas."""
        canvas.delete("all")
        w = canvas.winfo_width() or 300
        h = canvas.winfo_height() or 40

        # Background track
        bar_y1 = 12
        bar_y2 = 26
        margin_x = 10
        usable_w = w - (margin_x * 2)

        # Draw 3 color zones: Green (0-35), Yellow (35-70), Red (70-100)
        x_low = margin_x + (usable_w * 0.35)
        x_med = margin_x + (usable_w * 0.70)
        x_high = margin_x + usable_w

        canvas.create_rectangle(margin_x, bar_y1, x_low, bar_y2, fill="#86EFAC", outline="")
        canvas.create_rectangle(x_low, bar_y1, x_med, bar_y2, fill="#FDE047", outline="")
        canvas.create_rectangle(x_med, bar_y1, x_high, bar_y2, fill="#FCA5A5", outline="")

        # Indicator marker for current score
        clamped_score = max(0.0, min(100.0, score))
        marker_x = margin_x + (usable_w * (clamped_score / 100.0))

        # Color based on level
        if score < 35:
            m_col = "#15803D"
        elif score < 70:
            m_col = "#B45309"
        else:
            m_col = "#B91C1C"

        canvas.create_polygon(
            marker_x, bar_y2 + 8,
            marker_x - 6, bar_y2 + 1,
            marker_x + 6, bar_y2 + 1,
            fill=m_col, outline=""
        )
        canvas.create_line(marker_x, bar_y1 - 2, marker_x, bar_y2 + 2, fill="#0F172A", width=2)

        # Text score
        canvas.create_text(
            w / 2, 34,
            text=f"Live Risk Score: {score:.1f}/100 [{level}]",
            font=("Segoe UI", 8, "bold"),
            fill=m_col
        )

    # =========================================================================
    # TAB 1: User Mobile Wallet
    # =========================================================================
    def _init_wallet_tab(self):
        pane = ttk.PanedWindow(self.tab_wallet, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=6, pady=6)

        # Left Column: Account Overview, Action Forms & Risk Meter
        left_frame = ttk.Frame(pane, width=390, padding=8)
        pane.add(left_frame, weight=1)

        # Account Overview Card
        info_card = ttk.LabelFrame(left_frame, text="Account Overview", padding=10)
        info_card.pack(fill="x", pady=4)

        self.lbl_wallet_user = ttk.Label(info_card, text="Account Holder: -", font=("Segoe UI", 10, "bold"))
        self.lbl_wallet_user.pack(anchor="w", pady=2)
        self.lbl_wallet_num = ttk.Label(info_card, text="Wallet Number: -", font=("Segoe UI", 9))
        self.lbl_wallet_num.pack(anchor="w", pady=2)
        self.lbl_wallet_status = ttk.Label(info_card, text="Status: Active", foreground=self.c_success, font=("Segoe UI", 9, "bold"))
        self.lbl_wallet_status.pack(anchor="w", pady=2)
        
        self.lbl_wallet_balance = ttk.Label(info_card, text="$0.00", font=("Segoe UI", 20, "bold"), foreground=self.c_primary)
        self.lbl_wallet_balance.pack(anchor="w", pady=4)

        # Live Risk Evaluation Meter Card
        meter_card = ttk.LabelFrame(left_frame, text="Real-Time Risk Scoring Gauge", padding=6)
        meter_card.pack(fill="x", pady=4)

        self.canvas_wallet_meter = tk.Canvas(meter_card, height=44, bg="#F8FAFC", highlightthickness=0)
        self.canvas_wallet_meter.pack(fill="x", expand=True)
        self.canvas_wallet_meter.bind("<Configure>", lambda e: self._draw_risk_meter(self.canvas_wallet_meter, 0.0, "LOW"))

        # Quick Deposit Frame
        dep_frame = ttk.LabelFrame(left_frame, text="Deposit Funds", padding=8)
        dep_frame.pack(fill="x", pady=4)
        
        ttk.Label(dep_frame, text="Amount ($):").grid(row=0, column=0, sticky="w", pady=4)
        self.entry_dep_amount = ttk.Entry(dep_frame, width=15)
        self.entry_dep_amount.grid(row=0, column=1, sticky="w", pady=4, padx=5)
        self.entry_dep_amount.insert(0, "150.00")

        btn_deposit = ttk.Button(dep_frame, text="Deposit Funds", command=self._handle_deposit)
        btn_deposit.grid(row=0, column=2, padx=5, pady=4)

        # Transfer Frame
        tx_frame = ttk.LabelFrame(left_frame, text="Send Money (P2P Transfer)", padding=8)
        tx_frame.pack(fill="x", pady=4)

        ttk.Label(tx_frame, text="Recipient Wallet:").grid(row=0, column=0, sticky="w", pady=2)
        self.entry_rec_wallet = ttk.Entry(tx_frame, width=22)
        self.entry_rec_wallet.grid(row=0, column=1, sticky="w", pady=2, padx=5)
        self.entry_rec_wallet.insert(0, "MW-1000000002")

        ttk.Label(tx_frame, text="Amount ($):").grid(row=1, column=0, sticky="w", pady=2)
        self.entry_tx_amount = ttk.Entry(tx_frame, width=22)
        self.entry_tx_amount.grid(row=1, column=1, sticky="w", pady=2, padx=5)
        self.entry_tx_amount.insert(0, "45.00")

        ttk.Label(tx_frame, text="Location / City:").grid(row=2, column=0, sticky="w", pady=2)
        self.entry_tx_city = ttk.Entry(tx_frame, width=22)
        self.entry_tx_city.grid(row=2, column=1, sticky="w", pady=2, padx=5)
        self.entry_tx_city.insert(0, "New York, US")

        ttk.Label(tx_frame, text="Device Fingerprint:").grid(row=3, column=0, sticky="w", pady=2)
        self.entry_tx_dev = ttk.Entry(tx_frame, width=22)
        self.entry_tx_dev.grid(row=3, column=1, sticky="w", pady=2, padx=5)
        self.entry_tx_dev.insert(0, "dev-session-trusted")

        ttk.Label(tx_frame, text="Description / Note:").grid(row=4, column=0, sticky="w", pady=2)
        self.entry_tx_note = ttk.Entry(tx_frame, width=22)
        self.entry_tx_note.grid(row=4, column=1, sticky="w", pady=2, padx=5)
        self.entry_tx_note.insert(0, "Dinner split")

        btn_send = ttk.Button(tx_frame, text="🚀 Transfer Funds Through Fraud Shield", command=self._handle_transfer)
        btn_send.grid(row=5, column=0, columnspan=2, pady=8)

        # Right Column: Transaction History
        right_frame = ttk.Frame(pane, padding=8)
        pane.add(right_frame, weight=3)

        top_r = ttk.Frame(right_frame)
        top_r.pack(fill="x", pady=(0, 4))
        ttk.Label(top_r, text="Transaction Activity Ledger (Double-click any row to inspect)", font=("Segoe UI", 10, "bold")).pack(side="left")

        columns = ("id", "uuid", "type", "counterparty", "amount", "score", "level", "status", "time")
        self.tree_tx = ttk.Treeview(right_frame, columns=columns, show="headings", height=20)
        self.tree_tx.heading("id", text="ID")
        self.tree_tx.heading("uuid", text="Tx UUID")
        self.tree_tx.heading("type", text="Type")
        self.tree_tx.heading("counterparty", text="Destination / Sender")
        self.tree_tx.heading("amount", text="Amount")
        self.tree_tx.heading("score", text="Risk Score")
        self.tree_tx.heading("level", text="Level")
        self.tree_tx.heading("status", text="Status")
        self.tree_tx.heading("time", text="Timestamp")

        self.tree_tx.column("id", width=45, anchor="center")
        self.tree_tx.column("uuid", width=125)
        self.tree_tx.column("type", width=75)
        self.tree_tx.column("counterparty", width=125)
        self.tree_tx.column("amount", width=85, anchor="e")
        self.tree_tx.column("score", width=75, anchor="center")
        self.tree_tx.column("level", width=75, anchor="center")
        self.tree_tx.column("status", width=105, anchor="center")
        self.tree_tx.column("time", width=135)

        self.tree_tx.tag_configure("COMPLETED", foreground="#16A34A")
        self.tree_tx.tag_configure("PENDING_REVIEW", foreground="#D97706")
        self.tree_tx.tag_configure("BLOCKED", foreground="#DC2626")

        scroll_tx = ttk.Scrollbar(right_frame, orient="vertical", command=self.tree_tx.yview)
        self.tree_tx.config(yscrollcommand=scroll_tx.set)

        self.tree_tx.pack(side="left", fill="both", expand=True)
        scroll_tx.pack(side="right", fill="y")

        # Double click to inspect transaction details
        self.tree_tx.bind("<Double-1>", self._inspect_selected_transaction)
        self.tree_tx.bind("<<TreeviewSelect>>", self._on_tx_selected)

    def _on_user_switched(self):
        uname = self.user_switcher_var.get()
        self._set_active_user(uname)
        self._refresh_wallet_view()

    def _set_active_user(self, username: str):
        user = self.db.fetch_one("SELECT * FROM users WHERE username = ?", (username,))
        if user:
            self.current_user = user
            self.current_wallet = self.db.fetch_one("SELECT * FROM wallets WHERE user_id = ?", (user["id"],))

    def _refresh_wallet_view(self):
        if not self.current_user or not self.current_wallet:
            return

        self.current_wallet = self.wallet_service.get_wallet_by_id(self.current_wallet["id"])
        
        self.lbl_wallet_user.config(text=f"Account Holder: {self.current_user['full_name']} (@{self.current_user['username']})")
        self.lbl_wallet_num.config(text=f"Wallet Number: {self.current_wallet['wallet_number']}")
        
        status = self.current_wallet["status"]
        if status == "frozen":
            self.lbl_wallet_status.config(text="Status: ❄️ FROZEN (Account Locked for Fraud)", foreground=self.c_danger)
        else:
            self.lbl_wallet_status.config(text="Status: ✅ Active (Verified)", foreground=self.c_success)

        self.lbl_wallet_balance.config(text=f"${self.current_wallet['balance']:,.2f}")

        # Refresh transaction table
        for item in self.tree_tx.get_children():
            self.tree_tx.delete(item)

        txs = self.wallet_service.get_transaction_history(self.current_wallet["id"], limit=50)
        for tx in txs:
            counter = tx["receiver_wallet"] if tx["sender_wallet_id"] == self.current_wallet["id"] else (tx["sender_wallet"] or "Cash Deposit")
            prefix = "-" if tx["sender_wallet_id"] == self.current_wallet["id"] else "+"
            amt_str = f"{prefix}${tx['amount']:,.2f}"
            status_tag = tx["status"]
            self.tree_tx.insert(
                "",
                "end",
                values=(
                    tx["id"],
                    tx["transaction_uuid"][:12] + "...",
                    tx["transaction_type"],
                    counter,
                    amt_str,
                    f"{tx['risk_score']:.1f}",
                    tx["risk_level"],
                    tx["status"],
                    tx["timestamp"]
                ),
                tags=(status_tag,)
            )

    def _on_tx_selected(self, event):
        selected = self.tree_tx.selection()
        if not selected:
            return
        vals = self.tree_tx.item(selected[0])["values"]
        try:
            score = float(vals[5])
            level = str(vals[6])
            self._draw_risk_meter(self.canvas_wallet_meter, score, level)
        except Exception:
            pass

    def _inspect_selected_transaction(self, event):
        selected = self.tree_tx.selection()
        if not selected:
            return
        tx_id = self.tree_tx.item(selected[0])["values"][0]
        tx = self.db.fetch_one("SELECT * FROM transactions WHERE id = ?", (tx_id,))
        if not tx:
            return

        # Modal inspector window
        dlg = tk.Toplevel(self)
        dlg.title(f"Forensic Transaction Inspector: {tx['transaction_uuid']}")
        dlg.geometry("640x520")
        dlg.minsize(550, 420)
        dlg.transient(self)
        dlg.grab_set()

        frame = ttk.Frame(dlg, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="🔍 Forensic Transaction Record", font=("Segoe UI", 12, "bold")).pack(anchor="w")

        info_box = tk.Text(frame, wrap="word", font=("Consolas", 9), relief="groove")
        info_box.pack(fill="both", expand=True, pady=8)

        flagged_rules_pretty = "None"
        if tx.get("flagged_rules"):
            try:
                parsed = json.loads(tx["flagged_rules"])
                flagged_rules_pretty = json.dumps(parsed, indent=2)
            except Exception:
                flagged_rules_pretty = str(tx["flagged_rules"])

        content = (
            f"Transaction ID:      {tx['id']}\n"
            f"Transaction UUID:    {tx['transaction_uuid']}\n"
            f"Timestamp:           {tx['timestamp']}\n"
            f"Transaction Type:    {tx['transaction_type']}\n"
            f"Amount:              ${tx['amount']:,.2f}\n"
            f"Execution Status:    {tx['status']}\n"
            f"Evaluated Risk Score: {tx['risk_score']:.1f} / 100\n"
            f"Risk Level Tier:     {tx['risk_level']}\n"
            f"Sender Wallet ID:    {tx['sender_wallet_id']}\n"
            f"Receiver Wallet ID:  {tx['receiver_wallet_id']}\n"
            f"Device Fingerprint:  {tx['device_fingerprint']}\n"
            f"Geolocation Info:    {tx['location']}\n"
            f"Notes / Narrative:   {tx['notes']}\n"
            f"{'='*60}\n"
            f"TRIGGERED RULES BREAKDOWN:\n"
            f"{flagged_rules_pretty}\n"
        )
        info_box.insert("1.0", content)
        info_box.config(state="disabled")

        ttk.Button(frame, text="Close Inspector", command=dlg.destroy).pack(anchor="e")

    def _handle_deposit(self):
        try:
            amt = float(self.entry_dep_amount.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid numeric deposit amount.")
            return

        res = self.wallet_service.deposit(self.current_wallet["id"], amt, "Manual Desktop App Deposit")
        if res["success"]:
            messagebox.showinfo("Deposit Completed", res["message"])
            self._refresh_all_views()
        else:
            messagebox.showerror("Deposit Failed", res["message"])

    def _handle_transfer(self):
        rec_wallet = self.entry_rec_wallet.get().strip()
        try:
            amt = float(self.entry_tx_amount.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid numeric transfer amount.")
            return

        city = self.entry_tx_city.get().strip()
        dev = self.entry_tx_dev.get().strip()
        note = self.entry_tx_note.get().strip()

        location = {"city": city, "country": "US", "lat": 40.7128, "lon": -74.0060, "ip": "127.0.0.1"}

        res = self.wallet_service.transfer(
            sender_wallet_id=self.current_wallet["id"],
            receiver_wallet_number=rec_wallet,
            amount=amt,
            location=location,
            device_fingerprint=dev,
            notes=note
        )

        self._refresh_all_views()

        # Update Live Meter
        score = res.get("evaluation", {}).get("risk_score", 0.0)
        level = res.get("evaluation", {}).get("risk_level", "LOW")
        self._draw_risk_meter(self.canvas_wallet_meter, score, level)

        if res["success"]:
            messagebox.showinfo("Transfer Approved", f"✅ {res['message']}")
        elif res["status"] == "PENDING_REVIEW":
            messagebox.showwarning("Held for Review", f"⚠️ {res['message']}")
        else:
            messagebox.showerror("Transfer Blocked", f"❌ {res['message']}")

    # =========================================================================
    # TAB 2: Fraud Operations & Alerts Case Center
    # =========================================================================
    def _init_admin_tab(self):
        metrics_bar = ttk.Frame(self.tab_admin, padding=8)
        metrics_bar.pack(fill="x")

        self.m_tx_count = self._make_metric_card(metrics_bar, "Total Transactions", "0", 0)
        self.m_volume = self._make_metric_card(metrics_bar, "Total Volume (USD)", "$0.00", 1)
        self.m_fraud_rate = self._make_metric_card(metrics_bar, "Fraud Block Rate", "0.0%", 2)
        self.m_open_alerts = self._make_metric_card(metrics_bar, "Active Incident Alerts", "0", 3)

        main_pane = ttk.PanedWindow(self.tab_admin, orient="vertical")
        main_pane.pack(fill="both", expand=True, padx=8, pady=4)

        top_alert_frame = ttk.LabelFrame(main_pane, text="Incident Investigation Queue", padding=6)
        main_pane.add(top_alert_frame, weight=3)

        cols = ("id", "tx_uuid", "username", "wallet", "amount", "score", "alert_type", "action", "status", "time")
        self.tree_alerts = ttk.Treeview(top_alert_frame, columns=cols, show="headings", height=8)
        self.tree_alerts.heading("id", text="Alert ID")
        self.tree_alerts.heading("tx_uuid", text="Tx UUID")
        self.tree_alerts.heading("username", text="User")
        self.tree_alerts.heading("wallet", text="Wallet")
        self.tree_alerts.heading("amount", text="Amount")
        self.tree_alerts.heading("score", text="Risk Score")
        self.tree_alerts.heading("alert_type", text="Triggered Rule")
        self.tree_alerts.heading("action", text="Action Taken")
        self.tree_alerts.heading("status", text="Case Status")
        self.tree_alerts.heading("time", text="Timestamp")

        self.tree_alerts.column("id", width=55, anchor="center")
        self.tree_alerts.column("tx_uuid", width=110)
        self.tree_alerts.column("username", width=85)
        self.tree_alerts.column("wallet", width=110)
        self.tree_alerts.column("amount", width=80, anchor="e")
        self.tree_alerts.column("score", width=70, anchor="center")
        self.tree_alerts.column("alert_type", width=140)
        self.tree_alerts.column("action", width=95, anchor="center")
        self.tree_alerts.column("status", width=90, anchor="center")
        self.tree_alerts.column("time", width=130)

        self.tree_alerts.pack(side="left", fill="both", expand=True)
        sb_alerts = ttk.Scrollbar(top_alert_frame, orient="vertical", command=self.tree_alerts.yview)
        self.tree_alerts.config(yscrollcommand=sb_alerts.set)
        sb_alerts.pack(side="right", fill="y")

        self.tree_alerts.bind("<<TreeviewSelect>>", self._on_alert_selected)

        # Adjudication Box
        bottom_box = ttk.LabelFrame(main_pane, text="Analyst Adjudication & Case Enforcement", padding=8)
        main_pane.add(bottom_box, weight=2)

        self.txt_alert_details = tk.Text(bottom_box, height=5, font=("Consolas", 9), wrap="word")
        self.txt_alert_details.pack(fill="both", expand=True, pady=3)
        self.txt_alert_details.insert("1.0", "Select an incident alert from the table above to view forensic details and apply actions.")

        btn_row = ttk.Frame(bottom_box)
        btn_row.pack(fill="x", pady=4)

        ttk.Button(btn_row, text="✅ Approve & Settle Funds", command=self._action_approve_alert).pack(side="left", padx=4)
        ttk.Button(btn_row, text="🚫 Confirm Fraud & Freeze Account", command=self._action_block_alert).pack(side="left", padx=4)
        ttk.Button(btn_row, text="⚪ Dismiss (False Alarm)", command=self._action_dismiss_alert).pack(side="left", padx=4)
        ttk.Button(btn_row, text="❄️ Freeze Wallet", command=self._action_freeze_selected_wallet).pack(side="left", padx=12)
        ttk.Button(btn_row, text="☀️ Unfreeze Wallet", command=self._action_unfreeze_selected_wallet).pack(side="left", padx=4)

    def _make_metric_card(self, parent, title: str, initial_value: str, col: int):
        card = ttk.Frame(parent, style="Card.TFrame", padding=(14, 8))
        card.grid(row=0, column=col, padx=6, sticky="ew")
        parent.columnconfigure(col, weight=1)

        ttk.Label(card, text=title, style="MetricLabel.TLabel").pack(anchor="w")
        val_lbl = ttk.Label(card, text=initial_value, style="MetricValue.TLabel")
        val_lbl.pack(anchor="w")
        return val_lbl

    def _refresh_admin_view(self):
        m = self.admin_service.get_dashboard_metrics()
        self.m_tx_count.config(text=str(m["total_transactions"]))
        self.m_volume.config(text=f"${m['total_volume']:,.2f}")
        self.m_fraud_rate.config(text=f"{m['fraud_rate_percent']:.1f}%")
        self.m_open_alerts.config(text=str(m["open_alerts_count"]))

        for item in self.tree_alerts.get_children():
            self.tree_alerts.delete(item)

        alerts = self.admin_service.get_alerts(limit=50)
        for a in alerts:
            amt_str = f"${a['amount']:,.2f}" if a.get("amount") is not None else "-"
            self.tree_alerts.insert(
                "",
                "end",
                values=(
                    a["id"],
                    (a["transaction_uuid"][:10] + "...") if a.get("transaction_uuid") else "-",
                    a.get("username") or "Unknown",
                    a.get("wallet_number") or "-",
                    amt_str,
                    f"{a['risk_score']:.1f}",
                    a["alert_type"],
                    a["action_taken"],
                    a["status"],
                    a["created_at"]
                )
            )

    def _get_selected_alert_id(self) -> Optional[int]:
        selected = self.tree_alerts.selection()
        if not selected:
            messagebox.showwarning("Selection Required", "Please select an incident alert row first.")
            return None
        return int(self.tree_alerts.item(selected[0])["values"][0])

    def _on_alert_selected(self, event):
        selected = self.tree_alerts.selection()
        if not selected:
            return
        alert_id = self.tree_alerts.item(selected[0])["values"][0]
        alert = self.db.fetch_one("SELECT * FROM fraud_alerts WHERE id = ?", (alert_id,))
        if alert:
            tx = self.db.fetch_one("SELECT * FROM transactions WHERE id = ?", (alert["transaction_id"],)) if alert["transaction_id"] else {}
            details = (
                f"Alert ID: {alert['id']} | Case Status: {alert['status']} | Risk Score: {alert['risk_score']}/100\n"
                f"Reasons: {alert['reasons']}\n"
                f"Analyst Notes: {alert.get('analyst_notes') or 'None'}\n"
            )
            if tx:
                details += (
                    f"Transaction UUID: {tx.get('transaction_uuid')} | Type: {tx.get('transaction_type')} | Amount: ${tx.get('amount', 0):,.2f}\n"
                    f"Location JSON: {tx.get('location')} | Device: {tx.get('device_fingerprint')}\n"
                    f"Triggered Rules: {tx.get('flagged_rules')}\n"
                )
            self.txt_alert_details.delete("1.0", "end")
            self.txt_alert_details.insert("1.0", details)

    def _action_approve_alert(self):
        aid = self._get_selected_alert_id()
        if aid:
            res = self.admin_service.review_alert(aid, "APPROVE_RELEASE", "Approved by Analyst in Desktop Workstation", self.current_user["id"])
            messagebox.showinfo("Action Completed", res["message"])
            self._refresh_all_views()

    def _action_block_alert(self):
        aid = self._get_selected_alert_id()
        if aid:
            res = self.admin_service.review_alert(aid, "CONFIRM_FRAUD_BLOCK", "Confirmed malicious by Analyst", self.current_user["id"])
            messagebox.showinfo("Action Completed", res["message"])
            self._refresh_all_views()

    def _action_dismiss_alert(self):
        aid = self._get_selected_alert_id()
        if aid:
            res = self.admin_service.review_alert(aid, "DISMISS", "Dismissed as false positive", self.current_user["id"])
            messagebox.showinfo("Action Completed", res["message"])
            self._refresh_all_views()

    def _action_freeze_selected_wallet(self):
        aid = self._get_selected_alert_id()
        if aid:
            alert = self.db.fetch_one("SELECT wallet_id FROM fraud_alerts WHERE id = ?", (aid,))
            if alert and alert["wallet_id"]:
                self.admin_service.freeze_wallet(alert["wallet_id"], self.current_user["id"], "Manual freeze via Desktop App")
                messagebox.showinfo("Success", f"Wallet {alert['wallet_id']} is now FROZEN.")
                self._refresh_all_views()

    def _action_unfreeze_selected_wallet(self):
        aid = self._get_selected_alert_id()
        if aid:
            alert = self.db.fetch_one("SELECT wallet_id FROM fraud_alerts WHERE id = ?", (aid,))
            if alert and alert["wallet_id"]:
                self.admin_service.unfreeze_wallet(alert["wallet_id"], self.current_user["id"])
                messagebox.showinfo("Success", f"Wallet {alert['wallet_id']} has been restored to ACTIVE.")
                self._refresh_all_views()

    # =========================================================================
    # TAB 3: Dynamic Fraud Rules Config
    # =========================================================================
    def _init_rules_tab(self):
        frame = ttk.Frame(self.tab_rules, padding=8)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Active Detection Rules, Weights & Policy Configuration", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))

        cols = ("code", "name", "weight", "threshold", "action", "enabled", "desc")
        self.tree_rules = ttk.Treeview(frame, columns=cols, show="headings", height=12)
        self.tree_rules.heading("code", text="Rule Code")
        self.tree_rules.heading("name", text="Rule Name")
        self.tree_rules.heading("weight", text="Weight (Pts)")
        self.tree_rules.heading("threshold", text="Threshold")
        self.tree_rules.heading("action", text="Enforcement")
        self.tree_rules.heading("enabled", text="Active")
        self.tree_rules.heading("desc", text="Description")

        self.tree_rules.column("code", width=140)
        self.tree_rules.column("name", width=180)
        self.tree_rules.column("weight", width=85, anchor="center")
        self.tree_rules.column("threshold", width=85, anchor="center")
        self.tree_rules.column("action", width=95, anchor="center")
        self.tree_rules.column("enabled", width=65, anchor="center")
        self.tree_rules.column("desc", width=360)

        self.tree_rules.pack(side="top", fill="both", expand=True, pady=4)
        self.tree_rules.bind("<<TreeviewSelect>>", self._on_rule_selected)

        # Edit Rule Frame
        edit_box = ttk.LabelFrame(frame, text="Tune Selected Rule", padding=8)
        edit_box.pack(fill="x", pady=4)

        ttk.Label(edit_box, text="Rule Code:").grid(row=0, column=0, sticky="w", padx=4)
        self.entry_rule_code = ttk.Entry(edit_box, width=20, state="readonly")
        self.entry_rule_code.grid(row=0, column=1, sticky="w", padx=4)

        ttk.Label(edit_box, text="Weight (0-100):").grid(row=0, column=2, sticky="w", padx=4)
        self.entry_rule_weight = ttk.Entry(edit_box, width=10)
        self.entry_rule_weight.grid(row=0, column=3, sticky="w", padx=4)

        ttk.Label(edit_box, text="Enforcement Action:").grid(row=0, column=4, sticky="w", padx=4)
        self.combo_rule_action = ttk.Combobox(edit_box, values=["FLAG", "REVIEW", "BLOCK"], width=10, state="readonly")
        self.combo_rule_action.grid(row=0, column=5, sticky="w", padx=4)

        self.rule_enabled_var = tk.IntVar(value=1)
        ttk.Checkbutton(edit_box, text="Enabled", variable=self.rule_enabled_var).grid(row=0, column=6, padx=10)

        ttk.Button(edit_box, text="💾 Save Rule Changes", command=self._save_rule_changes).grid(row=0, column=7, padx=8)

    def _refresh_rules_view(self):
        for item in self.tree_rules.get_children():
            self.tree_rules.delete(item)

        rules = self.admin_service.get_rules()
        for r in rules:
            self.tree_rules.insert(
                "",
                "end",
                values=(
                    r["rule_code"],
                    r["name"],
                    f"{r['weight']:.1f}",
                    f"{r['threshold']:.2f}" if r["threshold"] else "-",
                    r["action_if_triggered"],
                    "✅ Yes" if r["is_enabled"] else "❌ No",
                    r["description"]
                )
            )

    def _on_rule_selected(self, event):
        selected = self.tree_rules.selection()
        if not selected:
            return
        vals = self.tree_rules.item(selected[0])["values"]
        self.entry_rule_code.config(state="normal")
        self.entry_rule_code.delete(0, "end")
        self.entry_rule_code.insert(0, str(vals[0]))
        self.entry_rule_code.config(state="readonly")

        self.entry_rule_weight.delete(0, "end")
        self.entry_rule_weight.insert(0, str(vals[2]))

        self.combo_rule_action.set(str(vals[4]))
        self.rule_enabled_var.set(1 if "Yes" in str(vals[5]) else 0)

    def _save_rule_changes(self):
        rcode = self.entry_rule_code.get().strip()
        if not rcode:
            messagebox.showwarning("Select Rule", "Please select a rule from the list first.")
            return

        try:
            w = float(self.entry_rule_weight.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Weight must be numeric.")
            return

        act = self.combo_rule_action.get()
        enabled = self.rule_enabled_var.get()

        self.admin_service.update_rule(
            rule_code=rcode,
            weight=w,
            is_enabled=enabled,
            action=act
        )
        messagebox.showinfo("Success", f"Rule '{rcode}' updated.")
        self._refresh_rules_view()

    # =========================================================================
    # TAB 4: Fraud Attack Simulator Lab
    # =========================================================================
    def _init_simulator_tab(self):
        pane = ttk.PanedWindow(self.tab_sim, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=8, pady=8)

        left_box = ttk.Frame(pane, width=380, padding=6)
        pane.add(left_box, weight=1)

        ttk.Label(left_box, text="Live Attack & Behavior Scenarios", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))

        scenarios = [
            ("⚡ Legitimate P2P Everyday Transfer", self._run_sim_normal, "Normal $20-$80 payment between active friends"),
            ("🚨 Account Takeover (ATO) & Balance Drain", self._run_sim_ato, "92% rapid drain from unknown Russian IP"),
            ("⚡ Velocity Burst Attack (Bot Spammer)", self._run_sim_velocity, "5 rapid-fire transfers in under 2 seconds"),
            ("🤖 Card Testing / Micro-Tx Bot", self._run_sim_micro, "Rapid succession of < $2.50 card probe tests"),
            ("✈️ Impossible Travel (NYC -> London)", self._run_sim_geo, "Transfers in NYC then London 15 mins later"),
            ("💼 AML Structuring / Smurfing", self._run_sim_structuring, "Transfer of $9,850 just under $10,000 threshold"),
            ("🛑 Blacklisted Mule Recipient Hit", self._run_sim_blacklist, "Transfer attempt to blacklisted mule wallet"),
            ("🎲 Run Mixed Batch Simulation (15 txs)", self._run_sim_batch, "Simulate realistic stream with 40% fraud ratio"),
        ]

        for title, func, desc in scenarios:
            card = ttk.Frame(left_box, relief="groove", padding=5)
            card.pack(fill="x", pady=2)
            btn = ttk.Button(card, text=title, command=func)
            btn.pack(anchor="w", fill="x")
            ttk.Label(card, text=desc, font=("Segoe UI", 8), foreground="#64748B").pack(anchor="w", pady=(1, 0))

        right_box = ttk.Frame(pane, padding=6)
        pane.add(right_box, weight=3)

        top_r = ttk.Frame(right_box)
        top_r.pack(fill="x")
        ttk.Label(top_r, text="Simulation Event Stream & Detection Console", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(top_r, text="Clear Console", command=lambda: self.txt_sim_logs.delete("1.0", "end")).pack(side="right")

        self.txt_sim_logs = tk.Text(right_box, font=("Consolas", 9), wrap="word", background="#0F172A", foreground="#F8FAFC")
        self.txt_sim_logs.pack(fill="both", expand=True, pady=4)

        self.txt_sim_logs.tag_configure("COMPLETED", foreground="#4ADE80")
        self.txt_sim_logs.tag_configure("PENDING_REVIEW", foreground="#FBBF24")
        self.txt_sim_logs.tag_configure("BLOCKED", foreground="#F87171")
        self.txt_sim_logs.tag_configure("HEADER", foreground="#60A5FA", font=("Consolas", 10, "bold"))

    def _log_sim(self, text: str, tag: Optional[str] = None):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {text}\n"
        self.txt_sim_logs.insert("end", line, tag)
        self.txt_sim_logs.see("end")

    def _run_sim_normal(self):
        res = self.simulator.run_normal_transaction()
        self._log_sim(f"--- SCENARIO: {res['scenario']} ---", "HEADER")
        self._log_sim(f"Result: {res['result']['status']} | Risk Score: {res['result']['evaluation']['risk_score']} | Message: {res['result']['message']}", res['result']['status'])
        self._refresh_all_views()

    def _run_sim_ato(self):
        res = self.simulator.run_account_takeover_attack()
        self._log_sim(f"--- SCENARIO: {res['scenario']} ---", "HEADER")
        self._log_sim(f"Result: {res['result']['status']} | Risk Score: {res['result']['evaluation']['risk_score']} | Message: {res['result']['message']}", res['result']['status'])
        self._refresh_all_views()

    def _run_sim_velocity(self):
        results = self.simulator.run_velocity_burst_attack(burst_count=5)
        self._log_sim("--- SCENARIO: Velocity Burst Attack (5 Rapid Transactions) ---", "HEADER")
        for r in results:
            self._log_sim(f"Iteration #{r['iteration']}: {r['status']} | Risk Score: {r['risk_score']} | {r['message']}", r['status'])
        self._refresh_all_views()

    def _run_sim_micro(self):
        results = self.simulator.run_micro_transaction_probing(count=4)
        self._log_sim("--- SCENARIO: Micro-Transaction Probing Bot ---", "HEADER")
        for r in results:
            self._log_sim(f"Probe #{r['iteration']} (${r['amount']}): {r['status']} | Risk Score: {r['risk_score']} | {r['message']}", r['status'])
        self._refresh_all_views()

    def _run_sim_geo(self):
        res = self.simulator.run_impossible_travel_attack()
        self._log_sim(f"--- SCENARIO: {res['scenario']} ---", "HEADER")
        self._log_sim(f"Origin: {res['origin']} -> Destination: {res['destination']} in {res['time_difference']}")
        self._log_sim(f"Result: {res['result']['status']} | Risk Score: {res['result']['evaluation']['risk_score']} | {res['result']['message']}", res['result']['status'])
        self._refresh_all_views()

    def _run_sim_structuring(self):
        res = self.simulator.run_structuring_attack()
        self._log_sim(f"--- SCENARIO: {res['scenario']} ---", "HEADER")
        self._log_sim(f"Result: {res['result']['status']} | Risk Score: {res['result']['evaluation']['risk_score']} | {res['result']['message']}", res['result']['status'])
        self._refresh_all_views()

    def _run_sim_blacklist(self):
        res = self.simulator.run_blacklist_attack()
        self._log_sim(f"--- SCENARIO: {res['scenario']} ---", "HEADER")
        self._log_sim(f"Result: {res['result']['status']} | Risk Score: {res['result']['evaluation']['risk_score']} | {res['result']['message']}", res['result']['status'])
        self._refresh_all_views()

    def _run_sim_batch(self):
        def worker():
            self._log_sim("--- Starting Batch Simulation of 15 Transactions ---", "HEADER")
            def on_progress(idx, total, entry):
                scenario = entry.get("scenario", "Tx")
                res = entry.get("result", {})
                status = res.get("status", "UNKNOWN")
                score = res.get("evaluation", {}).get("risk_score", 0.0)
                self.after(0, lambda: self._log_sim(f"[{idx}/{total}] {scenario} -> {status} (Score: {score})", status))

            self.simulator.run_batch_simulation(total_transactions=15, fraud_ratio=0.4, callback=on_progress)
            self.after(0, lambda: self._log_sim("--- Batch Simulation Finished ---", "HEADER"))
            self.after(0, self._refresh_all_views)

        threading.Thread(target=worker, daemon=True).start()

    # =========================================================================
    # TAB 5: Forensic Reports & SQL Analytics
    # =========================================================================
    def _init_reports_tab(self):
        frame = ttk.Frame(self.tab_reports, padding=10)
        frame.pack(fill="both", expand=True)

        top_controls = ttk.Frame(frame)
        top_controls.pack(fill="x", pady=(0, 8))

        ttk.Label(top_controls, text="Select Analytical Query: ", font=("Segoe UI", 9, "bold")).pack(side="left")

        self.report_choice_var = tk.StringVar(value="Top High-Risk Wallets")
        report_options = [
            "Top High-Risk Wallets",
            "High Velocity Spikes",
            "AML Smurfing ($9,000 - $9,999.99)",
            "High-Drain Risk Transactions",
            "System Audit & Compliance Logs"
        ]
        self.combo_report = ttk.Combobox(top_controls, textvariable=self.report_choice_var, values=report_options, width=32, state="readonly")
        self.combo_report.pack(side="left", padx=6)

        btn_run = ttk.Button(top_controls, text="▶ Execute Query", command=self._run_selected_report)
        btn_run.pack(side="left", padx=6)

        self.lbl_report_stats = ttk.Label(top_controls, text="Ready", font=("Segoe UI", 9), foreground="#64748B")
        self.lbl_report_stats.pack(side="right")

        # Dynamic Treeview for reports
        self.report_tree_frame = ttk.Frame(frame)
        self.report_tree_frame.pack(fill="both", expand=True)

        self.tree_report = ttk.Treeview(self.report_tree_frame, show="headings", height=18)
        self.tree_report.pack(side="left", fill="both", expand=True)

        sb_report = ttk.Scrollbar(self.report_tree_frame, orient="vertical", command=self.tree_report.yview)
        self.tree_report.config(yscrollcommand=sb_report.set)
        sb_report.pack(side="right", fill="y")

        # Run initial report
        self._run_selected_report()

    def _run_selected_report(self):
        choice = self.report_choice_var.get()
        for item in self.tree_report.get_children():
            self.tree_report.delete(item)

        if choice == "Top High-Risk Wallets":
            cols = ("wallet", "user", "balance", "status", "alerts", "avg_score", "max_score")
            self.tree_report["columns"] = cols
            headers = ["Wallet Number", "Account User", "Balance", "Wallet Status", "Alerts Count", "Avg Risk", "Max Risk"]
            for c, h in zip(cols, headers):
                self.tree_report.heading(c, text=h)
                self.tree_report.column(c, width=130, anchor="center")

            rows = self.admin_service.get_top_high_risk_wallets()
            for r in rows:
                self.tree_report.insert("", "end", values=(
                    r["wallet_number"], r["username"], f"${r['balance']:,.2f}",
                    r["wallet_status"], r["alert_count"], r["avg_risk_score"], r["max_risk_score"]
                ))
            self.lbl_report_stats.config(text=f"Total Records: {len(rows)}")

        elif choice == "High Velocity Spikes":
            cols = ("wallet", "user", "tx_count", "total_amt", "last_tx")
            self.tree_report["columns"] = cols
            headers = ["Wallet Number", "User", "Transfer Count", "Total Transferred", "Last Tx Timestamp"]
            for c, h in zip(cols, headers):
                self.tree_report.heading(c, text=h)
                self.tree_report.column(c, width=150, anchor="center")

            rows = self.admin_service.get_velocity_spikes()
            for r in rows:
                self.tree_report.insert("", "end", values=(
                    r["wallet_number"], r["username"], r["tx_count"], f"${r['total_amount']:,.2f}", r["last_tx_time"]
                ))
            self.lbl_report_stats.config(text=f"Total Records: {len(rows)}")

        elif choice == "AML Smurfing ($9,000 - $9,999.99)":
            cols = ("id", "uuid", "wallet", "user", "amount", "score", "status", "time")
            self.tree_report["columns"] = cols
            headers = ["Tx ID", "UUID", "Sender Wallet", "User", "Amount", "Risk Score", "Status", "Timestamp"]
            for c, h in zip(cols, headers):
                self.tree_report.heading(c, text=h)
                self.tree_report.column(c, width=120, anchor="center")

            rows = self.admin_service.get_structuring_records()
            for r in rows:
                self.tree_report.insert("", "end", values=(
                    r["id"], r["transaction_uuid"][:12] + "...", r["sender_wallet"],
                    r["username"], f"${r['amount']:,.2f}", f"{r['risk_score']:.1f}", r["status"], r["timestamp"]
                ))
            self.lbl_report_stats.config(text=f"Total Records: {len(rows)}")

        elif choice == "High-Drain Risk Transactions":
            cols = ("uuid", "user", "wallet", "amount", "balance", "score", "status", "time")
            self.tree_report["columns"] = cols
            headers = ["Tx UUID", "User", "Sender Wallet", "Amount", "Current Balance", "Risk Score", "Status", "Timestamp"]
            for c, h in zip(cols, headers):
                self.tree_report.heading(c, text=h)
                self.tree_report.column(c, width=120, anchor="center")

            rows = self.admin_service.get_balance_drain_records()
            for r in rows:
                self.tree_report.insert("", "end", values=(
                    r["transaction_uuid"][:12] + "...", r["username"], r["wallet_number"],
                    f"${r['amount']:,.2f}", f"${r['current_balance']:,.2f}", f"{r['risk_score']:.1f}",
                    r["status"], r["timestamp"]
                ))
            self.lbl_report_stats.config(text=f"Total Records: {len(rows)}")

        elif choice == "System Audit & Compliance Logs":
            cols = ("id", "user", "action", "details", "ip", "time")
            self.tree_report["columns"] = cols
            headers = ["Audit ID", "Performed By", "Action Taken", "Details Narrative", "IP Address", "Timestamp"]
            for c, h in zip(cols, headers):
                self.tree_report.heading(c, text=h)
                self.tree_report.column(c, width=150, anchor="center")

            rows = self.admin_service.get_audit_trail()
            for r in rows:
                self.tree_report.insert("", "end", values=(
                    r["id"], r["performed_by"], r["action"], r["details"], r["ip_address"] or "-", r["timestamp"]
                ))
            self.lbl_report_stats.config(text=f"Total Records: {len(rows)}")

    # =========================================================================
    # Global Refresh
    # =========================================================================
    def _refresh_all_views(self):
        self._refresh_wallet_view()
        self._refresh_admin_view()
        self._refresh_rules_view()


def launch_gui():
    app = MobileWalletFraudApp()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()

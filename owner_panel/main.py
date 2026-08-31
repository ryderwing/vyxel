import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QHeaderView,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

CFG = Path(__file__).with_name("config.json")


class API:
    def __init__(self, url, email, password):
        self.base = url.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({"Content-Type": "application/json"})

        r = self.s.post(
            self.base + "/owner-api/login",
            json={"email": email, "password": password},
            timeout=15,
        )
        r.raise_for_status()
        self.s.headers["Authorization"] = "Bearer " + r.json()["token"]

    def get(self, path):
        r = self.s.get(self.base + path, timeout=15)
        r.raise_for_status()
        return r.json()

    def post(self, path, payload=None):
        r = self.s.post(self.base + path, json=payload or {}, timeout=15)
        r.raise_for_status()
        return r.json()

    def delete(self, path):
        r = self.s.delete(self.base + path, timeout=15)
        r.raise_for_status()
        return r.json()

    def logout(self):
        try:
            self.post("/owner-api/logout", {})
        finally:
            self.s.headers.pop("Authorization", None)


class ControlPanel(QMainWindow):
    def __init__(self):
        super().__init__()
        self.api = None
        self.rows = []
        self.setWindowTitle("Vyxel Control Panel")
        self.resize(1220, 760)

        self.setStyleSheet("""
            QWidget { background:#070708; color:#f3f3f3; }
            QPushButton {
                background:#171719;
                border:1px solid #343438;
                border-radius:7px;
                padding:8px 11px;
            }
            QPushButton:hover { border-color:#d71f32; }
            QPushButton#danger { background:#9f1525; border-color:#c51c31; }
            QLineEdit {
                background:#0d0d0f;
                border:1px solid #343438;
                border-radius:7px;
                padding:8px;
            }
            QTableWidget {
                background:#0b0b0d;
                gridline-color:#26262a;
                selection-background-color:#5e101a;
            }
            QHeaderView::section {
                background:#151518;
                padding:7px;
                border:0;
                border-right:1px solid #2a2a2e;
            }
            QTabWidget::pane { border:1px solid #252529; }
        """)

        self.login()

    def login(self):
        cfg = json.loads(CFG.read_text(encoding="utf-8"))

        email, ok = QInputDialog.getText(self, "Vyxel", "Email:")
        if not ok:
            raise SystemExit

        password, ok = QInputDialog.getText(
            self,
            "Vyxel",
            "Password:",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            raise SystemExit

        try:
            self.api = API(cfg["base_url"], email.strip(), password)
        except Exception as e:
            QMessageBox.critical(self, "Login failed", str(e))
            raise SystemExit

        root = QWidget()
        outer = QVBoxLayout(root)

        top = QHBoxLayout()
        title = QLabel("VYXEL CONTROL PANEL")
        title.setStyleSheet("font-size:18px;font-weight:800;color:#e3263b;")
        top.addWidget(title)
        top.addStretch()

        logout = QPushButton("Log out")
        logout.setObjectName("danger")
        logout.clicked.connect(self.logout)
        top.addWidget(logout)

        outer.addLayout(top)

        tabs = QTabWidget()
        tabs.addTab(self.users_tab(), "Users")
        tabs.addTab(self.network_tab(), "IP / Anti-VPN")
        tabs.addTab(self.tickets_tab(), "Tickets")
        outer.addWidget(tabs)

        self.setCentralWidget(root)

    def logout(self):
        if QMessageBox.question(
            self,
            "Log out",
            "Log out of the Vyxel Control Panel?",
        ) != QMessageBox.StandardButton.Yes:
            return

        try:
            if self.api:
                self.api.logout()
        except Exception:
            pass

        self.close()

    def err(self, e):
        QMessageBox.critical(self, "Error", str(e))

    # ---------------- USERS ----------------

    def users_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        controls = QHBoxLayout()

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search name, email, role, or IP")

        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.load_users)

        restrict = QPushButton("Restrict / Unrestrict")
        restrict.clicked.connect(self.restrict)

        temp = QPushButton("Temp Ban")
        temp.clicked.connect(self.tempban)

        untemp = QPushButton("Remove Temp Ban")
        untemp.clicked.connect(self.untempban)

        make_pentester = QPushButton("Make Pentester")
        make_pentester.clicked.connect(self.make_pentester)

        remove_pentester = QPushButton("Remove Pentester")
        remove_pentester.clicked.connect(self.remove_pentester)

        ip = QPushButton("IP Ban Selected")
        ip.clicked.connect(self.ip_selected)

        for widget in [
            self.search,
            refresh,
            restrict,
            temp,
            untemp,
            make_pentester,
            remove_pentester,
            ip,
        ]:
            controls.addWidget(widget)

        layout.addLayout(controls)

        self.users = QTableWidget(0, 9)
        self.users.setHorizontalHeaderLabels([
            "ID",
            "Name",
            "Email",
            "Role",
            "Restricted",
            "Temp Banned",
            "Temp Ban Until",
            "Last IP",
            "Created",
        ])
        self.users.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.users.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.users.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        layout.addWidget(self.users)

        self.search.textChanged.connect(self.filter_users)
        refresh.click()
        return w

    def load_users(self):
        try:
            self.rows = self.api.get("/owner-api/users")
            self.draw(self.rows)
        except Exception as e:
            self.err(e)

    @staticmethod
    def is_temp_banned(user):
        value = user.get("temp_banned_until")
        if not value:
            return False
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt > datetime.now(timezone.utc)
        except Exception:
            return True

    def draw(self, rows):
        self.users.setRowCount(len(rows))

        for r, u in enumerate(rows):
            banned = self.is_temp_banned(u)
            vals = [
                u["id"],
                u["display_name"],
                u["email"],
                u["role"],
                "Yes" if u["restricted"] else "No",
                "Yes" if banned else "No",
                u["temp_banned_until"] or "",
                u["last_ip"],
                u["created_at"],
            ]

            for c, value in enumerate(vals):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.users.setItem(r, c, item)

    def filter_users(self):
        q = self.search.text().lower().strip()
        if not q:
            self.draw(self.rows)
            return

        self.draw([
            u for u in self.rows
            if q in (
                f"{u.get('display_name','')} "
                f"{u.get('email','')} "
                f"{u.get('role','')} "
                f"{u.get('last_ip','')}"
            ).lower()
        ])

    def selected_uid(self):
        row = self.users.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select user", "Select a user first.")
            return None
        return int(self.users.item(row, 0).text())

    def restrict(self):
        uid = self.selected_uid()
        if uid is None:
            return

        row = self.users.currentRow()
        currently = self.users.item(row, 4).text() == "Yes"
        make_restricted = not currently

        reason = ""
        if make_restricted:
            reason, ok = QInputDialog.getText(self, "Restriction", "Reason:")
            if not ok:
                return

        try:
            self.api.post(
                f"/owner-api/users/{uid}/restrict",
                {"restricted": make_restricted, "reason": reason},
            )
            self.load_users()
        except Exception as e:
            self.err(e)

    def tempban(self):
        uid = self.selected_uid()
        if uid is None:
            return

        minutes, ok = QInputDialog.getInt(
            self,
            "Temp Ban",
            "Ban length in minutes:",
            60,
            1,
            525600,
        )
        if not ok:
            return

        try:
            self.api.post(
                f"/owner-api/users/{uid}/temp-ban",
                {"minutes": minutes},
            )
            self.load_users()
        except Exception as e:
            self.err(e)

    def untempban(self):
        uid = self.selected_uid()
        if uid is None:
            return

        if QMessageBox.question(
            self,
            "Remove Temp Ban",
            "Remove this user's temporary ban?",
        ) != QMessageBox.StandardButton.Yes:
            return

        try:
            self.api.post(
                f"/owner-api/users/{uid}/temp-ban",
                {"minutes": 0},
            )
            self.load_users()
        except Exception as e:
            self.err(e)

    def make_pentester(self):
        uid = self.selected_uid()
        if uid is None:
            return

        row = self.users.currentRow()
        current_role = self.users.item(row, 3).text().strip().lower()

        if current_role == "owner":
            QMessageBox.information(
                self,
                "Not allowed",
                "The owner account cannot be changed to pentester.",
            )
            return

        if current_role == "pentester":
            QMessageBox.information(
                self,
                "Already Pentester",
                "This user is already a pentester.",
            )
            return

        if QMessageBox.question(
            self,
            "Make Pentester",
            "Give this user pentester access?",
        ) != QMessageBox.StandardButton.Yes:
            return

        try:
            self.api.post(
                f"/owner-api/users/{uid}/role",
                {"role": "pentester"},
            )
            self.load_users()
            QMessageBox.information(
                self,
                "Done",
                "User is now a pentester.",
            )
        except Exception as e:
            self.err(e)

    def remove_pentester(self):
        uid = self.selected_uid()
        if uid is None:
            return

        row = self.users.currentRow()
        current_role = self.users.item(row, 3).text().strip().lower()

        if current_role == "owner":
            QMessageBox.information(
                self,
                "Not allowed",
                "The owner account role cannot be changed here.",
            )
            return

        if current_role != "pentester":
            QMessageBox.information(
                self,
                "Not a Pentester",
                "This user is not currently a pentester.",
            )
            return

        if QMessageBox.question(
            self,
            "Remove Pentester",
            "Remove this user's pentester access?",
        ) != QMessageBox.StandardButton.Yes:
            return

        try:
            self.api.post(
                f"/owner-api/users/{uid}/role",
                {"role": "client"},
            )
            self.load_users()
            QMessageBox.information(
                self,
                "Done",
                "Pentester access removed.",
            )
        except Exception as e:
            self.err(e)

    def ip_selected(self):
        row = self.users.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select user", "Select a user first.")
            return

        ip = self.users.item(row, 7).text().strip()
        if not ip:
            QMessageBox.information(self, "No IP", "This user has no recorded IP.")
            return

        try:
            self.api.post(
                "/owner-api/ip-ban",
                {"ip": ip, "reason": "Control panel ban"},
            )
            QMessageBox.information(self, "Done", "IP banned.")
        except Exception as e:
            self.err(e)

    # ---------------- NETWORK ----------------

    def network_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        self.ip = QLineEdit()
        self.ip.setPlaceholderText("IP address")
        layout.addWidget(self.ip)

        buttons = [
            ("Ban IP", self.ban),
            ("Unban IP", self.unban),
            ("Allow through anti-VPN", self.allow),
            ("Remove anti-VPN allow", self.unallow),
        ]

        for label, fn in buttons:
            b = QPushButton(label)
            b.clicked.connect(fn)
            layout.addWidget(b)

        layout.addWidget(QLabel(
            "Anti-VPN is a risk signal and can produce false positives."
        ))
        layout.addStretch()
        return w

    def ban(self):
        try:
            self.api.post(
                "/owner-api/ip-ban",
                {"ip": self.ip.text().strip(), "reason": "Control panel ban"},
            )
        except Exception as e:
            self.err(e)

    def unban(self):
        try:
            self.api.delete("/owner-api/ip-ban/" + self.ip.text().strip())
        except Exception as e:
            self.err(e)

    def allow(self):
        try:
            self.api.post(
                "/owner-api/vpn-allowlist",
                {"ip": self.ip.text().strip(), "note": "Control panel allowlist"},
            )
        except Exception as e:
            self.err(e)

    def unallow(self):
        try:
            self.api.delete(
                "/owner-api/vpn-allowlist/" + self.ip.text().strip()
            )
        except Exception as e:
            self.err(e)

    # ---------------- TICKETS ----------------

    def tickets_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.load_tickets)
        layout.addWidget(refresh)

        self.tix = QTableWidget(0, 7)
        self.tix.setHorizontalHeaderLabels([
            "ID",
            "Title",
            "Target",
            "Status",
            "Client UID",
            "Pentester UID",
            "Updated",
        ])
        self.tix.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.tix)

        refresh.click()
        return w

    def load_tickets(self):
        try:
            rows = self.api.get("/owner-api/tickets")
            self.tix.setRowCount(len(rows))
            for r, t in enumerate(rows):
                vals = [
                    t["id"],
                    t["title"],
                    t["target"],
                    t["status"],
                    t["owner_user_id"],
                    t["assigned_pentester_id"] or "",
                    t["updated_at"],
                ]
                for c, value in enumerate(vals):
                    self.tix.setItem(r, c, QTableWidgetItem(str(value)))
        except Exception as e:
            self.err(e)


def main():
    app = QApplication(sys.argv)

    if not CFG.exists():
        QMessageBox.critical(
            None,
            "Missing config",
            "Copy config.example.json to config.json and set your site URL.",
        )
        return

    window = ControlPanel()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

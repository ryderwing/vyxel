import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication,QHeaderView,QHBoxLayout,QInputDialog,QLabel,QLineEdit,QMainWindow,QMenu,QMessageBox,QPushButton,QTabWidget,QTableWidget,QTableWidgetItem,QVBoxLayout,QWidget

CFG=Path(__file__).with_name("config.json")

class API:
    def __init__(self,url,email,password):
        self.base=url.rstrip("/")
        self.s=requests.Session()
        self.s.headers.update({"Content-Type":"application/json"})
        r=self.s.post(self.base+"/owner-api/login",json={"email":email,"password":password},timeout=15)
        r.raise_for_status()
        data=r.json()
        self.s.headers["Authorization"]="Bearer "+data["token"]
        self.is_primary_owner=bool(data.get("is_primary_owner"))
        self.user_id=data.get("user_id")

    def get(self,path):
        r=self.s.get(self.base+path,timeout=15)
        r.raise_for_status()
        return r.json()

    def post(self,path,payload=None):
        r=self.s.post(self.base+path,json=payload or {},timeout=15)
        r.raise_for_status()
        return r.json()

    def delete(self,path):
        r=self.s.delete(self.base+path,timeout=15)
        r.raise_for_status()
        return r.json()

    def logout(self):
        try:
            self.post("/owner-api/logout",{})
        finally:
            self.s.headers.pop("Authorization",None)

class ControlPanel(QMainWindow):
    def __init__(self):
        super().__init__()
        self.api=None
        self.rows=[]
        self.setWindowTitle("Vyxel Control Panel")
        self.resize(1280,760)
        self.setStyleSheet("""
            QWidget{background:#070708;color:#f3f3f3}
            QPushButton{background:#171719;border:1px solid #343438;border-radius:7px;padding:8px 11px}
            QPushButton:hover{border-color:#d71f32}
            QPushButton#danger{background:#9f1525;border-color:#c51c31}
            QLineEdit{background:#0d0d0f;border:1px solid #343438;border-radius:7px;padding:8px}
            QTableWidget{background:#0b0b0d;gridline-color:#26262a;selection-background-color:#5e101a}
            QHeaderView::section{background:#151518;padding:7px;border:0;border-right:1px solid #2a2a2e}
            QMenu{background:#101012;border:1px solid #343438;padding:5px}
            QMenu::item{padding:8px 28px 8px 12px}
            QMenu::item:selected{background:#7b1420}
        """)
        self.login()

    def login(self):
        cfg=json.loads(CFG.read_text(encoding="utf-8"))
        email,ok=QInputDialog.getText(self,"Vyxel","Email:")
        if not ok:
            raise SystemExit
        password,ok=QInputDialog.getText(self,"Vyxel","Password:",QLineEdit.EchoMode.Password)
        if not ok:
            raise SystemExit
        try:
            self.api=API(cfg["base_url"],email.strip(),password)
        except Exception as e:
            QMessageBox.critical(self,"Login failed",str(e))
            raise SystemExit

        root=QWidget()
        outer=QVBoxLayout(root)
        top=QHBoxLayout()
        title=QLabel("VYXEL CONTROL PANEL")
        title.setStyleSheet("font-size:18px;font-weight:800;color:#e3263b")
        top.addWidget(title)
        if self.api.is_primary_owner:
            badge=QLabel("MAIN OWNER")
            badge.setStyleSheet("color:#ff596c;font-weight:800")
            top.addWidget(badge)
        top.addStretch()
        logout=QPushButton("Log out")
        logout.setObjectName("danger")
        logout.clicked.connect(self.logout)
        top.addWidget(logout)
        outer.addLayout(top)

        tabs=QTabWidget()
        tabs.addTab(self.users_tab(),"Users")
        tabs.addTab(self.network_tab(),"IP / Anti-VPN")
        tabs.addTab(self.tickets_tab(),"Tickets")
        outer.addWidget(tabs)
        self.setCentralWidget(root)

    def logout(self):
        if QMessageBox.question(self,"Log out","Log out of Vyxel?")!=QMessageBox.StandardButton.Yes:
            return
        try:
            self.api.logout()
        except Exception:
            pass
        self.close()

    def err(self,e):
        message=str(e)
        if hasattr(e,"response") and e.response is not None:
            try:
                message=e.response.json().get("detail",message)
            except Exception:
                pass
        QMessageBox.critical(self,"Error",message)

    def users_tab(self):
        w=QWidget()
        layout=QVBoxLayout(w)
        bar=QHBoxLayout()
        self.search=QLineEdit()
        self.search.setPlaceholderText("Search users")
        refresh=QPushButton("Refresh")
        refresh.clicked.connect(self.load_users)
        bar.addWidget(self.search)
        bar.addWidget(refresh)
        layout.addLayout(bar)

        self.users=QTableWidget(0,10)
        self.users.setHorizontalHeaderLabels(["ID","Name","Email","Role","Restricted","Temp Banned","Temp Ban Until","Last IP","Created","Options"])
        self.users.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.users.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.users)
        self.search.textChanged.connect(self.filter_users)
        refresh.click()
        return w

    @staticmethod
    def is_temp_banned(user):
        value=user.get("temp_banned_until")
        if not value:
            return False
        try:
            dt=datetime.fromisoformat(value.replace("Z","+00:00"))
            if dt.tzinfo is None:
                dt=dt.replace(tzinfo=timezone.utc)
            return dt>datetime.now(timezone.utc)
        except Exception:
            return True

    def load_users(self):
        try:
            self.rows=self.api.get("/owner-api/users")
            self.draw(self.rows)
        except Exception as e:
            self.err(e)

    def filter_users(self):
        q=self.search.text().lower().strip()
        if not q:
            self.draw(self.rows)
            return
        self.draw([u for u in self.rows if q in f"{u.get('display_name','')} {u.get('email','')} {u.get('role','')} {u.get('last_ip','')}".lower()])

    def draw(self,rows):
        self.users.setRowCount(len(rows))
        for r,u in enumerate(rows):
            role="Main Owner" if u.get("primary_owner") else u["role"].title()
            vals=[
                u["id"],u["display_name"],u["email"],role,
                "Yes" if u["restricted"] else "No",
                "Yes" if self.is_temp_banned(u) else "No",
                u["temp_banned_until"] or "",u["last_ip"],u["created_at"]
            ]
            for c,value in enumerate(vals):
                item=QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.users.setItem(r,c,item)
            button=QPushButton("Options")
            button.clicked.connect(lambda checked=False,user=dict(u),btn=button:self.show_options(user,btn))
            self.users.setCellWidget(r,9,button)

    def show_options(self,user,button):
        menu=QMenu(self)
        role=user.get("role","client")
        restricted=bool(user.get("restricted"))
        banned=self.is_temp_banned(user)
        primary=bool(user.get("primary_owner"))

        temp=menu.addAction("Remove Temp Ban" if banned else "Temp Ban")
        temp.triggered.connect(lambda:self.remove_temp(user) if banned else self.temp_ban(user))

        restrict=menu.addAction("Unrestrict From Site" if restricted else "Restrict From Site")
        restrict.triggered.connect(lambda:self.set_restricted(user,not restricted))

        ipban=menu.addAction("IP Ban")
        ipban.triggered.connect(lambda:self.ip_ban_user(user))

        allow=menu.addAction("Allow VPN Block Bypass")
        allow.triggered.connect(lambda:self.vpn_bypass(user,True))

        unallow=menu.addAction("Remove VPN Block Bypass")
        unallow.triggered.connect(lambda:self.vpn_bypass(user,False))

        menu.addSeparator()

        if role=="pentester":
            pentester=menu.addAction("Remove Pentester")
            pentester.triggered.connect(lambda:self.set_role(user,"client"))
        elif role!="owner":
            pentester=menu.addAction("Make Pentester")
            pentester.triggered.connect(lambda:self.set_role(user,"pentester"))

        if self.api.is_primary_owner and not primary:
            if role=="owner":
                owner=menu.addAction("Remove Owner Access")
                owner.triggered.connect(lambda:self.set_role(user,"client"))
            else:
                owner=menu.addAction("Make Owner")
                owner.triggered.connect(lambda:self.set_role(user,"owner"))

        menu.addSeparator()
        delete=menu.addAction("Delete Account")
        delete.triggered.connect(lambda:self.delete_account(user))

        if primary:
            temp.setEnabled(False)
            restrict.setEnabled(False)
            ipban.setEnabled(False)
            delete.setEnabled(False)

        menu.exec(button.mapToGlobal(button.rect().bottomLeft()))

    def temp_ban(self,user):
        minutes,ok=QInputDialog.getInt(self,"Temp Ban",f"Ban {user['display_name']} for how many minutes?",60,1,525600)
        if not ok:
            return
        try:
            self.api.post(f"/owner-api/users/{user['id']}/temp-ban",{"minutes":minutes})
            self.load_users()
        except Exception as e:
            self.err(e)

    def remove_temp(self,user):
        try:
            self.api.post(f"/owner-api/users/{user['id']}/temp-ban",{"minutes":0})
            self.load_users()
        except Exception as e:
            self.err(e)

    def set_restricted(self,user,value):
        reason=""
        if value:
            reason,ok=QInputDialog.getText(self,"Restrict User","Reason:")
            if not ok:
                return
        try:
            self.api.post(f"/owner-api/users/{user['id']}/restrict",{"restricted":value,"reason":reason})
            self.load_users()
        except Exception as e:
            self.err(e)

    def ip_ban_user(self,user):
        if not user.get("last_ip"):
            QMessageBox.information(self,"No IP","This user has no recorded IP.")
            return
        if QMessageBox.question(self,"IP Ban",f"IP ban {user['display_name']}?")!=QMessageBox.StandardButton.Yes:
            return
        try:
            self.api.post(f"/owner-api/users/{user['id']}/ip-ban",{"reason":"Banned from user options"})
            self.load_users()
        except Exception as e:
            self.err(e)

    def vpn_bypass(self,user,enabled):
        if not user.get("last_ip"):
            QMessageBox.information(self,"No IP","This user has no recorded IP.")
            return
        try:
            self.api.post(f"/owner-api/users/{user['id']}/vpn-bypass",{"enabled":enabled})
            QMessageBox.information(self,"Done","VPN bypass enabled." if enabled else "VPN bypass removed.")
        except Exception as e:
            self.err(e)

    def set_role(self,user,role):
        labels={"client":"Client","pentester":"Pentester","owner":"Owner"}
        if QMessageBox.question(self,"Change Role",f"Change {user['display_name']} to {labels[role]}?")!=QMessageBox.StandardButton.Yes:
            return
        try:
            self.api.post(f"/owner-api/users/{user['id']}/role",{"role":role})
            self.load_users()
        except Exception as e:
            self.err(e)

    def delete_account(self,user):
        if QMessageBox.question(self,"Delete Account",f"Permanently delete {user['display_name']} and their tickets?")!=QMessageBox.StandardButton.Yes:
            return
        confirm,ok=QInputDialog.getText(self,"Confirm Delete",'Type DELETE to confirm:')
        if not ok or confirm!="DELETE":
            return
        try:
            self.api.delete(f"/owner-api/users/{user['id']}")
            self.load_users()
        except Exception as e:
            self.err(e)

    def network_tab(self):
        w=QWidget()
        layout=QVBoxLayout(w)
        self.ip=QLineEdit()
        self.ip.setPlaceholderText("IP address")
        layout.addWidget(self.ip)
        for label,fn in [("Ban IP",self.ban_ip),("Unban IP",self.unban_ip),("Allow VPN Bypass",self.allow_ip),("Remove VPN Bypass",self.unallow_ip)]:
            b=QPushButton(label)
            b.clicked.connect(fn)
            layout.addWidget(b)
        layout.addStretch()
        return w

    def ban_ip(self):
        try:
            self.api.post("/owner-api/ip-ban",{"ip":self.ip.text().strip(),"reason":"Manual owner ban"})
        except Exception as e:
            self.err(e)

    def unban_ip(self):
        try:
            self.api.delete("/owner-api/ip-ban/"+self.ip.text().strip())
        except Exception as e:
            self.err(e)

    def allow_ip(self):
        try:
            self.api.post("/owner-api/vpn-allowlist",{"ip":self.ip.text().strip(),"note":"Manual owner bypass"})
        except Exception as e:
            self.err(e)

    def unallow_ip(self):
        try:
            self.api.delete("/owner-api/vpn-allowlist/"+self.ip.text().strip())
        except Exception as e:
            self.err(e)

    def tickets_tab(self):
        w=QWidget()
        layout=QVBoxLayout(w)
        refresh=QPushButton("Refresh")
        refresh.clicked.connect(self.load_tickets)
        layout.addWidget(refresh)
        self.tix=QTableWidget(0,7)
        self.tix.setHorizontalHeaderLabels(["ID","Title","Target","Status","Client UID","Pentester UID","Updated"])
        self.tix.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.tix)
        refresh.click()
        return w

    def load_tickets(self):
        try:
            rows=self.api.get("/owner-api/tickets")
            self.tix.setRowCount(len(rows))
            for r,t in enumerate(rows):
                for c,value in enumerate([t["id"],t["title"],t["target"],t["status"],t["owner_user_id"],t["assigned_pentester_id"] or "",t["updated_at"]]):
                    self.tix.setItem(r,c,QTableWidgetItem(str(value)))
        except Exception as e:
            self.err(e)

def main():
    app=QApplication(sys.argv)
    if not CFG.exists():
        QMessageBox.critical(None,"Missing config","Copy config.example.json to config.json and set your site URL.")
        return
    window=ControlPanel()
    window.show()
    sys.exit(app.exec())

if __name__=="__main__":
    main()

import json,sys
from pathlib import Path
import requests
from PySide6.QtWidgets import QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QTableWidget,QTableWidgetItem,QPushButton,QLineEdit,QTabWidget,QHeaderView,QInputDialog,QMessageBox,QLabel
CFG=Path(__file__).with_name('config.json')
class API:
    def __init__(self,url,email,password):
        self.base=url.rstrip('/')
        self.s=requests.Session()
        self.s.headers.update({'Content-Type':'application/json'})
        r=self.s.post(self.base+'/owner-api/login',json={'email':email,'password':password},timeout=15)
        r.raise_for_status()
        self.s.headers['Authorization']='Bearer '+r.json()['token']
    def get(self,p):r=self.s.get(self.base+p,timeout=15);r.raise_for_status();return r.json()
    def post(self,p,j):r=self.s.post(self.base+p,json=j,timeout=15);r.raise_for_status();return r.json()
    def delete(self,p):r=self.s.delete(self.base+p,timeout=15);r.raise_for_status();return r.json()
class W(QMainWindow):
    def __init__(self):
        super().__init__();self.setWindowTitle('Vyxel Owner Control');self.resize(1180,720)
        c=json.loads(CFG.read_text())
        email,ok=QInputDialog.getText(self,'Owner Login','Owner email:')
        if not ok:raise SystemExit
        password,ok=QInputDialog.getText(self,'Owner Login','Owner password:',QLineEdit.EchoMode.Password)
        if not ok:raise SystemExit
        self.api=API(c['base_url'],email.strip(),password)
        tabs=QTabWidget();tabs.addTab(self.users_tab(),'Users');tabs.addTab(self.network_tab(),'IP / Anti-VPN');tabs.addTab(self.tickets_tab(),'Tickets');self.setCentralWidget(tabs)
        self.setStyleSheet('QWidget{background:#090b0e;color:#eef2f5} QPushButton{background:#141b22;border:1px solid #26323e;border-radius:7px;padding:8px} QLineEdit{background:#080b0f;border:1px solid #26323e;padding:8px} QTableWidget{background:#0b1015;gridline-color:#202a34} QHeaderView::section{background:#111820;padding:7px}')
    def err(self,e):QMessageBox.critical(self,'Error',str(e))
    def users_tab(self):
        w=QWidget();l=QVBoxLayout(w);b=QHBoxLayout();self.search=QLineEdit();self.search.setPlaceholderText('Search name/email/IP');refresh=QPushButton('Refresh');refresh.clicked.connect(self.load_users);restrict=QPushButton('Restrict / Unrestrict');restrict.clicked.connect(self.restrict);temp=QPushButton('Temp Ban');temp.clicked.connect(self.tempban);ip=QPushButton('IP Ban Selected');ip.clicked.connect(self.ip_selected)
        for x in [self.search,refresh,restrict,temp,ip]:b.addWidget(x)
        l.addLayout(b);self.users=QTableWidget(0,8);self.users.setHorizontalHeaderLabels(['ID','Name','Email','Role','Restricted','Temp Ban Until','Last IP','Created']);self.users.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch);l.addWidget(self.users);self.search.textChanged.connect(self.filter_users);refresh.click();return w
    def load_users(self):
        try:self.rows=self.api.get('/owner-api/users');self.draw(self.rows)
        except Exception as e:self.err(e)
    def draw(self,rows):
        self.users.setRowCount(len(rows))
        for r,u in enumerate(rows):
            vals=[u['id'],u['display_name'],u['email'],u['role'],u['restricted'],u['temp_banned_until'] or '',u['last_ip'],u['created_at']]
            for c,v in enumerate(vals):self.users.setItem(r,c,QTableWidgetItem(str(v)))
    def filter_users(self):
        q=self.search.text().lower();self.draw([u for u in self.rows if q in (u['display_name']+' '+u['email']+' '+u['last_ip']).lower()])
    def uid(self):
        r=self.users.currentRow();return int(self.users.item(r,0).text()) if r>=0 else None
    def restrict(self):
        u=self.uid();
        if not u:return
        make=self.users.item(self.users.currentRow(),4).text().lower()!='true';reason=''
        if make:reason,ok=QInputDialog.getText(self,'Restriction','Reason:');
        else:ok=True
        if not ok:return
        try:self.api.post(f'/owner-api/users/{u}/restrict',{'restricted':make,'reason':reason});self.load_users()
        except Exception as e:self.err(e)
    def tempban(self):
        u=self.uid();
        if not u:return
        mins,ok=QInputDialog.getInt(self,'Temp Ban','Minutes (0 clears):',60,0,525600)
        if not ok:return
        try:self.api.post(f'/owner-api/users/{u}/temp-ban',{'minutes':mins});self.load_users()
        except Exception as e:self.err(e)
    def ip_selected(self):
        r=self.users.currentRow();
        if r<0:return
        ip=self.users.item(r,6).text().strip();
        if not ip:return
        try:self.api.post('/owner-api/ip-ban',{'ip':ip,'reason':'Owner panel ban'});QMessageBox.information(self,'Done','IP banned')
        except Exception as e:self.err(e)
    def network_tab(self):
        w=QWidget();l=QVBoxLayout(w);self.ip=QLineEdit();self.ip.setPlaceholderText('IP address');l.addWidget(self.ip)
        for label,fn in [('Ban IP',self.ban),('Unban IP',self.unban),('Allow through anti-VPN',self.allow),('Remove anti-VPN allow',self.unallow)]:q=QPushButton(label);q.clicked.connect(fn);l.addWidget(q)
        l.addWidget(QLabel('Anti-VPN is a risk control, not perfect proof that an IP is using a VPN.'));l.addStretch();return w
    def ban(self):
        try:self.api.post('/owner-api/ip-ban',{'ip':self.ip.text().strip(),'reason':'Owner panel ban'})
        except Exception as e:self.err(e)
    def unban(self):
        try:self.api.delete('/owner-api/ip-ban/'+self.ip.text().strip())
        except Exception as e:self.err(e)
    def allow(self):
        try:self.api.post('/owner-api/vpn-allowlist',{'ip':self.ip.text().strip(),'note':'Owner allowlist'})
        except Exception as e:self.err(e)
    def unallow(self):
        try:self.api.delete('/owner-api/vpn-allowlist/'+self.ip.text().strip())
        except Exception as e:self.err(e)
    def tickets_tab(self):
        w=QWidget();l=QVBoxLayout(w);q=QPushButton('Refresh');q.clicked.connect(self.load_tickets);l.addWidget(q);self.tix=QTableWidget(0,7);self.tix.setHorizontalHeaderLabels(['ID','Title','Target','Status','Client UID','Pentester UID','Updated']);self.tix.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch);l.addWidget(self.tix);q.click();return w
    def load_tickets(self):
        try:
            rows=self.api.get('/owner-api/tickets');self.tix.setRowCount(len(rows))
            for r,t in enumerate(rows):
                for c,v in enumerate([t['id'],t['title'],t['target'],t['status'],t['owner_user_id'],t['assigned_pentester_id'] or '',t['updated_at']]):self.tix.setItem(r,c,QTableWidgetItem(str(v)))
        except Exception as e:self.err(e)
def main():
    a=QApplication(sys.argv)
    if not CFG.exists():QMessageBox.critical(None,'Missing config','Copy config.example.json to config.json and set your site URL.');return
    w=W();w.show();sys.exit(a.exec())
if __name__=='__main__':main()

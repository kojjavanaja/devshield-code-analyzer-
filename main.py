from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from pydantic import ValidationError
import csv, io, json, uuid, re
from app.core.config import APP_NAME, CORS_ORIGINS
from app.database.session import Base, engine, get_db
from app.models.models import User, Project, Scan, Finding, UserSetting, Notification, AuditLog
from app.schemas.schemas import RegisterIn, LoginIn, ProjectIn, ProjectPatch, ScanIn, UserPatch, SettingsPatch
from app.security.auth import hash_password, verify_password, create_token, current_user, admin_user
from app.analyzers.python_analyzer import analyze_python, score_risk

Base.metadata.create_all(bind=engine)
app=FastAPI(title=APP_NAME,version="1.0.0",description="DevShield static code analysis API")
app.add_middleware(CORSMiddleware,allow_origins=CORS_ORIGINS,allow_credentials=True,allow_methods=["GET","POST","PATCH","DELETE","OPTIONS"],allow_headers=["Authorization","Content-Type"])
@app.get("/health")
def health(): return {"status":"ok","service":"devshield-api"}
def audit(db,user,action,detail=""):
    db.add(AuditLog(user_id=user.id if user else None,action=action,detail=detail[:500]))
def owned_project(db,user_id,pid):
    p=db.query(Project).filter(Project.id==pid,Project.user_id==user_id).first()
    if not p: raise HTTPException(404,"Project not found")
    return p
def owned_scan(db,user_id,sid):
    s=db.query(Scan).filter(Scan.id==sid,Scan.user_id==user_id).first()
    if not s: raise HTTPException(404,"Scan not found")
    return s
@app.post("/api/auth/register",status_code=201)
def register(body:RegisterIn,db:Session=Depends(get_db)):
    email=body.email.lower()
    if db.query(User).filter(func.lower(User.email)==email).first(): raise HTTPException(409,"An account with this email already exists")
    user=User(name=body.name.strip(),email=email,password_hash=hash_password(body.password)); db.add(user); db.flush(); db.add(UserSetting(user_id=user.id)); audit(db,user,"register"); db.commit()
    return {"access_token":create_token(user.id),"token_type":"bearer","user":{"id":user.id,"name":user.name,"email":user.email,"role":user.role}}
@app.post("/api/auth/login")
def login(body:LoginIn,db:Session=Depends(get_db)):
    user=db.query(User).filter(func.lower(User.email)==body.email.lower()).first()
    if not user or not verify_password(body.password,user.password_hash): raise HTTPException(401,"Incorrect email or password")
    audit(db,user,"login"); db.commit(); return {"access_token":create_token(user.id),"token_type":"bearer","user":{"id":user.id,"name":user.name,"email":user.email,"role":user.role}}
@app.get("/api/auth/me")
def me(user:User=Depends(current_user)): return {"id":user.id,"name":user.name,"email":user.email,"role":user.role,"created_at":user.created_at}
@app.post("/api/auth/logout")
def logout(user:User=Depends(current_user),db:Session=Depends(get_db)):
    audit(db,user,"logout"); db.commit(); return {"message":"Logged out. Remove the access token from this browser."}
@app.get("/api/projects")
def list_projects(db:Session=Depends(get_db),user:User=Depends(current_user)):
    return [{"id":p.id,"name":p.name,"description":p.description,"language":p.language,"archived":p.archived,"created_at":p.created_at,"scan_count":len(p.scans)} for p in db.query(Project).filter(Project.user_id==user.id).order_by(desc(Project.created_at)).all()]
@app.post("/api/projects",status_code=201)
def create_project(body:ProjectIn,db:Session=Depends(get_db),user:User=Depends(current_user)):
    p=Project(user_id=user.id,name=body.name.strip(),description=body.description,language=body.language.lower()); db.add(p); audit(db,user,"project.created",p.name); db.commit(); db.refresh(p); return {"id":p.id,"name":p.name,"description":p.description,"language":p.language,"archived":p.archived,"created_at":p.created_at,"scan_count":0}
@app.get("/api/projects/{pid}")
def get_project(pid:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    p=owned_project(db,user.id,pid); return {"id":p.id,"name":p.name,"description":p.description,"language":p.language,"archived":p.archived,"created_at":p.created_at,"scans":[{"id":s.id,"filename":s.filename,"status":s.status,"risk_score":s.risk_score,"quality_score":s.quality_score,"created_at":s.created_at} for s in sorted(p.scans,key=lambda x:x.created_at,reverse=True)]}
@app.patch("/api/projects/{pid}")
def patch_project(pid:str,body:ProjectPatch,db:Session=Depends(get_db),user:User=Depends(current_user)):
    p=owned_project(db,user.id,pid)
    for k,v in body.model_dump(exclude_unset=True).items(): setattr(p,k,v)
    db.commit(); db.refresh(p); return {"id":p.id,"name":p.name,"description":p.description,"language":p.language,"archived":p.archived}
@app.delete("/api/projects/{pid}",status_code=204)
def delete_project(pid:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    p=owned_project(db,user.id,pid); db.delete(p); db.commit(); return Response(status_code=204)
@app.post("/api/scans",status_code=201)
def create_scan(body:ScanIn,db:Session=Depends(get_db),user:User=Depends(current_user)):
    if body.language.lower() not in {"python","py"}: raise HTTPException(422,"Fully supported analyzer currently targets Python. Other languages require a configured Semgrep integration.")
    if body.project_id: owned_project(db,user.id,body.project_id)
    filename=re.sub(r"[^a-zA-Z0-9_.-]","_",body.filename.split("/")[-1].split("\\")[-1])[:255] or "snippet.py"
    findings,metrics=analyze_python(body.code,filename); risk,category,factors=score_risk(findings,metrics)
    severity_weight={"critical":25,"high":15,"medium":7,"low":3,"info":1}; quality=max(0,round(100-min(100,sum(severity_weight.get(f["severity"],1) for f in findings)*1.5+metrics["cyclomatic_complexity"]*.5)))
    scan=Scan(user_id=user.id,project_id=body.project_id,filename=filename,language="python",source_code=body.code,status="completed",quality_score=quality,risk_score=risk,metrics={**metrics,"risk_category":category,"risk_factors":factors,"recommendations":[f["suggested_fix"] for f in findings[:8]]})
    db.add(scan); db.flush()
    for f in findings: db.add(Finding(scan_id=scan.id,rule_id=f["rule_id"],title=f["title"],severity=f["severity"],confidence=f["confidence"],line=f["line"],category=f["category"],description=f["description"],why_it_matters=f["why_it_matters"],suggested_fix=f["suggested_fix"],tool=f["tool"],fingerprint=f["fingerprint"]))
    db.add(Notification(user_id=user.id,title="Scan completed",message=f"{filename}: {len(findings)} finding(s), risk score {risk}/100.")); audit(db,user,"scan.completed",f"scan={scan.id}; findings={len(findings)}"); db.commit(); db.refresh(scan)
    return scan_payload(scan)
def scan_payload(s): return {"id":s.id,"project_id":s.project_id,"filename":s.filename,"language":s.language,"status":s.status,"quality_score":s.quality_score,"risk_score":s.risk_score,"metrics":s.metrics,"created_at":s.created_at,"finding_count":len(s.findings)}
@app.get("/api/scans")
def list_scans(page:int=Query(1,ge=1),limit:int=Query(20,ge=1,le=100),project_id:str|None=None,db:Session=Depends(get_db),user:User=Depends(current_user)):
    q=db.query(Scan).filter(Scan.user_id==user.id)
    if project_id: q=q.filter(Scan.project_id==project_id)
    total=q.count(); rows=q.order_by(desc(Scan.created_at)).offset((page-1)*limit).limit(limit).all(); return {"items":[scan_payload(s) for s in rows],"page":page,"limit":limit,"total":total}
@app.get("/api/scans/{sid}")
def get_scan(sid:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    s=owned_scan(db,user.id,sid); return {**scan_payload(s),"findings":[finding_payload(f) for f in s.findings]}
def finding_payload(f): return {"id":f.id,"rule_id":f.rule_id,"title":f.title,"severity":f.severity,"confidence":f.confidence,"line":f.line,"category":f.category,"description":f.description,"why_it_matters":f.why_it_matters,"suggested_fix":f.suggested_fix,"tool":f.tool,"fingerprint":f.fingerprint}
@app.get("/api/scans/{sid}/findings")
def scan_findings(sid:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    s=owned_scan(db,user.id,sid); return [finding_payload(f) for f in s.findings]
@app.get("/api/scans/{sid}/metrics")
def scan_metrics(sid:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    s=owned_scan(db,user.id,sid); return {"quality_score":s.quality_score,"risk_score":s.risk_score,**s.metrics}
@app.get("/api/scans/{sid}/status")
def scan_status(sid:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    s=owned_scan(db,user.id,sid); return {"id":s.id,"status":s.status}
@app.get("/api/analytics/dashboard")
def dashboard(db:Session=Depends(get_db),user:User=Depends(current_user)):
    projects=db.query(Project).filter(Project.user_id==user.id).count(); scans=db.query(Scan).filter(Scan.user_id==user.id).order_by(desc(Scan.created_at)).all(); allfind=[f for s in scans for f in s.findings]
    return {"total_projects":projects,"total_scans":len(scans),"critical_issues":sum(f.severity=="critical" for f in allfind),"security_findings":sum(f.category=="security" for f in allfind),"average_quality":round(sum(s.quality_score for s in scans)/len(scans),1) if scans else None,"average_risk":round(sum(s.risk_score for s in scans)/len(scans),1) if scans else None,"recent_scans":[scan_payload(s) for s in scans[:8]],"severity_distribution":{k:sum(f.severity==k for f in allfind) for k in ["critical","high","medium","low","info"]}}
@app.get("/api/analytics/trends")
@app.get("/api/analytics/code-health")
def trends(db:Session=Depends(get_db),user:User=Depends(current_user)):
    scans=db.query(Scan).filter(Scan.user_id==user.id).order_by(Scan.created_at).all(); return [{"scan_id":s.id,"date":s.created_at,"quality_score":s.quality_score,"risk_score":s.risk_score,"finding_count":len(s.findings),"complexity":s.metrics.get("cyclomatic_complexity",0)} for s in scans]
@app.get("/api/analytics/project/{pid}")
def project_analytics(pid:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    p=owned_project(db,user.id,pid); return {"project_id":p.id,"name":p.name,"timeline":[{"scan_id":s.id,"date":s.created_at,"quality_score":s.quality_score,"risk_score":s.risk_score,"finding_count":len(s.findings)} for s in sorted(p.scans,key=lambda x:x.created_at)]}
@app.get("/api/compare")
def compare(scan_a:str,scan_b:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    a=owned_scan(db,user.id,scan_a); b=owned_scan(db,user.id,scan_b)
    if a.project_id != b.project_id: raise HTTPException(400,"Compare scans from the same project")
    fa={f.fingerprint:f for f in a.findings}; fb={f.fingerprint:f for f in b.findings}
    return {"scan_a":scan_payload(a),"scan_b":scan_payload(b),"new_findings":[finding_payload(fb[k]) for k in fb.keys()-fa.keys()],"resolved_findings":[finding_payload(fa[k]) for k in fa.keys()-fb.keys()],"unchanged_count":len(fa.keys()&fb.keys()),"quality_delta":b.quality_score-a.quality_score,"risk_delta":b.risk_score-a.risk_score,"complexity_delta":b.metrics.get("cyclomatic_complexity",0)-a.metrics.get("cyclomatic_complexity",0)}
@app.post("/api/reports",status_code=201)
def create_report(payload:dict,db:Session=Depends(get_db),user:User=Depends(current_user)):
    sid=payload.get("scan_id")
    if not sid: raise HTTPException(422,"scan_id is required")
    s=owned_scan(db,user.id,sid); return {"report_id":s.id,"formats":["json","csv","pdf"],"download_urls":{fmt:f"/api/reports/{s.id}/download?format={fmt}" for fmt in ["json","csv","pdf"]}}
@app.get("/api/reports")
def reports(db:Session=Depends(get_db),user:User=Depends(current_user)):
    scans=db.query(Scan).filter(Scan.user_id==user.id).order_by(desc(Scan.created_at)).all(); return [{"id":s.id,"scan_id":s.id,"filename":s.filename,"created_at":s.created_at,"formats":["json","csv","pdf"]} for s in scans]
@app.get("/api/reports/{sid}/download")
def download_report(sid:str,format:str="json",db:Session=Depends(get_db),user:User=Depends(current_user)):
    s=owned_scan(db,user.id,sid); data={**scan_payload(s),"tool_versions":{"devshield":"1.0.0","python":"AST built-in"},"limitations":"Static heuristic analysis; findings are potential risks, not proof of exploitability.","findings":[finding_payload(f) for f in s.findings]}
    if format=="json": return JSONResponse(data,headers={"Content-Disposition":f'attachment; filename="devshield-{sid}.json"'})
    if format=="csv":
        out=io.StringIO(); w=csv.DictWriter(out,fieldnames=["rule_id","title","severity","line","category","description","suggested_fix"]); w.writeheader(); w.writerows(data["findings"]); return Response(out.getvalue(),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="devshield-{sid}.csv"'})
    if format=="pdf":
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        out=io.BytesIO(); doc=SimpleDocTemplate(out,pagesize=letter); styles=getSampleStyleSheet(); story=[Paragraph("DevShield Code Analysis Report",styles["Title"]),Paragraph(f"File: {s.filename} | Quality: {s.quality_score}/100 | Bug risk: {s.risk_score}/100",styles["Normal"]),Spacer(1,12),Paragraph("Findings",styles["Heading2"])]
        rows=[["Severity","Line","Finding"]]+[[f.severity,str(f.line),f.title[:80]] for f in s.findings]
        table=Table(rows,repeatRows=1); table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#332B34")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.4,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP")])); story.append(table); story.append(Spacer(1,10)); story.append(Paragraph("Heuristic score only. Static findings are potential risks, not proof of exploitability.",styles["Normal"])); doc.build(story); return Response(out.getvalue(),media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="devshield-{sid}.pdf"'})
    raise HTTPException(400,"format must be json, csv or pdf")
@app.get("/api/users/me")
def get_user(user:User=Depends(current_user)): return {"id":user.id,"name":user.name,"email":user.email,"role":user.role,"created_at":user.created_at}
@app.patch("/api/users/me")
def patch_user(body:UserPatch,db:Session=Depends(get_db),user:User=Depends(current_user)):
    user.name=body.name.strip(); db.commit(); return {"id":user.id,"name":user.name,"email":user.email,"role":user.role}
@app.get("/api/settings")
def get_settings(db:Session=Depends(get_db),user:User=Depends(current_user)):
    s=db.query(UserSetting).filter_by(user_id=user.id).first()
    if not s: s=UserSetting(user_id=user.id); db.add(s); db.commit(); db.refresh(s)
    return {"theme":s.theme,"default_language":s.default_language,"notifications":s.notifications}
@app.patch("/api/settings")
def patch_settings(body:SettingsPatch,db:Session=Depends(get_db),user:User=Depends(current_user)):
    s=db.query(UserSetting).filter_by(user_id=user.id).first()
    if not s: s=UserSetting(user_id=user.id); db.add(s)
    s.theme=body.theme if body.theme in {"midnight-plum","light-plum"} else "midnight-plum"; s.default_language=body.default_language; s.notifications=body.notifications; db.commit(); return {"theme":s.theme,"default_language":s.default_language,"notifications":s.notifications}
@app.get("/api/notifications")
def notifications(db:Session=Depends(get_db),user:User=Depends(current_user)):
    return [{"id":n.id,"title":n.title,"message":n.message,"read":n.read,"created_at":n.created_at} for n in db.query(Notification).filter_by(user_id=user.id).order_by(desc(Notification.created_at)).limit(100).all()]
@app.patch("/api/notifications/{nid}/read")
def read_notification(nid:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    n=db.query(Notification).filter_by(id=nid,user_id=user.id).first()
    if not n: raise HTTPException(404,"Notification not found")
    n.read=True; db.commit(); return {"id":n.id,"read":True}
@app.get("/api/admin/overview")
def admin_overview(db:Session=Depends(get_db),user:User=Depends(admin_user)):
    return {"users":db.query(User).count(),"projects":db.query(Project).count(),"scans":db.query(Scan).count(),"failed_scans":db.query(Scan).filter_by(status="failed").count()}
@app.get("/api/admin/users")
def admin_users(db:Session=Depends(get_db),user:User=Depends(admin_user)):
    return [{"id":u.id,"name":u.name,"email":u.email,"role":u.role,"created_at":u.created_at,"project_count":len(u.projects)} for u in db.query(User).order_by(desc(User.created_at)).limit(200).all()]
@app.get("/api/admin/scans")
def admin_scans(db:Session=Depends(get_db),user:User=Depends(admin_user)):
    return [{"id":s.id,"user_id":s.user_id,"filename":s.filename,"status":s.status,"created_at":s.created_at} for s in db.query(Scan).order_by(desc(Scan.created_at)).limit(200).all()]
@app.get("/api/admin/audit-logs")
def admin_logs(db:Session=Depends(get_db),user:User=Depends(admin_user)):
    return [{"id":a.id,"user_id":a.user_id,"action":a.action,"detail":a.detail,"created_at":a.created_at} for a in db.query(AuditLog).order_by(desc(AuditLog.created_at)).limit(200).all()]

from typing import List
import datetime
import re
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import FileResponse
from fastapi import Depends, FastAPI, HTTPException,status,UploadFile,File,Query,Form
from flask import flash
from sqlalchemy.orm import Session
from . import crud, models, schemas
from .database import SessionLocal, engine
from datetime import datetime,date
import secrets
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware

description = """
_Online Job Portal helps to connect employers with candidates in order to meet their requirements and goals._

## Employers

They can:

* **Create account**.
* **View profile**.
* **Update profile**.
* **Post jobs**.
* **Get posted jobs list**.
* **Get candidates list for particular job**.
* **Download candidates resume**.
* **Schedule Interview**.
* **View all interview schedules**.
* **Search candidates by skills**.

## Candidates

They can:

* **Create account**.
* **View profile**.
* **Update profile**.
* **View jobs**.
* **Search jobs**.
* **Apply for jobs and upload resume**.
* **View/Download resume**.
* **Update their resume**.
* **Get list of applied jobs**.
* **View interview schedules**.

## Admin

Admin can:

* **View all employers**.
* **Search employer by id**.
* **Delete employer**.
* **View all candidates**.
* **Search candidate by id**.
* **Delete candidate**.
* **View jobs**.
* **Delete job**.
* **View interview schedules**.

"""

models.Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Online Job Portal",description=description)

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
security=HTTPBasic()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_current_employer(credentials: HTTPBasicCredentials = Depends(security),db: Session = Depends(get_db)):
    db_employer=crud.get_employer_by_email(db,email=credentials.username)
    if db_employer:
        # correct_username = secrets.compare_digest(credentials.username, db_employer.email)
        # correct_password = secrets.compare_digest(password, db_employer.hashed_password)
        if not verify_password(credentials.password,db_employer.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Basic"},
            )
    if db_employer is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid user!!")
    return db_employer

def get_current_candidate(credentials: HTTPBasicCredentials = Depends(security),db: Session = Depends(get_db)):
    db_candidate=crud.get_candidate_by_email(db,email=credentials.username)
    if db_candidate:
        # correct_username = secrets.compare_digest(credentials.username, db_candidate.email)
        # correct_password = secrets.compare_digest(password, db_candidate.hashed_password)
        if not verify_password(credentials.password,db_candidate.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Basic"},
            )
    if db_candidate is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid user!!")
    return db_candidate

def get_admin(credentials: HTTPBasicCredentials = Depends(security),db: Session = Depends(get_db)):
    db_admin=crud.get_admin(db,userid=credentials.username)
    if db_admin:
        correct_username = secrets.compare_digest(credentials.username, db_admin.userid)
        correct_password = secrets.compare_digest(credentials.password, db_admin.password)
        if not (correct_username and correct_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"},
            )
    if db_admin is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid user!!")
    return db_admin

# welcome to job portal

@app.get("/welcome/",tags=["welcome"],responses={200: {
            "content": {"image/png": {}},
            "description": "Return an image.",
        }
    },)
def welcome_to_job_portal():
    return FileResponse("job_portal/images/OnlineJobPortal.png",media_type="image/png")

# employers


@app.post("/employers/create/", response_model=schemas.Employer,tags=["employers"],status_code=201,responses={201: {
            "content": {"image/png": {}},
            "description": "Return an image.",
        }
    },)
def create_employer(employer: schemas.EmployerCreate, db: Session = Depends(get_db)):
    db_employer = crud.get_employer_by_email1(db, email=employer.email)
    if db_employer:
        raise HTTPException(status_code=409, detail="Email already registered")
    if employer.name=="" or employer.contact=="" or employer.designation=="" or employer.email=="" or employer.address==""\
            or employer.company_name=="" or employer.password=="":
        raise HTTPException(status_code=422,detail="Fields can't be empty!!")
    if (bool(re.match('^[a-zA-Z. ]*$', employer.name)) == False):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid value for name!!")
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if not (re.fullmatch(email_pattern, employer.email)):
        raise HTTPException(status_code=422, detail="Invalid Email format!!")
    if (bool(re.match('^[a-zA-Z. ]*$', employer.company_name)) == False):
        raise HTTPException(status_code=422, detail="Invalid value for company_name!!")
    if (bool(re.match('^[a-zA-Z. ]*$', employer.designation)) == False):
        raise HTTPException(status_code=422, detail="Invalid value for designation!!")
    x = re.findall("\D", employer.contact)
    if x:
        raise HTTPException(status_code=422, detail="Enter only digits!!")
    if len(employer.contact) < 10 or len(employer.contact) > 10:
        raise HTTPException(status_code=422, detail="Contact should be of 10 digits!!")
    if len(employer.password)<8:
        raise HTTPException(status_code=422,detail="Password should be of minimum 8 characters!!")
    crud.create_employer(db=db, employer=employer)
    return FileResponse("job_portal/images/welcome.png", media_type="image/png",status_code=201)

@app.get("/employers/welcome-Employers/",tags=["employers"],responses={200: {
            "content": {"image/gif": {}},
            "description": "Return an image.",
        }
    },dependencies=[Depends(get_current_employer)])
def welcome_employers():
    return FileResponse("job_portal/images/emp1.gif",media_type="image/gif")

@app.post("/employers/login",tags=["employers"])
def employer_login(username:str=Form(...),password:str=Form(...),db:Session=Depends(get_db)):
    db_employer = crud.get_employer_by_email(db, email=username)
    if db_employer:
        if not verify_password(password, db_employer.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Basic"},
            )
    if db_employer is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user!!")
    return {"message":"Logged in Successfully!!"}

@app.get("/employers/me/", response_model=schemas.Employer,tags=["employers"],status_code=200)
def view_your_profile(current_employer: schemas.Employer = Depends(get_current_employer)):
    return current_employer

@app.put("/employers/update",dependencies=[Depends(get_current_employer)],status_code=200,tags=["employers"])
def update_profile(employer:schemas.EmployerUpdate,emp_update:schemas.Employer=Depends(get_current_employer),db:Session=Depends(get_db)):
    emp_id=emp_update.emp_id
    # employer.contact=emp_update.contact
    # employer.company_name=emp_update.company_name
    db_employer=crud.get_employer(db=db,emp_id=emp_id)
    if db_employer is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Employer with id:{emp_id} does not exist!!")

    if employer.name!=None:
        if employer.name =="":
            raise HTTPException(status_code=422, detail="Fields can't be empty!!")
        if (bool(re.match('^[a-zA-Z. ]*$', employer.name)) == False):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid value for name!!")
        crud.update_employer(db,employer=employer,emp_id=emp_id)
    if employer.designation!=None:
        if employer.designation == "":
            raise HTTPException(status_code=422, detail="Fields can't be empty!!")
        if (bool(re.match('^[a-zA-Z. ]*$', employer.designation)) == False):
            raise HTTPException(status_code=422, detail="Invalid value for designation!!")
        crud.update_employer(db,employer=employer,emp_id=emp_id)
    if employer.company_name!=None:
        if employer.company_name == "":
            raise HTTPException(status_code=422, detail="Fields can't be empty!!")
        if (bool(re.match('^[a-zA-Z. ]*$', employer.company_name)) == False):
            raise HTTPException(status_code=422, detail="Invalid value for company_name!!")
        crud.update_employer(db,employer=employer,emp_id=emp_id)
    if employer.contact!=None:
        if employer.contact == "":
            raise HTTPException(status_code=422, detail="Fields can't be empty!!")
        x = re.findall("\D", employer.contact)
        if x:
            raise HTTPException(status_code=422, detail="Enter only digits!!")
        if len(employer.contact) < 10 or len(employer.contact) > 10:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,detail="Contact should be of 10 digits!!")
        crud.update_employer(db,employer=employer,emp_id=emp_id)
    if employer.address!=None:
        if employer.address == "":
            raise HTTPException(status_code=422, detail="Fields can't be empty!!")
        crud.update_employer(db,employer=employer,emp_id=emp_id)

    return {"message":"Successfully Updated!!"}

@app.get("/employers/jobs/",dependencies=[Depends(get_current_employer)],tags=["employers"])
def get_posted_jobs(employer:schemas.Employer=Depends(get_current_employer),db:Session=Depends(get_db)):
    emp_id=employer.emp_id
    db_jobs=crud.get_posted_jobs(db,emp_id=emp_id)
    if db_jobs ==[]:
        raise HTTPException(status_code=400,detail="No jobs posted!!")
    return db_jobs

@app.get("/employers/{job_id}",dependencies=[Depends(get_current_employer)],tags=["employers"])
def view_candidates(job_id:int,employer: schemas.Employer = Depends(get_current_employer),db:Session=Depends(get_db)):
    if job_id<1:
        raise HTTPException(status_code=422,detail="Job id can't be 0 or negative!!!")
    emp_id = employer.emp_id
    db_job = crud.get_job(db, job_id=job_id)
    if db_job is None:
        raise HTTPException(status_code=404, detail=f"Job with id: {job_id} does not exist!!")
    check_job = crud.check_posted_jobs(db, job_id=job_id, emp_id=emp_id)
    if check_job is None:
        raise HTTPException(status_code=400, detail="This job is not posted by you!!You can view applied candidates "
                                                    "only for jobs posted by you!!")
    db_apply=crud.get_applied_candidates(db,job_id=job_id)
    if db_apply==[]:
        raise HTTPException(status_code=404,detail="No Candidates found!!")
    return db_apply

@app.post("/employers/interview/", response_model=schemas.Interview,tags=["employers"],status_code=201,
          dependencies=[Depends(get_current_employer)])
def schedule_interview(job_id:int,cand_id:int,interview: schemas.InterviewCreate,
                       employer: schemas.Employer = Depends(get_current_employer),db: Session = Depends(get_db)):
    if job_id<1:
        raise HTTPException(status_code=422,detail="Job id can't be 0 or negative!!!")
    emp_id = employer.emp_id
    db_job = crud.get_job(db, job_id=job_id)
    if db_job is None:
        raise HTTPException(status_code=404, detail=f"Job with id: {job_id} does not exist!!")
    check_job=crud.check_posted_jobs(db,job_id=job_id,emp_id=emp_id)
    if check_job is None:
        raise HTTPException(status_code=400,detail="This job is not posted by you!!You can schedule interview "
                                                   "only for jobs posted by you!!")
    db_cand=crud.get_candidate(db,cand_id=cand_id)
    if db_cand is None:
        raise HTTPException(status_code=404,detail=f"Candidate with id: {cand_id} does not exist!!")
    check_apply_job=crud.get_apply_info(db,job_id=job_id,cand_id=cand_id)
    if check_apply_job is None:
        raise HTTPException(status_code=400,detail="This candidate has not applied for this job!!")
    db_interview_schedule=crud.check_interview_schedule(db,job_id=job_id,cand_id=cand_id)
    if db_interview_schedule:
        raise HTTPException(status_code=409,detail="You have already scheduled an interview for this candidate!!")
    if interview.venue=="" or interview.day=="" or interview.time=="" or interview.message=="":
        raise HTTPException(status_code=422,detail="Fields can't be empty!!")
    if interview.venue=="string":
        raise HTTPException(status_code=422,detail="Enter valid venue!!")
    if interview.message=="string":
        raise HTTPException(status_code=422,detail="Enter valid message!!")
    if (bool(re.match(
            '^([1-9]|0[1-9]|1[0-9]|2[0-9]|3[0-1])(\.|-|/)([1-9]|0[1-9]|1[0-2])(\.|-|/)([0-9][0-9]|19[0-9][0-9]|20[0-9][0-9])$|^([0-9][0-9]|19[0-9][0-9]|20[0-9][0-9])(\.|-|/)([1-9]|0[1-9]|1[0-2])(\.|-|/)([1-9]|0[1-9]|1[0-9]|2[0-9]|3[0-1])$',
            interview.day)) == False):
        raise HTTPException(status_code=422, detail="Invalid date format!!Correct format is yyyy-mm-dd!!")
    time_re = re.compile(r'^(([01]\d|2[0-3]):([0-5]\d)|24:00)$')

    if bool(time_re.match(interview.time))==False:
        raise HTTPException(status_code=422,detail="Invalid time format!!Correct time format is from 00:00 to 24:00")
    return crud.create_interview(db=db, interview=interview,job_id=job_id,cand_id=cand_id,emp_id=emp_id)

@app.get("/employers/interview-schedules/",tags=["employers"],dependencies=[Depends(get_current_employer)])
def view_all_interview_schedules(employer:schemas.Employer=Depends(get_current_employer),db:Session=Depends(get_db)):
    emp_id=employer.emp_id
    db_interview=crud.get_all_interview_schedules(emp_id=emp_id,db=db)
    if db_interview==[]:
        raise HTTPException(status_code=404,detail="No interview scheduled yet!!")
    return db_interview

@app.get("/employers/{skills}/",dependencies=[Depends(get_current_employer)],tags=["employers"])
def search_candidates_by_skills(skills:str, db: Session = Depends(get_db)):
    db_cand = crud.get_candidate_by_skills(db, skills=skills)
    if (bool(re.match('^[a-zA-Z#+]*$', skills)) == False):
        raise HTTPException(status_code=422, detail="Enter valid skills!!")
    if db_cand == []:
        raise HTTPException(status_code=404, detail="No candidates found having this skill!!")

    return db_cand

@app.post("/employers/download-resume/",dependencies=[Depends(get_current_employer)],tags=["employers"])
def download_candidate_resume(cand_id:int,db:Session=Depends(get_db)):
    if cand_id<1:
        raise HTTPException(status_code=422,detail="Candidate id can't be 0 or negative!!!")
    db_cand=crud.get_candidate(db,cand_id=cand_id)
    if db_cand is None:
        raise HTTPException(status_code=404,detail=f"Candidate with id:{cand_id} does not exist!!")
    if db_cand.resume is None:
        raise HTTPException(status_code=400,detail="This candidate has not uploaded resume!!")
    resume=db_cand.resume
    return FileResponse(f'job_portal/files/{resume}',media_type="application/pdf",filename=resume)

# candidates


@app.post("/candidates/create/", response_model=schemas.Candidate,tags=["candidates"],status_code=201,
          description="Maximum 4 skills allowed",responses={201: {
            "content": {"image/png": {}},
            "description": "Return an image.",
        }
    },)
def create_candidate(candidate: schemas.CandidateCreate,skills:List[str]=Query(...), db: Session = Depends(get_db)):
    db_candidate = crud.get_candidate_by_email1(db, email=candidate.email)
    if db_candidate:
        raise HTTPException(status_code=409, detail="Email already registered")
    if candidate.name=="" or candidate.contact=="" or candidate.dob=="" or candidate.email=="" or candidate.address==""\
            or candidate.grad=="" or candidate.post_grad=="" or candidate.password=="" : #or candidate.skills=="":
        raise HTTPException(status_code=422,detail="Fields can't be empty!!")
    if (bool(re.match('^[a-zA-Z. ]*$', candidate.name)) == False):
        raise HTTPException(status_code=422, detail="Invalid value for name!!")
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if not (re.fullmatch(email_pattern, candidate.email)):
        raise HTTPException(status_code=422, detail="Invalid Email format!!")
    if (bool(re.match('^[a-zA-Z. ]*$', candidate.grad)) == False):
        raise HTTPException(status_code=422, detail="Invalid value for grad!!")
    if (bool(re.match('^[a-zA-Z. ]*$', candidate.post_grad)) == False):
        raise HTTPException(status_code=422, detail="Invalid value for post_grad!!")
    # if (bool(re.match('^[a-zA-Z]*$',i for i in candidate.skills)) == False):
    #     raise HTTPException(status_code=422, detail="Invalid value for skills!!")
    if (bool(re.match(
            '^([1-9]|0[1-9]|1[0-9]|2[0-9]|3[0-1])(\.|-|/)([1-9]|0[1-9]|1[0-2])(\.|-|/)([0-9][0-9]|19[0-9][0-9]|20[0-9][0-9])$|^([0-9][0-9]|19[0-9][0-9]|20[0-9][0-9])(\.|-|/)([1-9]|0[1-9]|1[0-2])(\.|-|/)([1-9]|0[1-9]|1[0-9]|2[0-9]|3[0-1])$',
            candidate.dob)) == False):
        raise HTTPException(status_code=422, detail="Invalid dob format!!Correct format is yyyy-mm-dd!!")
    x = re.findall("\D", candidate.contact)
    if x:
        raise HTTPException(status_code=422, detail="Enter only digits!!")
    if len(candidate.contact) < 10 or len(candidate.contact) > 10:
        raise HTTPException(status_code=422, detail="Contact should be of 10 digits!!")
    if len(candidate.password)<8:
        raise HTTPException(status_code=422,detail="Password should be of minimum 8 characters!!")

    len_of_skills=len(skills)
    skill1=skill2=skill3=skill4=""
    if len_of_skills==1:
        if skills[0] == "string":
            raise HTTPException(status_code=422, detail="Enter valid skills!!")
        skill1=skills[0]
    if len_of_skills==2:
        if skills[0] == "string" or skills[1]=="string":
            raise HTTPException(status_code=422, detail="Enter valid skills!!")
        skill1=skills[0]
        skill2=skills[1]
    if len_of_skills==3:
        if skills[0] == "string" or skills[1] == "string" or skills[2] == "string":
            raise HTTPException(status_code=422, detail="Enter valid skills!!")
        skill1 = skills[0]
        skill2 = skills[1]
        skill3=skills[2]
    if len_of_skills==4:
        if skills[0] == "string" or skills[1] == "string" or skills[2] == "string" or skills[3] == "string":
            raise HTTPException(status_code=422, detail="Enter valid skills!!")
        skill1 = skills[0]
        skill2 = skills[1]
        skill3 = skills[2]
        skill4=skills[3]
    if skills==[]:
        raise HTTPException(status_code=422,detail="Please enter at least one skill!!")
    if len_of_skills>4:
        raise HTTPException(status_code=422,detail="Only 4 skills allowed")
    db_cand = crud.create_candidate(db=db, candidate=candidate)
    db_cand_id = db_cand.cand_id
    crud.create_cand_skills(db, cand_id=db_cand_id, skill1=skill1,
                                        skill2=skill2,
                                        skill3=skill3,
                                        skill4=skill4)
    return FileResponse("job_portal/images/wel2.png", media_type="image/png",status_code=201)

@app.get("/welcome_Candidates/",tags=["candidates"],responses={200: {
            "content": {"image/gif": {}},
            "description": "Return an image.",
        }
    },dependencies=[Depends(get_current_candidate)])
def welcome_candidates():
    return FileResponse("job_portal/images/cand5.gif",media_type="image/gif")

@app.post("/candidates/login",tags=["candidates"])
def candidate_login(username:str=Form(...),password:str=Form(...),db:Session=Depends(get_db)):
    db_candidate = crud.get_candidate_by_email(db, email=username)
    if db_candidate:
        if not verify_password(password, db_candidate.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Basic"},
            )
    if db_candidate is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user!!")
    return {"message":"Logged in Successfully!!"}

@app.get("/candidates/me/", response_model=schemas.Candidate,tags=["candidates"],status_code=200)
def view_your_profile(current_candidate: schemas.Candidate = Depends(get_current_candidate)):
    return current_candidate

@app.put("/candidates/update",dependencies=[Depends(get_current_candidate)],status_code=200,tags=["candidates"])
def update_profile(candidate:schemas.CandidateUpdate,skills:List[str]=Query(None),cand_update:schemas.Candidate=Depends(get_current_candidate),
                   db:Session=Depends(get_db)):
    cand_id=cand_update.cand_id
    db_candidate=crud.get_candidate(db=db,cand_id=cand_id)
    if db_candidate is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Candidate with id:{cand_id} does not exist!!")

    if candidate.name!=None:
        if candidate.name == "":
            raise HTTPException(status_code=422, detail="Fields can't be empty!!")
        if (bool(re.match('^[a-zA-Z. ]*$', candidate.name)) == False):
            raise HTTPException(status_code=422, detail="Invalid value for name!!")
        crud.update_candidate(db,candidate=candidate,cand_id=cand_id)

    if candidate.grad!=None:
        if candidate.grad == "":
            raise HTTPException(status_code=422, detail="Fields can't be empty!!")
        if (bool(re.match('^[a-zA-Z. ]*$', candidate.grad)) == False):
            raise HTTPException(status_code=422, detail="Invalid value for grad!!")
        crud.update_candidate(db,candidate=candidate,cand_id=cand_id)
    if candidate.post_grad != None:
        if candidate.post_grad == "":
            raise HTTPException(status_code=422, detail="Fields can't be empty!!")
        if (bool(re.match('^[a-zA-Z. ]*$', candidate.post_grad)) == False):
            raise HTTPException(status_code=422, detail="Invalid value for post_grad!!")
        crud.update_candidate(db, candidate=candidate, cand_id=cand_id)

    if skills!=None:
        len_of_skills = len(skills)
        skills_list=crud.get_cand_skills(db,cand_id=cand_id)
        skill1 = skills_list.skill1
        skill2 = skills_list.skill2
        skill3 = skills_list.skill3
        skill4 = skills_list.skill4
        if len_of_skills == 1:
            if skills[0] == "string":
                raise HTTPException(status_code=422, detail="Enter valid skills!!")
            skill1 = skills[0]
        if len_of_skills == 2:
            if skills[0] == "string" or skills[1] == "string":
                raise HTTPException(status_code=422, detail="Enter valid skills!!")
            skill1 = skills[0]
            skill2 = skills[1]
        if len_of_skills == 3:
            if skills[0] == "string" or skills[1] == "string" or skills[2] == "string":
                raise HTTPException(status_code=422, detail="Enter valid skills!!")
            skill1 = skills[0]
            skill2 = skills[1]
            skill3 = skills[2]
        if len_of_skills == 4:
            if skills[0] == "string" or skills[1] == "string" or skills[2] == "string" or skills[3] == "string":
                raise HTTPException(status_code=422, detail="Enter valid skills!!")
            skill1 = skills[0]
            skill2 = skills[1]
            skill3 = skills[2]
            skill4 = skills[3]
        if skills == []:
            raise HTTPException(status_code=422, detail="Please enter at least one skill!!")
        if len_of_skills > 4:
            raise HTTPException(status_code=422, detail="Only 4 skills allowed")
        crud.update_cand_skills(db,skill1=skill1,skill2=skill2,skill3=skill3,skill4=skill4,cand_id=cand_id)

    if candidate.contact!=None:
        if candidate.contact == "":
            raise HTTPException(status_code=422, detail="Fields can't be empty!!")
        x = re.findall("\D", candidate.contact)
        if x:
            raise HTTPException(status_code=422, detail="Enter only digits!!")
        if len(candidate.contact) < 10 or len(candidate.contact) > 10:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,detail="Contact should be of 10 digits!!")
        crud.update_candidate(db,candidate=candidate,cand_id=cand_id)
    if candidate.address!=None:
        if candidate.address == "":
            raise HTTPException(status_code=422, detail="Fields can't be empty!!")
        crud.update_candidate(db,candidate=candidate,cand_id=cand_id)
    return {"message":"Successfully Updated!!"}

@app.get("/candidates/interview-call/",dependencies=[Depends(get_current_candidate)],tags=["candidates"])
def view_interview_schedules(candidate:schemas.Candidate=Depends(get_current_candidate),db:Session=Depends(get_db)):
    cand_id=candidate.cand_id
    db_interview=crud.get_interview_info(db,cand_id=cand_id)
    if db_interview ==[]:
        raise HTTPException(status_code=404,detail="No interview scheduled!!")
    return db_interview

@app.post("/candidates/download-resume/",dependencies=[Depends(get_current_candidate)],tags=["candidates"])
def view_resume(candidate:schemas.Candidate=Depends(get_current_candidate),db:Session=Depends(get_db)):
    cand_id=candidate.cand_id
    db_cand=crud.get_candidate(db,cand_id=cand_id)
    if db_cand.resume is None:
        raise HTTPException(status_code=400,detail="You have not uploaded resume!!")
    resume=db_cand.resume
    return FileResponse(f'job_portal/files/{resume}',media_type="application/pdf",filename=resume)

@app.put("/candidates/update-resume/",dependencies=[Depends(get_current_candidate)],tags=["candidates"])
def update_resume(resume:UploadFile=File(...),candidate: schemas.Candidate = Depends(get_current_candidate),
                  db:Session=Depends(get_db)):
    cand_id=candidate.cand_id
    if resume.content_type not in ["application/pdf","application/vnd.openxmlformats-officedocument.wordprocessingml.document"]:
        raise HTTPException(400, detail="Only pdf and doc file accepted!!")
    crud.update_resume(db,cand_id=cand_id,resume=resume.filename)
    file_location = f"job_portal/files/{resume.filename}"
    with open(file_location, "wb+") as file_object:
        file_object.write(resume.file.read())
    return "Resume successfully updated!!"


# jobs

@app.get("/Find-Jobs/",tags=["jobs"],responses={200: {
            "content": {"image/jpg": {}},
            "description": "Return an image.",
        }
    },)
def find_jobs_here():
    return FileResponse("job_portal/images/img3.jpg",media_type="image/jpg")

@app.get("/jobs/{job_id}", response_model=schemas.Jobs,tags=["jobs"])
def get_job_by_id(job_id: int, db: Session = Depends(get_db)):
    if job_id<1:
        raise HTTPException(status_code=422,detail="Job id can't be 0 or negative!!!")
    db_job = crud.get_job(db, job_id=job_id)
    if db_job is None:
        raise HTTPException(status_code=404, detail=f"Job with id: {job_id} does not exist!!")
    return db_job

@app.post("/employers/jobs/", response_model=schemas.Jobs,tags=["employers"],status_code=201,
          dependencies=[Depends(get_current_employer)])
def post_job(job: schemas.JobCreate,employer: schemas.Employer = Depends(get_current_employer),db: Session = Depends(get_db)):
    emp_id=employer.emp_id
    if job.title=="" or job.post=="" or job.company_name=="" or job.job_location=="" or job.description==""\
            or job.annual_salary_in_lakhs=="" or job.apply_to=="" or job.apply_from=="":
        raise HTTPException(status_code=422,detail="Fields can't be empty!!")
    if (bool(re.match('^[a-zA-Z. ]*$', job.title)) == False):
        raise HTTPException(status_code=422, detail="Invalid value for title!!")
    if (bool(re.match('^[a-zA-Z. ]*$', job.post)) == False):
        raise HTTPException(status_code=422, detail="Invalid value for post!!")
    if (bool(re.match('^[a-zA-Z. ]*$', job.description)) == False):
        raise HTTPException(status_code=422, detail="Invalid value for description!!")
    if (bool(re.match('^[a-zA-Z. ]*$', job.company_name)) == False):
        raise HTTPException(status_code=422, detail="Invalid value for company_name!!")
    if (bool(re.match('^[0-9.]*$', job.annual_salary_in_lakhs)) == False):
        raise HTTPException(status_code=422, detail="Invalid value for annual salary!!")
    if (bool(re.match('^[a-zA-Z. ]*$', job.job_location)) == False):
        raise HTTPException(status_code=422, detail="Invalid value for job location!!")
    return crud.create_job(db=db, job=job, emp_id=emp_id)
    
@app.get("/jobs/", response_model=List[schemas.Jobs],tags=["jobs"])
def get_all_jobs(db: Session = Depends(get_db)):
    jobs = crud.get_jobs(db)
    if jobs==[]:
        raise HTTPException(status_code=404,detail="No Jobs Found!!")
    return jobs

@app.get("/jobs/{title}/",tags=["jobs"],status_code=200)
def search_job_by_title(title:str, db: Session = Depends(get_db)):
    db_job = crud.get_jobs_by_title(db, title=title)
    if db_job==[]:
        raise HTTPException(status_code=404, detail=f"No results found on title: {title} !!")
    return db_job


@app.get("/candidates/jobs/",dependencies=[Depends(get_current_candidate)],tags=["candidates"])
def get_applied_jobs(candidate:schemas.Candidate=Depends(get_current_candidate),db:Session=Depends(get_db)):
    cand_id=candidate.cand_id
    db_apply=crud.get_applied_jobs(db,cand_id=cand_id)
    if db_apply==[]:
        raise HTTPException(status_code=404,detail="Not applied for any job!!")
    return db_apply

#apply

@app.post("/candidates/{job_id}/",status_code=201,tags=["candidates"],dependencies=[Depends(get_current_candidate)])
def apply_for_job(job_id:int,resume:UploadFile=File(...),candidate: schemas.Candidate = Depends(get_current_candidate),
                  db:Session=Depends(get_db)):
    if job_id<1:
        raise HTTPException(status_code=422,detail="Job id can't be 0 or negative!!!")
    cand_id=candidate.cand_id
    db_job = crud.get_job(db, job_id=job_id)

    if db_job is None:
        raise HTTPException(status_code=404, detail=f"Job with id: {job_id} does not exist!!")
    db_apply = crud.get_apply_info(db, job_id=job_id, cand_id=cand_id)
    if db_apply:
        raise HTTPException(status_code=409,detail="Already Applied for this job!!")
    current_date=datetime.date(datetime.now())
    # apply_date=datetime(datetime.date(db_job.apply_to))
    if (current_date) < (db_job.apply_from) or (current_date) is (db_job.apply_from):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Sorry!! apply date not started!!")
    if (current_date) > (db_job.apply_to) or (current_date) is (db_job.apply_to):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Sorry!! apply date is over!!")
    if resume.content_type not in ["application/pdf","application/vnd.openxmlformats-officedocument.wordprocessingml.document"]:
        raise HTTPException(400, detail="Only pdf and doc file accepted!!")
    file_location = f"job_portal/files/{resume.filename}"
    with open(file_location, "wb+") as file_object:
        file_object.write(resume.file.read())
    crud.apply_job(db=db,job_id=job_id,cand_id=cand_id,resume=resume.filename)
    return "Successfully Applied!!"

# Admin

@app.post("/admin/login/",tags=["admin"])
def admin_login(username:str=Form(...),password:str=Form(...),db:Session=Depends(get_db)):
    db_admin = crud.get_admin(db, userid=username,password=password)
    if db_admin is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials!!")
    return {"message":"Logged in Successfully!!"}

@app.get("/welcome_Admin/",tags=["admin"],dependencies=[Depends(get_admin)],responses={200: {
            "content": {"image/jpg": {}},
            "description": "Return an image.",
        }
    })
def welcome_admin():
    return FileResponse("job_portal/images/emp4.jpg",media_type="image/jpg")

           #employers

@app.get("/admin/employers/", response_model=List[schemas.Employer],tags=["admin"],dependencies=[Depends(get_admin)])
def get_all_employers(db: Session = Depends(get_db)):
    employers = crud.get_employers(db)
    if employers==[]:
        raise HTTPException(status_code=404,detail="No Employers Found")
    return employers

@app.get("/admin/employers/{emp_id}/", response_model=schemas.Employer,tags=["admin"],dependencies=[Depends(get_admin)])
def get_employer_by_id(emp_id: int, db: Session = Depends(get_db)):
    if emp_id<1:
        raise HTTPException(status_code=422,detail="Employer id can't be 0 or negative!!!")
    db_employer = crud.get_employer(db, emp_id=emp_id)
    if db_employer is None:
        raise HTTPException(status_code=404, detail=f"Employer with id: {emp_id} does not exist!!")
    return db_employer

@app.delete("/admin/employers/{emp_id}",dependencies=[Depends(get_admin)],tags=["admin"])
def delete_employer(emp_id:int,db:Session=Depends(get_db)):
    if emp_id<1:
        raise HTTPException(status_code=422,detail="Employer id can't be 0 or negative!!!")
    db_employer=crud.get_employer(db,emp_id=emp_id)
    if db_employer is None or db_employer.status==0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Employer with id: {emp_id} does not exist!!")
    crud.delete_employer(db,emp_id=emp_id)
    return "Successfully Deleted!!"

        # candidates


@app.get("/admin/candidates/", response_model=List[schemas.Candidate],tags=["admin"],dependencies=[Depends(get_admin)])
def get_all_candidates(db: Session = Depends(get_db)):
    candidates = crud.get_candidates(db)
    if candidates==[]:
        raise HTTPException(status_code=404,detail="No Candidates Found!!")
    return candidates

@app.get("/admin/candidates/{cand_id}/", response_model=schemas.Candidate,tags=["admin"],dependencies=[Depends(get_admin)])
def get_candidate_by_id(cand_id: int, db: Session = Depends(get_db)):
    if cand_id<1:
        raise HTTPException(status_code=422,detail="Candidate id can't be 0 or negative!!!")
    db_candidate = crud.get_candidate(db, cand_id=cand_id)
    if db_candidate is None:
        raise HTTPException(status_code=404, detail=f"Candidate with id: {cand_id} does not exist!!")
    return db_candidate

@app.delete("/admin/candidates/{cand_id}/",dependencies=[Depends(get_admin)],tags=["admin"])
def delete_candidate(cand_id:int,db:Session=Depends(get_db)):
    if cand_id<1:
        raise HTTPException(status_code=422,detail="Candidate id can't be 0 or negative!!!")
    db_candidate=crud.get_candidate(db,cand_id=cand_id)
    if db_candidate is None or db_candidate.status==0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Candidate with id: {cand_id} does not exist!!")
    crud.delete_candidate(db,cand_id=cand_id)
    return "Successfully Deleted!!"

        # jobs

@app.delete("/admin/jobs/{job_id}",tags=["admin"],dependencies=[Depends(get_admin)])
def remove_job(job_id:int,db:Session=Depends(get_db)):
    if job_id<1:
        raise HTTPException(status_code=422,detail="Job id can't be 0 or negative!!!")
    db_job=crud.get_job(db,job_id=job_id)
    if db_job is None or db_job.status==0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Job with id: {job_id} does not exist!!")
    crud.delete_job(db,job_id=job_id)
    return "Successfully Deleted!!"

        # interview

@app.get("/admin/interview/",tags=["admin"],dependencies=[Depends(get_admin)])
def view_interview_schedules(db:Session=Depends(get_db)):
    db_interview=crud.get_interview_schedules(db)
    if db_interview==[]:
        raise HTTPException(status_code=404,detail="No interview scheduled yet!!")
    return db_interview

from datetime import datetime, date
from typing import List, Optional

import sqlalchemy
from pydantic import BaseModel,EmailStr
import time

# jobs

class JobBase(BaseModel):
    title: str
    post:str
    description: Optional[str] = None
    company_name: str
    annual_salary_in_lakhs:str="0"
    job_location:str
    apply_from:date=datetime.date(datetime.now())
    apply_to:date=datetime.date(datetime.now())

class JobCreate(JobBase):
    pass

class Jobs(JobBase):
    job_id: int
    posted_by: int

    class Config:
        orm_mode = True

# employers

class EmployerBase(BaseModel):
    name:str
    email: str
    designation:str
    company_name:str
    contact:str="0"
    address:str

class EmployerCreate(EmployerBase):
    password: str

class Employer(EmployerBase):
    emp_id: int
    post_jobs: List[Jobs] = []

    class Config:
        orm_mode = True

class EmployerUpdate(BaseModel):
    name:Optional[str]
    designation:Optional[str]
    company_name:Optional[str]
    contact:Optional[str]
    address:Optional[str]

# candidates

class CandidateBase(BaseModel):
    name:str
    email: str
    dob:str=datetime.date(datetime.now())
    grad:str
    post_grad:Optional[str]=None
    # skills:List[str]=[]
    contact:str="0"
    address:str

class CandidateCreate(CandidateBase):
    password: str

class Candidate(CandidateBase):
    cand_id: int
    skills:List
    class Config:
        orm_mode = True

class CandidateUpdate(BaseModel):
    name:Optional[str]
    grad:Optional[str]
    post_grad:Optional[str]
    # skills:Optional[str]
    contact:Optional[str]
    address:Optional[str]

# interview

class InterviewBase(BaseModel):
    venue: str
    day:str=datetime.date(datetime.now())
    time: str="00:00"
    # time:str=datetime.time(datetime.now())
    message: str

class InterviewCreate(InterviewBase):
    pass

class Interview(InterviewBase):
    i_id: int
    emp_id: int
    cand_id: int
    job_id: int

    class Config:
        orm_mode = True
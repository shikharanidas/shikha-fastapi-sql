from datetime import datetime, date

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
import sqlalchemy
from .database import Base

class Employer(Base):
    __tablename__ = "employers"

    emp_id = Column(Integer, primary_key=True, index=True)
    name=Column(String, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    designation=Column(String, index=True)
    company_name=Column(String, index=True)
    contact=Column(sqlalchemy.VARCHAR(10), index=True)
    address=Column(String, index=True)
    status = Column(Integer, default=1)

    post_jobs = relationship("Jobs", back_populates="employer")
    interview3 = relationship("Interview", back_populates="emp")

class Candidate(Base):
    __tablename__ = "candidates"

    cand_id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    dob=Column(String, index=True)
    contact = Column(sqlalchemy.VARCHAR(10), index=True)
    address = Column(String, index=True)
    grad = Column(String, index=True)
    post_grad=Column(String, index=True)
    resume=Column(String,index=True)
    # skills=Column(String, index=True)
    status = Column(Integer, default=1)

    skills=relationship("Skills",back_populates="candidates")
    apply = relationship("Apply", back_populates="candidates")
    interview1=relationship("Interview",back_populates="cand")

class Jobs(Base):
    __tablename__="jobs"

    job_id=Column(Integer,primary_key=True,index=True)
    title=Column(String, index=True)
    post=Column(String, index=True)
    description=Column(String, index=True)
    company_name=Column(String, index=True)
    annual_salary_in_lakhs=Column(String, index=True)
    job_location=Column(String, index=True)
    apply_from=Column(sqlalchemy.DATE)
    apply_to=Column(sqlalchemy.DATE)
    status=Column(Integer,default=1)
    posted_by=Column(Integer, ForeignKey("employers.emp_id"))

    employer=relationship("Employer", back_populates="post_jobs")
    job_apply=relationship("Apply", back_populates="jobs")
    interview2=relationship("Interview",back_populates="job")

class Apply(Base):
    __tablename__="apply"

    apply_id=Column(Integer,primary_key=True,index=True)
    job_id=Column(Integer, ForeignKey("jobs.job_id"))
    cand_id=Column(Integer, ForeignKey("candidates.cand_id"))
    apply_date=Column(String, index=True)

    candidates=relationship("Candidate", back_populates="apply")
    jobs=relationship("Jobs", back_populates="job_apply")

class Admin(Base):
    __tablename__="admin"

    a_id=Column(Integer,primary_key=True,index=True)
    userid=Column(String,index=True)
    password=Column(String)
    status=Column(Integer,default=1)

class Interview(Base):
    __tablename__="interview"

    i_id=Column(Integer,primary_key=True)
    job_id=Column(Integer,ForeignKey("jobs.job_id"))
    cand_id = Column(Integer, ForeignKey("candidates.cand_id"))
    emp_id = Column(Integer, ForeignKey("employers.emp_id"))
    venue=Column(String,index=True)
    day=Column(String,index=True)
    time=Column(String,index=True)
    message=Column(String,index=True)

    cand=relationship("Candidate", back_populates="interview1")
    job = relationship("Jobs", back_populates="interview2")
    emp = relationship("Employer", back_populates="interview3")

class Skills(Base):
    __tablename__="skills"
    s_id=Column(Integer,primary_key=True)
    skill1=Column(String,index=True)
    skill2 = Column(String, index=True)
    skill3 = Column(String, index=True)
    skill4 = Column(String, index=True)
    cand_id=Column(Integer,ForeignKey("candidates.cand_id"))

    candidates=relationship("Candidate",back_populates="skills")
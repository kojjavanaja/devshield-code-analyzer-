from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional
class RegisterIn(BaseModel): name: str = Field(min_length=2,max_length=120); email: EmailStr; password: str = Field(min_length=10,max_length=128)
class LoginIn(BaseModel): email: EmailStr; password: str
class ProjectIn(BaseModel): name: str = Field(min_length=1,max_length=160); description: str = Field(default="",max_length=5000); language: str = "python"
class ProjectPatch(BaseModel): name: Optional[str] = Field(default=None,min_length=1,max_length=160); description: Optional[str] = Field(default=None,max_length=5000); language: Optional[str] = None; archived: Optional[bool] = None
class ScanIn(BaseModel): code: str = Field(min_length=1,max_length=200000); language: str = "python"; filename: str = "snippet.py"; project_id: Optional[str] = None
class UserPatch(BaseModel): name: str = Field(min_length=2,max_length=120)
class SettingsPatch(BaseModel): theme: str = "midnight-plum"; default_language: str = "python"; notifications: bool = True

from fastapi import Request, HTTPException, FastAPI, Depends, status, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordRequestForm
import datetime
from starlette.middleware.cors import CORSMiddleware


app = FastAPI()

templates = Jinja2Templates(directory='templates')

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173","https://just-test-eg0s.onrender.com/"],  # Lokal server uchun domen
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get('/', response_class=HTMLResponse)
async def read_root(request:Request):
    return templates.TemplateResponse('index.html', {"request":request})

class User(BaseModel):
    username:str
    password:str

class Settings(BaseModel):
    authjwt_secret_key:str = 'secret'
@AuthJWT.load_config
def get_config():
    return Settings()

@app.exception_handler(AuthJWTException)
def authjwt_exeption_handler(request:Request, exc:AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={'detail':exc.message}
    )
@app.post('/login')
def login(user: User, Authorize:AuthJWT = Depends(), response:Response = None):
    if user.username !='test' or user.password != 'test':
        raise HTTPException(status_code=401, detail='Bad username or password')
    
    access_token = Authorize.create_access_token(subject=user.username, expires_time=datetime.timedelta(seconds=3600))
    refresh_token = Authorize.create_refresh_token(subject=user.username, expires_time=datetime.timedelta(seconds=3600*24))

    response.set_cookie(key="access_token", value=access_token, max_age=3600, samesite='none', secure=True)
    response.set_cookie(key="refresh_token", value=refresh_token, max_age=3600*24, samesite='none', secure=True)

    
    return {'message':'Successfully login'}






@app.post('/resfresh')
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()
    
    current_user = Authorize.get_jwt_subject()
    new_access_token = Authorize.create_access_token(subject=current_user)
    Authorize.set_access_cookies(new_access_token)
    return {"msg":"The token has been refresh"}



@app.delete('/logout')
def logout(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    Authorize.unset_jwt_cookies()
    return {"msg":"Successfully logout"}



@app.get('/protected')
def protected(Authorize: AuthJWT = Depends()):
    
    try:
        Authorize.jwt_required()

        current_user = Authorize.get_jwt_subject()
        return {"user": current_user}
    
    except Exception as e:
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Bad request")
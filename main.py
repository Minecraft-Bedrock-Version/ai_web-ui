from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
# static 파일 설정
from fastapi.staticfiles import StaticFiles


app = FastAPI()
templates = Jinja2Templates(directory="templates")

# static 라우트
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse) 
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
@app.get("/service/iam",response_class=HTMLResponse)
async def service_iam(request: Request):
    return templates.TemplateResponse("/service/iam/iam.html",{"request":request})




# mbv_search.py 라우팅
from backend.embed.mbv_search import router as mbv_search_router
app.include_router(mbv_search_router)

# mbv_llm_gpt.py 라우팅
from backend.llm.mbv_llm_gpt import router as mbv_llm_gpt_router
app.include_router(mbv_llm_gpt_router)

# grok_ext.py 라우팅
from backend.grok.grok_exe import router as grok_exe_router
app.include_router(grok_exe_router)

# lambda.py 라우팅
from backend.mbv_lambda.mbv_lambda import router as mbv_lambda_router
app.include_router(mbv_lambda_router)

# cliCreate.py 라우팅
from backend.cliCreate.cliCreate import router as cli_create_router
app.include_router(cli_create_router)
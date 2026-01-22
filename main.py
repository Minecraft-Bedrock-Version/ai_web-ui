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

# mbv_embed.py 라우팅
from backend.embed.mbv_embed import router as mbv_embed_router
app.include_router(mbv_embed_router)

# mbv_search.py 라우팅
from backend.embed.mbv_search import router as mbv_search_router
app.include_router(mbv_search_router)

# mbv_llm_gpt.py 라우팅
from backend.llm.mbv_llm_gpt import router as mbv_llm_gpt_router
app.include_router(mbv_llm_gpt_router)
from __future__ import annotations
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import uvicorn
import httpx
import os

# 学长的推理服务地址
REMOTE_API = 'http://10.15.14.103:8000'

# 创建FastAPI应用
app = FastAPI(title="金丝猴智能平台", version="1.0")

# 允许跨域（ngrok场景下浏览器需要）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 提供前端HTML页面
_HTML_PATH = os.path.join(os.path.dirname(__file__), 'golden_monkey14.html')

@app.get('/', response_class=HTMLResponse)
async def serve_index():
    with open(_HTML_PATH, 'r', encoding='utf-8') as f:
        return f.read()

# ---- 代理：上传图片 ----
@app.post('/proxy/upload')
async def proxy_upload(folder: str = Form(default=''), files: List[UploadFile] = File(...)):
    """将图片转发到学长的服务器"""
    upload_files = []
    for f in files:
        content = await f.read()
        upload_files.append(('files', (f.filename, content, f.content_type or 'image/jpeg')))
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(f'{REMOTE_API}/upload',
                                 files=upload_files,
                                 data={'folder': folder})
    try:
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception:
        # 响应体不是JSON时，根据HTTP状态码判断成功与否
        success = resp.status_code < 400
        return JSONResponse(content={'success': success, 'details': {}}, status_code=resp.status_code)

# ---- 代理：登录注册/AI问答 → 本地 auth_server (8000) ----
LOCAL_AUTH = 'http://127.0.0.1:6000'

@app.api_route('/api/{path:path}', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
async def proxy_auth(path: str, request: Request):
    """将 /api/* 请求转发到本地 auth_server（8000端口）"""
    url = f'{LOCAL_AUTH}/api/{path}'
    body = await request.body()
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in ('host', 'content-length')}
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.request(
            method=request.method,
            url=url,
            content=body,
            headers=headers,
            params=dict(request.query_params)
        )
    return JSONResponse(content=resp.json(), status_code=resp.status_code,
                        headers=dict(resp.headers))

# ---- 代理：情绪推理 ----
@app.post('/proxy/inference')
async def proxy_inference(request: Request):
    """将推理请求转发到学长的服务器"""
    body = await request.json()
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(f'{REMOTE_API}/inference',
                                 json=body,
                                 headers={'Content-Type': 'application/json'})
    return JSONResponse(content=resp.json(), status_code=resp.status_code)

# ---- 视频获取：直接从本地 video/ 目录读取 mp4 ----
import glob
from fastapi.responses import FileResponse

@app.get('/proxy/cover/{folder}')
async def get_cover(folder: str):
    """返回视频封面图"""
    _video_dir = os.path.join(os.path.dirname(__file__), 'video', folder)
    for ext in ('*.png', '*.jpg', '*.jpeg', '*.webp'):
        covers = glob.glob(os.path.join(_video_dir, 'cover' + ext[1:]))
        if covers:
            return FileResponse(covers[0])
    return JSONResponse(content={'detail': '封面不存在'}, status_code=404)

@app.get('/proxy/frame/{folder}/{frame}')
async def get_frame(folder: str, frame: str):
    """返回 video/video/{folder}/{frame}.jpg 帧图片"""
    path = os.path.join(os.path.dirname(__file__), 'video', 'video', folder, frame + '.jpg')
    if not os.path.exists(path):
        return JSONResponse(content={'detail': '图片不存在'}, status_code=404)
    return FileResponse(path, media_type='image/jpeg')

@app.get('/proxy/video/{folder}')
async def get_video(folder: str, request: Request):
    """从本地 video/{folder}/ 目录返回mp4，优先返回video.mp4（H.264），FileResponse自动支持Range请求"""
    _video_dir = os.path.join(os.path.dirname(__file__), 'video', folder)
    # 优先返回转码后的H.264版本
    preferred = os.path.join(_video_dir, 'video.mp4')
    if os.path.exists(preferred):
        return FileResponse(preferred, media_type='video/mp4')
    mp4_files = glob.glob(os.path.join(_video_dir, '*.mp4'))
    if not mp4_files:
        return JSONResponse(content={'detail': '视频文件不存在'}, status_code=404)
    return FileResponse(
        mp4_files[0],
        media_type='video/mp4'
    )

# 定义请求体模型
class InferenceRequest(BaseModel):
    text_desc: str  # 文本描述
    data_dir: str   # 包含16张jpg图像的文件夹路径

# 定义响应模型
class InferenceResponse(BaseModel):
    predicted_label: int  # 预测标签
    confidence: float     # 置信度


@app.post("/inference", response_model=InferenceResponse, summary="视频分类推理")
async def inference(request: InferenceRequest):
    """
    视频分类推理接口
    
    - **text_desc**: 文本描述
    - **data_dir**: 包含16张jpg图像的文件夹路径
    
    返回预测标签和置信度
    """
    try:
        # 调用single_inference函数进行推理
        result = single_inference(request.text_desc, request.data_dir)
        
        # 检查是否有错误
        if "error" in result:
            return {"predicted_label": -1, "confidence": 0.0}
        
        # 返回预测结果
        return {
            "predicted_label": result["predicted_label"],
            "confidence": result["confidence"]
        }
    except Exception as e:
        # 处理异常
        print(f"推理失败: {e}")
        return {"predicted_label": -1, "confidence": 0.0}


# 运行应用（端口改为8001，避免与学长服务的8000冲突）
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9999, log_level="info")

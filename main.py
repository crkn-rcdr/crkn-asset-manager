import os
import io
import hashlib
import json
import requests
import datetime
import swiftclient
import boto3
import botocore
import httpx
from PIL import Image
from fastapi import FastAPI, HTTPException, Request, Response, Depends, Security, File
from fastapi.responses import RedirectResponse, StreamingResponse, JSONResponse
from fastapi.security import APIKeyCookie
from fastapi_sso.sso.microsoft import MicrosoftSSO
from fastapi_sso.sso.base import OpenID
from jose import jwt
from typing import List
from typing_extensions import Annotated
import random
import string
import uvicorn
# from dotenv import load_dotenv
# Load environment variables
# load_dotenv(".env")

# Azure Active Directory (AAD) configuration
AAD_CLIENT_SECRET = os.getenv("AAD_CLIENT_SECRET")
AAD_CLIENT_ID = os.getenv("AAD_CLIENT_ID")
AAD_TENANT_ID = os.getenv("AAD_TENANT_ID")
AAD_SCOPE_DESCRIPTION = os.getenv("AAD_SCOPE_DESCRIPTION")
AAD_SCOPE_NAME = os.getenv("AAD_SCOPE_NAME")
AAD_TENANT_NAME = os.getenv("AAD_TENANT_NAME")
AAD_AUTH_URL = os.getenv("AAD_AUTH_URL")
AAD_TOKEN_URL = os.getenv("AAD_TOKEN_URL")

# Other configurations
NOID_SERVER = os.getenv("NOID_SERVER")
SWIFT_AUTH_URL = os.getenv("SWIFT_AUTH_URL")
SWIFT_USERNAME = os.getenv("SWIFT_USERNAME")
SWIFT_PASSWORD = os.getenv("SWIFT_PASSWORD")
SWIFT_PREAUTH_URL = os.getenv("SWIFT_PREAUTH_URL")

IIIF_SWIFT_AUTH_URL = os.getenv("IIIF_SWIFT_AUTH_URL")
IIIF_SWIFT_USERNAME = os.getenv("IIIF_SWIFT_USERNAME")
IIIF_SWIFT_PASSWORD = os.getenv("IIIF_SWIFT_PASSWORD")
IIIF_SWIFT_PREAUTH_URL = os.getenv("IIIF_SWIFT_PREAUTH_URL")

S3SOURCE_ENDPOINT = os.getenv("S3SOURCE_ENDPOINT")
S3SOURCE_ACCESS_KEY_ID = os.getenv("S3SOURCE_ACCESS_KEY_ID")
S3SOURCE_SECRET_KEY = os.getenv("S3SOURCE_SECRET_KEY")
S3SOURCE_ACCESSFILES_BUCKET_NAME = os.getenv("S3SOURCE_ACCESSFILES_BUCKET_NAME")

PRES_API_HOST = os.getenv("PRES_API_HOST")

# API URLs
image_api_url = "https://image-tor.canadiana.ca"
presentation_api_url = "https://crkn-iiif-presentation-api.azurewebsites.net"
crkn_digirati_editor_api_url = "https://crkn-asset-manager.azurewebsites.net"

# Initialize connections
connCanvas = swiftclient.Connection(
    authurl=SWIFT_AUTH_URL,
    user=SWIFT_USERNAME,
    key=SWIFT_PASSWORD,
    preauthurl=SWIFT_PREAUTH_URL,
)
connIIIF = swiftclient.Connection(
    user=IIIF_SWIFT_USERNAME,
    key=IIIF_SWIFT_PASSWORD,
    authurl=IIIF_SWIFT_AUTH_URL,
    preauthurl=IIIF_SWIFT_PREAUTH_URL
)
s3_conn = boto3.client(
    service_name="s3",
    aws_access_key_id=S3SOURCE_ACCESS_KEY_ID,
    aws_secret_access_key=S3SOURCE_SECRET_KEY,
    endpoint_url=S3SOURCE_ENDPOINT,
    config=botocore.client.Config(signature_version="s3"),
)

# TODO - replace with call to new ARK
def mint_noid(noid_type):
    if noid_type not in ['canvas', 'manifest']:
        raise ValueError("noid_type must be 'canvas' or 'manifest'")
    prefix = "69429/"
    type_char = noid_type[0]  # 'm' for manifest, 'c' for canvas
    while True:
        random_digits = random.choice(string.digits) 
        random_part = random_digits 
        for _ in range(3):
            random_consonants = ''.join(random.choices("bcdfghjkmnpqrstvwxz", k=2)) 
            random_part += random_consonants + random.choice(string.digits) 
        random_part += random.choice("bcdfghjkmnpqrstvwxz")  # Add final consonant
        # Construct the full NOID
        generated_noid = f"{prefix}{type_char}{random_part}"
        # Check for uniqueness based on noid_type
        if noid_type == "canvas":
            file, heads = get_file_from_swift(f"{generated_noid}.jpg", "access-files")
            if file:  # If file exists, retry
                continue
            else:
                return generated_noid.lower()
        elif noid_type == "manifest":
            file, heads = get_iiif_from_swift(f"{generated_noid}/manifest.json")
            if file:
                continue
            else:
                return generated_noid.lower()

def convert_image(source_file, output_path):
    original = Image.open(source_file)
    original.save(output_path, quality=80)
    output = Image.open(output_path)
    return {"width": output.width, "height": output.height, "size": output.size}

def save_image_to_swift(local_filename, swift_filename, container):
    with open(local_filename, "rb") as local_file:
        file_content = local_file.read()
        file_md5_hash = hashlib.md5(file_content).hexdigest()
        swift_md5_hash = connCanvas.put_object(container, swift_filename, contents=file_content)
        print("swift:", swift_md5_hash, swift_filename)
        print("swift_filename:", swift_filename)
        print("container:", container)
        print("local_filename:",  local_filename)
    return file_md5_hash

def get_file_from_swift(swift_filename, container):
    try:
        resp_headers, obj_contents = connCanvas.get_object(container, swift_filename)
        return resp_headers, obj_contents
    except:
        return None, None

def get_iiif_from_swift(swift_filename):
    try:
        resp_headers, obj_contents = connIIIF.get_object("IIIF", swift_filename)
        return resp_headers, obj_contents
    except:
        return None, None

# Helper function to process each file or URL
def process_file_or_url(file_or_url, is_url, manifest_noid):
    if is_url:
        response = requests.get(file_or_url)
        if response.status_code != 200:
            print("Failed to retrieve the image")
            raise ValueError("Could not get file from URL")
        source_file = io.BytesIO(response.content)
    else:
        source_file = io.BytesIO(file_or_url)

    canvas_noid = mint_noid("canvas")
    print("new canvas id:", canvas_noid) #es: 69429/mCa08E9Je9k-p3
    encoded_canvas_noid = canvas_noid.replace("/", "%2F")
    swift_filename = f"{canvas_noid}.jpg"
    local_filename = f"{encoded_canvas_noid}.jpg"

    # Convert the image
    convert_info = convert_image(source_file, local_filename)

    # Save image to swift storage
    swift_md5 = save_image_to_swift(local_filename, swift_filename, "access-files")
    if swift_md5:
        #save_canvas(canvas_noid, encoded_canvas_noid, convert_info['width'], convert_info['height'], convert_info['size'], swift_md5)

        # Prepare the canvas data to return
        return {
            "id": f"{presentation_api_url}/canvas/{canvas_noid}",
            "width": convert_info["width"],
            "height": convert_info["height"],
            "thumbnail": [{
                "id": f"{image_api_url}/iiif/2/{encoded_canvas_noid}/full/max/0/default.jpg",
                "type": "Image",
                "format": "image/jpeg"
            }],
            "items": [{
                "id": f"{presentation_api_url}/{manifest_noid}/annotationpage/{canvas_noid}/main",
                "type": "AnnotationPage",
                "items": [{
                    "id": f"{presentation_api_url}/{manifest_noid}/annotation/{canvas_noid}/main/image",
                    "body": {
                        "id": f"{image_api_url}/iiif/2/{encoded_canvas_noid}/full/max/0/default.jpg",
                        "type": "Image",
                        "width": convert_info["width"],
                        "height": convert_info["height"],
                        "format": "image/jpeg",
                        "service": [{
                            "id": f"{image_api_url}/iiif/2/{encoded_canvas_noid}",
                            "type": "ImageService2",
                            "profile": "level2"
                        }]
                    },
                    "type": "Annotation",
                    "target": f"{presentation_api_url}/canvas/{canvas_noid}",
                    "motivation": "painting"
                }]
            }],
            "seeAlso": [{
                "id": f"{crkn_digirati_editor_api_url}/ocr/{canvas_noid}",
                "type": "Dataset",
                "label": {"en": ["Optical Character Recognition text in XML"]},
                "format": "text/xml",
                "profile": "http://www.loc.gov/standards/alto"
            }],
            "rendering": [{
                "id": f"{crkn_digirati_editor_api_url}/pdf/{canvas_noid}",
                "type": "Text",
                "label": {"en": ["PDF version"]},
                "format": "application/pdf"
            }],
        }
    return None

# Microsoft SSO configuration
sso = MicrosoftSSO(
    client_id=AAD_CLIENT_ID,
    client_secret=AAD_CLIENT_SECRET,
    tenant=AAD_TENANT_ID,
    redirect_uri=f"{crkn_digirati_editor_api_url}/auth/callback",
    allow_insecure_http=True,
)

# JWT Token verification
async def get_logged_user(cookie: str = Security(APIKeyCookie(name="token"))) -> OpenID:
    try:
        claims = jwt.decode(cookie, key=AAD_CLIENT_SECRET, algorithms=["HS256"])
        return OpenID(**claims["pld"])
    except Exception as error:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        ) from error

def verify_token(req: Request):
    try:
        token = req.headers["Authorization"]
        valid = jwt.decode(
            token.replace("Bearer ", ""), key=AAD_CLIENT_SECRET, algorithms=["HS256"]
        )
        return True
    except Exception:
        return False

# FastAPI application
app = FastAPI()

@app.get("/")
async def main(cookie: str = Security(APIKeyCookie(name="token"))):
    return {"token": cookie}

@app.get("/auth/login")
async def login():
    async with sso:
        return await sso.get_login_redirect()

@app.get("/auth/logout")
async def logout():
    response = RedirectResponse(url="/")
    response.delete_cookie(key="token")
    return response

@app.get("/auth/callback")
async def login_callback(request: Request):
    request.timeout = 100000000000000
    async with sso:
        openid = await sso.verify_and_process(request)
        if not openid:
            raise HTTPException(status_code=401, detail="Authentication failed")
    expiration = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1)
    token = jwt.encode(
        {"pld": openid.dict(), "exp": expiration, "sub": openid.id},
        key=AAD_CLIENT_SECRET,
        algorithm="HS256",
    )
    response = RedirectResponse(url="/")
    response.set_cookie(key="token", value=token, expires=expiration)
    return response

@app.get("/ocr/{prefix}/{noid}")
async def ocr(prefix, noid):
    resp_headers, obj_contents = get_file_from_swift(f"{prefix}/{noid}/ocrTXTMAP.xml", "access-metadata")
    if obj_contents is None:
        resp_headers, obj_contents = get_file_from_swift(f"{prefix}/{noid}/ocrALTO.xml", "access-metadata")
    if obj_contents is None:
        return {"message": "File not found."}
    return Response(content=obj_contents, media_type=resp_headers["content-type"])

@app.get("/pdf/{prefix}/{noid}")
async def pdf(prefix, noid):
    try:
        result = s3_conn.get_object(Bucket="access-files", Key=f"{prefix}/{noid}.pdf")
        return StreamingResponse(content=result["Body"].iter_chunks())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/bearer-protected")
async def protected_endpoint(authorized: bool = Depends(verify_token)):
    return {"message": "You are authorized!" if authorized else "You are not authorized!"}

@app.get("/newid")
async def new_id():
    return {
        "id": mint_noid("manifest")
    }

# TODO: Add a line calling map ark to slug in new ark service
@app.post("/savemanifest/{prefix}/{noid}")
async def create_files(prefix, noid, request: Request, authorized: bool = Depends(verify_token)):
    if not authorized:
        return JSONResponse(
            content={"message": "You are not authorized to make this request."},
            status_code=403
        )
    try:
        data = await request.json()
        json_filename = f"{prefix}%2F{noid}.json"
        with open(json_filename, 'w', encoding='utf-8') as json_file:
            json.dump(data, json_file, ensure_ascii=False, indent=4)
        with open(json_filename, 'rb') as file:
            # Set up the HTTP client with timeout
            timeout = httpx.Timeout(3000.0, read=3000.0)
            with httpx.Client(timeout=timeout) as client:
                # Create the JWT token
                expiration = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1)
                token = jwt.encode(
                    {"pld": "editor-api-source", "exp": expiration},
                    key=AAD_CLIENT_SECRET,
                    algorithm="HS256",
                )
                if not token:
                    raise ValueError("No access token generated.")
                # Send the file to the API
                url = f"https://{PRES_API_HOST}/admin/file"
                headers = {"Authorization": f"Bearer {token}"}
                file_data = {'file': (json_filename, file, 'application/json')}
                response = client.put(url, files=file_data, headers=headers)

                if response.status_code == 200:
                    return JSONResponse(
                        content={"success": True, "message": "File successfully uploaded."},
                        status_code=200
                    )
                else:
                    raise ValueError(f"API Error: {response.text}")
    except Exception as e:
        # Catch all errors and return a generic error message
        return JSONResponse(
            content={"success": False, "message": f"Error: {str(e)}"},
            status_code=500
        )

@app.post("/uploadfiles/{prefix}/{noid}")
async def upload_files(prefix, noid, files: List[bytes] = File(...), authorized: bool = Depends(verify_token)):
    if not authorized:
        return JSONResponse(content={"message": "You are not authorized to make this request."}, status_code=403)
    manifest_noid = f"{prefix}/{noid}"
    canvases = []
    for file in files:
        #try:
        canvas_data = process_file_or_url(file, is_url=False, manifest_noid=manifest_noid)
        if canvas_data:
            canvases.append(canvas_data)
        #except ValueError as e:
        #    return JSONResponse(content={"message": str(e)}, status_code=400)
    return {"canvases": canvases}

@app.post("/createfilesfromurl/{prefix}/{noid}")
async def create_files_from_url(prefix, noid, request: Request, authorized: bool = Depends(verify_token)):
    if not authorized:
        return JSONResponse(content={"message": "You are not authorized to make this request."}, status_code=403)
    manifest_noid = f"{prefix}/{noid}"
    data = await request.json()  # This will give you a Python dictionary
    canvases = []
    for url in data['urls']:
        try:
            canvas_data = process_file_or_url(url, is_url=True, manifest_noid=manifest_noid)
            if canvas_data:
                canvases.append(canvas_data)
        except ValueError as e:
            return JSONResponse(content={"message": str(e)}, status_code=400)
    return {"canvases": canvases}

if __name__ == '__main__':
    uvicorn.run('main:app', host='0.0.0.0', port=8000)
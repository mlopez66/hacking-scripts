#!/usr/bin/env python3

from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    content_type = flow.response.headers.get("content-type", "").lower()

    try:
        if "image" in content_type:
            url = flow.request.url
            extension = content_type.split("/")[-1]
            if extension == "jpeg":
                extension = "jpg"
            file_name = f"images/{url.replace(':','_').replace('/','_').replace('?','_')}.{extension}"
            with open(file_name, "wb") as f:
                f.write(flow.response.content)
            print(f"[+] file saved: {file_name}")
    except Exception as e:
        pass


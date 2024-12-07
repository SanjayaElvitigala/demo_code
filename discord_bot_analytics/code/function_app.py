import azure.functions as func
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from binascii import unhexlify
import requests

import os
import json

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from io import BytesIO

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


# # For testing locally through ngrok tunnel (https://ngrok.com/our-product/secure-tunnels)
# os.environ["SHEET_ID"] = ""
# os.environ["DISCORD_PUBLIC_KEY"] =""
# os.environ["SHEET_API_KEY"] = ""
# os.environ["DATA_RANGE"] = "" # Sheet1!A:C
# os.environ["CHANNEL_WEBHOOK"] = ""


def verify_headers(request: func.HttpRequest, discord_public_key: str):
    signature = request.headers.get("X-Signature-Ed25519")
    timestamp = request.headers.get("X-Signature-Timestamp")
    body = request.get_body().decode("utf-8")

    if not (signature and timestamp):
        return func.HttpResponse(
            "missing headers",
            status_code=400,
        )

    try:
        # Load the public key
        public_key = Ed25519PublicKey.from_public_bytes(unhexlify(discord_public_key))

        # Verify the signature
        public_key.verify(unhexlify(signature), f"{timestamp}{body}".encode("utf-8"))
    except InvalidSignature:
        return func.HttpResponse(
            "invalid request signature",
            status_code=401,
        )
    except ValueError as e:
        logging.error(f"Error processing public key or signature: {e}")
        return func.HttpResponse(
            "invalid public key or signature",
            status_code=400,
        )

    req_body = request.get_json()
    # Handle Discord PING type
    if req_body["type"] == 1:  # PING
        response_data = {"type": 1}  # PONG
        return func.HttpResponse(json.dumps(response_data), mimetype="application/json")


def get_sheet_data():
    SHEET_ID = os.environ["SHEET_ID"]
    SHEET_API_KEY = os.environ["SHEET_API_KEY"]
    DATA_RANGE = os.environ["DATA_RANGE"]

    get_sheets_url = (
        lambda sheet_id, data_range: f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/{data_range}"
    )

    PARAMS = {"key": SHEET_API_KEY}
    sheet_data = requests.get(
        url=get_sheets_url(sheet_id=SHEET_ID, data_range=DATA_RANGE),
        params=PARAMS,
    )
    df = pd.DataFrame(
        sheet_data.json()["values"][1:], columns=sheet_data.json()["values"][0]
    )
    df = df.astype("int")
    return df


def string_analysis(data):
    out_str = ""
    for col_name, col_value in zip(data.columns, data.sum(axis=0).values):
        out_str += f"sum {col_name}: {col_value}, "

    return out_str.strip()


def visual_analysis(data):
    plt.bar(x=data.columns, height=data.sum(axis=0).values)
    plt.title("column summation")
    plt.xlabel("columns")
    plt.ylabel("sum")
    plt.tight_layout()

    # Save plot to BytesIO
    img_buffer = BytesIO()
    plt.savefig(img_buffer, format="jpg")
    img_buffer.seek(0)
    plt.close()

    return img_buffer


@app.route(route="http_demobot")
def http_demobot(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Python HTTP trigger function processed a request.")

    DISCORD_PUBLIC_KEY = os.environ["DISCORD_PUBLIC_KEY"]
    req_body = req.get_json()

    if req_body["type"] == 1:
        response_data = verify_headers(
            request=req, discord_public_key=DISCORD_PUBLIC_KEY
        )
        return response_data
    else:
        df = get_sheet_data()

        if req_body["data"]["name"] == "give_analysis":

            str_analysis = string_analysis(data=df)
            response_data = {
                "type": 4,
                "data": {"content": str_analysis},
            }

            return func.HttpResponse(
                json.dumps(response_data), mimetype="application/json", status_code=200
            )
        elif req_body["data"]["name"] == "give_viz_analysis":
            img_buffer = visual_analysis(df)

            # binary files,  multipart/form-data POST request
            files = {
                "file": (
                    "image.jpg",
                    img_buffer.getvalue(),
                    "image/jpg",
                )  # The picture that we want to send in binary
            }
            # Optional message to send with the picture
            payload = {"content": "visual result"}

            r = requests.post(os.environ["CHANNEL_WEBHOOK"], data=payload, files=files)

            response_data = {
                "type": 4,
                "data": {"content": "visualization will be return shortly"},
            }
            return func.HttpResponse(
                json.dumps(response_data), mimetype="application/json", status_code=200
            )

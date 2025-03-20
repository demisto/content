import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import traceback
import json

''' MAIN FUNCTION '''


def main() -> None:
    channel_access_token = demisto.params().get('channel_access_token')  # 取得 LINE Bot 的 Access Token
    try:
        if demisto.command() == 'line-send-message':
            headers = {
                "Authorization": f"Bearer {channel_access_token}",
                "Content-Type": "application/json"
            }

            # 接收輸入參數
            recipient_id = demisto.args().get('to')  # 接收者的 User ID 或群組 ID
            message_text = demisto.args().get('message')

            # 建立 Payload
            payload = {
                "to": recipient_id,
                "messages": [
                    {
                        "type": "text",
                        "text": message_text
                    }
                ]
            }

            # 發送請求
            response = requests.post(
                "https://api.line.me/v2/bot/message/push",
                headers=headers,
                json=payload
            )

            # 處理回應
            if response.status_code == 200:
                return_results("Message sent successfully.")
            else:
                return_error(f"Failed to send message. Status code: {response.status_code}, Response: {response.text}")

        elif demisto.command() == 'test-module':
            # 測試 API 是否正常
            headers = {
                "Authorization": f"Bearer {channel_access_token}",
                "Content-Type": "application/json"
            }

            response = requests.get("https://api.line.me/v2/bot/info", headers=headers)
            if response.status_code == 200:
                return_results("ok")
            else:
                return_error(f"Test failed. Status code: {response.status_code}, Response: {response.text}")

        if demisto.command() == 'line-reply-message':
            headers = {
                "Authorization": f"Bearer {channel_access_token}",
                "Content-Type": "application/json"
            }

            # 接收輸入參數
            recipient_id = demisto.args().get('replytoken')  # replytoken
            message_text = demisto.args().get('message')

            # 建立 Payload
            payload = {
                "replyToken": recipient_id,
                "messages": [
                    {
                        "type": "text",
                        "text": message_text
                    }
                ]
            }

            # 發送請求
            response = requests.post(
                "https://api.line.me/v2/bot/message/reply",
                headers=headers,
                json=payload
            )

            # 處理回應
            if response.status_code == 200:
                return_results("Message sent successfully.")
            else:
                return_error(f"Failed to send message. Status code: {response.status_code}, Response: {response.text}")

        elif demisto.command() == 'test-module':
            # 測試 API 是否正常
            headers = {
                "Authorization": f"Bearer {channel_access_token}",
                "Content-Type": "application/json"
            }

            response = requests.get("https://api.line.me/v2/bot/info", headers=headers)
            if response.status_code == 200:
                return_results("ok")
            else:
                return_error(f"Test failed. Status code: {response.status_code}, Response: {response.text}")

    except Exception as e:
        demisto.error(traceback.format_exc())  # 印出 traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

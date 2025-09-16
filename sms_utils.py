import requests

def send_otp_sms(phone_number, otp):
    url = "https://www.fast2sms.com/dev/bulkV2"
    payload = {
        "route": "otp",
        "variables_values": otp,
        "numbers": phone_number
    }
    headers = {
        'authorization': 'YOUR_FAST2SMS_API_KEY',  # Replace with your actual API key
        'Content-Type': "application/x-www-form-urlencoded",
        'Cache-Control': "no-cache"
    }
    response = requests.post(url, data=payload, headers=headers)
    return response.json() 
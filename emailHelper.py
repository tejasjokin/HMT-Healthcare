import http.client
from codecs import encode

def send_email(reciever_email, message, email_type):
    conn = http.client.HTTPSConnection("l3nqmd.api.infobip.com")
    dataList = []
    boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'

    # Append boundary and content for 'from'
    dataList.append(encode('--' + boundary))
    dataList.append(encode('Content-Disposition: form-data; name="from"'))
    dataList.append(encode(''))
    dataList.append(encode("Harshika <hmthealthcare@outlook.com>"))

    # Append boundary and content for 'subject'
    dataList.append(encode('--' + boundary))
    dataList.append(encode('Content-Disposition: form-data; name="subject"'))
    dataList.append(encode(''))
    dataList.append(encode("{0}".format(email_type)))

    # Append boundary and content for 'to'
    dataList.append(encode('--' + boundary))
    dataList.append(encode('Content-Disposition: form-data; name="to"'))
    dataList.append(encode(''))
    dataList.append(encode(reciever_email))

    # Append boundary and content for 'text'
    dataList.append(encode('--' + boundary))
    dataList.append(encode('Content-Disposition: form-data; name="text"'))
    dataList.append(encode(''))
    dataList.append(encode(message))

    # End boundary
    dataList.append(encode('--' + boundary + '--'))
    dataList.append(encode(''))

    # Combine all parts into the body
    body = b'\r\n'.join(dataList)

    headers = {
        'Authorization': 'App 2ffd42f3bc64b536b2af6d8700ee9bfa-cb507eb9-faa8-4635-9391-655533cbe3a4',
        'Content-Type': 'multipart/form-data; boundary={}'.format(boundary),
        'Accept': 'application/json',
    }

    conn.request("POST", "/email/3/send", body, headers)
    res = conn.getresponse()
    data = res.read()
    return data.decode("utf-8")
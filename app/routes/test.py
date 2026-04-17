import qrcode

url = "https://play.google.com/apps/test/com.aak.tilsynsapp/11"

qr = qrcode.make(url)
qr.save("qrcode.png")
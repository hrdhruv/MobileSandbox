To check ratings prog: 

http://localhost:8000/ratings/progression

to view db:

python3 view_db.py progression

to push apk:

adb push base.apk /sdcard/Download/
adb push split_config.x86_64.apk /sdcard/Download/
adb push split_config.xhdpi.apk /sdcard/Download/
adb push split_config.en.apk /sdcard/Download/

to download apk:

adb install-multiple base.apk \
split_config.x86_64.apk \
split_config.xhdpi.apk \
split_config.en.apk
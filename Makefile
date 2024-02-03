.PHONY: upload showapi
.INTERMEDIATE: totp.asm totp.zap
.PRECIOUS: totp_template.asm

totp.zap: totp.asm
	rm -f totp.zap
	asm6805 totp.asm totp.zap

totp.asm: totp_template.asm
	python preprocessor.py < totp_template.asm > totp.asm

upload: totp.zap
	td150 --serial-device /dev/ttyACM2 --verbose --wrist-app totp.zap

showapi:
	docker run -ti timex-datalink-assembler cat /root/wine/drive_c/Program\ Files/DataLink\ Devel/Inc150/Wristapp.i

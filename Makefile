.PHONY: upload

totp.zap: totp.asm
	rm -f totp.zap
	asm6805 totp.asm totp.zap

upload: totp.zap
	td150 --serial-device /dev/ttyACM1 --verbose --wrist-app totp.zap

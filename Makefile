.PHONY: upload showapi
.INTERMEDIATE: totp.asm totp.zap
.PRECIOUS: totp.tasm

totp.zap: totp.asm
	rm -f totp.zap
	asm6805 totp.asm totp.zap

totp.asm: totp.tasm
	python preprocessor.py < totp.tasm > totp.asm

upload: totp.zap
	td150 --serial-device /dev/ttyACM2 --verbose --wrist-app totp.zap

showapi:
	docker run -ti timex-datalink-assembler cat /root/wine/drive_c/Program\ Files/DataLink\ Devel/Inc150/Wristapp.i

totp_reference_implementation: totp_reference_implementation.c
	gcc -o totp_reference_implementation totp_reference_implementation.c -lm
	./totp_reference_implementation

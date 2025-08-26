all: ./src/main.c
	@gcc ./src/main.c -o main && ./main
	@rm main

test:
	@gcc ./tests/my_test.c -o test_runner && ./test_runner
	@rm test_runner



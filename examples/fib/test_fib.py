from fib import fib


def test_base():
    assert fib(0) == 0
    assert fib(1) == 1


def test_ten():
    assert fib(10) == 55


def test_series():
    assert [fib(i) for i in range(7)] == [0, 1, 1, 2, 3, 5, 8]

# python doesn't support importing a file with a -.
# We need to use importlib for this case
import importlib
aws_lambda = importlib.import_module("AWS-Lambda")


def test_get_timeout():
    (read, connect) = aws_lambda.get_timeout(None)
    assert read == 60 and connect == 10
    (read, connect) = aws_lambda.get_timeout("100")
    assert read == 100 and connect == 10
    (read, connect) = aws_lambda.get_timeout("200,2")
    assert read == 200 and connect == 2

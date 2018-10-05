resource "aws_iam_role" "iam-for-lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com",
        "AWS": "${var.iam-user-arn}"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "iam-for-lambda" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchFullAccess"
  role       = "${aws_iam_role.iam-for-lambda.name}"
}

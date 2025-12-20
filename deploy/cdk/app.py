#!/usr/bin/env python3
import os
from aws_cdk import App, Environment
from keep_cdk.keep_stack import KeepEnclaveStack

prefix = os.getenv("CDK_PREFIX", "dev")

app = App()

KeepEnclaveStack(
    app,
    f"{prefix}KeepEnclave",
    env=Environment(
        region=os.environ.get("CDK_DEPLOY_REGION", "us-east-1"),
        account=os.environ.get("CDK_DEPLOY_ACCOUNT"),
    ),
)

app.synth()

"""CloudGuardIQ — AWS rule pack.

All rules are cloud-agnostic PolicyRule subclasses that read only from
``ResourceSnapshot.config``. They never import boto3.

Resource type strings follow the AWS Config naming convention
(``AWS::<Service>::<Type>``). See
[`cloudguardiq.adapters.aws.adapter`](../../aws/adapter.py) for how the
AWSAdapter populates these snapshots from boto3 responses.
"""

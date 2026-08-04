# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import os
import secrets
import string

import boto3

cognito = boto3.client('cognito-idp')

USER_POOL_ID = os.environ['USER_POOL_ID']
USER_NAME = os.environ.get('USER_NAME', 'flowadmin')

# Symbols kept to a safe set that the Cognito password policy accepts and that
# survive JSON/URL round-trips cleanly.
SYMBOLS = '!@#$%^&*()-_=+'
LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits


def generate_password(length=20):
    """Generate a random password that satisfies the Cognito policy:
    minLength 8, at least one lower, upper, digit and symbol.
    Guarantees one of each required class then fills the rest from the
    combined alphabet, finally shuffling so the required chars aren't in
    fixed positions."""
    if length < 8:
        length = 8
    alphabet = LOWER + UPPER + DIGITS + SYMBOLS
    chars = [
        secrets.choice(LOWER),
        secrets.choice(UPPER),
        secrets.choice(DIGITS),
        secrets.choice(SYMBOLS),
    ]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    # secrets-backed shuffle (Fisher-Yates) so the guaranteed classes land
    # in random positions.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return ''.join(chars)


def ensure_user_exists():
    """Create the user if it does not already exist. Idempotent."""
    try:
        cognito.admin_get_user(UserPoolId=USER_POOL_ID, Username=USER_NAME)
        return
    except cognito.exceptions.UserNotFoundException:
        pass
    cognito.admin_create_user(
        UserPoolId=USER_POOL_ID,
        Username=USER_NAME,
        MessageAction='SUPPRESS',
    )


def set_password():
    """(Re)set a fresh permanent password and return it."""
    password = generate_password()
    cognito.admin_set_user_password(
        UserPoolId=USER_POOL_ID,
        Username=USER_NAME,
        Password=password,
        Permanent=True,
    )
    return password


def handler(event, context):
    request_type = event.get('RequestType', '')
    physical_id = event.get('PhysicalResourceId', 'cognito-seed-user-' + USER_NAME)

    if request_type == 'Delete':
        # No-op on delete; the user pool is destroyed with the stack.
        return {'PhysicalResourceId': physical_id}

    # Create and Update both ensure the user exists and reset to a fresh
    # permanent password, then return it to CloudFormation.
    ensure_user_exists()
    password = set_password()

    return {
        'PhysicalResourceId': physical_id,
        'Data': {
            'Username': USER_NAME,
            'Password': password,
        },
    }
